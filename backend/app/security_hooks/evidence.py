"""审计证据包与多维风险指标（方向四）。

对应赛题原文：「形成可量化的测试方法、风险指标与**审计证据输出机制**，
支持攻击复现、问题定位、效果验证和持续优化」。

- **证据包**（``build_evidence_bundle``）：把一条 trace 上的全部 hook 事件、
  污点状态、哈希链完整性校验与分项指标聚合成一份可下载的 JSON，
  使「攻击复现」与「问题定位」有据可依——每一步的输入判定与依据都在时间线里。
- **多维指标**（``collect_metrics``）：按阶段 / 决策 / 标签 / 风险等级 / 安全维度
  五个角度汇总，其中安全维度对齐赛题要求的
  数据安全、内容安全、执行安全、供应链安全、合规风险。
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .audit import get_hook_audit_store
from .taint import get_taint_ledger

# 标签 → 安全维度的映射。一个标签可归属多个维度（例如跨阶段升级既属执行安全也属合规）。
DIMENSIONS: Dict[str, frozenset] = {
    "content_safety": frozenset({
        "prompt_injection", "indirect_prompt_injection", "jailbreak", "role_play_attack",
        "goal_hijacking", "social_engineering", "evasion", "reconnaissance",
        "sensitive_probe", "suspicious_content",
    }),
    "data_security": frozenset({
        "data_exfiltration", "data_poisoning", "data_destruction",
        "sensitive_output_redacted", "retrieval_prompt_injection",
        "retrieval_padding_poisoning",
    }),
    "execution_safety": frozenset({
        "command_execution", "code_injection", "sql_injection", "privilege_bypass",
        "tool_destructive_sql", "tool_command_injection", "tool_path_traversal",
        "taint_escalation", "gateway_unavailable",
    }),
    # 本系统未加载第三方 MCP 组件，该维度暂无数据；保留键位以对齐赛题的维度划分，
    # 并标注为 0 而不是隐瞒——这本身就是可审计的信息。
    "supply_chain": frozenset({
        "dynamic_execution", "subprocess", "covert_network", "secret_access",
        "fs_escape", "obfuscation", "declaration_mismatch", "undeclared_dependency",
    }),
    "compliance": frozenset({
        "taint_escalation", "gateway_unavailable", "approval_required",
    }),
}

# 决策本身也算合规维度：转人工审批是治理动作
_COMPLIANCE_DECISIONS = frozenset({"approval_required"})


def _payload_of(event: Dict[str, Any]) -> Dict[str, Any]:
    payload = event.get("payload")
    return payload if isinstance(payload, dict) else {}


def build_evidence_bundle(trace_id: str) -> Dict[str, Any]:
    """聚合一条 trace 的完整审计证据，供攻击复现与问题定位使用。"""
    events = get_hook_audit_store().list_events(trace_id)
    taint = get_taint_ledger().snapshot(trace_id)

    timeline: List[Dict[str, Any]] = []
    for event in events:
        payload = _payload_of(event)
        timeline.append({
            "seq": event.get("seq"),
            "ts": event.get("created_at"),
            "event_type": event.get("event_type"),
            "stage": payload.get("stage"),
            "source_type": payload.get("source_type"),
            "agent_name": payload.get("agent_name"),
            "tool_name": payload.get("tool_name"),
            "decision": payload.get("decision"),
            "risk_score": payload.get("risk_score"),
            "risk_level": payload.get("risk_level"),
            "labels": payload.get("labels") or [],
            "evidence": payload.get("evidence") or [],
            "event_hash": event.get("event_hash"),
            "previous_event_hash": event.get("previous_event_hash"),
        })

    blocked = [item for item in timeline if item["decision"] == "block"]
    modified = [item for item in timeline if item["decision"] == "modified"]
    all_labels = sorted({label for item in timeline for label in item["labels"]})
    stages = sorted({item["stage"] for item in timeline if item["stage"]})

    return {
        "trace_id": trace_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "event_count": len(timeline),
            "blocked_count": len(blocked),
            "modified_count": len(modified),
            "tainted": bool(taint.get("tainted")),
            "max_risk_score": max((item["risk_score"] or 0 for item in timeline), default=0),
            "stages": stages,
            "labels": all_labels,
        },
        "timeline": timeline,
        "taint": taint,
        "integrity": {
            # 哈希链校验：任一事件被改、被删或换序都会返回 valid=False
            "hash_chain": get_hook_audit_store().verify(trace_id),
        },
        "metrics": collect_metrics(trace_id),
    }


def collect_metrics(trace_id: Optional[str] = None) -> Dict[str, Any]:
    """从审计事件汇总多维指标。``trace_id`` 为空时统计全部。"""
    events = get_hook_audit_store().list_events(trace_id)

    by_stage: Counter = Counter()
    by_decision: Counter = Counter()
    by_label: Counter = Counter()
    by_risk_level: Counter = Counter()
    by_dimension: Counter = Counter({name: 0 for name in DIMENSIONS})
    trace_ids = set()

    for event in events:
        payload = _payload_of(event)
        trace_ids.add(event.get("trace_id"))
        if payload.get("stage"):
            by_stage[payload["stage"]] += 1
        by_decision[payload.get("decision") or "unknown"] += 1
        by_risk_level[payload.get("risk_level") or "unknown"] += 1

        labels = payload.get("labels") or []
        for label in labels:
            by_label[label] += 1
            for dimension, members in DIMENSIONS.items():
                if label in members:
                    by_dimension[dimension] += 1
        if payload.get("decision") in _COMPLIANCE_DECISIONS:
            by_dimension["compliance"] += 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "trace_id": trace_id or "",
        "total_events": sum(by_stage.values()),
        "trace_count": len(trace_ids),
        "by_stage": dict(by_stage),
        "by_decision": dict(by_decision),
        "by_label": dict(by_label),
        "by_risk_level": dict(by_risk_level),
        "by_dimension": {name: by_dimension[name] for name in DIMENSIONS},
    }
