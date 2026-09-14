"""跨阶段污点传播（cross-stage taint propagation）。

把「单点风险打分」升级为「跨阶段关联」：某个阶段发现的风险会污染整条 trace，
后续高风险动作据此升级处置。这对应赛题方向一的「关联分析」与方向二的
「异常任务链阻断」——此前系统只有 ``chain_risk // 8`` 的粗略加权，无法表达
「检索到污染后禁止直接导出」这类语义规则。

参考思路来自 Invariant 的 trace 规则思想（Apache-2.0），本模块为轻量重写。
"""
from __future__ import annotations

import threading
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Set

# ---- 污点标记 ----
POISONED_RETRIEVAL = "poisoned_retrieval"   # 召回内容中发现注入/投毒片段
SENSITIVE_OUTPUT = "sensitive_output"       # 工具结果中出现敏感信息并已脱敏

# ---- 出网/落地类动作：污点存在时升级处置 ----
OUTBOUND_ACTIONS: FrozenSet[str] = frozenset({
    "report_export_delivery",   # 报告外发
    "sandbox_file_write",       # 落地文件
    "knowledge_base_ingest",    # 写入知识库
    "code_execution",           # 执行代码
    "sandbox_command",          # 执行命令
    "http_request",             # 任意接口调用
})

_SEVERITY = {"allow": 0, "approval_required": 1, "block": 2}

_MAX_EVIDENCE = 20

# 污点的固有风险等级：用于让污点事件与 Hook 事件遵守同一套审计字段契约
TAINT_SEVERITY: Dict[str, tuple] = {
    POISONED_RETRIEVAL: (80, "high"),
    SENSITIVE_OUTPUT: (50, "medium"),
}


def _rule_for(flag: str, tool_name: str) -> Optional[Dict[str, str]]:
    if tool_name not in OUTBOUND_ACTIONS:
        return None
    if flag == POISONED_RETRIEVAL:
        return {
            "action": "block",
            "reason": f"TAINT-CHAIN-001: 本任务链已检索到污染内容，禁止执行出网/落地动作 {tool_name}",
            "policy": "TAINT-CHAIN-001",
        }
    if flag == SENSITIVE_OUTPUT:
        return {
            "action": "approval_required",
            "reason": f"TAINT-CHAIN-002: 本任务链已出现敏感信息，动作 {tool_name} 需人工审批",
            "policy": "TAINT-CHAIN-002",
        }
    return None


def evaluate_taint(flags: Iterable[str], tool_name: str) -> Optional[Dict[str, str]]:
    """根据 trace 上的污点标记，判定某工具调用是否需要升级处置。

    返回 ``None`` 表示无需升级；否则返回含 ``action`` / ``reason`` / ``policy`` 的字典。
    多条规则命中时取最严格的一条。
    """
    candidates = [rule for flag in flags if (rule := _rule_for(flag, tool_name))]
    if not candidates:
        return None
    return max(candidates, key=lambda rule: _SEVERITY[rule["action"]])


def max_severity(*actions: str) -> str:
    """取最严格的决策，用于「只允许升级、不允许降级」。"""
    return max(actions, key=lambda action: _SEVERITY.get(action, 0))


class TaintLedger:
    """按 trace_id 记录污点状态的进程内账本（有界，防内存泄漏）。"""

    def __init__(self, max_traces: int = 2000):
        self._max_traces = max(1, int(max_traces))
        self._traces: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self._lock = threading.Lock()

    def __len__(self) -> int:
        with self._lock:
            return len(self._traces)

    def _entry(self, trace_id: str) -> Dict[str, Any]:
        entry = self._traces.get(trace_id)
        if entry is None:
            entry = {
                "flags": set(),
                "evidence": [],
                "first_seen": datetime.now(timezone.utc).isoformat(),
            }
            self._traces[trace_id] = entry
        self._traces.move_to_end(trace_id)
        while len(self._traces) > self._max_traces:
            self._traces.popitem(last=False)
        return entry

    def mark(self, trace_id: str, flag: str, evidence: Optional[Iterable[str]] = None) -> Dict[str, Any]:
        """给某条 trace 打上污点标记；返回更新后的状态。"""
        if not trace_id or not flag:
            return {"flags": set(), "evidence": []}
        with self._lock:
            entry = self._entry(trace_id)
            entry["flags"].add(flag)
            existing = entry["evidence"]
            for item in evidence or []:
                text = str(item or "").strip()
                if text and text not in existing:
                    existing.append(text)
            del existing[_MAX_EVIDENCE:]
            return {"flags": set(entry["flags"]), "evidence": list(entry["evidence"])}

    def get(self, trace_id: str) -> Dict[str, Any]:
        with self._lock:
            entry = self._traces.get(trace_id)
            if entry is None:
                return {"flags": set(), "evidence": []}
            return {"flags": set(entry["flags"]), "evidence": list(entry["evidence"])}

    def snapshot(self, trace_id: str) -> Dict[str, Any]:
        """可 JSON 序列化的快照，用于审计与前端展示。"""
        state = self.get(trace_id)
        return {
            "trace_id": trace_id,
            "flags": sorted(state["flags"]),
            "evidence": state["evidence"],
            "tainted": bool(state["flags"]),
        }

    def reset(self) -> None:
        with self._lock:
            self._traces.clear()


_taint_ledger = TaintLedger()


def get_taint_ledger() -> TaintLedger:
    return _taint_ledger
