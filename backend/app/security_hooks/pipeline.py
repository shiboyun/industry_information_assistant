"""Public adapters for the generic security hook pipeline."""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

from .audit import get_hook_audit_store
from .detectors import (
    classify_text,
    classify_tool_params,
    filter_retrieval_documents,
    redact_sensitive_values,
    risk_level,
    text_from_payload,
)
from .security_log import get_security_log
from .taint import (
    POISONED_RETRIEVAL,
    SENSITIVE_OUTPUT,
    TAINT_SEVERITY,
    evaluate_taint,
    get_taint_ledger,
    max_severity,
)
from .types import HookContext, HookResult, HookStage


def run_security_hooks(
    stage: HookStage | str,
    payload: Any = None,
    trace_id: Optional[str] = None,
    source_type: str = "runtime",
    agent_name: str = "assistant",
    tool_name: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    db: Any = None,
    actor: Any = None,
) -> HookResult:
    resolved_stage = stage if isinstance(stage, HookStage) else HookStage(stage)
    context = HookContext(
        stage=resolved_stage,
        trace_id=trace_id or _resolve_trace_id(metadata),
        source_type=source_type,
        agent_name=agent_name,
        tool_name=tool_name,
        metadata=dict(metadata or {}),
    )

    if resolved_stage == HookStage.RETRIEVAL:
        result = _run_retrieval_guard(payload, context)
    elif resolved_stage == HookStage.TOOL_CALL:
        result = _run_tool_call_guard(tool_name or "unknown", payload or {}, context, db, actor)
    elif resolved_stage in {HookStage.TOOL_RESULT, HookStage.OUTPUT}:
        result = _run_output_guard(payload, context)
    else:
        result = _run_input_guard(payload, context)

    result.metadata.setdefault("trace_id", context.trace_id)
    result.metadata.setdefault("stage", context.stage.value)
    taint_state = get_taint_ledger().get(context.trace_id)
    if taint_state["flags"]:
        result.metadata["taint_flags"] = sorted(taint_state["flags"])
    _record_hook_event(context, result, db)
    return result


def _mark_taint(
    context: HookContext,
    flag: str,
    evidence: Optional[List[str]] = None,
    labels: Optional[List[str]] = None,
) -> None:
    """打污点标记并写入审计链，使跨阶段关联本身也可追溯。

    事件遵守与 Hook 事件相同的审计字段契约（阶段/决策/风险/标签/证据/元数据），
    否则审计字段完整率统计会失真。
    """
    state = get_taint_ledger().mark(context.trace_id, flag, evidence)
    try:
        _append_taint_event(context, flag, labels, evidence, state)
    except Exception:
        logger.exception("污点事件写入审计链失败：trace_id=%s flag=%s", context.trace_id, flag)


def _append_taint_event(context: HookContext, flag: str, labels, evidence, state) -> None:
    score, level = TAINT_SEVERITY.get(flag, (50, "medium"))
    payload = {
        "stage": context.stage.value,
        "source_type": context.source_type,
        "agent_name": context.agent_name,
        "tool_name": context.tool_name,
        "decision": "taint_flagged",
        "risk_score": score,
        "risk_level": level,
        "labels": list(labels or []) or [flag],
        "evidence": (evidence or [])[:10],
        "metadata": {"flag": flag, "trace_id": context.trace_id, "flags": sorted(state["flags"])},
    }
    _emit_security_log(context.trace_id, "taint_marked", payload)
    get_hook_audit_store().append(context.trace_id, "taint_marked", payload)


def _unregistered_tool_reason(tool_name: str) -> Optional[str]:
    """未注册工具即为风险。注册表不可用（独立接入场景）时跳过检查而不是误拦。"""
    try:
        from security_tools.registry import get_tool_profile
    except Exception:
        return None
    if get_tool_profile(tool_name) is None:
        return f"TOOL-REGISTRY-001: 工具 {tool_name} 未注册，禁止执行"
    return None


def _emit_security_log(trace_id: str, event_type: str, payload: Dict[str, Any]) -> None:
    """写结构化安全日志。失败只记录、不抛出——日志故障不能中断业务。"""
    try:
        get_security_log().write(event_type, payload, trace_id=trace_id)
    except Exception:
        logger.exception("安全日志写入失败：trace_id=%s event_type=%s", trace_id, event_type)


def guard_user_input(
    text: str,
    trace_id: Optional[str] = None,
    source_type: str = "user_input",
    metadata: Optional[Dict[str, Any]] = None,
    db: Any = None,
    actor: Any = None,
) -> HookResult:
    return run_security_hooks(HookStage.USER_INPUT, text, trace_id, source_type, "user", metadata=metadata, db=db, actor=actor)


def guard_retrieval_results(
    question: str,
    documents: List[Dict[str, Any]],
    trace_id: Optional[str] = None,
    source_type: str = "knowledge_retrieval",
    metadata: Optional[Dict[str, Any]] = None,
    db: Any = None,
    actor: Any = None,
) -> HookResult:
    hook_metadata = dict(metadata or {})
    hook_metadata["question"] = question
    return run_security_hooks(
        HookStage.RETRIEVAL,
        documents,
        trace_id=trace_id,
        source_type=source_type,
        agent_name=hook_metadata.get("agent_name", "rag"),
        metadata=hook_metadata,
        db=db,
        actor=actor,
    )


def guard_tool_call(
    tool_name: str,
    params: Dict[str, Any],
    context: Any = None,
    trace_id: Optional[str] = None,
    source_type: str = "model_action",
    metadata: Optional[Dict[str, Any]] = None,
    db: Any = None,
    actor: Any = None,
) -> HookResult:
    context_metadata = _metadata_from_context(context)
    context_metadata.update(metadata or {})
    return run_security_hooks(
        HookStage.TOOL_CALL,
        params,
        trace_id=trace_id or context_metadata.get("security_trace_id") or context_metadata.get("trace_id"),
        source_type=source_type,
        agent_name=context_metadata.get("agent_name", "react"),
        tool_name=tool_name,
        metadata=context_metadata,
        db=db or context_metadata.get("db"),
        actor=actor or context_metadata.get("current_user") or context_metadata.get("actor"),
    )


def guard_tool_result(
    tool_name: str,
    payload: Any,
    context: Any = None,
    trace_id: Optional[str] = None,
    source_type: str = "tool_result",
    metadata: Optional[Dict[str, Any]] = None,
    db: Any = None,
) -> HookResult:
    context_metadata = _metadata_from_context(context)
    context_metadata.update(metadata or {})
    return run_security_hooks(
        HookStage.TOOL_RESULT,
        payload,
        trace_id=trace_id or context_metadata.get("security_trace_id") or context_metadata.get("trace_id"),
        source_type=source_type,
        agent_name=context_metadata.get("agent_name", "react"),
        tool_name=tool_name,
        metadata=context_metadata,
        db=db or context_metadata.get("db"),
    )


def _run_input_guard(payload: Any, context: HookContext) -> HookResult:
    score, level, labels, evidence = classify_text(text_from_payload(payload))
    decision = "block" if score >= 80 and {"prompt_injection", "data_exfiltration", "command_execution"}.intersection(labels) else "allow"
    return HookResult(
        decision=decision,
        risk_score=score,
        risk_level=level,
        labels=labels,
        evidence=evidence,
        sanitized_payload=payload,
    )


def _run_retrieval_guard(payload: Any, context: HookContext) -> HookResult:
    documents = payload if isinstance(payload, list) else []
    sanitized, score, labels, evidence = filter_retrieval_documents(documents)
    filtered_count = max(0, len(documents) - len(sanitized))
    if filtered_count:
        # 召回内容被污染 → 污染整条任务链，后续出网/落地动作将被升级处置
        _mark_taint(context, POISONED_RETRIEVAL, evidence, labels)

    # 三态结果：让调用方能区分「全部被过滤」与「本来就没检索到」。
    # 此前恒返 allow，两者都表现为空列表，无法告警也无法降级。
    if documents and filtered_count >= len(documents):
        decision = "block"
        evidence = _dedupe(evidence + ["全部召回内容均被判定为不可信，已清空"])
    elif filtered_count:
        decision = "modified"
    else:
        decision = "allow"

    return HookResult(
        decision=decision,
        risk_score=score,
        risk_level=risk_level(score),
        labels=labels,
        evidence=evidence,
        sanitized_payload=sanitized,
        metadata={"filtered_count": filtered_count, "input_count": len(documents)},
    )


def _run_tool_call_guard(
    tool_name: str,
    params: Dict[str, Any],
    context: HookContext,
    db: Any,
    actor: Any,
) -> HookResult:
    score, labels, evidence = classify_tool_params(tool_name, params)
    decision = "block" if score >= 100 else "allow"
    level = risk_level(score)
    metadata: Dict[str, Any] = {}

    # 工具注册表校验**不依赖数据库**：注册表是静态声明，无 db 会话时也应拦截未知工具。
    # 此前该检查只在网关内做，而网关需要 db——独立接入或本地评测场景下未注册工具会被放行。
    unregistered = _unregistered_tool_reason(tool_name)
    if unregistered:
        decision = "block"
        labels = _dedupe(labels + ["tool_unregistered"])
        evidence = _dedupe(evidence + [unregistered])

    gateway_result = None
    if decision != "block":
        gateway_result = _authorize_with_gateway(tool_name, params, context, db, actor, score, labels, evidence)
    if gateway_result is not None:
        gateway_decision, invocation, approval, gateway_error = gateway_result
        if gateway_error:
            # fail-closed：安全控制不可用时拒绝，而不是静默放行。
            # 上一版是 `except Exception: return None`，网关一挂就退化成只做正则，
            # 且不留任何痕迹——这是安全组件里最危险的失效方式。
            decision = "block"
            labels = _dedupe(labels + ["gateway_unavailable"])
            evidence = _dedupe(evidence + [gateway_error])
            metadata["gateway_error"] = gateway_error
        else:
            decision = gateway_decision
            score = max(score, int(getattr(invocation, "risk_score", 0) or 0))
            level = getattr(invocation, "risk_level", None) or risk_level(score)
            evidence = _dedupe(evidence + [str(item) for item in (getattr(invocation, "evidence", []) or [])])
            metadata["gateway_invocation"] = invocation
            metadata["gateway_invocation_id"] = str(getattr(invocation, "id", ""))
            if approval is not None:
                metadata["approval_id"] = str(getattr(approval, "id", ""))

    # 跨阶段关联：本 trace 上累积的污点可升级处置。
    # 用 max_severity 保证只升级不降级——网关已判 block 时不会被 taint 规则放宽。
    taint_state = get_taint_ledger().get(context.trace_id)
    if taint_state["flags"]:
        escalation = evaluate_taint(taint_state["flags"], tool_name)
        if escalation:
            decision = max_severity(decision, escalation["action"])
            labels = _dedupe(labels + ["taint_escalation"])
            evidence = _dedupe(evidence + [escalation["reason"]])
            metadata["taint_policy"] = escalation["policy"]
            metadata["taint_flags"] = sorted(taint_state["flags"])

    return HookResult(
        decision=decision,
        risk_score=score,
        risk_level=level,
        labels=labels,
        evidence=evidence,
        sanitized_payload=dict(params),
        metadata=metadata,
    )


def _run_output_guard(payload: Any, context: HookContext) -> HookResult:
    sanitized, labels, evidence = redact_sensitive_values(payload)
    score = 50 if labels else 0
    if labels:
        # 本任务链已出现敏感信息 → 后续出网动作升级为人工审批
        _mark_taint(context, SENSITIVE_OUTPUT, evidence, labels)
    return HookResult(
        decision="allow",
        risk_score=score,
        risk_level=risk_level(score),
        labels=labels,
        evidence=evidence,
        sanitized_payload=sanitized,
    )


def _record_hook_event(context: HookContext, result: HookResult, db: Any = None) -> None:
    payload = {
        "stage": context.stage.value,
        "source_type": context.source_type,
        "agent_name": context.agent_name,
        "tool_name": context.tool_name,
        "decision": result.decision,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "labels": result.labels,
        "evidence": result.evidence[:10],
        "metadata": _safe_metadata(result.metadata),
    }
    try:
        get_hook_audit_store().append(context.trace_id, f"hook_{context.stage.value}", payload)
    except Exception:
        # 审计故障不中断业务，但必须可见
        logger.exception(
            "安全事件写入内存审计链失败：trace_id=%s event_type=hook_%s",
            context.trace_id,
            context.stage.value,
        )

    # 结构化安全日志：全链路可用（不依赖数据库会话），可被 SIEM 采集
    _emit_security_log(context.trace_id, f"hook_{context.stage.value}", payload)

    if db is None:
        return
    try:
        from security_tools.gateway import ToolSecurityGateway

        ToolSecurityGateway(db).record_event(
            trace_id=context.trace_id,
            event_type=f"hook_{context.stage.value}",
            payload=payload,
            invocation_id=result.metadata.get("gateway_invocation_id"),
        )
    except Exception:
        # 审计落库失败不阻断业务（内存链已写入、业务不应因审计故障中断），
        # 但必须可见——此前是静默 return，故障时没有任何痕迹。
        logger.exception(
            "安全事件落库失败（已写入内存链）：trace_id=%s event_type=hook_%s",
            context.trace_id,
            context.stage.value,
        )


def _authorize_with_gateway(
    tool_name: str,
    params: Dict[str, Any],
    context: HookContext,
    db: Any,
    actor: Any,
    score: int,
    labels: List[str],
    evidence: List[str],
) -> Optional[tuple[str, Any, Any, Optional[str]]]:
    """调用数据库化工具安全网关。

    返回 ``(decision, invocation, approval, error)``。``error`` 非空表示网关不可用，
    调用方应据此 fail-closed；返回 ``None`` 仅表示「没有数据库上下文，跳过网关」。
    """
    if db is None:
        return None
    try:
        from security_tools.gateway import ToolSecurityGateway

        authorization = ToolSecurityGateway(db).authorize(
            tool_name=tool_name,
            params=params,
            actor=actor,
            trace_id=context.trace_id,
            agent_name=context.agent_name,
            source_type=context.source_type,
            upstream_risk_score=score,
            risk_labels=labels,
            evidence=evidence,
        )
        invocation = authorization.invocation
        return invocation.decision, invocation, authorization.approval, None
    except Exception as exc:
        logger.exception(
            "工具安全网关调用失败，按 fail-closed 处理：trace_id=%s tool=%s",
            context.trace_id,
            tool_name,
        )
        return "block", None, None, f"GATEWAY-UNAVAILABLE: 工具安全网关不可用，已拒绝本次调用（{exc}）"


def _resolve_trace_id(metadata: Optional[Dict[str, Any]]) -> str:
    metadata = metadata or {}
    return str(metadata.get("security_trace_id") or metadata.get("trace_id") or metadata.get("session_id") or uuid.uuid4().hex)


def _metadata_from_context(context: Any) -> Dict[str, Any]:
    if context is None:
        return {}
    metadata = getattr(context, "metadata", None)
    return dict(metadata or {})


def _safe_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
    safe: Dict[str, Any] = {}
    for key, value in metadata.items():
        if key.startswith("_") or key in {"gateway_invocation", "db", "current_user", "actor"}:
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            safe[key] = value
        elif isinstance(value, (list, dict)):
            safe[key] = value
        else:
            safe[key] = str(value)
    return safe


def _dedupe(values: List[str]) -> List[str]:
    seen = set()
    result = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result
