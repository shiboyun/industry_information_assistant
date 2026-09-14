"""工具调用安全网关、审批与审计接口。"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from core.database import get_db
from models.security_tools import ToolApprovalRequest, ToolInvocation, ToolSecurityEvent
from models.user import User
from router.auth_router import get_current_user_required
from service.attack_detect_service import multi_source_attack_detect
from security_hooks import (
    build_evidence_bundle,
    collect_metrics,
    get_hook_audit_store,
    get_security_log,
    get_taint_ledger,
)
from security_tools.gateway import ToolSecurityGateway
from security_tools.registry import TOOL_REGISTRY
from security_tools.supply_chain import rule_catalog, scan_component
from security_tools.sandbox import (
    execute_report_export_delivery,
    execute_restricted_code,
    execute_sandbox_command,
    execute_sandbox_file_write,
)

router = APIRouter(prefix="/security", tags=["工具安全"])


class ToolInvokeRequest(BaseModel):
    tool_name: str
    params: Dict[str, Any] = Field(default_factory=dict)
    trace_id: Optional[str] = None
    agent_name: str = "operator"
    source_type: str = "user_input"
    upstream_risk_score: int = Field(0, ge=0, le=100)
    risk_labels: List[str] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)


class ApprovalDecisionRequest(BaseModel):
    approved: bool
    comment: Optional[str] = Field(None, max_length=500)


class RoleUpdateRequest(BaseModel):
    role: str


class ApprovalCloseRequest(BaseModel):
    comment: Optional[str] = Field(None, max_length=500)


class AttackDetectRequest(BaseModel):
    user_input: Optional[str] = None
    web_text: Optional[str] = None
    knowledge_text: Optional[str] = None


def serialize_datetime(value: Optional[datetime]) -> Optional[str]:
    """数据库历史记录使用无时区 UTC；接口统一返回明确的 UTC ISO 时间。"""
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def serialize_invocation(item: ToolInvocation) -> Dict[str, Any]:
    return {
        "id": str(item.id), "trace_id": item.trace_id, "actor_id": str(item.actor_id) if item.actor_id else None,
        "agent_name": item.agent_name, "tool_name": item.tool_name, "source_type": item.source_type,
        "safe_params": item.safe_params, "risk_score": item.risk_score, "risk_level": item.risk_level,
        "decision": item.decision, "status": item.status, "policy_id": item.policy_id,
        "evidence": item.evidence, "result_summary": item.result_summary,
        "created_at": serialize_datetime(item.created_at), "updated_at": serialize_datetime(item.updated_at),
    }


def serialize_approval(item: ToolApprovalRequest, invocation: Optional[ToolInvocation] = None, users: Optional[Dict] = None) -> Dict[str, Any]:
    users = users or {}
    return {
        "id": str(item.id), "invocation_id": str(item.invocation_id), "requester_id": str(item.requester_id) if item.requester_id else None,
        "approver_id": str(item.approver_id) if item.approver_id else None, "status": item.status,
        "claimant_id": str(item.claimant_id) if item.claimant_id else None,
        "requester_name": users.get(item.requester_id), "claimant_name": users.get(item.claimant_id),
        "approver_name": users.get(item.approver_id), "comment": item.comment,
        "claimed_at": serialize_datetime(item.claimed_at), "decided_at": serialize_datetime(item.decided_at),
        "created_at": serialize_datetime(item.created_at), "invocation": serialize_invocation(invocation) if invocation else None,
    }


def require_role(user: User, allowed: set[str]) -> None:
    role = ToolSecurityGateway.effective_role(user)
    if role not in allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="当前账号没有安全管理权限")


def run_demo_tool(invocation: ToolInvocation) -> Dict[str, Any]:
    if invocation.tool_name == "report_export_delivery":
        return execute_report_export_delivery(invocation.execution_params)
    if invocation.tool_name == "sandbox_file_write":
        return execute_sandbox_file_write(invocation.execution_params)
    if invocation.tool_name == "sandbox_command":
        return execute_sandbox_command(invocation.execution_params)
    if invocation.tool_name == "code_execution":
        return execute_restricted_code(invocation.execution_params)
    raise ValueError("该工具不能通过演示接口直接执行")


@router.get("/me")
async def get_security_me(current_user: User = Depends(get_current_user_required)):
    return {"user_id": str(current_user.id), "role": ToolSecurityGateway.effective_role(current_user)}


@router.post("/attack-detect")
async def detect_attack(request: AttackDetectRequest, current_user: User = Depends(get_current_user_required)):
    return multi_source_attack_detect(
        user_input=request.user_input,
        web_text=request.web_text,
        knowledge_text=request.knowledge_text,
    )


@router.get("/hooks/events")
async def list_hook_events(
    trace_id: Optional[str] = None,
    current_user: User = Depends(get_current_user_required),
):
    require_role(current_user, {"approver", "security_admin"})
    return get_hook_audit_store().list_events(trace_id)


@router.get("/hooks/verify/{trace_id}")
async def verify_hook_trace(
    trace_id: str,
    current_user: User = Depends(get_current_user_required),
):
    return get_hook_audit_store().verify(trace_id)


@router.get("/tools")
async def list_tool_profiles(current_user: User = Depends(get_current_user_required)):
    return [
        {"name": item.name, "base_risk": item.base_risk, "policy_id": item.policy_id,
         "approval_required": item.approval_required, "max_calls_per_trace": item.max_calls_per_trace}
        for item in TOOL_REGISTRY.values()
    ]


@router.post("/tools/invoke")
async def invoke_demo_tool(
    request: ToolInvokeRequest,
    current_user: User = Depends(get_current_user_required),
    db: Session = Depends(get_db),
):
    gateway = ToolSecurityGateway(db)
    result = gateway.authorize(
        tool_name=request.tool_name, params=request.params, actor=current_user, trace_id=request.trace_id,
        agent_name=request.agent_name, source_type=request.source_type,
        upstream_risk_score=request.upstream_risk_score, risk_labels=request.risk_labels, evidence=request.evidence,
    )
    invocation = result.invocation
    response = {"invocation": serialize_invocation(invocation), "approval": serialize_approval(result.approval, invocation) if result.approval else None}
    if invocation.decision == "block":
        return response
    if invocation.tool_name not in {"sandbox_file_write", "sandbox_command", "code_execution", "report_export_delivery"}:
        return response
    if result.pending:
        return response
    try:
        output = run_demo_tool(invocation)
        gateway.record_execution(invocation, True, str(output))
        response["result"] = output
    except Exception as exc:
        gateway.record_execution(invocation, False, str(exc))
        response["error"] = str(exc)
    return response


@router.get("/approvals")
async def list_approvals(
    statuses: str = "pending,claimed",
    tool_name: Optional[str] = None,
    requester_id: Optional[str] = None,
    risk_level: Optional[str] = None,
    current_user: User = Depends(get_current_user_required),
    db: Session = Depends(get_db),
):
    require_role(current_user, {"approver", "security_admin"})
    query = db.query(ToolApprovalRequest).join(ToolInvocation, ToolApprovalRequest.invocation_id == ToolInvocation.id)
    allowed_statuses = [item.strip() for item in statuses.split(",") if item.strip()]
    if allowed_statuses:
        query = query.filter(ToolApprovalRequest.status.in_(allowed_statuses))
    if tool_name:
        query = query.filter(ToolInvocation.tool_name == tool_name)
    if requester_id:
        query = query.filter(ToolApprovalRequest.requester_id == requester_id)
    if risk_level:
        query = query.filter(ToolInvocation.risk_level == risk_level)
    items = query.order_by(ToolApprovalRequest.created_at.desc()).limit(100).all()
    invocations = {item.id: item for item in db.query(ToolInvocation).filter(ToolInvocation.id.in_([x.invocation_id for x in items])).all()} if items else {}
    user_ids = {value for item in items for value in (item.requester_id, item.claimant_id, item.approver_id) if value}
    users = {user.id: user.username for user in db.query(User).filter(User.id.in_(user_ids)).all()} if user_ids else {}
    return [serialize_approval(item, invocations.get(item.invocation_id), users) for item in items]


@router.get("/approvals/mine")
async def list_my_approvals(
    current_user: User = Depends(get_current_user_required),
    db: Session = Depends(get_db),
):
    """发起人查看自己的审批队列，包含待审批和最近已处理记录。"""
    items = (
        db.query(ToolApprovalRequest)
        .filter(ToolApprovalRequest.requester_id == current_user.id)
        .order_by(ToolApprovalRequest.created_at.desc())
        .limit(50)
        .all()
    )
    invocations = {
        item.id: item
        for item in db.query(ToolInvocation).filter(
            ToolInvocation.id.in_([request.invocation_id for request in items])
        ).all()
    } if items else {}
    return [serialize_approval(item, invocations.get(item.invocation_id)) for item in items]


@router.post("/approvals/{approval_id}/claim")
async def claim_approval(
    approval_id: str,
    current_user: User = Depends(get_current_user_required),
    db: Session = Depends(get_db),
):
    try:
        approval = ToolSecurityGateway(db).claim_approval(approval_id, current_user)
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    invocation = db.query(ToolInvocation).filter(ToolInvocation.id == approval.invocation_id).first()
    if invocation and invocation.tool_name == "knowledge_base_ingest":
        from models.knowledge import QuarantinedKnowledgeUpload
        upload = db.query(QuarantinedKnowledgeUpload).filter(
            QuarantinedKnowledgeUpload.invocation_id == invocation.id,
            QuarantinedKnowledgeUpload.status == "pending",
        ).first()
        if upload:
            upload.status = "claimed"
            db.commit()
    return {"approval": serialize_approval(approval, invocation), "invocation": serialize_invocation(invocation)}


@router.post("/approvals/{approval_id}/decision")
async def decide_approval(
    approval_id: str,
    request: ApprovalDecisionRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user_required),
    db: Session = Depends(get_db),
):
    gateway = ToolSecurityGateway(db)
    try:
        approval = gateway.decide_approval(approval_id, current_user, request.approved, request.comment)
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    invocation = db.query(ToolInvocation).filter(ToolInvocation.id == approval.invocation_id).first()
    response = {"approval": serialize_approval(approval, invocation), "invocation": serialize_invocation(invocation)}
    if invocation.tool_name == "knowledge_base_ingest":
        # 已执行过的批准请求只返回既有结果，绝不再次推广或执行。
        if invocation.status in {"executed", "failed"}:
            return response
        from router.knowledge_router import close_quarantined_upload, promote_quarantined_upload
        if approval.status == "approved":
            document = promote_quarantined_upload(str(invocation.id), db, background_tasks)
            response["result"] = {"document_id": str(document.id), "status": "processing"} if document else {"status": "not_promoted"}
            ToolSecurityGateway(db).record_execution(
                invocation, document is not None,
                "隔离资料已转入正式处理队列" if document else "隔离资料未能转入正式处理队列",
            )
        else:
            close_quarantined_upload(str(invocation.id), "rejected", db)
        return response
    if approval.status != "approved" or invocation.tool_name not in {"sandbox_file_write", "sandbox_command", "code_execution", "report_export_delivery"}:
        return response
    try:
        output = run_demo_tool(invocation)
        gateway.record_execution(invocation, True, str(output))
        response["result"] = output
    except Exception as exc:
        gateway.record_execution(invocation, False, str(exc))
        response["error"] = str(exc)
    return response


@router.post("/approvals/{approval_id}/close")
async def close_approval(
    approval_id: str,
    request: ApprovalCloseRequest,
    current_user: User = Depends(get_current_user_required),
    db: Session = Depends(get_db),
):
    try:
        approval = ToolSecurityGateway(db).close_approval(approval_id, current_user, request.comment)
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    invocation = db.query(ToolInvocation).filter(ToolInvocation.id == approval.invocation_id).first()
    if invocation and invocation.tool_name == "knowledge_base_ingest":
        from router.knowledge_router import close_quarantined_upload
        # 管理员关闭等同于终止入库申请，隔离副本不得保留为可继续处理的资料。
        close_quarantined_upload(str(invocation.id), "closed", db)
    return {"approval": serialize_approval(approval, invocation), "invocation": serialize_invocation(invocation)}


@router.post("/approvals/{approval_id}/withdraw")
async def withdraw_approval(
    approval_id: str,
    current_user: User = Depends(get_current_user_required),
    db: Session = Depends(get_db),
):
    gateway = ToolSecurityGateway(db)
    try:
        approval = gateway.withdraw_approval(approval_id, current_user)
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    invocation = db.query(ToolInvocation).filter(ToolInvocation.id == approval.invocation_id).first()
    if invocation and invocation.tool_name == "knowledge_base_ingest":
        from router.knowledge_router import close_quarantined_upload
        close_quarantined_upload(str(invocation.id), "withdrawn", db)
    return {"approval": serialize_approval(approval, invocation), "invocation": serialize_invocation(invocation)}


@router.get("/traces/{trace_id}")
async def get_trace(
    trace_id: str,
    current_user: User = Depends(get_current_user_required),
    db: Session = Depends(get_db),
):
    invocations = db.query(ToolInvocation).filter(ToolInvocation.trace_id == trace_id).order_by(ToolInvocation.created_at.asc()).all()
    role = ToolSecurityGateway.effective_role(current_user)
    if role not in {"approver", "security_admin"} and any(item.actor_id != current_user.id for item in invocations):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="只能查看本人调用链")
    events = db.query(ToolSecurityEvent).filter(ToolSecurityEvent.trace_id == trace_id).order_by(ToolSecurityEvent.created_at.asc()).all()
    return {
        "trace_id": trace_id,
        "invocations": [serialize_invocation(item) for item in invocations],
        "events": [{"id": str(item.id), "event_type": item.event_type, "payload": item.payload,
                    "previous_event_hash": item.previous_event_hash, "event_hash": item.event_hash, "created_at": serialize_datetime(item.created_at)} for item in events],
        "integrity": ToolSecurityGateway(db).verify_trace(trace_id),
        # 跨阶段污点状态：本 trace 上累积的关联风险（检索污染 / 敏感信息）
        "taint": get_taint_ledger().snapshot(trace_id),
    }


@router.post("/users/{user_id}/role")
async def update_user_role(
    user_id: str,
    request: RoleUpdateRequest,
    current_user: User = Depends(get_current_user_required),
    db: Session = Depends(get_db),
):
    require_role(current_user, {"security_admin"})
    if request.role not in {"operator", "approver", "security_admin"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="不支持的角色")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="用户不存在")
    user.role = request.role
    db.commit()
    return {"user_id": str(user.id), "role": user.role}


# ==================== 审计证据与多维指标（赛题方向四） ====================

@router.get("/metrics")
async def get_security_metrics(
    trace_id: Optional[str] = None,
    current_user: User = Depends(get_current_user_required),
):
    """多维度安全指标：按阶段 / 决策 / 标签 / 风险等级 / 安全维度汇总。

    安全维度对齐赛题要求：数据安全、内容安全、执行安全、供应链安全、合规风险。
    供应链维度当前恒为 0——本系统未加载第三方 MCP 组件，
    如实反映而不是隐瞒，这本身就是可审计的信息。
    """
    return collect_metrics(trace_id)


@router.get("/logs/tail")
async def tail_security_logs(
    limit: int = 100,
    current_user: User = Depends(get_current_user_required),
):
    """最近若干条结构化安全日志（供安全控制台展示）。

    完整日志以 JSON Lines 落盘（默认 `logs/security_events.jsonl`），
    可被 SIEM / ELK / Filebeat 直接采集。
    """
    log = get_security_log()
    return {
        "path": str(log.path),
        "enabled": log.enabled,
        "events": log.tail(limit=limit),
    }


@router.get("/traces/{trace_id}/evidence")
async def get_trace_evidence(
    trace_id: str,
    current_user: User = Depends(get_current_user_required),
):
    """导出某条 trace 的审计证据包（攻击复现 / 问题定位）。

    聚合：完整事件时间线（含每步的判定与依据）、污点状态、哈希链完整性校验、
    以及该 trace 的分项指标。任一事件被改、删或换序，`integrity.hash_chain.valid`
    会返回 false。
    """
    return build_evidence_bundle(trace_id)


# ==================== 供应链安全（插件 / Skill / 脚本） ====================

class SupplyChainScanRequest(BaseModel):
    """静态扫描请求。

    刻意只接受**源码文本**而不是文件路径：`/evaluate/batch` 接受任意路径的写法
    会引入任意文件读取面，这里不重蹈覆辙。需要扫描磁盘上的组件请用
    `app/scripts/scan_plugin.py`（本地 CLI，不经网络）。
    """

    source: str = Field(..., description="组件源码文本")
    name: str = Field("unnamed-component", description="组件名")
    declared: Optional[Dict[str, Any]] = Field(
        None, description="组件清单声明（permissions / dependencies / reviewed 等）"
    )


@router.get("/supply-chain/rules")
async def list_supply_chain_rules(
    current_user: User = Depends(get_current_user_required),
):
    """供应链扫描规则目录。"""
    return {"rules": rule_catalog()}


@router.post("/supply-chain/scan")
async def scan_supply_chain(
    request: SupplyChainScanRequest,
    current_user: User = Depends(get_current_user_required),
):
    """静态扫描一个插件/Skill/脚本组件，返回发现项、评分、评级与发布策略状态。"""
    report = scan_component(request.source, name=request.name, declared=request.declared)
    return report.to_dict()
