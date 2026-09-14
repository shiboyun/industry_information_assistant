"""统一工具安全网关：策略、审批、任务链风险和审计哈希链。"""
import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from models.security_tools import ToolApprovalRequest, ToolInvocation, ToolSecurityEvent
from models.user import User
from .registry import ToolProfile, get_tool_profile


@dataclass
class ToolAuthorizationResult:
    invocation: ToolInvocation
    approval: Optional[ToolApprovalRequest] = None

    @property
    def allowed(self) -> bool:
        return self.invocation.decision == "allow"

    @property
    def pending(self) -> bool:
        return self.invocation.decision == "approval_required"


class ToolSecurityGateway:
    """所有智能体工具调用必须经由此类完成安全决策。"""

    POLICY_VERSION = "tool-security-v1"
    CHAIN_BLOCK_THRESHOLD = 120

    def __init__(self, db: Session):
        self.db = db

    @staticmethod
    def effective_role(user: Optional[User]) -> str:
        if user is None:
            return "operator"
        if user.is_superuser:
            return "security_admin"
        return user.role or "operator"

    @staticmethod
    def _hash(value: Any) -> str:
        raw = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def _safe_params(params: Dict[str, Any]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        sensitive_names = {"content", "code", "report_content", "token", "password", "api_key", "authorization"}
        for key, value in params.items():
            if key.lower() in sensitive_names:
                result[key] = f"<redacted:{len(str(value))}>"
            elif isinstance(value, str) and len(value) > 300:
                result[key] = value[:300] + "..."
            else:
                result[key] = value
        return result

    def _append_event(self, trace_id: str, invocation_id, event_type: str, payload: Dict[str, Any]) -> ToolSecurityEvent:
        previous = (
            self.db.query(ToolSecurityEvent)
            .filter(ToolSecurityEvent.trace_id == trace_id)
            .order_by(ToolSecurityEvent.created_at.desc())
            .first()
        )
        previous_hash = previous.event_hash if previous else None
        event_hash = self._hash({
            "trace_id": trace_id,
            "invocation_id": str(invocation_id) if invocation_id else None,
            "event_type": event_type,
            "payload": payload,
            "previous_event_hash": previous_hash,
        })
        event = ToolSecurityEvent(
            trace_id=trace_id,
            invocation_id=invocation_id,
            event_type=event_type,
            payload=payload,
            previous_event_hash=previous_hash,
            event_hash=event_hash,
        )
        self.db.add(event)
        return event

    def record_event(
        self,
        trace_id: str,
        event_type: str,
        payload: Dict[str, Any],
        invocation_id=None,
    ) -> ToolSecurityEvent:
        """Append a generic security event to the same verifiable hash chain."""
        if invocation_id:
            invocation_id = uuid.UUID(str(invocation_id))
        event = self._append_event(trace_id, invocation_id, event_type, payload)
        self.db.commit()
        self.db.refresh(event)
        return event

    def _validate_params(self, tool_name: str, params: Dict[str, Any]) -> List[str]:
        evidence: List[str] = []
        if tool_name == "sandbox_file_write":
            path = str(params.get("path", ""))
            if not path or path.startswith(("/", "\\")) or ".." in path.replace("\\", "/").split("/"):
                evidence.append("SANDBOX-PATH-001: 文件路径越权或无效")
        if tool_name == "sandbox_command" and params.get("command") not in {"runtime_info", "python_version"}:
            evidence.append("COMMAND-WHITELIST-001: 命令不在白名单")
        if tool_name == "text2sql_query":
            sql = str(params.get("sql", ""))
            if sql and re.search(r"\b(drop|delete|update|insert|alter|truncate|grant|revoke)\b", sql, re.I):
                evidence.append("SQL-READONLY-001: 检测到非只读 SQL")
        return evidence

    def authorize(
        self,
        tool_name: str,
        params: Dict[str, Any],
        actor: Optional[User] = None,
        trace_id: Optional[str] = None,
        agent_name: str = "agent",
        source_type: str = "user_input",
        upstream_risk_score: int = 0,
        risk_labels: Optional[List[str]] = None,
        evidence: Optional[List[str]] = None,
    ) -> ToolAuthorizationResult:
        trace_id = trace_id or uuid.uuid4().hex
        profile = get_tool_profile(tool_name)
        role = self.effective_role(actor)
        evidence = list(evidence or []) + list(risk_labels or [])

        if profile is None:
            risk_score, risk_level, decision, policy_id = 100, "critical", "block", "TOOL-REGISTRY-001"
            evidence.append("工具未注册，禁止执行")
        else:
            invalid_evidence = self._validate_params(tool_name, params)
            evidence.extend(invalid_evidence)
            call_count = self.db.query(ToolInvocation).filter(
                ToolInvocation.trace_id == trace_id,
                ToolInvocation.tool_name == tool_name,
            ).count()
            chain_risk = sum(
                row[0] for row in self.db.query(ToolInvocation.risk_score).filter(
                    ToolInvocation.trace_id == trace_id
                ).all()
            )
            risk_score = min(100, max(profile.base_risk, int(upstream_risk_score)) + min(chain_risk // 8, 25))
            policy_id = profile.policy_id
            if invalid_evidence:
                risk_score, risk_level, decision = 100, "critical", "block"
            elif role not in profile.allowed_roles:
                risk_score, risk_level, decision = 100, "critical", "block"
                evidence.append("RBAC-TOOL-001: 当前角色无权调用该工具")
            elif call_count >= profile.max_calls_per_trace:
                risk_score, risk_level, decision = 80, "critical", "block"
                evidence.append("CHAIN-LIMIT-001: 单任务工具调用次数超限")
            elif chain_risk >= self.CHAIN_BLOCK_THRESHOLD:
                risk_score, risk_level, decision = 80, "critical", "block"
                evidence.append("CHAIN-RISK-001: 任务链累计风险超限")
            elif profile.approval_required or risk_score >= 60:
                risk_level, decision = "high", "approval_required"
            elif risk_score >= 30:
                risk_level, decision = "medium", "allow"
            else:
                risk_level, decision = "low", "allow"

        invocation = ToolInvocation(
            trace_id=trace_id,
            actor_id=actor.id if actor else None,
            agent_name=agent_name,
            tool_name=tool_name,
            source_type=source_type,
            safe_params=self._safe_params(params),
            execution_params=params,
            params_hash=self._hash(params),
            risk_score=risk_score,
            risk_level=risk_level,
            decision=decision,
            status="pending" if decision == "approval_required" else ("blocked" if decision == "block" else "allowed"),
            policy_id=policy_id,
            evidence=evidence,
        )
        self.db.add(invocation)
        self.db.flush()
        self._append_event(trace_id, invocation.id, "tool_authorized", {
            "tool_name": tool_name,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "decision": decision,
            "policy_id": policy_id,
            "evidence": evidence,
        })

        approval = None
        if decision == "approval_required":
            approval = ToolApprovalRequest(
                invocation_id=invocation.id,
                requester_id=actor.id if actor else None,
                # 资料入库与人工审批不使用短时自动失效；保留字段兼容旧表。
                expires_at=datetime.utcnow() + timedelta(days=3650),
            )
            self.db.add(approval)
            self.db.flush()
            self._append_event(trace_id, invocation.id, "approval_requested", {"approval_id": str(approval.id)})

        self.db.commit()
        self.db.refresh(invocation)
        if approval:
            self.db.refresh(approval)
        return ToolAuthorizationResult(invocation=invocation, approval=approval)

    def claim_approval(self, approval_id: str, approver: User) -> ToolApprovalRequest:
        if self.effective_role(approver) not in {"approver", "security_admin"}:
            raise PermissionError("当前账号没有领取审批请求的权限")
        # 条件更新在 PostgreSQL 中是原子的。只有 pending 请求可被首次领取。
        updated = self.db.query(ToolApprovalRequest).filter(
            ToolApprovalRequest.id == approval_id,
            ToolApprovalRequest.status == "pending",
        ).update({
            ToolApprovalRequest.status: "claimed",
            ToolApprovalRequest.claimant_id: approver.id,
            ToolApprovalRequest.claimed_at: datetime.utcnow(),
        }, synchronize_session=False)
        if updated != 1:
            self.db.rollback()
            raise ValueError("该请求已被其他审批员领取或已处理")
        self.db.commit()
        approval = self.db.query(ToolApprovalRequest).filter(ToolApprovalRequest.id == approval_id).first()
        invocation = self.db.query(ToolInvocation).filter(ToolInvocation.id == approval.invocation_id).first()
        self._append_event(invocation.trace_id, invocation.id, "approval_claimed", {
            "approval_id": str(approval.id), "claimant_id": str(approver.id),
        })
        self.db.commit()
        self.db.refresh(approval)
        return approval

    def decide_approval(self, approval_id: str, approver: User, approved: bool, comment: Optional[str] = None) -> ToolApprovalRequest:
        approval = self.db.query(ToolApprovalRequest).filter(ToolApprovalRequest.id == approval_id).with_for_update().first()
        if not approval:
            raise ValueError("审批请求不存在")
        if self.effective_role(approver) not in {"approver", "security_admin"}:
            raise PermissionError("当前账号没有审批权限")
        if approval.requester_id and approval.requester_id == approver.id:
            raise PermissionError("操作员不能审批自己发起的请求")
        # 浏览器重试或重复点击时，向原领取人返回已经落库的最终决定。
        # 这不会再次触发工具执行，调用方应将其作为幂等成功处理。
        if approval.status in {"approved", "rejected"}:
            if approval.claimant_id != approver.id:
                raise PermissionError("只有原领取人可以查看该审批决定")
            return approval
        if approval.status != "claimed" or approval.claimant_id != approver.id:
            raise PermissionError("请先领取该审批请求，且只能处理本人领取的请求")
        invocation = self.db.query(ToolInvocation).filter(ToolInvocation.id == approval.invocation_id).first()
        if approved:
            approval.status, invocation.status = "approved", "approved"
            event_type = "approval_approved"
        else:
            approval.status, invocation.status = "rejected", "rejected"
            event_type = "approval_rejected"
        approval.approver_id = approver.id
        approval.comment = comment
        approval.decided_at = datetime.utcnow()
        self._append_event(invocation.trace_id, invocation.id, event_type, {
            "approval_id": str(approval.id), "approver_id": str(approver.id), "comment": comment or ""
        })
        self.db.commit()
        self.db.refresh(approval)
        return approval

    def close_approval(self, approval_id: str, admin: User, comment: Optional[str] = None) -> ToolApprovalRequest:
        if self.effective_role(admin) != "security_admin":
            raise PermissionError("只有安全管理员可以关闭审批请求")
        approval = self.db.query(ToolApprovalRequest).filter(ToolApprovalRequest.id == approval_id).with_for_update().first()
        if not approval:
            raise ValueError("审批请求不存在")
        if approval.status not in {"pending", "claimed"}:
            raise ValueError("只有未处理的审批请求可以关闭")
        invocation = self.db.query(ToolInvocation).filter(ToolInvocation.id == approval.invocation_id).first()
        approval.status, approval.comment, approval.decided_at = "closed", comment or "安全管理员关闭", datetime.utcnow()
        invocation.status = "closed"
        self._append_event(invocation.trace_id, invocation.id, "approval_closed", {
            "approval_id": str(approval.id), "admin_id": str(admin.id), "comment": approval.comment,
        })
        self.db.commit()
        self.db.refresh(approval)
        return approval

    def withdraw_approval(self, approval_id: str, requester: User) -> ToolApprovalRequest:
        """由发起人撤回尚未处理的请求，撤回后不会发生实际工具执行。"""
        approval = self.db.query(ToolApprovalRequest).filter(ToolApprovalRequest.id == approval_id).first()
        if not approval:
            raise ValueError("审批请求不存在")
        if approval.requester_id != requester.id:
            raise PermissionError("只能撤回本人发起的审批请求")
        if approval.status != "pending":
            raise ValueError("只有待审批请求可以撤回")
        invocation = self.db.query(ToolInvocation).filter(ToolInvocation.id == approval.invocation_id).first()
        approval.status = "withdrawn"
        approval.comment = "发起人撤回，可修改后重新提交"
        approval.decided_at = datetime.utcnow()
        invocation.status = "withdrawn"
        self._append_event(invocation.trace_id, invocation.id, "approval_withdrawn", {
            "approval_id": str(approval.id), "requester_id": str(requester.id)
        })
        self.db.commit()
        self.db.refresh(approval)
        return approval

    def record_execution(self, invocation: ToolInvocation, success: bool, result_summary: str) -> None:
        invocation.status = "executed" if success else "failed"
        invocation.result_summary = result_summary[:1000]
        self._append_event(invocation.trace_id, invocation.id, "tool_executed" if success else "tool_failed", {
            "success": success, "result_summary": invocation.result_summary
        })
        self.db.commit()

    def verify_trace(self, trace_id: str) -> Dict[str, Any]:
        events = self.db.query(ToolSecurityEvent).filter(
            ToolSecurityEvent.trace_id == trace_id
        ).order_by(ToolSecurityEvent.created_at.asc()).all()
        previous_hash = None
        for event in events:
            expected = self._hash({
                "trace_id": event.trace_id,
                "invocation_id": str(event.invocation_id) if event.invocation_id else None,
                "event_type": event.event_type,
                "payload": event.payload,
                "previous_event_hash": previous_hash,
            })
            if event.previous_event_hash != previous_hash or event.event_hash != expected:
                return {"valid": False, "event_id": str(event.id), "event_count": len(events)}
            previous_hash = event.event_hash
        return {"valid": True, "event_count": len(events)}
