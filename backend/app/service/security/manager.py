"""
安全管理器：统一编排「策略校验 → 审批 → 任务链阻断」

它是"感知—决策—调用—执行"全流程安全控制的核心：
- 每次工具调用都会先经过 SecurityManager.evaluate() 做安全判定
- 判定结果：allow(放行) / deny(拒绝) / pending_approval(需人工审批)
- 通过 wrap() 包装所有工具处理器，作为统一的安全网关(单点拦截)
"""

import logging
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from .approval import ApprovalStore, ApprovalRequest
from .chain import TaskChainTracker
from .policy import PolicyConfig, PolicyEngine

logger = logging.getLogger(__name__)


@dataclass
class SecurityDecision:
    """一次安全判定结果"""

    action: str  # allow / deny / pending_approval
    reason: str = ""
    risk_level: str = "low"
    policy: str = ""  # 命中的策略名(用于审计)
    approval_id: Optional[str] = None

    @property
    def allowed(self) -> bool:
        return self.action == "allow"

    @property
    def denied(self) -> bool:
        return self.action == "deny"

    @property
    def pending(self) -> bool:
        return self.action == "pending_approval"


class _RetryContext:
    """审批通过后重新执行时使用的最小上下文"""

    def __init__(self):
        self.query = ""
        self.metadata = {"session_id": "approval-retry"}
        self.collected_data: list = []
        self.insights: list = []
        self.charts: list = []


class SecurityManager:
    def __init__(self, config: Optional[PolicyConfig] = None):
        self.config = config or PolicyConfig.from_env()
        self.policy_engine = PolicyEngine(self.config)
        self.approvals = ApprovalStore()
        self.chain = TaskChainTracker(self.config)

    # ---- 会话标识 ----
    @staticmethod
    def resolve_session_id(context) -> str:
        meta = getattr(context, "metadata", None) or {}
        return meta.get("session_id") or f"ctx-{id(context)}"

    @staticmethod
    def resolve_user(context):
        """从上下文元数据中提取用户身份(用于审批/审计绑定)"""
        meta = getattr(context, "metadata", None) or {}
        return meta.get("user_id"), meta.get("username")

    # ---- 核心：安全判定 ----
    def evaluate(
        self,
        tool_name: str,
        params: Dict[str, Any],
        context,
        handler: Optional[Callable] = None,
    ) -> SecurityDecision:
        session_id = self.resolve_session_id(context)

        if self.chain.is_blocked(session_id):
            return SecurityDecision("deny", "会话已被阻断(异常任务链)", "high", "chain_block")

        risk = self.policy_engine.risk_of(tool_name, params)

        # 1) 异常任务链检测(基于历史调用)
        anomaly = self.chain.check_anomaly(session_id, tool_name, params, risk)
        if anomaly:
            self.chain.block(session_id, anomaly)
            return SecurityDecision("deny", anomaly, risk, "chain_block")

        # 2) 动态策略硬性拒绝(黑名单/白名单/路径穿越)
        deny_reason = self.policy_engine.check_deny(tool_name, params)
        if deny_reason:
            return SecurityDecision("deny", deny_reason, risk, "policy_deny")

        # 3) 关键操作审批
        if self.policy_engine.needs_approval(tool_name, params):
            if self.config.approval_mode == "manual":
                user_id, username = self.resolve_user(context)
                req = self.approvals.create(
                    tool_name, params, risk, "高危操作需人工审批", handler,
                    user_id=user_id, username=username, session_id=session_id,
                )
                return SecurityDecision(
                    "pending_approval", f"需人工审批 approval_id={req.id}", risk, "approval", req.id
                )
            if self.config.approval_mode == "auto_deny":
                return SecurityDecision(
                    "deny", "高危操作被自动拒绝(approval_mode=auto_deny)", risk, "approval"
                )
            # auto_approve → 放行

        return SecurityDecision("allow", "", risk, "allow")

    # ---- 包装工具处理器(安全网关) ----
    def wrap(self, tool_name: str, handler: Callable) -> Callable:
        async def wrapped(params, context):
            session_id = self.resolve_session_id(context)
            user_id, username = self.resolve_user(context)
            decision = self.evaluate(tool_name, params, context, handler)

            if decision.denied:
                self.chain.record(session_id, tool_name, "deny", params, decision.risk_level, decision.reason, user_id, username)
                return self._deny_result(tool_name, decision)

            if decision.pending:
                self.chain.record(session_id, tool_name, "pending", params, decision.risk_level, decision.reason, user_id, username)
                return self._deny_result(tool_name, decision)

            # allow → 真正执行
            try:
                result = await handler(params, context)
                self.chain.record(session_id, tool_name, "allow", params, decision.risk_level, "", user_id, username)
                return self._attach_decision(result, decision)
            except Exception as e:
                self.chain.record(session_id, tool_name, "error", params, decision.risk_level, str(e), user_id, username)
                raise

        return wrapped

    @staticmethod
    def _deny_result(tool_name: str, decision: SecurityDecision) -> Dict[str, Any]:
        """构造拒绝/待审批的统一返回结果"""
        result: Dict[str, Any] = {
            "success": False,
            "tool": tool_name,
            "error": decision.reason,
            "policy_decision": {
                "action": decision.action,
                "reason": decision.reason,
                "risk_level": decision.risk_level,
                "policy": decision.policy,
            },
        }
        if decision.approval_id:
            result["approval"] = {"id": decision.approval_id}
        return result

    @staticmethod
    def _attach_decision(result: Any, decision: SecurityDecision) -> Any:
        """把实际安全判定结果附加到工具返回值(便于审计/前端展示)"""
        if isinstance(result, dict):
            result.setdefault("policy_decision", {
                "action": decision.action,
                "reason": decision.reason,
                "risk_level": decision.risk_level,
                "policy": decision.policy,
            })
        return result

    # ---- 审批通过后重新执行 ----
    async def execute_approved(self, approval_id: str, context=None) -> Dict[str, Any]:
        req = self.approvals.get(approval_id)
        if not req or req.status != "approved":
            return {"success": False, "error": "审批请求不存在或尚未批准"}
        if not req.handler:
            return {"success": False, "error": "审批请求缺少可执行处理器"}

        context = context or _RetryContext()
        session_id = self.resolve_session_id(context)
        try:
            result = await req.handler(req.params, context)
            self.chain.record(session_id, req.tool, "allow", req.params, req.risk_level, "approved_retry")
            return result
        except Exception as e:
            self.chain.record(session_id, req.tool, "error", req.params, req.risk_level, str(e))
            return {"success": False, "error": str(e)}

    # ---- 动态策略 ----
    def update_policy(self, patch: Dict[str, Any]) -> Dict[str, Any]:
        self.config.update(patch)
        return self.config.to_dict()

    def get_policy(self) -> Dict[str, Any]:
        return self.config.to_dict()

    # ---- 审计 ----
    def audit(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        if session_id:
            return {"session_id": session_id, "records": self.chain.get_records(session_id)}
        return {"sessions": self.chain.get_all()}

    def reset(self) -> None:
        self.chain.reset()
        self.approvals.reset()


# 全局单例(供 ToolExecutor 与路由共享同一份策略/审批/审计状态)
_security_manager: Optional[SecurityManager] = None


def get_security_manager() -> SecurityManager:
    global _security_manager
    if _security_manager is None:
        _security_manager = SecurityManager()
    return _security_manager
