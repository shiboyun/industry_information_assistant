"""
安全控制子包：工具调用与审批控制的核心实现

组成：
- policy    细粒度权限约束 + 动态策略校验
- approval  关键操作审批
- chain     异常任务链阻断
- manager   安全管理器(统一编排 + 安全网关)

用法：
    from service.security.manager import SecurityManager, get_security_manager
"""

from .manager import SecurityManager, SecurityDecision, get_security_manager
from .policy import PolicyConfig, PolicyEngine, RISK_PROFILES
from .approval import ApprovalStore, ApprovalRequest
from .chain import TaskChainTracker

__all__ = [
    "SecurityManager",
    "SecurityDecision",
    "get_security_manager",
    "PolicyConfig",
    "PolicyEngine",
    "RISK_PROFILES",
    "ApprovalStore",
    "ApprovalRequest",
    "TaskChainTracker",
]
