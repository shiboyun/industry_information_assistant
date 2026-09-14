"""Shared types for the generic security hook layer."""
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class HookStage(str, Enum):
    USER_INPUT = "user_input"
    RETRIEVAL = "retrieval"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    OUTPUT = "output"


@dataclass
class HookResult:
    decision: str = "allow"
    risk_score: int = 0
    risk_level: str = "low"
    labels: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    sanitized_payload: Any = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"

    @property
    def blocked(self) -> bool:
        return self.decision == "block"

    @property
    def pending(self) -> bool:
        return self.decision == "approval_required"

    @property
    def modified(self) -> bool:
        """载荷已被安全处理（片段被过滤 / 敏感值被脱敏），但请求本身未被拒绝。

        引入这个状态是因为此前检索层恒返回 ``allow``，调用方无法区分
        「全部召回都被过滤」与「本来就没检索到」——两者都表现为空列表，
        无法告警也无法降级。参考 NeMo Guardrails 的
        ``RailsResult(PASSED | MODIFIED | BLOCKED)`` 三态契约。
        """
        return self.decision == "modified"


@dataclass
class HookContext:
    stage: HookStage
    trace_id: str
    source_type: str = "runtime"
    agent_name: str = "assistant"
    tool_name: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
