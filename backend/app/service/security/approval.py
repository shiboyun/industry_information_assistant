"""
关键操作审批模块

高危操作(如命令执行、文件写删)在真正执行前，会生成一条审批请求，
由人工通过接口 approve / deny。审批通过后可重新执行该操作。
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional


@dataclass
class ApprovalRequest:
    """一条审批请求"""

    id: str
    tool: str
    params: Dict[str, Any]
    risk_level: str
    reason: str
    handler: Optional[Callable] = None   # 原始处理器(批准后用于重新执行)
    status: str = "pending"              # pending / approved / denied
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    decided_at: Optional[str] = None
    user_id: Optional[str] = None        # 发起审批的用户(身份绑定)
    username: Optional[str] = None
    session_id: Optional[str] = None     # 归属会话

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tool": self.tool,
            "params": self.params,
            "risk_level": self.risk_level,
            "reason": self.reason,
            "status": self.status,
            "created_at": self.created_at,
            "decided_at": self.decided_at,
            "user_id": self.user_id,
            "username": self.username,
            "session_id": self.session_id,
        }


class ApprovalStore:
    """审批请求存储(内存版，演示用；生产可落库)"""

    def __init__(self):
        self._requests: Dict[str, ApprovalRequest] = {}

    def create(
        self,
        tool: str,
        params: Dict[str, Any],
        risk_level: str,
        reason: str,
        handler: Optional[Callable] = None,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> ApprovalRequest:
        req = ApprovalRequest(
            id=uuid.uuid4().hex[:12],
            tool=tool,
            params=params,
            risk_level=risk_level,
            reason=reason,
            handler=handler,
            user_id=user_id,
            username=username,
            session_id=session_id,
        )
        self._requests[req.id] = req
        return req

    def get(self, approval_id: str) -> Optional[ApprovalRequest]:
        return self._requests.get(approval_id)

    def approve(self, approval_id: str) -> Optional[ApprovalRequest]:
        req = self._requests.get(approval_id)
        if req and req.status == "pending":
            req.status = "approved"
            req.decided_at = datetime.now().isoformat()
        return req

    def deny(self, approval_id: str) -> Optional[ApprovalRequest]:
        req = self._requests.get(approval_id)
        if req and req.status == "pending":
            req.status = "denied"
            req.decided_at = datetime.now().isoformat()
        return req

    def list(self, status: Optional[str] = None) -> List[ApprovalRequest]:
        items = list(self._requests.values())
        if status:
            items = [r for r in items if r.status == status]
        return items

    def reset(self) -> None:
        self._requests.clear()
