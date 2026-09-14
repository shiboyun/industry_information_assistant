"""工具安全、审批与审计数据模型。"""
import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID

from core.database import Base


class ToolInvocation(Base):
    """一次工具调用的安全决策快照。"""

    __tablename__ = "tool_invocations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    trace_id = Column(String(64), index=True, nullable=False)
    actor_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    agent_name = Column(String(64), nullable=False, default="user")
    tool_name = Column(String(64), index=True, nullable=False)
    source_type = Column(String(32), nullable=False, default="user_input")
    safe_params = Column(JSONB, nullable=False, default=dict)
    execution_params = Column(JSONB, nullable=False, default=dict)
    params_hash = Column(String(64), nullable=False)
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String(16), nullable=False)
    decision = Column(String(32), nullable=False)
    status = Column(String(32), nullable=False)
    policy_id = Column(String(64), nullable=False)
    evidence = Column(JSONB, nullable=False, default=list)
    result_summary = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class ToolApprovalRequest(Base):
    """高风险工具调用的双人审批记录。"""

    __tablename__ = "tool_approval_requests"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    invocation_id = Column(UUID(as_uuid=True), ForeignKey("tool_invocations.id", ondelete="CASCADE"), unique=True, nullable=False)
    requester_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approver_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    # 领取人与最终审批人分开保存，避免多名审批员同时处理同一条高风险请求。
    claimant_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    status = Column(String(16), nullable=False, default="pending")
    comment = Column(Text)
    expires_at = Column(DateTime, nullable=False)
    claimed_at = Column(DateTime)
    decided_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class ToolSecurityEvent(Base):
    """追加式安全事件；同一 trace 使用哈希链连接。"""

    __tablename__ = "tool_security_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    trace_id = Column(String(64), index=True, nullable=False)
    invocation_id = Column(UUID(as_uuid=True), ForeignKey("tool_invocations.id", ondelete="SET NULL"), nullable=True)
    event_type = Column(String(64), nullable=False)
    payload = Column(JSONB, nullable=False, default=dict)
    previous_event_hash = Column(String(64))
    event_hash = Column(String(64), nullable=False, unique=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
