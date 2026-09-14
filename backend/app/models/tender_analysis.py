"""投标分析任务及其证据快照。"""
import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID

from core.database import Base


class TenderAnalysisTask(Base):
    __tablename__ = "tender_analysis_tasks"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    trace_id = Column(String(64), unique=True, nullable=False, index=True)
    project_name = Column(String(255), nullable=False)
    analysis_goal = Column(Text, nullable=False)
    deadline = Column(DateTime)
    public_scope = Column(Text)
    conclusion_draft = Column(Text, default="")
    verification_items = Column(Text, default="")
    status = Column(String(32), nullable=False, default="draft")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class TenderAnalysisEvidence(Base):
    __tablename__ = "tender_analysis_evidence"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    task_id = Column(UUID(as_uuid=True), ForeignKey("tender_analysis_tasks.id", ondelete="CASCADE"), nullable=False, index=True)
    source_type = Column(String(32), nullable=False)  # knowledge_document / bidding / news
    source_id = Column(UUID(as_uuid=True), nullable=False)
    title = Column(String(500), nullable=False)
    summary = Column(Text)
    metadata_snapshot = Column(JSONB, nullable=False, default=dict)
    invocation_id = Column(UUID(as_uuid=True), ForeignKey("tool_invocations.id", ondelete="SET NULL"))
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
