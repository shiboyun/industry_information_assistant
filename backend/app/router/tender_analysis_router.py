"""投标分析任务：只组织已存在的本地证据，不触发外部采集或模型调用。"""
import uuid
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from core.database import get_db
from models.knowledge import Document, KnowledgeBase
from models.news import BiddingInfo, IndustryNews
from models.tender_analysis import TenderAnalysisEvidence, TenderAnalysisTask
from models.user import User
from router.auth_router import get_current_user_required
from security_tools.gateway import ToolSecurityGateway

router = APIRouter(prefix="/tender-analysis-tasks", tags=["投标分析任务"])


class EvidenceInput(BaseModel):
    source_type: Literal["knowledge_document", "bidding", "news"]
    source_id: str


class TaskCreate(BaseModel):
    project_name: str = Field(..., min_length=1, max_length=255)
    analysis_goal: str = Field(..., min_length=1, max_length=2000)
    deadline: datetime | None = None
    public_scope: str | None = Field(None, max_length=1000)
    evidence: list[EvidenceInput] = Field(default_factory=list, max_length=12)


class TaskUpdate(BaseModel):
    conclusion_draft: str = Field(default="", max_length=8000)
    verification_items: str = Field(default="", max_length=4000)


def _task_response(task: TenderAnalysisTask, evidence: list[TenderAnalysisEvidence] | None = None) -> dict:
    data = {
        "id": str(task.id), "trace_id": task.trace_id, "project_name": task.project_name,
        "analysis_goal": task.analysis_goal, "deadline": task.deadline, "public_scope": task.public_scope,
        "conclusion_draft": task.conclusion_draft or "", "verification_items": task.verification_items or "",
        "status": task.status, "created_at": task.created_at, "updated_at": task.updated_at,
    }
    if evidence is not None:
        data["evidence"] = [{
            "id": str(item.id), "source_type": item.source_type, "source_id": str(item.source_id),
            "title": item.title, "summary": item.summary, "metadata": item.metadata_snapshot or {},
            "invocation_id": str(item.invocation_id) if item.invocation_id else None, "created_at": item.created_at,
        } for item in evidence]
    return data


def _uuid(value: str, label: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail=f"无效的{label} ID")


def _resolve_evidence(item: EvidenceInput, user: User, db: Session) -> tuple[str, str, dict, str]:
    source_id = _uuid(item.source_id, "证据")
    if item.source_type == "knowledge_document":
        record = db.query(Document).join(KnowledgeBase).filter(
            Document.id == source_id, Document.status == "completed", KnowledgeBase.user_id == user.id,
        ).first()
        if not record:
            raise HTTPException(status_code=400, detail="内部资料必须是本人已完成入库的正式文档")
        return record.filename, f"已审批内部资料，{record.chunk_count or 0} 个可检索切片", {
            "knowledge_base_id": str(record.knowledge_base_id), "file_type": record.file_type,
            "chunk_count": record.chunk_count or 0, "security_boundary": "已审批正式文档",
        }, "knowledge_search"
    if item.source_type == "bidding":
        record = db.query(BiddingInfo).filter(BiddingInfo.id == source_id).first()
        if not record:
            raise HTTPException(status_code=404, detail="本地招投标记录不存在")
        return record.title, (record.content or "")[:500], {
            "notice_type": record.notice_type, "province": record.province, "city": record.city,
            "source": record.source, "publish_time": record.publish_time.isoformat() if record.publish_time else None,
            "security_boundary": "本地已采集公开记录",
        }, "local_public_record_read"
    record = db.query(IndustryNews).filter(IndustryNews.id == source_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="本地行业资讯记录不存在")
    return record.title, (record.content or "")[:500], {
        "category": record.category, "source": record.source, "department": record.department,
        "publish_time": record.publish_time.isoformat() if record.publish_time else None,
        "security_boundary": "本地已采集公开记录",
    }, "local_public_record_read"


@router.get("/available-evidence")
def get_available_evidence(
    current_user: User = Depends(get_current_user_required), db: Session = Depends(get_db),
):
    documents = db.query(Document).join(KnowledgeBase).filter(
        KnowledgeBase.user_id == current_user.id, Document.status == "completed",
    ).order_by(Document.updated_at.desc()).limit(30).all()
    bidding = db.query(BiddingInfo).order_by(BiddingInfo.publish_time.desc()).limit(30).all()
    news = db.query(IndustryNews).order_by(IndustryNews.publish_time.desc()).limit(30).all()
    return {
        "documents": [{"id": str(item.id), "title": item.filename, "summary": f"已审批资料，{item.chunk_count or 0} 个切片"} for item in documents],
        "bidding": [{"id": str(item.id), "title": item.title, "summary": (item.content or "")[:160], "meta": item.notice_type} for item in bidding],
        "news": [{"id": str(item.id), "title": item.title, "summary": (item.content or "")[:160], "meta": item.category} for item in news],
    }


@router.get("")
def list_tasks(current_user: User = Depends(get_current_user_required), db: Session = Depends(get_db)):
    tasks = db.query(TenderAnalysisTask).filter(TenderAnalysisTask.user_id == current_user.id).order_by(TenderAnalysisTask.updated_at.desc()).all()
    return [_task_response(item) for item in tasks]


@router.post("", status_code=status.HTTP_201_CREATED)
def create_task(payload: TaskCreate, current_user: User = Depends(get_current_user_required), db: Session = Depends(get_db)):
    task = TenderAnalysisTask(
        user_id=current_user.id, trace_id=uuid.uuid4().hex, project_name=payload.project_name,
        analysis_goal=payload.analysis_goal, deadline=payload.deadline, public_scope=payload.public_scope,
    )
    db.add(task)
    db.flush()
    gateway = ToolSecurityGateway(db)
    evidence_rows = []
    seen = set()
    for item in payload.evidence:
        key = (item.source_type, item.source_id)
        if key in seen:
            continue
        seen.add(key)
        title, summary, metadata, tool_name = _resolve_evidence(item, current_user, db)
        authorization = gateway.authorize(
            tool_name=tool_name, actor=current_user, trace_id=task.trace_id,
            agent_name="tender_analysis_task", source_type=item.source_type,
            params={"task_id": str(task.id), "project_name": task.project_name, "source_id": item.source_id, "source_title": title},
        )
        if not authorization.allowed:
            raise HTTPException(status_code=409, detail="该任务的证据引用超过安全策略限额")
        row = TenderAnalysisEvidence(
            task_id=task.id, source_type=item.source_type, source_id=_uuid(item.source_id, "证据"),
            title=title, summary=summary, metadata_snapshot=metadata, invocation_id=authorization.invocation.id,
        )
        db.add(row)
        evidence_rows.append(row)
    task.status = "evidence_ready" if evidence_rows else "draft"
    db.commit()
    # 提交后重新查询，避免返回已过期/未完整刷新的 ORM 证据对象导致响应序列化失败。
    task = db.query(TenderAnalysisTask).filter(TenderAnalysisTask.id == task.id).one()
    evidence_rows = db.query(TenderAnalysisEvidence).filter(
        TenderAnalysisEvidence.task_id == task.id
    ).order_by(TenderAnalysisEvidence.created_at.asc()).all()
    return _task_response(task)


def _owned_task(task_id: str, user: User, db: Session) -> TenderAnalysisTask:
    task = db.query(TenderAnalysisTask).filter(TenderAnalysisTask.id == _uuid(task_id, "任务"), TenderAnalysisTask.user_id == user.id).first()
    if not task:
        raise HTTPException(status_code=404, detail="投标分析任务不存在")
    return task


@router.get("/{task_id}")
def get_task(task_id: str, current_user: User = Depends(get_current_user_required), db: Session = Depends(get_db)):
    task = _owned_task(task_id, current_user, db)
    evidence = db.query(TenderAnalysisEvidence).filter(TenderAnalysisEvidence.task_id == task.id).order_by(TenderAnalysisEvidence.created_at.asc()).all()
    return _task_response(task, evidence)


@router.put("/{task_id}/draft")
def update_draft(task_id: str, payload: TaskUpdate, current_user: User = Depends(get_current_user_required), db: Session = Depends(get_db)):
    task = _owned_task(task_id, current_user, db)
    task.conclusion_draft = payload.conclusion_draft
    task.verification_items = payload.verification_items
    task.status = "draft_ready" if payload.conclusion_draft.strip() else task.status
    db.commit()
    db.refresh(task)
    return _task_response(task)


@router.delete("/{task_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_task(task_id: str, current_user: User = Depends(get_current_user_required), db: Session = Depends(get_db)):
    task = _owned_task(task_id, current_user, db)
    db.delete(task)
    db.commit()
