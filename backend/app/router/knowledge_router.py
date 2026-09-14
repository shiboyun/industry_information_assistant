"""知识库管理路由"""
import os
import re
import shutil
import uuid
from typing import List
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, BackgroundTasks
from sqlalchemy.orm import Session

from core.database import get_db
from models.knowledge import KnowledgeBase, Document, QuarantinedKnowledgeUpload
from models.security_tools import ToolApprovalRequest
from models.user import User
from router.auth_router import get_current_user_required
from security_tools.gateway import ToolSecurityGateway
from schemas.knowledge import (
    KnowledgeBaseCreate,
    KnowledgeBaseUpdate,
    KnowledgeBaseResponse,
    KnowledgeBaseWithDocuments,
    DocumentResponse,
    DocumentUploadResponse,
)

router = APIRouter(prefix="/knowledge-bases", tags=["知识库管理"])

# 文件上传目录
UPLOAD_DIR = "/tmp/knowledge_uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)
QUARANTINE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "knowledge_quarantine"))
os.makedirs(QUARANTINE_DIR, exist_ok=True)

# 支持的文件类型
ALLOWED_EXTENSIONS = {
    # 文档类型
    '.pdf', '.docx', '.doc', '.txt', '.md', '.html', '.xlsx', '.xls', '.pptx', '.ppt',
    # 图片类型
    '.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp',
    # 代码/数据类型
    '.py', '.js', '.ts', '.json', '.yaml', '.yml', '.xml', '.csv',
}


def get_file_extension(filename: str) -> str:
    """获取文件扩展名"""
    return os.path.splitext(filename)[1].lower()


def _safe_filename(filename: str) -> str:
    """防止上传文件名影响隔离目录路径。"""
    return os.path.basename(filename or "upload.bin").replace("\x00", "_")[:200]


def _redact_preview(file_path: str, extension: str) -> str:
    """只为审批提供短文本预览，二进制文件不尝试解析。"""
    if extension not in {".txt", ".md", ".csv", ".json", ".yaml", ".yml", ".xml", ".html"}:
        return "该文件类型不提供文本预览；审批通过后才会进入正式解析流程。"
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as source:
            text = source.read(1600)
    except OSError:
        return "预览提取失败。"
    text = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "[已脱敏邮箱]", text)
    text = re.sub(r"(?<!\d)1[3-9]\d{9}(?!\d)", "[已脱敏手机号]", text)
    return text.strip()[:1200] or "文件无可显示文本内容。"


def serialize_quarantine(item: QuarantinedKnowledgeUpload) -> dict:
    return {
        "id": str(item.id), "knowledge_base_id": str(item.knowledge_base_id),
        "invocation_id": str(item.invocation_id) if item.invocation_id else None,
        "document_id": str(item.document_id) if item.document_id else None,
        "filename": item.filename, "file_type": item.file_type, "file_size": item.file_size,
        "status": item.status, "preview_text": item.preview_text,
        "risk_labels": item.risk_labels, "evidence": item.evidence,
        "created_at": item.created_at, "updated_at": item.updated_at,
    }


def promote_quarantined_upload(invocation_id: str, db: Session, background_tasks: BackgroundTasks) -> Document | None:
    """审批通过后的唯一正式入库入口；重复调用不会重复创建文档。"""
    upload = db.query(QuarantinedKnowledgeUpload).filter(
        QuarantinedKnowledgeUpload.invocation_id == invocation_id
    ).first()
    if not upload or upload.status not in {"pending", "claimed"}:
        return None
    kb = db.query(KnowledgeBase).filter(KnowledgeBase.id == upload.knowledge_base_id).first()
    if not kb or not os.path.exists(upload.quarantine_path):
        upload.status = "closed"
        db.commit()
        return None
    formal_path = os.path.join(UPLOAD_DIR, f"{upload.id}_{upload.filename}")
    shutil.move(upload.quarantine_path, formal_path)
    document = Document(
        knowledge_base_id=upload.knowledge_base_id, user_id=upload.user_id,
        filename=upload.filename, file_type=upload.file_type, file_size=upload.file_size,
        file_path=formal_path, status="pending",
    )
    db.add(document)
    db.flush()
    upload.document_id = document.id
    upload.status = "approved"
    kb.document_count = (kb.document_count or 0) + 1
    db.commit()
    from core.database import SessionLocal
    background_tasks.add_task(process_document, str(document.id), formal_path, kb.name, SessionLocal)
    return document


def close_quarantined_upload(invocation_id: str, final_status: str, db: Session) -> None:
    """拒绝或撤回后的隔离文件永远不得进入正式处理队列。"""
    upload = db.query(QuarantinedKnowledgeUpload).filter(
        QuarantinedKnowledgeUpload.invocation_id == invocation_id
    ).first()
    if not upload or upload.status not in {"pending", "claimed"}:
        return
    upload.status = final_status
    if os.path.exists(upload.quarantine_path):
        os.remove(upload.quarantine_path)
    db.commit()


def kb_to_response(kb: KnowledgeBase) -> KnowledgeBaseResponse:
    """将知识库模型转换为响应"""
    return KnowledgeBaseResponse(
        id=str(kb.id),
        name=kb.name,
        description=kb.description,
        document_count=kb.document_count or 0,
        created_at=kb.created_at,
        updated_at=kb.updated_at,
    )


def doc_to_response(doc: Document) -> DocumentResponse:
    """将文档模型转换为响应"""
    return DocumentResponse(
        id=str(doc.id),
        knowledge_base_id=str(doc.knowledge_base_id),
        filename=doc.filename,
        file_type=doc.file_type,
        file_size=doc.file_size,
        status=doc.status,
        chunk_count=doc.chunk_count or 0,
        error_message=doc.error_message,
        created_at=doc.created_at,
        updated_at=doc.updated_at,
    )


def process_document(document_id: str, file_path: str, kb_name: str, db_session_factory):
    """后台处理文档（使用 DocMind 解析、向量化、存储到ES）"""
    from service.docmind_service import process_document_with_docmind
    from service.milvus_service import knowledge_base_collection_name

    # 创建新的数据库会话
    db = db_session_factory()
    try:
        # 获取文档记录
        doc = db.query(Document).filter(Document.id == document_id).first()
        if not doc:
            return

        # 更新状态为处理中
        doc.status = "processing"
        db.commit()

        try:
            # 使用知识库名称作为ES索引名
            # 集合名不能使用中文等用户可见名称；Milvus 仅接受 ASCII 字母、数字和下划线。
            index_name = knowledge_base_collection_name(str(doc.knowledge_base_id))

            # 使用 DocMind 处理文档
            result = process_document_with_docmind(
                file_path=file_path,
                file_name=doc.filename,
                index_name=index_name,
            )

            if result["success"]:
                doc.status = "completed"
                doc.chunk_count = result["document_count"]
                doc.error_message = None
            else:
                doc.status = "failed"
                doc.error_message = result["message"]

        except Exception as e:
            doc.status = "failed"
            doc.error_message = str(e)

        db.commit()

    finally:
        db.close()
        # 清理临时文件
        if os.path.exists(file_path):
            os.remove(file_path)


@router.get("", response_model=List[KnowledgeBaseResponse])
async def get_knowledge_bases(
    current_user: User = Depends(get_current_user_required),
    db: Session = Depends(get_db),
):
    """获取用户的知识库列表"""
    kbs = db.query(KnowledgeBase).filter(
        KnowledgeBase.user_id == current_user.id
    ).order_by(KnowledgeBase.updated_at.desc()).all()

    return [kb_to_response(kb) for kb in kbs]


@router.post("", response_model=KnowledgeBaseResponse, status_code=status.HTTP_201_CREATED)
async def create_knowledge_base(
    kb_data: KnowledgeBaseCreate,
    current_user: User = Depends(get_current_user_required),
    db: Session = Depends(get_db),
):
    """创建知识库"""
    # 检查是否已存在同名知识库
    existing = db.query(KnowledgeBase).filter(
        KnowledgeBase.user_id == current_user.id,
        KnowledgeBase.name == kb_data.name
    ).first()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="已存在同名知识库"
        )

    kb = KnowledgeBase(
        user_id=current_user.id,
        name=kb_data.name,
        description=kb_data.description,
    )
    db.add(kb)
    db.commit()
    db.refresh(kb)

    return kb_to_response(kb)


@router.get("/{kb_id}", response_model=KnowledgeBaseWithDocuments)
async def get_knowledge_base(
    kb_id: str,
    current_user: User = Depends(get_current_user_required),
    db: Session = Depends(get_db),
):
    """获取知识库详情（包含文档列表）"""
    try:
        kb_uuid = UUID(kb_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="无效的知识库ID格式"
        )

    kb = db.query(KnowledgeBase).filter(
        KnowledgeBase.id == kb_uuid,
        KnowledgeBase.user_id == current_user.id
    ).first()

    if not kb:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="知识库不存在"
        )

    documents = db.query(Document).filter(
        Document.knowledge_base_id == kb.id
    ).order_by(Document.created_at.desc()).all()

    return KnowledgeBaseWithDocuments(
        id=str(kb.id),
        name=kb.name,
        description=kb.description,
        document_count=kb.document_count or 0,
        created_at=kb.created_at,
        updated_at=kb.updated_at,
        documents=[doc_to_response(doc) for doc in documents],
    )


@router.put("/{kb_id}", response_model=KnowledgeBaseResponse)
async def update_knowledge_base(
    kb_id: str,
    kb_data: KnowledgeBaseUpdate,
    current_user: User = Depends(get_current_user_required),
    db: Session = Depends(get_db),
):
    """更新知识库"""
    try:
        kb_uuid = UUID(kb_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="无效的知识库ID格式"
        )

    kb = db.query(KnowledgeBase).filter(
        KnowledgeBase.id == kb_uuid,
        KnowledgeBase.user_id == current_user.id
    ).first()

    if not kb:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="知识库不存在"
        )

    if kb_data.name is not None:
        # 检查是否与其他知识库重名
        existing = db.query(KnowledgeBase).filter(
            KnowledgeBase.user_id == current_user.id,
            KnowledgeBase.name == kb_data.name,
            KnowledgeBase.id != kb_uuid
        ).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="已存在同名知识库"
            )
        kb.name = kb_data.name

    if kb_data.description is not None:
        kb.description = kb_data.description

    db.commit()
    db.refresh(kb)

    return kb_to_response(kb)


@router.delete("/{kb_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_knowledge_base(
    kb_id: str,
    current_user: User = Depends(get_current_user_required),
    db: Session = Depends(get_db),
):
    """删除知识库"""
    try:
        kb_uuid = UUID(kb_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="无效的知识库ID格式"
        )

    kb = db.query(KnowledgeBase).filter(
        KnowledgeBase.id == kb_uuid,
        KnowledgeBase.user_id == current_user.id
    ).first()

    if not kb:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="知识库不存在"
        )

    db.delete(kb)
    db.commit()
    return None


@router.post("/{kb_id}/documents", response_model=DocumentUploadResponse)
async def upload_document(
    kb_id: str,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user_required),
    db: Session = Depends(get_db),
):
    """上传文档到知识库"""
    try:
        kb_uuid = UUID(kb_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="无效的知识库ID格式"
        )

    # 验证知识库存在
    kb = db.query(KnowledgeBase).filter(
        KnowledgeBase.id == kb_uuid,
        KnowledgeBase.user_id == current_user.id
    ).first()

    if not kb:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="知识库不存在"
        )

    # 验证文件类型
    ext = get_file_extension(file.filename)
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"不支持的文件类型: {ext}，支持的类型: {', '.join(ALLOWED_EXTENSIONS)}"
        )

    # 保存文件到临时目录
    safe_filename = _safe_filename(file.filename)
    file_path = os.path.join(QUARANTINE_DIR, f"{uuid.uuid4().hex}_{safe_filename}")
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"文件保存失败: {str(e)}"
        )

    # 获取文件大小
    file_size = os.path.getsize(file_path)

    # 只创建隔离申请；正式 Document 和后台解析均由审批通过后的入口创建。
    preview_text = _redact_preview(file_path, ext)
    upload = QuarantinedKnowledgeUpload(
        knowledge_base_id=kb_uuid, user_id=current_user.id, filename=safe_filename,
        file_type=ext[1:] if ext else None, file_size=file_size,
        quarantine_path=file_path, preview_text=preview_text,
    )
    db.add(upload)
    db.flush()
    authorization = ToolSecurityGateway(db).authorize(
        tool_name="knowledge_base_ingest",
        params={"quarantine_upload_id": str(upload.id), "filename": upload.filename,
                "file_type": upload.file_type, "file_size": file_size, "knowledge_base": kb.name,
                "content_preview": preview_text,
                "impact_scope": "审批通过后将进入该知识库的文档解析与检索范围"},
        actor=current_user, agent_name="knowledge_upload", source_type="knowledge_upload",
    )
    upload.invocation_id = authorization.invocation.id
    upload.upstream_risk_score = authorization.invocation.risk_score
    upload.risk_labels = ["内部资料入库", "人工审批"]
    upload.evidence = authorization.invocation.evidence
    db.commit()
    db.refresh(upload)
    return DocumentUploadResponse(
        id=str(upload.id), filename=upload.filename, process_status="pending_approval",
        message="文件已进入隔离区，等待数据安全专员审批；审批前不会解析或参与知识库检索。",
    )

    # 创建文档记录
    doc = Document(
        knowledge_base_id=kb_uuid,
        user_id=current_user.id,
        filename=file.filename,
        file_type=ext[1:] if ext else None,  # 去掉点
        file_size=file_size,
        file_path=file_path,
        status="pending",
    )
    db.add(doc)

    # 更新知识库文档计数
    kb.document_count = (kb.document_count or 0) + 1

    db.commit()
    db.refresh(doc)

    # 获取数据库会话工厂
    from core.database import SessionLocal

    # 在后台处理文档
    background_tasks.add_task(
        process_document,
        str(doc.id),
        file_path,
        kb.name,
        SessionLocal
    )

    return DocumentUploadResponse(
        id=str(doc.id),
        filename=doc.filename,
        process_status="pending",
        message="文档已上传，正在后台处理中"
    )


@router.get("/{kb_id}/quarantine")
async def get_quarantined_uploads(
    kb_id: str,
    current_user: User = Depends(get_current_user_required),
    db: Session = Depends(get_db),
):
    """发起人查看自己的隔离入库队列；不返回隔离文件的下载路径。"""
    try:
        kb_uuid = UUID(kb_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="无效的知识库 ID")
    kb = db.query(KnowledgeBase).filter(
        KnowledgeBase.id == kb_uuid, KnowledgeBase.user_id == current_user.id
    ).first()
    if not kb:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="知识库不存在")
    uploads = db.query(QuarantinedKnowledgeUpload).filter(
        QuarantinedKnowledgeUpload.knowledge_base_id == kb_uuid,
        QuarantinedKnowledgeUpload.user_id == current_user.id,
    ).order_by(QuarantinedKnowledgeUpload.created_at.desc()).all()
    return [serialize_quarantine(item) for item in uploads]


@router.post("/{kb_id}/quarantine/{upload_id}/withdraw")
async def withdraw_quarantined_upload(
    kb_id: str,
    upload_id: str,
    current_user: User = Depends(get_current_user_required),
    db: Session = Depends(get_db),
):
    try:
        kb_uuid, upload_uuid = UUID(kb_id), UUID(upload_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="无效的 ID")
    upload = db.query(QuarantinedKnowledgeUpload).filter(
        QuarantinedKnowledgeUpload.id == upload_uuid,
        QuarantinedKnowledgeUpload.knowledge_base_id == kb_uuid,
        QuarantinedKnowledgeUpload.user_id == current_user.id,
    ).first()
    if not upload:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="隔离申请不存在")
    if upload.status != "pending" or not upload.invocation_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="只有待审批申请可以撤回")
    approval = db.query(ToolApprovalRequest).filter_by(
        invocation_id=upload.invocation_id
    ).first()
    if not approval:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="审批记录不存在")
    try:
        ToolSecurityGateway(db).withdraw_approval(str(approval.id), current_user)
    except (PermissionError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    close_quarantined_upload(str(upload.invocation_id), "withdrawn", db)
    db.refresh(upload)
    return serialize_quarantine(upload)


@router.get("/{kb_id}/documents", response_model=List[DocumentResponse])
async def get_documents(
    kb_id: str,
    current_user: User = Depends(get_current_user_required),
    db: Session = Depends(get_db),
):
    """获取知识库的文档列表"""
    try:
        kb_uuid = UUID(kb_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="无效的知识库ID格式"
        )

    # 验证知识库存在
    kb = db.query(KnowledgeBase).filter(
        KnowledgeBase.id == kb_uuid,
        KnowledgeBase.user_id == current_user.id
    ).first()

    if not kb:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="知识库不存在"
        )

    documents = db.query(Document).filter(
        Document.knowledge_base_id == kb_uuid
    ).order_by(Document.created_at.desc()).all()

    return [doc_to_response(doc) for doc in documents]


@router.get("/{kb_id}/documents/{doc_id}/chunks")
async def get_document_chunks(
    kb_id: str,
    doc_id: str,
    current_user: User = Depends(get_current_user_required),
    db: Session = Depends(get_db),
):
    """获取文档的所有切片"""
    from service.milvus_service import get_milvus_service

    try:
        kb_uuid = UUID(kb_id)
        doc_uuid = UUID(doc_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="无效的ID格式"
        )

    # 验证知识库存在
    kb = db.query(KnowledgeBase).filter(
        KnowledgeBase.id == kb_uuid,
        KnowledgeBase.user_id == current_user.id
    ).first()

    if not kb:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="知识库不存在"
        )

    # 获取文档
    doc = db.query(Document).filter(
        Document.id == doc_uuid,
        Document.knowledge_base_id == kb_uuid
    ).first()

    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="文档不存在"
        )

    if doc.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="文档尚未处理完成"
        )

    # 从 Milvus 获取切片
    from service.milvus_service import knowledge_base_collection_name
    collection_name = knowledge_base_collection_name(str(kb.id))
    print(f"[get_document_chunks] 查询切片: collection={collection_name}, filename={doc.filename}")

    try:
        milvus = get_milvus_service()
        chunks = milvus.get_chunks_by_filename(collection_name, doc.filename)
        print(f"[get_document_chunks] 找到 {len(chunks)} 个切片")
    except Exception as e:
        print(f"[get_document_chunks] Milvus 查询失败: {e}")
        # 返回空结果而不是报错
        chunks = []

    return {
        "document_id": str(doc.id),
        "filename": doc.filename,
        "chunk_count": len(chunks),
        "chunks": [
            {
                "index": chunk.get("chunk_index", i),
                "content": chunk.get("content", ""),
            }
            for i, chunk in enumerate(chunks)
        ]
    }


@router.delete("/{kb_id}/documents/{doc_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_document(
    kb_id: str,
    doc_id: str,
    current_user: User = Depends(get_current_user_required),
    db: Session = Depends(get_db),
):
    """删除文档"""
    try:
        kb_uuid = UUID(kb_id)
        doc_uuid = UUID(doc_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="无效的ID格式"
        )

    # 验证知识库存在
    kb = db.query(KnowledgeBase).filter(
        KnowledgeBase.id == kb_uuid,
        KnowledgeBase.user_id == current_user.id
    ).first()

    if not kb:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="知识库不存在"
        )

    # 获取文档
    doc = db.query(Document).filter(
        Document.id == doc_uuid,
        Document.knowledge_base_id == kb_uuid
    ).first()

    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="文档不存在"
        )

    # 删除文件（如果存在）
    if doc.file_path and os.path.exists(doc.file_path):
        os.remove(doc.file_path)

    # 更新知识库文档计数
    kb.document_count = max((kb.document_count or 0) - 1, 0)

    db.delete(doc)
    db.commit()
    return None
