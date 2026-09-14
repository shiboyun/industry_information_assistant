import os
from typing import Dict, Any, List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from starlette.status import HTTP_200_OK, HTTP_500_INTERNAL_SERVER_ERROR
from sqlalchemy.orm import Session

from core.database import get_db
from models.chat import ChatAttachment
from models.user import User
from router.auth_router import get_current_user
from service import DocumentService, WebSearchService, ChatService, SessionService, ServiceConfig
from service.retrieval_service import retrieve_content
from service.tool_qa_service import ToolQAService
from schemas import ChatRequest, LegacySessionResponse, ChatWithAttachmentsRequest

# Create router instance
router = APIRouter(prefix="/chat", tags=["chat"])

# Get service instances
def get_services():
    config = ServiceConfig.get_api_config()
    doc_service = DocumentService(
        base_url=config['base_url'],
        api_key=config['api_key']
    )
    web_service = WebSearchService(api_key=config.get('serper_api_key'))
    session_service = SessionService()
    chat_service = ChatService(doc_service, web_service, session_service)
    return {
        "chat_service": chat_service,
        "session_service": session_service,
        "default_dataset_id": config['default_dataset_id']
    }



@router.post("/session", response_model=LegacySessionResponse, status_code=HTTP_200_OK)
async def create_session(
    services: Dict[str, Any] = Depends(get_services)
):
    """
    创建新的聊天会话

    Returns:
        新创建的会话信息
    """
    session_service = services["session_service"]

    try:
        session_data = session_service.create_session()
        return LegacySessionResponse(**session_data)
    except Exception as e:
        raise HTTPException(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"创建会话失败: {str(e)}"
        )

@router.post("/completion/v1", status_code=HTTP_200_OK)
async def chat_completion(
    request: ChatRequest,
    services: Dict[str, Any] = Depends(get_services)
):
    """
    聊天补全接口，结合知识库检索和Web搜索，进行问答

    Args:
        request: 包含用户问题和会话信息的请求体

    Returns:
        流式响应，包含检索内容和模型生成内容
    """
    chat_service = services["chat_service"]
    default_dataset_id = services["default_dataset_id"]
    session_service = services["session_service"]

    # 验证会话ID（如果提供）
    if request.session_id:
        session = session_service.get_session(request.session_id)
        if not session:
            # 如果会话不存在，创建新会话
            session_data = session_service.create_session()
            request.session_id = session_data["session_id"]

    # 创建异步生成器函数
    async def generate_response():
        try:
            # 从知识库检索文档
            knowledge_docs = []
            if request.search_knowledge:
                knowledge_docs = chat_service.retrieve_from_knowledge_base(
                    question=request.question,
                    dataset_id=default_dataset_id,
                    trace_id=request.session_id,
                )

            # 从Web搜索检索信息
            web_docs = []
            if request.search_web:
                web_docs = chat_service.retrieve_from_web(
                    question=request.question,
                    trace_id=request.session_id,
                )

            # 合并文档并重排
            all_docs = knowledge_docs + web_docs
            reranked_docs = chat_service.rerank_documents(
                question=request.question,
                documents=all_docs
            )

            # 生成流式回答
            for message_chunk in chat_service.get_chat_completion(
                session_id=request.session_id,
                question=request.question,
                retrieved_content=reranked_docs
            ):
                yield message_chunk

        except Exception as e:
            # 错误处理
            error_message = f"event: error\ndata: {str(e)}\n\n"
            yield error_message

    # 返回流式响应
    return StreamingResponse(
        generate_response(),
        media_type="text/event-stream"
    )

@router.post("/completion", status_code=HTTP_200_OK)
async def chat_completion_v2(
    request: ChatRequest,
    services: Dict[str, Any] = Depends(get_services)
):
    """
    聊天补全接口v2版本，使用policy_documents索引进行检索，采用Dealer检索引擎，结合Web搜索进行问答

    Args:
        request: 包含用户问题和会话信息的请求体

    Returns:
        流式响应，包含检索内容和模型生成内容
    """
    chat_service = services["chat_service"]
    default_dataset_id = services["default_dataset_id"]
    session_service = services["session_service"]

    # 验证会话ID（如果提供）
    if request.session_id:
        session = session_service.get_session(request.session_id)
        if not session:
            # 如果会话不存在，创建新会话
            session_data = session_service.create_session()
            request.session_id = session_data["session_id"]

    # 创建异步生成器函数
    async def generate_response():
        try:
            # 从政策文档索引检索（使用新的检索方式）
            policy_docs = []
            if request.search_knowledge:
                # 使用 retrieve_content 函数进行检索，默认索引为 policy_documents
                retrieved_data = retrieve_content(
                    indexNames="policy_documents",
                    question=request.question,
                    trace_id=request.session_id,
                )

                # 转换数据格式以适配现有系统
                policy_docs = []
                for item in retrieved_data:
                    policy_docs.append({
                        "id": item["id"],
                        "content": item["content_with_weight"],
                        "source": f"{item['document_name']} (ID: {item['document_id']})",
                        "document_id": item["document_id"],
                        "document_name": item["document_name"]
                    })

            # 从Web搜索检索信息
            web_docs = []
            if request.search_web:
                web_docs = chat_service.retrieve_from_web(
                    question=request.question,
                    trace_id=request.session_id,
                )

            # 合并文档并重排
            all_docs = policy_docs + web_docs
            reranked_docs = chat_service.rerank_documents(
                question=request.question,
                documents=all_docs
            )

            # 生成流式回答
            for message_chunk in chat_service.get_chat_completion(
                session_id=request.session_id,
                question=request.question,
                retrieved_content=reranked_docs
            ):
                yield message_chunk

        except Exception as e:
            # 错误处理
            error_message = f"event: error\ndata: {str(e)}\n\n"
            yield error_message

    # 返回流式响应
    return StreamingResponse(
        generate_response(),
        media_type="text/event-stream"
    )


@router.post("/completion/v3", status_code=HTTP_200_OK)
async def chat_completion_with_attachments(
    request: ChatWithAttachmentsRequest,
    db: Session = Depends(get_db),
    services: Dict[str, Any] = Depends(get_services)
):
    """
    聊天补全接口v3版本，支持附件的问答

    附件内容会被提取并加入到上下文中，用于回答问题。

    Args:
        request: 包含用户问题、附件ID列表和会话信息的请求体

    Returns:
        流式响应，包含检索内容和模型生成内容
    """
    chat_service = services["chat_service"]
    session_service = services["session_service"]

    # 验证会话ID（如果提供）
    if request.session_id:
        session = session_service.get_session(request.session_id)
        if not session:
            session_data = session_service.create_session()
            request.session_id = session_data["session_id"]

    # 获取附件内容
    attachment_contents = []
    if request.attachment_ids:
        for att_id in request.attachment_ids:
            try:
                att_uuid = UUID(att_id)
                att = db.query(ChatAttachment).filter(ChatAttachment.id == att_uuid).first()
                if att and att.content_text and att.status == "completed":
                    attachment_contents.append({
                        "filename": att.filename,
                        "content": att.content_text[:10000],  # 限制每个附件内容长度
                    })
            except ValueError:
                continue

    async def generate_response():
        try:
            # 从政策文档索引检索
            policy_docs = []
            if request.search_knowledge:
                retrieved_data = retrieve_content(
                    indexNames="policy_documents",
                    question=request.question,
                    trace_id=request.session_id,
                )
                for item in retrieved_data:
                    policy_docs.append({
                        "id": item["id"],
                        "content": item["content_with_weight"],
                        "source": f"{item['document_name']} (ID: {item['document_id']})",
                        "document_id": item["document_id"],
                        "document_name": item["document_name"]
                    })

            # 从Web搜索检索信息
            web_docs = []
            if request.search_web:
                web_docs = chat_service.retrieve_from_web(
                    question=request.question,
                    trace_id=request.session_id,
                )

            # 合并文档并重排
            all_docs = policy_docs + web_docs
            reranked_docs = chat_service.rerank_documents(
                question=request.question,
                documents=all_docs
            )

            # 构建附件上下文
            attachment_context = ""
            if attachment_contents:
                attachment_context = "\n\n=== 用户上传的附件内容 ===\n"
                for att in attachment_contents:
                    attachment_context += f"\n--- {att['filename']} ---\n{att['content']}\n"
                attachment_context += "\n=== 附件内容结束 ===\n\n"

            # 修改问题，加入附件上下文
            enhanced_question = request.question
            if attachment_context:
                enhanced_question = f"用户问题：{request.question}\n\n请结合以下上传的附件内容来回答问题：{attachment_context}"

            # 生成流式回答
            for message_chunk in chat_service.get_chat_completion(
                session_id=request.session_id,
                question=enhanced_question,
                retrieved_content=reranked_docs
            ):
                yield message_chunk

        except Exception as e:
            error_message = f"event: error\ndata: {str(e)}\n\n"
            yield error_message

    return StreamingResponse(
        generate_response(),
        media_type="text/event-stream"
    )


@router.post("/completion/tools", status_code=HTTP_200_OK)
async def chat_completion_with_tools(
    request: ChatRequest,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user),
    services: Dict[str, Any] = Depends(get_services),
):
    """工具调用问答（ReAct 式）。

    与 /chat/completion 的区别：模型会按需调用联网搜索、知识库检索、Text2SQL、
    数据分析、图表生成等工具，再把工具结果整合成回答。

    安全链路（与纯 RAG 问答不同）：
    - 输入先过 ``guard_user_input``；
    - 每次工具调用走 ``ToolExecutor.execute``，因而受工具注册表、RBAC、
      单任务调用次数、任务链累计风险与人工审批约束，并写入数据库审计链；
    - 工具返回值按不可信数据封装后再回灌模型（工具结果是间接注入的主要入口）。

    鉴权为可选：带 token 时记录调用者（供审批追责与 RBAC 分角色），
    不带 token 时按 operator 处理，与既有 chat 端点的行为保持一致。
    """
    config = ServiceConfig.get_api_config()
    session_service = services["session_service"]

    # 会话不存在则创建，保证工具调用审计有可关联的 trace
    if request.session_id and not session_service.get_session(request.session_id):
        request.session_id = session_service.create_session()["session_id"]

    tool_qa_service = ToolQAService(
        llm_api_key=config.get("dashscope_api_key") or os.environ.get("DASHSCOPE_API_KEY", ""),
        llm_base_url=config.get("dashscope_base_url", "https://dashscope.aliyuncs.com/compatible-mode/v1"),
        model=os.environ.get("OPENAI_MODEL", "qwen-max"),
        search_api_key=config.get("serper_api_key"),
        db_connection_string=os.environ.get("DATABASE_URL"),
    )

    return StreamingResponse(
        tool_qa_service.answer_stream(
            request.question,
            session_id=request.session_id,
            db=db,
            user=current_user,
        ),
        media_type="text/event-stream",
    )
