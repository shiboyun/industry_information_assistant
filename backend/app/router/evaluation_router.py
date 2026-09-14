from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import logging
import os

from service.evaluation.evaluator import Evaluator
from service.checkpoint_service import get_checkpoint_service

router = APIRouter(prefix="/evaluate", tags=["RAG Evaluation"])
logger = logging.getLogger(__name__)


# ---------- 请求/响应模型 ----------
class EvaluateRequest(BaseModel):
    question: str
    answer: str
    contexts: List[str]
    ground_truth: Optional[str] = None


class EvaluateSessionRequest(BaseModel):
    session_id: str


class EvaluateResponse(BaseModel):
    session_id: Optional[str] = None
    rageval: Dict[str, float]
    mirage: Optional[Dict[str, float]] = None
    exact_match: Optional[float] = None


# ---------- 依赖注入 ----------
def get_evaluator():
    # 这里您可以改为从 config 读取
    return Evaluator(
        llm_api_key=os.getenv("DASHSCOPE_API_KEY", ""),
        llm_base_url=os.getenv("LLM_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1"),
        model="qwen-plus"
    )


# ---------- API 端点 ----------
@router.post("/single", response_model=EvaluateResponse)
async def evaluate_single(req: EvaluateRequest, evaluator: Evaluator = Depends(get_evaluator)):
    """
    单次评估：传入问题、答案、上下文，立即返回 RAGEval 指标
    """
    try:
        result = evaluator.evaluate_rag_output(
            question=req.question,
            answer=req.answer,
            contexts=req.contexts,
            ground_truth=req.ground_truth
        )
        return EvaluateResponse(
            rageval=result["rageval"],
            exact_match=result.get("exact_match")
        )
    except Exception as e:
        logger.error(f"Evaluation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/session", response_model=EvaluateResponse)
async def evaluate_session(req: EvaluateSessionRequest, evaluator: Evaluator = Depends(get_evaluator)):
    """
    从会话检查点进行评估：传入 session_id，自动提取状态
    """
    checkpoint_service = get_checkpoint_service()
    if not checkpoint_service:
        raise HTTPException(status_code=500, detail="Checkpoint service not available")

    state = checkpoint_service.load_checkpoint(req.session_id)
    if not state:
        raise HTTPException(status_code=404, detail="Session not found")

    try:
        result = evaluator.evaluate_from_checkpoint(state)
        return EvaluateResponse(
            session_id=req.session_id,
            rageval=result["rageval"],
            exact_match=result.get("exact_match")
        )
    except Exception as e:
        logger.error(f"Session evaluation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/batch")
async def evaluate_batch(file_path: str, evaluator: Evaluator = Depends(get_evaluator)):
    """
    批量评估：传入 JSON 数据集文件路径，输出汇总指标
    """
    import json
    import os

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Dataset file not found")

    with open(file_path, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    results = []
    for item in dataset:
        result = evaluator.evaluate_rag_output(
            question=item.get("question", ""),
            answer=item.get("answer", ""),
            contexts=item.get("contexts", []),
            ground_truth=item.get("ground_truth")
        )
        results.append(result)

    # 汇总平均分
    avg = {
        "completeness": sum(r["rageval"]["completeness"] for r in results) / len(results),
        "hallucination": sum(r["rageval"]["hallucination"] for r in results) / len(results),
        "irrelevance": sum(r["rageval"]["irrelevance"] for r in results) / len(results)
    }

    return {
        "total_samples": len(results),
        "average_scores": avg,
        "details": results
    }