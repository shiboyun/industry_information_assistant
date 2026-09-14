import json
import logging
from typing import Dict, Any, List, Optional
from openai import OpenAI

from .rageval_metrics import RAGEvalMetrics
from .mirage_metrics import MIRAGEMetrics

logger = logging.getLogger(__name__)


class Evaluator:
    """
    评估编排器：聚合 RAGEval 和 MIRAGE，对外提供统一评估接口
    """

    def __init__(self, llm_api_key: str, llm_base_url: str, model: str = "qwen-plus"):
        self.client = OpenAI(api_key=llm_api_key, base_url=llm_base_url)
        self.model = model
        self.rageval = RAGEvalMetrics(self.client, model)
        self.mirage = MIRAGEMetrics()

    def evaluate_rag_output(
            self,
            question: str,
            answer: str,
            contexts: List[str],
            ground_truth: Optional[str] = None,
            keypoints: Optional[List[str]] = None,
            mirage_results: Optional[List[Dict]] = None
    ) -> Dict[str, Any]:
        """
        对单次 RAG 输出进行全维度评估

        Args:
            question: 用户问题
            answer: 模型生成的答案
            contexts: 检索到的上下文片段列表
            ground_truth: 标准答案（可选）
            keypoints: 标准答案的关键点列表（可选，用于 RAGEval 精确评估）
            mirage_results: MIRAGE 所需的三种设置结果列表（可选）
        """
        result = {
            "rageval": self.rageval.evaluate(
                question=question,
                answer=answer,
                contexts=contexts,
                keypoints=keypoints
            )
        }

        if mirage_results:
            result["mirage"] = self.mirage.evaluate_batch(mirage_results)

        if ground_truth:
            result["exact_match"] = float(answer.strip() == ground_truth.strip())

        return result

    def evaluate_from_checkpoint(self, checkpoint_state: Dict[str, Any]) -> Dict[str, Any]:
        """
        从检查点状态中提取数据并评估（对接您的 CheckpointService）
        """
        question = checkpoint_state.get("query", "")
        answer = checkpoint_state.get("final_report", "")

        # 从 facts 中提取上下文
        facts = checkpoint_state.get("facts", [])
        contexts = [f.get("content", "") for f in facts if f.get("content")]

        # 如果检查点里存了 ground_truth，直接取用
        ground_truth = checkpoint_state.get("ground_truth", None)

        # 如果检查点里存了 keypoints，直接取用
        keypoints = checkpoint_state.get("keypoints", None)

        return self.evaluate_rag_output(
            question=question,
            answer=answer,
            contexts=contexts,
            ground_truth=ground_truth,
            keypoints=keypoints
        )