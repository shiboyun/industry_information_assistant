from openai import OpenAI
import re
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class RAGEvalMetrics:
    """
    RAGEval 三大指标：
    1. Completeness（完整性）：答案覆盖关键点的比例
    2. Hallucination（幻觉率）：答案与关键点矛盾的比例
    3. Irrelevance（不相关度）：答案既未覆盖也未矛盾的关键点比例

    论文公式：
    Comp(A,K) = 1/|K| * Σ 1[A covers k_i]
    Hallu(A,K) = 1/|K| * Σ 1[A contradicts k_i]
    Ir(A,K) = 1 - Comp(A,K) - Hallu(A,K)
    """

    def __init__(self, llm_client: OpenAI, llm_model: str = "qwen-plus"):
        self.client = llm_client
        self.model = llm_model

    def evaluate(
        self,
        question: str,
        answer: str,
        contexts: List[str],
        keypoints: Optional[List[str]] = None
    ) -> Dict[str, float]:
        """
        对外暴露的统一评估接口

        Args:
            question: 用户问题
            answer: 模型生成的答案
            contexts: 检索到的上下文片段列表（用于生成 keypoints 或幻觉检测）
            keypoints: 标准答案的关键点列表（优先使用）

        Returns:
            {"completeness": float, "hallucination": float, "irrelevance": float}
        """
        # 如果提供了 keypoints，使用基于 keypoints 的精确评估
        if keypoints and len(keypoints) > 0:
            return self._evaluate_with_keypoints(answer, keypoints)

        # 如果没有 keypoints，自动生成（向后兼容）
        logger.warning("未提供 keypoints，使用 LLM 自动评估（精度较低）")
        return {
            "completeness": self._compute_completeness(question, answer),
            "hallucination": self._compute_hallucination(answer, contexts),
            "irrelevance": self._compute_irrelevance(question, answer)
        }

    def _evaluate_with_keypoints(self, answer: str, keypoints: List[str]) -> Dict[str, float]:
        """
        基于 keypoints 的精确评估（RAGEval 论文公式 3、4、5）

        Args:
            answer: 模型生成的答案
            keypoints: 标准答案的关键点列表

        Returns:
            {"completeness": float, "hallucination": float, "irrelevance": float}
        """
        if not keypoints:
            return {"completeness": 0.0, "hallucination": 0.0, "irrelevance": 1.0}

        # 用 LLM 判断每个 keypoint 的状态
        keypoint_status = self._classify_keypoints(answer, keypoints)

        # 统计
        total = len(keypoints)
        covered = sum(1 for s in keypoint_status if s == "covered")
        contradicted = sum(1 for s in keypoint_status if s == "contradicted")
        irrelevant = total - covered - contradicted

        return {
            "completeness": round(covered / total, 4),
            "hallucination": round(contradicted / total, 4),
            "irrelevance": round(irrelevant / total, 4)
        }

    def _classify_keypoints(self, answer: str, keypoints: List[str]) -> List[str]:
        if not keypoints:
            return []

        cache_key = self._get_cache_key(answer, keypoints)
        if hasattr(self, '_classify_cache') and cache_key in self._classify_cache:
            logger.debug(f"Keypoint classification cache hit")
            return self._classify_cache[cache_key]

        prompt = f"""
        你是一位严格的但公正的评估专家。请判断以下**关键点（Keypoints）** 是否被**答案（Answer）** 覆盖、矛盾或无关。

        ## 答案（Answer）
        {answer}

        ## 关键点列表
        {chr(10).join([f"{i + 1}. {kp}" for i, kp in enumerate(keypoints)])}

        ## 分类规则（请严格遵循，不要过度解读）

        ### 1. covered（已覆盖）✅
        答案中包含该关键点的**核心语义信息**，即使措辞不同、格式不同也算覆盖。
        判断标准：一个正常读者能从答案中推断出该关键点的核心意思。

        **覆盖示例（即使不完全相同）：**
        - 关键点: "2024年智慧交通行业整体市场规模为2850亿元"
          答案: "市场规模达2850亿元" → ✅ covered（核心数字正确）
        - 关键点: "该增长率显著高于GDP名义增速"
          答案: "增速远超GDP增速" → ✅ covered（核心意思一致）
        - 关键点: "银行线上业务渗透率为92.3%"
          答案: "线上渗透率约92%" → ✅ covered（数字接近即可）

        **不覆盖的情况（真正缺失时）：**
        - 关键点: "该增长率显著高于GDP名义增速"
          答案: 完全没有提到增长率对比 → ❌ irrelevant

        ### 2. contradicted（矛盾）❌
        答案中明确说了与该关键点**完全相反或严重冲突**的内容。
        **注意：这需要是真正的、明显的矛盾，不是细微差异！**

        **矛盾示例：**
        - 关键点: "市场规模为2850亿元"
          答案: "市场规模为1850亿元" → ❌ contradicted（数值冲突明显）
        - 关键点: "同比增长22.3%"
          答案: "同比下降22.3%" → ❌ contradicted（方向相反）
        - 关键点: "中国平安位居第一"
          答案: "中国人寿位居第一" → ❌ contradicted（主体不同）

        **不算矛盾的情况：**
        - 关键点: "22.3%" 答案: "约22%" → ✅ covered（不是矛盾）
        - 关键点: "92.3%" 答案: "约92%" → ✅ covered（不是矛盾）
        - 关键点: "超82%" 答案: "82%" → ✅ covered（不是矛盾）

        ### 3. irrelevant（无关）🔘
        答案中既没有覆盖该关键点，也没有与它矛盾。

        **判断原则：当你不确定时，倾向于判为 covered（宁可放过，不要错杀）**

        请为每个关键点输出一个分类标签，用逗号分隔，顺序与关键点列表一致。
        只输出标签列表，例如：covered, covered, irrelevant, covered, contradicted

        不要输出任何其他内容。
        """
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=300
            )
            raw = response.choices[0].message.content.strip()

            # 解析标签列表
            labels = self._parse_labels(raw, len(keypoints))

            # 缓存结果
            if not hasattr(self, '_classify_cache'):
                self._classify_cache = {}
            self._classify_cache[cache_key] = labels

            return labels

        except Exception as e:
            logger.error(f"Keypoint classification failed: {e}")
            # fallback: 全部标记为 irrelevant
            return ["irrelevant"] * len(keypoints)

    def _get_cache_key(self, answer: str, keypoints: List[str]) -> str:
        """生成缓存 key"""
        import hashlib
        content = answer + "|||" + "|||".join(keypoints)
        return hashlib.md5(content.encode()).hexdigest()

    def _parse_labels(self, raw: str, expected_count: int) -> List[str]:
        """
        解析 LLM 返回的标签列表

        Args:
            raw: LLM 原始响应，如 "covered, covered, irrelevant, covered, contradicted"
            expected_count: 期望的标签数量

        Returns:
            标准化的标签列表
        """
        # 清理
        raw = raw.strip()
        # 移除可能的 Markdown 代码块标记
        raw = re.sub(r'^```\w*\s*', '', raw)
        raw = re.sub(r'\s*```$', '', raw)
        # 移除多余的标点
        raw = re.sub(r'[\[\]"\'()]', '', raw)

        # 按逗号分割
        labels = [l.strip().lower() for l in raw.split(',') if l.strip()]

        # 标准化标签
        valid_labels = {"covered", "contradicted", "irrelevant"}
        normalized = []
        for l in labels:
            # 处理可能的缩写或变体
            if l.startswith("cover"):
                normalized.append("covered")
            elif l.startswith("contradict"):
                normalized.append("contradicted")
            elif l.startswith("irrel"):
                normalized.append("irrelevant")
            elif l in valid_labels:
                normalized.append(l)
            else:
                normalized.append("irrelevant")

        # 确保数量一致
        while len(normalized) < expected_count:
            normalized.append("irrelevant")
        normalized = normalized[:expected_count]

        return normalized

    def _compute_completeness(self, question: str, answer: str) -> float:
        """完整性评分 (0~1) - 无 keypoints 时的 fallback"""
        prompt = f"""请评估以下回答是否完整覆盖了问题的所有方面。
        问题：{question}
        回答：{answer}
        请只返回一个 0 到 1 之间的分数（浮点数），1 表示完全覆盖所有方面，0 表示完全没有覆盖。
        分数："""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=10
            )
            score = float(response.choices[0].message.content.strip())
            return min(max(score, 0.0), 1.0)
        except Exception as e:
            logger.error(f"Completeness scoring failed: {e}")
            return 0.5

    def _compute_hallucination(self, answer: str, contexts: List[str]) -> float:
        """幻觉率 (0~1) - 无 keypoints 时的 fallback"""
        if not contexts:
            return 1.0
        context_text = "\n".join(contexts)
        prompt = f"""请判断以下回答中的内容是否有事实支撑，还是模型凭空编造（幻觉）。
        参考上下文：{context_text}
        回答：{answer}
        请估算回答中**没有来源支撑的比例**（即幻觉比例），只返回 0 到 1 之间的浮点数。
        幻觉比例："""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=10
            )
            score = float(response.choices[0].message.content.strip())
            return min(max(score, 0.0), 1.0)
        except Exception as e:
            logger.error(f"Hallucination scoring failed: {e}")
            return 0.5

    def _compute_irrelevance(self, question: str, answer: str) -> float:
        """不相关度 (0~1) - 无 keypoints 时的 fallback"""
        prompt = f"""请评估以下回答中与问题无关的内容占比。
        问题：{question}
        回答：{answer}
        请估算无关内容的比例（即不相关度），只返回 0 到 1 之间的浮点数。
        不相关度："""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=10
            )
            score = float(response.choices[0].message.content.strip())
            return min(max(score, 0.0), 1.0)
        except Exception as e:
            logger.error(f"Irrelevance scoring failed: {e}")
            return 0.3