import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class MIRAGEMetrics:
    """
    MIRAGE 四大适应性指标（基于三类输入配置）：
    - Noise Vulnerability（噪声脆弱性）
    - Context Acceptability（上下文可接受性）
    - Context Insensitivity（上下文不敏感性）
    - Context Misinterpretation（上下文误解释）

    注意：此指标需要同一个问题在三种设置下的答案：
    - Base: 无上下文
    - Oracle: 仅正确上下文
    - Mixed: 混合上下文（含噪声）
    """

    def evaluate_batch(self, results: List[Dict]) -> Dict[str, float]:
        """
        批量评估一组样本
        每个样本需包含：
        {
            "base_correct": bool,    # Base 设置下是否答对
            "oracle_correct": bool,  # Oracle 设置下是否答对
            "mixed_correct": bool    # Mixed 设置下是否答对
        }
        """
        total = len(results)
        if total == 0:
            return self._empty_result()

        # 统计四种组合的样本数（对应论文公式中的 G(b,o,m)）
        counts = self._count_combinations(results)

        # 计算四个指标（论文公式 2~5）
        noise_vulnerability = (counts[(0, 1, 0)] + counts[(1, 1, 0)]) / total
        context_acceptability = (counts[(0, 1, 1)] + counts[(1, 1, 1)]) / total
        context_insensitivity = (counts[(0, 0, 0)] + counts[(0, 0, 1)]) / total
        context_misinterpretation = (counts[(1, 0, 0)] + counts[(1, 0, 1)]) / total

        return {
            "noise_vulnerability": round(noise_vulnerability, 4),
            "context_acceptability": round(context_acceptability, 4),
            "context_insensitivity": round(context_insensitivity, 4),
            "context_misinterpretation": round(context_misinterpretation, 4)
        }

    def _count_combinations(self, results: List[Dict]) -> Dict[tuple, int]:
        counts = {(0, 0, 0): 0, (0, 0, 1): 0, (0, 1, 0): 0, (0, 1, 1): 0,
                  (1, 0, 0): 0, (1, 0, 1): 0, (1, 1, 0): 0, (1, 1, 1): 0}
        for r in results:
            key = (int(r["base_correct"]), int(r["oracle_correct"]), int(r["mixed_correct"]))
            counts[key] = counts.get(key, 0) + 1
        return counts

    def _empty_result(self) -> Dict[str, float]:
        return {
            "noise_vulnerability": 0.0,
            "context_acceptability": 0.0,
            "context_insensitivity": 0.0,
            "context_misinterpretation": 0.0
        }