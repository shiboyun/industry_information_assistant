"""消融实验：逐个关闭安全组件，量化其对检出能力的贡献。

**为什么需要消融。** 只报告"完整系统召回率 X%"无法证明各组件是必要的——
那些指标也可能是别的组件带来的。消融实验通过"关掉一个组件 → 指标掉多少"
来把整体性能归因到具体机制上，这是论文证明**必要性**的标准做法。

实验方式：对每个组件做**最小化禁用**（只替换该组件的判定函数，不改动其余逻辑），
在同一数据集上复测，与完整系统对比。

输出：各组件关闭后的指标下降量，以及受影响最严重的攻击类别。

用法：
    PYTHONPATH=app python app/scripts/run_ablation.py
"""
from __future__ import annotations

import io
import json
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATASET_PATH = PROJECT_ROOT / "backend" / "app" / "data" / "security_eval_dataset.json"
OUTPUT_PATH = PROJECT_ROOT / "backend" / "app" / "data" / "ablation_result.json"


# ==================== 各组件的"关闭"实现 ====================

def _disable_taint() -> Callable[[], None]:
    """关闭跨阶段污点传播：策略层不再依据上游状态升级判定。"""
    from security_hooks import pipeline

    original = pipeline.evaluate_taint
    pipeline.evaluate_taint = lambda flags, tool_name: None
    return lambda: setattr(pipeline, "evaluate_taint", original)


def _disable_padding_detection() -> Callable[[], None]:
    """关闭统计特征检测：不再识别低熵高重复的投毒填充。"""
    from security_hooks import detectors

    original = detectors.looks_like_padding
    detectors.looks_like_padding = lambda text: False
    return lambda: setattr(detectors, "looks_like_padding", original)


def _disable_normalization() -> Callable[[], None]:
    """关闭输入归一化：只匹配原文，不再展开变形与编码视图。"""
    from security_hooks import detectors

    original = detectors.expand_obfuscation
    detectors.expand_obfuscation = lambda text: [text]
    return lambda: setattr(detectors, "expand_obfuscation", original)


def _disable_retrieval_filtering() -> Callable[[], None]:
    """关闭检索层过滤：召回片段原样进入上下文。"""
    from security_hooks import pipeline

    original = pipeline.filter_retrieval_documents

    def _passthrough(documents):
        return list(documents), 0, [], []

    pipeline.filter_retrieval_documents = _passthrough
    return lambda: setattr(pipeline, "filter_retrieval_documents", original)


def _disable_tool_registry() -> Callable[[], None]:
    """关闭工具注册表校验：未注册工具不再被拦截。"""
    from security_hooks import pipeline

    original = pipeline._unregistered_tool_reason
    pipeline._unregistered_tool_reason = lambda tool_name: None
    return lambda: setattr(pipeline, "_unregistered_tool_reason", original)


def _disable_redaction() -> Callable[[], None]:
    """关闭结果脱敏：工具返回的敏感信息原样透出。"""
    from security_hooks import pipeline

    original = pipeline.redact_sensitive_values

    def _passthrough(payload):
        return payload, [], []

    pipeline.redact_sensitive_values = _passthrough
    return lambda: setattr(pipeline, "redact_sensitive_values", original)


ABLATIONS: List[Dict[str, Any]] = [
    {
        "key": "taint",
        "name": "跨阶段污点传播",
        "disable": _disable_taint,
        "expect": "B6 异常任务链",
    },
    {
        "key": "padding",
        "name": "统计特征检测（投毒填充）",
        "disable": _disable_padding_detection,
        "expect": "A6 低熵填充投毒",
    },
    {
        "key": "normalization",
        "name": "输入归一化（变形与编码）",
        "disable": _disable_normalization,
        "expect": "A8 变形与编码绕过",
    },
    {
        "key": "retrieval_filter",
        "name": "检索层片段过滤",
        "disable": _disable_retrieval_filtering,
        "expect": "A3 / A4 间接注入",
    },
    {
        "key": "tool_registry",
        "name": "工具注册表校验",
        "disable": _disable_tool_registry,
        "expect": "B5 越权调用",
    },
    {
        "key": "redaction",
        "name": "结果敏感信息脱敏",
        "disable": _disable_redaction,
        "expect": "B8 工具结果泄露",
    },
]


@contextmanager
def _disabled(disable: Callable[[], Callable[[], None]]):
    restore = disable()
    try:
        yield
    finally:
        restore()


def _evaluate() -> Dict[str, Any]:
    """在当前（可能已打补丁的）实现上跑一次完整评测。"""
    from security_eval.metrics import evaluate_dataset, load_dataset

    dataset = load_dataset(DATASET_PATH)
    return evaluate_dataset(dataset)


def _overall_recall(report: Dict[str, Any]) -> float:
    """只看定向语料（自建部分）的召回率——消融针对的是机制，不是泛化能力。"""
    tp = fn = 0
    for group, matrix in report["by_group"].items():
        if group.startswith("EXT_"):
            continue
        tp += matrix["tp"]
        fn += matrix["fn"]
    return tp / (tp + fn) if (tp + fn) else 0.0


def _group_recall(report: Dict[str, Any], prefix: str) -> float:
    tp = fn = 0
    for group, matrix in report["by_group"].items():
        if group.startswith(prefix):
            tp += matrix["tp"]
            fn += matrix["fn"]
    return tp / (tp + fn) if (tp + fn) else 0.0


def main() -> int:
    print("=" * 92)
    print("消融实验：逐个关闭安全组件，观察检出能力的下降")
    print("=" * 92)
    print(f"数据集：{DATASET_PATH.name}\n")

    print("跑基线（完整系统）…")
    baseline = _evaluate()
    base_recall = _overall_recall(baseline)
    print(f"  定向语料召回率：{base_recall:.2%}\n")

    results: List[Dict[str, Any]] = []
    print(f"{'关闭的组件':<28}{'定向召回率':>12}{'下降':>10}   受影响类别")
    print("-" * 92)

    for ablation in ABLATIONS:
        with _disabled(ablation["disable"]):
            report = _evaluate()

        recall = _overall_recall(report)
        drop = base_recall - recall
        target_recall = _group_recall(report, ablation["expect"].split()[0])
        base_target = _group_recall(baseline, ablation["expect"].split()[0])

        results.append({
            "key": ablation["key"],
            "name": ablation["name"],
            "overall_recall_without": round(recall, 4),
            "overall_recall_drop": round(drop, 4),
            "target_group": ablation["expect"],
            "target_recall_full": round(base_target, 4),
            "target_recall_without": round(target_recall, 4),
            "target_recall_drop": round(base_target - target_recall, 4),
        })

        print(f"{ablation['name']:<28}{recall:>11.2%}{drop:>10.2%}   "
              f"{ablation['expect']}：{base_target:.1%} → {target_recall:.1%}")

    print("-" * 92)
    print(f"{'完整系统（基线）':<28}{base_recall:>11.2%}{'—':>10}")

    OUTPUT_PATH.write_text(
        json.dumps({
            "baseline_recall": round(base_recall, 4),
            "ablations": results,
        }, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"\n结果已写入：{OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
