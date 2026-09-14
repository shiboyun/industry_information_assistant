"""评测指标：混淆矩阵、Precision/Recall/F1、误报率/漏报率与明细清单。

赛题原文要求「形成**可量化的测试方法、风险指标**与审计证据输出机制」。
数据集只解决"有语料"，把语料变成可信指标还需要一个算法正确的评测器——
本模块就是那一步，并且刻意输出**误报与漏报的逐条明细**，
因为赛题还要求"问题定位"：只给一个百分比是没法定位问题的。

关键设计：**按阶段定义"检出"**。检索层恒不阻断（只过滤片段），
输出层恒不阻断（只脱敏），若统一用 `decision == "block"` 判定，
这两个阶段会恒判为"漏报"。因此每个阶段有自己的检出信号。
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

# 非 allow 即视为"有检出动作"
_DETECTED_SIGNALS = frozenset({"block", "filter", "redact", "approval_required", "modified"})


@dataclass
class ConfusionMatrix:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    def __post_init__(self) -> None:
        for name in ("tp", "fp", "tn", "fn"):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} 不能为负")

    def __add__(self, other: "ConfusionMatrix") -> "ConfusionMatrix":
        return ConfusionMatrix(
            tp=self.tp + other.tp, fp=self.fp + other.fp,
            tn=self.tn + other.tn, fn=self.fn + other.fn,
        )

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def precision(self) -> float:
        denominator = self.tp + self.fp
        return self.tp / denominator if denominator else 0.0

    @property
    def recall(self) -> float:
        denominator = self.tp + self.fn
        return self.tp / denominator if denominator else 0.0

    @property
    def f1(self) -> float:
        denominator = self.precision + self.recall
        return 2 * self.precision * self.recall / denominator if denominator else 0.0

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total else 0.0

    @property
    def false_positive_rate(self) -> float:
        """误报率：良性样本中被误拦的比例。"""
        denominator = self.fp + self.tn
        return self.fp / denominator if denominator else 0.0

    @property
    def false_negative_rate(self) -> float:
        """漏报率：攻击样本中被放行的比例。"""
        denominator = self.tp + self.fn
        return self.fn / denominator if denominator else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "total": self.total,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "false_negative_rate": round(self.false_negative_rate, 4),
        }


def _signal_for_user_input(sample: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
    from security_hooks import guard_user_input

    result = guard_user_input(sample.get("text", ""), trace_id=sample.get("id", "eval"))
    signal = "block" if result.decision == "block" else "allow"
    return signal, {"decision": result.decision, "labels": result.labels, "evidence": result.evidence[:3]}


def _signal_for_retrieval(sample: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
    from security_hooks import guard_retrieval_results

    documents = sample.get("documents") or []
    result = guard_retrieval_results(
        question=sample.get("question", ""),
        documents=documents,
        trace_id=sample.get("id", "eval"),
    )
    filtered = result.metadata.get("filtered_count", 0)
    signal = "filter" if filtered else "allow"
    return signal, {"decision": result.decision, "filtered_count": filtered, "evidence": result.evidence[:3]}


def _signal_for_tool_call(sample: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
    from security_hooks import guard_tool_call

    result = guard_tool_call(
        tool_name=sample.get("tool_name", ""),
        params=sample.get("params") or {},
        trace_id=sample.get("id", "eval"),
    )
    if result.decision == "block":
        signal = "block"
    elif result.decision == "approval_required":
        signal = "approval_required"
    else:
        signal = "allow"
    return signal, {"decision": result.decision, "labels": result.labels, "evidence": result.evidence[:3]}


def _signal_for_tool_result(sample: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
    from security_hooks import guard_tool_result

    result = guard_tool_result(
        tool_name=sample.get("tool_name", ""),
        payload=sample.get("payload") or {},
        trace_id=sample.get("id", "eval"),
    )
    signal = "redact" if "sensitive_output_redacted" in result.labels else "allow"
    return signal, {"decision": result.decision, "labels": result.labels, "evidence": result.evidence[:3]}


_DISPATCH = {
    "user_input": _signal_for_user_input,
    "retrieval": _signal_for_retrieval,
    "tool_call": _signal_for_tool_call,
    "tool_result": _signal_for_tool_result,
    "chain": None,  # 见 _signal_for_chain，需要按序执行多步
}


def _signal_for_chain(sample: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
    """跨阶段攻击链：同一条 trace 上按序执行多步，**以终止动作的判定作为信号**。

    这是本系统区别于单点检测的核心能力（检索到污染 → 禁止后续导出）。
    评测时必须让各步共享 trace_id，否则跨阶段污点不会生效，
    链式样例会被误判成漏报。

    **取"终止动作"而非"全链最严格"，是有意为之。** 链式攻击是否被阻止，
    取决于最后那个危险动作有没有真的执行。若取全链最严格，前面的检索过滤
    （产出 `modified`）也会被算作检出——那样即使导出动作放行了，整条链仍记为
    拦截成功，等于把检索层的功劳记到跨阶段关联上。该口径缺陷由消融实验暴露：
    关闭污点传播后 B6 的指标毫无变化，说明测的不是污点贡献。
    """
    from security_hooks import (
        get_taint_ledger,
        guard_retrieval_results,
        guard_tool_call,
        guard_tool_result,
        guard_user_input,
    )

    trace_id = sample.get("id", "eval-chain")
    get_taint_ledger().reset()

    severity = {"allow": 0, "modified": 1, "approval_required": 2, "block": 3}
    strictest = "allow"
    steps: List[Dict[str, Any]] = []

    for step in sample.get("steps") or []:
        kind = step.get("kind")
        if kind == "user_input":
            result = guard_user_input(step.get("text", ""), trace_id=trace_id)
            signal = "block" if result.decision == "block" else "allow"
        elif kind == "retrieval":
            result = guard_retrieval_results(
                question=step.get("question", ""),
                documents=step.get("documents") or [],
                trace_id=trace_id,
            )
            signal = "modified" if result.metadata.get("filtered_count") else "allow"
            if result.decision == "block":
                signal = "block"
        elif kind == "tool_result":
            result = guard_tool_result(
                tool_name=step.get("tool_name", ""),
                payload=step.get("payload") or {},
                trace_id=trace_id,
            )
            signal = "modified" if "sensitive_output_redacted" in result.labels else "allow"
        else:
            result = guard_tool_call(
                tool_name=step.get("tool_name", ""),
                params=step.get("params") or {},
                trace_id=trace_id,
            )
            signal = result.decision if result.decision in severity else "allow"

        steps.append({"kind": kind, "signal": signal, "decision": getattr(result, "decision", None)})
        if severity.get(signal, 0) > severity.get(strictest, 0):
            strictest = signal

    # 终止动作（最后一步）的判定才是这条链是否被阻止的依据；
    # 同时保留全链最严格值，便于在明细中观察中途的过滤动作。
    terminal = steps[-1]["signal"] if steps else "allow"
    return terminal, {
        "steps": steps,
        "strictest_signal": strictest,
        "terminal_signal": terminal,
        "taint": sorted(get_taint_ledger().get(trace_id)["flags"]),
    }


_DISPATCH["chain"] = _signal_for_chain


def evaluate_sample(sample: Dict[str, Any]) -> Dict[str, Any]:
    """跑单条样例，返回判定结果（TP/FP/TN/FN/ERROR）与依据。"""
    stage = sample.get("stage")
    handler = _DISPATCH.get(stage)
    if handler is None:
        return {
            "id": sample.get("id"),
            "group": sample.get("group"),
            "stage": stage,
            "result": "ERROR",
            "expected_signal": sample.get("expected_signal"),
            "actual_signal": None,
            "detail": {"error": f"未知阶段：{stage}"},
        }

    actual_signal, detail = handler(sample)
    is_attack = bool(sample.get("is_attack"))
    detected = actual_signal in _DETECTED_SIGNALS

    if is_attack and detected:
        outcome = "TP"
    elif is_attack and not detected:
        outcome = "FN"
    elif not is_attack and detected:
        outcome = "FP"
    else:
        outcome = "TN"

    return {
        "id": sample.get("id"),
        "group": sample.get("group"),
        "stage": stage,
        "is_attack": is_attack,
        "result": outcome,
        "expected_signal": sample.get("expected_signal"),
        "actual_signal": actual_signal,
        "signal_matches_expected": actual_signal == sample.get("expected_signal"),
        "detail": detail,
    }


def _accumulate(matrix: ConfusionMatrix, outcome: str) -> ConfusionMatrix:
    field = outcome.lower()
    if field not in {"tp", "fp", "tn", "fn"}:
        return matrix
    current = matrix.to_dict()
    current[field] += 1
    return ConfusionMatrix(tp=current["tp"], fp=current["fp"], tn=current["tn"], fn=current["fn"])


def evaluate_dataset(dataset: Dict[str, Any]) -> Dict[str, Any]:
    """评测整个数据集，输出总体 / 分组 / 分阶段指标与误报漏报明细。"""
    samples: List[Dict[str, Any]] = dataset.get("samples") or dataset.get("cases") or []

    overall = ConfusionMatrix()
    by_group: Dict[str, ConfusionMatrix] = {}
    by_stage: Dict[str, ConfusionMatrix] = {}
    false_positives: List[Dict[str, Any]] = []
    false_negatives: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    attack_count = benign_count = 0

    for sample in samples:
        outcome = evaluate_sample(sample)
        if sample.get("is_attack"):
            attack_count += 1
        else:
            benign_count += 1

        if outcome["result"] == "ERROR":
            errors.append(outcome)
            continue

        overall = _accumulate(overall, outcome["result"])
        group = str(sample.get("group") or "未分组")
        by_group[group] = _accumulate(by_group.get(group, ConfusionMatrix()), outcome["result"])
        stage = str(outcome["stage"])
        by_stage[stage] = _accumulate(by_stage.get(stage, ConfusionMatrix()), outcome["result"])

        if outcome["result"] == "FP":
            false_positives.append(outcome)
        elif outcome["result"] == "FN":
            false_negatives.append(outcome)

    return {
        "dataset_name": (dataset.get("meta") or {}).get("name", ""),
        "sample_count": len(samples),
        "attack_count": attack_count,
        "benign_count": benign_count,
        "error_count": len(errors),
        "overall": overall.to_dict(),
        "by_group": {name: matrix.to_dict() for name, matrix in sorted(by_group.items())},
        "by_stage": {name: matrix.to_dict() for name, matrix in sorted(by_stage.items())},
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "errors": errors,
    }


def load_dataset(path: Any) -> Dict[str, Any]:
    """加载数据集文件，接受 ``{"meta":..,"samples":[..]}`` 或裸数组。"""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    dataset = {"meta": {"name": Path(path).stem}, "samples": raw} if isinstance(raw, list) else dict(raw)
    samples = dataset.get("samples") or []

    for index, sample in enumerate(samples):
        missing = [field for field in ("id", "stage") if not sample.get(field)]
        if missing:
            raise ValueError(f"第 {index} 条样例缺少必填字段：{missing}")
    return dataset


def format_report(report: Dict[str, Any], max_detail: int = 10) -> str:
    """把评测结果渲染成便于贴进报告的文字表格。"""
    overall = report["overall"]
    lines = [
        f"数据集：{report['dataset_name'] or '(未命名)'}",
        f"样例总数 {report['sample_count']}（攻击 {report['attack_count']} / 良性 {report['benign_count']}）"
        + (f"，无法解析 {report['error_count']} 条" if report["error_count"] else ""),
        "",
        f"混淆矩阵  TP={overall['tp']}  FP={overall['fp']}  TN={overall['tn']}  FN={overall['fn']}",
        f"精确率 {overall['precision']:.2%}   召回率 {overall['recall']:.2%}   F1 {overall['f1']:.2%}",
        f"误报率 {overall['false_positive_rate']:.2%}   漏报率 {overall['false_negative_rate']:.2%}",
        "",
        "分阶段：",
    ]
    for stage, matrix in report["by_stage"].items():
        lines.append(
            f"  {stage:<12} P={matrix['precision']:.2%} R={matrix['recall']:.2%} "
            f"误报率={matrix['false_positive_rate']:.2%} 漏报率={matrix['false_negative_rate']:.2%}"
        )

    if report["false_positives"]:
        lines += ["", f"误报明细（前 {max_detail} 条）："]
        for item in report["false_positives"][:max_detail]:
            lines.append(f"  [{item['id']}] {item['group']} → 期望放行，实际 {item['actual_signal']}")
    if report["false_negatives"]:
        lines += ["", f"漏报明细（前 {max_detail} 条）："]
        for item in report["false_negatives"][:max_detail]:
            lines.append(f"  [{item['id']}] {item['group']} → 期望拦截，实际 {item['actual_signal']}")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="安全评测数据集指标计算")
    parser.add_argument("dataset", help="数据集 JSON 路径")
    parser.add_argument("--output", help="指标结果落盘路径（JSON）")
    parser.add_argument("--json", action="store_true", help="直接输出 JSON")
    args = parser.parse_args(argv)

    dataset = load_dataset(args.dataset)
    report = evaluate_dataset(dataset)

    print(json.dumps(report, ensure_ascii=False, indent=2) if args.json else format_report(report))
    if args.output:
        Path(args.output).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n指标已写入：{args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
