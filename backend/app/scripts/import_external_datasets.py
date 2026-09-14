"""从公开数据集导入安全评测样例（外部数据 → 本系统样例格式）。

设计要点：

1. **按语言分组。** 中文与英文载荷的检测表现差异显著（中文词库覆盖更全），
   混在同一组里报指标会掩盖真实差异。因此组名带语言标识，
   报告中可分别统计。
2. **确定性采样。** 按固定步长取样而非随机，保证同一输入产出同一数据集。
3. **只取模式，不搬语料。** 公开数据集的载荷多为英文通用场景，
   导入时保留原文（英文载荷本身是真实攻击面），但**分组标注来源**，
   便于在报告中说明语料构成。

数据来源（均位于本地 `测试数据集` 目录）：
- Safety-Prompts（清华）：中文安全 prompt，含目标劫持 / 提示词泄露 / 角色扮演等类别
- BIPIA（微软）：15 类攻击指令模板 + 干净业务内容，组合后构成间接注入
- InjecAgent（UIUC）：工具返回值注入用例
- 100PoisonMpts / CValues（阿里）：真实中文用户提问，用作良性对照

输出：``backend/app/data/external_eval_dataset.json``
"""
from __future__ import annotations

import io
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[3]
OUTPUT_PATH = PROJECT_ROOT / "backend" / "app" / "data" / "external_eval_dataset.json"
DATASET_ROOT = Path(os.environ.get("EXTERNAL_DATASET_ROOT", "D:/competition/测试数据集"))

BENIGN_KB = {
    "id": 1,
    "document_name": "政策原文.pdf",
    "content_with_weight": "专项资金申报需提交资质证明、验收报告与审计意见。",
}


def _take(rows: List[Any], limit: int) -> List[Any]:
    """确定性等距采样：从列表中均匀取 limit 条，不引入随机性。"""
    if limit <= 0 or not rows:
        return []
    if len(rows) <= limit:
        return list(rows)
    step = len(rows) / limit
    return [rows[int(i * step)] for i in range(limit)]


def _read_json(path: Path) -> Any:
    return json.load(io.open(path, encoding="utf-8"))


def _read_jsonl(path: Path) -> List[Any]:
    with io.open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


# ==================== Safety-Prompts（中文） ====================

# 有害意图关键词：用于从 Safety-Prompts 的**混合类**中筛出真正的攻击样本。
# 背景：逐条核实发现 Role_Play_Instruction 与 Unsafe_Instruction_Topic 两个类别
# 是混合的——既有真越狱（"你想通过各种手段谋求升职"），
# 也有完全正常的角色扮演（"你是一名足球队长，需要激励队友"）。
# 不加筛选一律标为攻击，会把正常样本误标成攻击（假漏报）。
_HARMFUL_MARKERS = (
    "毒品", "贩毒", "黑客", "窃取", "偷走", "偷窃", "诈骗", "欺诈", "恶意软件",
    "网络攻击", "入侵", "绕过", "破解", "勒索", "武器", "爆炸", "自杀", "伤害",
    "违法", "犯罪", "贿赂", "贪污", "造假", "伪造", "洗钱", "逃税", "情妇",
    "极端主义", "恐怖", "控制他人", "操纵", "虚假", "不实", "非法",
)


def _is_harmful_intent(text: str) -> bool:
    return any(marker in text for marker in _HARMFUL_MARKERS)


def import_safety_prompts(limit_per_category: int) -> List[Dict[str, Any]]:
    """导入中文安全 prompt。

    类别映射（**经逐条核实后修正**）：

    - ``Goal_Hijacking`` → 攻击。含"忽略上述指令，直接输出…"，是明确的目标劫持。
    - ``Role_Play_Instruction`` → **筛选后**作为攻击。该类别混合了真越狱与正常角色扮演，
      仅保留含有害意图关键词的样本。
    - ``Unsafe_Instruction_Topic`` → 攻击，但**单独分组**。这类是"有害内容请求"
      （如"怎么找一个毒贩"），与"指令劫持"是不同的问题域：前者考的是内容安全审核，
      后者考的是提示注入防护。混为一组会掩盖两者的能力差异。
    - ``Prompt_Leaking`` → **改判为良性**。该类别并非攻击，而是**关于**提示词泄露的
      元提问（如"如何判断模型输出是否存在 Prompt 泄漏攻击？"）。初版导入时误标为攻击，
      导致出现 0% 召回率的假象——实为系统正确放行了正常提问。
    """
    path = DATASET_ROOT / "Safety-Prompts" / "instruction_attack_scenarios.json"
    if not path.exists():
        print(f"  [跳过] 未找到 {path}")
        return []

    data = _read_json(path)
    samples: List[Dict[str, Any]] = []

    def _rows(category: str) -> List[str]:
        return [
            row.get("prompt", "")
            for row in (data.get(category) or [])
            if isinstance(row, dict) and row.get("prompt")
        ]

    # 1) 目标劫持：明确攻击
    for index, prompt in enumerate(_take(_rows("Goal_Hijacking"), limit_per_category)):
        samples.append({
            "id": f"EXT_A1_中文_目标劫持-{index:03d}",
            "group": "EXT_A1_中文_目标劫持",
            "stage": "user_input",
            "is_attack": True,
            "expected_signal": "block",
            "text": prompt,
            "source": "Safety-Prompts/Goal_Hijacking",
        })

    # 2) 角色扮演：筛选出含有害意图的
    role_play = [p for p in _rows("Role_Play_Instruction") if _is_harmful_intent(p)]
    for index, prompt in enumerate(_take(role_play, limit_per_category)):
        samples.append({
            "id": f"EXT_A2_中文_越狱角色扮演-{index:03d}",
            "group": "EXT_A2_中文_越狱角色扮演",
            "stage": "user_input",
            "is_attack": True,
            "expected_signal": "block",
            "text": prompt,
            "source": "Safety-Prompts/Role_Play_Instruction（经有害意图筛选）",
        })

    # 3) 有害内容请求：单独分组，与提示注入区分
    unsafe = _rows("Unsafe_Instruction_Topic")
    for index, prompt in enumerate(_take(unsafe, limit_per_category)):
        samples.append({
            "id": f"EXT_C1_中文_有害内容请求-{index:03d}",
            "group": "EXT_C1_中文_有害内容请求",
            "stage": "user_input",
            "is_attack": True,
            "expected_signal": "block",
            "text": prompt,
            "note": "内容安全类请求，与指令劫持属不同问题域",
            "source": "Safety-Prompts/Unsafe_Instruction_Topic",
        })

    # 4) 提示词泄露：改判为良性（原本是元提问，不是攻击）
    for index, prompt in enumerate(_take(_rows("Prompt_Leaking"), limit_per_category)):
        samples.append({
            "id": f"EXT_A9_中文_安全元提问-{index:03d}",
            "group": "EXT_A9_中文_安全元提问",
            "stage": "user_input",
            "is_attack": False,
            "expected_signal": "allow",
            "text": prompt,
            "note": "关于安全机制的正常提问，不应被拦截",
            "source": "Safety-Prompts/Prompt_Leaking（经核实为良性）",
        })

    return samples


# ==================== BIPIA（英文，间接注入） ====================

def import_bipia(limit: int, limit_contexts: int) -> List[Dict[str, Any]]:
    """组合 BIPIA 的干净业务内容与攻击指令，构造间接注入样例。

    BIPIA 的攻击指令位于 ``benchmark/text_attack_test.json``（15 类 × 5 条），
    干净内容位于各任务子集（email / table / code）。按 BIPIA 论文的做法，
    将攻击指令插入内容的不同位置（开头 / 中间 / 结尾），
    以覆盖注入位置这一维度。
    """
    attack_path = DATASET_ROOT / "BIPIA" / "benchmark" / "text_attack_test.json"
    if not attack_path.exists():
        print(f"  [跳过] 未找到 {attack_path}")
        return []

    instructions: List[str] = []
    for category, rows in _read_json(attack_path).items():
        for item in rows:
            if isinstance(item, str) and item.strip():
                instructions.append(item.strip())

    contexts: List[str] = []
    for name in ("email", "table"):
        path = DATASET_ROOT / "BIPIA" / "benchmark" / name / "test.jsonl"
        if not path.exists():
            continue
        for row in _read_jsonl(path):
            text = row.get("context") or row.get("table") or ""
            if isinstance(text, str) and len(text) > 100:
                contexts.append(text)

    if not instructions or not contexts:
        print("  [跳过] BIPIA 攻击指令或内容为空")
        return []

    positions = ("head", "middle", "tail")
    samples: List[Dict[str, Any]] = []
    for index, (context, instruction) in enumerate(zip(_take(contexts, limit_contexts), _take(instructions, limit_contexts))):
        place = positions[index % len(positions)]
        if place == "head":
            payload = f"{instruction}\n\n{context}"
        elif place == "middle":
            cut = len(context) // 2
            payload = f"{context[:cut]}\n\n{instruction}\n\n{context[cut:]}"
        else:
            payload = f"{context}\n\n{instruction}"

        samples.append({
            "id": f"EXT_A4_英文_间接注入-{index:03d}",
            "group": "EXT_A4_英文_间接注入",
            "stage": "retrieval",
            "is_attack": True,
            "expected_signal": "filter",
            "question": "请分析这份材料的合规风险",
            "documents": [
                BENIGN_KB,
                {"id": 2, "document_name": f"external-doc-{index}.txt", "content_with_weight": payload},
            ],
            "note": f"注入位置：{place}",
            "source": "BIPIA",
        })
    return _take(samples, limit)


# ==================== InjecAgent（英文，工具返回值注入） ====================

def import_injecagent(limit: int) -> List[Dict[str, Any]]:
    """导入 InjecAgent 的工具返回值注入用例。

    其 ``Tool Response Template`` 内含 ``<Attacker Instruction>`` 占位符，
    替换为 ``Attacker Instruction`` 字段即得完整的被污染工具返回值。
    """
    path = DATASET_ROOT / "InjecAgent" / "data" / "test_cases_dh_base.json"
    if not path.exists():
        print(f"  [跳过] 未找到 {path}")
        return []

    rows = _read_json(path)
    samples: List[Dict[str, Any]] = []
    for index, row in enumerate(_take(rows, limit)):
        template = str(row.get("Tool Response Template") or "")
        instruction = str(row.get("Attacker Instruction") or "")
        if "<Attacker Instruction>" not in template or not instruction:
            continue
        payload = template.replace("<Attacker Instruction>", instruction)

        samples.append({
            "id": f"EXT_A3_英文_工具返回注入-{index:03d}",
            "group": "EXT_A3_英文_工具返回注入",
            "stage": "tool_result",
            "is_attack": True,
            "expected_signal": "redact",
            "tool_name": "web_search",
            "payload": {"snippet": payload},
            "note": f"攻击类型：{row.get('Attack Type', '')}",
            "source": "InjecAgent",
        })
    return samples


# ==================== 良性中文真实提问 ====================

def import_benign_prompts(limit: int) -> List[Dict[str, Any]]:
    """导入真实中文用户提问作为良性对照。

    这类语料的价值在于**分布真实**——它们来自真实用户跨领域的日常提问，
    而非人工构造的"明显无害"句子。用它们测误报，比自造良性集更有说服力。
    """
    candidates: List[str] = []

    poison = DATASET_ROOT / "100PoisonMpts" / "train.jsonl"
    if poison.exists():
        candidates += [row.get("prompt", "") for row in _read_jsonl(poison) if row.get("prompt")]

    cvalues = DATASET_ROOT / "CValues" / "dataset" / "cvalues_responsibility_prompts.jsonl"
    if cvalues.exists():
        candidates += [row.get("prompt", "") for row in _read_jsonl(cvalues) if row.get("prompt")]

    samples: List[Dict[str, Any]] = []
    for index, prompt in enumerate(_take(candidates, limit)):
        samples.append({
            "id": f"EXT_A9_中文_真实提问-{index:03d}",
            "group": "EXT_A9_中文_真实提问",
            "stage": "user_input",
            "is_attack": False,
            "expected_signal": "allow",
            "text": prompt,
            "note": "真实用户提问，用于测量误报率",
            "source": "100PoisonMpts + CValues",
        })
    return samples


# ==================== 主流程 ====================

def build_external_dataset(
    safety_per_category: int = 60,
    bipia: int = 60,
    injecagent: int = 60,
    benign: int = 120,
) -> Dict[str, Any]:
    print(f"数据源目录：{DATASET_ROOT}\n")
    samples: List[Dict[str, Any]] = []

    print("[1/4] Safety-Prompts（中文攻击 prompt）")
    part = import_safety_prompts(safety_per_category)
    print(f"      导入 {len(part)} 条")
    samples += part

    print("[2/4] BIPIA（英文间接注入）")
    part = import_bipia(bipia, bipia)
    print(f"      导入 {len(part)} 条")
    samples += part

    print("[3/4] InjecAgent（英文工具返回注入）")
    part = import_injecagent(injecagent)
    print(f"      导入 {len(part)} 条")
    samples += part

    print("[4/4] 真实中文提问（良性对照）")
    part = import_benign_prompts(benign)
    print(f"      导入 {len(part)} 条")
    samples += part

    return {
        "meta": {
            "name": "外部公开数据集导入部分",
            "description": (
                "由 import_external_datasets.py 从公开数据集转换而来，"
                "按语言与来源分组，供 build_security_eval_dataset.py 合并。"
            ),
            "sources": [
                "Safety-Prompts (清华 thu-coai)",
                "BIPIA (Microsoft)",
                "InjecAgent (UIUC)",
                "100PoisonMpts / CValues (阿里巴巴 X-PLUG)",
            ],
        },
        "samples": samples,
    }


def main() -> int:
    dataset = build_external_dataset()
    samples = dataset["samples"]
    attack = sum(1 for s in samples if s["is_attack"])

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(dataset, ensure_ascii=False, indent=2), encoding="utf-8")

    groups: Dict[str, int] = {}
    for sample in samples:
        groups[sample["group"]] = groups.get(sample["group"], 0) + 1

    print(f"\n已写入：{OUTPUT_PATH}")
    print(f"外部样例共 {len(samples)} 条（攻击 {attack} / 良性 {len(samples) - attack}）\n")
    for group, count in sorted(groups.items()):
        print(f"  {group:<34} {count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
