# backend/app/scripts/generate_rageval_dataset.py
"""
基于 RAGEval 论文方法，利用现有的行业配置自动生成跨行业评估数据集

使用方法：
    cd backend
    python -m app.scripts.generate_rageval_dataset

输出：
    - backend/data/rageval_multidomain.json    完整生成数据
    - backend/data/rageval_eval_dataset.json  兼容现有评估脚本的格式
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# 加载 .env
env_path = Path(__file__).parent.parent.parent / ".env"
load_dotenv(env_path)

import json
import asyncio
from typing import Dict, Any, List
from openai import AsyncOpenAI

# 复用现有行业配置
from app.config.industry_config import INDUSTRY_CONFIGS, get_all_industries
from app.config.llm_config import get_config


async def generate_industry_data(
        industry_id: str,
        llm_client: AsyncOpenAI,
        model: str = "qwen-plus"
) -> Dict[str, Any]:
    """
    为单个行业生成 RAGEval 数据集
    """
    config_obj = INDUSTRY_CONFIGS[industry_id]

    print(f"\n{'=' * 50}")
    print(f"📊 生成行业: {config_obj.name} ({industry_id})")
    print(f"{'=' * 50}")

    # ===== 步骤1：生成配置 (Configuration) =====
    config_prompt = f"""
请以纯 JSON 格式返回，不要包含任何其他文字、解释或 Markdown 标记。

你是一位行业研究专家。请根据以下行业信息，生成一份虚构但符合行业常识的配置数据。

**行业名称**：{config_obj.name}
**行业描述**：{config_obj.description}
**研究关键词**：{', '.join(config_obj.research_keywords)}
**新闻关键词**：{', '.join(config_obj.news_keywords[:5])}

请生成一个 JSON 配置，包含：
1. 一个虚构但有代表性的企业名称（在该行业中真实存在的知名企业）
2. 该行业的 3-5 个核心量化指标（如市场规模、增长率、渗透率等）
3. 该行业当前的热点议题 3 个

JSON 格式必须如下：
{{
    "company_name": "企业名称",
    "report_year": 2024,
    "market_size": {{"value": 数值, "unit": "亿元"}},
    "growth_rate": {{"value": 数值, "unit": "%"}},
    "key_metrics": {{
        "指标名称1": {{"value": 数值, "unit": "单位"}},
        "指标名称2": {{"value": 数值, "unit": "单位"}}
    }},
    "hot_topics": ["议题1", "议题2", "议题3"],
    "policy_context": "简要描述当前该行业的政策环境"
}}
"""

    resp = await llm_client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": config_prompt}],
        response_format={"type": "json_object"},
        temperature=0.3
    )
    raw_config = resp.choices[0].message.content
    print(f"   [DEBUG] Config 原始响应前 300 字符: {raw_config[:300]}...")

    try:
        config_data = json.loads(raw_config)
    except json.JSONDecodeError as e:
        raise ValueError(f"配置 JSON 解析失败: {e}\n原始内容: {raw_config[:500]}")

    if not isinstance(config_data, dict):
        raise ValueError(f"配置数据不是 dict，而是 {type(config_data)}，内容: {config_data[:200]}")

    # ===== 步骤2：生成文档 (Document) =====
    doc_prompt = f"""
你是一位资深的行业分析师。请根据以下行业信息和配置数据，撰写一篇深度行业研究报告。

行业名称：{config_obj.name}
行业描述：{config_obj.description}
研究关键词：{', '.join(config_obj.research_keywords)}

配置数据：
{json.dumps(config_data, indent=2, ensure_ascii=False)}

写作要求：
1. 报告必须包含以下章节：
   - 一、行业概况与市场规模
   - 二、政策环境与监管动态（要结合真实政策方向）
   - 三、核心技术/产品创新（大量使用行业专业术语）
   - 四、竞争格局与主要企业
   - 五、未来发展趋势与展望

2. 大量使用行业黑话和专业术语（如"车路协同"、"不良贷款率"、"光伏转换效率"等）
3. 每个章节至少 250 字，总字数 1500-2500 字
4. 数据要与配置数据一致，不要编造新数据
5. 格式为纯文本，不要使用 Markdown 标题符号（如 #、## 等）

开始撰写：
"""
    doc_resp = await llm_client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": doc_prompt}],
        temperature=0.7
    )
    document = doc_resp.choices[0].message.content

    # ===== 步骤3：生成 QRA（问题-答案-引用） =====
    qra_prompt = f"""
请以纯 JSON 格式返回，不要包含任何其他文字、解释或 Markdown 标记。

基于以下行业研究报告，生成 RAG 评估用的 (问题-答案-引用) 三元组。

行业：{config_obj.name}
文档内容：
{document}

任务：生成 5 个不同类型的问题

类型                数量  说明
事实性问题 (Factual)  2   基于文档中的具体数据，如市场规模、增长率
多跳推理 (Multi-hop)  1   需要结合多个段落推理得出，不要是简单的拼接
数值比较 (Comparison) 1   对比两个数据或指标
摘要性问题 (Summary)  1   概括某一部分的核心内容

JSON 格式必须如下：
{{
    "qas": [
        {{
            "type": "Factual",
            "question": "问题内容",
            "answer": "标准答案（完整、准确）",
            "references": ["支撑答案的原文句子1（逐字复制）", "原文句子2"]
        }},
        ...
    ]
}}

重要：
- references 必须从文档中逐字复制，不要修改
- 答案要准确完整，覆盖关键信息
- 问题要有一定难度，不能太简单
"""

    qra_resp = await llm_client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": qra_prompt}],
        response_format={"type": "json_object"},
        temperature=0.4
    )
    raw_qra = qra_resp.choices[0].message.content
    print(f"   [DEBUG] QRA 原始响应前 300 字符: {raw_qra[:300]}...")

    try:
        qra_data = json.loads(raw_qra)
    except json.JSONDecodeError as e:
        raise ValueError(f"QRA JSON 解析失败: {e}\n原始内容: {raw_qra[:500]}")

    if not isinstance(qra_data, dict):
        raise ValueError(f"QRA 数据不是 dict，而是 {type(qra_data)}，内容: {qra_data[:200]}")
    if "qas" not in qra_data:
        raise ValueError(f"QRA 数据缺少 'qas' 键，实际键: {list(qra_data.keys())}")

    # ===== 步骤4：提取 Keypoints（用于 RAGEval 评分） =====
    keypoint_prompt = f"""
请以纯 JSON 格式返回，不要包含任何其他文字、解释或 Markdown 标记。

请为以下每个答案提取 3-5 个关键点 (Keypoints)，用于后续的 RAGEval 评估。

评估规则：
- Completeness（完整性）：检查答案是否覆盖了这些关键点
- Hallucination（幻觉率）：检查答案是否错误/矛盾了这些关键点
- Irrelevance（不相关度）：检查答案是否忽略或跳过了这些关键点

问题列表：
{json.dumps(qra_data['qas'], indent=2, ensure_ascii=False)}

对于每个问题，JSON 格式必须如下：
[
    {{
        "question": "原问题",
        "answer": "原答案",
        "keypoints": ["关键点1", "关键点2", "关键点3", ...]
    }},
    ...
]

要求：
- 关键点之间要相对独立
- 每个关键点包含一个完整的语义单元
- 至少 3 个，最多 5 个
"""

    kp_resp = await llm_client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": keypoint_prompt}],
        response_format={"type": "json_object"},
        temperature=0.2
    )
    raw_kp = kp_resp.choices[0].message.content
    print(f"   [DEBUG] Keypoints 原始响应前 300 字符: {raw_kp[:300]}...")

    try:
        keypoints_data = json.loads(raw_kp)
    except json.JSONDecodeError as e:
        raise ValueError(f"Keypoints JSON 解析失败: {e}\n原始内容: {raw_kp[:500]}")

    # 注意：keypoints_data 应该是列表，但也可能是 dict
    if isinstance(keypoints_data, dict):
        # 如果返回的是对象，尝试提取列表
        if "keypoints" in keypoints_data:
            keypoints_data = keypoints_data["keypoints"]
        else:
            # 尝试获取第一个值
            for v in keypoints_data.values():
                if isinstance(v, list):
                    keypoints_data = v
                    break
    if not isinstance(keypoints_data, list):
        raise ValueError(f"Keypoints 数据不是 list，而是 {type(keypoints_data)}，内容: {keypoints_data[:200]}")

    # 构建映射
    kp_map = {}
    for item in keypoints_data:
        if isinstance(item, dict) and "question" in item and "keypoints" in item:
            kp_map[item["question"]] = item["keypoints"]
        else:
            print(f"   ⚠️ 跳过无效的 keypoints 条目: {item}")

    for qa in qra_data["qas"]:
        qa["keypoints"] = kp_map.get(qa["question"], [])

    print(f" ✅ 生成完成：{len(qra_data['qas'])} 个问答")

    return {
        "industry_id": industry_id,
        "industry_name": config_obj.name,
        "industry_description": config_obj.description,
        "config": config_data,
        "document": document,
        "qas": qra_data["qas"],
    }


def convert_to_eval_format(all_industry_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    将生成的行业数据转换为兼容现有评估脚本的格式
    包含 keypoints 字段，供 RAGEval 指标计算使用
    """
    eval_dataset = []
    for industry_data in all_industry_data:
        for qa in industry_data["qas"]:
            eval_dataset.append({
                "id": f"{industry_data['industry_id']}_{hash(qa['question'])}",
                "question": qa["question"],
                "answer": qa["answer"],
                "contexts": qa.get("references", []),
                "ground_truth": qa["answer"],
                "industry": industry_data["industry_name"],
                "question_type": qa.get("type", "Factual"),
                "keypoints": qa.get("keypoints", [])
            })
    return eval_dataset


async def main():
    """主函数：循环生成所有行业的数据集"""
    config = get_config()
    client = AsyncOpenAI(
        api_key=config.api_key,
        base_url=config.base_url
    )

    industries = get_all_industries()
    print(f"📋 共发现 {len(industries)} 个行业：{[i['name'] for i in industries]}")

    all_data = []
    for industry in industries:
        try:
            result = await generate_industry_data(
                industry_id=industry["id"],
                llm_client=client
            )
            all_data.append(result)
        except Exception as e:
            print(f" ❌ 生成失败: {e}")
            continue


    from pathlib import Path
    data_dir = Path(__file__).parent.parent / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    output_full = data_dir / "rageval_multidomain.json"
    with open(output_full, "w", encoding="utf-8") as f:
        json.dump(all_data, f, indent=2, ensure_ascii=False)
    print(f"\n📁 完整数据已保存: {output_full}")

    eval_dataset = convert_to_eval_format(all_data)
    output_eval = data_dir / "rageval_eval_dataset.json"
    with open(output_eval, "w", encoding="utf-8") as f:
        json.dump(eval_dataset, f, indent=2, ensure_ascii=False)

    print(f"📋 评估数据集已保存: {output_eval}")
    print(f"📊 总计: {len(eval_dataset)} 条评估样本")

    print("\n" + "="*60)
    print("📊 数据集统计")
    print("="*60)
    for d in all_data:
        qas = d["qas"]
        types = {}
        for qa in qas:
            t = qa.get("type", "Unknown")
            types[t] = types.get(t, 0) + 1
        print(f"\n🏢 {d['industry_name']}")
        print(f"   总问答: {len(qas)} 条")
        print(f"   问题类型: {json.dumps(types, ensure_ascii=False)}")


if __name__ == "__main__":
    asyncio.run(main())