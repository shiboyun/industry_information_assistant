from typing import Dict, Optional

from config.security_config import ATTACK_TYPES, DANGEROUS_WORDS, SECURITY_ENABLED

def multi_source_attack_detect(
    user_input: Optional[str] = None,
    web_text: Optional[str] = None,
    knowledge_text: Optional[str] = None
) -> Dict:
    """
    多源输入攻击识别：用户输入、网页文本、知识库内容
    识别：提示注入、间接指令污染、越狱诱导、数据投毒
    """
    source_list = []
    if user_input:
        source_list.append(f"【用户输入】：{user_input}")
    if web_text:
        source_list.append(f"【网页内容】：{web_text}")
    if knowledge_text:
        source_list.append(f"【知识库文本】：{knowledge_text}")

    if len(source_list) == 0:
        return {
            "风险状态": "无输入内容",
            "风险等级": "无",
            "风险类型": [],
            "分析说明": "未传入任何待检测文本"
        }
    all_text = "\n".join(source_list)

    if not SECURITY_ENABLED:
        return {
            "风险状态": "检测未启用",
            "风险等级": "无",
            "风险类型": [],
            "分析说明": "安全检测配置已关闭。"
        }

    matched_words = []
    risk_level = "无"
    for level in ("high", "medium", "low"):
        words = [word for word in DANGEROUS_WORDS.get(level, []) if word.lower() in all_text.lower()]
        if words:
            matched_words.extend(words)
            risk_level = {"high": "高", "medium": "中", "low": "低"}[level]
            break

    risk_found = len(matched_words) > 0
    risk_types = sorted({ATTACK_TYPES.get(word, "未知风险") for word in matched_words})

    if risk_found:
        return {
            "风险状态": "存在风险",
            "风险等级": risk_level,
            "风险类型": risk_types,
            "命中词": matched_words,
            "分析说明": "检测到文本包含高风险或可疑指令，可能影响政企 RAG 与智能体工具链安全。"
        }
    else:
        return {
            "风险状态": "无风险",
            "风险等级": "无",
            "风险类型": [],
            "分析说明": "未检测到提示注入、越狱诱导、数据投毒等攻击内容。"
        }
