"""输入归一化与变形展开，以及针对「投毒填充」的统计特征。

为什么需要这一层：关键词/正则匹配的是**字面量**，而攻击者只需插入零宽字符、
把字拆开、用繁体或西里尔同形字、或把指令 base64 编码，就能让字面匹配全部失效。
报告 §14.1 已把这个短板写进局限性，本模块是对它的正面回应。

依赖策略：全部用标准库实现；``hanziconv`` 若可用则用它做完整繁简转换，
否则退回到内置的高频字表（覆盖安全领域常用字），保证离线可跑。
"""
from __future__ import annotations

import base64
import binascii
import math
import re
import unicodedata
from typing import Dict, List

try:  # 可选依赖：装了就用完整字表，没装也能工作
    from hanziconv import HanziConv  # type: ignore
except Exception:  # pragma: no cover - 取决于部署环境
    HanziConv = None  # type: ignore

# 零宽 / 双向控制 / 软连字符 / BOM / 词连接符
_INVISIBLE_RE = re.compile("[­​-‏‪-‮⁠-⁩﻿]")

# 常见西里尔/希腊同形字 → 拉丁字母
_HOMOGLYPHS: Dict[str, str] = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "у": "y", "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d", "ɡ": "g",
    "А": "A", "В": "B", "Е": "E", "Н": "H", "О": "O", "Р": "P",
    "С": "C", "Т": "T", "Х": "X", "М": "M", "К": "K",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I",
    "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T",
    "Υ": "Y", "Χ": "X", "ο": "o", "ν": "v", "ρ": "p",
}

# 内置繁→简表：覆盖安全领域与政企业务高频字。
_TRAD_TO_SIMP: Dict[str, str] = {
    "統": "统", "執": "执", "洩": "泄", "繞": "绕", "權": "权", "刪": "删",
    "獲": "获", "數": "数", "據": "据", "庫": "库", "讀": "读", "誌": "志",
    "碼": "码", "鑰": "钥", "擊": "击", "檢": "检", "測": "测", "過": "过",
    "隱": "隐", "驗": "验", "證": "证", "導": "导", "誘": "诱", "騙": "骗",
    "偽": "伪", "裝": "装", "變": "变", "為": "为", "內": "内", "網": "网",
    "頁": "页", "檔": "档", "設": "设", "計": "计", "規": "规", "則": "则",
    "請": "请", "詞": "词", "說": "说", "話": "话", "資": "资", "訊": "讯",
    "詢": "询", "單": "单", "業": "业", "務": "务", "員": "员", "級": "级",
    "書": "书", "寫": "写", "開": "开", "關": "关", "於": "于", "對": "对",
    "應": "应", "該": "该", "們": "们", "個": "个", "這": "这", "麼": "么",
    "樣": "样", "時": "时", "間": "间", "現": "现", "實": "实", "際": "际",
    "場": "场", "環": "环", "節": "节", "點": "点", "線": "线", "戶": "户",
    "體": "体", "義": "义", "確": "确", "認": "认", "執": "执", "傳": "传",
    "輸": "输", "轉": "转", "連": "连", "遠": "远", "選": "选", "錄": "录",
}

_CJK_RANGE = "一-鿿㐀-䶿"
_SEPARATOR_CLASS = r"\s　·・,，;；、。*＊_\-—+=~|/\\"
_CJK_SEPARATOR_RE = re.compile(
    f"(?<=[{_CJK_RANGE}])[{_SEPARATOR_CLASS}]+(?=[{_CJK_RANGE}])"
)

# 形似 base64 的长 token
_BASE64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/]{16,4096}={0,2}")

_MAX_DECODED_VIEWS = 5


def normalize_text(text: str) -> str:
    """把文本归一化成「用于匹配」的规范视图（不用于展示）。"""
    if not text:
        return text
    result = unicodedata.normalize("NFKC", str(text))
    result = _INVISIBLE_RE.sub("", result)
    if any(ch in _HOMOGLYPHS for ch in result):
        result = "".join(_HOMOGLYPHS.get(ch, ch) for ch in result)
    result = _to_simplified(result)
    # 仅合并「CJK 之间」的分隔符，避免破坏英文正常空格
    result = _CJK_SEPARATOR_RE.sub("", result)
    return result


def _to_simplified(text: str) -> str:
    if HanziConv is not None:
        try:
            return HanziConv.toSimplified(text)
        except Exception:
            pass
    if not any(ch in _TRAD_TO_SIMP for ch in text):
        return text
    return "".join(_TRAD_TO_SIMP.get(ch, ch) for ch in text)


def _decode_base64_tokens(text: str) -> List[str]:
    decoded: List[str] = []
    for match in _BASE64_TOKEN_RE.finditer(text):
        if len(decoded) >= _MAX_DECODED_VIEWS:
            break
        token = match.group(0)
        padded = token + "=" * (-len(token) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            plain = raw.decode("utf-8")
        except UnicodeDecodeError:
            plain = raw.decode("utf-8", errors="ignore")
        if _looks_like_text(plain):
            decoded.append(plain)
    return decoded


def _looks_like_text(value: str) -> bool:
    """过滤随机字节解出来的噪声，只保留「像文本」的解码结果。"""
    if len(value) < 6:
        return False
    printable = sum(1 for ch in value if ch.isprintable() or ch.isspace())
    if printable / len(value) < 0.85:
        return False
    cjk = sum(1 for ch in value if "一" <= ch <= "鿿")
    letters = sum(1 for ch in value if ch.isalpha())
    return cjk >= 2 or letters >= 4


def expand_obfuscation(text: str) -> List[str]:
    """返回同一输入的多个「视图」：原文、归一化文本、base64 解码结果。

    检测器会在所有视图上匹配，任一视图命中即视为命中，
    从而覆盖编码/隐写/拆字/同形字这几类绕过。
    """
    if not text:
        return [text]
    views: List[str] = [str(text)]
    normalized = normalize_text(text)
    if normalized not in views:
        views.append(normalized)
    for plain in _decode_base64_tokens(str(text)):
        if plain not in views:
            views.append(plain)
        normalized_plain = normalize_text(plain)
        if normalized_plain not in views:
            views.append(normalized_plain)
    return views


# ---------------- 统计特征（针对投毒填充） ----------------

_PADDING_MIN_LENGTH = 200
_PADDING_REPETITION_THRESHOLD = 0.7
_PADDING_ENTROPY_THRESHOLD = 1.5


def shannon_entropy(text: str) -> float:
    """字符级香农熵（比特/字符）。重复填充内容会显著偏低。"""
    if not text:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def repetition_ratio(text: str, n: int = 4) -> float:
    """重复 n-gram 占比。大量复读的填充内容会接近 1.0。"""
    if not text or len(text) < n:
        return 0.0
    grams = [text[i:i + n] for i in range(len(text) - n + 1)]
    if not grams:
        return 0.0
    unique = len(set(grams))
    return 1.0 - (unique / len(grams))


def longest_run_ratio(text: str) -> float:
    """最长连续重复字符段占全文比例。

    与 ``repetition_ratio``（整段复读）互补：它抓的是「同字符长串」这种
    简单填充，例如用大量重复字符撑长度。
    """
    if not text:
        return 0.0
    best = current = 1
    for index in range(1, len(text)):
        if text[index] == text[index - 1]:
            current += 1
            if current > best:
                best = current
        else:
            current = 1
    return best / len(text)


_PADDING_LONGEST_RUN_THRESHOLD = 0.25


def looks_like_padding(text: str) -> bool:
    """判定是否为「语义正常但统计异常」的填充/投毒内容。

    这是关键词与正则都抓不到的一类风险：内容本身没有违规词，
    但通过低熵、高重复或同字符长串的填充来挤占上下文或稀释检索结果。
    三项特征（熵 / 重复 n-gram / 最长连续段）任一中招即判定为填充——
    对齐 NeMo Guardrails 的 context bloat detection。
    """
    if not text or len(text) < _PADDING_MIN_LENGTH:
        return False
    return (
        repetition_ratio(text) >= _PADDING_REPETITION_THRESHOLD
        or shannon_entropy(text) <= _PADDING_ENTROPY_THRESHOLD
        or longest_run_ratio(text) >= _PADDING_LONGEST_RUN_THRESHOLD
    )
