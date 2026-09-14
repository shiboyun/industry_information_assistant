"""Reusable local detectors for RAG and tool-use security hooks."""
from __future__ import annotations

import copy
import re
from typing import Any, Dict, Iterable, List, Tuple

from config.security_config import ATTACK_TYPES, DANGEROUS_WORDS

from .normalize import expand_obfuscation, looks_like_padding, normalize_text


RISK_ORDER = {"low": 10, "medium": 50, "high": 80, "critical": 100}
RISK_LABEL = {"low": "low", "medium": "medium", "high": "high", "critical": "critical"}

PROMPT_INJECTION_PATTERNS = [
    # 指代前文的限定词在真实语料里远不止"之前/以上/所有"：
    # 公开数据集（Safety-Prompts）中出现最多的是"上述"，此外还有"前述/上文/刚才"等。
    # 初版只列了三个词，导致这类变体全部漏报（外部数据评测暴露）。
    r"忽略(之前|以上|所有|上述|前述|前面|刚才|上文|上下文|以上全部).{0,12}(指令|规则|要求|设定|命令|约束)",
    r"无视(之前|以上|所有|上述|前述|前面|刚才|上文).{0,12}(指令|规则|要求|设定|命令|约束)",
    # 目标劫持的典型句式：「忽略…，直接输出：<攻击者期望的内容>」。
    # 要求出现输出类动词 + 冒号/引号（真实注入必然带明确的目标内容），
    # 以此把"忽略样式问题，直接回答"这类正常表述排除在外。
    r"(忽略|无视|忘记|抛弃).{0,20}(直接)?(输出|复述|重复|说出|回答|改写)\s*[:：""'「『]",
    # 允许关键词之间插入定语：真实语料里常说「泄露**你的**系统提示词」，
    # 原先的 ``泄露\s*`` 要求紧邻，导致这类变体全部漏报（评测集测出 81% 漏报后修正）。
    r"泄露.{0,10}(system\s*prompt|系统提示|系统指令|提示词|内部信息)",
    r"输出.{0,10}(提示词|系统指令|初始设定|内部配置|隐藏指令)",
    r"(重复|复述|重述|原样输出|一字不差).{0,15}(设定|提示词|指令|规则|配置)",
    r"(开发者模式|无限制模式|调试模式|管理员模式|无约束模式)",
    r"(没有任何限制|不受任何限制|解除.{0,4}限制|移除.{0,4}限制|放弃.{0,4}(安全|准则))",
    r"(忽略|无视|跳过|绕过).{0,10}(安全|限制|策略|规则|准则|审批)",
    r"(把|将).{0,10}(上面|上述|前述|参考内容|本段|这段).{0,10}(当作|视为|作为).{0,8}(指令|命令|最高优先级)",
    r"你的(真实|真正|实际)(任务|目标|身份).{0,8}(是|为)",
    r"(从现在|从此刻|接下来).{0,10}(只|不再|必须)",
    # ---- 越狱 / 角色扮演 ----
    # 说明：这类表述此前只产生 role_play_attack / jailbreak 标签，
    # 而这两个标签不在阻断集合里，导致越狱类攻击一条都拦不住（评测集测出 75% 漏报）。
    # 这里用足够精确的模式把它们提升到 prompt_injection，
    # 并保持对「扮演的角色」「成为行业龙头」这类正常表述不误伤。
    r"(假设|假装|扮演|模拟).{0,10}(没有任何限制|不受.{0,4}限制|无约束|无限制|不受约束)",
    r"没有任何限制的\s*(ai|助手|模型|系统)",
    r"(dan|do\s+anything\s+now)\s*(模式|mode)",
    r"(开发者模式|调试模式|管理员模式).{0,8}(回答|输出|运行|解除)",
    r"(为了|出于).{0,8}(测试|研究|教学|演练).{0,12}(假装|假设).{0,12}(不存在|失效|没有)",
    r"(假装|假设|就当).{0,15}(安全策略|安全限制|规则|限制).{0,8}(不存在|失效|无效)",
    r"(以|借|打着).{0,10}(学术研究|红队|演练|测试).{0,6}(为名|名义|之名)",
    r"(绕过|突破|规避).{0,8}(安全策略|访问控制|审批|检测|限制)",
    r"(解除|放弃|抛开).{0,6}(全部|所有|一切)?\s*(安全|伦理|准则|约束)",
    r"(虚构|小说|剧本|故事).{0,20}(如何|怎么).{0,10}(绕过|获取|泄露|突破)",

    # ---- 索要内部信息的动作句式 ----
    # 这类表述本身不含"注入"字样，只是要求模型输出内部配置，
    # 因此既有的关键词匹配够不到阻断阈值（评测集显示这是剩余漏报的最大来源）。
    # 模式要求「动作动词 + 受保护对象」，避免误伤正常讨论。
    r"(输出|返回|显示|给我|发我|复述|列出|逐条列|逐行|原样|完整).{0,12}"
    r"(系统提示|系统指令|系统消息|提示词|隐藏指令|初始设定|完整上下文|规则清单|开发者注释|禁止事项)",
    r"(角色说明|设定).{0,10}(清单|逐条|完整)?\s*(输出|列出|复述|给我)",

    # ---- 结构绕过 / 权限冒充 ----
    r"(把|将).{0,10}(限制|约束|规则).{0,8}(解除|取消|作废|全部解除)",
    r"(不再|不受|无须|无需).{0,8}(任何)?\s*(政策|规则|限制|约束|准则)",
    r"(当作|视为|当成).{0,8}(系统管理员|管理员|开发者)",
    r"(绕过|规避|突破).{0,8}(内容过滤|内容审核|检测|审批|限制|安全策略)",
    r"(把|将).{0,10}(内部数据|敏感数据|内部资料|内部文件).{0,10}(带出|导出|外发|发送)",
    r"(关闭|停用|禁用).{0,8}(审计日志|审计|日志记录|安全策略)",

    r"(system|developer|assistant|user)\s*:",
    r"<\|im_(start|end)\|>",
    r"begin\s+(system|developer)\s+prompt",
    # 英文字序多变（"Ignore all previous instructions" / "Ignore the above instructions"），
    # 单一词序会漏掉变体——评测集测出后改成允许插入修饰词。
    r"ignore\s+(all\s+|the\s+|any\s+)?(previous|prior|above|preceding)\s+(instructions|prompts|rules)",
    r"forget\s+(everything|all)\s+(above|previous|prior)",
    r"follow\s+these\s+instructions\s+instead",
    r"reveal\s+(the\s+)?(system\s+prompt|hidden\s+prompt)",
]

DESTRUCTIVE_SQL_PATTERNS = [
    r"\b(drop|delete|update|insert|alter|truncate|grant|revoke)\b",
    r"union\s+(all\s+)?select",
    r"(--|#|/\*|\*/|;)\s*\w",
    r"information_schema|xp_cmdshell|load_file|outfile|into\s+dumpfile",
    # 恒真式注入与时间盲注：评测集测出这些变体此前完全未覆盖
    r"\bor\s+1\s*=\s*1\b",
    r"'\s*or\s*'",
    r"\b(sleep|benchmark|pg_sleep)\s*\(",
    r"\bwaitfor\s+delay\b",
]

COMMAND_INJECTION_PATTERNS = [
    r"\b(rm\s+-rf|del\s+/[sfq]|format\s+[a-z]:|shutdown|taskkill)",
    r"powershell\s+.*(-enc|-encodedcommand)",
    r"\b(curl|wget)\b.*(\||>|;|&&)",
    # 敏感文件读取、反弹 shell、fork bomb、权限提升（评测集测出此前未覆盖）
    r"cat\s+/etc/|/etc/(passwd|shadow|sudoers)",
    r"\bnc\s+(-e|--exec)\b|\bncat\b.*-e\b|/dev/tcp/",
    r"\(\s*\)\s*\{\s*:\s*\|",
    r"\bchmod\s+(\+x|[0-7]*7[0-7]*)\b",
    r"\b(base64\s+-d|xxd\s+-r)\b.*\|",
]

# 查询串/片段中属于凭据的参数名（含常见厂商前缀，如 X-Amz-Signature）。
_SECRET_QUERY_KEY = (
    r"(?:signature|credential|access_token|refresh_token|id_token|api[_-]?key|apikey"
    r"|private_key|access_key|secret|password|passwd|pwd|session|token|auth|sig|code)"
)
_SECRET_QUERY_RE = re.compile(
    rf"([?&#])([\w\-]{{0,32}}?{_SECRET_QUERY_KEY}=)[^&\s#\"'<>]{{1,512}}", re.I
)

# 顺序敏感：更具体的模式必须先跑。
# 尤其 URL userinfo 必须早于邮箱——否则 postgres://user:pw@host 会被邮箱规则
# 误判成 "pw@host" 并打上错误标签。
SECRET_PATTERNS = [
    # PEM 私钥块（含无 END 的截断转储）
    (re.compile(
        r"-----BEGIN[ A-Z]{0,32}PRIVATE KEY-----[\s\S]{0,8192}?(?:-----END[ A-Z]{0,32}PRIVATE KEY-----|\Z)"
    ), "[私钥已脱敏]"),
    # 连接串与 URL 中的 userinfo（保留主机名以便定位问题）
    (re.compile(r"([a-zA-Z][a-zA-Z0-9+.\-]{0,31}://)[^/\s:@]{1,128}:[^/\s@]{1,128}@"), r"\1[已脱敏]@"),
    # 查询串/片段中的凭据参数（含 OAuth 隐式流放在 # 片段里的 token）
    (_SECRET_QUERY_RE, r"\1\2[已脱敏]"),
    # JWT（三段式）
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"), "[令牌已脱敏]"),
    # 各厂商令牌与访问密钥
    (re.compile(
        r"\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[opusr]_[A-Za-z0-9]{20,}"
        r"|xox[abposrce]-[A-Za-z0-9\-]{10,}|AIza[A-Za-z0-9_\-]{20,}"
        r"|sk-ant-[A-Za-z0-9_\-]{20,}|sk_live_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{12,20})\b"
    ), "[密钥已脱敏]"),
    # 以下为原有覆盖面
    (re.compile(r"(?<!\d)1\d{10}(?!\d)"), "[手机号已脱敏]"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[邮箱已脱敏]"),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "[密钥已脱敏]"),
    (re.compile(r"(?i)\b(api[_-]?key|token|password|secret)\s*[:=]\s*[^\s,;，；]+"), r"\1=[已脱敏]"),
    (re.compile(r"(?i)authorization\s*[:=]\s*bearer\s+[^\s,;，；]+"), "authorization=[已脱敏]"),
]


def text_from_payload(payload: Any) -> str:
    if payload is None:
        return ""
    if isinstance(payload, str):
        return payload
    if isinstance(payload, dict):
        parts = []
        for key, value in payload.items():
            if isinstance(value, (str, int, float, bool)):
                parts.append(f"{key}: {value}")
            elif isinstance(value, (dict, list, tuple)):
                parts.append(text_from_payload(value))
        return "\n".join(parts)
    if isinstance(payload, (list, tuple)):
        return "\n".join(text_from_payload(item) for item in payload)
    return str(payload)


def _scan_single_view(view: str) -> Tuple[int, List[str], List[str]]:
    """在单个文本视图上做关键词与正则匹配。"""
    labels: List[str] = []
    evidence: List[str] = []
    score = 0
    lowered = view.lower()

    for level in ("high", "medium", "low"):
        for word in DANGEROUS_WORDS.get(level, []):
            if word.lower() in lowered:
                score = max(score, RISK_ORDER[level])
                label = ATTACK_TYPES.get(word, "suspicious_content")
                labels.append(_normalize_label(label))
                evidence.append(f"{level.upper()} keyword matched: {word}")

    for pattern in PROMPT_INJECTION_PATTERNS:
        match = re.search(pattern, view, re.IGNORECASE)
        if match:
            score = max(score, RISK_ORDER["high"])
            labels.append("prompt_injection")
            evidence.append(f"Prompt injection pattern matched: {match.group(0)}")

    return score, labels, evidence


def classify_text(text: str) -> Tuple[int, str, List[str], List[str]]:
    """在原文、归一化文本与解码文本等多个视图上匹配，取最高风险。

    只在「非原文视图」命中时，证据里会标注是归一化还是解码后命中，
    便于审计时看清攻击用了哪种绕过手法。
    """
    original = str(text or "")
    normalized = normalize_text(original)
    labels: List[str] = []
    evidence: List[str] = []
    score = 0

    for view in expand_obfuscation(original):
        view_score, view_labels, view_evidence = _scan_single_view(view)
        if view_score <= 0 or not view_evidence:
            continue
        if view == original:
            marker = ""
        elif view == normalized:
            marker = "归一化后命中："
        else:
            marker = "解码后命中："
        score = max(score, view_score)
        labels.extend(view_labels)
        evidence.extend([f"{marker}{item}" for item in view_evidence] if marker else view_evidence)

    return score, risk_level(score), _dedupe(labels), _dedupe(evidence)


def classify_tool_params(tool_name: str, params: Dict[str, Any]) -> Tuple[int, List[str], List[str]]:
    text = text_from_payload(params)
    score, _, labels, evidence = classify_text(text)

    if tool_name in {"text2sql", "text2sql_query"}:
        question_or_sql = str(params.get("question") or params.get("sql") or text)
        for pattern in DESTRUCTIVE_SQL_PATTERNS:
            match = re.search(pattern, question_or_sql, re.IGNORECASE)
            if match:
                score = max(score, RISK_ORDER["critical"])
                labels.append("tool_destructive_sql")
                evidence.append(f"Destructive SQL pattern matched: {match.group(0)}")

    command = str(params.get("command") or "")
    if command:
        for pattern in COMMAND_INJECTION_PATTERNS:
            match = re.search(pattern, command, re.IGNORECASE)
            if match:
                score = max(score, RISK_ORDER["critical"])
                labels.append("tool_command_injection")
                evidence.append(f"Dangerous command pattern matched: {match.group(0)}")

    for value in (params.get("path"), params.get("file_path"), params.get("target_path")):
        if value and _has_path_traversal(str(value)):
            score = max(score, RISK_ORDER["critical"])
            labels.append("tool_path_traversal")
            evidence.append(f"Path traversal attempt matched: {value}")

    return score, _dedupe(labels), _dedupe(evidence)


def filter_retrieval_documents(documents: Iterable[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int, List[str], List[str]]:
    sanitized: List[Dict[str, Any]] = []
    score = 0
    labels: List[str] = []
    evidence: List[str] = []

    for doc in documents:
        doc_text = text_from_payload(_retrieval_text_fields(doc))
        name = doc.get("document_name") or doc.get("title") or doc.get("name") or doc.get("source") or "unknown"
        doc_score, _, doc_labels, doc_evidence = classify_text(doc_text)
        if doc_score >= RISK_ORDER["high"] or "prompt_injection" in doc_labels:
            score = max(score, doc_score, RISK_ORDER["high"])
            labels.append("retrieval_prompt_injection")
            evidence.append(f"Filtered retrieval document: {name}")
            evidence.extend(doc_evidence[:3])
            continue
        # 统计特征：语义正常但低熵高重复的填充/投毒内容，关键词与正则都抓不到
        if looks_like_padding(doc_text):
            score = max(score, RISK_ORDER["high"])
            labels.append("retrieval_padding_poisoning")
            evidence.append(f"Filtered padded retrieval document: {name}")
            continue
        sanitized.append(copy.deepcopy(doc))

    for index, doc in enumerate(sanitized, start=1):
        if isinstance(doc, dict) and "id" in doc:
            doc["id"] = index

    return sanitized, score, _dedupe(labels), _dedupe(evidence)


def redact_sensitive_values(payload: Any) -> Tuple[Any, List[str], List[str]]:
    labels: List[str] = []
    evidence: List[str] = []

    def redact_text(value: str) -> str:
        redacted = value
        for pattern, replacement in SECRET_PATTERNS:
            redacted, count = pattern.subn(replacement, redacted)
            if count:
                labels.append("sensitive_output_redacted")
                evidence.append(f"Redacted {count} sensitive value(s)")
        return redacted

    def walk(value: Any) -> Any:
        if isinstance(value, str):
            return redact_text(value)
        if isinstance(value, dict):
            return {key: walk(item) for key, item in value.items()}
        if isinstance(value, list):
            return [walk(item) for item in value]
        if isinstance(value, tuple):
            return tuple(walk(item) for item in value)
        return value

    return walk(copy.deepcopy(payload)), _dedupe(labels), _dedupe(evidence)


def risk_level(score: int) -> str:
    if score >= RISK_ORDER["critical"]:
        return "critical"
    if score >= RISK_ORDER["high"]:
        return "high"
    if score >= RISK_ORDER["medium"]:
        return "medium"
    return "low"


def _retrieval_text_fields(doc: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "content": doc.get("content") or doc.get("summary") or doc.get("snippet") or "",
        "content_with_weight": doc.get("content_with_weight") or "",
        "title": doc.get("document_name") or doc.get("title") or doc.get("name") or "",
    }


_URL_ENCODED_TRAVERSAL_RE = re.compile(r"(%2e|%2f|\.\.)[%2e%2f/\\]*", re.IGNORECASE)
_WINDOWS_DRIVE_RE = re.compile(r"^[a-zA-Z]:")


def _has_path_traversal(value: str) -> bool:
    """判定路径是否越界。

    评测集测出两处此前未覆盖的变体：
    - Windows 盘符路径（``C:\\Windows\\...``）——旧实现只查 ``/`` 与 ``\\`` 开头；
    - URL 编码穿越（``..%2f..%2f/etc/passwd``）与 ``....//`` 折叠写法。
    """
    if not value:
        return False
    normalized = value.replace("\\", "/")
    if value.startswith(("/", "\\")) or _WINDOWS_DRIVE_RE.match(value):
        return True
    if ".." in [part for part in normalized.split("/") if part]:
        return True
    lowered = value.lower()
    if "%2e" in lowered or "%2f" in lowered:
        return True
    # ``....//`` 折叠后等价于 ``../``
    return bool(re.search(r"\.{2,}\s*[/\\]", value))


def _normalize_label(label: str) -> str:
    mapping = {
        "系统命令执行": "command_execution",
        "代码注入": "code_injection",
        "SQL注入": "sql_injection",
        "数据破坏": "data_destruction",
        "权限绕过": "privilege_bypass",
        "信息泄露": "data_exfiltration",
        "越狱诱导": "jailbreak",
        "提示注入": "prompt_injection",
        "角色扮演攻击": "role_play_attack",
        "间接指令污染": "indirect_prompt_injection",
        "目标偏移": "goal_hijacking",
        "社会工程攻击": "social_engineering",
        "数据投毒": "data_poisoning",
        "探测行为": "reconnaissance",
        "敏感词探测": "sensitive_probe",
        "规避检测": "evasion",
    }
    return mapping.get(label, label)


def _dedupe(values: List[str]) -> List[str]:
    seen = set()
    result = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result
