"""插件 / Skill / 脚本 的供应链静态安全扫描（赛题方向三）。

赛题要求的四项能力：
- **代码行为检测** —— 基于 AST 遍历，而不是文本正则，避免被字符串/注释干扰；
- **依赖关系分析** —— 声明依赖与实际 import 的比对；
- **恶意逻辑识别** —— 动态执行、隐蔽外联、密钥读取、文件系统越权、子进程、混淆；
- **安全评级** —— A/B/C/D 四级 + 发布策略状态机。

威胁模型参照 MCP-SafetyBench（ICLR 2026）的 **server / host / user 三侧面**分类：
每个发现都标注它落在哪一侧，便于按面归因。

本模块只做**静态**分析：不执行被测代码。因此对混淆与动态拼接的检出能力有限，
这一局限已在报告 §14 中说明，动态沙箱验证列为后续工作。
"""
from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ---- 信任侧面（MCP-SafetyBench 三侧面） ----
SIDE_SERVER = "server"   # 组件自身的行为：外联、数据回传
SIDE_HOST = "host"       # 与宿主环境交互：子进程、文件系统、环境变量
SIDE_USER = "user"       # 面向使用者：声明与行为不符、混淆

# 规则 → (类别, 严重度分, 侧面)
_RULES: Dict[str, tuple] = {
    "SC-CODE-001": ("dynamic_execution", 85, SIDE_SERVER),   # eval / exec / compile / __import__
    "SC-EXEC-001": ("subprocess", 85, SIDE_HOST),            # subprocess / os.system / pty
    "SC-NET-001": ("covert_network", 80, SIDE_SERVER),       # requests / socket / urllib
    "SC-FS-001": ("fs_escape", 80, SIDE_HOST),               # 越权写 / 递归删除
    "SC-SECRET-001": ("secret_access", 55, SIDE_HOST),       # os.environ / getenv
    "SC-OBF-001": ("obfuscation", 60, SIDE_USER),            # 大段编码载荷
    "SC-DECL-001": ("declaration_mismatch", 80, SIDE_USER),  # 声明与行为不符
    "SC-DEP-001": ("undeclared_dependency", 25, SIDE_USER),  # 未声明依赖
    "SC-PARSE-001": ("unparsable", 50, SIDE_USER),           # 无法静态解析
}

_DYNAMIC_CALLS = {"eval", "exec", "compile", "__import__"}
_SUBPROCESS_ATTRS = {
    "subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output",
    "subprocess.check_call", "os.system", "os.popen", "os.exec", "os.execl", "os.execv",
    "os.spawn", "os.spawnl", "os.spawnv", "pty.spawn",
}
_NETWORK_ATTRS = {
    "requests.get", "requests.post", "requests.put", "requests.delete", "requests.patch",
    "requests.request", "requests.head", "requests.Session",
    "httpx.get", "httpx.post", "httpx.request", "httpx.Client", "httpx.AsyncClient",
    "urllib.request.urlopen", "urllib.request.Request",
    "socket.socket", "socket.create_connection",
    "aiohttp.ClientSession", "http.client.HTTPConnection", "http.client.HTTPSConnection",
}
_DESTRUCTIVE_ATTRS = {
    "shutil.rmtree", "os.remove", "os.unlink", "os.rmdir", "os.removedirs", "os.truncate",
}
# 编码/压缩载荷解码：插件里出现通常是混淆或外带数据的信号
_DECODE_ATTRS = {
    "base64.b64decode", "base64.standard_b64decode", "base64.urlsafe_b64decode",
    "binascii.a2b_base64", "binascii.unhexlify", "binascii.a2b_hex",
    "codecs.decode", "zlib.decompress", "marshal.loads", "bytes.fromhex",
}
_WRITE_MODES = set("wax+")
_BASE64_BLOB_RE = re.compile(r"^[A-Za-z0-9+/=\s]{100,}$")
_SYSTEM_PREFIXES = ("/etc/", "/var/", "/usr/", "/root/", "/bin/", "/sbin/", "/boot/", "C:\\Windows")


class ComponentStatus:
    """发布策略状态机（报告 §10.4）。"""

    UNREGISTERED = "未登记"
    PENDING_REVIEW = "已登记未审查"
    APPROVED = "审查通过"
    NEEDS_REVIEW = "风险变更，需重新审查"


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    evidence: str
    lineno: int
    side: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity,
            "evidence": self.evidence,
            "lineno": self.lineno,
            "side": self.side,
        }


@dataclass
class ComponentReport:
    name: str
    declared: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "low"
    rating: str = "A"
    status: str = ComponentStatus.UNREGISTERED
    source_hash: str = ""
    scanned_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "rating": self.rating,
            "status": self.status,
            "source_hash": self.source_hash,
            "scanned_at": self.scanned_at,
            "declared": self.declared,
            "findings": [f.to_dict() for f in self.findings],
        }


def _severity_of(score: int) -> str:
    if score >= 85:
        return "high"
    if score >= 55:
        return "medium"
    return "low"


def _level_of(score: int) -> str:
    if score >= 80:
        return "high"
    if score >= 50:
        return "medium"
    if score > 0:
        return "low"
    return "low"


def _rating_of(score: int) -> str:
    if score <= 0:
        return "A"
    if score < 40:
        return "B"
    if score < 80:
        return "C"
    return "D"


class _Scanner(ast.NodeVisitor):
    def __init__(self) -> None:
        self.findings: List[Finding] = []
        self.imports: set = set()
        self.network_literals: List[str] = []
        self._seen: set = set()

    # ---- 工具 ----

    def _emit(self, rule_id: str, evidence: str, lineno: int) -> None:
        key = (rule_id, lineno)
        if key in self._seen:
            return
        self._seen.add(key)
        category, score, side = _RULES[rule_id]
        self.findings.append(Finding(
            rule_id=rule_id,
            category=category,
            severity=_severity_of(score),
            evidence=evidence[:200],
            lineno=lineno or 0,
            side=side,
        ))

    @staticmethod
    def _dotted(node: ast.AST) -> str:
        """把 a.b.c 形式的属性链还原成字符串，否则返回空串。"""
        parts: List[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
            return ".".join(reversed(parts))
        return ""

    @staticmethod
    def _literal(node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    # ---- 访问器 ----

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.add(alias.name.split(".")[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            self.imports.add(node.module.split(".")[0])
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        dotted = self._dotted(node.func)
        name = dotted or (node.func.id if isinstance(node.func, ast.Name) else "")

        if name in _DYNAMIC_CALLS or name.startswith("importlib.import_module"):
            self._emit("SC-CODE-001", f"动态代码执行：{name}(...)", node.lineno)

        if name in _SUBPROCESS_ATTRS:
            self._emit("SC-EXEC-001", f"子进程/命令执行：{name}(...)", node.lineno)

        if name in _NETWORK_ATTRS:
            self._emit("SC-NET-001", f"网络调用：{name}(...)", node.lineno)
            for arg in list(node.args) + [kw.value for kw in node.keywords]:
                literal = self._literal(arg)
                if literal and ("://" in literal or literal.count(".") >= 1):
                    self.network_literals.append(literal)

        if name in _DECODE_ATTRS:
            self._emit("SC-OBF-001", f"解码/解压载荷：{name}(...)", node.lineno)

        if name in _DESTRUCTIVE_ATTRS:
            target = self._literal(node.args[0]) if node.args else None
            self._emit("SC-FS-001", f"破坏性文件操作：{name}({target or '...'})", node.lineno)

        if name in {"os.getenv"}:
            key = self._literal(node.args[0]) if node.args else None
            self._emit("SC-SECRET-001", f"读取环境变量：os.getenv({key or '...'})", node.lineno)

        if name == "open":
            self._check_open(node)

        self.generic_visit(node)

    def _check_open(self, node: ast.Call) -> None:
        path = self._literal(node.args[0]) if node.args else None
        mode = self._literal(node.args[1]) if len(node.args) > 1 else None
        if mode is None:
            for kw in node.keywords:
                if kw.arg == "mode":
                    mode = self._literal(kw.value)
        if not path:
            return
        normalized = path.replace("\\", "/")
        suspicious_path = (
            normalized.startswith("/")
            or (len(normalized) > 1 and normalized[1] == ":")
            or ".." in [p for p in normalized.split("/") if p]
            or normalized.startswith(_SYSTEM_PREFIXES)
            or any(normalized.startswith(p) for p in _SYSTEM_PREFIXES)
        )
        writing = bool(mode) and any(ch in _WRITE_MODES for ch in mode)
        if suspicious_path and writing:
            self._emit("SC-FS-001", f"向沙箱外路径写入：open({path!r}, {mode!r})", node.lineno)
        elif suspicious_path:
            self._emit("SC-FS-001", f"访问沙箱外路径：open({path!r})", node.lineno)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        dotted = self._dotted(node)
        if dotted in {"os.environ", "os.environb"}:
            self._emit("SC-SECRET-001", "读取全部环境变量：os.environ", node.lineno)
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        value = node.value
        if isinstance(value, str) and len(value) >= 100 and _BASE64_BLOB_RE.match(value):
            self._emit("SC-OBF-001", f"疑似编码载荷（{len(value)} 字符的 base64 串）", node.lineno)
        self.generic_visit(node)


def rule_catalog() -> List[Dict[str, Any]]:
    """规则目录：供接口/前端展示与报告引用。"""
    return [
        {
            "rule_id": rule_id,
            "category": category,
            "severity": _severity_of(score),
            "score": score,
            "side": side,
        }
        for rule_id, (category, score, side) in sorted(_RULES.items())
    ]


def scan_component(
    source: str,
    name: str = "unnamed-component",
    declared: Optional[Dict[str, Any]] = None,
) -> ComponentReport:
    """静态扫描一个组件的源码，返回含发现项、评分、评级与状态的报告。"""
    declared = dict(declared or {})
    report = ComponentReport(
        name=name,
        declared=declared,
        source_hash=hashlib.sha256((source or "").encode("utf-8")).hexdigest(),
        scanned_at=datetime.now(timezone.utc).isoformat(),
    )

    scanner = _Scanner()
    try:
        tree = ast.parse(source or "")
        scanner.visit(tree)
    except SyntaxError as exc:
        scanner._emit("SC-PARSE-001", f"无法静态解析（SyntaxError: {exc.msg}）", exc.lineno or 0)

    report.findings = list(scanner.findings)
    _apply_declaration_checks(report, scanner)
    _finalize(report)
    return report


def _apply_declaration_checks(report: ComponentReport, scanner: _Scanner) -> None:
    declared = report.declared or {}
    categories = {f.category for f in report.findings}

    # 1) 声明网络白名单，却发起了未在白名单内的网络调用
    permissions = declared.get("permissions") or {}
    if "network" in permissions and "covert_network" in categories:
        allowed = [str(host) for host in (permissions.get("network") or [])]
        undeclared_targets = [
            literal for literal in scanner.network_literals
            if not any(host and host in literal for host in allowed)
        ]
        if undeclared_targets or not allowed:
            sample = (undeclared_targets or scanner.network_literals or ["<未取到目标>"])[0]
            report.findings.append(Finding(
                rule_id="SC-DECL-001",
                category="declaration_mismatch",
                severity=_severity_of(_RULES["SC-DECL-001"][1]),
                evidence=f"声明网络白名单为 {allowed or '空'}，但代码访问 {sample[:120]}",
                lineno=0,
                side=SIDE_USER,
            ))

    # 2) 使用了未声明的依赖
    declared_deps = declared.get("dependencies")
    if isinstance(declared_deps, list):
        allowed_imports = {str(dep).split(".")[0].replace("-", "_").lower() for dep in declared_deps}
        stdlib = getattr(__import__("sys"), "stdlib_module_names", set())
        for module in sorted(scanner.imports):
            normalized = module.replace("-", "_").lower()
            if normalized in allowed_imports or module in stdlib:
                continue
            report.findings.append(Finding(
                rule_id="SC-DEP-001",
                category="undeclared_dependency",
                severity=_severity_of(_RULES["SC-DEP-001"][1]),
                evidence=f"使用了未声明依赖：{module}",
                lineno=0,
                side=SIDE_USER,
            ))


def _finalize(report: ComponentReport) -> None:
    scores = [_RULES[f.rule_id][1] for f in report.findings if f.rule_id in _RULES]
    if scores:
        # 取最高分，并让额外发现项小幅累加（上限 100），避免"多项低危"被淹没
        report.risk_score = min(100, max(scores) + 3 * (len(scores) - 1))
    else:
        report.risk_score = 0

    report.risk_level = _level_of(report.risk_score)
    report.rating = _rating_of(report.risk_score)

    declared = report.declared or {}
    if not declared:
        report.status = ComponentStatus.UNREGISTERED
    elif report.risk_score >= 80:
        report.status = ComponentStatus.NEEDS_REVIEW
    elif declared.get("reviewed") is True:
        report.status = ComponentStatus.APPROVED
    else:
        report.status = ComponentStatus.PENDING_REVIEW
