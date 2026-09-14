"""竞赛原型的受限演示工具。

这不是生产级隔离边界。生产环境必须改为独立容器或专用执行服务。
"""
import ast
import io
import platform
import subprocess
import sys
import hashlib
import re
from pathlib import Path, PureWindowsPath
from typing import Any, Dict
from contextlib import redirect_stdout

PROJECT_ROOT = Path(__file__).resolve().parents[3]
SANDBOX_ROOT = PROJECT_ROOT / "data" / "security_sandbox"
ALLOWED_EXTENSIONS = {".txt", ".json", ".csv"}
MAX_CONTENT_BYTES = 64 * 1024


def _redact_delivery_summary(value: str) -> str:
    """将演示递送内容压缩为可审计但不含常见直接标识符的摘要。"""
    compact = re.sub(r"\s+", " ", value).strip()
    compact = re.sub(r"(?<!\d)1\d{10}(?!\d)", "[手机号已脱敏]", compact)
    compact = re.sub(r"[\w.+-]+@[\w.-]+", "[邮箱已脱敏]", compact)
    return compact[:500] or "（未提供报告摘要）"


def execute_report_export_delivery(params: Dict[str, Any]) -> Dict[str, Any]:
    """生成本地报告与模拟接收回执，绝不进行网络发送。"""
    title = str(params.get("report_title", "未命名投标情报报告")).strip()[:120]
    content = str(params.get("report_content", "")).strip()
    business_task = str(params.get("business_task", "投标情报分析")).strip()[:200]
    if not content:
        raise ValueError("报告内容不能为空")
    if len(content.encode("utf-8")) > MAX_CONTENT_BYTES:
        raise ValueError("报告内容超过 64KB 演示限制")

    delivery_id = hashlib.sha256(f"{title}|{content}".encode("utf-8")).hexdigest()[:16]
    outbox = SANDBOX_ROOT / "report_delivery" / "outbox"
    receiver = SANDBOX_ROOT / "report_delivery" / "mock_receiver"
    outbox.mkdir(parents=True, exist_ok=True)
    receiver.mkdir(parents=True, exist_ok=True)
    report_path = outbox / f"{delivery_id}.txt"
    receipt_path = receiver / f"{delivery_id}.json"
    report_path.write_text(f"# {title}\n\n业务任务：{business_task}\n\n{content}\n", encoding="utf-8")
    summary = _redact_delivery_summary(content)
    receipt_path.write_text(
        '{"delivery_id":"%s","channel":"local_mock_receiver","summary":"%s"}'
        % (delivery_id, json_escape(summary)),
        encoding="utf-8",
    )
    return {
        "delivery_id": delivery_id,
        "mode": "local_mock_only",
        "report_path": str(Path("data") / "security_sandbox" / report_path.relative_to(SANDBOX_ROOT)),
        "receipt_path": str(Path("data") / "security_sandbox" / receipt_path.relative_to(SANDBOX_ROOT)),
        "summary": summary,
    }


def json_escape(value: str) -> str:
    """避免为了一个演示回执引入外部发送或复杂依赖。"""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def validate_sandbox_path(path_value: str) -> Path:
    candidate = Path(path_value)
    normalized = path_value.replace("\\", "/")
    windows_drive_path = bool(re.match(r"^[A-Za-z]:", normalized))
    if (
        candidate.is_absolute()
        or PureWindowsPath(path_value).is_absolute()
        or path_value.startswith(("/", "\\"))
        or windows_drive_path
        or ".." in [part for part in normalized.split("/") if part]
    ):
        raise ValueError("仅允许访问项目安全沙箱内的相对路径")
    if candidate.suffix.lower() not in ALLOWED_EXTENSIONS:
        raise ValueError("只允许写入 .txt、.json 或 .csv 文件")
    target = (SANDBOX_ROOT / candidate).resolve()
    if SANDBOX_ROOT.resolve() not in target.parents:
        raise ValueError("目标路径超出安全沙箱")
    return target


def execute_sandbox_file_write(params: Dict[str, Any]) -> Dict[str, Any]:
    target = validate_sandbox_path(str(params.get("path", "")))
    content = str(params.get("content", ""))
    if not content:
        raise ValueError("写入内容不能为空")
    if len(content.encode("utf-8")) > MAX_CONTENT_BYTES:
        raise ValueError("写入内容超过 64KB 限制")
    SANDBOX_ROOT.mkdir(parents=True, exist_ok=True)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return {"path": str(target.relative_to(PROJECT_ROOT)), "bytes_written": len(content.encode("utf-8"))}


def execute_sandbox_command(params: Dict[str, Any]) -> Dict[str, Any]:
    command = str(params.get("command", ""))
    if command == "runtime_info":
        return {"command": command, "output": f"Python {sys.version.split()[0]} on {platform.system()}"}
    if command == "python_version":
        completed = subprocess.run(
            [sys.executable, "--version"],
            capture_output=True,
            text=True,
            timeout=3,
            shell=False,
            check=False,
        )
        return {"command": command, "output": (completed.stdout or completed.stderr).strip()[:512]}
    raise ValueError("命令不在白名单中")


def execute_restricted_code(params: Dict[str, Any]) -> Dict[str, Any]:
    """仅用于审批演示的受限计算代码，不支持导入、文件或网络访问。"""
    code = str(params.get("code", ""))
    if not code or len(code) > 4096:
        raise ValueError("代码不能为空且不能超过 4KB")
    tree = ast.parse(code, mode="exec")
    forbidden = (ast.Import, ast.ImportFrom, ast.Attribute, ast.Subscript, ast.Lambda,
                 ast.FunctionDef, ast.ClassDef, ast.With, ast.Try, ast.While, ast.For,
                 ast.AsyncFor, ast.Delete, ast.Global, ast.Nonlocal, ast.ListComp,
                 ast.SetComp, ast.DictComp, ast.GeneratorExp, ast.Await, ast.Yield,
                 ast.YieldFrom)
    if any(isinstance(node, forbidden) for node in ast.walk(tree)):
        raise ValueError("演示代码只能进行基础计算，禁止导入、属性访问、循环和文件/网络操作")
    if any(isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Pow, ast.LShift, ast.RShift, ast.MatMult)) for node in ast.walk(tree)):
        raise ValueError("演示代码不允许高资源消耗运算")
    if any(isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) > 1024 for node in ast.walk(tree)):
        raise ValueError("演示代码中的字符串常量不能超过 1KB")
    allowed_builtins = {"print": print, "len": len, "sum": sum, "min": min, "max": max, "range": range}
    invalid_calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call) and (not isinstance(node.func, ast.Name) or node.func.id not in allowed_builtins)
    ]
    if invalid_calls:
        raise ValueError("演示代码只允许调用明确白名单中的计算函数")
    output = io.StringIO()
    with redirect_stdout(output):
        exec(compile(tree, "<security-demo>", "exec"), {"__builtins__": allowed_builtins}, {})
    return {"output": output.getvalue()[:1024], "mode": "restricted_expression"}
