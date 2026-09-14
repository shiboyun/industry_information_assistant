"""
安全策略模块：细粒度权限约束 + 动态策略校验

实现两类能力：
1. 细粒度权限约束 —— 针对不同工具、不同动作(如 file_operation 的 read/write/delete)
   赋予不同风险等级与审批要求，而非"一刀切"。
2. 动态策略校验 —— 将风险规则、命令黑名单、敏感路径黑名单、写文件扩展名白名单等
   抽成可配置项，支持运行时动态修改(见 security_router 的 PUT /security/policy)。
"""

import os
import re
import socket
import ipaddress
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


@dataclass
class PolicyConfig:
    """安全策略配置（可通过环境变量初始化，运行时动态修改）"""

    approval_mode: str = "auto_deny"  # manual / auto_deny / auto_approve
    max_high_risk_calls: int = 3      # 单会话高危操作调用上限
    max_total_calls: int = 20         # 单会话工具调用总数上限
    max_repeated_command: int = 2     # 同一命令允许重复执行的次数(超过则视为死循环)
    max_path_traversal_attempts: int = 2  # 路径穿越尝试次数上限(超过则阻断会话)
    max_repeated_call: int = 4        # 同一工具+参数重复调用上限(通用死循环检测，覆盖所有工具)

    # 命令黑名单：命中即硬性拒绝(即使在 auto_approve 模式下也不放行)
    command_denylist: List[str] = field(default_factory=lambda: [
        r"rm\s+-rf",                       # 递归强制删除
        r"format\s+[a-z]:",                # 格式化磁盘
        r"shutdown",                       # 关机
        r"taskkill",                       # 杀进程
        r"del\s+/[sfq]",                   # 强制删除文件
        r"powershell.*(-enc|-encodedcommand)",  # 编码执行
        r"curl.*>\s*/",                    # 下载并覆盖文件
        r"wget.*>\s*/",
        r":\(\)\s*\{\s*:\|:&\s*\};:",      # fork bomb
    ])

    # 敏感路径黑名单：命中即硬性拒绝(防止读取/篡改凭据、密钥)
    file_path_denylist: List[str] = field(default_factory=lambda: [
        r"\.env", r"\.ssh", r"id_rsa", r"id_ed25519",
        r"password", r"secret", r"credential", r"\.key\b", r"token",
    ])

    # 写文件扩展名白名单：仅允许写入这些类型的文件，防止落地可执行/脚本文件
    file_write_ext_allowlist: List[str] = field(default_factory=lambda: [
        ".txt", ".md", ".json", ".csv", ".log", ".yaml", ".yml", ".html",
    ])

    # 浏览器访问协议白名单
    url_scheme_allowlist: List[str] = field(default_factory=lambda: ["http", "https"])

    # SQL 危险语句黑名单(用于 text2sql 工具，防止注入/越权/拖库)
    sql_danger_patterns: List[str] = field(default_factory=lambda: [
        r"\b(drop|delete|insert|update|truncate|alter|create|grant|revoke)\b",  # 非查询/DDL 语句
        r"union\s+(all\s+)?select",          # union 注入
        r"(--|\#|/\*|\*/|;)\s*\w",           # 注释/多语句注入
        r"xp_cmdshell|load_file|outfile|into\s+dumpfile",  # 危险函数
        r"information_schema",               # 拖库探测
        r"删库|拖库",                          # 中文恶意意图
    ])

    # 搜索敏感关键词黑名单(用于 web_search / knowledge_search / bidding_search)
    search_keyword_denylist: List[str] = field(default_factory=lambda: [
        r"密码", r"口令", r"凭证", r"密钥", r"内部账号",
        r"password", r"secret", r"credential", r"token", r"api[_-]?key",
    ])

    # 股票代码格式白名单(用于 stock_query，防止非法输入/注入)
    stock_code_pattern: str = r"^(sh|sz|bj)?\d{6}$"

    @classmethod
    def from_env(cls) -> "PolicyConfig":
        return cls(
            approval_mode=os.getenv("SECURITY_APPROVAL_MODE", "auto_deny"),
            max_high_risk_calls=int(os.getenv("SECURITY_MAX_HIGH_RISK_CALLS", "3")),
            max_total_calls=int(os.getenv("SECURITY_MAX_TOTAL_CALLS", "20")),
            max_repeated_command=int(os.getenv("SECURITY_MAX_REPEATED_COMMAND", "2")),
            max_path_traversal_attempts=int(os.getenv("SECURITY_MAX_PATH_TRAVERSAL", "2")),
            max_repeated_call=int(os.getenv("SECURITY_MAX_REPEATED_CALL", "4")),
        )

    def update(self, patch: Dict[str, Any]) -> "PolicyConfig":
        """动态更新策略：仅更新提供的字段，未提供的保持不变"""
        for k, v in patch.items():
            if hasattr(self, k) and v is not None:
                setattr(self, k, v)
        return self

    def to_dict(self) -> Dict[str, Any]:
        return {
            "approval_mode": self.approval_mode,
            "max_high_risk_calls": self.max_high_risk_calls,
            "max_total_calls": self.max_total_calls,
            "max_repeated_command": self.max_repeated_command,
            "max_path_traversal_attempts": self.max_path_traversal_attempts,
            "command_denylist": self.command_denylist,
            "file_path_denylist": self.file_path_denylist,
            "file_write_ext_allowlist": self.file_write_ext_allowlist,
            "url_scheme_allowlist": self.url_scheme_allowlist,
            "max_repeated_call": self.max_repeated_call,
            "sql_danger_patterns": self.sql_danger_patterns,
            "search_keyword_denylist": self.search_keyword_denylist,
            "stock_code_pattern": self.stock_code_pattern,
        }


# 工具-动作 的细粒度风险分级(risk: low / medium / high)
RISK_PROFILES: Dict[str, Dict[str, Any]] = {
    "file_operation": {
        "default": "medium",
        "actions": {
            "read": "low",
            "list": "low",
            "write": "high",
            "append": "high",
            "delete": "high",
        },
        # 需要人工审批的动作
        "approval_actions": ["write", "append", "delete"],
    },
    "command_exec": {
        "default": "high",
        "approval_actions": ["*"],  # 所有命令执行都需审批
    },
    "browser_access": {
        "default": "medium",
        "approval_actions": [],  # 中风险，默认放行(工具内部已做 SSRF 防护)
    },
    "http_request": {
        "default": "medium",
        "actions": {
            "get": "medium",
            "head": "medium",
            "post": "high",
            "put": "high",
            "delete": "high",
        },
        # 写操作类方法(可能产生副作用)需人工审批
        "approval_actions": ["post", "put", "delete"],
    },
    # ---- 以下为扩充工具的风险分级(补齐"针对所有工具制定权限约束") ----
    "web_search": {
        "default": "medium",  # 外部网络搜索，可能被用于不当信息搜集
        "approval_actions": [],
    },
    "knowledge_search": {
        "default": "medium",  # 内部资料检索，可能泄露敏感文档
        "approval_actions": [],
    },
    "text2sql": {
        "default": "high",  # 数据库查询，存在注入/越权/拖库风险
        "approval_actions": ["*"],  # 所有数据库查询都需审批
    },
    "data_analyzer": {
        "default": "low",  # 纯内存计算，无副作用
        "approval_actions": [],
    },
    "chart_generator": {
        "default": "low",  # 纯内存生成图表配置，无副作用
        "approval_actions": [],
    },
    "stock_query": {
        "default": "medium",  # 外部行情接口调用
        "approval_actions": [],
    },
    "bidding_search": {
        "default": "medium",  # 外部招投标接口调用
        "approval_actions": [],
    },
}


class PolicyEngine:
    """策略校验引擎：根据策略配置对每次工具调用做细粒度判定"""

    def __init__(self, config: PolicyConfig):
        self.config = config

    # ---- 风险等级(细粒度权限) ----
    def _action_of(self, tool_name: str, params: Dict[str, Any]) -> str:
        """提取工具的"动作"字段：file_operation 用 action，http_request 用 method"""
        if tool_name == "http_request":
            return str(params.get("method") or "get").lower()
        return str(params.get("action") or "").lower()

    def risk_of(self, tool_name: str, params: Dict[str, Any]) -> str:
        profile = RISK_PROFILES.get(tool_name)
        if not profile:
            return "low"
        action = self._action_of(tool_name, params)
        actions = profile.get("actions", {})
        return actions.get(action, profile.get("default", "low"))

    def needs_approval(self, tool_name: str, params: Dict[str, Any]) -> bool:
        profile = RISK_PROFILES.get(tool_name)
        if not profile:
            return False
        approval_actions = profile.get("approval_actions", [])
        if "*" in approval_actions:
            return True
        action = self._action_of(tool_name, params)
        return action in approval_actions

    # ---- 动态策略校验：命中硬性 deny 规则则拒绝 ----
    def check_deny(self, tool_name: str, params: Dict[str, Any]) -> Optional[str]:
        """返回拒绝原因(命中黑名单/白名单约束)，未命中返回 None"""
        if tool_name == "command_exec":
            return self._check_command(params.get("command") or "")

        if tool_name == "file_operation":
            return self._check_file(params)

        if tool_name == "text2sql":
            return self._check_text2sql(params.get("question") or "")

        if tool_name == "http_request":
            return self._check_http_request(params)

        if tool_name in ("web_search", "knowledge_search", "bidding_search"):
            query = params.get("query") or params.get("keyword") or ""
            return self._check_search_query(query)

        if tool_name == "stock_query":
            return self._check_stock_query(params)

        return None

    def _check_command(self, command: str) -> Optional[str]:
        # 命令黑名单(运行时编译，保证动态更新后立即生效)
        for pattern in self.config.command_denylist:
            if re.search(pattern, command, re.IGNORECASE):
                return f"命令命中高危黑名单: {pattern}"
        return None

    def _check_file(self, params: Dict[str, Any]) -> Optional[str]:
        path = params.get("path") or ""
        action = str(params.get("action") or "").lower()

        # 1) 路径穿越尝试(与工具内沙箱构成纵深防御，同时供任务链分析)
        normalized = path.replace("\\", "/")
        parts = [p for p in normalized.split("/") if p != ""]
        if ".." in parts:
            return "路径越界: 检测到路径穿越尝试"

        # 2) 敏感文件黑名单
        for pattern in self.config.file_path_denylist:
            if re.search(pattern, path, re.IGNORECASE):
                return f"路径命中敏感文件黑名单: {pattern}"

        # 3) 写操作扩展名白名单(防止落地 .py/.sh/.exe 等可执行文件)
        if action in ("write", "append"):
            ext = os.path.splitext(path)[1].lower()
            if ext and self.config.file_write_ext_allowlist and ext not in self.config.file_write_ext_allowlist:
                return f"禁止写入该类型文件: {ext or '(无扩展名)'}"

        return None

    def _check_text2sql(self, question: str) -> Optional[str]:
        """text2sql 安全校验：拦截危险 SQL 语句 / 注入 / 拖库探测"""
        if not question:
            return None
        for pattern in self.config.sql_danger_patterns:
            if re.search(pattern, question, re.IGNORECASE):
                return f"SQL 查询命中危险语句黑名单: {pattern}"
        return None

    def _check_search_query(self, query: str) -> Optional[str]:
        """搜索类工具安全校验：拦截敏感关键词(防止检索泄露凭据/内部信息)"""
        if not query:
            return None
        for pattern in self.config.search_keyword_denylist:
            if re.search(pattern, query, re.IGNORECASE):
                return f"搜索内容命中敏感关键词黑名单: {pattern}"
        return None

    def _check_stock_query(self, params: Dict[str, Any]) -> Optional[str]:
        """股票查询安全校验：校验股票代码格式(防止非法输入/注入)"""
        code = params.get("stock_code") or ""
        if code and not re.fullmatch(self.config.stock_code_pattern, code, re.IGNORECASE):
            return f"股票代码格式非法: {code} (仅允许 sh/sz/bj 前缀 + 6 位数字)"
        return None

    def _check_http_request(self, params: Dict[str, Any]) -> Optional[str]:
        """接口调用安全校验：协议白名单 + SSRF(内网/保留地址)防护"""
        url = params.get("url") or ""
        if not url:
            return None  # 交由工具层返回"URL 不能为空"

        try:
            parsed = urlparse(url)
        except Exception as e:
            return f"URL 解析失败: {e}"

        if parsed.scheme not in self.config.url_scheme_allowlist:
            return f"不支持的协议: {parsed.scheme}，仅支持 {'/'.join(self.config.url_scheme_allowlist)}"

        host = parsed.hostname
        if not host:
            return "URL 缺少主机名"

        # 若主机名是字面量 IP，直接校验；否则解析 DNS 后逐 IP 校验(SSRF 防护)
        try:
            ip = ipaddress.ip_address(host)
            ips = [ip]
        except ValueError:
            try:
                infos = socket.getaddrinfo(host, None)
                ips = []
                for info in infos:
                    try:
                        ips.append(ipaddress.ip_address(info[4][0]))
                    except ValueError:
                        continue
            except Exception as e:
                return f"无法解析主机 {host}: {e}"

        for ip in ips:
            if (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
                return f"禁止访问内网/保留地址: {host} ({ip})"

        return None
