"""
异常任务链阻断模块

记录每个会话(session)的工具调用链，并据此检测异常模式：
- 工具调用总数超限
- 高危操作次数超限
- 同一命令重复执行(死循环)
- 多次路径穿越尝试(攻击行为)

一旦命中，则阻断整个会话后续的所有工具调用。
"""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional


class TaskChainTracker:
    """任务链追踪器：按会话维护调用链，检测异常并阻断"""

    def __init__(self, config):
        self.config = config
        self._chains: Dict[str, List[Dict[str, Any]]] = {}  # session_id -> 调用记录
        self._blocked: set = set()                          # 被阻断的 session_id

    # ---- 记录 ----
    def _summarize(self, tool: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """提取关键字段做摘要，避免把长命令/长内容整段塞进审计日志"""
        if tool == "command_exec":
            return {"command": params.get("command", "")}
        if tool == "file_operation":
            return {"action": params.get("action", ""), "path": params.get("path", "")}
        if tool == "browser_access":
            return {"url": params.get("url", "")}
        if tool == "http_request":
            return {"method": params.get("method", "GET"), "url": params.get("url", "")}
        if tool == "web_search":
            return {"query": params.get("query", ""), "count": params.get("count", "")}
        if tool == "knowledge_search":
            return {"query": params.get("query", ""), "kb_name": params.get("kb_name", "")}
        if tool == "text2sql":
            return {"question": params.get("question", ""), "intent": params.get("intent", "")}
        if tool == "data_analyzer":
            return {"analysis_type": params.get("analysis_type", "")}
        if tool == "chart_generator":
            return {"chart_type": params.get("chart_type", ""), "title": params.get("title", "")}
        if tool == "stock_query":
            return {"stock_code": params.get("stock_code", ""), "keyword": params.get("keyword", "")}
        if tool == "bidding_search":
            return {"keyword": params.get("keyword", ""), "category": params.get("category", "")}
        return {k: v for k, v in list(params.items())[:3]}

    def _same_call_key(self, tool: str, params: Dict[str, Any]) -> str:
        """生成同一工具调用的规范化键，用于通用死循环检测"""
        if tool == "command_exec":
            return f"{tool}:{params.get('command', '')}"
        if tool == "file_operation":
            return f"{tool}:{params.get('action', '')}:{params.get('path', '')}"
        if tool == "browser_access":
            return f"{tool}:{params.get('url', '')}"
        if tool == "http_request":
            return f"{tool}:{params.get('method', 'GET')}:{params.get('url', '')}"
        if tool == "web_search":
            return f"{tool}:{params.get('query', '')}"
        if tool == "knowledge_search":
            return f"{tool}:{params.get('query', '')}:{params.get('kb_name', '')}"
        if tool == "text2sql":
            return f"{tool}:{params.get('question', '')}"
        if tool == "data_analyzer":
            return f"{tool}:{params.get('analysis_type', '')}"
        if tool == "chart_generator":
            return f"{tool}:{params.get('chart_type', '')}:{params.get('title', '')}"
        if tool == "stock_query":
            return f"{tool}:{params.get('stock_code', '')}:{params.get('keyword', '')}"
        if tool == "bidding_search":
            return f"{tool}:{params.get('keyword', '')}:{params.get('category', '')}"
        return f"{tool}:{json.dumps(params, sort_keys=True, ensure_ascii=False, default=str)}"

    def record(
        self,
        session_id: str,
        tool: str,
        outcome: str,
        params: Dict[str, Any],
        risk: str,
        reason: str = "",
        user_id: Optional[str] = None,
        username: Optional[str] = None,
    ) -> Dict[str, Any]:
        rec = {
            "seq": len(self._chains.setdefault(session_id, [])) + 1,
            "time": datetime.now().isoformat(),
            "tool": tool,
            "outcome": outcome,  # allow / deny / pending / error / block
            "risk": risk,
            "reason": reason,
            "params": self._summarize(tool, params),
            "call_key": self._same_call_key(tool, params),
        }
        if user_id:
            rec["user_id"] = user_id
        if username:
            rec["username"] = username
        self._chains[session_id].append(rec)
        return rec

    def block(self, session_id: str, reason: str) -> None:
        """阻断会话，并记录一条 block 事件用于审计"""
        self._blocked.add(session_id)
        self.record(session_id, "__session_block__", "block", {}, "high", reason)

    def is_blocked(self, session_id: str) -> bool:
        return session_id in self._blocked

    # ---- 异常检测 ----
    def check_anomaly(self, session_id: str, tool: str, params: Dict[str, Any], risk: str) -> Optional[str]:
        """检查当前调用是否命中异常链规则，返回阻断原因或 None"""
        if self.is_blocked(session_id):
            return "会话已被阻断(异常任务链)"

        records = self._chains.setdefault(session_id, [])
        cfg = self.config

        # 1) 工具调用总数超限
        if len(records) >= cfg.max_total_calls:
            return f"任务链调用次数超限({len(records)}>={cfg.max_total_calls})"

        # 2) 高危操作执行次数超限
        if risk == "high":
            high_count = sum(
                1 for r in records if r["risk"] == "high" and r["outcome"] == "allow"
            )
            if high_count >= cfg.max_high_risk_calls:
                return f"高危操作次数超限({high_count}>={cfg.max_high_risk_calls})"

        # 3) 同一命令重复执行(死循环检测)
        if tool == "command_exec":
            cmd = params.get("command", "")
            same = [
                r for r in records
                if r["tool"] == "command_exec"
                and r["params"].get("command") == cmd
                and r["outcome"] == "allow"
            ]
            if len(same) >= cfg.max_repeated_command:
                return f"检测到同一命令重复执行({cmd[:40]}...)，疑似死循环"

        # 4) 路径穿越尝试次数(攻击行为)
        traversal = [
            r for r in records if r["reason"] and "路径越界" in r["reason"]
        ]
        if len(traversal) >= cfg.max_path_traversal_attempts:
            return f"检测到多次路径穿越尝试({len(traversal)})，阻断会话"

        # 5) 同一工具+参数重复调用(通用死循环检测，覆盖所有工具)
        call_key = self._same_call_key(tool, params)
        same_call = [
            r for r in records
            if r.get("call_key") == call_key and r["outcome"] == "allow"
        ]
        if len(same_call) >= cfg.max_repeated_call:
            return f"检测到同一工具重复调用({tool}:{str(params)[:40]}...)，疑似死循环"

        return None

    # ---- 审计 ----
    def get_records(self, session_id: str) -> List[Dict[str, Any]]:
        return self._chains.get(session_id, [])

    def get_all(self) -> Dict[str, List[Dict[str, Any]]]:
        return {sid: recs for sid, recs in self._chains.items()}

    def reset(self) -> None:
        self._chains.clear()
        self._blocked.clear()
