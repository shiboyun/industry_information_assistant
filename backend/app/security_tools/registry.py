"""工具安全元数据与参数约束。"""
from dataclasses import dataclass
from typing import Dict, FrozenSet


@dataclass(frozen=True)
class ToolProfile:
    name: str
    base_risk: int
    policy_id: str
    approval_required: bool = False
    max_calls_per_trace: int = 5
    allowed_roles: FrozenSet[str] = frozenset({"operator", "approver", "security_admin"})


TOOL_REGISTRY: Dict[str, ToolProfile] = {
    "web_search": ToolProfile("web_search", 20, "TOOL-WEB-001", max_calls_per_trace=8),
    "knowledge_search": ToolProfile("knowledge_search", 15, "TOOL-KNOWLEDGE-001", max_calls_per_trace=8),
    "local_public_record_read": ToolProfile("local_public_record_read", 30, "TOOL-LOCAL-PUBLIC-001", max_calls_per_trace=4),
    "knowledge_base_ingest": ToolProfile("knowledge_base_ingest", 65, "TOOL-KB-INGEST-001", approval_required=True, max_calls_per_trace=5),
    "stock_query": ToolProfile("stock_query", 30, "TOOL-STOCK-001", max_calls_per_trace=3),
    "bidding_search": ToolProfile("bidding_search", 35, "TOOL-BID-001", max_calls_per_trace=2),
    "text2sql_query": ToolProfile("text2sql_query", 35, "TOOL-SQL-001", max_calls_per_trace=4),
    "text2sql": ToolProfile("text2sql", 35, "TOOL-SQL-001", max_calls_per_trace=4),
    "data_analyzer": ToolProfile("data_analyzer", 20, "TOOL-DATA-001", max_calls_per_trace=4),
    "chart_generator": ToolProfile("chart_generator", 20, "TOOL-CHART-001", max_calls_per_trace=4),
    "finish": ToolProfile("finish", 0, "TOOL-FINISH-001", max_calls_per_trace=1),
    "code_execution": ToolProfile("code_execution", 65, "TOOL-CODE-001", approval_required=True, max_calls_per_trace=1),
    # 报告导出与递送只用于竞赛原型：审批通过后仅写入项目本地模拟接收端。
    "report_export_delivery": ToolProfile("report_export_delivery", 70, "TOOL-REPORT-DELIVERY-001", approval_required=True, max_calls_per_trace=2),
    "sandbox_file_write": ToolProfile("sandbox_file_write", 65, "TOOL-FILE-001", approval_required=True, max_calls_per_trace=3),
    "sandbox_command": ToolProfile("sandbox_command", 70, "TOOL-CMD-001", approval_required=True, max_calls_per_trace=2),
}


def get_tool_profile(tool_name: str) -> ToolProfile | None:
    return TOOL_REGISTRY.get(tool_name)
