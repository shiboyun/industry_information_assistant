"""Generic lifecycle hooks for RAG and tool-use security."""
from .audit import HookAuditStore, get_hook_audit_store
from .envelope import build_guarded_prompt, strip_autofetch_markup, wrap_untrusted
from .pipeline import (
    guard_retrieval_results,
    guard_tool_call,
    guard_tool_result,
    guard_user_input,
    run_security_hooks,
)
from .evidence import build_evidence_bundle, collect_metrics
from .security_log import SecurityLog, get_security_log
from .taint import (
    POISONED_RETRIEVAL,
    SENSITIVE_OUTPUT,
    TaintLedger,
    evaluate_taint,
    get_taint_ledger,
)
from .types import HookContext, HookResult, HookStage

__all__ = [
    "HookAuditStore",
    "HookContext",
    "HookResult",
    "HookStage",
    "POISONED_RETRIEVAL",
    "SENSITIVE_OUTPUT",
    "SecurityLog",
    "TaintLedger",
    "build_evidence_bundle",
    "build_guarded_prompt",
    "collect_metrics",
    "evaluate_taint",
    "get_hook_audit_store",
    "get_security_log",
    "get_taint_ledger",
    "guard_retrieval_results",
    "guard_tool_call",
    "guard_tool_result",
    "guard_user_input",
    "run_security_hooks",
    "strip_autofetch_markup",
    "wrap_untrusted",
]
