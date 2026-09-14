# Security Hooks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a generic security hook layer that monitors and controls RAG retrieval and tool calls without depending on the multi-agent research module.

**Architecture:** Introduce a small `security_hooks` package with lifecycle stages, reusable detectors, retrieval filtering, tool authorization, and append-only audit events. Existing DB-backed `security_tools.gateway` remains the strong policy and approval backend when a database session is available; the hook layer also keeps an in-memory audit chain for local demos and tests.

**Tech Stack:** Python, FastAPI, SQLAlchemy models already present in the backend, local `unittest` tests.

**Spec:** User discussion in this task plus `OPEN_SOURCE_SECURITY_PROJECTS_ANALYSIS.md`.

## Global Constraints

- Keep multi-agent modules optional; the first integration must work for RAG and Tool Use alone.
- Reuse the existing tool registry, approval, RBAC, and hash-chain audit instead of replacing it.
- Make hooks platform-agnostic: callers pass stage, payload, trace metadata, and optional DB/user context.
- Keep local tests independent of external APIs, Milvus, LLM services, and PostgreSQL.
- Preserve existing routes and return shapes unless a call is blocked by security policy.

---

### Task 1: Hook Core

**Files:**
- Create: `backend/app/security_hooks/types.py`
- Create: `backend/app/security_hooks/detectors.py`
- Create: `backend/app/security_hooks/audit.py`
- Create: `backend/app/security_hooks/pipeline.py`
- Create: `backend/app/security_hooks/__init__.py`
- Test: `backend/test/test_security_hooks.py`

**Interfaces:**
- Produces: `HookStage`, `HookResult`, `run_security_hooks(...)`, `guard_retrieval_results(...)`, `guard_tool_call(...)`, `guard_tool_result(...)`, `get_hook_audit_store()`.
- Consumes: `service.attack_detect_service.multi_source_attack_detect` and optional `security_tools.gateway.ToolSecurityGateway`.

- [ ] Write failing tests for retrieval poisoning filtering, dangerous tool call blocking, and audit hash-chain verification.
- [ ] Implement detector helpers for prompt injection, destructive SQL/commands, path traversal, and secret redaction.
- [ ] Implement hook result aggregation and in-memory audit events.
- [ ] Run the hook tests and confirm they pass.

### Task 2: RAG Integration

**Files:**
- Modify: `backend/app/service/retrieval_service.py`
- Modify: `backend/app/service/chat_service.py`
- Test: `backend/test/test_security_hooks.py`

**Interfaces:**
- Consumes: `guard_retrieval_results(question, documents, trace_id, source_type)`.
- Produces: retrieval outputs with unsafe chunks removed and safe chunks renumbered.

- [ ] Call retrieval hook after Milvus results are formatted.
- [ ] Call retrieval hook after remote knowledge/web search results are formatted.
- [ ] Preserve existing empty-list fallback behavior when filtering removes all chunks.
- [ ] Run local tests.

### Task 3: Tool-Use Integration

**Files:**
- Modify: `backend/app/service/tool_executor.py`
- Modify: `backend/app/security_tools/gateway.py`
- Test: `backend/test/test_security_hooks.py`

**Interfaces:**
- Consumes: `guard_tool_call(tool_name, params, context, db, actor)` and `guard_tool_result(...)`.
- Produces: every bound ReAct tool handler goes through the same hook path.

- [ ] Wrap `ToolExecutor.execute()` with pre-tool and post-tool hooks.
- [ ] Change `bind_tools_to_controller()` so controller-bound handlers call `executor.execute(...)`.
- [ ] Add a public `record_event(...)` method to the DB gateway for generic hook audit events.
- [ ] Run local tests and compile backend Python files.

### Task 4: Demo Audit API

**Files:**
- Modify: `backend/app/router/security_router.py`

**Interfaces:**
- Produces: `/security/hooks/events` and `/security/hooks/verify/{trace_id}` for non-DB demo traces.

- [ ] Expose in-memory hook events for local demonstration.
- [ ] Expose hash-chain verification for any hook trace.
- [ ] Run local tests and compile backend Python files.

## Self-Review

- Spec coverage: the plan covers RAG input/output filtering, tool-call policy enforcement, audit logging, trace verification, and multi-agent independence.
- Placeholder scan: no implementation placeholders are left for the executor.
- Type consistency: hook function names and result fields are defined in Task 1 and consumed by Tasks 2-4.
