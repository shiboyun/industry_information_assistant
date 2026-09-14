"""安全控制失败时的行为测试。

此前 ``_authorize_with_gateway`` 用裸 ``except Exception: return None`` 吞掉网关异常，
结果是**安全控制失败时静默放行**（fail-open），且没有任何日志或计数——
这种"看起来一切正常"的失效方式在安全组件里是最危险的。

对齐 Cisco AI Defense 的教训：不应把"控制不可用"折叠成"放行"，
而应显式 fail-closed 并留下可观测痕迹。
"""
from __future__ import annotations

import logging
import unittest
from unittest.mock import patch

from security_hooks import guard_tool_call


class GatewayFailClosedTests(unittest.TestCase):
    def _call_with_broken_gateway(self, exc: Exception):
        with patch(
            "security_tools.gateway.ToolSecurityGateway.authorize",
            side_effect=exc,
        ):
            return guard_tool_call(
                tool_name="report_export_delivery",
                params={"report_title": "投标情报", "report_content": "内容"},
                trace_id="fail-closed-1",
                db=object(),  # 非 None 才会走到网关
                actor=None,
            )

    def test_gateway_exception_blocks_instead_of_allowing(self):
        result = self._call_with_broken_gateway(RuntimeError("数据库连接中断"))
        self.assertEqual(result.decision, "block", "网关不可用时必须拒绝，不能静默放行")
        self.assertTrue(result.blocked)

    def test_gateway_exception_is_recorded_in_evidence(self):
        result = self._call_with_broken_gateway(RuntimeError("数据库连接中断"))
        joined = " ".join(result.evidence)
        self.assertIn("数据库连接中断", joined)
        self.assertIn("gateway_unavailable", result.labels)

    def test_gateway_exception_is_logged(self):
        with self.assertLogs("security_hooks.pipeline", level=logging.ERROR) as captured:
            self._call_with_broken_gateway(RuntimeError("boom"))
        self.assertTrue(any("boom" in line for line in captured.output), captured.output)

    def test_healthy_gateway_is_unaffected(self):
        result = guard_tool_call(
            tool_name="web_search",
            params={"query": "政企安全合规案例"},
            trace_id="fail-healthy-1",
        )
        self.assertNotEqual(result.decision, "block")

    def test_no_db_still_uses_heuristics(self):
        """未接数据库时（本地测试场景）不应被 fail-closed 误伤。"""
        result = guard_tool_call(
            tool_name="web_search",
            params={"query": "政企安全合规案例"},
            trace_id="fail-nodb-1",
            db=None,
        )
        self.assertNotEqual(result.decision, "block")


class AuditFailureVisibilityTests(unittest.TestCase):
    """审计写入失败不应阻断业务，但必须可见。"""

    def test_audit_append_failure_is_logged_not_swallowed(self):
        from security_hooks import audit as audit_module

        original = audit_module.HookAuditStore.append
        try:
            audit_module.HookAuditStore.append = lambda self, *a, **k: (_ for _ in ()).throw(RuntimeError("审计链写入失败"))
            with self.assertLogs("security_hooks.pipeline", level=logging.ERROR) as captured:
                guard_tool_call("web_search", {"query": "q"}, trace_id="audit-fail-1")
            self.assertTrue(any("审计链写入失败" in line for line in captured.output), captured.output)
        finally:
            audit_module.HookAuditStore.append = original

    def test_business_call_still_succeeds_when_audit_fails(self):
        from security_hooks import audit as audit_module

        original = audit_module.HookAuditStore.append
        try:
            audit_module.HookAuditStore.append = lambda self, *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
            result = guard_tool_call("web_search", {"query": "q"}, trace_id="audit-fail-2")
            self.assertNotEqual(result.decision, "block", "审计失败不应阻断业务")
        finally:
            audit_module.HookAuditStore.append = original


if __name__ == "__main__":
    unittest.main()
