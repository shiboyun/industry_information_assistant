"""脱敏覆盖度测试（对齐 RAPTOR redaction.py 的覆盖面）。

原有实现只覆盖手机号 / 邮箱 / sk- 密钥 / Bearer。真实泄漏场景里更常见的是：
连接串里的 userinfo、预签名 URL 的查询参数、OAuth 隐式流放在 # 片段里的 token
（该片段正是规范为**避开服务器日志**而设计的位置），以及 JWT 与各厂商令牌前缀。
"""
from __future__ import annotations

import unittest

from security_hooks.detectors import redact_sensitive_values


def _redact(payload):
    sanitized, labels, evidence = redact_sensitive_values(payload)
    return sanitized, labels


class UrlCredentialTests(unittest.TestCase):
    def test_redacts_userinfo_in_connection_string(self):
        out, _ = _redact({"dsn": "postgres://admin:s3cretPw@db.internal:5432/app"})
        self.assertNotIn("s3cretPw", out["dsn"])
        self.assertIn("db.internal", out["dsn"], "主机名应保留以便定位问题")

    def test_redacts_credentials_in_any_scheme_not_just_http(self):
        for dsn in (
            "mongodb+srv://u:p%40ss@cluster.example/db",
            "redis://default:redisPass123@cache:6379",
            "amqp://guest:guestPw@mq:5672",
        ):
            out, _ = _redact({"dsn": dsn})
            self.assertNotIn("Pw", out["dsn"].replace("%40", "@"), dsn)

    def test_redacts_presigned_query_parameters(self):
        aws_key = "AKIA" + "IOSFODNN7EXAMPLE"  # 拼接，避免源码出现完整令牌字面量
        url = f"https://oss.example.com/f.pdf?X-Amz-Signature=abc123def456&X-Amz-Credential={aws_key}"
        out, _ = _redact({"url": url})
        self.assertNotIn("abc123def456", out["url"])
        self.assertNotIn(aws_key, out["url"])

    def test_redacts_oauth_implicit_flow_fragment(self):
        url = "https://app.example/cb#access_token=eyJhbGciOiJIUzI1NiJ9.payload.sig&token_type=Bearer"
        out, _ = _redact({"url": url})
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", out["url"])

    def test_keeps_ordinary_url_intact(self):
        url = "https://www.example.com/news/2026/09/policy.html?page=2"
        out, _ = _redact({"url": url})
        self.assertEqual(out["url"], url)


class TokenShapeTests(unittest.TestCase):
    def test_redacts_jwt(self):
        jwt = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
               "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
               "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
        out, _ = _redact({"note": f"凭证 {jwt} 已下发"})
        self.assertNotIn("dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", out["note"])

    def test_redacts_vendor_token_prefixes(self):
        # 下列"密钥"均由片段拼接而成，源码中不存在完整的令牌字面量。
        # 原因：GitHub 推送保护会把形似真实令牌的字面量判为密钥泄漏并拒绝推送，
        # 而这只是测试夹具。拼接不影响测试有效性——被测的是脱敏规则能否识别该**形态**。
        cases = {
            "github_pat_" + "11ABCDEFG0" + "abcdefghijklmnop": "github_pat_",
            "ghp_" + "A" * 20 + "0123456789": "ghp_",
            "xoxb-" + "1" * 12 + "-" + "a" * 16: "xoxb-",
            "AIza" + "Sy" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6": "AIzaSy",
            "sk-ant-" + "api03-" + "A" * 20 + "0123456789": "sk-ant-",
        }
        for secret, prefix in cases.items():
            out, _ = _redact({"v": f"值为 {secret} 请勿外传"})
            self.assertNotIn(secret, out["v"], f"未脱敏：{prefix}")

    def test_redacts_aws_access_key_id(self):
        aws_key = "AKIA" + "IOSFODNN7EXAMPLE"  # 拼接，避免源码出现完整令牌字面量
        out, _ = _redact({"v": f"{aws_key} 是访问密钥"})
        self.assertNotIn(aws_key, out["v"])

    def test_redacts_pem_private_key_block(self):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234\n-----END RSA PRIVATE KEY-----"
        out, _ = _redact({"v": f"配置如下\n{pem}\n结束"})
        self.assertNotIn("MIIEowIBAAKCAQEA1234", out["v"])


class RegressionTests(unittest.TestCase):
    """扩充不能破坏原有覆盖面，也不能误伤正常文本。"""

    def test_still_redacts_original_patterns(self):
        out, labels = _redact({"v": "手机 13800138000 邮箱 a@example.com key sk-abcdefghijklmnopqrstuvwx"})
        self.assertNotIn("13800138000", out["v"])
        self.assertNotIn("a@example.com", out["v"])
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwx", out["v"])
        self.assertIn("sensitive_output_redacted", labels)

    def test_ordinary_business_text_is_untouched(self):
        text = "本项目读取文件中的合同条款并生成汇总报告，付款节点为验收后30日。"
        out, labels = _redact({"v": text})
        self.assertEqual(out["v"], text)
        self.assertEqual(labels, [])

    def test_ordinary_numbers_and_ids_are_untouched(self):
        for text in ("项目编号 2026-XA-0620", "共计 12345 条记录", "版本 v1.2.3"):
            out, _ = _redact({"v": text})
            self.assertEqual(out["v"], text, text)

    def test_redaction_is_idempotent(self):
        out1, _ = _redact({"v": "postgres://u:pw@h/db 与 sk-abcdefghijklmnopqrstuvwx"})
        out2, _ = _redact(out1)
        self.assertEqual(out1["v"], out2["v"])

    def test_recurses_into_nested_structures(self):
        payload = {"a": [{"b": "postgres://u:pw@h/db"}]}
        out, _ = _redact(payload)
        self.assertNotIn("pw@", out["a"][0]["b"])


if __name__ == "__main__":
    unittest.main()
