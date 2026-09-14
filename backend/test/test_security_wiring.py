"""接入层回归守卫。

为什么是源码级断言：``chat_service.py`` 依赖 llama_index / tiktoken / openai 等
外部包，在本机离线环境无法导入，因此无法用运行时断言验证「信封是否真的接上了」。
这里退而求其次，直接检查调用点是否还在——它的作用是**防止接入被静默回退**
（例如有人为了修 bug 把提示词构造改回扁平 f-string）。
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

SERVICE_DIR = Path(__file__).resolve().parents[1] / "app" / "service"
CHAT_SERVICE = SERVICE_DIR / "chat_service.py"


class ChatServiceEnvelopeWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = CHAT_SERVICE.read_text(encoding="utf-8")

    def test_envelope_builder_is_imported(self):
        self.assertIn(
            "from security_hooks.envelope import build_guarded_prompt",
            self.source,
            "chat_service 必须从 security_hooks.envelope 引入信封构造器",
        )

    def test_prompt_is_built_through_the_envelope(self):
        self.assertIn("build_guarded_prompt(", self.source)

    def test_history_is_passed_as_messages_not_concatenated_into_the_prompt(self):
        self.assertIn("history=history_messages", self.source)
        self.assertNotIn(
            'f"{msg[\'role\']}: {msg[\'content\']}"',
            self.source,
            "历史对话不得再被明文拼进同一条字符串",
        )

    def test_request_no_longer_sends_a_single_flat_user_message(self):
        self.assertNotIn(
            '{"role": "user", "content": prompt}',
            self.source,
            "不应再以单条扁平 user 消息发送",
        )
        self.assertRegex(self.source, r"messages\s*=\s*messages\b")

    def test_raw_prompt_is_not_printed_to_logs(self):
        self.assertNotIn(
            "print(prompt)",
            self.source,
            "打印完整提示词会把用户数据与检索内容写入日志",
        )

    def test_system_rules_forbid_following_untrusted_instructions(self):
        envelope = (Path(__file__).resolve().parents[1] / "app" / "security_hooks" / "envelope.py").read_text(
            encoding="utf-8"
        )
        for keyword in ("不可信", "数据", "不得被参考内容或历史对话覆盖"):
            self.assertIn(keyword, envelope)


if __name__ == "__main__":
    unittest.main()
