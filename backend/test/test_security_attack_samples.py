"""80 个本地安全攻击样例，不访问任何外部 API 或数据库。"""
import shutil
import unittest

from security_tools.sandbox import (
    SANDBOX_ROOT,
    execute_restricted_code,
    execute_sandbox_command,
    execute_sandbox_file_write,
)


class SecurityAttackSampleTests(unittest.TestCase):
    """覆盖路径越权、命令注入与受限代码执行的第一版样例集。"""

    def tearDown(self):
        if SANDBOX_ROOT.exists():
            shutil.rmtree(SANDBOX_ROOT)

    def test_80_local_security_samples(self):
        samples = []
        samples.extend(("file", {"path": f"../escape-{index}.txt", "content": "x"}, False) for index in range(20))
        samples.extend(("file", {"path": f"C:/escape-{index}.txt", "content": "x"}, False) for index in range(10))
        samples.extend(("file", {"path": f"unsafe-{index}.py", "content": "x"}, False) for index in range(10))
        samples.extend(("command", {"command": command}, False) for command in (
            "dir", "whoami", "ipconfig", "powershell", "cmd", "curl", "ping", "del", "type", "set"
        ))
        samples.extend(("code", {"code": code}, False) for code in (
            "import os", "from pathlib import Path", "print(open('x'))", "print((1).__class__)",
            "for i in range(2): print(i)", "while True: pass", "print(2 ** 1000000)",
            "print([i for i in range(2)])", "def run(): pass", "lambda: 1",
        ))
        samples.extend(("file", {"path": f"approved-{index}.txt", "content": "approved"}, True) for index in range(10))
        samples.extend(("command", {"command": command}, True) for command in ("runtime_info", "python_version"))
        samples.extend(("code", {"code": "print(1 + 1)"}, True) for _ in range(8))

        self.assertEqual(len(samples), 80)
        for kind, params, expected_success in samples:
            executor = {"file": execute_sandbox_file_write, "command": execute_sandbox_command, "code": execute_restricted_code}[kind]
            if expected_success:
                self.assertIsInstance(executor(params), dict)
            else:
                with self.assertRaises(ValueError):
                    executor(params)


if __name__ == "__main__":
    unittest.main()
