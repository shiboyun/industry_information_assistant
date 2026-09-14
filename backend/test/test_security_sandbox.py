"""不依赖外部 API 的工具安全沙箱测试。"""
import shutil
import unittest

from security_tools.sandbox import SANDBOX_ROOT, execute_restricted_code, execute_sandbox_command, execute_sandbox_file_write


class SecuritySandboxTests(unittest.TestCase):
    def tearDown(self):
        if SANDBOX_ROOT.exists():
            shutil.rmtree(SANDBOX_ROOT)

    def test_file_write_stays_in_sandbox(self):
        result = execute_sandbox_file_write({"path": "test.txt", "content": "approved"})
        self.assertEqual(result["bytes_written"], 8)
        self.assertTrue((SANDBOX_ROOT / "test.txt").exists())

    def test_path_traversal_is_blocked(self):
        with self.assertRaises(ValueError):
            execute_sandbox_file_write({"path": "../outside.txt", "content": "blocked"})

    def test_absolute_path_and_non_whitelisted_extension_are_blocked(self):
        with self.assertRaises(ValueError):
            execute_sandbox_file_write({"path": "C:/outside.txt", "content": "blocked"})
        with self.assertRaises(ValueError):
            execute_sandbox_file_write({"path": "script.py", "content": "blocked"})

    def test_command_whitelist(self):
        self.assertIn("Python", execute_sandbox_command({"command": "python_version"})["output"])
        with self.assertRaises(ValueError):
            execute_sandbox_command({"command": "dir"})

    def test_restricted_code_rejects_import(self):
        result = execute_restricted_code({"code": "print(1 + 1)"})
        self.assertEqual(result["output"], "2\n")
        with self.assertRaises(ValueError):
            execute_restricted_code({"code": "import os"})

    def test_restricted_code_rejects_resource_intensive_operations(self):
        with self.assertRaises(ValueError):
            execute_restricted_code({"code": "print(2 ** 1000000)"})
        with self.assertRaises(ValueError):
            execute_restricted_code({"code": "print([x for x in range(10)])"})


if __name__ == "__main__":
    unittest.main()
