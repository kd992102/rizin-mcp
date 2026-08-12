"""Regression tests for P3 hardening: execute_rizin_command blocks shell-escape, file
open/switch, and write commands (it's documented as a read-only static analysis tool)."""

import json
import unittest

import rizin_mcp.server as server_mod
from rizin_mcp.server import execute_rizin_command, _rizin_command_denial_reason


class FakeRz:
    def __init__(self):
        self.calls = []

    def cmd(self, command: str) -> str:
        self.calls.append(command)
        return "ok"


class TestRizinCommandDenylist(unittest.TestCase):
    def test_shell_escape_is_blocked(self):
        self.assertIsNotNone(_rizin_command_denial_reason("!calc"))
        self.assertIsNotNone(_rizin_command_denial_reason("afl; !whoami"))

    def test_write_commands_are_blocked(self):
        for cmd in ["w hello", "wx 41414141", "wa nop", "wf /etc/passwd", "w0 10"]:
            self.assertIsNotNone(_rizin_command_denial_reason(cmd), f"expected block for: {cmd}")

    def test_open_commands_are_blocked(self):
        for cmd in ["o /etc/passwd", "o+ /etc/passwd", "oo", "on /some/other/file"]:
            self.assertIsNotNone(_rizin_command_denial_reason(cmd), f"expected block for: {cmd}")

    def test_safe_read_only_commands_are_allowed(self):
        for cmd in ["afl", "px 64 @ 0x140001000", "pdf @ main", "ii", "iR", "izj"]:
            self.assertIsNone(_rizin_command_denial_reason(cmd), f"expected allow for: {cmd}")

    def test_chained_command_with_a_blocked_segment_is_blocked(self):
        self.assertIsNotNone(_rizin_command_denial_reason("afl ; wx 90"))


class TestExecuteRizinCommandEnforcesDenylist(unittest.TestCase):
    def setUp(self):
        self._orig_rz = server_mod.CURRENT_RZ

    def tearDown(self):
        server_mod.CURRENT_RZ = self._orig_rz

    def test_blocked_command_never_reaches_rizin(self):
        rz = FakeRz()
        server_mod.CURRENT_RZ = rz
        result = json.loads(execute_rizin_command("!rm -rf /"))
        self.assertEqual(result["status"], "error")
        self.assertEqual(rz.calls, [])  # never actually invoked

    def test_allowed_command_still_works(self):
        rz = FakeRz()
        server_mod.CURRENT_RZ = rz
        result = json.loads(execute_rizin_command("afl"))
        self.assertEqual(result["status"], "success")
        self.assertEqual(rz.calls, ["afl"])


if __name__ == "__main__":
    unittest.main()
