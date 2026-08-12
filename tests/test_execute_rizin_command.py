"""Regression tests for P1-4: paginated execute_rizin_command output."""

import json
import unittest

import rizin_mcp.server as server_mod
from rizin_mcp.server import execute_rizin_command


class FakeRz:
    def __init__(self, output: str):
        self._output = output
        self.calls = []

    def cmd(self, command: str) -> str:
        self.calls.append(command)
        return self._output


class TestExecuteRizinCommandPagination(unittest.TestCase):
    def setUp(self):
        self._orig_rz = server_mod.CURRENT_RZ

    def tearDown(self):
        server_mod.CURRENT_RZ = self._orig_rz

    def test_no_file_open_returns_error(self):
        server_mod.CURRENT_RZ = None
        result = json.loads(execute_rizin_command("afl"))
        self.assertEqual(result["status"], "error")

    def test_small_output_is_not_truncated(self):
        server_mod.CURRENT_RZ = FakeRz("hello world")
        result = json.loads(execute_rizin_command("i"))
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["output"], "hello world")
        self.assertEqual(result["total_length"], 11)
        self.assertFalse(result["truncated"])
        self.assertIsNone(result["next_offset"])

    def test_large_output_is_paginated_with_default_limit(self):
        big_output = "A" * 50000
        server_mod.CURRENT_RZ = FakeRz(big_output)
        result = json.loads(execute_rizin_command("pd 100000"))
        self.assertEqual(result["status"], "success")
        self.assertEqual(len(result["output"]), 20000)
        self.assertEqual(result["total_length"], 50000)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["next_offset"], 20000)

    def test_can_page_through_output_using_next_offset(self):
        big_output = "0123456789" * 10  # 100 chars
        server_mod.CURRENT_RZ = FakeRz(big_output)

        first = json.loads(execute_rizin_command("iR", offset=0, limit=40))
        self.assertTrue(first["truncated"])
        self.assertEqual(first["next_offset"], 40)

        second = json.loads(execute_rizin_command("iR", offset=first["next_offset"], limit=40))
        self.assertTrue(second["truncated"])
        self.assertEqual(second["next_offset"], 80)

        third = json.loads(execute_rizin_command("iR", offset=second["next_offset"], limit=40))
        self.assertFalse(third["truncated"])
        self.assertIsNone(third["next_offset"])

        reassembled = first["output"] + second["output"] + third["output"]
        self.assertEqual(reassembled, big_output)


if __name__ == "__main__":
    unittest.main()
