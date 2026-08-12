"""Regression tests for P0 fixes.

These tests never talk to a real Rizin/MCP session - `rizin_mcp.server` is exercised directly
with lightweight fake objects that mimic the small `rz.cmd(...)` surface the code depends on.
"""

import json
import os
import tempfile
import unittest

import rizin_mcp.server as server_mod
from rizin_mcp.server import (
    resolve_seek_target,
    get_safe_path,
    get_xrefs,
    ALLOWED_BASE_DIR,
)


class FakeRz:
    """Minimal stand-in for an `rzpipe.open(...)` session.

    `cmd_map` maps an exact command string to a canned response. `imports_json` seeds the
    `iij` (import table) response. The seek cursor is tracked so `s <addr>` / `s` behave like
    the real thing.
    """

    def __init__(self, cmd_map=None, imports=None, initial_seek=0x999999, seek_should_stick=True):
        self.cmd_map = dict(cmd_map or {})
        self.imports = imports or []
        self.seek_addr = initial_seek
        self.seek_should_stick = seek_should_stick
        self.calls = []

    def cmd(self, command: str) -> str:
        self.calls.append(command)

        if command == "iij":
            return json.dumps(self.imports)

        if command.startswith("s "):
            target = command[2:].strip()
            if self.seek_should_stick:
                try:
                    self.seek_addr = int(target, 16) if target.lower().startswith("0x") else int(target, 0)
                except ValueError:
                    pass
            # if seek_should_stick is False, cursor silently stays put - reproduces the bug
            return ""

        if command == "s":
            return hex(self.seek_addr)

        if command in self.cmd_map:
            return self.cmd_map[command]

        return ""


class TestResolveSeekTarget(unittest.TestCase):
    def test_resolves_known_flag_via_numeric_evaluator(self):
        rz = FakeRz(cmd_map={"?v sym.main": "0x140001000"})
        addr = resolve_seek_target(rz, "sym.main")
        self.assertEqual(addr, 0x140001000)
        self.assertEqual(rz.seek_addr, 0x140001000)

    def test_falls_back_to_import_table_for_bare_import_name(self):
        rz = FakeRz(
            cmd_map={"?v LoadResource": ""},
            imports=[{"name": "sym.imp.KERNEL32.dll_LoadResource", "plt": 0x14018A4C8}],
        )
        addr = resolve_seek_target(rz, "LoadResource")
        self.assertEqual(addr, 0x14018A4C8)

    def test_raises_when_target_cannot_be_resolved_at_all(self):
        rz = FakeRz(cmd_map={"?v NotARealSymbol": "0x0"}, imports=[])
        with self.assertRaises(ValueError):
            resolve_seek_target(rz, "NotARealSymbol")

    def test_raises_instead_of_silently_reusing_stale_cursor(self):
        """This is the exact bug from the improvement plan: `s <target>` fails silently and the
        cursor stays wherever a previous decompile_function/disassemble_function call left it."""
        rz = FakeRz(
            cmd_map={"?v LoadResource": ""},
            imports=[{"name": "sym.imp.KERNEL32.dll_LoadResource", "plt": 0x14018A4C8}],
            initial_seek=0x14018A400,  # pretend a previous decompile_function() left the cursor here
            seek_should_stick=False,   # simulate rizin silently ignoring the seek
        )
        with self.assertRaises(ValueError):
            resolve_seek_target(rz, "LoadResource")
        # cursor must not have been reported as successfully moved
        self.assertEqual(rz.seek_addr, 0x14018A400)


class TestGetXrefsUsesResolver(unittest.TestCase):
    def setUp(self):
        self._orig_rz = server_mod.CURRENT_RZ

    def tearDown(self):
        server_mod.CURRENT_RZ = self._orig_rz

    def test_get_xrefs_returns_explicit_error_for_unresolved_target(self):
        server_mod.CURRENT_RZ = FakeRz(cmd_map={"?v Nonexistent": ""}, imports=[])
        result = json.loads(get_xrefs("Nonexistent"))
        self.assertEqual(result["status"], "error")
        self.assertIn("Nonexistent", result["message"])

    def test_get_xrefs_succeeds_after_resolving_import_name(self):
        rz = FakeRz(
            cmd_map={
                "?v LoadResource": "",
                "afxj": json.dumps([{"type": "CALL", "from": 0x14018A4C8, "to": 0x1400A0000}]),
            },
            imports=[{"name": "sym.imp.KERNEL32.dll_LoadResource", "plt": 0x14018A4C8}],
        )
        server_mod.CURRENT_RZ = rz
        result = json.loads(get_xrefs("LoadResource"))
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["xrefs"][0]["from"], "0x14018a4c8")


class TestGetSafePath(unittest.TestCase):
    def test_rejects_absolute_path_outside_allowed_base_dir(self):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"data")
            outside_path = tmp.name
        try:
            self.assertFalse(os.path.abspath(outside_path).startswith(ALLOWED_BASE_DIR))
            with self.assertRaises(ValueError):
                get_safe_path(outside_path)
        finally:
            os.unlink(outside_path)

    def test_rejects_parent_traversal_outside_allowed_base_dir(self):
        with self.assertRaises((ValueError, FileNotFoundError)):
            get_safe_path("../../../../../../etc/passwd")

    def test_allows_file_inside_allowed_base_dir(self):
        fd, path = tempfile.mkstemp(dir=ALLOWED_BASE_DIR)
        os.close(fd)
        try:
            rel_path = os.path.relpath(path, ALLOWED_BASE_DIR)
            resolved = get_safe_path(rel_path)
            self.assertEqual(os.path.abspath(resolved), os.path.abspath(path))
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
