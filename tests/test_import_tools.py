"""Regression tests for P1-5 (search_imports) and P1-9 (find_import_callers)."""

import json
import unittest

import rizin_mcp.server as server_mod
from rizin_mcp.server import search_imports, find_import_callers


class FakeRz:
    def __init__(self, cmd_map=None, imports=None, initial_seek=0x0):
        self.cmd_map = dict(cmd_map or {})
        self.imports = imports or []
        self.seek_addr = initial_seek
        self.calls = []

    def cmd(self, command: str) -> str:
        self.calls.append(command)

        if command == "iij":
            return json.dumps(self.imports)

        if command.startswith("s "):
            target = command[2:].strip()
            try:
                self.seek_addr = int(target, 16) if target.lower().startswith("0x") else int(target, 0)
            except ValueError:
                pass
            return ""

        if command == "s":
            return hex(self.seek_addr)

        for prefix, value in self.cmd_map.items():
            if command == prefix:
                return value
        return ""


IMPORTS = [
    {"name": "sym.imp.KERNEL32.dll_WriteProcessMemory", "libname": "KERNEL32.dll", "plt": 0x1000},
    {"name": "sym.imp.KERNEL32.dll_CreateRemoteThread", "libname": "KERNEL32.dll", "plt": 0x1010},
    {"name": "sym.imp.WININET.dll_InternetOpenA", "libname": "WININET.dll", "plt": 0x1020},
    {"name": "sym.imp.KERNEL32.dll_LoadResource", "libname": "KERNEL32.dll", "plt": 0x1030},
]


class TestSearchImports(unittest.TestCase):
    def setUp(self):
        self._orig_rz = server_mod.CURRENT_RZ

    def tearDown(self):
        server_mod.CURRENT_RZ = self._orig_rz

    def test_no_file_open(self):
        server_mod.CURRENT_RZ = None
        result = json.loads(search_imports("WriteProcessMemory"))
        self.assertEqual(result["status"], "error")

    def test_query_filters_by_name_only(self):
        server_mod.CURRENT_RZ = FakeRz(imports=IMPORTS)
        result = json.loads(search_imports(query="WriteProcessMemory"))
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["count"], 1)
        self.assertIn("WriteProcessMemory", result["imports"][0]["name"])

    def test_dll_filters_without_dumping_whole_table(self):
        server_mod.CURRENT_RZ = FakeRz(imports=IMPORTS)
        result = json.loads(search_imports(dll="KERNEL32"))
        self.assertEqual(result["count"], 3)  # not WININET
        names = {i["name"] for i in result["imports"]}
        self.assertNotIn("sym.imp.WININET.dll_InternetOpenA", names)

    def test_combined_query_and_dll_filter(self):
        server_mod.CURRENT_RZ = FakeRz(imports=IMPORTS)
        result = json.loads(search_imports(query="Open", dll="WININET"))
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["imports"][0]["name"], "sym.imp.WININET.dll_InternetOpenA")

    def test_no_match_returns_empty_not_full_table(self):
        server_mod.CURRENT_RZ = FakeRz(imports=IMPORTS)
        result = json.loads(search_imports(query="DefinitelyNotThere"))
        self.assertEqual(result["count"], 0)
        self.assertEqual(result["imports"], [])


class TestFindImportCallers(unittest.TestCase):
    def setUp(self):
        self._orig_rz = server_mod.CURRENT_RZ

    def tearDown(self):
        server_mod.CURRENT_RZ = self._orig_rz

    def test_no_file_open(self):
        server_mod.CURRENT_RZ = None
        result = json.loads(find_import_callers("LoadResource"))
        self.assertEqual(result["status"], "error")

    def test_unresolvable_import_returns_error(self):
        server_mod.CURRENT_RZ = FakeRz(cmd_map={"?v NotAnImport": ""}, imports=[])
        result = json.loads(find_import_callers("NotAnImport"))
        self.assertEqual(result["status"], "error")

    def test_resolves_import_and_annotates_call_sites_with_owning_function(self):
        rz = FakeRz(
            cmd_map={
                "?v LoadResource": "",
                "axtj @ 4144": json.dumps([{"from": 0x2000}, {"from": 0x3000}]),
                "afij @ 8192": json.dumps([{"name": "sub_2000", "offset": 0x2000}]),
                "afij @ 12288": json.dumps([{"name": "fcn.main", "offset": 0x2f00}]),
            },
            imports=IMPORTS,
        )
        server_mod.CURRENT_RZ = rz
        result = json.loads(find_import_callers("LoadResource"))

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["target_address"], "0x1030")
        self.assertEqual(result["count"], 2)

        call1 = result["call_sites"][0]
        self.assertEqual(call1["call_site"], "0x2000")
        self.assertEqual(call1["in_function"]["name"], "sub_2000")

        call2 = result["call_sites"][1]
        self.assertEqual(call2["call_site"], "0x3000")
        self.assertEqual(call2["in_function"]["name"], "fcn.main")
        self.assertEqual(call2["in_function"]["address"], "0x2f00")


if __name__ == "__main__":
    unittest.main()
