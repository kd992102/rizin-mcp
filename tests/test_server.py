"""Basic test suite for Rizin MCP Server."""

import os
import unittest
from rizin_mcp.server import (
    server,
    sanitize_symbol_or_address,
    get_file_sha256,
    get_cache_file_path,
    ANALYSIS_CACHE_DIR,
)

class TestRizinMCPServer(unittest.TestCase):
    def test_server_initialization(self):
        self.assertEqual(server.name, "rizin-analyzer")
        
    def test_sanitize_symbol_valid(self):
        self.assertEqual(sanitize_symbol_or_address("0x140001000"), "0x140001000")
        self.assertEqual(sanitize_symbol_or_address("fcn.140001000"), "fcn.140001000")
        
    def test_sanitize_symbol_injection(self):
        with self.assertRaises(ValueError):
            sanitize_symbol_or_address("0x140001000; !calc")
            
        with self.assertRaises(ValueError):
            sanitize_symbol_or_address("main && whoami")

    def test_cache_file_path_generation(self):
        notepad_path = r"C:\Windows\SysWOW64\notepad.exe"
        if os.path.exists(notepad_path):
            sha256 = get_file_sha256(notepad_path)
            self.assertEqual(len(sha256), 64)
            cache_path = get_cache_file_path(notepad_path)
            self.assertTrue(cache_path.startswith(ANALYSIS_CACHE_DIR))
            self.assertTrue(cache_path.endswith("_full.json"))

if __name__ == "__main__":
    unittest.main()

