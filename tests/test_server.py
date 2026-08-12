"""Basic test suite for Rizin MCP Server."""

import unittest
from rizin_mcp.server import server, sanitize_symbol_or_address

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

if __name__ == "__main__":
    unittest.main()
