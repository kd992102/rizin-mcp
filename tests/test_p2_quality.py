"""Regression tests for P2-7 (capa confidence classification) and P2-8 (decompile warning
separation)."""

import json
import unittest

import rizin_mcp.server as server_mod
from rizin_mcp.server import (
    _confidence_hint_for_meta,
    _summarize_capability_confidence,
    _split_ghidra_warnings,
    decompile_function,
)


class TestCapaConfidenceHint(unittest.TestCase):
    def test_rule_with_attack_tag_is_behavioral(self):
        meta = {"namespace": "", "attack": ["T1055 Process Injection"], "mbc": []}
        self.assertEqual(_confidence_hint_for_meta(meta), "behavioral")

    def test_rule_with_mbc_tag_is_behavioral(self):
        meta = {"namespace": "", "attack": [], "mbc": ["C0002 Data Obfuscation"]}
        self.assertEqual(_confidence_hint_for_meta(meta), "behavioral")

    def test_rule_with_no_tags_and_no_namespace_is_generic_library(self):
        # e.g. Luhn algorithm / murmur3 / CRC32 / aPLib style fingerprints
        meta = {"namespace": "", "attack": [], "mbc": []}
        self.assertEqual(_confidence_hint_for_meta(meta), "generic-library")

    def test_rule_with_namespace_but_no_tags_is_unclassified(self):
        meta = {"namespace": "anti-analysis/packer", "attack": [], "mbc": []}
        self.assertEqual(_confidence_hint_for_meta(meta), "unclassified")

    def test_summary_counts_match_plan_scenario(self):
        capabilities = (
            [{"confidence_hint": "behavioral"}] * 5
            + [{"confidence_hint": "generic-library"}] * 60
            + [{"confidence_hint": "unclassified"}] * 11
        )
        summary = _summarize_capability_confidence(capabilities)
        self.assertEqual(summary, {
            "behavioral_count": 5,
            "generic_library_count": 60,
            "unclassified_count": 11
        })


class TestDecompileWarningSeparation(unittest.TestCase):
    def test_split_extracts_warning_lines(self):
        raw = (
            "// WARNING: Variable defined which should be unmapped\n"
            "void fcn_1400(void) {\n"
            "    // WARNING: [rz-ghidra] Detected overlap for variable\n"
            "    int x = 1;\n"
            "}\n"
        )
        clean_code, warnings = _split_ghidra_warnings(raw)
        self.assertNotIn("WARNING", clean_code)
        self.assertIn("void fcn_1400(void) {", clean_code)
        self.assertIn("int x = 1;", clean_code)
        self.assertEqual(len(warnings), 2)
        self.assertIn("Variable defined which should be unmapped", warnings[0])
        self.assertIn("Detected overlap for variable", warnings[1])

    def test_split_handles_no_warnings(self):
        raw = "void fcn(void) {\n    return;\n}\n"
        clean_code, warnings = _split_ghidra_warnings(raw)
        self.assertEqual(warnings, [])
        self.assertIn("return;", clean_code)

    def test_split_handles_empty_input(self):
        clean_code, warnings = _split_ghidra_warnings("")
        self.assertEqual(clean_code, "")
        self.assertEqual(warnings, [])


class FakeRz:
    def __init__(self, pdg_output: str):
        self._pdg_output = pdg_output

    def cmd(self, command: str) -> str:
        if command == "pdg":
            return self._pdg_output
        return ""


class TestDecompileFunctionUsesCleanCode(unittest.TestCase):
    def setUp(self):
        self._orig_rz = server_mod.CURRENT_RZ

    def tearDown(self):
        server_mod.CURRENT_RZ = self._orig_rz

    def test_decompile_function_response_has_separate_warnings_field(self):
        raw = (
            "// WARNING: Variable defined which should be unmapped\n"
            "void sub_1400(void) {\n"
            "    return;\n"
            "}\n"
        )
        server_mod.CURRENT_RZ = FakeRz(raw)
        result = json.loads(decompile_function("sub_1400"))
        self.assertEqual(result["status"], "success")
        self.assertNotIn("WARNING", result["code"])
        self.assertEqual(len(result["warnings"]), 1)


if __name__ == "__main__":
    unittest.main()
