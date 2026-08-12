"""Regression tests for P1-3: list_resources / extract_resource.

pefile.PE is monkeypatched with a fake object shaped like the real one (DIRECTORY_ENTRY_RESOURCE
tree + get_data), so these tests never open a real PE file or talk to Rizin/MCP.
"""

import base64
import json
import unittest
from types import SimpleNamespace
from unittest import mock

import rizin_mcp.server as server_mod
from rizin_mcp.server import list_resources, extract_resource


def _make_leaf(lang, offset_to_data, size):
    return SimpleNamespace(data=SimpleNamespace(lang=lang, struct=SimpleNamespace(OffsetToData=offset_to_data, Size=size)))


def _make_id_entry(name, struct_id, leaves):
    entry = SimpleNamespace(name=name, struct=SimpleNamespace(Id=struct_id))
    entry.directory = SimpleNamespace(entries=leaves)
    return entry


def _make_type_entry(name, struct_id, id_entries):
    entry = SimpleNamespace(name=name, struct=SimpleNamespace(Id=struct_id))
    entry.directory = SimpleNamespace(entries=id_entries)
    return entry


class FakePE:
    """Stands in for pefile.PE with a small, hand-built resource tree and a byte blob."""

    def __init__(self, type_entries, blob: bytes, image_base=0x400000):
        self.DIRECTORY_ENTRY_RESOURCE = SimpleNamespace(entries=type_entries)
        self._blob = blob
        self.OPTIONAL_HEADER = SimpleNamespace(ImageBase=image_base)
        self.closed = False

    def parse_data_directories(self, directories=None):
        pass

    def get_data(self, rva, size):
        return self._blob[rva:rva + size]

    def close(self):
        self.closed = True


class TestListAndExtractResources(unittest.TestCase):
    def setUp(self):
        self._orig_rz = server_mod.CURRENT_RZ
        self._orig_path = server_mod.CURRENT_FILE_PATH
        server_mod.CURRENT_RZ = object()  # anything non-None means "a file is open"
        server_mod.CURRENT_FILE_PATH = "/fake/sample.exe"

        # blob layout: [0:4] "MZ.." fake PE header bytes, [4:16] a real-looking PNG-tagged resource
        self.blob = b"MZ\x90\x00" + b"\x89PNG\r\n\x1a\n\x00\x00\x00\x00"
        # RT_ICON (id 3 well-known) resource whose bytes are actually an MZ header -> mismatch
        icon_leaf = _make_leaf(lang=0x0409, offset_to_data=0, size=4)
        icon_id_entry = _make_id_entry(name=None, struct_id=1, leaves=[icon_leaf])
        icon_type_entry = _make_type_entry(name=None, struct_id=3, id_entries=[icon_id_entry])  # RT_ICON

        # RT_RCDATA resource whose bytes really are a PNG -> no mismatch (RCDATA is a generic blob type)
        rcdata_leaf = _make_leaf(lang=0x0409, offset_to_data=4, size=12)
        rcdata_id_entry = _make_id_entry(name=None, struct_id=101, leaves=[rcdata_leaf])
        rcdata_type_entry = _make_type_entry(name=None, struct_id=10, id_entries=[rcdata_id_entry])  # RT_RCDATA

        self.fake_pe = FakePE([icon_type_entry, rcdata_type_entry], self.blob)
        self._pe_patch = mock.patch.object(server_mod.pefile, "PE", return_value=self.fake_pe)
        self._pe_patch.start()

    def tearDown(self):
        self._pe_patch.stop()
        server_mod.CURRENT_RZ = self._orig_rz
        server_mod.CURRENT_FILE_PATH = self._orig_path

    def test_no_file_open_returns_error(self):
        server_mod.CURRENT_RZ = None
        result = json.loads(list_resources())
        self.assertEqual(result["status"], "error")

    def test_list_resources_flags_disguised_executable(self):
        result = json.loads(list_resources())
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["count"], 2)

        by_type = {r["type"]: r for r in result["resources"]}
        icon_entry = by_type["RT_ICON"]
        self.assertTrue(icon_entry["type_content_mismatch"])
        self.assertEqual(icon_entry["detected_magic"], "PE/EXE")
        self.assertIsNotNone(icon_entry["mismatch_note"])

        rcdata_entry = by_type["RT_RCDATA"]
        self.assertFalse(rcdata_entry["type_content_mismatch"])
        self.assertEqual(rcdata_entry["detected_magic"], "PNG")

    def test_extract_resource_returns_base64_bytes(self):
        result = json.loads(extract_resource("RT_ICON", "1"))
        self.assertEqual(result["status"], "success")
        self.assertEqual(base64.b64decode(result["data_base64"]), b"MZ\x90\x00")
        self.assertEqual(result["detected_magic"], "PE/EXE")

    def test_extract_resource_not_found(self):
        result = json.loads(extract_resource("RT_BITMAP", "999"))
        self.assertEqual(result["status"], "error")

    def test_extract_resource_respects_max_bytes(self):
        result = json.loads(extract_resource("RT_RCDATA", "101", max_bytes=4))
        self.assertEqual(result["status"], "success")
        self.assertTrue(result["truncated"])
        self.assertEqual(result["returned_size"], 4)
        self.assertEqual(base64.b64decode(result["data_base64"]), b"\x89PNG")


if __name__ == "__main__":
    unittest.main()
