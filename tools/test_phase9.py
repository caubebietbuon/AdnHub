"""String boundary, binary preservation and reference-edge regression checks."""
import tempfile
from pathlib import Path
import unittest

from string_resolver import descriptor_preview, function_reference_edges, resolve_string, run


def fixture(payload, ref=1, tag=174):
    # Independent byte-at-a-time mask, not OW/VW or the implementation decoder.
    length = len(payload)
    if length < 128:
        marker = bytes([length])
    else:
        marker = bytes([128 + length % 128, length // 128])
    state, cipher = (ref + 83) % 256, bytearray()
    for value in payload:
        state = (state * 61 + 123) % 256
        cipher.append(value ^ state ^ 83)
    return bytes([tag]) + marker + cipher


class StringResolverTests(unittest.TestCase):
    def test_independent_mask_words_and_tail(self):
        payload = b"EnumType\x00Clone"
        result = resolve_string(fixture(payload, 2), 2, 0)
        self.assertEqual(bytes.fromhex(result["bytes_hex"]), payload)
        self.assertEqual(result["utf8"], "EnumType\x00Clone")

    def test_multibyte_length_and_empty(self):
        result = resolve_string(fixture(b"a" * 128), 1, 0)
        self.assertEqual(result["length"], 128)
        self.assertEqual(result["payload_offset"], 3)
        self.assertEqual(resolve_string(fixture(b""), 1, 0)["utf8"], "")

    def test_binary_string_is_lossless(self):
        result = resolve_string(fixture(b"\xff\x00\xfe"), 1, 0)
        self.assertFalse(result["utf8_valid"])
        self.assertIsNone(result["utf8"])
        self.assertEqual(result["bytes_hex"], "ff00fe")

    def test_raw_string_and_invalid_length(self):
        self.assertEqual(resolve_string(b"\xfa\x03cat", 1, 0)["utf8"], "cat")
        with self.assertRaises(ValueError): resolve_string(b"\xfa\x7fcat", 1, 0)
        with self.assertRaises(ValueError): resolve_string(b"\xae", 1, 0)
        self.assertEqual(resolve_string(b"\xc3\x00", 1, 0)["status"], "not_supported_string_branch")

    def test_descriptor_is_not_a_string_or_prototype(self):
        result = descriptor_preview(fixture(b"\x02\x00\x00", tag=219), 1, 0)
        self.assertEqual(result["count_marker"], 2)
        self.assertEqual(result["status"], "decoded_descriptor_header_only")
        self.assertNotIn("utf8", result)

    def test_only_source_supported_reference_edges(self):
        result = function_reference_edges(b"\x01", [{"value": 0}, {"value": 99}], {"j": [1, 2, 9999]})
        self.assertEqual(len(result["candidate_reference_edges"]), 1)
        self.assertEqual(result["opaque_directory_ids"], [2])
        self.assertIsNone(result["verified_hierarchy"])

    def test_unknown_hash_no_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "g").write_bytes(b"unknown")
            (root / "d").write_bytes(b"unknown")
            with self.assertRaises(ValueError): run(root / "g", root / "d", root / "out")
            self.assertFalse((root / "out").exists())

    @unittest.skipUnless(Path("output/stage1-vm-data.bin").exists(), "Local artifacts required")
    def test_pinned_strings_and_explicit_hierarchy_boundary(self):
        with tempfile.TemporaryDirectory() as temp:
            result = run(Path("output/stage1-vm-source.lua.txt"), Path("output/stage1-vm-data.bin"), Path(temp))
            strings = {row["reference_id"]: row for row in result["strings"]}
            self.assertEqual(strings[2]["utf8"], "EnumType")
            self.assertEqual(strings[4]["utf8"], "Clone")
            self.assertEqual(len(strings), 172)
            self.assertEqual(len(result["descriptor_headers"]), 32)
            self.assertEqual(len(result["unresolved"]), 99)
            self.assertEqual(result["phase8_unresolved_count"], 303)
            self.assertEqual(result["prototype_mapping"]["candidate_reference_edges"], [])
            self.assertIsNone(result["prototype_mapping"]["verified_hierarchy"])


if __name__ == "__main__":
    unittest.main()
