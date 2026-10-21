"""Static capture grammar and guarded directory-reference tests."""
from pathlib import Path
import tempfile
import unittest

from prototype_mapper import DIRECTORY_MASK, conditional_links, parse_descriptors, run


class PrototypeMapperTests(unittest.TestCase):
    def test_all_capture_kinds_and_optional_span(self):
        result = parse_descriptors(bytes([4, 3, 8, 13, 18, 2]))
        self.assertEqual([x["triplet"] for x in result["captures"]],
                         [[7030, 0, 3], [7030, 2, 0], [7030, 3, 1], [3, 4, 2]])
        self.assertTrue(all(x["prototype_id"] is None for x in result["captures"]))
        self.assertEqual(parse_descriptors(b"\x00")["count"], 0)

    def test_multibyte_packed_descriptor(self):
        result = parse_descriptors(bytes([1, 163, 1]))
        self.assertEqual(result["captures"][0]["target_index"], 40)
        self.assertEqual(result["captures"][0]["kind"], 3)

    def test_truncation_count_limit_and_trailing_data(self):
        for raw in [b"", b"\x02\x03", b"\x01\x02", b"\x00\x03"]:
            with self.assertRaises(ValueError): parse_descriptors(raw)
        with self.assertRaises(ValueError): parse_descriptors(b"\x01\x03", max_count=0)

    def test_conditional_xor_edge_does_not_verify_parenthood(self):
        result = conditional_links(b"\x01\x01\x00", [{"value": DIRECTORY_MASK}], {"B": [1, 1]})
        self.assertEqual(len(result["conditional_function_edges"]), 1)
        edge = result["conditional_function_edges"][0]
        self.assertEqual(edge["candidate_offset"], 0)
        self.assertEqual(len(edge["root_stream_uses"]), 2)
        self.assertFalse(edge["factory_invoked"])
        self.assertIsNone(result["verified_hierarchy"])

    def test_conditional_string_not_promoted_and_invalid_bounds(self):
        result = conditional_links(b"\xae\x01\x00", [{"value": DIRECTORY_MASK}], {"j": [1]})
        self.assertEqual(len(result["conditional_string_targets"]), 1)
        self.assertEqual(result["conditional_function_edges"], [])
        rejected = conditional_links(b"\x01\x7f", [{"value": DIRECTORY_MASK}], {"B": [1]})
        self.assertEqual(rejected["rejected"][0]["status"], "function_bounds_rejected")

    def test_unknown_snapshot_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "g").write_bytes(b"unknown")
            (root / "d").write_bytes(b"unknown")
            with self.assertRaises(ValueError): run(root / "g", root / "d", root / "out")
            self.assertFalse((root / "out").exists())

    @unittest.skipUnless(Path("output/stage1-vm-data.bin").exists(), "Local artifacts required")
    def test_pinned_synthesis_and_capture_counts(self):
        with tempfile.TemporaryDirectory() as temp:
            result = run(Path("output/stage1-vm-source.lua.txt"), Path("output/stage1-vm-data.bin"), Path(temp))
            self.assertEqual(result["root"]["register_capacity"], 181)
            self.assertEqual(result["root"]["entry_pc"], 9942)
            self.assertEqual(len(result["constant_candidates"]["primitives"]), 281)
            self.assertEqual(len(result["constant_candidates"]["strings"]), 172)
            self.assertEqual(len(result["descriptors"]), 32)
            self.assertEqual(sum(d["count"] for d in result["descriptors"]), 163)
            self.assertEqual(result["descriptor_failures"], [])
            self.assertEqual(len(result["prototype_mapping"]["conditional_function_edges"]), 34)
            self.assertEqual(len(result["prototype_mapping"]["conditional_string_targets"]), 47)
            self.assertIsNone(result["prototype_mapping"]["verified_hierarchy"])


if __name__ == "__main__":
    unittest.main()
