"""Fill isolation, overwrite invalidation and pinned reconstruction regression."""
import json
from pathlib import Path
import tempfile
import unittest

from reconstructor import apply_fill_copy, materialize_candidates, record_probe, run


class ReconstructionTests(unittest.TestCase):
    def test_fill_bounds_and_input_preservation(self):
        original = bytearray(b"abcdef")
        self.assertEqual(apply_fill_copy(original, 2, 3, 221), b"ab\xdd\xdd\xddf")
        self.assertEqual(original, b"abcdef")
        self.assertEqual(apply_fill_copy(original, 6, 0, 0), original)
        for args in [(-1, 2, 0), (5, 2, 0), (0, -1, 0), (0, 1, 256), (True, 1, 0)]:
            with self.assertRaises(ValueError): apply_fill_copy(original, *args)

    def test_overwritten_primitive_excluded_even_if_tag_survives(self):
        before = bytes([195, 7])
        after = apply_fill_copy(before, 1, 1, 221)
        result = materialize_candidates(before, after, [{"value": 0}], {"j": [1]}, (1, 2))
        self.assertEqual(result["candidate_constants"], [])
        self.assertTrue(result["observations"][0]["overlaps_fill"])
        self.assertTrue(result["observations"][0]["observation_changed"])

    def test_unaffected_candidate_deduplicated_and_cache_separate(self):
        before = bytes([195, 7, 0, 0])
        after = apply_fill_copy(before, 2, 2, 221)
        result = materialize_candidates(before, after, [{"value": 0}], {"j": [1, 1], "O": [1]}, (2, 4))
        self.assertEqual(len(result["candidate_constants"]), 1)
        self.assertEqual(len(result["candidate_wrapper_materializations"]["j"]), 2)
        self.assertEqual(result["shared_cache"]["actual_initial_entries"], {})
        self.assertIsNone(result["prototype_mapping"]["verified_child_hierarchy"])

    def test_invalid_ids_and_unsupported_records(self):
        self.assertEqual(record_probe(b"", [], 1)[0]["status"], "id_outside_directory")
        self.assertEqual(record_probe(b"\x01\x7f", [{"value": 0}], 1)[0]["status"], "record_bounds_not_validated")
        item, plain, begin = record_probe(b"\x01\x01\x01", [{"value": 0}] * 2, 2)
        self.assertEqual(item["status"], "unvalidated_record_not_reconstructed")
        self.assertIsNone(plain)

    def test_unknown_hash_has_no_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "g").write_bytes(b"unknown")
            (root / "d").write_bytes(b"unknown")
            with self.assertRaises(ValueError): run(root / "g", root / "d", root / "out", [664])
            self.assertFalse((root / "out").exists())

    @unittest.skipUnless(Path("output/stage1-vm-data.bin").exists(), "Local artifacts required")
    def test_pinned_snapshot_and_comparison_failures(self):
        with tempfile.TemporaryDirectory() as temp:
            result = run(Path("output/stage1-vm-source.lua.txt"), Path("output/stage1-vm-data.bin"), Path(temp), [664, 1, 2])
            root, one, two = result["records"]
            self.assertEqual(root["eligible_constant_candidates"], 281)
            self.assertEqual(root["distinct_observations"], 584)
            self.assertEqual(root["fill_changed_bytes"], 53668)
            self.assertEqual(root["observations_changed_after_fill"], 0)
            self.assertFalse(root["fully_materialized"])
            self.assertEqual(one["status"], "record_bounds_not_validated")
            self.assertEqual(two["format_byte"], 85)
            self.assertEqual(two["status"], "unvalidated_record_not_reconstructed")
            plain = (Path(temp) / "record-664.transformed.bin").read_bytes()
            self.assertEqual(plain[-5:].hex(), "05ed8324dd")
            mapping = json.loads((Path(temp) / "record-664.mapping.json").read_text())
            self.assertEqual(len(mapping["unresolved"]), 303)


if __name__ == "__main__":
    unittest.main()
