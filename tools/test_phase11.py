"""Mask equations, abstract boundaries and structurally constrained records."""
import json
from pathlib import Path
import tempfile
import unittest

from payload_decoder import mixer, xor_bytes, string_candidates, run
from prologue_analyzer import analyze


class PayloadTests(unittest.TestCase):
    def test_root_mask_vectors(self):
        self.assertEqual(mixer(1947447901), 336835166)
        self.assertEqual(mixer(4179906283), 421809900)
        self.assertEqual(336835115 ^ mixer(1947447901), 117)
        self.assertEqual(421809851 ^ mixer(4179906283), 87)

    def test_xor_is_bounded_and_reversible(self):
        self.assertEqual(xor_bytes(xor_bytes(b"\x00\xffabc", 91), 91), b"\x00\xffabc")
        with self.assertRaises(ValueError): xor_bytes(b"", -1)
        with self.assertRaises(ValueError): xor_bytes(b"", True)

    def test_unknown_operation_stops_without_dispatch(self):
        streams = {"O": [78], "j": [0], "Z": [0], "B": [0]}
        result = analyze(streams, 1, 0, 0)
        self.assertEqual(result["pc"], 1)
        self.assertEqual(result["patches"], [])
        self.assertEqual(streams["O"], [78])

    def test_abstract_jump_unknown_register_and_budget(self):
        streams = {"O": [22], "j": [0], "Z": [1], "B": [0]}
        self.assertEqual(analyze(streams, 1, 0, 0)["pc"], 1)
        streams = {"O": [129], "j": [0], "Z": [0], "B": [0]}
        self.assertIn("budget", analyze(streams, 1, 0, 0, budget=3)["stop"])

    def test_bulk_reader_is_one_based_and_does_not_touch_input(self):
        streams = {"O": [57, 0], "j": [1, 0], "Z": [1, 0], "B": [1, 0]}
        result = analyze(streams, 1, 0, 0)
        self.assertEqual(result["trace"][0]["rewritten_range"], [2, 3])
        self.assertEqual(streams["O"], [57, 0])
        self.assertNotEqual(result["arrays"]["Z"][1], 0)

    def test_readability_not_used_as_a_key_proof(self):
        result = string_candidates(b"\xae\x01\x00", {"reference_id": 1, "candidate_offset": 0})
        self.assertEqual(result["status"], "unresolved_mask")
        self.assertEqual(result["possible_masks"], 256)
        self.assertNotIn("source_mask", result)

    def test_unknown_input_no_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "g").write_bytes(b"unknown")
            (root / "d").write_bytes(b"unknown")
            with self.assertRaises(ValueError): run(root / "g", root / "d", root / "out")
            self.assertFalse((root / "out").exists())

    @unittest.skipUnless(Path("output/stage1-vm-data.bin").exists(), "Local artifacts required")
    def test_pinned_partial_decryption_and_truthful_hierarchy(self):
        with tempfile.TemporaryDirectory() as temp:
            result = run(Path("output/stage1-vm-source.lua.txt"), Path("output/stage1-vm-data.bin"), Path(temp))
            self.assertEqual(len(result["functions"]), 38)
            self.assertTrue(all(f["candidates"] for f in result["functions"]))
            self.assertEqual(sum(f["source_mask"] is not None for f in result["functions"]), 17)
            strings = [s for s in result["strings"] if s["status"] == "source_mask_string_candidate"]
            self.assertEqual(len(strings), 21)
            self.assertEqual(next(s["utf8"] for s in strings if s["reference_id"] == 115), "Random")
            self.assertEqual(result["record_1_2_reclassification"][0]["value"], 2503038408)
            self.assertEqual(result["record_1_2_reclassification"][1]["utf8"], "EnumType")
            self.assertIsNone(result["verified_hierarchy"])
            self.assertEqual(result["initialization_analysis"]["pc"], 9063)
            self.assertEqual(result["initialization_analysis"]["trace"][-1]["application_boundary"]["global_name"], "task")
            self.assertEqual(len(result["combined_string_candidates"]), 193)


if __name__ == "__main__":
    unittest.main()
