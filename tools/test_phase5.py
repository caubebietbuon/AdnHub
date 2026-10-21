"""Reader arithmetic and reviewed snapshot regressions; never execute Lua."""
from pathlib import Path
import hashlib
import tempfile
import unittest

import reader_tracer


class ReaderTests(unittest.TestCase):
    def test_custom_integer_permutations(self):
        cases = [(b"\x7f", 127), (b"\x80\x01", 128),
                 (b"\x87\x85\x6a", 95495),
                 (b"\x81\x82\x83\x84", (1 << 21) | 2 | (3 << 14) | (4 << 7) | (1 << 28))]
        for data, expected in cases:
            self.assertEqual(reader_tracer.custom_uint(data, 0), (expected, len(data)))

    def test_custom_integer_bounds(self):
        for data in (b"", b"\x80", b"\x80\x80", b"\x80\x80\x80"):
            with self.subTest(data=data), self.assertRaises(ValueError): reader_tracer.custom_uint(data, 0)
        with self.assertRaises(ValueError): reader_tracer.custom_uint(b"\0", -1)

    def test_word_mask_known_vector(self):
        output, trace = reader_tracer.decrypt_record(bytes.fromhex("3913669c"), 664, 91)
        self.assertEqual(output.hex(), "009d0100")
        self.assertEqual(trace["initial_state"], 243)
        self.assertEqual(trace["submask_hex"], "5b5b5b5b")
        self.assertEqual(trace["word_trace_first16"][0]["OW_hex"], "c73cd562")
        self.assertEqual(trace["final_state"], 199)

    def test_tail_matches_independent_scalar_reference(self):
        for length in range(12):
            ciphertext = bytes(range(length))
            state = 243
            reference = bytearray()
            for byte in ciphertext:
                state = (state * 61 + 123) % 256
                reference.append(byte ^ 91 ^ state)
            output, trace = reader_tracer.decrypt_record(ciphertext, 664, 91)
            self.assertEqual(output, bytes(reference))
            self.assertEqual(trace["final_state"], state)
        with self.assertRaises(ValueError): reader_tracer.decrypt_record(b"", 664, 256)

    def test_unknown_snapshot_stops(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "g").write_text("unknown")
            (root / "d").write_bytes(b"unknown")
            with self.assertRaises(ValueError): reader_tracer.run(root / "g", root / "d", root / "out")
            self.assertFalse((root / "out").exists())

    @unittest.skipUnless(Path("output/stage1-vm-source.lua.txt").exists(), "Local artifacts required")
    def test_selected_snapshot_record(self):
        with tempfile.TemporaryDirectory() as temp:
            report = reader_tracer.run(Path("output/stage1-vm-source.lua.txt"), Path("output/stage1-vm-data.bin"), Path(temp))
            self.assertEqual(report["loader"]["record_payload_input_offset"], 43414)
            self.assertEqual(report["loader"]["record_length"], 53886)
            self.assertEqual(len(report["loader"]["lookup_entries"]), 748)
            self.assertEqual(report["loader"]["slice_end"], 154419)
            self.assertEqual(report["selected_record_first64"]["decoded_hex"][:16], "009d01000000009a")
            self.assertEqual(hashlib.sha256((Path(temp) / "selected-record-prefix.bin").read_bytes()).hexdigest(), "fa6871bc0acd37b71207626e55d7e880a87c7b981a3dcf14cbd8170dde5eb243")
            self.assertEqual(report["source_evidence"]["zW_shift_operator_offsets"], [])
            self.assertEqual(report["source_evidence"]["zW_band_calls"], 0)
            self.assertFalse(report["payload_executed"])


if __name__ == "__main__": unittest.main()
