"""LCG arithmetic, experimental controls and static extraction boundaries."""
from pathlib import Path
import tempfile
import unittest

import analyzer
import lcg_decoder
import state_separator


class LCGTests(unittest.TestCase):
    def test_inverse_all_states(self):
        self.assertEqual(lcg_decoder.INVERSE_MULTIPLIER, 21)
        for state in range(256):
            self.assertEqual(lcg_decoder.inverse_step(lcg_decoder.step(state)), state)

    def test_word_stream_matches_independent_byte_reference(self):
        data = bytes(range(255))
        for seed in (0, 9, 137, 255):
            state = seed
            expected = bytearray()
            for byte in data:
                state = (61 * state + 123) % 256
                expected.append(byte ^ state)
            actual, final = lcg_decoder.unxor(data, seed)
            self.assertEqual(actual, bytes(expected))
            self.assertEqual(final, state)
        self.assertEqual(lcg_decoder.unxor(b"\0" * 5, 0), (bytes([123, 202, 157, 228, 207]), 207))

    def test_extra_word_mask_and_xor_involution(self):
        data = bytes(range(101))
        decoded, _ = lcg_decoder.unxor(data, 9, 0xAABBCCDD)
        restored, _ = lcg_decoder.unxor(decoded, 9, 0xAABBCCDD)
        self.assertEqual(restored, data)
        plain, _ = lcg_decoder.unxor(b"\0" * 4, 0, 0xAABBCCDD)
        self.assertEqual(plain, bytes(a ^ b for a, b in zip(bytes([123, 202, 157, 228]), bytes([221, 204, 187, 170]))))
        with self.assertRaises(ValueError): lcg_decoder.unxor(b"", 256)

    def test_entropy_cannot_distinguish_high_bit_seed(self):
        data = bytes(range(256)) * 2
        left, _ = lcg_decoder.unxor(data, 9)
        right, _ = lcg_decoder.unxor(data, 137)
        self.assertEqual(right, bytes(byte ^ 128 for byte in left))
        self.assertAlmostEqual(analyzer.entropy(left), analyzer.entropy(right))

    def test_synthetic_plaintext_control(self):
        original = b"A" * 512
        ciphertext, _ = lcg_decoder.unxor(original, 37)
        report, results = lcg_decoder.scan_window(ciphertext, 0, 512, 2, 0)
        self.assertIn((37, original), results)
        self.assertFalse(report["verified_decryption"])
        self.assertAlmostEqual(report["baseline"]["entropy_bits_per_byte"], report["fixed_xor_control_entropy"])

    def test_unknown_binary_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "d").write_bytes(b"unknown")
            with self.assertRaises(ValueError): lcg_decoder.run(root / "d", root / "out", [0], 64, 1, 0)
            self.assertFalse((root / "out").exists())


class SeparationTests(unittest.TestCase):
    def test_trim_known_metadata_only(self):
        function, tail = state_separator.trim_region("sW=function()return 1;end,[46]=buffer.readu8,[88]=table.pack,")
        self.assertTrue(function.endswith("end"))
        self.assertEqual(tail, ",[46]=buffer.readu8,[88]=table.pack,")
        with self.assertRaises(ValueError): state_separator.trim_region("x=function()end,arbitrary=unknown(),")

    @unittest.skipUnless(Path("output/stage1-vm-source.lua.txt").exists(), "Local g required")
    def test_real_regions_and_view_cut(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            report = state_separator.separate(Path("output/stage1-vm-source.lua.txt"), root)
            self.assertEqual(len(report["regions"]), 11)
            view = (root / "sW-before-v.view.txt").read_text()
            self.assertNotIn("x:v(", view)
            self.assertNotIn("(x.K,nil,nil)", view)
            self.assertIn("BEFORE_V_NO_CALL", view)
            self.assertFalse(report["payload_executed"])


if __name__ == "__main__": unittest.main()
