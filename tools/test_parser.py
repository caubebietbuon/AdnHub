"""Run with: python -m unittest discover -s tools -p test_parser.py"""
import hashlib
import lzma
from pathlib import Path
import struct
import tempfile
import unittest

import parser


class ParserTests(unittest.TestCase):
    def test_radix85_permutation_and_little_endian(self):
        # Base85 digits 0,0,0,1,2 are stored with digits four/five swapped.
        self.assertEqual(parser.decode_radix85(b"LPH~   \"!", {}), struct.pack("<I", 87))
        self.assertEqual(parser.decode_radix85(b"LPH~x", {120: b"   \"!"}), struct.pack("<I", 87))

    def test_bad_radix85(self):
        for blob in (b"NOPE     ", b"LPH~ ", b"LPH~ttttt", b"LPH~\xff    "):
            with self.subTest(blob=blob), self.assertRaises(ValueError):
                parser.decode_radix85(blob, {})

    def test_raw_lzma_size_and_trailing_data(self):
        data = b"Known decoder test data" * 100
        packed = lzma.compress(data, format=lzma.FORMAT_RAW, filters=[{
            "id": lzma.FILTER_LZMA1, "dict_size": parser.MAX_UNPACKED,
            "lc": 3, "lp": 0, "pb": 0}])
        self.assertEqual(parser.decompress_raw(packed + b"\0\0", len(data)), (data, 2))
        for expected in (len(data) - 1, len(data) + 1, parser.MAX_UNPACKED + 1):
            with self.subTest(expected=expected), self.assertRaises(ValueError):
                parser.decompress_raw(packed, expected)
        with self.assertRaises(ValueError):
            parser.decompress_raw(packed + b"extra", len(data))

    def test_unknown_input_does_not_publish(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "input.lua").write_bytes(b"print('untrusted')")
            with self.assertRaises(ValueError):
                parser.parse(root / "input.lua", root / "output")
            self.assertFalse((root / "output").exists())

    @unittest.skipUnless(Path("input/StealAnEggg.lua").exists(), "Local snapshot not provided")
    def test_audited_snapshot(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            report = parser.parse(Path("input/StealAnEggg.lua"), root)
            expected = [(1261603, "1bc1f3c9df9aed79ff79a392423a5f59e41b04f7c326c90c4e0603362c745ed8"),
                        (373666, "0131f80c4b90b7a49aeaf5d44707ab90575321ebd2b7d0587ea56484a8c56a13")]
            for stream, (size, digest) in zip(report["streams"], expected):
                data = (root / stream["output_file"]).read_bytes()
                self.assertEqual(len(data), size)
                self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
            self.assertIsNone(report["verified_vm_instruction_bytes"])


if __name__ == "__main__":
    unittest.main()
