"""Regression checks for static tag classification and bounded data readers."""
import unittest

from lazy_tracer import inspect_reference, predicate, tag_path, tail_descriptor


class LazyReaderTests(unittest.TestCase):
    def test_complete_tag_partition_and_boundaries(self):
        expected = {
            0: 24, 15: 24, 16: 88, 17: 73, 28: 73, 29: 82, 53: 82,
            54: 21, 63: 21, 64: 84, 70: 161, 96: 84, 97: 17,
            104: 17, 105: 33, 166: 33, 167: 155, 168: 136, 169: 136,
            170: 98, 174: 98, 175: 130, 195: 130, 196: 65, 197: 68,
            198: 65, 203: 65, 204: 58, 218: 58, 219: 95,
            220: 140, 237: 140, 238: 55, 244: 70, 255: 55,
        }
        for tag, leaf in expected.items():
            self.assertEqual(tag_path(tag)[0], leaf, tag)
        for tag in range(256):
            self.assertLess(len(tag_path(tag)[1]), 9)
        with self.assertRaises(ValueError): tag_path(256)
        with self.assertRaises(ValueError): predicate("__import__('os')", 0)

    def test_byte_mask_golden_vector(self):
        # id3+aux255 -> seed2; step=245; 7 XOR245 XOR255=13.
        result = inspect_reference(bytes([195, 7]), [{"value": 0}] * 3, 3)
        self.assertEqual(result["value"], 13)
        self.assertEqual(result["auxiliary"], 255)

    def test_word_mask_golden_vector(self):
        # id122+aux134 -> seed0; OW[0]=e49dca7b; XOR86868686=621b4cfd.
        result = inspect_reference(bytes([167, 0, 0, 0, 0]), [{"value": 0}] * 122, 122)
        self.assertEqual(result["plain_hex"], "fd4c1b62")
        self.assertEqual(result["value"], 0x621b4cfd)

    def test_raw_string_and_bounds(self):
        result = inspect_reference(b"\xfa\x03cat", [{"value": 0}], 1)
        self.assertEqual(result["preview_utf8"], "cat")
        self.assertEqual(result["length"], 3)
        self.assertEqual(inspect_reference(b"\xfa\x09cat", [{"value": 0}], 1)["status"], "raw_string_out_of_bounds")
        self.assertEqual(inspect_reference(b"\xc3", [{"value": 0}], 1)["status"], "primitive_out_of_bounds")
        self.assertEqual(inspect_reference(b"", [{"value": 9}], 1)["status"], "opaque_directory_value_not_followed")

    def test_recursive_reference_remains_boundary(self):
        result = inspect_reference(b"\x01", [{"value": 0}], 1)
        self.assertEqual(result["status"], "recursive_v_reference_boundary")
        self.assertFalse(result["factory_invoked"])
        self.assertFalse(result["prototype_constructed"])

    def test_tail_golden_vector_and_bounds(self):
        result = tail_descriptor(bytes.fromhex("05ed8324dd"), 0, 41172, 152177)
        self.assertEqual(result["length"], 53869)
        self.assertEqual(result["backing_slice_range"], [41177, 95046])
        self.assertEqual(result["fill_byte"], 221)
        self.assertEqual(result["remaining_bytes"], 0)
        with self.assertRaises(ValueError):
            tail_descriptor(bytes.fromhex("05ed8324dd"), 0, 41172, 50000)


if __name__ == "__main__":
    unittest.main()
