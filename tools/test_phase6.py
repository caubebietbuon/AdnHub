"""GW reader subset semantics, denied boundaries, and snapshot alignment."""
from pathlib import Path
import struct
import tempfile
import unittest

import gw_aligner
from gw_reader_model import Boundary, ModelError, Opaque, Parser, ReaderModel, Table


def model(text, name="r", limit=10000):
    return ReaderModel({name: Parser(text).definition(name)}, limit)


def uint(value):
    if value < 128: return bytes([value])
    if value < 16384: return bytes([128 | (value & 127), value >> 7])
    return bytes([128 | (value & 127), 128 | ((value >> 14) & 127), (value >> 7) & 127])


class ReaderSubsetTests(unittest.TestCase):
    def test_shadowing_duplicate_parameters_and_assignment(self):
        reader = model("r=function(x,x,a)local a,b=a,2;if true then local a=99;b=a;end;a,b=b,a;return a,b,x;end")
        self.assertEqual(reader.function("r", [reader, 7, 3]), [99, 3, 7])

    def test_lua_truth_zero_and_boolean_equality(self):
        reader = model("r=function(x)if 0 then return 0==false,not 0,0 and 7;end;end")
        self.assertEqual(reader.function("r", [reader]), [False, False, 7])

    def test_factory_is_never_called(self):
        reader = model("r=function(x,W,b)local t=x[34](2);t[1]=x[46](b,0);t[2]=x[8](b,1);return x[4890](x,t);end")
        with self.assertRaises(Boundary) as stopped:
            reader.function("r", [reader, None, bytes([9, 1, 2, 3, 4])])
        self.assertEqual(stopped.exception.slot, 4890)
        self.assertEqual(stopped.exception.arguments[1].data, {1: 9, 2: 0x04030201})

    def test_lazy_metadata_is_not_evaluated(self):
        reader = model("r=function(x,meta)local t={};x[97](t,meta);return t[1];end")
        with self.assertRaises(Boundary) as stopped:
            reader.function("r", [reader, Opaque("unexecuted")])
        self.assertEqual(stopped.exception.reason, "Lazy metatable read denied")

    def test_budget_and_buffer_bounds(self):
        reader = model("GW=function(x)local c=0;while true do c=c+1;end;end", "GW", 100)
        with self.assertRaises(ModelError): reader.function("GW", [reader])
        reader = model("r=function(x,b)return x[8](b,0);end")
        with self.assertRaises(ModelError): reader.function("r", [reader, b"\0"])
        with self.assertRaises(ModelError): Parser("r=function(x)return loadstring('bad');end").definition("r")


class AlignmentTests(unittest.TestCase):
    def test_independent_normalized_fixture(self):
        prefix = b"\0" + uint(157) + struct.pack("<I", 0) + uint(4890) + uint(2) + struct.pack("<II", 1, 2)
        data = prefix
        for index in range(4):
            data += uint(20233) + uint(1) + uint(2)
            if index == 0: data += uint(0) + uint(4)
        data += uint(1) + b"padding"
        result = gw_aligner.normalized_primary_layout(data)
        self.assertEqual([row["slots"] for row in result["arrays"]], [2, 2, 2, 2])
        self.assertEqual(result["register_capacity"]["value"], 4)
        self.assertEqual(result["entry_pc"]["value"], 1)
        self.assertEqual(result["unread_tail_bytes"], 7)

    def test_wrong_hash_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "g").write_text("unknown")
            (root / "d").write_bytes(b"unknown")
            with self.assertRaises(ModelError): gw_aligner.run(root / "g", root / "d", root / "out", [664])
            self.assertFalse((root / "out").exists())

    @unittest.skipUnless(Path("output/stage1-vm-source.lua.txt").exists(), "Local artifacts required")
    def test_source_reader_and_independent_parser_agree(self):
        with tempfile.TemporaryDirectory() as temp:
            result = gw_aligner.run(Path("output/stage1-vm-source.lua.txt"), Path("output/stage1-vm-data.bin"), Path(temp), [664, 1, 2])
            root, rejected, alternate = result["records"]
            self.assertEqual(root["factory_slot"], 4890)
            roles = root["factory"]["source_supported_roles"]
            self.assertEqual(roles["opcode_slots"]["positive_key_count"], 9965)
            self.assertEqual(roles["register_capacity"], 181)
            self.assertEqual(roles["entry_pc"], 9942)
            self.assertTrue(all(row["metatable_metadata_present"] for row in roles["lazy_reference_wrappers"].values()))
            self.assertEqual(root["normalized_reader_crosscheck"], "counts_ranges_pc_register_size_and_cursor_match")
            self.assertTrue(root["contiguous_coverage_to_cursor"])
            self.assertEqual(root["unread_tail_bytes"], 5)
            self.assertEqual(rejected["status"], "record_bounds_not_validated")
            self.assertEqual(alternate["bytes_read_through"], 1)
            self.assertEqual(result["vm_opcodes_executed"], 0)


if __name__ == "__main__": unittest.main()
