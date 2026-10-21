"""Static analyzer checks; never execute extracted Lua."""
from pathlib import Path
import tempfile
import unittest

import analyzer


class AnalyzerTests(unittest.TestCase):
    def test_literals_and_comments_do_not_create_fake_dispatch(self):
        text = 'return setmetatable({CW=function(x) local s="while true do local op=A[pc]"; -- while true do local z=B[p]\n return s end},{}):CW(...);'
        result, literals = analyzer.source_structure(analyzer.lex(text), text)
        self.assertEqual(result["dispatch_candidates"], [])
        self.assertEqual(len(literals), 1)
        self.assertTrue(result["entrypoint"]["evidence"])

    def test_dispatch_and_calls_ignore_literal(self):
        text = 'return setmetatable({CW=function(x) local s="x:Fake()"; x:Real(); while true do local op=A[pc]; end end},{}):CW(...);'
        result, _ = analyzer.source_structure(analyzer.lex(text), text)
        self.assertEqual(result["dispatch_candidates"][0]["opcode_variable"], "op")
        self.assertEqual(result["field_candidates"][0]["method_call_candidates"], ["Real"])

    def test_lua_decimal_escape_and_long_string(self):
        tokens = analyzer.lex(r'''"hello\10world\x21" [=[
long text]=]''')
        self.assertEqual(analyzer.decode_literal(tokens[0]), "hello\nworld!")
        self.assertEqual(analyzer.decode_literal(tokens[1]), "long text")
        with self.assertRaises(ValueError): analyzer.lex('"unfinished')

    def test_binary_runs_offsets_and_uleb_bounds(self):
        runs = analyzer.binary_strings(b"\x00abcdef\xffH\x00e\x00l\x00l\x00o\x00!\x00")
        self.assertEqual([(r["offset"], r["text"]) for r in runs], [(1, "abcdef"), (8, "Hello!")])
        self.assertEqual(analyzer.uleb_probe(b"\x81\x01")["values"][0]["value"], 129)
        self.assertEqual(analyzer.uleb_probe(b"\xff" * 5)["stop"], "exceeds_five_bytes")
        self.assertEqual(analyzer.entropy(b"a" * 20), 0)

    def test_hash_failure_has_no_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "g").write_bytes(b"untrusted")
            (root / "d").write_bytes(b"untrusted")
            with self.assertRaises(ValueError): analyzer.analyze(root / "g", root / "d", root / "out")
            self.assertFalse((root / "out").exists())

    @unittest.skipUnless(Path("output/stage1-vm-source.lua.txt").exists(), "Local extracted snapshot required")
    def test_snapshot_structure(self):
        with tempfile.TemporaryDirectory() as temp:
            report = analyzer.analyze(Path("output/stage1-vm-source.lua.txt"), Path("output/stage1-vm-data.bin"), Path(temp))
            self.assertEqual(report["source"]["literal_count"], 9224)
            self.assertEqual(len(report["source"]["dispatch_candidates"]), 7)
            self.assertEqual(report["binary"]["bytes"], 373666)
            self.assertEqual(report["binary"]["verified_fields"], [])
            self.assertFalse(report["payload_executed"])


if __name__ == "__main__": unittest.main()
