"""SSA slicing, independent equations and diagnostic/proxy scope tests."""
from pathlib import Path
import tempfile
import unittest

from layer_decomposer import (CRITERIA, core_decoder, graph_checks, indirect_paths, run)
from register_slicer import RegisterSlicer
from prologue_analyzer import analyze


def event(pc, op, a=0, b=0, c=0, writes=(), variant=157, words=(10, 20), **extra):
    return {"pc": pc, "opcode": op, "variant": variant, "operand1": a, "H": b, "operand3": c,
            "state_words_before": list(words), "register_writes": [{"register": reg, "value": value} for reg, value in writes], **extra}


class Phase15Tests(unittest.TestCase):
    def test_trace_order_not_numeric_pc_order(self):
        slicer = RegisterSlicer(1, [event(90, 69, 1, 5, writes=[(1, 5)]), event(2, 69, 1, 7, writes=[(1, 7)])])
        self.assertEqual(slicer.slice(register=1)["constant"], 7)
        self.assertEqual(slicer.slice(register=1, before_step=1)["constant"], 5)

    def test_parallel_swap_reads_old_versions(self):
        trace = [event(1, 69, 1, 10, writes=[(1, 10)]), event(2, 69, 2, 20, writes=[(2, 20)]),
                 event(3, 84, 2, 1, 1, writes=[(1, 20), (2, 10)])]
        slicer = RegisterSlicer(1, trace)
        self.assertEqual(slicer.slice(register=1)["constant"], 20)
        self.assertEqual(slicer.slice(register=2)["constant"], 10)

    def test_variant163_copy_order_matches_source_with_distinct_inputs(self):
        arrays = {"O": [69, 69, 20, 3, 0], "j": [1, 2, 3, 109, 30],
                  "Z": [10, 20, 163, 2, 0], "B": [0, 0, 0, 1, 0]}
        report = analyze(arrays, 1, 10, 20, track_register_writes=True)
        copied = report["trace"][3]["register_writes"]
        self.assertEqual(copied, [{"register": 3, "value": 10}, {"register": 4, "value": 20}])
        slicer = RegisterSlicer(1, report["trace"])
        self.assertEqual(slicer.slice(register=3)["constant"], 10)
        self.assertEqual(slicer.slice(register=4)["constant"], 20)

    def test_state_chain_reaches_header_and_decoded_numeric_inputs(self):
        trace = [event(1, 142, 1, 2, 3, writes=[(1, 3)], variant=228,
                       constant_inputs=[{"reference_id": 2, "value": 1}, {"reference_id": 3, "value": 2}]),
                 event(2, 56, b=2, writes=[(2, 20)], variant=228),
                 event(3, 122, 1, 2, 2, writes=[(2, 23)], variant=228),
                 event(4, 132, b=2, variant=228, state_word_write={"word": "y", "source_register": 2, "value": 23}),
                 event(5, 70, variant=228, words=(10, 23))]
        sliced = RegisterSlicer(1, trace).slice(word="y")
        self.assertEqual(sliced["constant"], 23)
        self.assertEqual(sliced["unresolved_leaves"], [])
        self.assertIn("decoded_constant", [node["op"] for node in sliced["nodes"]])

    def test_failed_state_write_attempt_does_not_change_state(self):
        slicer = RegisterSlicer(1, [event(1, 132, b=0, variant=228)])
        self.assertEqual(slicer.slice(word="y")["constant"], 20)

    def test_absent_entry_is_not_numeric_zero(self):
        sliced = RegisterSlicer(1, [event(1, 140)]).slice(register=0)
        self.assertIsNone(sliced["constant"])
        self.assertEqual(sliced["nodes"][0]["op"], "absent_frame_entry")

    def test_unknown_write_kills_previous_constant(self):
        trace = [event(1, 69, 1, 5, writes=[(1, 5)]), event(2, 999, writes=[(1, 99)])]
        sliced = RegisterSlicer(1, trace).slice(register=1)
        self.assertIsNone(sliced["constant"])
        self.assertEqual(sliced["nodes"][-1]["op"], "opaque_write")

    def test_capture_address_does_not_become_a_value(self):
        trace = [event(1, 69, 107, 0, writes=[(107, 0)]), event(2, 44, 1, 107, writes=[(1, {"symbol": "cell"})])]
        sliced = RegisterSlicer(1, trace).slice(register=1)
        self.assertIsNone(sliced["constant"])
        self.assertEqual(sliced["nodes"][-1]["op"], "capture_cell_address")

    def test_backward_forward_disagreement_rejected(self):
        with self.assertRaises(ValueError): RegisterSlicer(1, [event(1, 69, 1, 5, writes=[(1, 6)])])
        with self.assertRaises(ValueError): RegisterSlicer(1, [event(1, 69, 1, 1, writes=[(1, True)])])

    def test_query_bounds_are_explicit(self):
        slicer = RegisterSlicer(1, [event(1, 140)])
        with self.assertRaises(ValueError): slicer.slice(register=1, before_step=5)
        with self.assertRaises(ValueError): slicer.slice(register=1, word="y")

    def test_direct_decoder_keeps_non_utf8_without_selecting_it(self):
        bad = core_decoder({"word_variable": None, "operand": 110}, bytes([239]))
        readable = core_decoder({"word_variable": None, "operand": 140}, bytes([239]))
        self.assertEqual(bad["decoded_bytes_hex"], "81")
        self.assertIsNone(bad["utf8"])
        self.assertEqual(readable["utf8"], "c")
        self.assertFalse(bad["activation_proved"])
        self.assertFalse(readable["activation_proved"])

    def test_unknown_mixer_state_is_not_replaced_by_header(self):
        site = {"word_variable": "y", "operand": 3, "inverse_domain_count": 2048}
        unknown = core_decoder(site, b"a")
        self.assertFalse(unknown["state_input_resolved_at_site"])
        exact = core_decoder(site, b"a", state=0)
        self.assertEqual(exact["key"], 3)
        self.assertEqual(exact["decoded_bytes_hex"], "62")
        self.assertFalse(core_decoder(site, b"a", state=123456)["algebra_satisfiable"])
        with self.assertRaises(ValueError): core_decoder(site, b"a", state=True)

    def test_graph_coverage_and_cycles_are_separate(self):
        edges = [{"parent": 1, "child": 2}, {"parent": 2, "child": 3}]
        graph = graph_checks(1, [1, 2, 3, 4], edges)
        self.assertEqual(graph["missing"], [4])
        self.assertEqual(graph["cycles"], [])
        self.assertTrue(graph_checks(1, [1, 2, 3], edges + [{"parent": 3, "child": 2}])["cycles"])

    def test_proxy_paths_use_prototypes_not_shared_factories(self):
        edges = [{"parent": 664, "child": 567}, {"parent": 664, "child": 258}]
        self.assertEqual(indirect_paths(567, 258, edges), [])
        self.assertEqual(indirect_paths(664, 258, edges + [{"parent": 567, "child": 258}]), [[664, 567, 258]])

    def test_unknown_snapshot_rejected_before_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            (base / "g").write_bytes(b"bad")
            (base / "d").write_bytes(b"bad")
            with self.assertRaises(ValueError): run(base / "g", base / "d", base / "out")
            self.assertFalse((base / "out").exists())

    @unittest.skipUnless(Path("output/stage1-vm-data.bin").exists(), "Pinned artifacts required")
    def test_pinned_decomposition_and_six_column_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = run(Path("output/stage1-vm-source.lua.txt"), Path("output/stage1-vm-data.bin"), Path(temporary))
            self.assertTrue((Path(temporary) / "DIAGNOSTIC_MATRIX.md").exists())
        self.assertEqual(len(report["string_decomposition"]), 17)
        self.assertTrue(all(row["selected_key"] is None for row in report["string_decomposition"]))
        sites = [site for row in report["string_decomposition"] for site in row["sites"]]
        self.assertEqual(len(sites), 14)
        self.assertEqual(sum(site["core_decoder"]["kind"] == "direct_xor" for site in sites), 9)
        self.assertTrue(all(not site["frontier_value_may_be_used_at_site"] for site in sites))
        self.assertEqual(report["backward_slice_controls"]["root_y_at_frontier"]["constant"], 2639318406)
        self.assertEqual(len(report["prototype_diagnostic_matrix"]), 8)
        for row in report["prototype_diagnostic_matrix"]:
            self.assertEqual(set(row["criteria"]), set(CRITERIA))
            self.assertEqual(row["criteria"]["coverage"]["status"], "FAIL")
            self.assertEqual(row["criteria"]["cycle_checks"]["status"], "PASS")
            self.assertFalse(row["unchanged_validator_proofs"]["ancestry_unconditional"])
        blocked = next(row for row in report["prototype_diagnostic_matrix"] if row["parent"] == 137)
        self.assertEqual(blocked["criteria"]["control_flow"]["status"], "FAIL")
        self.assertEqual(len(report["proxy_linkages"]), 8)
        self.assertTrue(all(not row["indirect_lexical_owner_proved"] for row in report["proxy_linkages"]))
        self.assertIsNone(report["verified_hierarchy"])
        self.assertEqual(report["application_calls_executed"], 0)
        self.assertEqual(report["network_requests"], 0)


if __name__ == "__main__":
    unittest.main()
