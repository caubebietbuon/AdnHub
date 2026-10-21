"""Exact inverse intersections, source-prefix contradictions and proof gates."""
import json
from pathlib import Path
import tempfile
import unittest

from obligation_resolver import (capture_constraints, evaluate_mask_site,
                                 projected_frontier_proof, run, source_transfer)
from prologue_analyzer import analyze, mix


def site(operand, word="y"):
    return {"reference_id": 74, "pc": 9, "variant": 157,
            "operand": operand, "word_variable": word}


def observation(operand, state, opcode=11, variant=157, ref=74):
    return {"pc": 9, "variant": variant, "opcode": opcode,
            "operand1": ref, "H": operand, "operand3": 0,
            "state_words_before": [123, state]}


class Phase14Tests(unittest.TestCase):
    def test_exact_inverse_intersection_from_same_site_state(self):
        state, key = 2639318406, 91
        operand = mix(state) ^ key
        result = evaluate_mask_site(site(operand), [observation(operand, state)])
        self.assertEqual(result["inverse_domain_count"], 2048)
        self.assertEqual(result["observed_visit_results"][0]["key"], key)
        self.assertEqual(result["observed_visit_results"][0]["state"], state)
        self.assertIsNone(result["unconditional_key"])

    def test_inverse_excludes_incompatible_observed_state(self):
        result = evaluate_mask_site(site(3), [observation(3, 123456)])
        self.assertEqual(result["observed_visit_results"][0]["status"], "pruned_observed_visit")
        self.assertIn("excludes", result["observed_visit_results"][0]["reason"])

    def test_dispatcher_mismatch_does_not_disprove_future_visits(self):
        result = evaluate_mask_site(site(3), [observation(3, 0, variant=163)])
        self.assertEqual(result["observed_visit_results"][0]["reason"], "different dispatcher")
        self.assertTrue(result["local_equation_satisfiable"])
        self.assertIsNone(result["unconditional_key"])

    def test_rewritten_reference_cannot_use_old_equation(self):
        result = evaluate_mask_site(site(3), [observation(3, 0, ref=75)])
        self.assertIn("differ", result["observed_visit_results"][0]["reason"])

    def test_local_equation_has_distinct_exact_witnesses(self):
        result = evaluate_mask_site(site(1234), [])
        self.assertEqual(result["observed_visit_results"], [])
        self.assertEqual([w["key"] for w in result["local_equation_witnesses"]], [0, 255])
        self.assertTrue(all(w["key"] == w["forward_key"] for w in result["local_equation_witnesses"]))
        self.assertIsNone(result["unconditional_key"])

    def test_non_uint32_state_does_not_enter_inverse_domain(self):
        result = evaluate_mask_site(site(3), [observation(3, 1 << 32)])
        self.assertEqual(result["observed_visit_results"][0]["status"], "unproved_uint32_state")

    def test_unsatisfiable_local_domain(self):
        result = evaluate_mask_site(site(0xffffffff), [])
        self.assertFalse(result["local_equation_satisfiable"])
        self.assertEqual(result["inverse_domain_count"], 0)

    def test_direct_mask_retains_path_guard(self):
        event = observation(9, 0, opcode=14, ref=0)
        event["operand3"] = 74
        result = evaluate_mask_site(site(9, None), [event])
        self.assertEqual(result["observed_visit_results"][0]["key"], 9)
        self.assertIsNone(result["unconditional_key"])

    def test_symbolic_context_read_does_not_call_assert(self):
        registers, event = {}, {"pc": 1}
        self.assertTrue(source_transfer(228, 131, 5, 109, 0, registers, event))
        self.assertEqual(registers[5], {"decoder_context_slot": 109})
        self.assertFalse(source_transfer(228, 93, 0, 5, 2, registers, event))

    def test_branch_transfer_uses_exact_numeric_relation(self):
        event = {"pc": 238}
        result = source_transfer(163, 78, 8, 7, 263, {7: 11}, event)
        self.assertEqual(result, {"next_pc": 264})
        self.assertFalse(event["exact_branch"]["result"])
        self.assertFalse(source_transfer(163, 78, 8, 7, 263, {7: {"symbol": "argument"}}, event))

    def test_literal_addition_requires_exact_numeric_input(self):
        registers, event = {1: 11}, {"pc": 152}
        self.assertTrue(source_transfer(163, 83, 1, 1, 1, registers, event))
        self.assertEqual(registers[1], 12)
        self.assertFalse(source_transfer(163, 83, 1, 1, 1, {1: None}, event))
        self.assertFalse(source_transfer(163, 83, 1, 1, 1, {1: 2**53}, event))

    def test_source_transfer_targets_are_bounded(self):
        arrays = {"O": [140], "j": [0], "Z": [0], "B": [0]}
        with self.assertRaises(ValueError):
            analyze(arrays, 1, 0, 0, source_transfer=lambda *args: {"next_pc": 0})
        with self.assertRaises(ValueError):
            analyze(arrays, 1, 0, 0, source_transfer=lambda *args: {"advance": 5})

    def test_capture_ordinals_are_not_child_register_numbers(self):
        binding = {"parent": 664, "child": 379, "descriptor_id": 462,
                   "captures": [{"cell_identity": "frame:664:register:107"}]}
        root = {"trace": [{"register_writes": [{"register": 107, "value": 0}]}]}
        row = capture_constraints([binding], root)[0]
        self.assertEqual(row["captures"][0]["capture_ordinal"], 1)
        self.assertEqual(row["captures"][0]["parent_register"], 107)
        self.assertEqual(row["captures"][0]["frontier_value"], 0)
        self.assertFalse(row["mask_word_dependency_proved"])

    def test_xor_self_cannot_cancel_unwritten_nil_operands(self):
        trace = {"trace": [{"pc": 29, "variant": 163, "opcode": 39, "H": 0, "operand3": 0}]}
        proof = projected_frontier_proof(137, trace)
        self.assertEqual(proof["unwritten_operands"], [0, 0])
        self.assertEqual(proof["status"], "normal continuation refuted under stated contracts")
        trace["trace"].insert(0, {"pc": 1, "variant": 157, "opcode": 69,
                                     "register_writes": [{"register": 0, "value": 7}]})
        self.assertEqual(projected_frontier_proof(137, trace)["status"], "pending")

    def test_bad_snapshot_rejected_before_writing_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "g").write_bytes(b"bad")
            (root / "d").write_bytes(b"bad")
            with self.assertRaises(ValueError): run(root / "g", root / "d", root / "out")
            self.assertFalse((root / "out").exists())

    @unittest.skipUnless(Path("output/stage1-vm-data.bin").exists(), "Pinned artifacts required")
    def test_pinned_phase14_evidence_and_unresolved_guards(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = run(Path("output/stage1-vm-source.lua.txt"), Path("output/stage1-vm-data.bin"), Path(temporary))
            saved = json.loads((Path(temporary) / "obligation-resolution.json").read_text(encoding="utf-8"))
        self.assertEqual(report["root_analysis"]["pc"], 8398)
        frame = report["fused_call_frontier"]
        self.assertEqual(frame["callee_expression"], {"decoder_context_slot": 109})
        self.assertEqual(frame["argument_expressions"][0], {"symbol": "global.debug"})
        self.assertEqual(frame["normal_return_pc"], 8400)
        self.assertFalse(frame["callee_invoked"])
        self.assertEqual(len(report["mask_audit"]), 18)
        strings = report["new_conditional_string_results"]
        self.assertEqual([(s["owner"], s["reference_id"], s["key"], s["utf8"]) for s in strings], [(711, 192, 5, "rawlen")])
        self.assertEqual(strings[0]["unknown_branch_constraints_before_patch"], [])
        self.assertEqual(len(report["still_without_trace_equation"]), 17)
        self.assertTrue(next(e for e in report["candidate_entry_analyses"] if e["owner"] == 711)["live_header_matches_root_context"])
        self.assertEqual(len(report["candidate_entry_analyses"]), 31)
        self.assertTrue(all(row["unconditional_key"] is None for row in report["mask_audit"]))
        self.assertTrue(all(row["distinct_local_plaintexts"] == 256 for row in report["local_ambiguity_certificates"]))
        self.assertTrue(all(row["payload_bytes"] > 0 for row in report["local_ambiguity_certificates"]))
        self.assertEqual(report["prefix_mask_coverage"]["remaining_ids_patched_in_prefix"], [])
        self.assertEqual(len(report["prototype_root_causes"]), 4)
        self.assertEqual([row["child"] for row in report["capture_frame_constraints"]], [567, 258, 379, 663])
        self.assertEqual(next(p for p in report["projected_frontier_proofs"] if p["owner"] == 137)["status"],
                         "normal continuation refuted under stated contracts")
        self.assertEqual(next(p for p in report["parent_activation_analyses"] if p["owner"] == 237)["pc"], 152)
        self.assertIsNone(report["verified_hierarchy"])
        self.assertIsNone(saved["verified_hierarchy"])
        self.assertTrue(report["validation_issues"])
        self.assertEqual(report["application_calls_executed"], 0)
        self.assertEqual(report["network_requests"], 0)


if __name__ == "__main__":
    unittest.main()
