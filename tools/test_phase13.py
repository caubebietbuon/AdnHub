"""Phase13 source predicates, symbolic transfers and proof boundaries."""
from pathlib import Path
import tempfile
import unittest

from fused_call_analyzer import (Constants, Closures, classify_228, constructor_contract,
                                inverse_mix, mask_word_domain, run, summarize_fused_call)
from prologue_analyzer import mix


class Phase13Tests(unittest.TestCase):
    def test_dispatch_truth_table(self):
        expected = ["indirect_jump", "fused_call", "multiply", "field_lookup",
                    "not", "constant_add", "subtract"]
        self.assertEqual([classify_228(i)["handler"] for i in range(92, 99)], expected)
        for value in (True, 91, 99):
            with self.assertRaises(ValueError): classify_228(value)

    def test_fused_copy_happens_before_target_resolution(self):
        arrays = {"B": [93, 0], "O": [4, 4], "Z": [8, 2], "j": [0, 3]}
        registers = {4: "old", 8: "callee"}
        result = summarize_fused_call(arrays, 1, registers)
        self.assertEqual(result["callee_expression"], "callee")
        self.assertEqual(result["argument_range_half_open"], [5, 7])
        self.assertEqual(result["result_range_half_open"], [4, 7])
        self.assertEqual(result["normal_return_pc"], 3)
        self.assertIsNone(result["exception_or_nonreturn_pc"])
        self.assertFalse(result["callee_invoked"])
        self.assertEqual(registers[4], "old")

    def test_noncall_rejected_and_empty_frame(self):
        arrays = {"B": [95, 0], "O": [0, 2], "Z": [0, 0], "j": [0, 0]}
        with self.assertRaises(ValueError): summarize_fused_call(arrays, 1, {})
        arrays["B"][0] = 93
        result = summarize_fused_call(arrays, 1, {})
        self.assertEqual(result["argument_range_half_open"], [3, 3])
        self.assertEqual(result["result_range_half_open"], [2, 2])

    def test_constructor_only_alias_prefixes(self):
        source = "[4890]=function(x)local a=x[1];return function(g)local b=a;return function(...)evil()end end end"
        self.assertFalse(constructor_contract(source, 4890)["body_executed"])
        with self.assertRaises(ValueError): constructor_contract(source.replace("local b=a;", "evil();"), 4890)

    def test_inverse_mixer_has_exact_eight_preimages(self):
        for value in (0, 1, 7, 255, 306486104, (1 << 29) - 1):
            preimages = inverse_mix(value)
            self.assertEqual(len(set(preimages)), 8)
            self.assertTrue(all(mix(word) == value for word in preimages))
            self.assertEqual({word >> 29 for word in preimages}, set(range(8)))
        with self.assertRaises(ValueError): inverse_mix(1 << 29)

    def test_byte_domain_is_not_unique_key_proof(self):
        domain = mask_word_domain(12345)
        self.assertEqual(len(domain), 2048)
        self.assertTrue(all(0 <= (12345 ^ mix(word)) <= 255 for word in domain))
        restricted = mask_word_domain(12345, [91])
        self.assertEqual(len(restricted), 8)
        self.assertTrue(all(12345 ^ mix(word) == 91 for word in restricted))
        self.assertEqual(mask_word_domain(0xffffffff), [])

    def test_future_masks_not_injected_and_repeat_toggle_rejected(self):
        view = Constants(bytes(10), [{"value": 3 ^ 306486104}])
        self.assertIsNone(view.text(1))
        self.assertEqual(view.effects, {})
        self.assertTrue(view.observe({"reference_id": 1, "key": 7}))
        self.assertEqual(view.positions[1], 3)
        self.assertFalse(view.observe({"reference_id": 1, "key": 7}))
        self.assertEqual(view.effects[1], 7)

    def test_invalid_closure_id_stops_before_header_read(self):
        closures = Closures("", Constants(b"", []), 664, 181, {})
        self.assertIsNone(closures.build(0, 1, 1, 228, {}))
        self.assertIn("outside directory", closures.obligations[0]["reason"])

    @unittest.skipUnless(Path("output/stage1-vm-data.bin").exists(), "Pinned artifacts needed")
    def test_pinned_corrected_path_and_open_proof_obligations(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = run(Path("output/stage1-vm-source.lua.txt"), Path("output/stage1-vm-data.bin"), Path(temporary))
        events = {e["pc"]: e for e in report["focused_register_snapshots"]}
        self.assertEqual(events[9251]["opcode"], 95)
        self.assertEqual(events[9251]["register_writes"][0]["value"]["key_text"], "cancel")
        self.assertEqual(events[9253]["register_writes"][0]["value"]["key_text"], "spawn")
        self.assertEqual(report["root_analysis"]["pc"], 8395)
        self.assertEqual(len(report["path_local_patch_events"]), 45)
        self.assertEqual(report["patch_violations"], [])
        self.assertEqual([b["child"] for b in report["guarded_closure_bindings"]], [567, 258, 379, 663])
        a, b = report["guarded_closure_bindings"][:2]
        self.assertEqual(a["captures"], b["captures"])
        self.assertEqual(len(report["ownership_audits"]), 4)
        self.assertTrue(all(not a["proofs"]["ancestry_unconditional"] for a in report["ownership_audits"]))
        self.assertEqual(len(report["remaining_string_constraints"]), 18)
        self.assertTrue(all(s["unconditional_key"] is None for s in report["remaining_string_constraints"]))
        self.assertIsNone(report["verified_hierarchy"])
        self.assertEqual(report["network_requests"], 0)
        self.assertEqual(report["factory_invocations"], 0)


if __name__ == "__main__":
    unittest.main()
