"""Symbolic unknowns, guarded brute force and hierarchy proof obligations."""
from pathlib import Path
import tempfile
import unittest

from prologue_analyzer import analyze
from symbolic_resolver import PROOFS, enumerate_masks, explore, validate_tree, run


class SymbolicTests(unittest.TestCase):
    def test_global_symbol_is_not_default_zero(self):
        # Enter variant228, then read a global into register7, then stop at a call.
        streams = {"O": [20, 1, 0], "j": [1, 7, 0], "Z": [228, 0, 0], "B": [0, 111, 95]}
        baseline = analyze(streams, 1, 0, 0, text_constant=lambda _: "task")
        self.assertEqual(baseline["pc"], 2)
        result = analyze(streams, 1, 0, 0, text_constant=lambda _: "task",
                         symbolic_environment=True, snapshot_pcs=(3,))
        self.assertEqual(result["pc"], 3)
        self.assertEqual(result["trace"][-1]["registers_before"][7], {"symbol": "global.task"})

    def test_both_unknown_branches_preserve_constraints(self):
        streams = {"O": [71, 78, 78], "j": [0, 0, 0], "Z": [1, 0, 0], "B": [2, 0, 0]}
        paths, capped = explore(streams, 1, (0, 0), lambda _: None, lambda _: None)
        self.assertEqual(len(paths), 3)
        self.assertEqual({p["pc"] for p in paths[1:]}, {2, 3})
        self.assertEqual({p["constraints"][1] for p in paths[1:]}, {True, False})
        self.assertFalse(capped)

    def test_exhaustive_mask_domain_is_not_filtered_by_readability(self):
        result = enumerate_masks(b"abc", [{"key": 7, "guard": "state-dependent"}])
        self.assertEqual(len(result["all_masks"]), 256)
        self.assertEqual(len(result["unconditional_mask_domain"]), 256)
        self.assertEqual(result["conditional_plaintexts"][0]["key"], 7)
        self.assertFalse(result["resolved_unconditionally"])
        empty = enumerate_masks(b"", [])
        self.assertEqual(len({r["sha256"] for r in empty["all_masks"]}), 1)
        self.assertEqual(len(empty["unconditional_mask_domain"]), 256)

    def test_overlap_alone_cannot_verify_tree(self):
        result = validate_tree(1, [1, 2], [{"parent": 1, "child": 2,
                              "proofs": {"capture_indices_fit_owner": True}}])
        self.assertIsNone(result["verified_hierarchy"])
        self.assertTrue(result["validation_issues"])

    def test_tree_requires_coverage_unique_parent_and_no_cycle(self):
        proofs = dict.fromkeys(PROOFS, True)
        edge = {"parent": 1, "child": 2, "proofs": proofs}
        self.assertIsNotNone(validate_tree(1, [1, 2], [edge])["verified_hierarchy"])
        self.assertIsNone(validate_tree(1, [1, 2, 3], [edge])["verified_hierarchy"])
        cycle = [edge, {"parent": 2, "child": 1, "proofs": proofs}]
        self.assertIsNone(validate_tree(1, [1, 2], cycle)["verified_hierarchy"])
        parents = [edge, {"parent": 1, "child": 3, "proofs": proofs},
                   {"parent": 3, "child": 2, "proofs": proofs}]
        self.assertIsNone(validate_tree(1, [1, 2, 3], parents)["verified_hierarchy"])

    def test_unknown_hash_before_outputs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "g").write_bytes(b"unknown")
            (root / "d").write_bytes(b"unknown")
            with self.assertRaises(ValueError): run(root / "g", root / "d", root / "out")
            self.assertFalse((root / "out").exists())

    @unittest.skipUnless(Path("output/stage1-vm-data.bin").exists(), "Local artifacts required")
    def test_pinned_symbolic_and_guarded_ownership_results(self):
        with tempfile.TemporaryDirectory() as temp:
            report = run(Path("output/stage1-vm-source.lua.txt"), Path("output/stage1-vm-data.bin"), Path(temp))
            self.assertEqual(report["root_paths"][0]["pc"], 9251)
            self.assertEqual(len(report["string_mask_search"]), 29)
            self.assertEqual(sum(bool(s["conditional_plaintexts"]) for s in report["string_mask_search"]), 11)
            self.assertEqual(len(report["vm_record_analysis"]), 31)
            self.assertEqual(len(report["native_factory_references"]), 7)
            links = {(e["parent"], e["child"]) for e in report["candidate_capture_ownership"]}
            self.assertEqual(links, {(664, 506), (137, 747), (237, 572), (704, 288)})
            self.assertEqual(len(report["additional_node_header_hypotheses"]), 2)
            self.assertIsNone(report["verified_hierarchy"])
            self.assertEqual(report["network_requests"], 0)


if __name__ == "__main__":
    unittest.main()
