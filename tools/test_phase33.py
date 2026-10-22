"""Exact arithmetic hypotheses must never become unproved epoch aliases."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from epoch_mapper import (affine_hypotheses,bitwise_hypotheses,controlled_intersection,
    factory_audit,mixer_preimages,rotate,run,slot_translation)


class AffineTests(unittest.TestCase):
    def test_unique_odd_affine_map(self):
        r=affine_hypotheses([[0,7],[1,10],[13,46]],8)
        self.assertEqual((r['coefficient_residue'],r['offset_for_residue']),(3,7))
        self.assertEqual(r['status'],'UNIQUE_FIT')
        self.assertFalse(r['source_transfer_proved'])

    def test_noninvertible_difference_retains_coefficient_family(self):
        r=affine_hypotheses([[0,7],[2,13]],8)
        self.assertEqual((r['coefficient_residue'],r['coefficient_period'],r['coefficient_count']),(3,128,2))

    def test_inconsistent_congruence(self):
        self.assertEqual(affine_hypotheses([[0,0],[2,1]],8)['status'],'INCONSISTENT')

    def test_even_multiplier_is_not_permutation(self):
        p=[[0,5],[1,7]]
        self.assertEqual(affine_hypotheses(p,8)['status'],'INCONSISTENT')
        self.assertEqual(affine_hypotheses(p,8,False)['coefficient_residue'],2)

    def test_empty_and_single_observations_do_not_select_defaults(self):
        self.assertEqual(affine_hypotheses([])['status'],'UNDERCONSTRAINED')
        self.assertNotIn('coefficient_residue',affine_hypotheses([]))
        self.assertEqual(affine_hypotheses([[5,6]],8)['coefficient_count'],128)

    def test_conflicting_repeated_source(self):
        self.assertEqual(affine_hypotheses([[5,6],[5,7]],8)['status'],'INCONSISTENT')

    def test_exact_modular_wrap(self):
        r=affine_hypotheses([[255,4],[0,7],[1,10]],8)
        self.assertEqual((r['coefficient_residue'],r['offset_for_residue']),(3,7))

    def test_differing_periods_intersect_exactly(self):
        r=affine_hypotheses([[0,1],[4,21],[2,11]],8)
        self.assertEqual((r['coefficient_period'],r['coefficient_residue']),(128,5))
        self.assertEqual(affine_hypotheses([[0,1],[4,21],[2,13]],8)['status'],'INCONSISTENT')

    def test_exhaustive_small_domains_match_congruence_solution(self):
        for pairs in ([[0,1],[2,7]],[[0,1],[4,5]],[[2,3],[5,4]],[[0,1],[2,2]]):
            r=affine_hypotheses(pairs,4)
            exact=[a for a in range(1,16,2) if all((a*x+(pairs[0][1]-a*pairs[0][0]))%16==y for x,y in pairs)]
            self.assertEqual(r['status']=='INCONSISTENT',not exact)
            if exact:
                predicted=[a for a in range(16) if a%r['coefficient_period']==r['coefficient_residue']]
                self.assertEqual(predicted,exact)

    def test_bad_types_width_and_bounds(self):
        for pairs,width in (([[True,1]],8),([[-1,0]],8),([[256,1]],8),([],33),([],0)):
            with self.assertRaises(ValueError):affine_hypotheses(pairs,width)


class BitwiseAndSlotTests(unittest.TestCase):
    def test_unique_rotate_xor_fit_does_not_prove_source_mapping(self):
        pairs=[[x,rotate(x,3,8)^91] for x in (0,1,17,143)]
        r=bitwise_hypotheses(pairs,8)
        self.assertEqual(r['models'],[{'rotate_left':3,'xor_key':91}])
        self.assertFalse(r['source_transfer_proved'])

    def test_ambiguous_bit_patterns_remain_ambiguous(self):
        r=bitwise_hypotheses([[0,7]],8)
        self.assertEqual(len(r['models']),8)
        self.assertEqual(r['status'],'UNDERCONSTRAINED')

    def test_xor_inconsistency_and_empty_domain(self):
        self.assertEqual(bitwise_hypotheses([[1,2],[1,3]],8)['status'],'INCONSISTENT')
        self.assertEqual(bitwise_hypotheses([],8)['status'],'UNDERCONSTRAINED')

    def test_rotation_zero_and_bad_inputs(self):
        self.assertEqual(rotate(255,0,8),255)
        for args in ((256,1,8),(1,8,8),(True,0,8)):
            with self.assertRaises(ValueError):rotate(*args)

    def test_call_slot_mapping_is_finite_integer_affine(self):
        r=slot_translation(24,31,2)
        self.assertEqual(r['pairs'],[[24,31],[25,32]])
        self.assertEqual(r['offset'],7)
        self.assertEqual(slot_translation(31,24,2)['offset'],-7)

    def test_no_unknown_defaults_or_modular_slot_wrap(self):
        for args in ((None,1,2),(True,1,2),(99999,0,2),(0,0,1025)):
            with self.assertRaises(ValueError):slot_translation(*args)
        self.assertEqual(slot_translation(0,0,0)['pairs'],[])

    def test_sample_data_immutable(self):
        p=[[1,2],[2,3]];before=deepcopy(p)
        affine_hypotheses(p,8);bitwise_hypotheses(p,8)
        self.assertEqual(p,before)

    def test_mixer_inverse_preserves_all_eight_high_bit_choices(self):
        for masked in (0,1,0x1fffffff,12345678):
            words=mixer_preimages(masked)
            self.assertEqual(len(set(words)),8)
            self.assertEqual([w>>29 for w in words],list(range(8)))
            self.assertTrue(all(((w^((w>>29)&7))&0x1fffffff)==masked for w in words))

    def test_mixer_inverse_rejects_unknown_or_truncated_inputs(self):
        for masked in (True,None,-1,1<<29):
            with self.assertRaises(ValueError):mixer_preimages(masked)


class AuditTests(unittest.TestCase):
    def test_unknown_source_rejected(self):
        with self.assertRaises(ValueError):factory_audit('return "forged index translation"')

    def test_output_alias_guard(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);source=p/'epoch-mapping.json';source.write_text('protected')
            with self.assertRaises(ValueError):run(source,p/'data',p)
            self.assertEqual(source.read_text(),'protected')

    def test_empty_graphs_do_not_supply_bridge(self):
        self.assertEqual(controlled_intersection({'summaries':[]}),[])

    @unittest.skipUnless(Path('output/stage1-vm-data.bin').exists(),'Pinned local artifacts required')
    def test_fresh_pinned_translation_and_all_locks(self):
        with tempfile.TemporaryDirectory() as d:
            r=run(Path('output/stage1-vm-source.lua.txt'),Path('output/stage1-vm-data.bin'),Path(d))
        audit=r['factory_audit']
        self.assertFalse(audit['global_register_permutation_proved'])
        self.assertEqual(audit['index_categories'].get('unclassified_index',0),0)
        self.assertEqual(len(audit['state_assignment_candidates']),8)
        self.assertEqual(audit['mask_mixer']['preimages_per_29bit_output'],8)
        windows=[w for row in r['controlled_intersections'] for w in row['windows'] if 'offset'in w]
        self.assertTrue(windows)
        self.assertEqual(windows[0]['pairs'],[[24,31],[25,32]])
        self.assertTrue(windows[0]['already_represented_as_data_edges'])
        for row in r['controlled_intersections']:
            for query in row['queries']:
                self.assertEqual(query['before']['status'],query['after']['status'])
                self.assertEqual(query['after']['status'],'no_meeting_in_recorded_graph')
        self.assertEqual(r['candidate_solution']['model_count'],2048)
        self.assertEqual(len(r['global_gate_matrix']),19)
        self.assertTrue(all(g['status']=='UNDERCONSTRAINED' for g in r['global_gate_matrix']))
        self.assertEqual(r['numeric_filters_admitted'],[])
        self.assertIsNone(r['verified_hierarchy'])
        self.assertFalse(r['formal_promotion_patch']['applicable'])
        self.assertEqual(r['network_requests']+r['factory_invocations']+r['application_calls_executed'],0)


if __name__=='__main__':unittest.main()
