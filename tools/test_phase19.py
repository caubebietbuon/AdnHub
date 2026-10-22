"""Conditional numeric relations and activation/lifetime proof boundaries."""
from pathlib import Path
import tempfile
import unittest

from lineage_auditor import activation_ledger, coupled_masks, directory_step, run


class Phase19Tests(unittest.TestCase):
    def test_coupled_mask_relation_all_uint32_preimages(self):
        proof=coupled_masks(53,4)
        self.assertEqual(proof['xor_delta'],49)
        self.assertEqual(proof['state_domain_count'],2048)
        self.assertEqual(len(proof['key_pairs']),256)
        self.assertTrue(all(first^second==49 for first,second in proof['key_pairs']))
        self.assertFalse(proof['unique_key_proved'])

    def test_non_byte_operands_rejected(self):
        for value in (True,-1,256):
            with self.assertRaises(ValueError): coupled_masks(value,4)

    def test_directory_guard_fails_without_prior_toggle(self):
        proof=directory_step(1,[{'value':134543}],[],152177)
        self.assertEqual(proof['after'],306616023)
        self.assertFalse(proof['bounded_after'])

    def test_prior_directory_history_changes_guard(self):
        proof=directory_step(1,[{'value':134543}],[{'reference_id':1,'directory_after':134543^306486104}],152177)
        self.assertTrue(proof['bounded_after'])
        self.assertEqual(proof['after'],134543)

    def test_creation_is_not_activation(self):
        bindings=[{'child':567,'pc':1,'captures':[{'cell_identity':'frame:664:register:107'}]}]
        trace=[{'pc':1,'register_writes':[{'register':108,'value':{'symbolic_closure':567}}]}]
        proof=activation_ledger(bindings,trace,567)
        self.assertIsNone(proof['activation_witness'])
        self.assertFalse(proof['formal_promotion_patch']['applicable'])
        self.assertEqual(proof['formal_promotion_patch']['operations'],[])

    def test_sibling_alias_is_tracked(self):
        bindings=[{'child':child,'pc':1,'captures':[{'cell_identity':'cell'}]} for child in (567,258,379)]
        proof=activation_ledger(bindings,[],567)
        self.assertEqual(proof['sibling_closures_sharing_cell'],[258,379])
        self.assertFalse(proof['whole_lifetime_stable'])

    @unittest.skipUnless(Path('output/stage1-vm-data.bin').exists(),'Pinned input required')
    def test_pinned_numeric_guard_and_lifetime_results(self):
        with tempfile.TemporaryDirectory() as temporary:
            report=run(Path('output/stage1-vm-source.lua.txt'),Path('output/stage1-vm-data.bin'),Path(temporary))
        numeric=report['numeric_r9_proof']
        self.assertEqual(numeric['recorded_definitions'][0]['pc'],9910)
        self.assertFalse(numeric['numeric_value_proved_at980'])
        state=report['state_V_proof']
        self.assertEqual(state['prefix_slice']['constant'],4179906283)
        self.assertEqual(state['conditional_relation']['xor_delta'],49)
        self.assertFalse(state['frozen_frontier_V_satisfies_byte_key_model'])
        self.assertFalse(state['straight_line_978_path_valid_in_unchanged_directory'])
        self.assertTrue(all(not row['same_reference_sites'] for row in report['rewritten_equation_audit']))
        ledger=report['closure567_activation_lifetime']
        self.assertEqual(ledger['sibling_closures_sharing_cell'],[258,379])
        self.assertFalse(ledger['formal_promotion_patch']['applicable'])
        self.assertIsNone(report['verified_hierarchy'])
        self.assertEqual(report['network_requests'],0)


if __name__=='__main__': unittest.main()
