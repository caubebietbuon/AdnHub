"""Local symbolic paths cannot discharge activation or frame scope by default."""
from pathlib import Path
import tempfile
import unittest

from scope_tracer import bind_captures, localized_trace, run, symbolic_path


def arrays(instructions):
    return {name:[instruction[i] for instruction in instructions] for i,name in enumerate(('B','j','Z','O'))}


class Phase17Tests(unittest.TestCase):
    def test_local_state_reset_and_exact_key(self):
        code=arrays([(139,1,0,7),(132,0,1,0),(125,74,2,0)])
        result=localized_trace(code,3,228,'y',2)
        self.assertEqual(result['paths'][0]['state_at_site'],7)
        self.assertEqual(result['paths'][0]['constant_key'],5)
        self.assertFalse(result['entry_reachability_proved'])

    def test_unknown_instruction_is_barrier(self):
        result=localized_trace(arrays([(93,0,0,0),(125,74,2,0)]),2,228,'V',2)
        self.assertEqual(result['paths'][0]['path'],[2])
        self.assertIsNone(result['paths'][0]['constant_key'])

    def test_impossible_numeric_branch_refuted(self):
        code=arrays([(139,1,0,9),(13,1,3,2),(70,0,0,0),(125,74,2,0)])
        proof=symbolic_path(code,228,[1,2,3,4],'V')
        self.assertEqual(proof['status'],'refuted_numeric_branch')

    def test_incoming_jump_outside_lexical_window(self):
        code=arrays([(32,9,0,0)]+[(999,0,0,0)]*8+[(125,74,2,0)])
        result=localized_trace(code,10,228,'V',2,radius=1)
        self.assertIn([1,10],[row['path'] for row in result['paths']])

    def test_upvalue_forwarding_preserves_cell_identity(self):
        parent=bind_captures(664,[{'kind':3,'target_index':107}])
        child=bind_captures(567,[{'kind':1,'target_index':1}],parent['bindings'])
        self.assertEqual(child['bindings'][0]['cell_identity'],'frame:664:register:107')

    def test_unknown_environment_not_guessed(self):
        result=bind_captures(237,[{'kind':1,'target_index':8}])
        self.assertEqual(result['bindings'][0]['unresolved_enclosing_capture'],8)
        self.assertFalse(result['incoming_scope_known'])

    def test_out_of_bounds_environment_and_invalid_span(self):
        result=bind_captures(237,[{'kind':1,'target_index':2}],[{'cell_identity':'one'}])
        self.assertEqual(len(result['bounds_errors']),1)
        with self.assertRaises(ValueError): bind_captures(1,[{'kind':2,'target_index':1,'span_length':0}])

    def test_budgets_are_enforced(self):
        with self.assertRaises(ValueError): localized_trace(arrays([(70,0,0,0)]),1,228,'V',1,depth=33)

    @unittest.skipUnless(Path('output/stage1-vm-data.bin').exists(),'Pinned artifacts required')
    def test_pinned_local_and_scope_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            report=run(Path('output/stage1-vm-source.lua.txt'),Path('output/stage1-vm-data.bin'),Path(temporary))
        self.assertEqual(len(report['localized_mask_traces']),5)
        self.assertEqual(sum(row['site_equation_matches_snapshot'] for row in report['localized_mask_traces']),1)
        self.assertTrue(all(not row['entry_reachability_proved'] for row in report['localized_mask_traces']))
        self.assertEqual(len(report['upvalue_scope_audit']),8)
        child=next(row for row in report['upvalue_scope_audit'] if row['child']==567)
        self.assertEqual(child['bindings'][0]['cell_identity'],'frame:664:register:107')
        read=next(row for row in child['child_capture_reads'] if row['pc']==23 and row['ordinal']==1)
        self.assertEqual(read['resolved_cell_identity'],'frame:664:register:107')
        self.assertEqual(read['value_at_root_frontier'],0)
        self.assertFalse(read['value_stability_proved_until_child_activation'])
        self.assertFalse(child['lexical_parent_verified'])
        self.assertEqual(len(report['extended_environment_search']),31)
        self.assertTrue(all(row['new_parent_edge'] is None for row in report['extended_environment_search']))
        self.assertIsNone(report['verified_hierarchy'])
        self.assertEqual(report['application_calls_executed'],0)
        self.assertEqual(report['network_requests'],0)


if __name__=='__main__': unittest.main()
