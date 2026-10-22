"""Watched normalization revisions, scoped boundary rejection and exit guards."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from boundary_auditor import capture_transfer, exit_contract, run, slot_revisions
from predicate_solver import constrain_boundaries
from prologue_analyzer import analyze
from register_slicer import RegisterSlicer


def fixture():
    # Source-reviewed literal range XOR at1 transforms slot2, then stops on
    # whichever unsupported operation follows. No application call is allowed.
    return {'O':[57,11],'j':[1,74],'Z':[123,7],'B':[1,42]}


class Phase23Tests(unittest.TestCase):
    def test_watch_is_observational_and_tracks_target_only(self):
        streams=fixture()
        plain=analyze(streams,1,1,2,track_register_writes=True)
        watched=analyze(streams,1,1,2,track_register_writes=True,watch_code_slots=(2,))
        self.assertEqual(plain['arrays'],watched['arrays'])
        self.assertEqual(plain['stop'],watched['stop'])
        self.assertEqual(streams,fixture())
        stripped=[{k:v for k,v in e.items() if k!='code_slot_writes'} for e in watched['trace']]
        self.assertEqual(plain['trace'],stripped)
        writes=watched['trace'][0]['code_slot_writes']
        self.assertEqual({w['pc'] for w in writes},{2})
        self.assertTrue(all(w['before']!=w['after'] for w in writes))
        self.assertEqual(json.loads(json.dumps(watched['arrays'])),dict(plain['arrays']))
        metadata_only=analyze(fixture(),1,1,2,watch_code_slots=(2,))
        self.assertEqual(metadata_only['trace'][0]['state_words_before'],[1,2])

    def test_watched_arrays_can_be_reused_without_old_logging(self):
        watched=analyze(fixture(),1,1,2,track_register_writes=True,watch_code_slots=(2,))
        snapshot=deepcopy(watched['trace'])
        replay=analyze(watched['arrays'],1,1,2,budget=2)
        self.assertEqual(watched['trace'],snapshot)
        self.assertTrue(all('code_slot_writes' not in event for event in replay['trace']))

    def test_watch_indices_rejected_before_input_changes(self):
        for slot in (0,3,True):
            streams=fixture()
            with self.assertRaises(ValueError): analyze(streams,1,1,2,watch_code_slots=(slot,))
            self.assertEqual(streams,fixture())
        with self.assertRaises(ValueError): analyze(fixture(),1,1,2,watch_code_slots=(1,True))

    def test_revision_reverse_and_atomic_forward_replay(self):
        streams=fixture()
        watched=analyze(streams,1,1,2,track_register_writes=True,watch_code_slots=(2,))
        anchor={name:values[1] for name,values in streams.items()}
        proof=slot_revisions(watched['arrays'],watched['trace'],2,157,('y',74,7),anchor)
        self.assertTrue(proof['initial']['matches_expected'])
        self.assertFalse(proof['final']['matches_expected'])
        self.assertEqual(len(proof['revisions']),1)
        self.assertEqual(proof['revisions'][0]['source_pc'],1)

    def test_missing_revision_rejected_by_independent_anchor(self):
        streams=fixture()
        watched=analyze(streams,1,1,2,track_register_writes=True,watch_code_slots=(2,))
        anchor={name:values[1] for name,values in streams.items()}
        corrupted=deepcopy(watched['trace'])
        corrupted[0]['code_slot_writes'].pop()
        with self.assertRaises(ValueError): slot_revisions(watched['arrays'],corrupted,2,157,('y',74,7),anchor)

    def test_corrupt_after_value_fails_reverse_check(self):
        streams=fixture()
        watched=analyze(streams,1,1,2,track_register_writes=True,watch_code_slots=(2,))
        anchor={name:values[1] for name,values in streams.items()}
        corrupted=deepcopy(watched['trace'])
        corrupted[0]['code_slot_writes'][0]['after']^=1
        with self.assertRaises(ValueError): slot_revisions(watched['arrays'],corrupted,2,157,('y',74,7),anchor)

    def test_failed_boundary_rejects_model_not_algebraic_domain(self):
        path={'state_at_site':{'input':'V'},'predicates':[]}
        result=constrain_boundaries(path,4,[{'name':'reader','proved':False,'scope':'unchanged backing only'}])
        self.assertEqual(result['local']['state_count_after'],2048)
        self.assertEqual(result['admissible_in_declared_model'],[])
        self.assertFalse(result['global_reachability_proved'])
        self.assertIsNone(result['unconditional_state'])

    def test_unknown_boundary_cannot_select_state(self):
        result=constrain_boundaries({'state_at_site':{'input':'V'}},4,
            [{'name':'epoch','proved':None,'scope':'unvisited cutpoint'}])
        self.assertEqual(len(result['admissible_in_declared_model']),2048)
        self.assertEqual(result['unknown_boundaries'],['epoch'])
        self.assertEqual(result['model_status'],'conditional_model')

    def test_boundary_proofs_require_explicit_type_and_scope(self):
        for row in ({'name':'bad','proved':1,'scope':'x'},{'name':'bad','proved':True}):
            with self.assertRaises(ValueError): constrain_boundaries({'state_at_site':0},4,[row])

    def test_capture_reader_is_symbolic_and_has_correct_ordinal(self):
        registers,event={},{}
        self.assertTrue(capture_transfer(228,75,1,4,0,registers,event))
        self.assertEqual(registers[4],{'enclosing_capture_value':1})
        self.assertFalse(event['capture_cell_read']['value_dereferenced'])
        self.assertFalse(capture_transfer(163,75,1,4,0,registers,{}))
        trace=[{'pc':544,'variant':228,'opcode':75,'operand1':1,'H':4,'operand3':0,
                'state_words_before':[1,2],'register_writes':[{'register':4,'value':registers[4]}]}]
        sliced=RegisterSlicer(663,trace).slice(register=4)
        self.assertIsNone(sliced['constant'])
        self.assertEqual(sliced['nodes'][-1]['ordinal'],1)

    def test_exit_contract_is_a_source_condition_not_exit_witness(self):
        for opcode,kind in ((99,'constant_return'),(102,'tail_call')):
            contract=exit_contract((opcode,1,2,3),228)
            self.assertEqual(contract['handler'],kind)
            self.assertFalse(contract['actual_exit_proved'])
            self.assertTrue(contract['closes_open_cells_before_return_or_tailcall'])
        self.assertIsNone(exit_contract((99,1,2,3),163))
        self.assertIsNone(exit_contract((93,1,2,3),228))

    @unittest.skipUnless(Path('output/stage1-vm-data.bin').exists(),'Pinned data required')
    def test_pinned_revisions_and_extended_capture_frontiers(self):
        with tempfile.TemporaryDirectory() as temporary:
            report=run(Path('output/stage1-vm-source.lua.txt'),Path('output/stage1-vm-data.bin'),Path(temporary))
        equations=report['equations']
        self.assertTrue(all(row['state_count']==2048 for row in equations))
        self.assertTrue(all(row['admissible_declared_model_count']==0 for row in equations))
        expected={(402,83):210,(711,269):16,(593,393):590,(379,686):2106}
        for row in equations:
            if row['owner']==664: continue
            history=row['revision_history']
            self.assertTrue(history['initial']['matches_expected'])
            self.assertFalse(history['final']['matches_expected'])
            self.assertEqual(history['revisions'][0]['source_pc'],expected[(row['owner'],row['pc'])])
            self.assertEqual(row['final_same_reference_patch_sites'],[])
            self.assertEqual(history['observed_visits'],[])
        frames={row['owner']:row for row in report['scope_exits']}
        self.assertEqual(frames[663]['frontier_pc'],546)
        self.assertEqual(frames[379]['frontier_pc'],1852)
        self.assertEqual(frames[663]['capture_reads'][0]['guarded_root_binding'],'frame:664:register:159')
        self.assertEqual([row['guarded_root_binding'] for row in frames[379]['capture_reads']],
                         ['frame:664:register:106','frame:664:register:107'])
        self.assertTrue(all(not frame['scope_exit_lifetime_verified'] for frame in frames.values()))
        self.assertIsNone(report['verified_hierarchy'])
        self.assertFalse(report['formal_promotion_patch']['applicable'])
        self.assertEqual(report['network_requests']+report['factory_invocations']+report['application_calls_executed'],0)


if __name__=='__main__': unittest.main()
