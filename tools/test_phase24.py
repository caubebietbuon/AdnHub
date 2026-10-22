"""Epoch-specific constraints, exact checkpoints and parallel fused-call data."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from checkpoint_aligner import (align_history,checkpoint_factory,checkpoint_transfer,
    parallel_call_summary,primitive_input,run)
from register_slicer import RegisterSlicer


def context(value=7):
    # Ref1/aux255 seed0 -> state123, then plain = cipher XOR255 XOR123.
    return SimpleNamespace(backing=bytes([195,value^255^123]),entries=[{'value':0}],positions={},effects={})


def history(final=None):
    initial={'instruction':[96,141,2,17],'equation':('V',141,2),'matches_expected':True}
    revised={'step':9,'instruction':[54,130,122,74],'equation':None,'matches_expected':False}
    return {'initial':initial,'revisions':[revised],'final':final or revised,'observed_visits':[]}


class Phase24Tests(unittest.TestCase):
    def test_old_domain_is_retired_when_code_epoch_no_longer_matches(self):
        result=align_history(history(),('V',141,2))
        self.assertEqual(result['status'],'retired_initial_pattern')
        self.assertIsNone(result['active_equation'])
        self.assertFalse(result['current_algebraic_domain_applicable'])
        self.assertEqual(result['epochs'][0]['before_next_revision_step'],9)
        self.assertFalse(result['future_reactivation_excluded'])

    def test_current_epoch_and_json_equations_are_supported(self):
        data=history()
        data['final']=data['initial']
        data['revisions']=[]
        data['observed_visits']=[{'step':1,'equation':('V',141,2)}]
        result=align_history(json.loads(json.dumps(data)),('V',141,2))
        self.assertEqual(result['status'],'current_equation_identity')
        self.assertEqual(len(result['historical_matching_visits']),1)
        self.assertFalse(result['runtime_state_proved'])

    def test_later_proven_rewrite_can_restore_a_historical_pattern(self):
        data=history()
        restored={'step':20,**data['initial']}
        data['revisions'].append(restored)
        data['final']=restored
        self.assertTrue(align_history(data,('V',141,2))['current_algebraic_domain_applicable'])

    def test_primitive_read_respects_directory_and_unapplied_masks(self):
        data=context()
        self.assertEqual(primitive_input(data,1)['value'],7)
        data.effects[1]=1
        self.assertIsNone(primitive_input(data,1))
        data.effects.clear()
        data.backing=b'XX'+data.backing
        data.positions[1]=2
        self.assertEqual(primitive_input(data,1)['position'],2)
        data.positions[1]=999
        self.assertIsNone(primitive_input(data,1))

    def test_noninteger_and_invalid_primitive_inputs_stay_unknown(self):
        data=context()
        for ref in (0,2,True): self.assertIsNone(primitive_input(data,ref))
        self.assertIsNone(primitive_input(None,1))
        data.backing=b'\xf4\x00'  # Boolean reader, never a Python integer proof.
        self.assertIsNone(primitive_input(data,1))
        data.backing=b'\xfa\x00'  # Empty string is also not a numeric proof.
        self.assertIsNone(primitive_input(data,1))

    def test_exact_constant_add_and_register_subtract(self):
        registers,event={},{}
        self.assertTrue(checkpoint_transfer(228,97,1,2,3,registers,event,context()))
        self.assertEqual(registers[2],10)
        registers[5]=17
        self.assertTrue(checkpoint_transfer(228,98,5,1,6,registers,{},context()))
        self.assertEqual(registers[6],10)

    def test_reverse_subtract_uses_immediate_minus_register(self):
        registers,event={4:20},{}
        self.assertTrue(checkpoint_transfer(228,140,4,8,0,registers,event))
        self.assertEqual(registers[8],-20)
        self.assertIsNone(event['checkpoint_arithmetic']['primitive'])
        self.assertEqual(event['checkpoint_arithmetic']['input_register'],4)

    def test_backward_slice_derives_subtraction_from_header_word(self):
        trace=[{'pc':545,'variant':228,'opcode':56,'operand1':0,'H':6,'operand3':0,
                'state_words_before':[1,871012737],'register_writes':[{'register':6,'value':871012737}]},
               {'pc':546,'variant':228,'opcode':98,'operand1':6,'H':735,'operand3':8,
                'state_words_before':[1,871012737],
                'checkpoint_arithmetic':{'primitive':{'value':664522614,'reference_id':735}},
                'register_writes':[{'register':8,'value':206490123}]}]
        result=RegisterSlicer(663,trace).slice(register=8)
        self.assertEqual(result['constant'],206490123)
        self.assertEqual(result['nodes'][-1]['op'],'subtract')
        trace[-1]['checkpoint_arithmetic']['primitive']=None
        self.assertIsNone(RegisterSlicer(663,trace).slice(register=8)['constant'])

    def test_unknown_capture_value_does_not_become_a_numeric_default(self):
        registers={4:{'enclosing_capture_value':1}}
        before=deepcopy(registers)
        event={}
        self.assertFalse(checkpoint_transfer(228,98,4,1,6,registers,event,context()))
        self.assertEqual(registers,before)
        self.assertIn('checkpoint_boundary',event)

    def test_inexact_and_boolean_arithmetic_are_rejected(self):
        for value in (-1,True):
            registers={4:value}
            immediate=2**53 if value==-1 else 0
            self.assertFalse(checkpoint_transfer(228,140,4,8,immediate,registers,{}))
            self.assertNotIn(8,registers)

    def test_context_factory_does_not_leak_constants_between_frames(self):
        first,second=checkpoint_factory(context(7)),checkpoint_factory(context(2))
        left,right={},{}
        self.assertTrue(first(228,97,1,2,3,left,{}))
        self.assertTrue(second(228,97,1,2,3,right,{}))
        self.assertEqual((left[2],right[2]),(10,5))

    def test_unreviewed_opcode_does_not_advance(self):
        registers={}
        self.assertFalse(checkpoint_transfer(228,4,1,2,3,registers,{},context()))
        self.assertEqual(registers,{})

    def test_parallel_call_preserves_precopy_source_versions(self):
        arrays={'B':[4,0],'j':[4,2],'Z':[6,1],'O':[6,6]}
        registers={4:{'enclosing_capture_value':1},6:42}
        original=deepcopy(registers)
        result=parallel_call_summary(arrays,1,registers)
        self.assertEqual(result['callee_expression'],registers[4])
        self.assertEqual(result['argument_expressions'],[42])
        self.assertEqual(result['requested_results'],2)
        self.assertEqual(registers,original)
        self.assertIsNone(result['result_values'])
        self.assertFalse(result['callee_invoked'])

    def test_parallel_call_requires_valid_lookahead_and_frame_bounds(self):
        arrays={'B':[4,0],'j':[1,2],'Z':[2,1],'O':[3,3]}
        with self.assertRaises(ValueError): parallel_call_summary(arrays,2,{})
        arrays['Z'][1]=-1
        with self.assertRaises(ValueError): parallel_call_summary(arrays,1,{})
        arrays['Z'][1]=1;arrays['B'][0]=93
        with self.assertRaises(ValueError): parallel_call_summary(arrays,1,{})

    @unittest.skipUnless(Path('output/stage1-vm-data.bin').exists(),'Pinned artifacts required')
    def test_pinned_aligned_domains_arithmetic_and_conditional_call(self):
        with tempfile.TemporaryDirectory() as temporary:
            result=run(Path('output/stage1-vm-source.lua.txt'),Path('output/stage1-vm-data.bin'),Path(temporary))
        models=result['aligned_models']
        self.assertEqual(sum(row['alignment']['current_algebraic_domain_applicable'] for row in models),1)
        self.assertEqual([row['alignment']['status'] for row in models].count('retired_initial_pattern'),4)
        self.assertTrue(all(row['current_mixer_candidate_count'] is None for row in models if row['owner']!=664))
        root=next(row for row in models if row['owner']==664)
        self.assertEqual(root['current_mixer_candidate_count'],2048)
        self.assertEqual(root['current_paths'][0]['constraints']['admissible_in_declared_model'],[])
        frames={row['owner']:row for row in result['checkpoint_proofs']}
        self.assertEqual(frames[663]['arithmetic'][0]['result'],206490123)
        self.assertEqual(frames[663]['arithmetic'][0]['result_slice']['constant'],206490123)
        self.assertEqual(frames[663]['arithmetic'][0]['register_input_definition']['pc'],545)
        self.assertEqual(frames[663]['arithmetic'][0]['register_input_definition']['state_word_read']['word'],'y')
        self.assertEqual([row['result'] for row in frames[379]['arithmetic']],[20,-20,274])
        self.assertEqual((frames[663]['frontier_pc'],frames[379]['frontier_pc'],frames[258]['frontier_pc']),(547,1840,40))
        call=frames[663]['parallel_fused_call_boundary']
        self.assertEqual(call['argument_expressions'],[206490123])
        self.assertEqual(call['requested_results'],2)
        self.assertEqual(next(row for row in result['scope_exits'] if row['owner']==663)['fused_call_boundary']['opcode'],4)
        candidate=result['conditional_activation_candidate']
        self.assertEqual(candidate['body_candidate_at_root_frontier'],379)
        self.assertEqual(candidate['cell_identity'],'frame:664:register:159')
        self.assertFalse(candidate['actual_activation_verified'])
        self.assertFalse(candidate['is_lexical_parent_edge'])
        self.assertIsNone(result['verified_hierarchy'])
        self.assertFalse(result['formal_promotion_patch']['applicable'])
        self.assertEqual(result['network_requests']+result['factory_invocations']+result['application_calls_executed'],0)


if __name__=='__main__': unittest.main()
