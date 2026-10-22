"""Scoped gate allocation, conditional path rejection and exact bit constraints."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from subgate_resolver import (assertion_cases,capture_plan,guarded_continuation,
    numeric_handoff,parse_open_matrix,run)
from checkpoint_filter import mix
from fused_call_analyzer import mask_word_domain


def binding(pc,child,registers):
    return {'pc':pc,'parent':664,'child':child,'variant':228,
        'capture_bounds':[{'kind':3,'index_range':[r,r+1]} for r in registers],
        'captures':[{'cell_identity':f'frame:664:register:{r}','span':1} for r in registers]}


def arrays(rows):
    size=max(rows)+1
    result={name:[0]*size for name in ('B','j','Z','O')}
    for pc,inst in rows.items():
        for name,value in zip(('B','j','Z','O'),inst): result[name][pc-1]=value
    return result


def call_frame():
    return {'pc':8398,'opcode':93,'callee_register':2,'callee_expression':{'decoder_context_slot':109},
        'argument_range_half_open':[3,5],'requested_results':1,'normal_return_pc':8400,
        'pre_call_copy':{'destination':2,'source':5}}


class Phase27Tests(unittest.TestCase):
    def test_observed_entry_inverse_and_site_domains_are_disjoint(self):
        result=numeric_handoff(421809843,95,4179906283)
        self.assertEqual(result['entry_mask_preimage_count'],8)
        self.assertTrue(all(421809843^mix(v)==95 for v in result['entry_mask_preimages']))
        self.assertEqual(result['unchanged_handoff_intersection'],[])
        self.assertTrue(result['unchanged_handoff_refuted'])
        self.assertEqual(result['remaining_site_candidates'],mask_word_domain(4))
        self.assertEqual(result['site_candidates_pruned'],0)
        self.assertEqual(result['entry_to_site_hamming_bounds'],[9,20])

    def test_required_delta_bits_hold_for_every_candidate(self):
        result=numeric_handoff(421809843,95,4179906283)
        for value in result['remaining_site_candidates']:
            delta=value^result['entry_V']
            self.assertTrue(all(delta&(1<<b) for b in result['required_changed_bits']))
            self.assertTrue(all(not delta&(1<<b) for b in result['required_unchanged_bits']))

    def test_handoff_can_be_consistent_in_a_different_scoped_model(self):
        result=numeric_handoff(4,4,0)
        self.assertFalse(result['unchanged_handoff_refuted'])
        self.assertIn(0,result['unchanged_handoff_intersection'])

    def test_numeric_proof_rejects_mismatch_and_coercion(self):
        for args in ((True,0,0),(0,256,0),(0,-1,0),(4,4,1),(2**29,0,0)):
            with self.assertRaises(ValueError): numeric_handoff(*args)
        with self.assertRaises(ValueError): numeric_handoff(4,4,0,site_operand=2**29)

    def test_capture_reuse_follows_trace_order_not_pc_sort(self):
        bindings=[binding(100,567,[107,106]),binding(20,258,[107,106]),binding(80,663,[159,105])]
        before=deepcopy(bindings)
        result=capture_plan(bindings)
        self.assertEqual([row['action'] for row in result['events']],['create','create','reuse','reuse','create','create'])
        self.assertEqual(result['events'][0]['object'],result['events'][2]['object'])
        self.assertEqual(bindings,before)
        self.assertFalse(result['unconditional_lifetime_proof'])

    def test_capture_plan_rejects_unreviewed_or_ambiguous_metadata(self):
        for change in ('kind','address','span','count','frame'):
            item=binding(100,663,[159])
            if change=='kind': item['capture_bounds'][0]['kind']=1
            elif change=='address': item['captures'][0]['cell_identity']='frame:664:register:105'
            elif change=='span': item['captures'][0]['span']=2
            elif change=='count': item['captures']=[]
            else: item['parent']=663
            with self.assertRaises(ValueError): capture_plan([item])
        with self.assertRaises(ValueError): capture_plan([binding(100,567,[1]),binding(100,663,[2])])

    def test_lua_truthiness_has_no_zero_or_empty_string_false_default(self):
        for value in (0,'',True,7):
            self.assertTrue(assertion_cases(value)['normal']['normal_return_possible_under_binding'])
        for value in (False,{'literal_nil':True}):
            self.assertFalse(assertion_cases(value)['normal']['normal_return_possible_under_binding'])
        self.assertIsNone(assertion_cases({'symbol':'global.debug'})['normal']['normal_return_possible_under_binding'])
        self.assertIsNone(assertion_cases(None)['normal']['normal_return_possible_under_binding'])

    def test_falsey_assertion_case_has_no_projected_normal_path(self):
        result=guarded_continuation(arrays({8400:(31,0,2,71)}),{5:{'decoder_context_slot':109},3:False},call_frame())
        self.assertEqual(result['stop'],'refuted_normal_assertion_case')
        self.assertEqual(result['trace'],[])
        self.assertIsNone(result['last_register_values'])

    def test_continuation_tracks_register_jump_and_preserves_unknown_effects(self):
        stream=arrays({8400:(31,0,2,71),8401:(95,10,66,71),8402:(139,126,0,8404),
                       8403:(89,126,0,0),8405:(82,110,137,58)})
        regs={5:{'decoder_context_slot':109},3:{'symbol':'global.debug'}}
        before=deepcopy(regs)
        result=guarded_continuation(stream,regs,call_frame())
        self.assertEqual([r['pc'] for r in result['trace']],[8400,8401,8402,8403,8405])
        self.assertEqual(result['frontier_pc'],8405)
        self.assertEqual(result['last_register_values'][126],8404)
        self.assertIn('escaping_alias_effects',result['trace'][1])
        self.assertFalse(result['capture_values_preserved'])
        self.assertEqual(regs,before)

    def test_unknown_jump_copy_cycle_and_budget_are_boundaries(self):
        regs={5:{'decoder_context_slot':109},3:{'symbol':'global.debug'}}
        self.assertEqual(guarded_continuation(arrays({8400:(89,99,0,0)}),regs,call_frame())['stop'],'unknown_or_outside_jump')
        self.assertEqual(guarded_continuation(arrays({8400:(31,0,99,1)}),regs,call_frame())['stop'],'unknown_copy_source')
        self.assertEqual(guarded_continuation(arrays({8400:(32,8399,0,0)}),regs,call_frame())['stop'],'cycle_boundary')
        self.assertEqual(guarded_continuation(arrays({8400:(139,1,0,7)}),regs,call_frame(),budget=1)['stop'],'budget')
        with self.assertRaises(ValueError): guarded_continuation(arrays({8400:(139,1,0,7)}),regs,call_frame(),budget=True)
        frame=call_frame();frame['callee_register']=85
        with self.assertRaises(ValueError): guarded_continuation(arrays({8400:(139,1,0,7)}),regs,frame)

    def test_matrix_is_validated_as_inventory_not_executable_proof(self):
        text='| Parent gate | Sub-gate | Status | Required predicate |\n| --- | --- | --- | --- |\n| A | x | open | A/x |'
        self.assertEqual(parse_open_matrix(text),['A/x'])
        for bad in (text+'\n| A | x | open | A/x |',text.replace('A/x','A/y'),text.replace('open','PROVED'), '| A | x | open |'):
            with self.assertRaises(ValueError): parse_open_matrix(bad)

    @unittest.skipUnless(Path('output/stage1-vm-data.bin').exists(),'Pinned local artifacts required')
    def test_pinned_twenty_gates_numeric_delta_and_conditional_continuation(self):
        with tempfile.TemporaryDirectory() as temporary:
            result=run(Path('output/stage1-vm-source.lua.txt'),Path('output/stage1-vm-data.bin'),Path(temporary))
            persisted=json.loads((Path(temporary)/'subgate-resolution.json').read_text())
        self.assertEqual(persisted,json.loads(json.dumps(result)))
        self.assertEqual((result['open_inventory_count'],result['conditionally_resolved_count'],
                          result['remaining_without_conditional_proof'],result['unconditionally_resolved_count']),(20,1,19,0))
        self.assertEqual(result['numeric_handoff']['site_candidate_count'],2048)
        self.assertEqual(result['numeric_handoff']['entry_to_site_hamming_bounds'],[9,20])
        self.assertEqual(result['conditional_continuation']['frontier_pc'],8481)
        self.assertEqual([r['pc'] for r in result['conditional_continuation']['trace']],
                         [8400,8401,8402,8403,9958,8478,8479,8480,8481])
        events=result['capture_plan']['events']
        self.assertEqual(len(events),12)
        self.assertEqual([r['register'] for r in events if r['child']==663],[159,105])
        self.assertTrue(all(r['action']=='create' for r in events if r['child']==663))
        self.assertFalse(any(r['unconditional_proof'] for r in result['subgate_audits']))
        self.assertTrue(all(r['refuted'] for r in result['rejected_models']))
        self.assertEqual(sum(r['status']=='conditionally_proved_in_construction_model' for r in result['subgate_audits']),1)
        self.assertIsNone(result['verified_hierarchy'])
        self.assertEqual(result['formal_promotion_patch'],{'applicable':False,'operations':[]})
        self.assertEqual(sum(result[k] for k in ('network_requests','factory_invocations',
                                               'application_calls_executed','input_byte_edits')),0)


if __name__=='__main__': unittest.main()
