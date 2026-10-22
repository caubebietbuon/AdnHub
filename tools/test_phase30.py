"""Backward SSA, typed weakest conditions and downstream summary contracts."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from prologue_analyzer import analyze
from upstream_solver import (backward_slice,dependency_graph,extension,lua_truth,
    resume_factory,returned_summary,run,truth_precondition)


def event(pc,variant,opcode,a=0,b=0,c=0,**data):
    return {'pc':pc,'variant':variant,'opcode':opcode,'operand1':a,'H':b,'operand3':c,**data}


def fixture():
    selection={'table_select':{'table':'capture:544:1','entries':[{'key':'table','value':True}],
                              'key':{'builtin_type_of':{'symbol':'global.Instance'}}}}
    frontier={'kind':'return','pc':44,'results':[selection],'guard':'synthetic reviewed path',
        'tables':{'capture:544:1':[],'capture:544:2':[{'key':False,'value':True},{'key':True,'value':False}]}}
    return {'unexplored_worklist':0,'paths':[{'frontier':frontier}],
            'initial_capture_tables':deepcopy(frontier['tables'])}


class ReaderAndTransferTests(unittest.TestCase):
    def test_instruction_window_observes_rewritten_epoch_without_input_mutation(self):
        stream={'O':[57,0,0],'j':[1,0,0],'Z':[87632825,0,0],'B':[1,0,0]}
        before=deepcopy(stream)
        result=analyze(stream,1,1,2,budget=2,instruction_window=2)
        self.assertEqual(stream,before)
        window=result['trace'][1]['instruction_window']
        self.assertEqual(window,{k:v[1:3] for k,v in result['arrays'].items()})
        self.assertNotEqual(window,{k:v[1:3] for k,v in before.items()})

    def test_variant82_is_opt_in_and_never_uses_157_fallback(self):
        stream={'O':[20,0,0],'j':[1,69,0],'Z':[82,0,0],'B':[0,31,0]}
        old=analyze(stream,1,1,2)
        new=analyze(stream,1,1,2,enable_variant82=True,track_register_writes=True)
        self.assertEqual(len(old['trace']),1)
        self.assertEqual(new['trace'][-1]['variant'],82)
        self.assertNotIn('register_writes',new['trace'][-1])
        self.assertEqual(new['pc'],2)

    def test_window_and_dispatch_flags_are_strictly_bounded(self):
        for kwargs in ({'instruction_window':True},{'instruction_window':6},{'enable_variant82':1}):
            with self.assertRaises(ValueError):analyze({},1,1,2,**kwargs)

    def test_literal_and_builtin_type_results_are_truthy_without_guessing_type(self):
        self.assertIs(lua_truth({'string_literal':''}),True)
        self.assertIs(lua_truth({'builtin_type_of':{'symbol':'Instance'}}),True)
        self.assertIsNone(lua_truth({'symbol':'Instance'}))

    def test_numeric_string_order_is_refuted_but_unknown_values_are_not(self):
        frontier={};transfer=extension(258)(None,{}, {},frontier,{})
        e=event(71,228,51,4,1,6)
        self.assertFalse(transfer(228,51,4,1,6,{1:4,4:'slnaf'},e))
        self.assertTrue(frontier['normal_return_refuted_in_guarded_model'])
        frontier.clear()
        self.assertFalse(transfer(228,51,4,1,6,{1:4,4:{'unknown':'value'}},e))
        self.assertNotIn('normal_return_refuted_in_guarded_model',frontier)
        regs={1:4,4:3};self.assertTrue(transfer(228,51,4,1,6,regs,e))
        self.assertIs(regs[6],True)

    def test_fused_literal_copy_reads_second_source_after_first_assignment(self):
        frontier={};transfer=extension(258)(None,{}, {},frontier,{})
        regs={1:99};e=event(1,228,173,0,3,1,instruction_window={'O':[1,6],'Z':[3,1]})
        with patch('upstream_solver.primitive',return_value={'reference':3,'value':4}):
            self.assertEqual(transfer(228,173,0,3,1,regs,e),{'next_pc':3})
        self.assertEqual((regs[1],regs[6]),(4,4))

    def test_unverified_fused_operands_and_oversized_allocations_stop(self):
        frontier={};transfer=extension(258)(None,{}, {},frontier,{})
        self.assertFalse(transfer(228,173,0,3,1,{},event(1,228,173)))
        self.assertEqual(frontier['kind'],'unproved_fused_literal_copy')
        self.assertFalse(transfer(228,113,0,1,10001,{},event(2,228,113)))
        self.assertEqual(frontier['kind'],'allocation_bound')

    def test_helper_scratch_table_is_restored_and_read_is_a_snapshot(self):
        captures={1:{'plain_entries':[]},2:{'plain_entries':[{'key':False,'value':True},{'key':True,'value':False}]}}
        frontier={};transfer=extension(544)(None,captures,{},frontier,{})
        regs={31:{'string_literal':'table'},32:{'builtin_type_of':{'symbol':'Instance'}}}
        with patch('upstream_solver.primitive',return_value={'reference':16,'value':True}):
            self.assertTrue(transfer(163,50,16,1,31,regs,event(17,163,50)))
        self.assertTrue(transfer(163,12,2,32,1,regs,event(18,163,12)))
        self.assertTrue(transfer(163,91,18,31,1,regs,event(19,163,91)))
        self.assertFalse(transfer(82,81,2,0,0,regs,event(44,82,81)))
        self.assertEqual(frontier['tables']['capture:544:1'],[])
        self.assertEqual(frontier['results'][0]['table_select']['entries'],[{'key':'table','value':True}])
        self.assertEqual(captures[1],{'plain_entries':[]})


class BackwardTests(unittest.TestCase):
    def test_weakest_truth_condition_is_typed_and_not_assumed_satisfied(self):
        value=fixture()['paths'][0]['frontier']['results'][0]
        expected={'any':[{'typed_equal':[{'builtin_type_of':{'symbol':'global.Instance'}},'table']}]}
        self.assertEqual(truth_precondition(value),expected)
        self.assertEqual(truth_precondition(value,False),{'not':expected})
        value['table_select']['entries']=[{'key':True,'value':True},{'key':1,'value':True}]
        self.assertEqual(len(truth_precondition(value)['any']),2)
        with self.assertRaises(ValueError):truth_precondition(value,1)

    def test_unknown_entry_is_not_solved_and_duplicate_key_is_rejected(self):
        value=fixture()['paths'][0]['frontier']['results'][0]
        value['table_select']['entries'][0]['value']={'unknown':'truth'}
        self.assertIn('unresolved',truth_precondition(value))
        value['table_select']['entries']=[{'key':1,'value':True}]*2
        with self.assertRaises(ValueError):truth_precondition(value)

    def test_ssa_does_not_connect_equal_constants_in_distinct_frames(self):
        trace=[event(1,157,69,1,7,register_writes=[{'register':1,'value':7}]),
               event(2,82,81,1,upstream_return={'source':1,'results':[7]})]
        g=dependency_graph(544,trace)
        leaves=backward_slice(g,'frame544:return@2')['leaves']
        self.assertNotIn('root664.V@981',leaves)
        self.assertEqual(leaves,['frame544:r1@1:0:0'])

    def test_parallel_copy_uses_before_versions_even_if_source_was_nil(self):
        trace=[event(1,228,23,1,2,2,register_writes=[{'register':2,'value':None},{'register':3,'value':None}]),
               event(2,82,81,3,upstream_return={'source':3,'results':[None]})]
        g=dependency_graph(544,trace)
        self.assertEqual(backward_slice(g,'frame544:return@2')['leaves'],['frame544:initial-nil:r2'])

    def test_fused_graph_tracks_sequential_overlapping_copy(self):
        e=event(1,228,173,0,3,1,register_writes=[{'register':1,'value':4},{'register':6,'value':4}],
                upstream_fused_copy={'second_source':1})
        trace=[e,event(2,82,81,6,upstream_return={'source':6,'results':[4]})]
        g=dependency_graph(258,trace)
        self.assertEqual(backward_slice(g,'frame258:return@2')['leaves'],['constant:3'])

    def test_slice_budget_and_unknown_definitions_fail_closed(self):
        e=event(1,228,777,register_writes=[{'register':1,'value':5}])
        g=dependency_graph(258,[e,event(2,82,81,1,upstream_return={'source':1})])
        self.assertIn('unknown-definition',backward_slice(g,'frame258:return@2')['leaves'][0])
        self.assertTrue(backward_slice(g,'frame258:return@2',budget=1)['budget_exhausted'])
        with self.assertRaises(ValueError):backward_slice(g,'x',True)

    def test_partial_return_or_non_restored_table_cannot_resume_caller(self):
        data=fixture();self.assertIsNotNone(returned_summary(data))
        data['unexplored_worklist']=1;self.assertIsNone(returned_summary(data))
        data=fixture();data['paths'][0]['frontier']['pc']=45;self.assertIsNone(returned_summary(data))
        data=fixture();data['paths'][0]['frontier']['tables']['capture:544:1']=[{'key':1,'value':True}]
        self.assertIsNone(returned_summary(data))
        data=fixture();data['initial_capture_tables']['capture:544:1']=[{'key':'table','value':True}]
        self.assertIsNone(returned_summary(data))

    def test_summary_binding_checks_callee_arguments_and_exact_continuation(self):
        summary=returned_summary(fixture());frontier={}
        transfer=resume_factory(summary)(None,{}, {},frontier,{})
        regs={2:{'symbolic_closure':544},24:{'string_literal':'table'},25:{'builtin_type_of':{'symbol':'global.Instance'}}}
        e=event(162,228,93,instruction_window={'j':[0,1],'O':[23,23],'Z':[2,2]})
        self.assertEqual(transfer(228,93,0,2,23,regs,e),{'next_pc':164})
        self.assertEqual(regs[23],summary['value'])
        regs[25]={'symbol':'unrelated'}
        self.assertFalse(transfer(228,93,0,2,23,regs,e))
        self.assertEqual(frontier['kind'],'summary_binding_mismatch')
        regs[25]={'builtin_type_of':{'symbol':'global.Instance'}}
        e['instruction_window']['j'][1]=2
        self.assertFalse(transfer(228,93,0,2,23,regs,e))

    def test_output_alias_is_rejected_before_read(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);source=root/'upstream-analysis.json';source.write_text('protected')
            with self.assertRaises(ValueError):run(source,root/'data',root)
            self.assertEqual(source.read_text(),'protected')

    @unittest.skipUnless(Path('output/stage1-vm-data.bin').exists(),'Pinned local artifacts required')
    def test_pinned_backward_summaries_and_guarded_path_refutations(self):
        with tempfile.TemporaryDirectory() as d:
            result=run(Path('output/stage1-vm-source.lua.txt'),Path('output/stage1-vm-data.bin'),Path(d))
            saved=json.loads((Path(d)/'upstream-analysis.json').read_text())
        self.assertEqual(saved,json.loads(json.dumps(result)))
        helper,writer=result['summaries']
        self.assertEqual((helper['owner'],writer['owner']),(544,258))
        self.assertTrue(helper['return_proof']['restored_captured_tables'])
        error=writer['analysis']['paths'][0]['frontier']
        self.assertEqual((error['pc'],error['left'],error['right']),(71,4,'slnaf'))
        leaves=writer['backward_graphs'][0]['slices'][0]['leaves']
        self.assertEqual(leaves,['constant:3','constant:45'])
        self.assertEqual({p['pc'] for p in result['caller_path_refutations']},{102,131})
        self.assertEqual(result['backward_normal_return_query']['normal_and_non_table']['status'],'UNSAT')
        self.assertEqual(result['backward_normal_return_query']['normal_and_true']['status'],'SAT')
        self.assertEqual(result['candidate_solution']['model_count'],2048)
        self.assertEqual(result['constraint_propagation']['admitted'],[])
        self.assertEqual(len(result['gate_queries']),19)
        self.assertTrue(all(q['status']=='UNDERCONSTRAINED' for q in result['gate_queries']))
        self.assertIsNone(result['verified_hierarchy'])
        self.assertEqual(result['network_requests']+result['application_calls_executed']+result['factory_invocations'],0)


if __name__=='__main__':unittest.main()
