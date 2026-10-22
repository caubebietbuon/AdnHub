"""Frame isolation, exact Boolean transfer and guarded interprocedural proofs."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from automated_explorer import explore
from finite_solver import term
from gate_solver import query_gate
from interprocedural_solver import (boolean_not,capture_inputs,materialize_heap,
    primitive,propagate,propagate_gates,run,table_read,trace_body,truth)
from test_phase28 import arrays,FakeMetadata


def frame(rows):
    """Mixed dispatch fixture, not Lua source or executable bytecode."""
    result={k:[0]*(max(rows)+1) for k in ('j','O','Z','B')}
    for pc,(variant,op,a,b,c) in rows.items():
        names={157:('O','j','Z','B'),228:('B','j','Z','O')}[variant]
        for name,value in zip(names,(op,a,b,c)):result[name][pc-1]=value
    return result


class TransferTests(unittest.TestCase):
    def test_lua_truthiness_preserves_zero_and_empty_string(self):
        for value in (0,1,'',True):self.assertIs(truth(value),True)
        for value in (False,None):self.assertIs(truth(value),False)
        self.assertIsNone(truth({'symbol':'global.Instance'}))
        self.assertIs(boolean_not(0),False)

    def test_typed_lookup_distinguishes_boolean_from_numeric_key(self):
        table={'plain_entries':[{'key':True,'value':7},{'key':1,'value':8}]}
        self.assertEqual(table_read(table,True)['value'],7)
        self.assertEqual(table_read(table,1)['value'],8)
        self.assertIsNone(table_read(table,False))

    def test_complement_table_has_exact_symbolic_reduction(self):
        table={'plain_entries':[{'key':False,'value':True},{'key':True,'value':False}]}
        symbol={'symbol':'arg2'}
        self.assertEqual(table_read(table,boolean_not(symbol))['value'],{'lua_truth':symbol})
        self.assertIsNone(table_read({'plain_entries':[]},boolean_not(symbol)))

    def test_primitive_uses_effective_offset_and_rejects_masks(self):
        ctx=SimpleNamespace(entries=[{'value':0}],positions={1:4},effects={},backing=b'x'*9)
        row={'status':'explicit_python_primitive_reader','kind':'boolean','value':False}
        with patch('interprocedural_solver.inspect_reference',return_value=row) as reader:
            self.assertIs(primitive(ctx,1)['value'],False)
            self.assertEqual(reader.call_args.args[1],[{'value':4}])
            ctx.effects[1]=3
            self.assertIsNone(primitive(ctx,1))
            self.assertIsNone(primitive(ctx,True))
            self.assertEqual(reader.call_count,1)

    def test_heap_keys_are_materialized_and_alias_collisions_rejected(self):
        heap={'t':{'lazy-key:1':{'lazy-value-reference':2},'lazy-key:2':{'lazy-value-reference':1}}}
        with patch('interprocedural_solver.primitive',side_effect=lambda c,r:{'value':r==2}):
            tables,_=materialize_heap(heap,None)
            self.assertEqual(tables['t']['plain_entries'],[{'key':False,'value':True},{'key':True,'value':False}])
        with patch('interprocedural_solver.primitive',return_value={'value':True}):
            self.assertEqual(materialize_heap(heap,None)[0],{})

    def test_unresolved_heap_never_becomes_empty_proved_table(self):
        with patch('interprocedural_solver.primitive',return_value=None):
            self.assertEqual(materialize_heap({'t':{'lazy-key:1':{'lazy-value-reference':2}}},None)[0],{})

    def test_call_time_capture_is_copied_and_frame_scoped(self):
        callee={'captures':[{'cell_identity':'frame:664:register:95','span':1},
                            {'cell_identity':'frame:777:register:95','span':1}]}
        regs={95:474124151}
        values,proof=capture_inputs(callee,regs,{})
        regs[95]=0
        self.assertEqual(values,{1:474124151})
        self.assertIn('guard',proof[0])

    def test_boundary_observer_receives_isolated_register_heap_metadata_snapshot(self):
        seen=[]
        def observe(state,reason):
            state['registers'][1]=999
            state['heap']['new']={}
            state['metadata'].patch=lambda *args:False
            state['metadata'].constants.entries[0]['value']=999
            seen.append(reason)
        metadata=FakeMetadata()
        metadata.constants=SimpleNamespace(backing=b'x',positions={},effects={},entries=[{'value':0}])
        result=explore(arrays({1:(139,1,0,7),2:(44,1,0,0)}),1,{},metadata,boundary_observer=observe)
        self.assertEqual(result['terminal_paths'][0]['registers'][1],7)
        self.assertTrue(metadata.patch(1,1,1))
        self.assertEqual(metadata.constants.entries,[{'value':0}])
        self.assertEqual(seen,['opaque_call_boundary'])

    def test_repeated_truth_predicate_does_not_fork_incompatible_branch(self):
        stream=frame({1:(157,73,2,0,20),2:(157,20,3,228,0),
            4:(228,96,21,4,0),5:(228,146,1,4,1),6:(228,181,1,9,6),
            7:(228,181,1,11,7),8:(228,150,0,0,0),10:(228,150,0,0,0)})
        captures={1:{'plain_entries':[{'key':False,'value':True},{'key':True,'value':False}]}}
        with patch('interprocedural_solver.arrays_from_candidate',return_value=(stream,(1,2))):
            result=trace_body({'layout':{'entry_pc':{'value':1}}},[12,{'symbol':'arg2'}],captures,None)
        self.assertEqual([p['pc'] for p in result['paths']],[6,8,10])
        self.assertEqual(len(result['paths'][1]['decisions']),1)
        self.assertEqual(result['unexplored_worklist'],0)
        self.assertFalse(result['all_paths_covered'])

    def test_budget_unknown_is_retained_without_false_completeness(self):
        stream=frame({1:(157,73,2,0,20),2:(157,20,3,228,0),
            4:(228,96,21,4,0),5:(228,146,1,4,1),6:(228,181,1,9,6)})
        cap={1:{'plain_entries':[{'key':False,'value':True},{'key':True,'value':False}]}}
        with patch('interprocedural_solver.arrays_from_candidate',return_value=(stream,(1,2))):
            result=trace_body({'layout':{'entry_pc':{'value':1}}},[12,{'symbol':'arg2'}],cap,None,max_paths=1)
        self.assertEqual(result['unexplored_worklist'],2)
        self.assertFalse(result['all_paths_covered'])
        with self.assertRaises(ValueError):trace_body({},[],{},None,budget=True)


class PropagationTests(unittest.TestCase):
    def test_local_number_is_not_caller_V_even_with_identical_value(self):
        result=propagate([1,2],[],[{'name':'arg','value':1,'target':'callee516.argument1'}])
        self.assertEqual(result['solution']['models'],[1,2])
        self.assertEqual(result['admitted'],[])

    def test_only_complete_bridge_certificate_licenses_numeric_constraint(self):
        row={'name':'synthetic-bridge','target':'caller664.V@981',
            'expression':term('eq',{'op':'var','name':'V'},1),
            'bridge_facts':{k:True for k in ('same-activation','reaching-definition','value-flow-relation','complete-effects')}}
        self.assertEqual(propagate([1,2],[],[row])['solution']['models'],[1])
        row['bridge_facts']['complete-effects']=None
        self.assertEqual(propagate([1,2],[],[row])['solution']['models'],[1,2])

    def test_foreign_frame_never_admitted_with_complete_certificate(self):
        row={'name':'foreign','target':'callee516.V','expression':False,
             'bridge_facts':{k:True for k in ('same-activation','reaching-definition','value-flow-relation','complete-effects')}}
        self.assertEqual(propagate([1,2],[],[row])['solution']['model_count'],2)

    def test_local_call_exclusion_is_not_global_activation_refutation(self):
        global_query=query_gate('global663',['actual663-invocation'],{})
        result=propagate_gates([global_query],{'guarded8521.callee-is516':True})
        self.assertEqual(result[0]['status'],'UNDERCONSTRAINED')
        with self.assertRaises(ValueError):propagate_gates([global_query],{'actual663-invocation':False})

    def test_output_file_cannot_alias_input(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);source=root/'interprocedural-analysis.json';source.write_text('protected')
            with self.assertRaises(ValueError):run(source,root/'data',root)
            self.assertEqual(source.read_text(),'protected')

    @unittest.skipUnless(Path('output/stage1-vm-data.bin').exists(),'Pinned local artifacts required')
    def test_pinned_body516_parameters_branch_and_call_targets(self):
        with tempfile.TemporaryDirectory() as d:
            result=run(Path('output/stage1-vm-source.lua.txt'),Path('output/stage1-vm-data.bin'),Path(d))
            saved=json.loads((Path(d)/'interprocedural-analysis.json').read_text())
        self.assertEqual(saved,json.loads(json.dumps(result)))
        call=result['calls'][0]
        self.assertEqual(call['arguments'],[162944256,{'symbol':'global.Instance'}])
        self.assertEqual(call['captures'][2]['call_time_value'],474124151)
        self.assertEqual(call['analysis']['callee_header_words'],[4177667352,1242051610])
        self.assertEqual([p['pc'] for p in call['analysis']['paths']],[49,162,131])
        self.assertEqual([q['observed_body'] for q in result['guarded_call_queries']],[544,258])
        self.assertTrue(all(q['status']=='REFUTED_CERTIFICATE' for q in result['guarded_call_queries']))
        self.assertEqual(result['candidate_solution']['model_count'],2048)
        self.assertEqual(result['constraint_propagation']['admitted'],[])
        self.assertEqual(len(result['gate_queries']),19)
        self.assertTrue(all(q['status']=='UNDERCONSTRAINED' for q in result['gate_queries']))
        self.assertIsNone(result['verified_hierarchy'])
        self.assertEqual(result['application_calls_executed']+result['factory_invocations']+result['network_requests'],0)


if __name__=='__main__':unittest.main()
