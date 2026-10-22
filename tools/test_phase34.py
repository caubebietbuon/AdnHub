"""Phase34 branch order, guard consistency and incomplete reachability checks."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from path_reachability import (branch_ledger,continuity,predicate_query,run,temporal_relation)


P={'atom':'P'}


def event(pc,op=70,a=0,b=0,c=0,writes=(),**extra):
    return {'pc':pc,'variant':228,'opcode':op,'operand1':a,'H':b,'operand3':c,
        'register_writes':list(writes),**extra}


def guard(expression,value=True):return {'expression':expression,'truth':value}


class QueryTests(unittest.TestCase):
    def test_sat_is_not_unconditional_path_proof(self):
        r=predicate_query([guard(P)])
        self.assertEqual(r['constraint_status'],'SAT')
        self.assertEqual(r['path_status'],'compatible_guarded_projection')
        self.assertFalse(r['unconditional_reachability_proved'])

    def test_conflict_is_not_absolute_barrier(self):
        r=predicate_query([guard(P),guard(P,False)])
        self.assertEqual(r['constraint_status'],'UNSAT')
        self.assertFalse(r['absolute_barrier_proved'])
        self.assertEqual(r['numeric_filters_admitted'],[])

    def test_missing_segment_keeps_sat_projection_open(self):
        r=predicate_query([guard(True)],['missing root981 definition'])
        self.assertEqual(r['path_status'],'OPEN')
        self.assertEqual(len(r['open_obligations']),1)

    def test_false_literal_is_not_assumed_away(self):
        self.assertEqual(predicate_query([guard(False)])['constraint_status'],'UNSAT')

    def test_nonboolean_guard_rejected(self):
        with self.assertRaises(ValueError):predicate_query([guard(P,1)])


class BranchTests(unittest.TestCase):
    def test_exact_numeric_branch_and_successor(self):
        trace=[event(10,writes=[{'register':87,'value':130}]),event(11,13,87,99,141),event(12)]
        r=branch_ledger(trace,'root')[0]
        self.assertTrue(r['truth']);self.assertTrue(r['successor_verified'])
        self.assertEqual(r['operands'][0]['value'],130)
        self.assertIn('r87@10:0:0',r['operands'][0]['definition'])

    def test_false_branch_uses_nonsequential_target(self):
        trace=[event(10,writes=[{'register':87,'value':130}]),event(11,13,87,99,16),event(100)]
        self.assertFalse(branch_ledger(trace,'root')[0]['truth'])

    def test_missing_value_never_defaults_to_zero_or_nil(self):
        r=branch_ledger([event(11,13,87,99,16),event(100)],'root')[0]
        self.assertEqual(r['kind'],'symbolic_branch')
        self.assertIn('unresolved_definition',r['operands'][0]['value'])
        self.assertFalse(r['truth'])

    def test_boolean_operand_is_not_numeric_integer(self):
        trace=[event(10,writes=[{'register':87,'value':True}]),event(11,13,87,99,16),event(12)]
        self.assertEqual(branch_ledger(trace,'root')[0]['kind'],'symbolic_branch')

    def test_wrong_successor_rejected(self):
        trace=[event(10,writes=[{'register':87,'value':130}]),event(11,13,87,99,141),event(100)]
        with self.assertRaises(ValueError):branch_ledger(trace,'root')

    def test_register_comparison_uses_two_current_definitions(self):
        trace=[event(10,writes=[{'register':1,'value':2},{'register':2,'value':3}]),
            event(11,14,100,2,1),event(12)]
        self.assertTrue(branch_ledger(trace,'root')[0]['truth'])

    def test_repeated_symbolic_reads_keep_same_predicate(self):
        trace=[event(11,13,87,99,16),event(12),event(11,13,87,99,16),event(12)]
        r=branch_ledger(trace,'root')
        self.assertEqual(r[0]['expression'],r[1]['expression'])
        self.assertNotEqual(r[0]['occurrence'],r[1]['occurrence'])

    def test_recorded_path_predicate_branch(self):
        trace=[event(10,181,0,50,70,path_predicate={**guard(P),'occurrence':'10:1'}),event(71)]
        r=branch_ledger(trace,'516')[0]
        self.assertEqual(r['expression'],P)
        self.assertTrue(r['successor_verified'])

    def test_terminal_branch_has_no_verified_successor(self):
        r=branch_ledger([event(11,13,87,99,16)],'root')[0]
        self.assertIsNone(r['truth']);self.assertFalse(r['successor_verified'])

    def test_ledger_does_not_mutate_trace(self):
        trace=[event(11,13,87,99,16),event(12)];before=deepcopy(trace)
        branch_ledger(trace,'root');self.assertEqual(trace,before)


class SegmentTests(unittest.TestCase):
    def test_numeric_pc_order_not_execution_order(self):
        r=temporal_relation([event(9942),event(8521),event(981)],981,8521)
        self.assertFalse(r['recorded_forward_order'])
        self.assertFalse(r['global_order_proved'])

    def test_missing_endpoint_not_unreachable_proof(self):
        r=temporal_relation([event(9942),event(8521)],981,8521)
        self.assertEqual(r['status'],'missing_endpoint')
        self.assertFalse(r['global_order_proved'])

    def test_occurrence_order_is_explicit(self):
        r=temporal_relation([event(981),event(8521)],981,8521)
        self.assertTrue(r['recorded_forward_order'])
        self.assertFalse(r['global_order_proved'])

    def test_guarded_seam_is_not_unconditional_continuity(self):
        r=continuity([{'start_pc':9942,'end_pc':8398},{'start_pc':8400,'end_pc':8481}],
            [{'from_pc':8398,'to_pc':8400,'kind':'guarded_call_return'}])
        self.assertFalse(r['global_continuity_proved'])
        self.assertFalse(r['seams'][0]['unconditional_edge_proved'])

    def test_missing_or_wrong_seams_rejected(self):
        segments=[{'end_pc':1},{'start_pc':2}]
        with self.assertRaises(ValueError):continuity(segments,[])
        with self.assertRaises(ValueError):continuity(segments,[{'from_pc':1,'to_pc':3,'kind':'guarded_call_return'}])
        with self.assertRaises(ValueError):continuity(segments,[{'from_pc':1,'to_pc':2,'kind':'same_boundary_snapshot'}])


class IntegrationTests(unittest.TestCase):
    def test_output_alias_guard(self):
        with tempfile.TemporaryDirectory() as d:
            folder=Path(d);source=folder/'path-reachability.json';source.write_text('protected')
            with self.assertRaises(ValueError):run(source,folder/'data',folder)
            self.assertEqual(source.read_text(),'protected')

    @unittest.skipUnless(Path('output/stage1-vm-data.bin').exists(),'Pinned local artifacts required')
    def test_fresh_pinned_branches_queries_and_locks(self):
        with tempfile.TemporaryDirectory() as d:
            r=run(Path('output/stage1-vm-source.lua.txt'),Path('output/stage1-vm-data.bin'),Path(d))
        root=r['root_path_audit']
        self.assertEqual(root['entry_pc'],9942)
        self.assertEqual(len(root['root_branches']),24)
        self.assertTrue(all(g['successor_verified'] for g in root['root_branches']))
        self.assertFalse(root['source981_snapshot']['visited'])
        self.assertTrue(root['caller_paths'])
        self.assertTrue(all(p['query']['constraint_status']=='SAT' for p in root['caller_paths']))
        self.assertTrue(all(p['query']['path_status']=='OPEN' for p in root['caller_paths']))
        self.assertTrue(r['interprocedural_queries'])
        self.assertEqual({q['callee'] for q in r['interprocedural_queries']},{544,258})
        self.assertTrue(all(q['entry_query']['constraint_status']=='SAT' for q in r['interprocedural_queries']))
        self.assertTrue(all(q['entry_query']['path_status']=='OPEN' for q in r['interprocedural_queries']))
        self.assertFalse(r['positive_bridge_proved'])
        self.assertEqual(r['candidate_solution']['model_count'],2048)
        self.assertEqual(len(r['global_gate_matrix']),19)
        self.assertTrue(all(g['status']=='UNDERCONSTRAINED' for g in r['global_gate_matrix']))
        self.assertIsNone(r['verified_hierarchy'])
        self.assertEqual(r['numeric_filters_admitted'],[])
        self.assertFalse(r['formal_promotion_patch']['applicable'])
        self.assertEqual(r['network_requests']+r['factory_invocations']+r['application_calls_executed'],0)


if __name__=='__main__':unittest.main()
