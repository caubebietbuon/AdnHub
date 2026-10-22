"""Phase32 inversion, bounded meeting, and fresh pinned integration checks."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from constraint_inverter import inversion_queries, run
from path_domain import equal, negate
from upstream_solver import reaching_meet


P={'atom':'P'}


def certificate():
    return {'coverage_proved':True,'leaf_refutations':[
        {'pc':1,'guards':[{'expression':P,'truth':True,'occurrence':'10:1'}]},
        {'pc':2,'guards':[{'expression':P,'truth':False,'occurrence':'10:1'}]}]}


def edge(a,b,p=True,kind='copy'):
    return {'source':a,'target':b,'kind':kind,'predicate':p}


class InversionTests(unittest.TestCase):
    def test_flip_reaches_other_failure_without_fabricating_return(self):
        r=inversion_queries(certificate())
        self.assertEqual([q['compatible_blocked_leaf_pcs'] for q in r['queries']],[[2],[1]])
        self.assertTrue(all(q['boolean_query']=='SAT' for q in r['queries']))
        self.assertTrue(all(q['avoid_all_certified_failures_under_G']=='UNSAT' for q in r['queries']))
        self.assertFalse(r['positive_bridge_proved'])

    def test_not_G_is_not_sufficient_for_return(self):
        self.assertEqual(inversion_queries(certificate())['not_G_entails_normal_return']['status'],'OPEN')

    def test_uncertified_partition_never_used(self):
        c=certificate();c['coverage_proved']=False
        self.assertEqual(inversion_queries(c)['status'],'UNCERTIFIED')

    def test_coverage_is_rechecked(self):
        c=certificate();c['leaf_refutations'].pop()
        self.assertEqual(inversion_queries(c)['status'],'UNCERTIFIED')

    def test_drop_suffix_when_flipping_branch(self):
        c=certificate();c['leaf_refutations'][0]['guards'].append(
            {'expression':True,'truth':True,'occurrence':'11:1'})
        q=inversion_queries(c)['queries']
        self.assertEqual(len(q[0]['inverted_prefix']),1)
        self.assertEqual(q[1]['boolean_query'],'UNSAT')

    def test_keep_prefix_and_occurrence_identity(self):
        c=certificate()
        for row in c['leaf_refutations']:
            row['guards'].insert(0,{'expression':True,'truth':True,'occurrence':'1:2'})
        q=inversion_queries(c)['queries'][1]
        self.assertEqual(q['inverted_prefix'][0]['occurrence'],'1:2')
        self.assertEqual(q['occurrence'],'10:1')

    def test_nil_false_remain_distinct(self):
        x={'symbol':'M'};c=certificate()
        for row in c['leaf_refutations']:row['guards'][0]['expression']=equal(x,None)
        self.assertEqual(inversion_queries(c)['status'],'reviewed_guarded_partition')
        self.assertNotEqual(equal(x,None),equal(x,False))

    def test_inputs_not_modified(self):
        c=certificate();before=deepcopy(c);inversion_queries(c)
        self.assertEqual(c,before)


class MeetingTests(unittest.TestCase):
    def test_compatible_conditional_path_is_not_positive_proof(self):
        r=reaching_meet(dict.fromkeys('abc'),[edge('a','b',P),edge('b','c',P)],'a','c')
        self.assertEqual(r['status'],'compatible_abstract_path')
        self.assertFalse(r['positive_bridge_proved'])

    def test_opposite_guards_cannot_meet(self):
        r=reaching_meet(dict.fromkeys('abc'),[edge('a','b',P),edge('b','c',negate(P))],'a','c')
        self.assertEqual(r['status'],'no_meeting_in_recorded_graph')
        self.assertFalse(r['global_absence_proved'])

    def test_alternative_paths_not_widened_or_dropped(self):
        edges=[edge('a','b',P),edge('a','b',negate(P)),edge('b','c',negate(P))]
        r=reaching_meet(dict.fromkeys('abc'),edges,'a','c')
        self.assertEqual(r['status'],'compatible_abstract_path')

    def test_control_and_address_edges_not_value_bridges(self):
        for kind in ('control','address'):
            r=reaching_meet(dict.fromkeys('ab'),[edge('a','b',kind=kind)],'a','b')
            self.assertEqual(r['status'],'no_meeting_in_recorded_graph')

    def test_distinct_activation_cells_do_not_alias(self):
        nodes={'frame1:activation1:r1':{},'frame1:activation2:r1':{}}
        r=reaching_meet(nodes,[],*nodes)
        self.assertEqual(r['meetings'],[])

    def test_budget_exhaustion_is_unknown(self):
        r=reaching_meet(dict.fromkeys('abcd'),[edge('a','b'),edge('b','c'),edge('c','d')],'a','d',budget=1)
        self.assertEqual(r['status'],'UNKNOWN')
        self.assertTrue(r['budget_exhausted'])

    def test_dangling_edges_and_bad_budget_rejected(self):
        with self.assertRaises(ValueError):reaching_meet({'a':{}},[edge('a','b')],'a','a')
        with self.assertRaises(ValueError):reaching_meet({'a':{}},[],'a','a',budget=0)

    def test_cycles_are_bounded(self):
        r=reaching_meet(dict.fromkeys('abc'),[edge('a','b'),edge('b','a')],'a','c')
        self.assertFalse(r['budget_exhausted'])
        self.assertEqual(r['status'],'no_meeting_in_recorded_graph')


class IntegrationTests(unittest.TestCase):
    def test_output_alias_guard(self):
        with tempfile.TemporaryDirectory() as d:
            folder=Path(d);source=folder/'constraint-inversion.json';source.write_text('protected')
            with self.assertRaises(ValueError):run(source,folder/'data',folder)
            self.assertEqual(source.read_text(),'protected')

    @unittest.skipUnless(Path('output/stage1-vm-data.bin').exists(),'Pinned local artifacts required')
    def test_fresh_pinned_inversion_meeting_and_candidate_locks(self):
        with tempfile.TemporaryDirectory() as d:
            r=run(Path('output/stage1-vm-source.lua.txt'),Path('output/stage1-vm-data.bin'),Path(d))
            saved=json.loads((Path(d)/'constraint-inversion.json').read_text())
        self.assertEqual(saved,json.loads(json.dumps(r)))
        self.assertTrue(r['inversion_audits'])
        for audit in r['inversion_audits']:
            self.assertEqual(audit['status'],'reviewed_guarded_partition')
            self.assertTrue(all(q['avoid_all_certified_failures_under_G']=='UNSAT' for q in audit['queries']))
        self.assertTrue(r['ssa_transfer_mappings'])
        self.assertTrue(r['body258_operand_provenance'])
        self.assertTrue(r['meeting_audits'])
        for audit in r['meeting_audits']:
            self.assertFalse(audit['root981_observed'])
            self.assertTrue(audit['queries'])
            self.assertTrue(all(q['root981']['status']=='no_meeting_in_recorded_graph' for q in audit['queries']))
        self.assertEqual(r['candidate_solution']['model_count'],2048)
        self.assertEqual(r['numeric_filters_admitted'],[])
        self.assertEqual(len(r['global_gate_matrix']),19)
        self.assertTrue(all(g['status']=='UNDERCONSTRAINED' for g in r['global_gate_matrix']))
        self.assertIsNone(r['verified_hierarchy'])
        self.assertFalse(r['formal_promotion_patch']['applicable'])
        self.assertEqual(r['network_requests']+r['factory_invocations']+r['application_calls_executed'],0)


if __name__=='__main__':unittest.main()
