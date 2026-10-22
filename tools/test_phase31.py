"""Guarded indirect stores, activation scopes, correlated predicates and audits."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from path_domain import Aliases,Predicates,address,equal,heap_address,negate,truth
from path_refiner import META,certify_meta_helper,certify_route,refined_extension,run
from test_phase30 import event


class AliasTests(unittest.TestCase):
    def test_indirect_store_through_copied_pointer_updates_original_cell(self):
        a=Aliases();cell=address('664','entry',107);a.seed(cell,0)
        a.bind('p',[(True,cell)]);a.copy('q','p');a.store('q',17)
        self.assertEqual(a.load('p'),17)

    def test_register_offsets_preserve_source_choice_guards(self):
        a=Aliases();g={'atom':'choose'}
        a.bind('p',[(g,address('516','call1',20)),(negate(g),address('516','call1',30))])
        a.offset('q','p',2)
        self.assertEqual(a.pointers['q'],[(g,address('516','call1',22)),(negate(g),address('516','call1',32))])

    def test_activation_and_frame_numbers_never_alias_by_equal_index(self):
        a=Aliases()
        for frame,activation,value in [('516','a',1),('516','b',2),('664','a',3)]:
            loc=address(frame,activation,107);a.seed(loc,value);a.bind(frame+activation,[(True,loc)])
        a.store('516a',9)
        self.assertEqual((a.load('516b'),a.load('664a')),(2,3))

    def test_heap_pointee_and_register_cell_are_distinct(self):
        a=Aliases();cell=address('664','a',160);slot=heap_address('fresh:8360','a','table')
        a.seed(cell,{'table':'fresh:8360'});a.seed(slot,None)
        a.bind('property',[(True,slot)]);a.store('property',True)
        self.assertEqual(a.cells[cell],{'table':'fresh:8360'})

    def test_boolean_heap_key_is_distinct_from_numeric_one(self):
        self.assertNotEqual(heap_address('t','a',True),heap_address('t','a',1))
        self.assertEqual(heap_address('t','a',1),heap_address('t','a',1.0))

    def test_guarded_store_retains_old_value_in_opposite_branch(self):
        a=Aliases();cell=address('516','a',1);a.seed(cell,7);a.bind('p',[(True,cell)])
        g={'atom':'path'};a.store('p',9,g)
        self.assertEqual(a.load('p'),{'ite':[g,9,7]})

    def test_may_alias_store_never_becomes_a_strong_update(self):
        a=Aliases();x=address('516','a',1);y=address('516','a',2);g={'atom':'choice'}
        a.seed(x,1);a.seed(y,2);a.bind('p',[(g,x),(negate(g),y)]);a.copy('q','p');a.store('q',99)
        self.assertIsInstance(a.cells[x],dict);self.assertIsInstance(a.cells[y],dict)
        self.assertEqual(a.pointers['p'],a.pointers['q'])

    def test_unknown_store_havocs_cells_without_defaulting_to_zero(self):
        a=Aliases();x=address('664','a',107);a.seed(x,0);a.store('unknown',123)
        self.assertIn('unknown_indirect_store',a.cells[x])
        self.assertIn('unknown_indirect_load',a.load('unknown'))

    def test_inactive_unknown_store_does_not_change_memory_or_epoch(self):
        a=Aliases();x=address('664','a',107);a.seed(x,0);a.store('unknown',123,False)
        self.assertEqual(a.cells[x],0);self.assertEqual(a.unknown_epoch,0)

    def test_reads_are_snapshots_and_guarded_joins_keep_correlation(self):
        a=Aliases();cell=address('664','a',1);a.seed(cell,1);a.bind('p',[(True,cell)])
        old=a.load('p');b=a.fork();b.store('p',2)
        rows=Aliases.join([({'atom':'path'},a),(negate({'atom':'path'}),b)])
        self.assertEqual(old,1)
        self.assertEqual([r['memory'].load('p') for r in rows],[1,2])
        rows[0]['memory'].store('p',3);self.assertEqual(a.load('p'),1)

    def test_bounds_fail_closed_and_allocation_hint_is_not_a_register_bound(self):
        self.assertEqual(address('516','a',504247841)[2],504247841)
        with self.assertRaises(ValueError):address('516','a',1,True)
        with self.assertRaises(ValueError):address('516','a',2**53,1)
        with self.assertRaises(ValueError):Aliases().bind('p',[(1,address('516','a',1))])
        with self.assertRaises(ValueError):Aliases.join([(1,Aliases())])
        a=Aliases();a.bind('p',[(True,heap_address('t','a','x'))]);a.offset('q','p',1)
        self.assertIsNone(a.pointers['q'])


class PredicateTests(unittest.TestCase):
    def test_lua_truth_and_typed_numeric_boolean_equality(self):
        self.assertIs(truth(0),True);self.assertIs(truth(''),True)
        self.assertIs(truth(None),False);self.assertIs(equal(1,True),False)
        self.assertIs(equal(1,1.0),True)

    def test_type_table_implies_truth_without_choosing_a_runtime_type(self):
        x={'symbol':'Instance'};p=Predicates();p.assume(equal({'builtin_type_of':x},'table'))
        self.assertIs(p.decide(truth(x))['value'],True)
        self.assertIsNone(Predicates().decide(equal({'builtin_type_of':x},'table'))['value'])

    def test_mutually_exclusive_types_and_boolean_guard_contradictions(self):
        x={'builtin_type_of':{'symbol':'x'}};p=Predicates()
        p.assume(equal(x,'table'));p.assume(equal(x,'number'))
        self.assertEqual(p.check()['status'],'UNSAT')
        p=Predicates();p.assume({'atom':'a'});p.assume({'atom':'a'},False)
        self.assertEqual(p.check()['status'],'UNSAT')

    def test_nil_and_false_metatable_values_are_distinct(self):
        p=Predicates();p.assume(equal(META,False))
        self.assertIs(p.decide(truth(META))['value'],False)
        self.assertIs(p.decide(equal(META,None))['value'],False)
        self.assertEqual(equal(None,META),equal(META,None))

    def test_symbolic_self_equality_does_not_assume_away_nan(self):
        x={'unknown_numeric':'could be NaN'}
        self.assertIsNone(Predicates().decide(equal(x,x))['value'])

    def test_table_select_predicate_and_correlated_repeated_expression(self):
        value={'table_select':{'entries':[{'key':'table','value':True}],'key':{'builtin_type_of':{'symbol':'x'}}}}
        p=Predicates();condition=truth(value);p.assume(condition)
        self.assertIs(p.decide(condition)['value'],True)
        self.assertIs(p.decide(truth({'symbol':'x'}))['value'],True)

    def test_predicate_bounds_and_unknown_operators_are_not_unsat_proofs(self):
        with self.assertRaises(ValueError):Predicates().assume({'execute':'payload'})
        with self.assertRaises(ValueError):Predicates().assume(True,1)
        with self.assertRaises(ValueError):Predicates().encode({'all':[True]*65})


class RefinementTests(unittest.TestCase):
    def test_fresh_register_nil_comparison_does_not_use_allocation_bounds(self):
        frontier={};callback=refined_extension(516)(None,{}, {},frontier,{})
        self.assertFalse(callback(228,123,1,504247841,2,{},event(30,228,123)))
        self.assertEqual(frontier['comparison'],'2 < nil')
        frontier.clear()
        self.assertFalse(callback(228,123,1,504247841,2,{504247841:{'unknown':'external write'}},event(30,228,123)))
        self.assertEqual(frontier['kind'],'unproved_register_order')

    def test_unknown_table_equality_is_not_treated_as_pure_nil_equality(self):
        frontier={};callback=refined_extension(544)(None,{}, {},frontier,{})
        self.assertFalse(callback(163,97,1,31,27,{31:{'table':'a'},27:{'table':'b'}},event(133,163,97)))
        self.assertEqual(frontier['kind'],'possible_equality_metamethod')

    def test_partial_or_mismatching_helper_partition_is_not_certified(self):
        self.assertFalse(certify_meta_helper({'unexplored_worklist':1,'paths':[]})['coverage_proved'])
        self.assertFalse(certify_meta_helper({'unexplored_worklist':0,'paths':[]})['coverage_proved'])
        p={'unexplored_worklist':0,'paths':[{'branch_frontier':{},'frontier':{'kind':'opaque_call'},'trace':[]}]}
        self.assertFalse(certify_meta_helper(p)['coverage_proved'])
        self.assertFalse(certify_route(p,True)['coverage_proved'])

    def test_output_alias_protection(self):
        with tempfile.TemporaryDirectory() as d:
            folder=Path(d);source=folder/'path-refinement.json';source.write_text('protected')
            with self.assertRaises(ValueError):run(source,folder/'data',folder)
            self.assertEqual(source.read_text(),'protected')

    @unittest.skipUnless(Path('output/stage1-vm-data.bin').exists(),'Pinned local artifacts required')
    def test_pinned_aliases_predicate_partition_and_scoped_negative_route(self):
        with tempfile.TemporaryDirectory() as d:
            r=run(Path('output/stage1-vm-source.lua.txt'),Path('output/stage1-vm-data.bin'),Path(d))
            saved=json.loads((Path(d)/'path-refinement.json').read_text())
        self.assertEqual(saved,json.loads(json.dumps(r)))
        audit=r['aliases'][0]
        self.assertEqual(len(audit['shared_root107_pointers']),2)
        self.assertIn('havoc_capture',audit['root107_value'])
        self.assertIn('havoc_capture',audit['root159_current_value'])
        self.assertTrue(audit['register160_unchanged'])
        self.assertIs(audit['scratch_after_cleanup'],None)
        proof=r['metatable_call_analyses'][0]['return_certificate']
        self.assertTrue(proof['coverage_proved'])
        self.assertEqual([(p['pc'],p['result']) for p in proof['leaf_proofs']],[(93,False),(96,True),(127,False)])
        route=r['guarded_route_certificates'][0]
        self.assertTrue(route['coverage_proved'])
        self.assertEqual({p['pc'] for p in route['leaf_refutations']},{131,102,213,30})
        self.assertFalse(route['global_V_constraints_admitted'])
        self.assertEqual(r['candidate_solution']['model_count'],2048)
        self.assertTrue(all(p['entailed_by_domain'] for p in r['candidate_solution']['proof_steps']))
        self.assertEqual(len(r['gate_queries']),19)
        self.assertTrue(all(g['status']=='UNDERCONSTRAINED' for g in r['gate_queries']))
        self.assertIsNone(r['verified_hierarchy'])
        self.assertFalse(r['formal_promotion_patch']['applicable'])
        self.assertEqual(r['network_requests']+r['application_calls_executed']+r['factory_invocations'],0)


if __name__=='__main__':unittest.main()
