"""Directory alignments, finite predicate constraints and conjunctive proof gates."""
from pathlib import Path
import tempfile
import unittest

from predicate_solver import affine, constrain, evaluate, path_constraints
from schema_constraint_auditor import (ACTIVATION,LIFETIME,TREE,PROOFS,
    neighborhood,promotion_gate,record_span,run)


def path(state, predicates=()):
    return {'status':'conditional_local_path','state_at_site':state,'predicates':list(predicates)}


def compare(left,right,truth=True,operator='<='):
    return {'left':left,'right':right,'operator':operator,'allowed_truth_values':[truth]}


class Phase22Tests(unittest.TestCase):
    def test_exact_predicates_isolate_a_state_without_activation_claim(self):
        register={'register_input':10}
        result=constrain(path(register,[compare(register,7),compare(register,6,False)]),4)
        self.assertEqual(result['states'],[7])
        self.assertEqual(result['conditional_unique_key'],3)
        self.assertIsNone(result['unconditional_state'])

    def test_affine_register_offset_propagates_predicate_bounds(self):
        register={'register_input':10}
        result=constrain(path({'add':[register,3]},[compare(register,4),compare(register,3,False)]),4)
        self.assertEqual(result['states'],[7])
        self.assertEqual(affine({'add':[register,3]}),('r10',1,3))

    def test_unrelated_guard_cannot_constrain_V(self):
        result=constrain(path({'input':'V'},[compare({'register_input':88},66,operator='<')]),4)
        self.assertEqual(result['state_count_after'],2048)
        self.assertTrue(result['residual_predicates'])

    def test_proven_false_guard_refutes_only_the_local_model(self):
        result=constrain(path({'input':'V'},[compare(7,6)]),4)
        self.assertEqual(result['state_count_after'],0)
        self.assertEqual(result['status'],'refuted_local_path')

    def test_fractional_register_is_not_silently_excluded(self):
        register={'register_input':1}
        result=constrain(path({'add':[register,register]},[compare(register,0)]),4)
        self.assertEqual(result['state_count_after'],2048)
        self.assertIn('non-unit state expression; no inverse-register binding',result['residual_predicates'])

    def test_large_number_cancellation_is_not_exact_arithmetic_proof(self):
        expression={'add':[2**54+1,-2**54]}
        self.assertIsNone(affine(expression))
        self.assertIsNone(evaluate(expression,{}))
        self.assertEqual(constrain(path(expression),4)['state_count_after'],2048)

    def test_inexact_intermediate_cannot_bind_a_register(self):
        register={'register_input':1}
        expression={'add':[{'add':[register,2**53]},-2**53]}
        result=constrain(path(expression,[compare(register,0)]),4)
        self.assertGreater(result['state_count_after'],1)
        self.assertIn('state expression needs exact numeric provenance',result['residual_predicates'])

    def test_local_path_propagates_literal_branch_and_state_assignment(self):
        arrays={'B':[139,172,78,125,70],'j':[10,10,10,74,0],
                'Z':[0,4,0,4,0],'O':[4,5,0,0,0]}
        result=path_constraints(arrays,4,228,'V')
        self.assertEqual(result['paths'][0]['path'],[1,2,3,4])
        constraints=constrain(result['paths'][0],4)
        self.assertEqual(constraints['states'],[4])
        self.assertFalse(result['entry_reachability_proved'])
        arrays['O'][1]=3
        failed=constrain(path_constraints(arrays,4,228,'V')['paths'][0],4)
        self.assertEqual(failed['state_count_after'],0)

    def test_cycle_cut_and_budget_are_explicit(self):
        arrays={'B':[32],'j':[0],'Z':[0],'O':[0]}
        result=path_constraints(arrays,1,228,'V')
        self.assertEqual(result['paths'][0]['cutpoint_reason'],'cycle_cut')
        self.assertFalse(result['all_incoming_edges_known'])
        with self.assertRaises(ValueError): path_constraints(arrays,1,228,'V',depth=0)

    def test_identical_branch_successors_preserve_both_truth_values(self):
        arrays={'B':[172,125],'j':[88,74],'Z':[1,4],'O':[66,0]}
        result=path_constraints(arrays,2,228,'V')
        predicate=result['paths'][0]['predicates'][0]
        self.assertEqual(predicate['allowed_truth_values'],[True,False])

    def test_typed_neighbors_and_cross_record_prefix(self):
        backing=bytes([195,180,219,0])
        result=neighborhood(backing,[{'value':0},{'value':2}],center=0,radius=4)
        self.assertEqual([r['end_exclusive'] for r in result['records']],[2,4])
        self.assertEqual(result['boundaries'][0]['relation'],'exact_adjacency')
        self.assertEqual([r['reference_id'] for r in result['forced_prefix_intersections']],[1,2])
        self.assertIn('descriptor_error',result['records'][1])

    def test_unknown_reader_span_does_not_invent_alignment(self):
        result=record_span(bytes([197,0,0]),[{'value':0}],1)
        self.assertIsNone(result['end_exclusive'])
        with self.assertRaises(ValueError): record_span(b'a',[{'value':0}],0)
        with self.assertRaises(ValueError): record_span(b'a',[{'value':0}],1,True)
        with self.assertRaises(ValueError): neighborhood(b'a',[],radius=0)

    def test_promotion_requires_every_proof_group(self):
        groups=[dict.fromkeys(names,True) for names in (PROOFS,ACTIVATION,LIFETIME,TREE)]
        self.assertTrue(promotion_gate(*groups)['eligible'])
        for group,names in zip(groups,(PROOFS,ACTIVATION,LIFETIME,TREE)):
            name=names[0]
            group[name]=None
            self.assertFalse(promotion_gate(*groups)['eligible'])
            group[name]=True
        groups[1]['reachable_call']=1
        with self.assertRaises(ValueError): promotion_gate(*groups)

    @unittest.skipUnless(Path('output/stage1-vm-data.bin').exists(),'Pinned data required')
    def test_pinned_alignment_constraints_and_no_promotion(self):
        with tempfile.TemporaryDirectory() as temporary:
            result=run(Path('output/stage1-vm-source.lua.txt'),Path('output/stage1-vm-data.bin'),Path(temporary))
        neighborhood_result=result['schema_neighborhood']
        records={r['reference_id']:r for r in neighborhood_result['records']}
        self.assertEqual(records[436]['end_exclusive'],134543)
        self.assertEqual(records[101]['end_exclusive'],134545)
        self.assertEqual(records[101]['observation']['value'],4)
        self.assertEqual(records[251]['end_exclusive'],134562)
        self.assertEqual(records[251]['descriptor']['count'],7)
        self.assertEqual([r['reference_id'] for r in neighborhood_result['forced_prefix_intersections']],[101,251])
        equations=result['state_equation_constraints']
        self.assertEqual(len(equations),5)
        self.assertEqual(sum(r['equation_identity_verified'] for r in equations),1)
        self.assertTrue(all(row['state_count']==2048 for row in equations))
        root=next(r for r in equations if r['owner']==664)
        self.assertEqual(root['paths'][0]['path']['path'],[976,977,978,979,980,981])
        self.assertEqual([p['pc'] for p in root['paths'][0]['path']['predicates'] if p.get('operator')=='<'],[976,979])
        conditions=result['activation_lifetime']['conditions']
        self.assertTrue(all(not row['gate']['eligible'] for row in conditions))
        self.assertTrue(all(row['lifetime']['frame_slot_defined_before_capture'] is True for row in conditions))
        self.assertIsNone(result['verified_hierarchy'])
        self.assertEqual(result['network_requests']+result['factory_invocations']+result['application_calls_executed'],0)


if __name__=='__main__': unittest.main()
