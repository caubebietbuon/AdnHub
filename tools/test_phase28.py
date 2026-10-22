"""Independent finite certificates, DPLL queries and guarded symbolic forks."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from automated_explorer import explore,reduce_conditions
from automated_solver import activation_queries,run
from checkpoint_filter import mix
from finite_solver import evaluate,export_formula,mask_constraints,solve,term
from fused_call_analyzer import mask_word_domain
from gate_solver import query_gate,sat


def constraint(name,expr,guard=True):
    return {'name':name,'expression':expr,'guard_proved':guard,'scope':'synthetic finite test'}


def arrays(rows):
    result={key:[0]*(max(rows)+1) for key in ('B','j','Z','O')}
    for pc,row in rows.items():
        for key,value in zip(('B','j','Z','O'),row): result[key][pc-1]=value
    return result


class FakeMetadata:
    def fork(self): return deepcopy(self)
    def constructor(self,child,descriptor,pc,registers):
        return {'symbolic_closure':child},{'child':child,'captures':[{'cell_identity':'frame:664:register:9'}]}
    def patch(self,reference,key,pc): return True


class FiniteSolverTests(unittest.TestCase):
    def test_actual_domain_and_distance_bounds_are_redundant(self):
        domain=mask_word_domain(4)
        result=solve(domain,mask_constraints(4179906283))
        independent=[v for v in domain if (4^mix(v))<=255 and 9<=(v^4179906283).bit_count()<=20]
        self.assertEqual(result['models'],independent)
        self.assertEqual(result['model_count'],2048)
        self.assertTrue(all(r['entailed_by_domain'] for r in result['proof_steps']))
        self.assertTrue(result['certificate_replayed'])

    def test_heuristic_subset_pruning_has_exhaustive_certificate(self):
        v={'op':'var','name':'V'}
        rule=constraint('low3',term('eq',term('and',v,7),3))
        result=solve(mask_word_domain(4),[rule])
        self.assertEqual(result['model_count'],256)
        self.assertTrue(all(value&7==3 for value in result['models']))
        self.assertEqual(result['proof_steps'][0]['rejected_count'],1792)

    def test_hamming_bounds_are_derived_per_entry_not_assumed_universally(self):
        self.assertEqual(solve(mask_word_domain(4),mask_constraints(0))['model_count'],2048)
        with self.assertRaises(ValueError): mask_constraints(0,[True,20])

    def test_incompatible_constraints_are_unsat_in_finite_model_only(self):
        v={'op':'var','name':'V'}
        result=solve(list(range(8)),[constraint('zero',term('ule',v,0)),constraint('positive',term('uge',v,1))])
        self.assertEqual(result['status'],'UNSAT_IN_FINITE_MODEL')
        self.assertFalse(result['global_reachability_proved'])

    def test_unknown_terms_and_inactive_guards_never_prune(self):
        other={'op':'var','name':'unbound'}
        rules=[constraint('unknown',term('eq',other,0)),constraint('inactive',False,None)]
        self.assertEqual(solve([1,2],rules)['models'],[1,2])
        self.assertEqual(solve([1,2],rules)['status'],'SAT_WITH_RESIDUALS')

    def test_sorts_shifts_unsupported_terms_and_coercion(self):
        self.assertEqual(evaluate(term('lshr',0xffffffff,32),{}),0)
        self.assertEqual(evaluate(term('popcount',0xffffffff),{}),32)
        for expr in (term('xor',True,1),{'op':'eval','args':['exit()']},term('eq',1)):
            with self.assertRaises(ValueError): evaluate(expr,{})
        with self.assertRaises(ValueError): solve([True],[])
        with self.assertRaises(ValueError): solve([0],[constraint('x',True,1)])
        with self.assertRaises(ValueError): solve([0],[constraint('x',True),constraint('x',False)])

    def test_smt_export_is_typed_balanced_and_does_not_invoke_solver(self):
        text=export_formula(mask_constraints(4179906283))
        self.assertEqual(text.count('('),text.count(')'))
        self.assertIn('(set-logic QF_BV)',text)
        self.assertIn('zero_extend 31',text)
        self.assertIn('(check-sat)',text)


class GateSolverTests(unittest.TestCase):
    def test_unit_and_branching_unsat(self):
        self.assertEqual(sat([[1],[-1]])['status'],'UNSAT')
        self.assertEqual(sat([[1,2],[-1,2],[1,-2],[-1,-2]])['status'],'UNSAT')
        result=sat([[1,2]])
        self.assertEqual(result['status'],'SAT')
        self.assertEqual(len(result['model']),1)  # No defaults for unused literals.

    def test_query_distinguishes_known_false_from_missing_evidence(self):
        self.assertEqual(query_gate('goal',['a'],{})['status'],'UNDERCONSTRAINED')
        self.assertEqual(query_gate('goal',['a'],{'a':None})['status'],'UNDERCONSTRAINED')
        self.assertEqual(query_gate('goal',['a'],{'a':False})['status'],'REFUTED_CERTIFICATE')
        self.assertEqual(query_gate('goal',['a'],{'a':True})['status'],'ENTAILED_CERTIFICATE')

    def test_missing_call_metadata_is_not_false_activation_evidence(self):
        paths={'terminal_paths':[{'conditions':[],'trace':[{'pc':7,'call_metadata':{'callee_expression':None}}]}]}
        self.assertEqual(activation_queries(paths)[0]['status'],'UNDERCONSTRAINED')

    def test_budget_unknown_is_not_unsat_and_literals_are_typed(self):
        self.assertEqual(sat([[1,2],[-1,-2]],budget=1)['status'],'UNKNOWN_BUDGET')
        for clauses in ([[0]],[[True]]):
            with self.assertRaises(ValueError): sat(clauses)
        with self.assertRaises(ValueError): query_gate('goal',['a'],{'a':0})


class ExplorerTests(unittest.TestCase):
    def test_boolean_and_typed_interval_conflict_reduction(self):
        self.assertFalse(reduce_conditions([{'kind':'atom','name':'x','truth':True},
                                          {'kind':'atom','name':'x','truth':False}])['satisfiable'])
        self.assertFalse(reduce_conditions([{'kind':'bv_interval','name':'r','lo':7,'hi':10},
                                          {'kind':'bv_interval','name':'r','lo':0,'hi':6}])['satisfiable'])
        self.assertTrue(reduce_conditions([{'kind':'bv_interval','name':'r','lo':0,'hi':10}])['satisfiable'])

    def test_constructor_metadata_and_fresh_capture_havoc(self):
        stream=arrays({1:(82,5,137,58),2:(95,10,7,4),3:(44,5,7,112)})
        regs={4:{'symbol':'object'},9:123}
        result=explore(stream,1,regs,FakeMetadata())
        path=result['terminal_paths'][0]
        self.assertEqual(path['reason'],'opaque_call_boundary')
        self.assertIn('havoc_capture',path['registers'][9])
        self.assertEqual(path['trace'][-1]['call_metadata']['callee_expression']['symbolic_closure'],137)
        self.assertEqual(regs[9],123)

    def test_parallel_sources_use_before_versions(self):
        result=explore(arrays({1:(23,1,2,2),2:(44,2,3,7)}),1,{1:10,2:20},None)
        path=result['terminal_paths'][0]
        self.assertEqual((path['registers'][2],path['registers'][3]),(10,20))

    def test_numeric_branch_reduction_and_unknown_forks(self):
        stream=arrays({1:(172,1,3,5),2:(44,0,0,0),4:(44,0,0,0)})
        known=explore(stream,1,{1:2},None)
        self.assertEqual([p['pc'] for p in known['terminal_paths']],[2])
        unknown=explore(stream,1,{1:{'symbol':'unbound'}},None)
        self.assertEqual({p['pc'] for p in unknown['terminal_paths']},{2,4})
        self.assertFalse(unknown['all_application_paths_covered'])
        self.assertTrue(explore(stream,1,{},None,max_paths=1)['path_budget_exhausted'])

    def test_inconsistent_initial_conditions_are_pruned(self):
        result=explore(arrays({1:(44,0,0,0)}),1,{},None,initial_conditions=[
            {'kind':'atom','name':'x','truth':True},{'kind':'atom','name':'x','truth':False}])
        self.assertEqual(result['terminal_paths'],[])
        self.assertEqual(len(result['refuted_conditions']),1)

    def test_branching_loop_has_a_global_work_budget(self):
        stream=arrays({1:(172,1,0,5)})
        result=explore(stream,1,{},None,max_paths=2,max_steps=8)
        self.assertLessEqual(result['explored_instructions'],16)
        self.assertTrue(result['path_budget_exhausted'])
        self.assertGreater(result['dropped_worklist_branches'],0)

    def test_patch_rewrites_private_code_and_never_mutates_input_arrays(self):
        stream=arrays({1:(100,544,0,83),2:(44,0,0,0)})
        before=deepcopy(stream)
        path=explore(stream,1,{},FakeMetadata())['terminal_paths'][0]
        self.assertEqual(path['trace'][0]['code_rewrite'],{'j':74,'O':144,'Z':178,'B':68})
        self.assertEqual(stream,before)

    def test_unknown_call_jump_budget_and_table_alias_boundaries(self):
        self.assertEqual(explore(arrays({1:(89,1,0,0)}),1,{},None)['terminal_paths'][0]['reason'],'unknown_register_jump')
        path=explore(arrays({1:(149,0,0,3),2:(95,1,4,5),3:(154,1,2,3)}),1,{5:{'symbol':'obj'}},None)['terminal_paths'][0]
        self.assertEqual(path['reason'],'unproved_table_write_target')
        self.assertEqual(explore(arrays({1:(139,1,0,7),2:(139,1,0,8)}),1,{},None,max_steps=1)['terminal_paths'][0]['reason'],'step_budget')
        with self.assertRaises(ValueError): explore(arrays({1:(44,0,0,0)}),1,{},None,max_steps=True)

    @unittest.skipUnless(Path('output/stage1-vm-data.bin').exists(),'Pinned local artifacts required')
    def test_pinned_automated_candidates_six_constructors_and_gate_queries(self):
        with tempfile.TemporaryDirectory() as temporary:
            result=run(Path('output/stage1-vm-source.lua.txt'),Path('output/stage1-vm-data.bin'),Path(temporary))
            persisted=json.loads((Path(temporary)/'automated-analysis.json').read_text())
            self.assertTrue((Path(temporary)/'constraints.smt2').exists())
        self.assertEqual(persisted,json.loads(json.dumps(result)))
        self.assertEqual(result['candidate_solution']['model_count'],2048)
        self.assertTrue(all(p['entailed_by_domain'] for p in result['candidate_solution']['proof_steps']))
        self.assertEqual([p['child'] for p in result['conditional_constructor_observations']],[137,672,544,516,455,728])
        self.assertTrue(all(p['template_evidence']['footer_consumed'] for p in result['conditional_constructor_observations']))
        path=result['symbolic_exploration']['terminal_paths'][0]
        self.assertEqual((path['pc'],path['reason']),(8521,'opaque_call_boundary'))
        self.assertEqual(path['trace'][-1]['call_metadata']['callee_expression']['symbolic_closure'],516)
        self.assertFalse(path['trace'][-1]['call_metadata']['callee_invoked'])
        self.assertEqual(len(result['gate_queries']),19)
        self.assertTrue(all(p['status']=='UNDERCONSTRAINED' for p in result['gate_queries']))
        self.assertEqual(result['activation_candidate_queries'][0]['status'],'REFUTED_CERTIFICATE')
        self.assertEqual(result['activation_candidate_queries'][0]['observed_callee_body'],516)
        self.assertEqual(result['unconditionally_resolved_gates'],[])
        self.assertIsNone(result['verified_hierarchy'])
        self.assertEqual(result['formal_promotion_patch'],{'applicable':False,'operations':[]})
        self.assertEqual(sum(result[k] for k in ('network_requests','factory_invocations',
                                               'application_calls_executed','input_byte_edits')),0)


if __name__=='__main__': unittest.main()
