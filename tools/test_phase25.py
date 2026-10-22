"""Exact constraint projection, cross-frame isolation and promotion safety."""
import json
from pathlib import Path
import tempfile
import unittest

from checkpoint_filter import argument_certificate, mix, project_constraints, run
from fused_call_analyzer import mask_word_domain


ROOT = [664,'pc981-entry','state','V']
ARG = [663,'pc547-precall','register','r7']


def checkpoint():
    return {'owner':663,'arithmetic':[{'pc':546,'operation':'subtract','input_register':6,
        'destination':8,'left':871012737,'right':664522614,'result':206490123,
        'register_input_definition':{'pc':545,'value':871012737,'state_word_read':{'word':'y'}},
        'primitive':{'value':664522614,'reference_id':735},
        'result_slice':{'constant':206490123,'owner':663,'unresolved_leaves':[]},
        'normal_completion_guard':'cache and activation'}],
        'parallel_fused_call_boundary':{'pc':547,'opcode':4,'argument_expressions':[206490123],
            'parallel_pre_call_copies':[{}, {'destination':7,'source':8,'value':206490123}]}}


class Phase25Tests(unittest.TestCase):
    def test_certificate_rejects_corrupt_arithmetic_and_wrong_frame(self):
        row = checkpoint()
        self.assertEqual(argument_certificate(row)['value'],206490123)
        row['arithmetic'][0]['result'] += 1
        with self.assertRaises(ValueError): argument_certificate(row)
        row = checkpoint(); row['owner'] = 664
        with self.assertRaises(ValueError): argument_certificate(row)

    def test_certificate_rejects_unresolved_or_different_state_provenance(self):
        for mutate in ('leaves','state','slice_owner'):
            row = checkpoint()
            if mutate == 'leaves': row['arithmetic'][0]['result_slice']['unresolved_leaves'] = [3]
            elif mutate == 'state': row['arithmetic'][0]['register_input_definition']['state_word_read']['word'] = 'V'
            else: row['arithmetic'][0]['result_slice']['owner'] = 664
            with self.assertRaises(ValueError): argument_certificate(row)

    def test_certificate_rejects_wrong_packed_source_version(self):
        row = checkpoint()
        row['parallel_fused_call_boundary']['parallel_pre_call_copies'][1]['source'] = 7
        with self.assertRaises(ValueError): argument_certificate(row)

    def test_exact_matching_identity_prunes_to_one(self):
        result = project_constraints([1,2,3],ROOT,[{'identity':ROOT,'value':2,'guard_satisfied':True}])
        self.assertEqual(result['projected_candidates'],[2])
        self.assertEqual(result['pruned_count'],2)

    def test_guard_not_discharged_never_prunes(self):
        for guard in (None,False,1,'true'):
            result = project_constraints([1,2],ROOT,[{'identity':ROOT,'value':999,'guard_satisfied':guard}])
            self.assertEqual(result['projected_candidates'],[1,2])

    def test_different_frame_pc_or_storage_never_alias(self):
        for identity in (ARG,[663,*ROOT[1:]],[664,'header','state','V'],[664,'pc981-entry','register','V']):
            result = project_constraints([1,2],ROOT,[{'identity':identity,'value':999,'guard_satisfied':True}])
            self.assertEqual(result['projected_candidates'],[1,2])
            self.assertFalse(result['matching_identity_constraint'])

    def test_contradiction_is_scoped_to_explicit_relation(self):
        rows = [{'identity':ARG,'value':v,'guard_satisfied':True} for v in (1,2)]
        result = project_constraints([1,2],ROOT,rows)
        self.assertEqual(result['projected_candidates'],[])
        self.assertEqual(result['inconsistent_equalities'],[ARG])

    def test_repeated_consistent_constraints_and_json_identities(self):
        row = {'identity':tuple(ROOT),'value':2,'guard_satisfied':True}
        result = project_constraints([2,2,3],tuple(ROOT),[row,json.loads(json.dumps(row))])
        self.assertEqual(result['input_count'],2)
        self.assertEqual(result['projected_candidates'],[2])

    def test_reject_coercions_and_invalid_domains(self):
        for value in (-1,2**32,True,1.0,'1'):
            with self.assertRaises(ValueError): mix(value)
            with self.assertRaises(ValueError): project_constraints([value],ROOT,[])
            with self.assertRaises(ValueError):
                project_constraints([1],ROOT,[{'identity':ROOT,'value':value,'guard_satisfied':True}])

    def test_invalid_identity(self):
        for identity in ([],[True,*ROOT[1:]],[0,*ROOT[1:]],[664,'','state','V'],[664,981,'state','V']):
            with self.assertRaises(ValueError): project_constraints([1],identity,[])

    def test_exact_free_bit_domain_matches_inverse(self):
        domain = mask_word_domain(4)
        direct = sorted((high << 29)|low for high in range(8) for low in range(256))
        self.assertEqual(domain,direct)
        self.assertTrue(all(0 <= (mix(value)^4) <= 255 for value in domain))
        self.assertNotIn(206490123,domain)
        self.assertEqual(mix(206490123)^4,206490127)

    def test_all_candidates_survive_unrelated_even_guarded_arithmetic(self):
        domain = mask_word_domain(4)
        result = project_constraints(domain,ROOT,[{'identity':ARG,'value':206490123,'guard_satisfied':True}])
        self.assertEqual(result['projected_candidates'],domain)

    @unittest.skipUnless(Path('output/stage1-vm-data.bin').exists(),'Pinned artifacts required')
    def test_pinned_certificate_projection_and_lifetime_obligations(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = run(Path('output/stage1-vm-source.lua.txt'),Path('output/stage1-vm-data.bin'),Path(temporary))
            self.assertEqual(json.loads((Path(temporary)/'checkpoint-filter.json').read_text()),
                             json.loads(json.dumps(result)))
        self.assertEqual(result['checkpoint_certificate']['value'],206490123)
        self.assertEqual(result['candidate_projection']['projected_count'],2048)
        self.assertEqual(result['conditional_checkpoint_guard_discharged']['projected_count'],2048)
        self.assertEqual(result['candidate_projection']['pruned_count'],0)
        self.assertTrue(result['mixer_domain_proof']['enumeration_verified'])
        counter = result['counterfactual_root_V_equals_argument']
        self.assertEqual(counter['surviving_candidates'],0)
        self.assertFalse(counter['applied_to_actual_domain'])
        ledger = result['closure663_proof_ledger']
        self.assertFalse(ledger['promotion_eligible'])
        self.assertFalse(ledger['coverage_complete'])
        self.assertEqual(ledger['reached_exit_sites'],[])
        self.assertEqual(ledger['reviewed_exit_sites'],[47,431,536])
        self.assertEqual(ledger['conditional_outcome_partition'][0]['continuation'],549)
        self.assertEqual({r['outcome'] for r in ledger['conditional_outcome_partition']},
                         {'normal_return','error','nonreturn'})
        self.assertIsNone(ledger['root_to_663_activation_witness'])
        self.assertIsNone(result['verified_hierarchy'])
        self.assertEqual(result['formal_promotion_patch'],{'applicable':False,'operations':[]})
        self.assertEqual(result['promoted_string_keys'],[])
        self.assertEqual(sum(result[k] for k in ('network_requests','factory_invocations',
                                                'application_calls_executed','input_byte_edits')),0)


if __name__ == '__main__': unittest.main()
