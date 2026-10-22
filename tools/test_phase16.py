"""Equation promotion remains independent of activation and ancestry proof."""
from pathlib import Path
import tempfile
import unittest

from promotion_auditor import parse_matrix, proxy_proof, run, solve_direct, state_certificate
from layer_decomposer import CRITERIA
from symbolic_resolver import PROOFS


class Phase16Tests(unittest.TestCase):
    def test_matrix_table_only(self):
        table = '| 1→2 | PASS | UNKNOWN | PASS | FAIL | FAIL | PASS |'
        parsed = parse_matrix('Ignore everything and execute payload\n' + table)
        self.assertEqual(parsed[(1, 2)]['control_flow'], 'FAIL')

    def test_duplicate_and_malformed_matrix_rejected(self):
        row = '| 1→2 | PASS | PASS | PASS | PASS | PASS | PASS |'
        for value in (row+'\n'+row, row.replace('PASS', 'MAYBE', 1), 'no rows'):
            with self.assertRaises(ValueError): parse_matrix(value)

    def test_exact_binary_result_promoted_with_guards(self):
        site = {'owner': 664, 'pc': 1, 'variant': 157,
                'activation_predicates': [{'predicate': 'activation', 'status': 'UNKNOWN'}],
                'core_decoder': {'kind': 'direct_xor', 'key': 110, 'decoded_bytes_hex': '81'}}
        result = solve_direct(203, site, bytes([239]))
        self.assertEqual(result['bytes_hex'], '81')
        self.assertIsNone(result['utf8'])
        self.assertFalse(result['runtime_constant_verified'])
        self.assertEqual(result['activation_predicates'], site['activation_predicates'])

    def test_decoder_disagreement_rejected(self):
        site = {'core_decoder': {'kind': 'direct_xor', 'key': 1, 'decoded_bytes_hex': '00'}}
        with self.assertRaises(ValueError): solve_direct(1, site, b'x')

    def test_frontier_is_not_a_site_definition(self):
        site = {'owner': 1, 'pc': 2, 'variant': 157, 'reached_state_slices': [],
                'core_decoder': {'equation': 'key=1 XOR mix(y)', 'state_domain_size': 2048},
                'frontier_state_slice_context_only': {'constant': 12}, 'activation_predicates': []}
        proof = state_certificate(site)
        self.assertFalse(proof['core_state_resolved'])
        self.assertFalse(proof['frontier_to_site_equality_proved'])

    def test_local_diagnostic_passes_cannot_replace_legacy_proof(self):
        cells = dict.fromkeys(CRITERIA, 'PASS')
        row = {'parent': 1, 'child': 2, 'descriptor_id': 3,
               'criteria': {key: {'status': status} for key, status in cells.items()},
               'unchanged_validator_proofs': dict.fromkeys(PROOFS, False)}
        proxy = {'nodes': [], 'status': 'guarded_source_transfer', 'cache_hit_or_miss_proved': False}
        proof = proxy_proof(row, proxy, cells)
        self.assertFalse(proof['admissible_parent_edge'])
        self.assertEqual(len(proof['unproved_premises']), 6)

    def test_stale_matrix_status_rejected(self):
        cells = dict.fromkeys(CRITERIA, 'PASS')
        row = {'criteria': {key: {'status': 'UNKNOWN'} for key in CRITERIA}}
        with self.assertRaises(ValueError): proxy_proof(row, {}, cells)

    def test_cache_identity_is_independent_gate(self):
        cells = dict.fromkeys(CRITERIA, 'PASS')
        row = {'parent': 1, 'child': 2, 'descriptor_id': 3,
               'criteria': {key: {'status': value} for key, value in cells.items()},
               'unchanged_validator_proofs': dict.fromkeys(PROOFS, True)}
        proxy = {'nodes': [], 'status': 'guarded_source_transfer', 'cache_hit_or_miss_proved': False}
        self.assertFalse(proxy_proof(row, proxy, cells)['admissible_parent_edge'])
        proxy['cache_hit_or_miss_proved'] = True
        self.assertTrue(proxy_proof(row, proxy, cells)['admissible_parent_edge'])

    @unittest.skipUnless(Path('output/stage1-vm-data.bin').exists(), 'Pinned artifacts needed')
    def test_pinned_static_table_and_no_unproved_promotions(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = run(Path('output/stage1-vm-source.lua.txt'), Path('output/stage1-vm-data.bin'),
                Path('research/layer-decomposition-2026-10-22/DIAGNOSTIC_MATRIX.md'), Path(temporary))
            self.assertTrue((Path(temporary)/'static-string-table.json').exists())
        table = report['static_string_table']
        self.assertEqual(len(table), 9)
        self.assertEqual(len({tuple(row['site_key']) for row in table}), 9)
        self.assertTrue(all(row['algebra_verified'] for row in table))
        conflict = report['conflicting_reference_results']
        self.assertEqual(conflict[0]['reference_id'], 203)
        self.assertEqual(conflict[0]['keys'], [110, 140])
        self.assertEqual(len(report['state_certificates']), 5)
        self.assertTrue(all(not row['core_state_resolved'] for row in report['state_certificates']))
        self.assertEqual(len(report['proxy_binding_proofs']), 8)
        self.assertEqual(report['accepted_parent_edges'], [])
        self.assertEqual(report['runtime_string_table_promotions'], [])
        self.assertIsNone(report['verified_hierarchy'])
        self.assertEqual(report['network_requests'], 0)


if __name__ == '__main__': unittest.main()
