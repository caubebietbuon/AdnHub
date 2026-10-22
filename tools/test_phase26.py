"""Typed provenance paths, guarded equality, call-source versions and gates."""
import json
from pathlib import Path
import tempfile
import unittest

from provenance_bridge import EvidenceGraph, filter_through_bridge, snapshot_call_sites, run
from fused_call_analyzer import mask_word_domain


def graph():
    g = EvidenceGraph()
    for name in ('V','copy','argument','arithmetic','control','cell'): g.node(name)
    return g


class Phase26Tests(unittest.TestCase):
    def test_copy_path_can_filter_only_with_all_guards(self):
        g = graph()
        g.edge('V','copy','copy',['path'])
        g.edge('copy','argument','copy',['cache'])
        for guards in ((),('path',),('path','cache')):
            result = filter_through_bridge(g,'V','argument',7,range(10),['active'],guards)
            self.assertFalse(result['filter_applied'])
            self.assertEqual(result['remaining_count'],10)
        result = filter_through_bridge(g,'V','argument',7,range(10),['active'],['path','cache','active'])
        self.assertTrue(result['filter_applied'])
        self.assertEqual(result['remaining_candidates'],[7])

    def test_arithmetic_control_and_address_paths_never_imply_equality(self):
        for kind in ('data','control','payload','address'):
            g = graph()
            g.edge('V','argument',kind)
            self.assertFalse(g.path('V','argument',{kind})['numeric_equality'])
            result = filter_through_bridge(g,'V','argument',7,range(10),[])
            self.assertFalse(result['filter_applied'])

    def test_guarded_shortcut_does_not_hide_unguarded_proof(self):
        g = graph()
        g.edge('V','argument','copy',['unknown'])
        g.edge('V','copy','copy')
        g.edge('copy','argument','copy')
        result = g.path('V','argument',{'copy'})
        self.assertEqual(len(result['edge_indices']),2)
        self.assertEqual(result['status'],'path_with_discharged_guards')

    def test_cycles_are_bounded_and_directions_not_reversed(self):
        g = graph()
        g.edge('V','copy','copy'); g.edge('copy','V','copy')
        self.assertEqual(g.path('V','argument',{'copy'})['status'],'no_path_in_recorded_graph')
        g.edge('argument','V','copy')
        self.assertEqual(g.path('V','argument',{'copy'})['status'],'no_path_in_recorded_graph')
        result = g.path('V','argument',{'copy'},budget=1)
        self.assertEqual(result['status'],'budget_exhausted')
        self.assertFalse(result['global_absence_proved'])

    def test_conditional_route_preserves_each_unmet_guard(self):
        g = graph(); g.edge('V','copy','data',['A']); g.edge('copy','argument','control',['B'])
        result = g.path('V','argument',{'data','control'},conditional=True,discharged=['A'])
        self.assertEqual(result['status'],'conditional_path')
        self.assertEqual(result['unmet_guards'],['B'])
        self.assertFalse(result['numeric_equality'])

    def test_conditional_copy_is_not_an_unconditional_equality(self):
        g = graph(); g.edge('V','argument','copy',['unproved'])
        result = g.path('V','argument',{'copy'},conditional=True)
        self.assertTrue(result['copy_only_relation'])
        self.assertFalse(result['numeric_equality'])

    def test_different_frame_storage_names_do_not_alias(self):
        g = EvidenceGraph(); g.node('664:V'); g.node('663:V')
        self.assertEqual(g.path('664:V','663:V',{'copy'})['edge_indices'],[])

    def test_invalid_graph_and_query_inputs(self):
        g = graph()
        with self.assertRaises(ValueError): g.node('V')
        with self.assertRaises(ValueError): g.node(7)
        with self.assertRaises(ValueError): g.edge('missing','V','copy')
        with self.assertRaises(ValueError): g.edge('V','copy','invocation')
        with self.assertRaises(ValueError): g.edge('V','copy','copy','guard')
        for budget in (True,0,100001):
            with self.assertRaises(ValueError): g.path('V','copy',{'copy'},budget=budget)
        with self.assertRaises(ValueError): g.path('V','copy','copy')
        with self.assertRaises(ValueError): g.path('V','copy',{'copy'},discharged='guard')

    def test_filter_rejects_coercion_and_observation_guard_string(self):
        g = graph()
        for value in (True,1.0,-1,2**32):
            with self.assertRaises(ValueError): filter_through_bridge(g,'V','argument',value,[1],[])
        with self.assertRaises(ValueError): filter_through_bridge(g,'V','argument',1,[1],'active')

    def test_parallel_call_search_uses_old_source_register(self):
        # Callee slot6 gets old r85, while new slot7 gets old r8.
        arrays={'B':[4,0],'j':[85,2],'Z':[8,1],'O':[6,6]}
        result = snapshot_call_sites(arrays,85)
        self.assertEqual(len(result),1)
        self.assertEqual(result[0]['callee_register'],6)
        self.assertEqual(result[0]['callee_source_before_instruction'],85)
        self.assertEqual(result[0]['requested_results'],2)
        self.assertFalse(result[0]['reaching_definition_proved'])

    def test_single_copy_can_kill_apparent_callee_register(self):
        arrays={'B':[93,0],'j':[0,2],'Z':[9,1],'O':[85,85]}
        self.assertEqual(snapshot_call_sites(arrays,85),[])
        self.assertEqual(snapshot_call_sites(arrays,9)[0]['callee_register'],85)

    def test_parallel_second_copy_can_be_callee_and_lookahead_is_required(self):
        arrays={'B':[4,0],'j':[3,2],'Z':[85,1],'O':[6,7]}
        self.assertEqual(snapshot_call_sites(arrays,85)[0]['callee_register'],7)
        self.assertEqual(snapshot_call_sites({k:v[:1] for k,v in arrays.items()},85),[])
        arrays['j'][1]=-1
        self.assertEqual(snapshot_call_sites(arrays,85),[])
        with self.assertRaises(ValueError): snapshot_call_sites(arrays,True)

    @unittest.skipUnless(Path('output/stage1-vm-data.bin').exists(),'Pinned local artifacts required')
    def test_pinned_bridges_cached_header_and_independent_subgates(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = run(Path('output/stage1-vm-source.lua.txt'),Path('output/stage1-vm-data.bin'),Path(temporary))
            persisted = json.loads((Path(temporary)/'provenance-bridge.json').read_text())
        self.assertEqual(persisted,json.loads(json.dumps(result)))
        queries = result['path_queries']
        self.assertEqual(queries['root_site_to_argument_data']['status'],'no_path_in_recorded_graph')
        self.assertEqual(queries['root_entry_to_argument_mixed']['status'],'conditional_path')
        self.assertFalse(queries['root_entry_to_argument_mixed']['numeric_equality'])
        self.assertFalse(queries['checkpoint_y_to_argument']['numeric_equality'])
        self.assertEqual(result['candidate_filter']['remaining_candidates'],mask_word_domain(4))
        self.assertFalse(result['candidate_filter']['filter_applied'])
        template = result['cached_template_audit']
        self.assertTrue(template['cached_and_checkpoint_plain_hash_match'])
        self.assertTrue(template['header_words_match'])
        self.assertTrue(template['entry_pc_matches'])
        self.assertFalse(template['backing_reread_matches_after_cleanup'])
        self.assertTrue(template['cleanup_applied_after_template_read'])
        self.assertEqual(template['mask'],227)
        self.assertEqual(template['mask_instruction']['opcode'],100)
        self.assertEqual(set(result['discharged_local_guards']),
                         {'cached-header-matches:663','template-read-before-fill:663'})
        audit = result['closure663_subgates']
        self.assertEqual((len(audit['gates']),audit['subgate_count']),(18,36))
        self.assertEqual(audit['locally_established_count'],16)
        self.assertEqual(audit['register_contexts']['incoming_call_snapshot_candidates'],[])
        self.assertEqual(audit['discharged_parent_gates'],[])
        self.assertFalse(any(row['discharged'] for row in audit['gates']))
        lineage = {row['register']:row for row in audit['capture_register_lineage']}
        self.assertEqual(lineage[105]['definition_before_construction']['constant'],10054)
        self.assertEqual(lineage[159]['definition_before_construction']['nodes'][-1]['child'],379)
        self.assertTrue(all(not row['later_direct_prefix_writes'] for row in lineage.values()))
        args = audit['register_contexts']['incoming663_arguments']
        self.assertEqual([r['nodes'][-1]['ordinal'] for r in args],[1,2,3])
        self.assertIsNone(audit['incoming663_call_witness'])
        self.assertIsNone(result['verified_hierarchy'])
        self.assertEqual(result['formal_promotion_patch'],{'applicable':False,'operations':[]})
        self.assertEqual(sum(result[k] for k in ('network_requests','factory_invocations',
                                               'application_calls_executed','input_byte_edits')),0)


if __name__=='__main__': unittest.main()
