"""Inter-block provenance, local guard satisfiability and alias proof limits."""
from pathlib import Path
import tempfile
import unittest

from interblock_auditor import (cluster_audit, interblock_slice, local_guard_models,
                               payload_guard, recorded_blocks, run, snapshot_lineage, transfer)
from prologue_analyzer import mix


def event(pc,op,a,b,c,writes=(),variant=163):
    return {'pc':pc,'variant':variant,'opcode':op,'operand1':a,'H':b,'operand3':c,
            'state_words_before':[1,2],
            'register_writes':[{'register':r,'value':v} for r,v in writes]}


def arrays(instructions):
    return dict(zip(('j','B','Z','O'),map(list,zip(*instructions))))


class Phase20Tests(unittest.TestCase):
    def test_recorded_block_edges_preserve_order_and_repeated_pc(self):
        trace=[event(40,62,7,0,35,[(35,7)]),event(41,24,0,9,0),
               event(10,109,30,35,8,[(8,None),(9,7)]),event(40,62,8,0,35,[(35,8)])]
        graph=recorded_blocks(trace)
        self.assertEqual(graph['step_to_block'],[0,0,1,2])
        self.assertEqual(graph['edges'][0]['to_pc'],10)
        self.assertFalse(graph['complete_cfg'])

    def test_cross_block_backward_copy_finds_literal(self):
        trace=[event(40,62,7,0,35,[(35,7)]),event(10,109,30,35,8,[(8,None),(9,7)])]
        report=interblock_slice(trace,9)
        self.assertEqual(report['slice']['constant'],7)
        self.assertTrue(report['slice']['cross_block_dependencies'])
        self.assertFalse(report['at_unvisited980_proved'])

    def test_absent_input_is_not_numeric_zero(self):
        report=interblock_slice([event(9910,109,30,35,8,[(8,None),(9,None)])],9)
        self.assertIsNone(report['slice']['constant'])
        self.assertEqual(report['slice']['nodes'][0]['register'],35)
        self.assertEqual(report['slice']['nodes'][0]['op'],'absent_frame_entry')

    def test_parallel_copy_uses_predecessor_register(self):
        self.assertEqual(transfer((109,8,9,9),163,10),{'source_register':9})
        self.assertEqual(transfer((109,8,9,9),163,9),{'source_register':8})
        self.assertEqual(transfer((999,1,2,3),163,9)['terminal'],'unreviewed_transfer')
        for variant,op in ((157,140),(163,30),(228,70)):
            self.assertEqual(transfer((op,0,0,0),variant,35),{'source_register':35})

    def test_snapshot_interblock_backward_jump_and_copy(self):
        stream=arrays([(62,42,0,35),(24,0,3,0),(999,0,0,0),
                       (109,30,35,8),(24,0,0,0)])
        report=snapshot_lineage(stream,5,9,163)
        self.assertTrue(any(row.get('value')==42 for row in report['terminals']))
        self.assertTrue(any(edge['before_pc']==4 and edge['predecessor_pc']==2 for edge in report['edges']))
        self.assertFalse(report['entry_reachability_proved'])
        self.assertFalse(report['all_incoming_edges_known'])

    def test_snapshot_cycle_and_budget_terminate(self):
        report=snapshot_lineage(arrays([(24,0,1,0),(24,0,0,0)]),1,9,163,1)
        self.assertTrue(report['budget_exhausted'])
        report=snapshot_lineage(arrays([(24,0,1,0),(24,0,0,0)]),1,9,163,4)
        self.assertEqual(report['visited_states'],2)
        self.assertFalse(report['budget_exhausted'])
        with self.assertRaises(ValueError): snapshot_lineage(arrays([(24,0,0,0)]),1,9,163,0)

    def test_branch_predecessor_predicate_is_not_discarded(self):
        # variant228 layout: opcode B, operand1 j, H Z, operand3 O
        stream={'B':[172,139,139],'j':[88,1,1],'Z':[2,0,0],'O':[66,0,0]}
        proof=snapshot_lineage(stream,2,9,228)
        predicate=proof['edges'][0]['predicate']
        self.assertEqual(predicate,{'register':88,'numeric_required':True,'operator':'<','constant':66})

    def test_unknown_write_kills_prior_numeric_definition(self):
        trace=[event(1,62,42,0,9,[(9,42)]),event(10,999,0,0,0,[(9,{'unknown':True})])]
        proof=interblock_slice(trace,9)
        self.assertIsNone(proof['slice']['constant'])
        self.assertEqual(proof['slice']['nodes'][-1]['op'],'opaque_write')

    def test_payload_length_guard_stronger_than_offset_bound(self):
        report=payload_guard(bytes([0,200]),0)
        self.assertFalse(report['bounded_length_payload'])
        self.assertFalse(payload_guard(b'abc',-1)['bounded_length_payload'])

    def test_local_witnesses_do_not_promote_reachability(self):
        # custom_uint single-byte length 3, followed by exactly three bytes.
        report=local_guard_models(bytes([0,3,65,66,67]),0,0)
        self.assertEqual(report['payload_guard']['payload_length'],3)
        self.assertEqual(len(report['local_models']),2)
        self.assertFalse(report['current_directory_matches'])
        self.assertFalse(report['actual_path_proved'])
        for model in report['local_models']:
            self.assertLess(model['r88'],66)
            self.assertEqual(model['r13'],model['r9']^38)
            self.assertEqual(model['key101'],53^mix(model['V']))
            self.assertEqual(model['key74']^model['key101'],49)
            self.assertTrue(0<=model['key101']<=255)
            self.assertEqual(model['directory101_before']^306486104,0)
        self.assertEqual(local_guard_models(bytes([0,200]),0,0)['local_models'],[])
        self.assertEqual(len(local_guard_models(bytes([0,200]),0,0)['numeric_models']),2)

    def test_cluster_shared_cell_stability_and_body_alias(self):
        cell='frame:664:register:107'
        bindings=[{'child':child,'pc':i+2,'captures':[{'cell_identity':cell}]} for i,child in enumerate((567,258,379))]
        trace=[event(1,62,0,0,107,[(107,0)])]+[
            event(i+2,0,0,0,0,[(108+i,{'symbolic_closure':child})]) for i,child in enumerate((567,258,379))]
        constraints=[{'child':663,'captures':[{'capture_ordinal':1,'cell_identity':'frame:664:register:110',
                                              'frontier_value':{'symbolic_closure':379}}]}]
        report=cluster_audit(bindings,constraints,trace,[])
        self.assertTrue(report['identity_shared'])
        self.assertTrue(all(row['direct_prefix_stability'] for row in report['members']))
        self.assertEqual(report['members'][2]['body_aliases_in_other_closures'][0]['holder_child'],663)
        self.assertIsNone(report['members'][2]['whole_lifetime_stable'])
        trace.append(event(6,62,1,0,107,[(107,1)]))
        self.assertFalse(cluster_audit(bindings,constraints,trace,[])['members'][0]['direct_prefix_stability'])
        self.assertEqual(report['formal_promotion_patch']['operations'],[])

    @unittest.skipUnless(Path('output/stage1-vm-data.bin').exists(),'Pinned input required')
    def test_pinned_interblock_and_cluster_results(self):
        with tempfile.TemporaryDirectory() as temporary:
            report=run(Path('output/stage1-vm-source.lua.txt'),Path('output/stage1-vm-data.bin'),Path(temporary))
        leaves=report['recorded_r35_before9910']['slice']['nodes']
        self.assertEqual(leaves[0]['op'],'absent_frame_entry')
        self.assertEqual(leaves[0]['register'],35)
        guard=report['guard978']
        self.assertFalse(guard['directory']['bounded_after'])
        self.assertFalse(guard['local_constraints']['payload_guard']['bounded_length_payload'])
        self.assertEqual(guard['local_constraints']['local_models'],[])
        rows=report['root107_cluster']['members']
        self.assertEqual([r['child'] for r in rows],[567,258,379])
        self.assertTrue(all(r['direct_prefix_stability'] for r in rows))
        self.assertEqual(rows[2]['body_aliases_in_other_closures'][0]['holder_child'],663)
        self.assertTrue(rows[0]['hypothetical_child_capture_reads'])
        self.assertIsNone(report['verified_hierarchy'])
        self.assertFalse(report['root107_cluster']['formal_promotion_patch']['applicable'])
        self.assertEqual(report['network_requests']+report['factory_invocations']+report['application_calls_executed'],0)


if __name__=='__main__': unittest.main()
