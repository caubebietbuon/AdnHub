"""Reader-family correction, bounded patch copies and closure scope boundaries."""
import copy
from pathlib import Path
import tempfile
import unittest

from reader_scope_auditor import (CLOSE_CELL, PATCH_HEAD, PATCH_TAIL, DIRECTORY_XOR,
    copy_payload_patch, directory_audit, lifetime_audit, raw_prefix, run, source_contract, typed_probe)
from symbolic_resolver import PROOFS
from test_phase6 import uint


def lifecycle_fixture():
    bindings, trace, criteria = [], [], []
    for step,(child,register) in enumerate(((567,108),(258,109),(379,159),(663,85))):
        pc = 8390+step
        capture = 159 if child==663 else 107
        bindings.append({'child':child,'parent':664,'pc':pc,
                         'captures':[{'cell_identity':f'frame:664:register:{capture}'}]})
        trace.append({'pc':pc,'register_writes':[{'register':register,
                     'value':{'symbolic_closure':child,'creation_pc':pc}}]})
        criteria.append({'child':child,'proofs':dict.fromkeys(PROOFS,True)})
    return bindings,trace,criteria


class Phase21Tests(unittest.TestCase):
    def test_primitive_tag_does_not_have_a_length_prefix(self):
        # Ref101, aux255: seed100 -> next state79; encrypted4 = 4 XOR255 XOR79.
        backing=bytes([195,180,219,15])
        entries=[{'value':-1} for _ in range(100)]+[{'value':0}]
        result=typed_probe(backing,entries,101)
        self.assertEqual(result['observation']['value'],4)
        self.assertEqual(result['fixed_width'],1)
        self.assertFalse(result['length_prefix_applicable'])
        self.assertEqual(result['byte_edits'],[])

    def test_string_descriptor_function_families_use_length(self):
        for tag in (1,219,174,250):
            result=typed_probe(bytes([tag,0]),[{'value':0}],1)
            self.assertTrue(result['length_prefix_applicable'])
            self.assertEqual(result['prefix']['length'],0)

    def test_unknown_reader_and_bad_directory_are_not_repaired(self):
        self.assertEqual(typed_probe(bytes([16,0]),[{'value':0}],1)['status'],'unmodeled_reader_family')
        self.assertEqual(typed_probe(b'abc',[{'value':999}],1)['status'],'outside_backing')
        for reference in (0,2,True):
            with self.assertRaises(ValueError): typed_probe(b'abc',[{'value':0}],reference)

    def test_raw_length_shapes_and_truncation(self):
        for length in (0,127,128,16383,16384,2097151):
            prefix=uint(length)
            result=raw_prefix(bytes([174])+prefix,0)
            self.assertEqual(result['length'],length)
            self.assertEqual(result['prefix_end'],len(prefix)+1)
            self.assertEqual(result['status'],'bounded' if length==0 else 'length_out_of_bounds')
        four=raw_prefix(bytes([174,129,128,128,0]),0)
        self.assertEqual((four['length'],four['prefix_end']),(2097152,5))
        self.assertEqual(raw_prefix(bytes([174,128]),0)['status'],'truncated_prefix')
        self.assertEqual(raw_prefix(b'a',-1)['status'],'outside_backing')

    def test_all_byte_masks_preserve_prefix_and_other_bytes(self):
        backing=bytearray(b'\xae\x05ABCDEtail')
        original=bytes(backing)
        for key in range(256):
            patched,directory,proof=copy_payload_patch(backing,DIRECTORY_XOR,key)
            self.assertEqual(patched[:2],original[:2])
            self.assertEqual(patched[7:],b'tail')
            self.assertEqual(patched[2:7],bytes(value^key for value in b'ABCDE'))
            self.assertEqual(directory,0)
            self.assertTrue(proof['prefix_preserved'])
            self.assertFalse(proof['activation_proved'])
        self.assertEqual(bytes(backing),original)

    def test_repeated_patch_is_not_a_second_payload_xor_at_same_position(self):
        patched,position,_=copy_payload_patch(b'\xae\x01A',DIRECTORY_XOR,91)
        with self.assertRaises(ValueError): copy_payload_patch(patched,position,91)

    def test_bad_length_and_key_leave_input_untouched(self):
        backing=bytearray(b'\xae\x7fA')
        original=bytes(backing)
        for key in (True,-1,256):
            with self.assertRaises(ValueError): copy_payload_patch(backing,DIRECTORY_XOR,key)
        with self.assertRaises(ValueError): copy_payload_patch(backing,DIRECTORY_XOR,0)
        with self.assertRaises(ValueError): copy_payload_patch(backing,-1,0)
        self.assertEqual(bytes(backing),original)

    def test_directory_parity_alone_is_not_activation_proof(self):
        result=directory_audit(b'\xae\x01A',[{'value':DIRECTORY_XOR}],1)
        self.assertEqual([r['position'] for r in result['parity_cases']],[DIRECTORY_XOR,0,DIRECTORY_XOR])
        self.assertTrue(result['patch_attempts'][0]['normal_patch_length_contract'])
        self.assertFalse(result['state_equations_unblocked'])

    def test_source_prefix_exclusion_and_close_layout(self):
        source=PATCH_HEAD+'reader;'+PATCH_TAIL+CLOSE_CELL
        proof=source_contract(source)
        self.assertFalse(proof['payload_mask_changes_length_prefix'])
        self.assertTrue(proof['directory_written_before_length_read'])
        self.assertFalse(proof['actual_close_event_proved'])
        with self.assertRaises(ValueError): source_contract(PATCH_HEAD)

    def test_body_alias_is_not_lexical_parent_or_activation(self):
        bindings,trace,criteria=lifecycle_fixture()
        result=lifetime_audit(bindings,trace,[],criteria)
        edge=result['captured_body_edges'][0]
        self.assertEqual((edge['holder'],edge['target_body']),(663,379))
        self.assertFalse(edge['is_lexical_parent_edge'])
        self.assertFalse(edge['is_activation_edge'])
        self.assertTrue(all(row['end_reason'].startswith('right-censored') for row in result['body_register_intervals']))
        # Even all inherited structural flags cannot supply missing lifetime proof.
        self.assertFalse(result['formal_promotion_patch']['applicable'])
        self.assertIsNone(result['verified_hierarchy'])

    def test_register_overwrite_does_not_end_a_captured_cell_lifetime(self):
        bindings,trace,criteria=lifecycle_fixture()
        trace.append({'pc':8400,'register_writes':[{'register':159,'value':7}]})
        result=lifetime_audit(bindings,trace,[],criteria)
        interval=next(r for r in result['body_register_intervals'] if r['child']==379)
        self.assertEqual(interval['end_reason'],'observed register overwrite')
        self.assertFalse(interval['register_interval_is_cell_lifetime'])

    def test_equal_register_in_another_frame_does_not_create_body_alias(self):
        bindings,trace,criteria=lifecycle_fixture()
        bindings[-1]['captures'][0]['cell_identity']='frame:999:register:159'
        result=lifetime_audit(bindings,trace,[],criteria)
        self.assertEqual(result['captured_body_edges'],[])
        self.assertEqual(bindings[-1]['captures'][0]['cell_identity'],'frame:999:register:159')

    def test_ambiguous_construction_rejected(self):
        bindings,trace,criteria=lifecycle_fixture()
        trace.insert(0,copy.deepcopy(trace[0]))
        with self.assertRaises(ValueError): lifetime_audit(bindings,trace,[],criteria)

    @unittest.skipUnless(Path('output/stage1-vm-data.bin').exists(),'Pinned artifacts required')
    def test_pinned_schema_and_scope_obligations(self):
        with tempfile.TemporaryDirectory() as temporary:
            result=run(Path('output/stage1-vm-source.lua.txt'),Path('output/stage1-vm-data.bin'),Path(temporary))
        directory=result['directory101']
        typed=directory['interpretation_correction']
        self.assertEqual((typed['position'],typed['tag'],typed['leaf_state']),(134543,195,130))
        self.assertEqual(typed['observation']['value'],4)
        prefix=directory['parity_cases'][0]['raw_patch_prefix']
        self.assertEqual((prefix['length'],prefix['available_payload_bytes']),(1492916,17630))
        self.assertTrue(all(not r['normal_patch_length_contract'] for r in directory['patch_attempts']))
        self.assertEqual(directory['byte_edits'],[])
        edge=result['cluster']['captured_body_edges'][0]
        self.assertEqual((edge['holder'],edge['target_body']),(663,379))
        self.assertEqual(edge['cell'],'frame:664:register:159')
        self.assertEqual([r['child_entry_frontier'] for r in result['cluster']['closures']], [24,37,1849,544])
        self.assertIsNone(result['verified_hierarchy'])
        self.assertEqual(result['network_requests']+result['factory_invocations']+result['application_calls_executed'],0)


if __name__=='__main__': unittest.main()
