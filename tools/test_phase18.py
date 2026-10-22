"""Pinned fallback classification, local transfer and guarded binding proofs."""
from pathlib import Path
import tempfile
import unittest

from predecessor_auditor import classify_high_opcode, run
from scope_tracer import successors, symbolic_path


class Phase18Tests(unittest.TestCase):
    def test_high_opcode_default_is_xor_not_invalid(self):
        for opcode in (196,198,14842,0xffffffff):
            self.assertEqual(classify_high_opcode(opcode)['handler'],'register_xor_immediate')
        self.assertEqual(classify_high_opcode(197)['handler'],'array_rewrite')

    def test_classification_domain(self):
        for opcode in (195,True,1.5):
            with self.assertRaises(ValueError): classify_high_opcode(opcode)

    def test_default_handler_normal_successor(self):
        self.assertEqual(successors(980,(14842,13,9,38),228),[981])
        self.assertEqual(successors(980,(197,13,9,38),228),[])

    def test_exact_xor_transfer_and_unchanged_state(self):
        arrays={'B':[139,14842,125],'j':[9,13,74],'Z':[0,9,4],'O':[42,38,0]}
        result=symbolic_path(arrays,228,[1,2,3],'V')
        self.assertEqual(result['mutations'][-1]['register_writes'][13],42^38)
        self.assertEqual(result['state_at_site'],{'input':'V'})

    def test_unknown_xor_input_keeps_type_predicate(self):
        arrays={'B':[14842,125],'j':[13,74],'Z':[9,4],'O':[38,0]}
        result=symbolic_path(arrays,228,[1,2],'V')
        value=result['mutations'][0]['register_writes'][13]
        self.assertIn('bit32_bxor',value)
        self.assertIn('predicate',value)
        self.assertTrue(result['predicates'])

    @unittest.skipUnless(Path('output/stage1-vm-data.bin').exists(),'Pinned data required')
    def test_pinned_decode_alignment_and_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            report=run(Path('output/stage1-vm-source.lua.txt'),Path('output/stage1-vm-data.bin'),Path(temporary))
        self.assertEqual(report['predecessor_decode']['assignment'],'r13 = bit32.bxor(r9, 38)')
        alignment=report['rewritten_site_alignment']
        self.assertEqual(len(alignment),5)
        self.assertEqual(alignment[0]['matching_equation_pcs'],[981])
        self.assertTrue(all(not row['matching_equation_pcs'] for row in alignment[1:]))
        binding=report['closure567_proof']
        self.assertTrue(binding['guarded_binding_structurally_verified'])
        self.assertEqual(binding['capture_slice_before_creation']['constant'],0)
        self.assertTrue(binding['prefix_direct_write_stability'])
        self.assertFalse(binding['hierarchy_admissible'])
        self.assertIsNone(report['verified_hierarchy'])
        self.assertEqual(report['network_requests'],0)


if __name__=='__main__': unittest.main()
