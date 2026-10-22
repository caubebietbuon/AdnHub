"""Phase18: pinned dispatcher fallback, rewritten site alignment and scoped binding."""
import argparse
import json
from pathlib import Path
import tempfile

import obligation_resolver as phase14
import scope_tracer
from register_slicer import RegisterSlicer
from fused_call_analyzer import constructor_contract


FALLBACK = 'else if o==197 then d,T=H[W],i[W]+1;'
XOR_END = 'w[W]=68;else t[i[W]]=_(t[H[W]],A[W]);end;end;end;else if o<188'


def classify_high_opcode(opcode):
    if type(opcode) is not int or opcode<196: raise ValueError('Outside audited high subtree')
    return {'opcode':opcode,'handler':'array_rewrite' if opcode==197 else 'register_xor_immediate',
        'predicates':{'o>=99':True,'o<148':False,'o<173':False,'o>=185':True,
                      'o>=191':True,'o<194':False,'o<196':False,'o==197':opcode==197}}


def run(source,data,output):
    with tempfile.TemporaryDirectory() as temporary:
        report=phase14.run(source,data,Path(temporary)/'phase14',include_analysis_arrays=True)
    text=source.read_text(encoding='ascii')
    if any(fragment not in text for fragment in (FALLBACK,XOR_END,'[20]=bit32.bxor')): raise ValueError('Pinned fallback evidence missing')
    arrays=report['analysis_arrays']['664']
    inst=scope_tracer.instruction(arrays,980,228)
    decoded={'pc':980,'variant':228,'activation_guard':'arrival under variant228 with this unchanged snapshot slot',
        'instruction':inst,**classify_high_opcode(inst[0]),
        'assignment':f'r{inst[1]} = bit32.bxor(r{inst[2]}, {inst[3]})',
        'normal_successor_pc':981,'state_words_written':[],
        'type_guard':'source register is a numeric operand; normal completion unproved',
        'input_at_recorded_frontier_context_only':RegisterSlicer(664,report['root_analysis']['trace']).slice(register=inst[2])}
    alignments=[]
    for mask in report['mask_audit']:
        if mask['reference_id']==192: continue
        for site in mask['sites']:
            if site['word_variable'] is None: continue
            stream=report['analysis_arrays'][str(site['owner'])]
            expected=(site['word_variable'],mask['reference_id'],site['operand'])
            matches=[]
            reference_candidates=[]
            for pc in range(1,min(map(len,stream.values()))+1):
                op,a,b,c=scope_tracer.instruction(stream,pc,site['variant'])
                equation=phase14.patch_equation({'variant':site['variant'],'opcode':op,'operand1':a,'H':b,'operand3':c})
                if equation==expected: matches.append(pc)
                for candidate_variant in (157,163,228):
                    candidate_op,ca,cb,cc=scope_tracer.instruction(stream,pc,candidate_variant)
                    candidate=phase14.patch_equation({'variant':candidate_variant,'opcode':candidate_op,'operand1':ca,'H':cb,'operand3':cc})
                    if candidate and candidate[1]==mask['reference_id']:
                        reference_candidates.append({'pc':pc,'variant':candidate_variant,'state_word':candidate[0],
                            'operand':candidate[2],'guard':'dispatcher, rewritten-slot identity and actual reference use unproved'})
            current=scope_tracer.instruction(stream,site['pc'],site['variant'])
            alignments.append({'owner':site['owner'],'reference_id':mask['reference_id'],'old_pc':site['pc'],
                'variant':site['variant'],'current_instruction':current,'matching_equation_pcs':matches,
                'same_reference_candidates':reference_candidates,
                'relocation_verified':False,'guard':'same equation is not instruction identity; rewrite lineage/dispatcher required',
                'local_trace':scope_tracer.localized_trace(stream,site['pc'],site['variant'],site['word_variable'],site['operand'])})
    binding=next(row for row in report['guarded_closure_bindings'] if row['child']==567)
    root_trace=report['root_analysis']['trace']
    creation=next(i for i,e in enumerate(root_trace) if e.get('symbolic_closure_creation',{}).get('child')==567)
    capture=binding['captures'][0]
    writes=[{'pc':e['pc'],'write':w} for e in root_trace[creation+1:] for w in e.get('register_writes',[]) if w['register']==107]
    proof={'parent':664,'child':567,'descriptor_id':binding['descriptor_id'],
        'creation_pc':binding['pc'],'capture_ordinal':1,'cell_identity':capture['cell_identity'],
        'capture_count':len(binding['captures']),'factory_slot':binding['child_factory'],
        'capture_bound_evidence':binding['capture_bounds'],
        'guarded_binding_structurally_verified':capture['cell_identity']=='frame:664:register:107'
            and len(binding['captures'])==2 and binding['variant']==228 and binding['child_factory']==4890
            and all(bound.get('fits') is True for bound in binding['capture_bounds']),
        'capture_slice_before_creation':RegisterSlicer(664,root_trace).slice(register=107,before_step=creation),
        'subsequent_direct_writes_in_root_prefix':writes,
        'prefix_direct_write_stability':not writes,
        'child_activation_verified':False,'whole_lifetime_alias_stability_verified':False,
        'hierarchy_admissible':False,
        'missing':['actual child activation/order','intervening alias writes or escape effects','unconditional ancestry and global coverage']}
    result={'source_sha256':report['source_sha256'],'data_sha256':report['data_sha256'],
        'dispatcher_evidence':[{'offset':text.index(fragment),'text':fragment} for fragment in (FALLBACK,XOR_END,'[20]=bit32.bxor')],
        'factory_alias_evidence':constructor_contract(text,4890),
        'predecessor_decode':decoded,'rewritten_site_alignment':alignments,'closure567_proof':proof,
        'verified_hierarchy':None,'network_requests':0,'application_calls_executed':0,'factory_invocations':0}
    target=output/'predecessor-proofs.json'
    if target.resolve() in {source.resolve(),data.resolve()}: raise ValueError('Output aliases input')
    output.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps(result,indent=2,allow_nan=False)+'\n',encoding='utf-8')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=Path('output/stage1-vm-source.lua.txt'))
    parser.add_argument('--data',type=Path,default=Path('output/stage1-vm-data.bin'))
    parser.add_argument('--output',type=Path,default=Path('output/phase18'))
    args=parser.parse_args()
    result=run(args.source,args.data,args.output)
    print(result['predecessor_decode']['assignment'])
