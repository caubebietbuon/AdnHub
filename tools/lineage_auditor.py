"""Phase19 numeric constraints and closure activation/lifetime ledger; offline only."""
import argparse
import json
from pathlib import Path
import tempfile

import obligation_resolver as phase14
from fused_call_analyzer import mask_word_domain
from prologue_analyzer import mix
from reader_tracer import parse_loader
from register_slicer import RegisterSlicer
from scope_tracer import instruction


VARARGS='T,d,I=i[W],{...},H[W];K(d,1,T-1,I,t);t[I+T-1]=e(f(T,...));'
BRANCH='if o==172 then W=if t[i[W]]<A[W]then W else H[W];'


def coupled_masks(first_operand,second_operand):
    if any(type(x) is not int or not 0<=x<=255 for x in (first_operand,second_operand)):
        raise ValueError('Expected byte operands')
    states=mask_word_domain(first_operand)
    pairs=sorted({(first_operand^mix(state),second_operand^mix(state)) for state in states})
    return {'same_state_required':True,'state_contract':'same uint32 V at both sites','xor_delta':first_operand^second_operand,
            'state_domain_count':len(states),'key_pairs':pairs,'unique_key_proved':False}


def directory_step(reference,entries,patches,length):
    value=entries[reference-1]['value']
    for patch in patches:
        if patch['reference_id']==reference: value=patch['directory_after']
    after=value^306486104
    return {'reference_id':reference,'before':value,'after':after,'backing_length':length,
            'bounded_after':0<=after<length,
            'scope':'unchanged exported directory; not a proof about every future mutation history'}


def activation_ledger(bindings,trace,child):
    binding=next(row for row in bindings if row['child']==child)
    identity=binding['captures'][0]['cell_identity']
    shared=[row['child'] for row in bindings if row['child']!=child and
            any(capture.get('cell_identity')==identity for capture in row['captures'])]
    uses=[{'pc':event['pc'],'register':write['register']} for event in trace
          for write in event.get('register_writes',[]) if type(write['value']) is dict and
          write['value'].get('symbolic_closure')==child]
    return {'child':child,'binding_pc':binding['pc'],'capture_cell':identity,
            'body_value_register_definitions':uses,'sibling_closures_sharing_cell':shared,
            'creation_implies_activation':False,'activation_witness':None,
            'whole_lifetime_stable':False,
            'required_effect_summaries':['callee invocation/order','alias escapes','shared sibling capture effects'],
            'formal_promotion_patch':{'applicable':False,'operations':[],
                'reason':'activation, lifetime, ancestry and coverage obligations remain unproved'}}


def run(source,data,output):
    with tempfile.TemporaryDirectory() as temporary:
        report=phase14.run(source,data,Path(temporary)/'phase14',include_analysis_arrays=True)
    text=source.read_text(encoding='ascii')
    if VARARGS not in text or BRANCH not in text: raise ValueError('Source contract missing')
    arrays=report['analysis_arrays']['664'];trace=report['root_analysis']['trace']
    window={str(pc):instruction(arrays,pc,228) for pc in range(978,982)}
    if window!={'978':(125,101,53,109),'979':(172,88,112,66),
                '980':(14842,13,9,38),'981':(125,74,4,47)}:
        raise ValueError('Pinned local window differs; no cross-site constraint applied')
    slicer=RegisterSlicer(664,trace)
    r9=slicer.slice(register=9)
    definitions=[{'pc':event['pc'],'variant':event['variant'],'opcode':event['opcode'],'write':write}
                 for event in trace for write in event.get('register_writes',[]) if write['register']==9]
    argument_effects=[]
    for event in trace:
        if (event['variant'],event['opcode'])==(157,80):
            count,destination=event['operand1'],event['H']
            argument_effects.append({'pc':event['pc'],'copied_argument_range_half_open':[destination,destination+count-1],
                'packed_tail_register':destination+count-1,'source_contract':VARARGS})
    loader=parse_loader(data.read_bytes())
    directory=directory_step(101,loader['lookup_entries'],report['path_local_patch_events'],loader['slice_length'])
    prefix_V=slicer.slice(word='V')
    frozen_keys=None if type(prefix_V['constant']) is not int else {
        'key101':53^mix(prefix_V['constant']),'key74':4^mix(prefix_V['constant'])}
    alignments=[]
    for mask in report['mask_audit']:
        for site in mask['sites']:
            if site['word_variable'] is None or site['owner']==664: continue
            stream=report['analysis_arrays'][str(site['owner'])]
            alternatives=[]
            for pc in range(1,min(map(len,stream.values()))+1):
                for variant in (157,163,228):
                    op,a,b,c=instruction(stream,pc,variant)
                    equation=phase14.patch_equation({'variant':variant,'opcode':op,'operand1':a,'H':b,'operand3':c})
                    if equation and equation[1]==mask['reference_id']: alternatives.append({'pc':pc,'variant':variant,'equation':equation})
            alignments.append({'owner':site['owner'],'old_pc':site['pc'],'reference_id':mask['reference_id'],
                'same_reference_sites':alternatives,'lineage_verified':False})
    result={'source_sha256':report['source_sha256'],'data_sha256':report['data_sha256'],
        'source_evidence':[{'offset':text.index(fragment),'text':fragment} for fragment in (VARARGS,BRANCH)],
        'numeric_r9_proof':{'slice_at_prefix_frontier':r9,'recorded_definitions':definitions,
            'argument_transfer_effects':argument_effects,'numeric_value_proved_at980':False,
            'required_type_at980':'numeric bit32 operand; uint32 conversion required',
            'normalized_r9_domain_inclusive':[0,0xffffffff],'r13_normal_return_domain_inclusive':[0,0xffffffff],
            'missing':'reaching numeric definition of r9 on an entry-to-980 path; frontier None is not numeric zero'},
        'state_V_proof':{'prefix_slice':prefix_V,'at_site_value':None,
            'frozen_frontier_V_keys':frozen_keys,
            'frozen_frontier_V_satisfies_byte_key_model':frozen_keys is not None and all(0<=value<=255 for value in frozen_keys.values()),
            'byte_key_model_scope':'does not rule out an unmodeled wider word-mask layer',
            'local_window':window,'conditional_relation':coupled_masks(53,4),
            'branch_guard_at979':'r88 < 66 for fall-through to980; otherwise successor113',
            'path_contract':'normal patch978; numeric r88<66; numeric bit32 operand r9; stable code and reader context',
            'local_V_writes':[],'directory_guard_at978':directory,
            'straight_line_978_path_valid_in_unchanged_directory':directory['bounded_after'],
            'other_incoming_paths_excluded':False},
        'rewritten_equation_audit':alignments,
        'closure567_activation_lifetime':activation_ledger(report['guarded_closure_bindings'],trace,567),
        'frontier_call':report['fused_call_frontier'],
        'verified_hierarchy':None,'network_requests':0,'application_calls_executed':0,'factory_invocations':0}
    target=output/'lineage-proofs.json'
    if target.resolve() in {source.resolve(),data.resolve()}: raise ValueError('Output aliases input')
    output.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps(result,indent=2,allow_nan=False)+'\n',encoding='utf-8')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=Path('output/stage1-vm-source.lua.txt'))
    parser.add_argument('--data',type=Path,default=Path('output/stage1-vm-data.bin'))
    parser.add_argument('--output',type=Path,default=Path('output/phase19'))
    args=parser.parse_args()
    report=run(args.source,args.data,args.output)
    print('Directory guard:',report['state_V_proof']['directory_guard_at978']['bounded_after'])
