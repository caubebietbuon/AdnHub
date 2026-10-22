"""Phase24 epoch-aligned hypotheses and exact symbolic arithmetic checkpoints.

Only pinned Python text/data models; no Lua, factory, __index or application
call is invoked. Historical pattern domains are not current runtime equations.
"""
import argparse
from functools import partial
import json
from pathlib import Path
import tempfile

import obligation_resolver as phase14
from boundary_auditor import (CAPTURE75,RETURN99,TAIL102,capture_transfer,exit_audit,slot_revisions)
from fused_call_analyzer import DISPATCH_FRAGMENT
from lazy_tracer import inspect_reference
from predicate_solver import constrain_boundaries
from reader_scope_auditor import directory_audit, source_contract
from reader_tracer import parse_loader
from schema_constraint_auditor import activation_conditions, equation_search
from scope_tracer import instruction
from register_slicer import RegisterSlicer

REVERSE_SUB140='else if o>=139 then if o==140 then t[H[W]]=A[W]-t[i[W]];else t[i[W]]=A[W];end;'
PARALLEL_CALL4='else if o>=3 then if o<4 then t[A[W]]=t[i[W]]<=t[H[W]];else if o==5 then W=if t[A[W]]~=j[W]then H[W]else W;else T=A[W];t[T],t[T+1]=t[i[W]],t[H[W]];T,d,I=A[W+1],H[W+1],i[W+1];m,R,Q=T+I-1,T+d,e(t[T](P(t,T+1,T+d)));K(Q,1,I,T,t);W=W+1;end;end;'


def primitive_input(context, reference):
    """Respect effective directory and reject an unapplied payload-mask layer.

    No lazy reader or cache entry is called. Only independently translated
    primitive integer observations are admitted to exact-number arithmetic.
    """
    if context is None or type(reference) is not int or not 1<=reference<=len(context.entries):
        return None
    if context.effects.get(reference,0)!=0: return None
    position=context.positions.get(reference,context.entries[reference-1]['value'])
    entries=list(context.entries)
    entries[reference-1]={'value':position}
    row=inspect_reference(context.backing,entries,reference)
    if row.get('status')!='explicit_python_primitive_reader' or type(row.get('value')) is not int:
        return None
    return {'reference_id':reference,'position':position,'kind':row['kind'],'value':row['value'],
            'scope':'reviewed primitive bytes in current guarded data context; actual lazy/cache activation not invoked'}


def checkpoint_transfer(variant,op,a,b,c,registers,event,context=None):
    if capture_transfer(variant,op,a,b,c,registers,event): return True
    if variant!=228 or op not in (97,98,140): return False
    reference=a if op==97 else b
    primitive=primitive_input(context,reference) if op!=140 else None
    left=primitive['value'] if primitive and op==97 else c if op==140 else registers.get(a) if op==98 else None
    right=c if op==97 else registers.get(a) if op==140 else primitive['value'] if primitive else None
    destination=b if op in (97,140) else c
    value=None
    if type(left) is int and type(right) is int:
        candidate=left+right if op==97 else left-right
        if max(abs(left),abs(right),abs(candidate))<=2**53: value=candidate
    if value is None:
        event['checkpoint_boundary']={'operation':'constant_add' if op==97 else 'immediate_minus_register' if op==140 else 'constant_subtract',
            'reference_id':reference if op!=140 else None,'left':left,'right':right,'destination':destination,
            'requires':'exact integer register/immediate arithmetic; no default substitution' if op==140 else
                       'integer primitive and register operands with exact arithmetic; no default substitution'}
        return False
    registers[destination]=value
    event['checkpoint_arithmetic']={'operation':'add' if op==97 else 'subtract','left':left,'right':right,
        'result':value,'destination':destination,'primitive':primitive,'input_register':a if op in (98,140) else None,
        'normal_completion_guard':'source lazy constant/cache binding agrees with the reviewed primitive data context' if primitive else
                                  'input register has the established exact numeric provenance'}
    return True


def checkpoint_factory(context):
    return partial(checkpoint_transfer,context=context)


def align_history(history, expected):
    """Partition historical code epochs instead of retaining stale equations."""
    current=history['final']['equation']
    matching_visits=[visit for visit in history['observed_visits'] if visit['equation'] is not None and tuple(visit['equation'])==tuple(expected)]
    epochs=[]
    versions=[{'step':-1,**history['initial']}]+history['revisions']
    for index,version in enumerate(versions):
        epochs.append({'after_trace_step':version['step'],
            'before_next_revision_step':versions[index+1]['step'] if index+1<len(versions) else None,
            'instruction':version['instruction'],'equation':version['equation'],
            'matches_expected':version['matches_expected'],
            'epoch_scope':'observed revision sequence; last epoch is not a promise about future writes'})
    active=current is not None and tuple(current)==tuple(expected)
    return {'status':'current_equation_identity' if active else 'retired_initial_pattern' if
            history['initial']['matches_expected'] and not matching_visits else 'unmapped_hypothesis',
            'epochs':epochs,'active_equation':current if active else None,
            'current_algebraic_domain_applicable':active,'historical_matching_visits':matching_visits,
            'runtime_state_proved':False,'future_reactivation_excluded':False}


def parallel_call_summary(arrays,pc,registers):
    """228/4: parallel two-register copy, then the same packed-call frame.

    Requested results never become concrete without a proven callee contract.
    No call or result padding is evaluated here.
    """
    if not 1<=pc<min(map(len,arrays.values())): raise ValueError('Fused call lookahead missing')
    op,a,b,c=instruction(arrays,pc,228)
    if op!=4: raise ValueError('Only reviewed parallel fused call4 supported')
    target,argc,resultc=arrays['O'][pc],arrays['Z'][pc],arrays['j'][pc]
    if any(type(value) is not int or not 0<=value<=100000 for value in (a,b,c,target,argc,resultc)):
        raise ValueError('Call frame indices outside analysis budget')
    before=dict(registers)
    after=dict(before)
    after[c],after[c+1]=before.get(a),before.get(b)
    return {'pc':pc,'opcode':4,'parallel_pre_call_copies':[{'destination':c,'source':a,'value':before.get(a)},
                {'destination':c+1,'source':b,'value':before.get(b)}],
            'callee_register':target,'callee_expression':after.get(target),
            'argument_count':argc,'argument_range_half_open':[target+1,target+argc+1],
            'argument_expressions':[after.get(index) for index in range(target+1,target+argc+1)],
            'requested_results':resultc,'result_range_half_open':[target,target+resultc],
            'normal_return_pc':pc+2,'callee_invoked':False,'actual_activation_proved':False,
            'result_values':None,'call_effects_accounted_for':False}


def aligned_models(report, directory):
    equations=equation_search(report)
    traces={row['owner']:row['analysis']['trace'] for row in report['candidate_entry_analyses']}
    traces[664]=report['root_analysis']['trace']
    rows=[]
    for hypothesis in equations:
        owner,pc=hypothesis['owner'],hypothesis['pc']
        history=slot_revisions(report['analysis_arrays'][str(owner)],traces[owner],pc,hypothesis['variant'],
                               hypothesis['expected_equation'],report['initial_watched_slots'][str(owner)][str(pc)])
        alignment=align_history(history,hypothesis['expected_equation'])
        paths=[]
        if alignment['current_algebraic_domain_applicable']:
            for solution in hypothesis['paths']:
                path=solution['path']
                boundaries=[{'name':'aligned current equation identity','proved':True,'scope':'validated final instruction under selected dispatcher'},
                    {'name':'entry/cutpoint data and code epoch','proved':None,'scope':'no unobserved invocation or unchanged future state is assumed'}]
                if owner==664 and 978 in path.get('normal_patch_completion_pcs',[]):
                    boundaries.append({'name':'normal patch978 geometry','proved':False if not directory['patch_attempts'][0]['normal_patch_length_contract'] else None,
                        'scope':'unchanged reconstructed backing and exported directory101; not all future histories'})
                paths.append({'path':path,'constraints':constrain_boundaries(path,hypothesis['expected_equation'][2],boundaries)})
        rows.append({'owner':owner,'pc':pc,'reference_id':hypothesis['reference_id'],
            'expected_equation':hypothesis['expected_equation'],'alignment':alignment,'revision_history':history,
            'historical_mixer_candidate_count':hypothesis['state_count'],
            'current_mixer_candidate_count':hypothesis['state_count'] if alignment['current_algebraic_domain_applicable'] else None,
            'current_paths':paths,'promoted_keys':[],
            'scope':'epoch alignment retires an instruction hypothesis, not a string target or all possible future equations'})
    return rows


def checkpoint_proofs(report):
    rows=[]
    expected={663:546,379:1852,258:37}
    for candidate in report['candidate_entry_analyses']:
        owner=candidate['owner']
        if owner not in (663,379,258,567): continue
        state=candidate['analysis']
        arithmetic=[]
        definitions={}
        for step,event in enumerate(state['trace']):
            if 'checkpoint_arithmetic' in event:
                operation=event['checkpoint_arithmetic']
                arithmetic.append({'step':step,'pc':event['pc'],'state_words_before':event['state_words_before'],
                    **operation,'register_input_definition':definitions.get(operation['input_register'])})
            for write in event.get('register_writes',[]):
                definitions[write['register']]={'step':step,'pc':event['pc'],'variant':event['variant'],
                    'opcode':event['opcode'],'value':write['value'],'state_word_read':event.get('state_word_read')}
        checkpoint=expected.get(owner)
        selected=[event for event in state['trace'] if event['pc']==checkpoint] if checkpoint else []
        last=state['trace'][-1]
        slicer=RegisterSlicer(owner,state['trace'])
        for row in arithmetic:
            after_step=row['step']+1
            row['result_slice']=slicer.slice(register=row['destination'],
                before_step=after_step if after_step<len(state['trace']) else None)
        registers={}
        for event in state['trace'][:-1]:
            for write in event.get('register_writes',[]): registers[write['register']]=write['value']
        call=parallel_call_summary(report['analysis_arrays'][str(owner)],state['pc'],registers) if (last['variant'],last['opcode'])==(228,4) else None
        rows.append({'owner':owner,'previous_checkpoint':checkpoint,
            'checkpoint_transfer_verified':any('checkpoint_arithmetic' in event for event in selected),
            'arithmetic':arithmetic,'frontier_pc':state['pc'],
            'frontier_instruction':[last['variant'],last['opcode'],last['operand1'],last['H'],last['operand3']],
            'residual_boundary':last.get('checkpoint_boundary'),
            'parallel_fused_call_boundary':call,
            'entry_guard':candidate['guard'],'activation_verified':False,'complete_lifetime_verified':False})
    return rows


def conditional_activation(report, checkpoints):
    child=next(row for row in checkpoints if row['owner']==663)
    call=child['parallel_fused_call_boundary']
    if call is None: return None
    expression=call['callee_expression']
    if type(expression) is not dict or expression.get('enclosing_capture_value')!=1: return None
    frame=next(row for row in report['capture_frame_constraints'] if row['child']==663)
    captured=next(row for row in frame['captures'] if row['capture_ordinal']==1)
    observed=captured['frontier_value']
    target=observed.get('symbolic_closure') if type(observed) is dict else None
    return {'caller':663,'pc':call['pc'],'callee_capture_ordinal':1,'cell_identity':captured['cell_identity'],
        'body_candidate_at_root_frontier':target,'argument_expressions':call['argument_expressions'],
        'requested_results':call['requested_results'],
        'packed_numeric_argument_verified':bool(call['argument_expressions']) and all(type(value) is int for value in call['argument_expressions']),
        'target_identity_at_call_verified':False,'actual_activation_verified':False,
        'is_lexical_parent_edge':False,'verified_hierarchy_edge':None,
        'obligations':['actual663 activation and normal path to547',
            'root159 still holds the proposed body at the call, accounting for close/rebind and alias effects',
            'proposed callee template/cache and full captured-cell environment are the expected live objects',
            'guarded primitive observations agree with the source lazy constant/cache state',
            'normal call return and all escaping effects before claiming exit/lifetime']}


def run(source,data,output,include_provenance=False):
    target=output/'checkpoint-alignment.json'
    if target.resolve() in (source.resolve(),data.resolve()) or output.resolve() in (source.resolve(),data.resolve()):
        raise ValueError('Output aliases input')
    text=source.read_text(encoding='ascii')
    fragments=(DISPATCH_FRAGMENT,CAPTURE75,RETURN99,TAIL102,REVERSE_SUB140,PARALLEL_CALL4)
    evidence=[{'offset':text.index(fragment),'text':fragment} for fragment in fragments]
    source_contract(text)
    watched={664:tuple(range(976,982)),402:(83,),711:(269,),593:(393,),379:(686,)}
    with tempfile.TemporaryDirectory() as temporary:
        root=Path(temporary)
        report=phase14.run(source,data,root/'phase14',include_analysis_arrays=True,
                          watch_code_slots=watched,extra_source_transfer_factory=checkpoint_factory)
        from reconstructor import run as reconstruct
        reconstruct(source,data,root/'backing',[664])
        backing=(root/'backing/record-664.backing-postfill.bin').read_bytes()
    directory=directory_audit(backing,parse_loader(data.read_bytes())['lookup_entries'],101)
    checkpoints=checkpoint_proofs(report)
    exits=exit_audit(report)
    for frame in exits:
        checkpoint=next((row for row in checkpoints if row['owner']==frame['owner']),None)
        if checkpoint and checkpoint['parallel_fused_call_boundary'] is not None:
            frame['fused_call_boundary']=checkpoint['parallel_fused_call_boundary']
    result={'source_sha256':report['source_sha256'],'data_sha256':report['data_sha256'],'source_evidence':evidence,
        'aligned_models':aligned_models(report,directory),'checkpoint_proofs':checkpoints,
        'conditional_activation_candidate':conditional_activation(report,checkpoints),
        'scope_exits':exits,
        'activation_lifetime':activation_conditions(report['guarded_closure_bindings'],report['root_analysis']['trace'],
            report['candidate_entry_analyses'],report['structural_hierarchy_candidates']),
        'verified_hierarchy':None,'formal_promotion_patch':{'applicable':False,'operations':[]},
        'network_requests':0,'factory_invocations':0,'application_calls_executed':0,'input_byte_edits':0}
    if include_provenance:
        # Opt-in static evidence for downstream path finding; legacy callers
        # retain their compact report and no extra application transfer runs.
        result['provenance_inputs']={name:report[name] for name in (
            'root_analysis','candidate_entry_analyses','capture_frame_constraints',
            'guarded_closure_bindings','fused_call_frontier','analysis_arrays',
            'path_local_patch_events','guarded_template_evidence')}
    output.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps(result,indent=2,allow_nan=False)+'\n',encoding='utf-8')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=Path('output/stage1-vm-source.lua.txt'))
    parser.add_argument('--data',type=Path,default=Path('output/stage1-vm-data.bin'))
    parser.add_argument('--output',type=Path,default=Path('output/phase24'))
    args=parser.parse_args()
    result=run(args.source,args.data,args.output)
    print('Aligned models:',[(row['owner'],row['alignment']['status']) for row in result['aligned_models']])
    print('Checkpoints:',[(row['owner'],row['frontier_pc']) for row in result['checkpoint_proofs']])
