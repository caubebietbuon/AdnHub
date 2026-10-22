"""Phase23 scoped code/data boundaries, exact slot revisions and exit contracts.

Static Python observations only. No Lua, VM factory, __index, application call
or network operation. Optional reader transfers never dereference real cells.
"""
import argparse
import json
from pathlib import Path
import tempfile

import obligation_resolver as phase14
from fused_call_analyzer import summarize_fused_call
from predicate_solver import constrain_boundaries
from reader_scope_auditor import directory_audit, source_contract
from reader_tracer import parse_loader
from schema_constraint_auditor import activation_conditions, equation_search
from scope_tracer import instruction


CAPTURE75='else if o<75 then t[H[W]]=p(t[A[W]],t[i[W]]);else if o~=76 then T=g[i[W]];t[H[W]]=T[6][T[5]];'
CLOSE_ALL='if k then for f in X,k,nil do local xJ=k[f];if xJ then xJ[6]=xJ;xJ[4]=t[f];xJ[5]=4;k[f]=nil;end;end;end;'
RETURN99='else if o<100 then '+CLOSE_ALL
TAIL102='if o<103 then '+CLOSE_ALL


def capture_transfer(variant,op,a,b,c,registers,event):
    if (variant,op)!=(228,75): return False
    registers[b]={'enclosing_capture_value':a}
    event['capture_cell_read']={'ordinal':a,'destination':b,'value_dereferenced':False}
    event['normal_completion_assumption']='enclosing capture cell exists and its source storage read succeeds; value remains symbolic'
    return True


def slot_revisions(arrays,trace,pc,variant,expected,initial_values):
    """Reverse all watched writes, then replay atomic per-event revisions.

    Every before/after is checked. Intermediate partial multi-array writes are
    not interpreted as instruction visits. Initial tuples remain hypotheses.
    """
    names=('j','O','Z','B')
    current={name:arrays[name][pc-1] for name in names}
    changes=[(step,event,[write for write in event.get('code_slot_writes',[]) if write['pc']==pc])
             for step,event in enumerate(trace)]
    for _,_,writes in reversed(changes):
        for write in reversed(writes):
            name=write['array']
            if current[name]!=write['after']: raise ValueError('Incomplete slot revision history')
            current[name]=write['before']
    if current!=initial_values: raise ValueError('Revision history disagrees with independent initial slot anchor')
    def decode(values):
        order={157:('O','j','Z','B'),163:('j','B','Z','O'),228:('B','j','Z','O')}[variant]
        inst=tuple(values[name] for name in order)
        equation=phase14.patch_equation(dict(zip(('variant','opcode','operand1','H','operand3'),(variant,*inst))))
        return {'instruction':inst,'equation':equation,'matches_expected':equation==tuple(expected)}
    initial=decode(current)
    revisions=[]
    for step,event,writes in changes:
        if not writes: continue
        for write in writes:
            name=write['array']
            if current[name]!=write['before']: raise ValueError('Non-contiguous code revision')
            current[name]=write['after']
        revisions.append({'step':step,'source_pc':event['pc'],'source_variant':event['variant'],
            'source_opcode':event['opcode'],'state_words_before':event['state_words_before'],
            'rewritten_range':event.get('rewritten_range'),'writes':writes,**decode(current)})
    if any(current[name]!=arrays[name][pc-1] for name in names): raise ValueError('Final revision mismatch')
    visits=[{'step':step,'variant':event['variant'],'instruction':[event['opcode'],event['operand1'],event['H'],event['operand3']],
             'equation':phase14.patch_equation(event)} for step,event in enumerate(trace) if event['pc']==pc]
    return {'pc':pc,'variant_hypothesis':variant,'initial':initial,'revisions':revisions,
            'final':decode(current),'observed_visits':visits,
            'scope':'complete watched slot changes on the guarded recorded prefix only; no future rewrite proof'}


def exit_contract(inst,variant):
    op,a,b,c=inst
    if variant==228 and op in (99,102):
        return {'handler':'constant_return' if op==99 else 'tail_call',
                'closes_open_cells_before_return_or_tailcall':True,
                'cell_storage_after_close':'same cell object; slot6=self, slot4=frame value, slot5=4',
                'frame_escapes_accounted_for':False,'actual_exit_proved':False}
    return None


def exit_audit(report):
    frames=[(664,report['root_analysis'])]+[(row['owner'],row['analysis'])
        for row in report['candidate_entry_analyses'] if row['owner'] in (567,258,379,663)]
    bindings={row['child']:row for row in report['guarded_closure_bindings']}
    rows=[]
    for owner,state in frames:
        arrays=report['analysis_arrays'][str(owner)]
        trace=state['trace']
        reads=[]
        for event in trace:
            if 'capture_cell_read' not in event: continue
            read=event['capture_cell_read'];ordinal=read['ordinal']
            captures=bindings.get(owner,{}).get('captures',[])
            identity=captures[ordinal-1].get('cell_identity') if 1<=ordinal<=len(captures) else None
            reads.append({'pc':event['pc'],**read,'guarded_root_binding':identity,
                'binding_scope':'recorded constructor context, not a value-at-invocation proof'})
        potential=[]
        for pc in range(1,min(map(len,arrays.values()))+1):
            inst=instruction(arrays,pc,228)
            contract=exit_contract(inst,228)
            if contract: potential.append({'pc':pc,'variant_guard':228,'instruction':inst,**contract})
        observed=[{'pc':event['pc'],**exit_contract((event['opcode'],event['operand1'],event['H'],event['operand3']),event['variant'])}
            for event in trace if exit_contract((event['opcode'],event['operand1'],event['H'],event['operand3']),event['variant'])]
        last=trace[-1]
        registers={}
        for event in trace[:-1]:
            for write in event.get('register_writes',[]): registers[write['register']]=write['value']
        call=None
        if (last['variant'],last['opcode'])==(228,93): call=summarize_fused_call(arrays,last['pc'],registers)
        rows.append({'owner':owner,'frontier_pc':state['pc'],'frontier_instruction':
            [last['variant'],last['opcode'],last['operand1'],last['H'],last['operand3']],
            'capture_reads':reads,'reviewed_exit_candidates':potential,
            'reached_exit_instruction_boundaries':observed,'fused_call_boundary':call,
            'exit_reachability_complete':False,'scope_exit_lifetime_verified':False,
            'obligations':['actual frame activation','all dispatcher/code-version paths',
                'normal/error/nonreturn outcomes','open-cell and span-close order','all escaping alias effects']})
    return rows


def run(source,data,output):
    target=output/'boundary-proofs.json'
    if target.resolve() in (source.resolve(),data.resolve()) or output.resolve() in (source.resolve(),data.resolve()):
        raise ValueError('Output aliases input')
    text=source.read_text(encoding='ascii')
    evidence=[{'offset':text.index(fragment),'text':fragment} for fragment in (CAPTURE75,RETURN99,TAIL102)]
    source_contract(text)
    watched={664:tuple(range(976,982)),402:(83,),711:(269,),593:(393,),379:(686,)}
    with tempfile.TemporaryDirectory() as temporary:
        root=Path(temporary)
        report=phase14.run(source,data,root/'phase14',include_analysis_arrays=True,
                          watch_code_slots=watched,extra_source_transfer=capture_transfer)
        from reconstructor import run as reconstruct
        reconstruct(source,data,root/'backing',[664])
        backing=(root/'backing/record-664.backing-postfill.bin').read_bytes()
    directory=directory_audit(backing,parse_loader(data.read_bytes())['lookup_entries'],101)
    equations=equation_search(report)
    traces={row['owner']:row['analysis']['trace'] for row in report['candidate_entry_analyses']}
    traces[664]=report['root_analysis']['trace']
    for row in equations:
        owner=row['owner']
        row['revision_history']=slot_revisions(report['analysis_arrays'][str(owner)],traces[owner],
                                              row['pc'],row['variant'],row['expected_equation'],
                                              report['initial_watched_slots'][str(owner)][str(row['pc'])])
        history=row['revision_history']
        valid_visits=[visit for visit in history['observed_visits'] if visit['equation']==tuple(row['expected_equation'])]
        row['version_diagnosis']='initial pattern invalidated on recorded prefix' if history['initial']['matches_expected'] and not history['final']['matches_expected'] and not valid_visits else 'inspect retained version and visit evidence'
        alternate=[]
        arrays=report['analysis_arrays'][str(owner)]
        for pc in range(1,min(map(len,arrays.values()))+1):
            for variant in (157,163,228):
                op,a,b,c=instruction(arrays,pc,variant)
                equation=phase14.patch_equation({'variant':variant,'opcode':op,'operand1':a,'H':b,'operand3':c})
                if equation and equation[1]==row['reference_id']:
                    alternate.append({'pc':pc,'variant':variant,'equation':equation,'relocation_verified':False})
        row['final_same_reference_patch_sites']=alternate
        constrained=[]
        for solution in row['paths']:
            path=solution['path']
            obligations=[{'name':'current equation identity','proved':row['equation_identity_verified'],
                'scope':'this fixed rewritten slot under the selected dispatcher'},
                {'name':'entry and code epoch at local cutpoint','proved':None,
                 'scope':'no complete entry-to-cutpoint frame/code/directory history is assumed'}]
            if owner==664 and 978 in path.get('normal_patch_completion_pcs',[]):
                obligations.append({'name':'patch978 normal reader completion',
                    'proved':False if not directory['patch_attempts'][0]['normal_patch_length_contract'] else None,
                    'scope':'unchanged reconstructed backing and exported directory101 only; other histories remain open'})
            constrained.append(constrain_boundaries(path,row['expected_equation'][2],obligations))
        row['boundary_constraints']=constrained
        row['admissible_declared_model_count']=len({state for solution in constrained for state in solution['admissible_in_declared_model']})
    result={'source_sha256':report['source_sha256'],'data_sha256':report['data_sha256'],
            'source_evidence':evidence,'equations':equations,'directory101':directory,
            'scope_exits':exit_audit(report),
            'activation_lifetime':activation_conditions(report['guarded_closure_bindings'],report['root_analysis']['trace'],
                 report['candidate_entry_analyses'],report['structural_hierarchy_candidates']),
            'verified_hierarchy':None,'formal_promotion_patch':{'applicable':False,'operations':[]},
            'network_requests':0,'application_calls_executed':0,'factory_invocations':0,'input_byte_edits':0}
    output.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps(result,indent=2,allow_nan=False)+'\n',encoding='utf-8')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=Path('output/stage1-vm-source.lua.txt'))
    parser.add_argument('--data',type=Path,default=Path('output/stage1-vm-data.bin'))
    parser.add_argument('--output',type=Path,default=Path('output/phase23'))
    args=parser.parse_args()
    result=run(args.source,args.data,args.output)
    print('Scoped admissible counts:',[row['admissible_declared_model_count'] for row in result['equations']])
    print('Frame frontiers:',[(row['owner'],row['frontier_pc']) for row in result['scope_exits']])
