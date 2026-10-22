"""Phase34 guarded branch ledger, segment continuity and interprocedural SAT.

Recorded trace order is not numeric PC order. SAT of predicates does not prove
arrival, hidden effects, a same-epoch definition of V, or normal return.
"""
import argparse
from collections import Counter
from copy import deepcopy
import json
from pathlib import Path

from epoch_mapper import run as epoch_run
from path_domain import Predicates, key, truth
from subgate_resolver import guarded_continuation


ANCHORS=(
    'W=if o~=14 then if t[i[W]]<=A[W]then W else H[W]else if t[A[W]]<t[H[W]]then W else i[W];end;',
    'else W=if t[A[W]]then w[W]else H[W];',
    'else W=if t[i[W]]then A[W]else H[W];',
)


def predicate_query(guards,gaps=()):
    """Check conjunction under explicit premises; never equate SAT to reachability."""
    domain=Predicates()
    for row in guards:domain.assume(row['expression'],row['truth'])
    status=domain.check()['status']
    return {'constraint_status':status,
        'path_status':'inconsistent_guarded_projection' if status=='UNSAT' else
                      'OPEN' if gaps or status!='SAT' else 'compatible_guarded_projection',
        'open_obligations':list(gaps),'absolute_barrier_proved':False,
        'unconditional_reachability_proved':False,'numeric_filters_admitted':[]}


def branch_ledger(trace,scope):
    """Re-evaluate reviewed numeric branches from recorded reaching writes.

    Missing definitions remain symbolic, never zero/nil defaults. Expressions
    use SSA versions; repeated comparisons correlate only when inputs agree.
    Source-prefix/native/cache premises are retained by the enclosing report.
    """
    values={};versions={};rows=[];visits=Counter()
    for step,event in enumerate(trace):
        pc=event['pc'];visits[pc]+=1
        variant,op=event['variant'],event['opcode']
        a,b,c=(event[k] for k in ('operand1','H','operand3'))
        guard=event.get('path_predicate')
        if guard:
            row={'step':step,'pc':pc,'variant':variant,'opcode':op,
                'occurrence':guard['occurrence'],'expression':deepcopy(guard['expression']),
                'truth':guard['truth'],'kind':'source_path_predicate'}
            if variant==163 and op in (46,49):
                yes,no=(c+1,b+1) if op==46 else (a+1,b+1)
            elif (variant,op)==(228,181):yes,no=c+1,b+1
            else:raise ValueError('Unreviewed predicate branch schema')
            row.update(true_pc=yes,false_pc=no)
        elif variant==228 and op in (13,14):
            left_reg,right_reg=(a,None) if op==13 else (c,b)
            left=values.get(left_reg,{'unresolved_definition':versions.get(left_reg,f'{scope}:input:r{left_reg}')})
            right=c if right_reg is None else values.get(right_reg,{'unresolved_definition':f'{scope}:input:r{right_reg}'})
            exact=all(type(v)is int and abs(v)<=2**53 for v in (left,right))
            value=(left<=right if op==13 else left<right) if exact else None
            operands=[{'register':left_reg,'definition':versions.get(left_reg,f'{scope}:input:r{left_reg}'),'value':left},
                {'immediate':right} if right_reg is None else
                {'register':right_reg,'definition':versions.get(right_reg,f'{scope}:input:r{right_reg}'),'value':right}]
            expr=value if exact else {'atom':key({'scope':scope,'operator':'<=' if op==13 else '<',
                'inputs':[o.get('definition',o) for o in operands]})}
            yes,no=pc+1,(b if op==13 else a)+1
            successor=trace[step+1]['pc'] if step+1<len(trace) else None
            if value is None:
                if yes==no:raise ValueError('Ambiguous unrecorded branch outcome')
                choice=True if successor==yes else False if successor==no else None
            else:choice=value
            row={'step':step,'pc':pc,'variant':variant,'opcode':op,'occurrence':f'{pc}:{visits[pc]}',
                'expression':expr,'truth':choice,'operands':operands,'kind':'exact_integer_branch' if exact else 'symbolic_branch',
                'true_pc':yes,'false_pc':no,'operator':'<=' if op==13 else '<'}
        else:row=None
        if row:
            successor=trace[step+1]['pc'] if step+1<len(trace) else None
            expected=row['true_pc'] if row['truth']is True else row['false_pc'] if row['truth']is False else None
            row['recorded_successor']=successor
            row['successor_verified']=successor is not None and expected is not None and successor==expected
            if successor is not None and expected is not None and successor!=expected:
                raise ValueError(f'Branch successor mismatch at {scope}:{pc}')
            rows.append(row)
        for index,write in enumerate(event.get('register_writes',[])):
            register=write['register'];values[register]=deepcopy(write['value'])
            versions[register]=f'{scope}:r{register}@{pc}:{step}:{index}'
    return rows


def temporal_relation(trace,start,target):
    """Only a recorded occurrence order can justify this temporal relation."""
    starts=[i for i,e in enumerate(trace) if e['pc']==start]
    targets=[i for i,e in enumerate(trace) if e['pc']==target]
    return {'start_pc':start,'target_pc':target,'start_occurrences':starts,'target_occurrences':targets,
        'recorded_forward_order':any(a<b for a in starts for b in targets),
        'status':'recorded_order_only' if starts and targets else 'missing_endpoint',
        'global_order_proved':False}


def continuity(segments,seams):
    """Validate only explicit guarded seams, never infer edges from adjacent PCs."""
    if len(seams)!=max(0,len(segments)-1):raise ValueError('One seam required per segment boundary')
    rows=[]
    for index,seam in enumerate(seams):
        left,right=segments[index],segments[index+1]
        expected=(left['end_pc'],right['start_pc'])
        if (seam['from_pc'],seam['to_pc'])!=expected:raise ValueError('Segment endpoints mismatch')
        if seam['kind'] not in ('guarded_call_return','same_boundary_snapshot'):raise ValueError('Unknown seam')
        if seam['kind']=='same_boundary_snapshot' and expected[0]!=expected[1]:
            raise ValueError('Unequal snapshot seam')
        rows.append({**deepcopy(seam),'unconditional_edge_proved':False})
    return {'segments':segments,'seams':rows,'global_continuity_proved':False}


def root_path_audit(forward,automated):
    evidence=forward['provenance_inputs'];root=evidence['root_analysis']
    trace=root['trace'];regs=trace[-1]['registers_before']
    # JSON serialization changes integer dictionary keys. No values are filled in.
    regs={int(k):v for k,v in regs.items()}
    middle=guarded_continuation(evidence['analysis_arrays']['664'],regs,evidence['fused_call_frontier'])
    ledger=branch_ledger(trace,'root664:pinned-prefix')
    assumptions=[{'step':step,'pc':event['pc'],'kind':name,'condition':deepcopy(event[name])}
        for step,event in enumerate(trace) for name in
        ('normal_completion_assumption','application_boundary','ignored_metadata_assignment') if name in event]
    paths=[]
    for index,path in enumerate(automated['symbolic_exploration']['terminal_paths']):
        last=path['trace'][-1];call=last.get('call_metadata',{});callee=call.get('callee_expression',{})
        if not isinstance(callee,dict) or callee.get('symbolic_closure')!=516:continue
        advanced=path['trace']
        segment_list=[{'name':'pinned root prefix','start_pc':trace[0]['pc'],'end_pc':root['pc']},
            {'name':'guarded assertion continuation','start_pc':middle['trace'][0]['pc'],'end_pc':middle['frontier_pc']},
            {'name':'advanced guarded projection','start_pc':advanced[0]['pc'],'end_pc':path['pc']}]
        seams=[{'from_pc':8398,'to_pc':8400,'kind':'guarded_call_return',
                'guard':evidence['fused_call_frontier']['pending_contracts'],
                'source':'reviewed source93 normal-return frame; no actual assertion call'},
            {'from_pc':middle['frontier_pc'],'to_pc':advanced[0]['pc'],'kind':'same_boundary_snapshot',
                'guard':['same code/metadata snapshot and path conditions','capture havoc retained'],
                'source':'guarded_continuation boundary and advanced explorer input'}]
        seams_audit=continuity(segment_list,seams)
        guards=[{'expression':{'atom':f'premise:{g["name"]}'},'truth':g['truth']}
                for g in path['conditions'] if g['kind']=='atom']
        guards.append({'expression':truth(evidence['fused_call_frontier']['argument_expressions'][0]),
            'truth':True,'source':'necessary truth condition for reviewed standard assertion normal return'})
        guards += [{'expression':{'atom':'root-prefix-premise:'+key(row)},'truth':True} for row in assumptions]
        nonboolean=[g for g in path['conditions'] if g['kind']!='atom']
        guards += [{'expression':r['expression'],'truth':r['truth']} for r in ledger if type(r['truth'])is bool]
        gaps=['V@981 occurrence/arrival and temporal order to8521',
              'same activation and reaching definition of V@981',
              'all native, field, lazy/cache/code-epoch and no-reflection premises']
        if nonboolean:gaps.append('non-Boolean interval conditions require separate numeric solver')
        paths.append({'path_index':index,'call_pc':path['pc'],'callee':516,'guard_predicates':guards,
            'nonboolean_conditions':nonboolean,'continuity':seams_audit,
            'advanced_trace':advanced,'query':predicate_query(guards,gaps),
            'start981_to_call':temporal_relation(trace+middle['trace']+advanced,981,path['pc'])})
    slots={name:array[980] for name,array in evidence['analysis_arrays']['664'].items()}
    return {'entry_pc':trace[0]['pc'],'root_branches':ledger,'root_environment_assumptions':assumptions,
        'middle_projection':middle,
        'source981_snapshot':{'pc':981,'arrays':slots,'visited':any(e['pc']==981 for e in trace),
            'interpretation':'epoch-specific stream tuple only; do not infer an outgoing edge with missing V/cache state'},
        'caller_paths':paths,'complete_981_to_516_branch_sequence_available':False,
        'absolute_barrier_proved':False,'positive_bridge_proved':False}


def interprocedural_audit(root,refinement,epoch):
    rows=[];seen=set()
    for analysis in refinement['parent_analyses']+refinement['parent_continuations']:
        for path in analysis['paths']:
            ledger=branch_ledger(path['trace'],'caller516:guarded-invocation')
            front=path['frontier'];call=front.get('call',{});target=call.get('callee_expression',{})
            endpoints=[]
            if isinstance(target,dict) and target.get('symbolic_closure')in (544,258):
                endpoints.append((path['pc'],target['symbolic_closure'],len(path['trace'])))
            for index,event in enumerate(path['trace']):
                if 'upstream_return_binding'in event and event['pc']==162:
                    endpoints.append((162,544,index))
            for pc,owner,limit in endpoints:
                # For call162 omit conditions evaluated AFTER that call/return.
                local=[r for r in ledger if r['step']<limit and type(r['truth'])is bool]
                signature=key([pc,owner,[(r['expression'],r['truth']) for r in local]])
                if signature in seen:continue
                seen.add(signature)
                local_guards=[{'expression':r['expression'],'truth':r['truth']} for r in local]
                for caller in root['caller_paths']:
                    combined=caller['guard_predicates']+local_guards
                    rows.append({'caller_pc':pc,'callee':owner,'local_branch_sequence':local,
                        'entry_query':predicate_query(combined,caller['query']['open_obligations']+[
                            'actual516 invocation, source target/cache and call-frame identity']),
                        'local_arithmetic':deepcopy(epoch['controlled_intersections'][0]['windows']) if (owner,pc)==(544,162) else
                            {'kind':'separate invocation; call162 affine proof not reused'} if owner==544 else
                            {'kind':'immediate/lazy arguments to parameters20..21'},
                        'normal_return_claimed':False,'entry_vs_return':'SAT entry is not a normal-return proof'})
    return rows


def run(source,data,output):
    if any(p.resolve()in {source.resolve(),data.resolve()} for p in (output,output/'path-reachability.json')):
        raise ValueError('Output aliases input')
    epoch=epoch_run(source,data,output/'epoch')
    text=source.read_text(encoding='ascii');anchors=[{'offset':text.index(a),'text':a} for a in ANCHORS]
    base=output/'epoch/inversion'
    forward=json.loads((base/'forward/checkpoint-alignment.json').read_text(encoding='utf-8'))
    refinement=json.loads((base/'refinement/path-refinement.json').read_text(encoding='utf-8'))
    automated=json.loads((base/'refinement/upstream/caller/automated-analysis.json').read_text(encoding='utf-8'))
    root=root_path_audit(forward,automated)
    result={'source_sha256':epoch['source_sha256'],'data_sha256':epoch['data_sha256'],
        'source_evidence':anchors,'root_path_audit':root,
        'interprocedural_queries':interprocedural_audit(root,refinement,epoch),
        'guarded_normal_return_certificates':refinement['guarded_route_certificates'],
        'candidate_solution':epoch['candidate_solution'],'global_gate_matrix':epoch['global_gate_matrix'],
        'numeric_filters_admitted':[],'verified_hierarchy':None,
        'formal_promotion_patch':{'applicable':False,'operations':[]},'positive_bridge_proved':False,
        'network_requests':0,'factory_invocations':0,'application_calls_executed':0}
    output.mkdir(parents=True,exist_ok=True)
    (output/'path-reachability.json').write_text(json.dumps(result,indent=2,allow_nan=False)+'\n',encoding='utf-8')
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,default=Path('output/stage1-vm-source.lua.txt'))
    p.add_argument('--data',type=Path,default=Path('output/stage1-vm-data.bin'))
    p.add_argument('--output',type=Path,default=Path('output/phase34'))
    a=p.parse_args();r=run(a.source,a.data,a.output)
    print(json.dumps({'candidates':r['candidate_solution']['model_count'],
        'interprocedural_queries':len(r['interprocedural_queries']),'positive_bridge_proved':r['positive_bridge_proved']}))
