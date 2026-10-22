"""Phase28 offline finite solving, symbolic worklist and certificate queries."""
import argparse
from pathlib import Path
import json
import tempfile

from automated_explorer import MetadataState, explore
from checkpoint_aligner import run as checkpoint_run
from finite_solver import export_formula, mask_constraints, solve
from gate_solver import query_gate
from gw_aligner import definitions
from reader_tracer import parse_loader
from reconstructor import run as reconstruct
from subgate_resolver import analyze as subgate_analysis


SOURCE_FRAGMENTS=(
    'else if o~=150 then t[A[f]]={};',
    'else if o<155 then t[A[f]][Z[f]]=j[f];',
    'i[W]=74;A[W]=144;H[W]=178;w[W]=68;',
    'if o<68 then t[H[W]](t[i[W]],t[A[W]]);else if o==69 then T=g[i[W]];T[6][T[5]][O[W]]=Z[W];else end;end;',
    'elseif o>=43 then if o==44 then t[i[W]](O[W],t[H[W]]);',
)


def gate_queries(previous,local_facts):
    """Query the remaining19 evidence obligations using shared unknown facts."""
    requirements={
        'template_at_invocation':['header-bytes-agree','actual663-invocation','live-template-identity'],
        'entry_call_path':['actual663-invocation','entry-control-predicates'],
        'all_lexical_owners':['complete-owner-inventory','unique-owner-proof'],
        'incoming_call_witness':['actual663-invocation','call-target-identity'],
        'incoming_path_predicates':['actual663-invocation','entry-control-predicates'],
        'call_time_callee_value':['actual663-invocation','call-target-identity'],
        'incoming_arity_and_values':['actual663-invocation','incoming-argument-values'],
        'incoming_type_predicates':['incoming-argument-values','incoming-type-proof'],
        'call_time_storage_and_values':['actual663-invocation','capture-reaching-definitions'],
        'live_shared_cache_identity':['actual663-invocation','live-template-identity','complete-cache-effects'],
        'plain_context_binding':['constructor-prefix-alias-only','live-context-identity'],
        'escaping_and_future_alias_writes':['complete-alias-effects','complete-path-coverage'],
        'all_reaching_call_definitions':['actual663-invocation','capture-reaching-definitions','complete-path-coverage'],
        'all_exit_reachability':['complete-path-coverage','exit-outcome-proof'],
        'close_rebase_at_call':['actual663-invocation','all-close-rebind-effects'],
        'all_call_outcomes':['complete-path-coverage','callee-results-and-effects'],
        'all_owners_excluded':['complete-owner-inventory','unique-owner-proof'],
        'full_reachable_inventory':['complete-owner-inventory','complete-path-coverage'],
        'all_verified_edges_complete':['complete-owner-inventory','complete-path-coverage','verified-edge-inventory'],
    }
    rows=[]
    for audit in previous['subgate_audits']:
        if audit['status']!='open_with_diagnostics': continue
        name=audit['identity'].rsplit('/',1)[1]
        rows.append(query_gate(audit['identity'],requirements[name],local_facts))
    if len(rows)!=19: raise ValueError('Unreviewed gate inventory')
    return rows


def activation_queries(paths,target=663):
    rows=[]
    for path in paths['terminal_paths']:
        for event in path['trace']:
            call=event.get('call_metadata')
            if call is None: continue
            callee=call['callee_expression']
            known_body=callee.get('symbolic_closure') if type(callee) is dict else None
            fact=None if type(known_body) is not int else known_body==target
            query=query_gate(f'call:{event["pc"]}:activates:{target}', ['callee-body-matches'], {'callee-body-matches':fact})
            query['guarded_path_conditions']=path['conditions']
            query['observed_callee_body']=known_body
            query['scope']='candidate call in the guarded metadata projection only; not all future activations'
            rows.append(query)
    return rows


def run(source,data,output,matrix=None):
    target=output/'automated-analysis.json'
    matrix=matrix or Path('research/provenance-bridge-2026-10-22/SUBGATE_MATRIX.md')
    protected={p.resolve() for p in (source,data,matrix)}
    if output.resolve() in protected or any((output/name).resolve() in protected for name in ('automated-analysis.json','constraints.smt2')):
        raise ValueError('Output aliases input')
    text=source.read_text(encoding='ascii')
    anchors=[{'offset':text.index(fragment),'text':fragment} for fragment in SOURCE_FRAGMENTS]
    with tempfile.TemporaryDirectory() as temporary:
        work=Path(temporary)
        report=checkpoint_run(source,data,work/'base',include_provenance=True)
        prior=subgate_analysis(report,text,matrix.read_text(encoding='utf-8'))
        constraints=mask_constraints(prior['numeric_handoff']['entry_V'],prior['numeric_handoff']['entry_to_site_hamming_bounds'])
        solution=solve(prior['numeric_handoff']['remaining_site_candidates'],constraints)
        reconstruct(source,data,work/'backing',[664])
        backing=(work/'backing/record-664.backing-postfill.bin').read_bytes()
        metadata=MetadataState(text,backing,parse_loader(data.read_bytes())['lookup_entries'],definitions(text)[0])
        evidence=report['provenance_inputs']
        metadata.replay_prefix(evidence)
        continuation=prior['conditional_continuation']
        registers=continuation['last_register_values']
        captured=sorted({c['parent_register'] for row in evidence['capture_frame_constraints'] for c in row['captures']
                         if c['parent_register'] is not None})
        # The previous field projection explicitly lacked a capture-value proof.
        for register in captured:
            if register in registers: registers[register]={'havoc_capture':register,'epoch':'pre8481'}
        premises=continuation['conditions']+['no-reflective-frame-code-cache-mutation']
        for row in continuation['trace']:
            premises += [f'{condition}:at:{row["pc"]}' for condition in row['conditions']]
        paths=explore(evidence['analysis_arrays']['664'],continuation['frontier_pc'],registers,metadata,
                      captured=captured,initial_conditions=[{'kind':'atom','name':s,'truth':True} for s in dict.fromkeys(premises)])
    template=evidence['guarded_template_evidence'][663]
    candidate=next(row for row in evidence['candidate_entry_analyses'] if row['owner']==663)
    queries=gate_queries(prior,{'header-bytes-agree':template['header']['plain_sha256']==candidate['candidate_plain_sha256'],
        'constructor-prefix-alias-only':template['constructor_contract']['body_executed'] is False})
    constructors=[event['constructor_metadata'] for path in paths['terminal_paths'] for event in path['trace']
                  if 'constructor_metadata' in event and 'child' in event['constructor_metadata']]
    result={'source_sha256':report['source_sha256'],'data_sha256':report['data_sha256'],
        'source_evidence':anchors,'constraints':constraints,'candidate_solution':solution,
        'symbolic_exploration':paths,'conditional_constructor_observations':constructors,
        'gate_queries':queries,'activation_candidate_queries':activation_queries(paths),
        'unconditionally_resolved_gates':[],
        'verified_hierarchy':None,'formal_promotion_patch':{'applicable':False,'operations':[]},
        'solver_scope':'complete finite necessary-condition model, not complete program reachability',
        'network_requests':0,'factory_invocations':0,'application_calls_executed':0,'input_byte_edits':0}
    output.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps(result,indent=2,allow_nan=False)+'\n',encoding='utf-8')
    (output/'constraints.smt2').write_text(export_formula(constraints),encoding='ascii')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=Path('output/stage1-vm-source.lua.txt'))
    parser.add_argument('--data',type=Path,default=Path('output/stage1-vm-data.bin'))
    parser.add_argument('--output',type=Path,default=Path('output/phase28'))
    args=parser.parse_args()
    result=run(args.source,args.data,args.output)
    print('Finite models:',result['candidate_solution']['model_count'])
    print('Frontiers:',[(p['pc'],p['reason']) for p in result['symbolic_exploration']['terminal_paths']])
    print('Gate queries:',{r['status'] for r in result['gate_queries']})
