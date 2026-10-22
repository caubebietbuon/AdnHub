"""Phase27 scoped gate proofs, conditional paths and numeric handoff refutation.

Python static relations only. No Lua, actual assertion, field lookup, factory,
closure, __index or application function is invoked. Unknown calls stay opaque.
"""
import argparse
from copy import deepcopy
import json
from pathlib import Path
import tempfile

from checkpoint_aligner import run as checkpoint_run
from checkpoint_filter import uint32, mix
from fused_call_analyzer import inverse_mix, mask_word_domain
from obligation_resolver import patch_equation
from provenance_bridge import analyze as bridge_analysis
from scope_tracer import instruction


FRAME_CELLS = 'local V,m,k=W[1];local y,t=W[2],D(h);'
CELL_RULE = 'if jJ==3 then bJ=bJ or{};local oJ=bJ[OJ];if oJ then else oJ={[6]=t,[5]=OJ};bJ[OJ]=oJ;end;f[wJ]=oJ;'
CLOSE_RULE = 'xJ[6]=xJ;xJ[4]=t[f];xJ[5]=4;k[f]=nil;'


def numeric_handoff(operand, key, entry_v, site_operand=4):
    """Refute unchanged-state transport, not all paths to an unvisited site."""
    operand, entry_v, site_operand = map(uint32,(operand,entry_v,site_operand))
    if type(key) is not int or not 0<=key<=255:
        raise ValueError('Expected observed byte mask')
    image = operand ^ key
    if image>=2**29 or operand ^ mix(entry_v)!=key:
        raise ValueError('Observed mask contradicts the reviewed entry state')
    entries, sites = inverse_mix(image), mask_word_domain(site_operand)
    if not sites: raise ValueError('Empty site domain; no nonvacuous delta proof')
    overlap = sorted(set(entries)&set(sites))
    all_one = 0xffffffff
    all_zero = 0xffffffff
    distances = []
    for value in sites:
        delta = value ^ entry_v
        all_one &= delta
        all_zero &= ~delta & 0xffffffff
        distances.append(delta.bit_count())
    return {'observed_operand':operand,'observed_key':key,'entry_V':entry_v,
        'mixer_image':image,'entry_mask_preimages':entries,'entry_mask_preimage_count':len(entries),
        'site_operand':site_operand,'site_candidate_count':len(sites),
        'unchanged_handoff_intersection':overlap,
        'unchanged_handoff_refuted':not overlap,
        'required_changed_bits':[bit for bit in range(32) if all_one & (1<<bit)],
        'required_unchanged_bits':[bit for bit in range(32) if all_zero & (1<<bit)],
        'entry_to_site_hamming_bounds':[min(distances),max(distances)] if distances else None,
        'site_candidates_pruned':0,'remaining_site_candidates':sites,
        'implication':'if the same invocation reaches the current byte-key site model, its V differs from the entry state',
        'rejected_combination':['recorded entry mask equation','unchanged V to981',
                                'arrival at the current PC981 byte-key equation'],
        'scope':'conditional equation/epoch model; does not individually refute arrival or an unobserved V write'}


def capture_plan(bindings):
    """Translate source kind3 reuse in one fresh, guarded open-cell map.

    This does not model subsequent closes, escaping aliases, actual cache
    objects or calls. Its no-unmodeled-map-effects premise remains explicit.
    """
    cells, events, seen = {}, [], set()
    for binding in bindings:
        pc = binding['pc']
        if type(pc) is not int or pc in seen:
            raise ValueError('Distinct ordered construction observations required')
        seen.add(pc)  # Caller supplies trace order; do not sort by numeric PC.
        if binding['parent']!=664 or binding['variant']!=228:
            raise ValueError('Unreviewed capture context')
        bounds = binding['capture_bounds']
        if len(bounds)!=len(binding['captures']): raise ValueError('Capture count mismatch')
        for ordinal,(bound,capture) in enumerate(zip(bounds,binding['captures']),1):
            if bound['kind']!=3 or capture.get('span')!=1:
                raise ValueError('Only reviewed scalar kind3 cells are modeled')
            register,end = bound['index_range']
            if (type(register) is not int or type(end) is not int or register<0 or end!=register+1
                    or capture.get('cell_identity')!=f'frame:664:register:{register}'):
                raise ValueError('Capture address/range mismatch')
            created = register not in cells
            if created: cells[register]=f'cell:{register}:created-at:{pc}'
            events.append({'child':binding['child'],'pc':pc,'ordinal':ordinal,'register':register,
                           'action':'create' if created else 'reuse','object':cells[register]})
    return {'events':events,'final_open_cells':cells,'conditional_proof':True,
        'premises':['same guarded root invocation and descriptor observations',
                    'fresh local k at entry','no unmodeled close/rebind/map mutation before these constructions'],
        'unconditional_lifetime_proof':False,'actual_cell_objects_inspected':False}


def assertion_cases(first_argument):
    truth = None
    if type(first_argument) is bool: truth = first_argument
    elif type(first_argument) in (int,float,str): truth = True
    elif first_argument=={'literal_nil':True}: truth = False
    return {'normal':{'guard':['context109 is the reviewed standard assertion',
                               'first argument is truthy'],
                      'first_result':deepcopy(first_argument),'exception_taken':False,
                      'normal_return_possible_under_binding':truth},
            'falsey':{'guard':['context109 is the reviewed standard assertion',
                               'first argument is nil or false'],
                      'normal_return_possible':False,'actual_branch_proved':False},
            'different_binding':{'normal_return_possible':None,'effects':'opaque'},
            'actual_branch_proved':False,'assertion_invoked':False}


def guarded_continuation(arrays, registers, frame, budget=32):
    """Static fixed-epoch projection of an explicitly guarded assertion return.

    Copies/literals/jumps and symbolic field expressions only. A constructor,
    unknown opcode, unknown jump or cycle is a boundary. No field is accessed.
    """
    if type(budget) is not int or not 1<=budget<=128: raise ValueError('Invalid path budget')
    if not (frame['pc']==8398 and frame['opcode']==93 and frame['callee_register']==2
            and frame['callee_expression']=={'decoder_context_slot':109}
            and frame['argument_range_half_open']==[3,5] and frame['requested_results']==1
            and frame['normal_return_pc']==8400 and frame['pre_call_copy']=={'destination':2,'source':5}
            and registers.get(5)=={'decoder_context_slot':109}):
        raise ValueError('Unreviewed assertion frontier')
    values = deepcopy(registers)
    cases = assertion_cases(values.get(3))
    if 3 not in values: raise ValueError('Missing symbolic assertion argument')
    if cases['normal']['normal_return_possible_under_binding'] is False:
        return {'assertion_cases':cases,'trace':[],'frontier_pc':8398,
            'stop':'refuted_normal_assertion_case','assumed_variant':228,
            'normal_prefix_proved_unconditionally':False,'conditions':cases['normal']['guard'],
            'last_register_values':None,'capture_values_preserved':False,'actual_activation_proved':False}
    values[2] = deepcopy(values[3])
    pc, trace, visited = frame['normal_return_pc'], [], set()
    limit = min(map(len,arrays.values()))
    reason = 'budget'
    for _ in range(budget):
        if not 1<=pc<=limit: reason='outside_snapshot'; break
        if pc in visited: reason='cycle_boundary'; break
        visited.add(pc)
        op,a,b,c = instruction(arrays,pc,228)
        row = {'pc':pc,'variant':228,'instruction':[op,a,b,c],'writes':[],
               'conditions':[],'application_call_executed':False}
        trace.append(row)
        if op==31:
            if b not in values: reason='unknown_copy_source'; break
            values[c]=deepcopy(values[b]); row['writes']=[{'register':c,'value':values[c]}]
        elif op==139:
            values[a]=c; row['writes']=[{'register':a,'value':c}]
        elif op==95:
            if c not in values or values[c] is None: reason='unknown_field_base'; break
            values[b]={'symbolic_field':{'base':deepcopy(values[c]),'key_reference':a}}
            row['writes']=[{'register':b,'value':values[b]}]
            row['conditions']=['lazy key/cache binding agrees with this epoch','field read succeeds']
            row['escaping_alias_effects']='unmodeled; no capture-value preservation is inferred'
        elif op==32:
            pc=a+1; row['successor']=pc; continue
        elif op in (89,92):
            register=a if op==89 else b
            target=values.get(register)
            if type(target) is not int or not 0<=target<limit:
                reason='unknown_or_outside_jump'; break
            pc=target+1; row['successor']=pc; continue
        else:
            reason='unreviewed_instruction_boundary'; break
        pc+=1
        row['successor']=pc
    return {'assertion_cases':cases,'trace':trace,'frontier_pc':pc,'stop':reason,
            'assumed_variant':228,'normal_prefix_proved_unconditionally':False,
            'conditions':cases['normal']['guard']+['unchanged root snapshot/dispatcher along this projection'],
            'last_register_values':values,'capture_values_preserved':False,'actual_activation_proved':False}


def parse_open_matrix(text):
    """Verify the historical inventory, never treat Markdown prose as proof."""
    found, all_rows = [], set()
    for line in text.splitlines():
        if not line.startswith('|'): continue
        cols=[c.strip() for c in line.strip().strip('|').split('|')]
        if cols[0] in ('Parent gate','---'): continue
        if len(cols)!=4: raise ValueError('Malformed sub-gate table row')
        identity=cols[0]+'/'+cols[1]
        if identity in all_rows: raise ValueError('Duplicate sub-gate')
        all_rows.add(identity)
        if cols[2]=='open':
            if cols[3]!=identity: raise ValueError('Stale predicate identity')
            found.append(identity)
        elif cols[2]!='established_local_evidence': raise ValueError('Unknown gate status')
    if not found: raise ValueError('No open sub-gates')
    return sorted(found)


RECIPES = {
 'template_at_invocation':('incoming invocation and template/cache identity', 'byte hash equality does not identify a live cache object'),
 'entry_call_path':('entry-reaching path in the same code epoch', 'constructor visitation is not invocation'),
 'all_lexical_owners':('complete lexical owner inventory', 'one observed owner cannot exclude all others'),
 'incoming_call_witness':('a reachable callee resolved to663', 'the root assertion frontier is not a663 call under the reviewed binding'),
 'incoming_path_predicates':('all predicates for that incoming call', 'falsey standard-assert case has no normal successor'),
 'call_time_callee_value':('callee reaching definition at a663 invocation', 'under the reviewed assertion binding, context109 is not the root85 closure value'),
 'incoming_arity_and_values':('actual incoming argument tuple', 'the outgoing206490123 tuple belongs to a different call'),
 'incoming_type_predicates':('source requirements for the incoming values', 'symbolic argument copies are not numeric/default-value proofs'),
 'call_time_storage_and_values':('all capture storage/value definitions reaching that invocation', 'frontier159/105 snapshots cannot freeze future alias values'),
 'live_shared_cache_identity':('object identity and cache effects through invocation', 'post-fill backing is not the saved pre-fill template'),
 'plain_context_binding':('actual constructor decoder-context binding', 'alias-only source does not prove an arbitrary context object plain'),
 'open_cell_reuse_and_order':('guarded construction prefix without hidden map effects', 'allocation order can be proved locally without proving the full lifetime'),
 'escaping_and_future_alias_writes':('complete escaping writer/path coverage', 'zero direct prefix writes does not exclude alias writes'),
 'all_reaching_call_definitions':('all incoming-call definitions and epoch conditions', 'a sampled prefix is not the all-path reaching-definition set'),
 'all_exit_reachability':('all normal/error/nonreturn exit paths', 'candidate return sites are not reached-exit witnesses'),
 'close_rebase_at_call':('close/rebind history up to invocation', 'source closing preserves the same cell object and changes storage'),
 'all_call_outcomes':('callee results/effects for all reachable outcomes', 'a normal continuation alone does not cover errors or nonreturn'),
 'all_owners_excluded':('global unique-parent evidence', 'shared descriptors/factories do not exclude competing ownership'),
 'full_reachable_inventory':('complete reachable prototype inventory', 'hypothetical frame samples are not coverage proof'),
 'all_verified_edges_complete':('complete verified-edge graph', 'acyclic sampled edges do not prove completeness'),
}


def analyze(report, source_text, matrix_text):
    fragments=[{'offset':source_text.index(fragment),'text':fragment} for fragment in (FRAME_CELLS,CELL_RULE,CLOSE_RULE)]
    bridge=bridge_analysis(report)
    evidence=report['provenance_inputs']
    trace=evidence['root_analysis']['trace']
    equations=[(step,e) for step,e in enumerate(trace) if e['pc']==9840 and patch_equation(e) is not None]
    patches=[p for p in evidence['path_local_patch_events'] if p['pc']==9840]
    if len(equations)!=1 or len(patches)!=1: raise ValueError('Unique mixed-route patch required')
    step,event=equations[0]
    word,reference,operand=patch_equation(event)
    if word!='V' or reference!=patches[0]['reference_id']: raise ValueError('Unexpected route equation')
    numeric=numeric_handoff(operand,patches[0]['key'],event['state_words_before'][0])
    if any(e['state_words_before'][0]!=numeric['entry_V'] for e in trace):
        raise ValueError('Entry/frontier V changed; unchanged-prefix handoff must be reviewed')
    numeric['route_patch_evidence']={'trace_step':step,'event':event,'accepted_patch':patches[0]}
    plan=capture_plan(evidence['guarded_closure_bindings'])
    continuation=guarded_continuation(evidence['analysis_arrays']['664'],trace[-1]['registers_before'],
                                      evidence['fused_call_frontier'])
    opened=[gate['gate']+'/'+sub['name'] for gate in bridge['closure663_subgates']['gates']
            for sub in gate['subgates'] if sub['status']=='open']
    if sorted(opened)!=parse_open_matrix(matrix_text): raise ValueError('Historical matrix does not match fresh evidence')
    audits=[]
    for identity in sorted(opened):
        name=identity.rsplit('/',1)[1]
        need, warning=RECIPES[name]
        status='conditionally_proved_in_construction_model' if name=='open_cell_reuse_and_order' else 'open_with_diagnostics'
        refs=['conditional_continuation'] if name in ('entry_call_path','incoming_call_witness','incoming_path_predicates',
                   'call_time_callee_value','incoming_arity_and_values','incoming_type_predicates') else ['previous_register_contexts']
        if name=='open_cell_reuse_and_order': refs=['capture_plan','source_evidence']
        if name=='close_rebase_at_call': refs=['source_evidence','previous_register_contexts']
        audits.append({'identity':identity,'status':status,'unconditional_proof':False,
                      'required_evidence':need,'invalid_inference_rejected':warning,'evidence_refs':refs})
    new_cells=[e['register'] for e in plan['events'] if e['child']==663 and e['action']=='create']
    rejected_models=[
        {'model':'unchanged V across both mask equations','refuted':numeric['unchanged_handoff_refuted'],
         'scope':numeric['scope'],'evidence_ref':'numeric_handoff'},
        {'model':'falsey standard assertion returns normally','refuted':continuation['assertion_cases']['falsey']['normal_return_possible'] is False,
         'scope':'standard assertion binding plus falsey input; actual branch remains unknown',
         'evidence_ref':'conditional_continuation/assertion_cases'},
        {'model':'663 reuses already allocated159/105 in the guarded construction plan','refuted':new_cells==[159,105],
         'scope':plan['premises'],'evidence_ref':'capture_plan'},
        {'model':'the projected direct-instruction suffix invokes663 before its constructor boundary',
         'refuted':all(row['instruction'][0] not in (4,93) for row in continuation['trace']),
         'scope':'reviewed projection only; hidden field/metamethod effects and future code remain open',
         'evidence_ref':'conditional_continuation/trace'},
    ]
    return {'source_sha256':report['source_sha256'],'data_sha256':report['data_sha256'],
        'source_evidence':fragments,'numeric_handoff':numeric,'capture_plan':plan,
        'conditional_continuation':continuation,'subgate_audits':audits,'rejected_models':rejected_models,
        'previous_register_contexts':bridge['closure663_subgates']['register_contexts'],
        'open_inventory_count':len(audits),'conditionally_resolved_count':1,'unconditionally_resolved_count':0,
        'remaining_without_conditional_proof':len(audits)-1,
        'verified_hierarchy':None,'formal_promotion_patch':{'applicable':False,'operations':[]},
        'network_requests':0,'factory_invocations':0,'application_calls_executed':0,'input_byte_edits':0}


def run(source,data,output,matrix=None):
    target=output/'subgate-resolution.json'
    matrix=matrix or Path('research/provenance-bridge-2026-10-22/SUBGATE_MATRIX.md')
    if target.resolve() in (source.resolve(),data.resolve(),matrix.resolve()) or output.resolve() in (source.resolve(),data.resolve(),matrix.resolve()):
        raise ValueError('Output aliases input')
    with tempfile.TemporaryDirectory() as temporary:
        report=checkpoint_run(source,data,Path(temporary),include_provenance=True)
        result=analyze(report,source.read_text(encoding='ascii'),matrix.read_text(encoding='utf-8'))
    output.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps(result,indent=2,allow_nan=False)+'\n',encoding='utf-8')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=Path('output/stage1-vm-source.lua.txt'))
    parser.add_argument('--data',type=Path,default=Path('output/stage1-vm-data.bin'))
    parser.add_argument('--output',type=Path,default=Path('output/phase27'))
    args=parser.parse_args()
    result=run(args.source,args.data,args.output)
    print('Conditional proofs:',result['conditionally_resolved_count'])
    print('Remaining site candidates:',result['numeric_handoff']['site_candidate_count'])
    print('Guarded continuation frontier:',result['conditional_continuation']['frontier_pc'])
