"""Phase20 bounded inter-block provenance and scoped alias obligations, offline.

These are dataflow analyses of exported text/arrays, never an interpreter.
Snapshot predecessor candidates and local SAT witnesses do not prove activation.
"""
import argparse
import json
from pathlib import Path
import tempfile

import obligation_resolver as phase14
from lineage_auditor import BRANCH, VARARGS, coupled_masks, directory_step
from prologue_analyzer import mix
from reader_tracer import parse_loader
from register_slicer import RegisterSlicer
from scope_tracer import instruction, successors
from string_resolver import read_length_payload

DIRECTORY_XOR = 306486104
CLUSTER = (567, 258, 379)


def recorded_blocks(trace):
    """Observed straight-line segments; edges carry trace order, not PC order.

    A segment is cut at variant changes, non-unit steps or explicit conditions.
    This graph contains only observed edges, never all possible CFG edges.
    """
    blocks, membership, edges = [], [], []
    for step, event in enumerate(trace):
        previous = trace[step-1] if step else None
        cut = previous is None or event['variant'] != previous['variant'] or event['pc'] != previous['pc']+1 or 'unresolved_condition' in previous
        if cut:
            blocks.append({'id':len(blocks), 'first_step':step, 'last_step':step,
                           'entry_pc':event['pc'], 'exit_pc':event['pc'], 'variant':event['variant']})
            if previous is not None:
                edges.append({'from':len(blocks)-2, 'to':len(blocks)-1,
                              'from_pc':previous['pc'], 'to_pc':event['pc'], 'to_step':step})
        blocks[-1].update(last_step=step, exit_pc=event['pc'])
        membership.append(len(blocks)-1)
    return {'blocks':blocks, 'step_to_block':membership, 'edges':edges,
            'complete_cfg':False, 'scope':'recorded path; repeated PC occurrences remain distinct'}


def interblock_slice(trace, register, before_step=None):
    graph = recorded_blocks(trace)
    sliced = RegisterSlicer(664, trace).slice(register=register, before_step=before_step)
    for node in sliced['nodes']:
        node['block'] = graph['step_to_block'][node['step']] if 'step' in node else 'frame_entry'
    index = {node['id']:node for node in sliced['nodes']}
    sliced['cross_block_dependencies'] = [
        {'definition':node['id'], 'dependency':dep, 'from_block':index[dep]['block'], 'to_block':node['block']}
        for node in sliced['nodes'] for dep in node['deps'] if index[dep]['block'] != node['block']]
    return {'graph':graph, 'slice':sliced, 'at_unvisited980_proved':False}


def transfer(inst, variant, register):
    """Backward transfer: exact copies/literals, arithmetic stops, unknown kills.

    Return a source register or terminal definition. Parallel copies use the
    predecessor state, including overlapping source/destination ranges.
    """
    op,a,b,c = inst
    copies, literals = {}, {}
    if (variant,op) in ((157,34),(163,147)): copies[a] = b
    elif (variant,op) == (228,31): copies[c] = b
    elif (variant,op) == (157,84): copies = {b:a,b+1:c}
    elif (variant,op) in ((163,109),(228,23)): copies = {c:a,c+1:b}
    elif (variant,op) == (157,69): literals[a] = b
    elif (variant,op) == (163,62): literals[c] = a
    elif (variant,op) == (228,139): literals[a] = c
    elif (variant,op) == (228,134): literals = {c:a,c+1:b}
    elif (variant,op) in ((163,83),(228,21),(228,122)):
        if register == c: return {'terminal':'arithmetic_definition', 'instruction':inst}
    elif variant == 228 and op >= 196 and op != 197:
        if register == a: return {'terminal':'xor_definition', 'source_register':b, 'immediate':c}
    elif (variant,op) not in ((157,140),(163,30),(228,70),
                            (157,129),(163,24),(228,32),(163,78),(228,13),
                            (228,172),(228,78),(228,132),(228,125),(228,74)):
        return {'terminal':'unreviewed_transfer', 'instruction':inst}
    if register in literals: return {'terminal':'literal_definition', 'value':literals[register]}
    return {'source_register':copies.get(register, register)}


def snapshot_lineage(arrays, target_pc, register, variant, budget=2048):
    """Bounded worklist over (PC-before-instruction, register) product graph.

    Only reviewed normal successor edges are included. Missing incoming edges
    remain open-world; reaching a graph leaf never implies a nil initialization.
    """
    limit = min(map(len, arrays.values()))
    if type(budget) is not int or not 1 <= budget <= 10000 or not 1 <= target_pc <= limit:
        raise ValueError('Invalid lineage bounds')
    pred = {pc:[] for pc in range(1,limit+1)}
    for pc in pred:
        inst = instruction(arrays,pc,variant)
        destinations = successors(pc,inst,variant)
        if variant == 228 and inst[0] == 172: destinations = [pc+1,inst[2]+1]
        if variant == 228 and inst[0] in (125,74): destinations = [pc+1]
        for dest in set(destinations):
            if dest in pred: pred[dest].append(pc)
    queue, visited, edges, terminals = [(target_pc,register)], set(), [], []
    while queue and len(visited) < budget:
        pc, reg = queue.pop()
        if (pc,reg) in visited: continue
        visited.add((pc,reg))
        if not pred[pc]:
            terminals.append({'pc':pc, 'register':reg, 'terminal':'open_predecessor_frontier'})
        for previous in pred[pc]:
            result = transfer(instruction(arrays,previous,variant),variant,reg)
            if 'terminal' in result:
                terminals.append({'pc':previous, 'register':reg, **result})
            else:
                source = result['source_register']
                edge = {'before_pc':pc, 'register':reg, 'predecessor_pc':previous, 'source_register':source}
                inst = instruction(arrays,previous,variant)
                if variant == 228 and inst[0] == 172:
                    edge['predicate'] = {'register':inst[1], 'numeric_required':True,
                                         'operator':'<' if pc==previous+1 else '>=', 'constant':inst[3]}
                    # Identical successors do not constrain the truth value.
                    if previous+1 == inst[2]+1: edge['predicate'] = {'numeric_required':True,'truth_unconstrained':True}
                elif variant == 228 and inst[0] in (125,74):
                    edge['predicate'] = {'normal_patch_reader_completion_required':True}
                edges.append(edge)
                queue.append((previous,source))
    return {'target_pc':target_pc, 'input_register':register, 'variant':variant,
            'visited_states':len(visited), 'budget_exhausted':any(item not in visited for item in queue),
            'edges':edges, 'terminals':terminals, 'all_incoming_edges_known':False,
            'entry_reachability_proved':False,
            'guards':['fixed rewritten snapshot and dispatcher', 'normal return at guarded patch edges',
                      'branch predicates on chosen predecessor edges', 'unknown handlers/rewrites may add edges']}


def payload_guard(backing, position):
    try:
        payload, begin = read_length_payload(backing,position)
    except (ValueError, IndexError) as error:
        return {'position':position, 'bounded_length_payload':False, 'reason':str(error)}
    return {'position':position, 'bounded_length_payload':True, 'payload_begin':begin,
            'payload_length':len(payload), 'payload_end':begin+len(payload),
            'tag_type_and_cache_activation_verified':False}


def local_guard_models(backing, position, directory_before):
    """Solve numeric/byte-key/bounded-payload guards, separately from activation.

    V enumerates the proven uint32 inverse domain, not a small arbitrary range.
    A witness changes directory history explicitly; it never patches a file.
    Tag dispatch, cache state, reachability and reference74 remain obligations.
    """
    payload = payload_guard(backing,position)
    required = position ^ DIRECTORY_XOR if type(position) is int and 0 <= position < len(backing) else None
    from fused_call_analyzer import mask_word_domain
    states = mask_word_domain(53)
    numeric_models = [{'V':state, 'r9':0, 'r88':0, 'r13':38,
                       'key101':53^mix(state), 'key74':4^mix(state),
                       'scope':'numeric and byte-key guards only; no reaching definitions inferred'}
                      for state in (min(states),max(states))]
    result = {'payload_guard':payload, 'required_directory_before':required,
              'current_directory_before':directory_before,
              'current_directory_matches':required is not None and directory_before == required,
              'numeric_models':numeric_models, 'local_models':[], 'actual_path_proved':False,
              'unsatisfied_obligations':['entry-to978 reachability','reaching r9/r88/V definitions',
                  'directory mutation history','string tag/cache activation','normal patch74 reader guards']}
    if payload['bounded_length_payload']:
        for model in numeric_models:
            result['local_models'].append({**model,
                'directory101_before':required,
                'scope':'conditional numeric and bounded-length witness only; no inferred runtime assignment'})
    return result


def cluster_audit(bindings, constraints, trace, candidates):
    """Frame identity, guarded construction interval, and captured body aliases.

    No-effect observations in an incomplete prefix never imply purity or a
    whole-lifetime guarantee. Capture reads use exact reviewed opcode163/22.
    """
    cell = 'frame:664:register:107'
    graph = recorded_blocks(trace)
    rows = []
    for child in CLUSTER:
        binding = next(row for row in bindings if row['child']==child)
        ordinal = next((i for i,capture in enumerate(binding['captures'],1) if capture.get('cell_identity')==cell),None)
        steps = [step for step,event in enumerate(trace) if event['pc']==binding['pc'] and
                 any(type(write['value']) is dict and write['value'].get('symbolic_closure')==child
                     for write in event.get('register_writes',[]))]
        if len(steps) != 1: raise ValueError('Ambiguous or missing construction event')
        start = steps[0]
        before = [write for event in trace[:start] for write in event.get('register_writes',[]) if write['register']==107]
        writes = [{'pc':event['pc'], 'step':step, 'value':write['value']}
                  for step,event in enumerate(trace) if step>=start
                  for write in event.get('register_writes',[]) if write['register']==107]
        # Snapshot constraints record values of capture cells at the frontier.
        # A closure body stored in such a cell is an alias held by another closure.
        aliases = [{'holder_child':row['child'], 'capture_ordinal':capture['capture_ordinal'],
                    'cell_identity':capture['cell_identity']}
                   for row in constraints for capture in row['captures']
                   if type(capture.get('frontier_value')) is dict and
                   capture['frontier_value'].get('symbolic_closure')==child]
        candidate = next((row for row in candidates if row['owner']==child),None)
        child_trace = candidate['analysis']['trace'] if candidate else []
        reads = [{'pc':event['pc'], 'destination':event['operand3'], 'capture_ordinal':event['H']}
                 for event in child_trace if (event['variant'],event['opcode'])==(163,22) and event['H']==ordinal]
        rows.append({'child':child, 'construction_pc':binding['pc'], 'construction_step':start,
            'construction_block':graph['step_to_block'][start], 'shared_cell':cell,
            'capture_ordinal':ordinal, 'last_direct_value_before_construction':before[-1]['value'] if before else None,
            'direct_writes_in_recorded_interval':writes,
            'direct_prefix_stability':ordinal is not None and not writes,
            'body_aliases_in_other_closures':aliases, 'hypothetical_child_capture_reads':reads,
            'child_trace_scope':candidate['guard'] if candidate else 'no recorded child entry',
            'child_stop':candidate['analysis']['stop'] if candidate else None,
            'activation_witness':None, 'all_alias_effects_covered':False,
            'whole_lifetime_stable':None, 'unconditional_ancestry_proved':False})
    return {'cell':cell, 'members':rows, 'identity_shared':all(row['capture_ordinal'] is not None for row in rows),
            'stability_scope':'direct writes between guarded construction and recorded root frontier only',
            'missing_proofs':['actual invocation and order','all shared-cell writer effects',
                'alias escape/close/rebinding coverage','all-path lifetime and unconditional ancestry'],
            'formal_promotion_patch':{'applicable':False,'operations':[]}}


def run(source, data, output):
    if output.resolve() in (source.resolve(),data.resolve()): raise ValueError('Output aliases input')
    target = output/'interblock-proofs.json'
    if target.resolve() in (source.resolve(),data.resolve()): raise ValueError('Output aliases input')
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        report = phase14.run(source,data,root/'phase14',include_analysis_arrays=True)
        # Build the backing through the same reviewed reconstruction, not by
        # trusting output left by an earlier phase or a user's working file.
        from reconstructor import run as reconstruct
        reconstruct(source,data,root/'backing',[664])
        backing = (root/'backing/record-664.backing-postfill.bin').read_bytes()
    text = source.read_text(encoding='ascii')
    if VARARGS not in text or BRANCH not in text: raise ValueError('Source contracts missing')
    arrays = report['analysis_arrays']['664']
    expected = {978:(125,101,53,109),979:(172,88,112,66),980:(14842,13,9,38),981:(125,74,4,47)}
    if any(instruction(arrays,pc,228)!=value for pc,value in expected.items()):
        raise ValueError('Guarded local window differs')
    trace = report['root_analysis']['trace']
    copy_steps = [i for i,e in enumerate(trace) if e['pc']==9910 and (e['variant'],e['opcode'])==(163,109)]
    if len(copy_steps)!=1: raise ValueError('Ambiguous PC9910 copy')
    loader = parse_loader(data.read_bytes())
    directory = directory_step(101,loader['lookup_entries'],report['path_local_patch_events'],len(backing))
    models = local_guard_models(backing,loader['lookup_entries'][100]['value'],directory['before'])
    result = {'source_sha256':report['source_sha256'],'data_sha256':report['data_sha256'],
        'recorded_r9_lineage':interblock_slice(trace,9),
        'recorded_r35_before9910':interblock_slice(trace,35,copy_steps[0]),
        'snapshot_r35_predecessors':snapshot_lineage(arrays,9910,35,163),
        'guard978':{'directory':directory,'local_constraints':models,'shared_V':coupled_masks(53,4),
                    'predicates':{'979':'numeric r88 < 66', '980':'r9 accepts bit32 numeric conversion',
                                  'shared_V':'same uint32 V at978 and981; both patch keys are bytes',
                                  '978':'directory XOR and payload readers complete under current tag/cache state'},
                    'window':expected,'numeric_r9_proved_at980':False},
        'root107_cluster':cluster_audit(report['guarded_closure_bindings'],report['capture_frame_constraints'],
                                      trace,report['candidate_entry_analyses']),
        'frontier_call':report['fused_call_frontier'], 'verified_hierarchy':None,
        'network_requests':0,'application_calls_executed':0,'factory_invocations':0}
    output.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps(result,indent=2,allow_nan=False)+'\n',encoding='utf-8')
    return result


if __name__=='__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=Path('output/stage1-vm-source.lua.txt'))
    parser.add_argument('--data',type=Path,default=Path('output/stage1-vm-data.bin'))
    parser.add_argument('--output',type=Path,default=Path('output/phase20'))
    args = parser.parse_args()
    result = run(args.source,args.data,args.output)
    print('Conditional guard models:',len(result['guard978']['local_constraints']['local_models']))
    print('Hierarchy promotion:',result['root107_cluster']['formal_promotion_patch']['applicable'])
