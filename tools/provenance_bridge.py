"""Typed, bounded static provenance paths and closure663 sub-gate evidence.

Data dependencies, copies, captured addresses and control paths are distinct.
A mixed dependency path is never a numeric equality or an invocation witness.
"""
import argparse
from collections import deque
import json
from pathlib import Path
import tempfile

from checkpoint_aligner import run as checkpoint_run
from checkpoint_filter import analyze as filter_analysis, uint32
from fused_call_analyzer import mask_word_domain
from obligation_resolver import patch_equation
from register_slicer import RegisterSlicer
from scope_tracer import instruction
from symbolic_resolver import arrays_from_candidate


class EvidenceGraph:
    KINDS = {'copy','data','control','payload','address'}

    def __init__(self):
        self.nodes, self.edges, self.outgoing = {}, [], {}

    def node(self, identity, **evidence):
        if type(identity) is not str or not identity:
            raise ValueError('Node identity must be a nonempty string')
        if identity in self.nodes:
            raise ValueError('Duplicate evidence node')
        if len(self.nodes) >= 100000:
            raise ValueError('Node budget exceeded')
        self.nodes[identity] = evidence
        self.outgoing[identity] = []
        return identity

    def edge(self, source, target, kind, guards=()):
        if source not in self.nodes or target not in self.nodes or kind not in self.KINDS:
            raise ValueError('Invalid typed edge')
        if not isinstance(guards,(list,tuple)) or any(type(g) is not str or not g for g in guards):
            raise ValueError('Guards must be explicit names')
        if len(self.edges) >= 250000:
            raise ValueError('Edge budget exceeded')
        index = len(self.edges)
        self.edges.append({'source':source,'target':target,'kind':kind,'guards':sorted(set(guards))})
        self.outgoing[source].append(index)

    def path(self, source, target, kinds, discharged=(), conditional=False, budget=100000):
        """BFS on typed SSA/context identities, not PC numbers or register names.

        A no-path result is limited to the exported graph, which is incomplete.
        Conditional mode exposes unmet guards; it never discharges them.
        """
        if (not isinstance(kinds,(set,list,tuple)) or not kinds
                or source not in self.nodes or target not in self.nodes or not set(kinds) <= self.KINDS):
            raise ValueError('Invalid path query')
        if type(budget) is not int or not 1 <= budget <= 100000 or type(conditional) is not bool:
            raise ValueError('Invalid search budget/mode')
        if not isinstance(discharged,(set,list,tuple)) or any(type(g) is not str or not g for g in discharged):
            raise ValueError('Invalid discharged guards')
        discharged, pending, previous = set(discharged), deque([source]), {source:None}
        found = source == target
        expanded = 0
        while pending and not found and expanded < budget:
            current = pending.popleft()
            expanded += 1
            for index in self.outgoing[current]:
                edge = self.edges[index]
                if edge['kind'] not in kinds or (not conditional and set(edge['guards'])-discharged):
                    continue
                child = edge['target']
                if child in previous: continue
                previous[child] = index
                if child == target:
                    found = True
                    break
                pending.append(child)
        indices = []
        if found:
            current = target
            while current != source:
                index = previous[current]
                indices.append(index)
                current = self.edges[index]['source']
            indices.reverse()
        unmet = sorted({g for i in indices for g in self.edges[i]['guards']} - discharged)
        return {'source':source,'target':target,'status':'conditional_path' if found and unmet else
                'path_with_discharged_guards' if found else 'budget_exhausted' if pending else 'no_path_in_recorded_graph',
                'edge_indices':indices,'unmet_guards':unmet,'expanded_nodes':expanded,
                'copy_only_relation':found and all(self.edges[i]['kind']=='copy' for i in indices),
                'numeric_equality':found and not unmet and all(self.edges[i]['kind']=='copy' for i in indices),
                'global_absence_proved':False}


def filter_through_bridge(graph, source, target, value, candidates, observation_guards, discharged=()):
    """Only source->observed-value COPY identities justify equality filtering.

    Arithmetic/data/control/address routes require separate transfer equations;
    accepting their reachability as equality would be unsound.
    """
    value = uint32(value)
    domain = sorted({uint32(v) for v in candidates})
    if not isinstance(observation_guards,(set,list,tuple)) or any(type(g) is not str or not g for g in observation_guards):
        raise ValueError('Invalid observation guard')
    proof = graph.path(source,target,{'copy'},discharged)
    observation_unmet = sorted(set(observation_guards)-set(discharged))
    applicable = proof['status']=='path_with_discharged_guards' and not observation_unmet
    remaining = [v for v in domain if v == value] if applicable else domain
    return {'bridge':proof,'observation_guards_unmet':observation_unmet,'filter_applied':applicable,
            'initial_count':len(domain),'remaining_count':len(remaining),
            'pruned_count':len(domain)-len(remaining),'remaining_candidates':remaining}


def build_graph(report):
    evidence = report['provenance_inputs']
    frames = {664:evidence['root_analysis']}
    frames.update({row['owner']:row['analysis'] for row in evidence['candidate_entry_analyses']
                   if row['owner'] in (663,379,258,567)})
    graph, slicers, definitions, headers = EvidenceGraph(), {}, {}, {}
    for owner, frame in frames.items():
        trace = frame['trace']
        slicer = slicers[owner] = RegisterSlicer(owner,trace)
        prefix = f'guarded-prefix:{owner}'
        for node in slicer.nodes:
            graph.node(f'{owner}:ssa:{node["id"]}',owner=owner,ssa=node)
        for node in slicer.nodes:
            identity = f'{owner}:ssa:{node["id"]}'
            for dep in node['deps']:
                graph.edge(f'{owner}:ssa:{dep}',identity,'copy' if node['op']=='copy' else 'data',[prefix])
            if node['op']=='header_word': headers[(owner,node['word'])] = identity
            if 'register' in node and 'step' in node:
                definitions[(owner,node['step'],node['register'])] = identity
        for step, event in enumerate(trace):
            current = graph.node(f'{owner}:event:{step}',owner=owner,step=step,event=event)
            if step:
                graph.edge(f'{owner}:event:{step-1}',current,'control',[prefix])
            for write in event.get('register_writes',[]):
                graph.edge(current,definitions[(owner,step,write['register'])],'control',[prefix])
            equation = patch_equation(event)
            if equation and equation[0] is not None:
                state_node = slicer.before[step][1][equation[0]]
                graph.edge(f'{owner}:ssa:{state_node}',current,'data',[prefix])
    # Constructors expose a possible invocation boundary, never an actual call.
    for binding in evidence['guarded_closure_bindings']:
        child = binding['child']
        if child not in frames: continue
        matches = [(step,event) for step,event in enumerate(frames[664]['trace'])
                   if event.get('symbolic_closure_creation',{}).get('child')==child]
        if len(matches)!=1: raise ValueError('Ambiguous construction context')
        step,event = matches[0]
        graph.edge(f'664:event:{step}',f'{child}:event:0','control',
                   [f'actual-invocation:{child}',f'live-template-and-cells:{child}'])
        template = evidence['guarded_template_evidence'].get(str(child),
                    evidence['guarded_template_evidence'].get(child))
        template_node = graph.node(f'template:{child}',owner=child,
                                  plain_sha256=template['header']['plain_sha256'])
        patches = [row for row in evidence['path_local_patch_events'] if row['reference_id']==child]
        for patch in patches:
            positions = [s for s,e in enumerate(frames[664]['trace']) if e['pc']==patch['pc']]
            if len(positions)!=1: raise ValueError('Patch visit identity ambiguous')
            graph.edge(f'664:event:{positions[0]}',template_node,'payload',['guarded-prefix:664',
                       f'template-read-before-fill:{child}'])
        for word in ('V','y'):
            graph.edge(template_node,headers[(child,word)],'payload',[f'cached-header-matches:{child}'])
        for ordinal, capture in enumerate(binding['captures'],1):
            cell = capture.get('cell_identity')
            if cell is None: continue
            identity = 'address:'+cell
            if identity not in graph.nodes: graph.node(identity,storage='captured-cell-address',cell=cell)
            graph.edge(f'664:event:{step}',identity,'address',['guarded-prefix:664'])
            for node in slicers[child].nodes:
                if node['op']=='capture_cell_value' and node['ordinal']==ordinal:
                    graph.edge(identity,f'{child}:ssa:{node["id"]}','address',[f'capture-binding:{child}:{ordinal}'])
    cp = next(row for row in report['checkpoint_proofs'] if row['owner']==663)
    arithmetic = next(row for row in cp['arithmetic'] if row['pc']==546)
    source = definitions[(663,arithmetic['step'],8)]
    arg = graph.node('663:pc547:r7',owner=663,pc=547,storage='register7-precall')
    graph.edge(source,arg,'copy',['guarded-prefix:663','primitive735-cache-binding'])
    root_site = graph.node('664:pc981:V',owner=664,pc=981,storage='state-V',visited=False)
    root_frontier_v = f'664:ssa:{slicers[664].states["V"]}'
    graph.edge(root_frontier_v,root_site,'copy',['root981-arrival',
               'no-intervening-V-write-to981','same-code-epoch-and-dispatch-at981'])
    return graph, {'root_site':root_site,'root_entry':headers[(664,'V')],
                   'checkpoint_argument':arg,'checkpoint_y':headers[(663,'y')]}, slicers


def template_audit(report):
    """Distinguish cached pre-fill headers from later backing reconstruction."""
    evidence = report['provenance_inputs']
    template = evidence['guarded_template_evidence'].get('663',evidence['guarded_template_evidence'].get(663))
    header = template['header']
    arrays, words = arrays_from_candidate(header)
    candidate = next(row for row in evidence['candidate_entry_analyses'] if row['owner']==663)
    original = candidate['analysis']['trace'][0]
    initial = original['state_words_before']
    binding = next(row for row in evidence['guarded_closure_bindings'] if row['child']==663)
    patches = [p for p in evidence['path_local_patch_events'] if p['reference_id']==663]
    mask_visits = [event for event in evidence['root_analysis']['trace']
                   if event['pc']==9828 and patch_equation(event)==(None,663,header['key'])]
    if len(patches)!=1 or len(mask_visits)!=1 or patches[0]['key']!=header['key'] or patches[0]['pc']!=9828:
        raise ValueError('Cached mask lacks the unique direct patch provenance')
    return {'cached_plain_sha256':header['plain_sha256'],'mask':header['key'],
            'checkpoint_plain_sha256':candidate['candidate_plain_sha256'],
            'cached_and_checkpoint_plain_hash_match':header['plain_sha256']==candidate['candidate_plain_sha256'],
            'cached_header_words':list(words),'checkpoint_header_words':initial,
            'header_words_match':list(words)==initial,
            'entry_pc_matches':header['layout']['entry_pc']['value']==original['pc'],
            'cached_initial_arrays':{name:len(values) for name,values in arrays.items()},
            'factory_matches':header['factory_slot']==binding['child_factory']==4890,
            'cleanup_applied_after_template_read':template.get('cleanup_applied') is True,
            'backing_reread_matches_after_cleanup':candidate['live_header_matches_root_context'],
            'root_mask_patches':patches,'constructor_contract':template['constructor_contract'],
            'mask_input_kind':'direct operand, not a V/y read at this instruction',
            'mask_instruction':mask_visits[0],
            'cache_identity_at_invocation_proved':False,
            'scope':'guarded Python template observation before fill; no live VM/cache object was inspected'}


def snapshot_call_sites(arrays, closure_register):
    """Find reviewed228 fused calls whose PRE-COPY callee source is a slot.

    This is a source-register use search, not a reaching-definition proof. It
    neither substitutes a frontier closure value nor invokes the candidate.
    """
    if type(closure_register) is not int or not 0<=closure_register<=100000:
        raise ValueError('Invalid register')
    limit = min(map(len,arrays.values()))
    if limit>20000: raise ValueError('Snapshot budget exceeded')
    rows = []
    for pc in range(1,limit):
        op,a,b,c = instruction(arrays,pc,228)
        if op not in (4,93): continue
        _,resultc,argc,target = instruction(arrays,pc+1,228)
        if any(type(v) is not int or not 0<=v<=100000 for v in (resultc,argc,target)):
            continue
        copies = {c:b} if op==93 else {c:a,c+1:b}
        origin = copies.get(target,target)
        if origin!=closure_register: continue
        rows.append({'pc':pc,'variant_guard':228,'opcode':op,'callee_register':target,
            'callee_source_before_instruction':origin,'argument_count':argc,'requested_results':resultc,
            'normal_return_pc':pc+2,'reaching_definition_proved':False,
            'required_predicates':['arrival in this code epoch with dispatcher228',
                'the pre-copy source slot still holds closure663','exact live captures/template',
                'argument values and all earlier alias effects']})
    return rows


# Each gate has independently checkable local evidence and explicit universal
# obligations. Locally established facts cannot discharge a universal sub-gate.
GATE_PARTS = {
 'structural:child_header_verified':('cached_header_structure','template_at_invocation'),
 'structural:control_flow_verified':('construction_visit','entry_call_path'),
 'structural:ancestry_unconditional':('capture_descriptor_identity','all_lexical_owners'),
 'activation:reachable_call':('incoming_call_witness','incoming_path_predicates'),
 'activation:callee_identity':('closure_destination_definition','call_time_callee_value'),
 'activation:arguments_valid':('incoming_arity_and_values','incoming_type_predicates'),
 'activation:capture_cells_at_call':('capture_cell_addresses','call_time_storage_and_values'),
 'activation:live_template_cache_identity':('cached_header_agrees','live_shared_cache_identity'),
 'activation:normal_constructor_continuation':('alias_only_constructor_source','plain_context_binding'),
 'lifetime:cell_creation_order_verified':('definitions_before_capture','open_cell_reuse_and_order'),
 'lifetime:all_alias_writes_covered':('prefix_direct_writes','escaping_and_future_alias_writes'),
 'lifetime:call_time_capture_values_accounted_for':('frontier_capture_values','all_reaching_call_definitions'),
 'lifetime:close_or_rebind_paths_covered':('source_close_contract','all_exit_reachability'),
 'lifetime:storage_identity_at_call':('address_binding','close_rebase_at_call'),
 'lifetime:escape_effects_covered':('fused_call_result_and_effect_boundary','all_call_outcomes'),
 'tree:unique_incoming_owner':('observed_owner_occurrences','all_owners_excluded'),
 'tree:complete_node_coverage':('sampled_frame_inventory','full_reachable_inventory'),
 'tree:cycle_free_verified_edges':('enumerated_graph_cycle_audit','all_verified_edges_complete'),
}


def subgate_audit(report, slicers, cached):
    baseline = filter_analysis(report)['closure663_proof_ledger']
    if set(baseline['remaining_obligations']) != set(GATE_PARTS):
        raise ValueError('Gate inventory changed; audit definitions must be reviewed')
    evidence = report['provenance_inputs']
    trace = evidence['root_analysis']['trace']
    creation = [(i,e) for i,e in enumerate(trace) if e.get('symbolic_closure_creation',{}).get('child')==663]
    if len(creation)!=1: raise ValueError('One guarded663 construction required')
    step,event = creation[0]
    capture_rows = []
    for register in (159,105):
        sliced = slicers[664].slice(register=register,before_step=step)
        after = [{'step':s,'pc':e['pc'],'value':w['value']} for s,e in enumerate(trace) if s>step
                 for w in e.get('register_writes',[]) if w['register']==register]
        capture_rows.append({'register':register,'cell':f'frame:664:register:{register}',
            'definition_before_construction':sliced,'later_direct_prefix_writes':after,
            'call_time_value':None,'all_alias_writes_covered':False})
    witnesses = {
        'cached_header_structure':cached['factory_matches'] and cached['entry_pc_matches'],
        'construction_visit':True,'capture_descriptor_identity':event['symbolic_closure_creation']['descriptor']==722,
        'closure_destination_definition':event['symbolic_closure_creation']['destination']==85,
        'capture_cell_addresses':baseline['capture_cells'],
        'cached_header_agrees':cached['header_words_match'] and cached['cached_and_checkpoint_plain_hash_match'],
        'alias_only_constructor_source':cached['constructor_contract'],
        'definitions_before_capture':[row['definition_before_construction'] for row in capture_rows],
        'prefix_direct_writes':[row['later_direct_prefix_writes'] for row in capture_rows],
        'frontier_capture_values':next(row for row in evidence['capture_frame_constraints'] if row['child']==663),
        'source_close_contract':next(row for row in report['scope_exits'] if row['owner']==663)['reviewed_exit_candidates'],
        'address_binding':baseline['capture_cells'],
        'fused_call_result_and_effect_boundary':next(row for row in report['checkpoint_proofs'] if row['owner']==663)['parallel_fused_call_boundary'],
        'observed_owner_occurrences':[b for b in evidence['guarded_closure_bindings'] if b['child']==663],
        'sampled_frame_inventory':[row['owner'] for row in evidence['candidate_entry_analyses']],
        'enumerated_graph_cycle_audit':{'edges':[[b['parent'],b['child']] for b in evidence['guarded_closure_bindings']],
                                      'acyclic':all(b['parent']==664 and b['child']!=664 for b in evidence['guarded_closure_bindings'])},
    }
    contexts = {
        'root_closure_register':slicers[664].slice(register=85,before_step=step+1),
        'incoming663_arguments':[slicers[663].slice(register=r,before_step=1) for r in (1,2,3)],
        'root_frontier_callee':evidence['fused_call_frontier'],
        'capture_lineage':capture_rows,
        'header_words':{'V':cached['cached_header_words'][0],'y':cached['cached_header_words'][1]},
        'incoming_call_snapshot_candidates':snapshot_call_sites(evidence['analysis_arrays']['664'],85),
    }
    gates = []
    for gate, parts in GATE_PARTS.items():
        rows = []
        for name in parts:
            known = name in witnesses
            rows.append({'name':name,'status':'established_local_evidence' if known else 'open',
                'evidence':witnesses.get(name),'unconditional_proof':False,
                'required_predicates':[] if known else [gate+'/'+name],
                'scope':'guarded recorded context only' if known else 'requires unrecorded invocation/all-path evidence'})
        refs = ['capture_lineage'] if gate.startswith('lifetime:') else [] if gate.startswith('tree:') else ['root_closure_register','root_frontier_callee']
        if gate=='activation:arguments_valid': refs=['incoming663_arguments']
        if gate in ('activation:reachable_call','activation:callee_identity','structural:control_flow_verified'):
            refs+=['incoming_call_snapshot_candidates']
        if gate in ('structural:child_header_verified','activation:live_template_cache_identity'): refs+=['header_words']
        gates.append({'gate':gate,'subgates':rows,'register_context_refs':refs,'discharged':False})
    return {'gates':gates,'capture_register_lineage':capture_rows,'incoming663_call_witness':None,
            'register_contexts':contexts,
            'root_frontier_call':evidence['fused_call_frontier'],
            'subgate_count':sum(len(row['subgates']) for row in gates),
            'locally_established_count':sum(p['status']=='established_local_evidence' for row in gates for p in row['subgates']),
            'discharged_parent_gates':[],
            'rule':'all required unconditional sub-gates must be proved; local prefix facts do not imply invocation'}


def analyze(report):
    graph, endpoints, slicers = build_graph(report)
    cached = template_audit(report)
    local_guards = []
    if cached['cached_and_checkpoint_plain_hash_match'] and cached['header_words_match']:
        local_guards.append('cached-header-matches:663')
    if cached['cleanup_applied_after_template_read']:
        local_guards.append('template-read-before-fill:663')
    mixed = graph.KINDS-{'address'}
    queries = {
        'root_site_to_argument_data':graph.path(endpoints['root_site'],endpoints['checkpoint_argument'],{'copy','data','payload'},local_guards,conditional=True),
        'root_entry_to_argument_mixed':graph.path(endpoints['root_entry'],endpoints['checkpoint_argument'],mixed,local_guards,conditional=True),
        'checkpoint_y_to_argument':graph.path(endpoints['checkpoint_y'],endpoints['checkpoint_argument'],{'copy','data'},local_guards,conditional=True),
    }
    root_v_effects = [edge for edge in graph.edges if edge['source']==endpoints['root_entry'] and edge['kind']=='data']
    candidate = filter_through_bridge(graph,endpoints['root_site'],endpoints['checkpoint_argument'],206490123,
                                     mask_word_domain(4),['actual-invocation:663','primitive735-cache-binding'])
    gate_audit = subgate_audit(report,slicers,cached)
    frame_scopes = []
    evidence = report['provenance_inputs']
    for owner,slicer in slicers.items():
        frame = evidence['root_analysis'] if owner==664 else next(row['analysis'] for row in evidence['candidate_entry_analyses'] if row['owner']==owner)
        frame_scopes.append({'owner':owner,'guard_name':f'guarded-prefix:{owner}',
            'frontier_pc':frame['pc'],'actual_invocation_proved':False,
            'assumptions':[{'step':step,'pc':event['pc'],key:event[key]}
                           for step,event in enumerate(slicer.trace)
                           for key in ('normal_completion_assumption','assumed_branch_constraint') if key in event],
            'scope':'separately hypothesized frame activation, context, arguments and cache; not shared across calls'})
    return {'source_sha256':report['source_sha256'],'data_sha256':report['data_sha256'],
        'path_queries':queries,'root_entry_V_effect_edges':root_v_effects,'endpoints':endpoints,
        'discharged_local_guards':local_guards,'frame_scopes':frame_scopes,
        'candidate_filter':candidate,'cached_template_audit':cached,'closure663_subgates':gate_audit,
        'graph':{'nodes':graph.nodes,'edges':graph.edges},
        'graph_scope':'five separately guarded frame prefixes; future code, calls and alias histories remain open',
        'verified_hierarchy':None,'formal_promotion_patch':{'applicable':False,'operations':[]},
        'network_requests':0,'factory_invocations':0,'application_calls_executed':0,'input_byte_edits':0}


def run(source,data,output):
    target = output/'provenance-bridge.json'
    if output.resolve() in (source.resolve(),data.resolve()) or target.resolve() in (source.resolve(),data.resolve()):
        raise ValueError('Output aliases input')
    with tempfile.TemporaryDirectory() as temporary:
        report = checkpoint_run(source,data,Path(temporary),include_provenance=True)
        result = analyze(report)
    output.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps(result,indent=2,allow_nan=False)+'\n',encoding='utf-8')
    return result


if __name__=='__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=Path('output/stage1-vm-source.lua.txt'))
    parser.add_argument('--data',type=Path,default=Path('output/stage1-vm-data.bin'))
    parser.add_argument('--output',type=Path,default=Path('output/phase26'))
    args = parser.parse_args()
    result = run(args.source,args.data,args.output)
    print('Path results:',{k:v['status'] for k,v in result['path_queries'].items()})
    print('Remaining candidates:',result['candidate_filter']['remaining_count'])
    print('Sub-gates:',result['closure663_subgates']['subgate_count'])
