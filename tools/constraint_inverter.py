"""Phase32: bounded predicate inversion and qualified reaching-definition audit.

Rebuilds pinned evidence using Python metadata only. Flipping a branch does not
flip an exception, discharge its premises, or manufacture a root continuation.
"""
import argparse
from copy import deepcopy
import json
from pathlib import Path

from checkpoint_aligner import run as checkpoint_run
from path_domain import Predicates, negate
from path_refiner import run as refine
from register_slicer import RegisterSlicer
from upstream_solver import dependency_graph, reaching_meet


def conjunction(guards):
    return {'all':[g['expression'] if g['truth'] else negate(g['expression']) for g in guards]}


def inversion_queries(certificate):
    """Flip one occurrence with its prefix intact and its suffix discarded.

    Test the new guard both alone and with the necessary condition for avoiding
    ALL certified failures under G. Local SAT is never promoted to reachability.
    """
    if certificate.get('coverage_proved')is not True:
        return {'status':'UNCERTIFIED','queries':[],'positive_bridge_proved':False}
    rows=certificate['leaf_refutations']
    blocked={'any':[conjunction(r['guards']) for r in rows]}
    coverage=Predicates().decide(blocked)
    if coverage['value']is not True:
        return {'status':'UNCERTIFIED','queries':[],'positive_bridge_proved':False}
    queries=[]
    for leaf in rows:
        guards=leaf['guards']
        for index,guard in enumerate(guards):
            prefix=deepcopy(guards[:index])
            prefix.append({**deepcopy(guard),'truth':not guard['truth']})
            inverted=conjunction(prefix);domain=Predicates();domain.assume(inverted)
            alternatives=[]
            for other in rows:
                probe=domain.fork();probe.assume(conjunction(other['guards']))
                if probe.check()['status']!='UNSAT':alternatives.append(other['pc'])
            normal=domain.fork();normal.assume(negate(blocked))
            queries.append({'from_leaf_pc':leaf['pc'],'occurrence':guard['occurrence'],
                'original_predicate':guard,'inverted_prefix':prefix,
                'boolean_query':domain.check()['status'],'compatible_blocked_leaf_pcs':alternatives,
                'avoid_all_certified_failures_under_G':normal.check()['status'],
                'positive_bridge_proved':False})
    # G -> !NormalReturn implies NormalReturn -> !G. It does NOT imply !G -> NormalReturn.
    g={'atom':'reviewed-prefix-cache-code-epoch-native-no-reflection-G'}
    normal={'atom':'NormalReturn'}
    theory=Predicates();theory.assume({'any':[negate(g),negate(normal)]})
    theory.assume(negate(g))
    return {'status':'reviewed_guarded_partition','coverage':coverage,'queries':queries,
        'not_G_entails_normal_return':theory.decide(normal),
        'scope':'G retained for failure queries; escaping G requires new source evidence',
        'positive_bridge_proved':False}


def trace_mappings(report):
    """Expose source-transfer annotations, not inferred register equalities."""
    mappings=[]
    for invocation in report['metatable_call_analyses']:
        for path in invocation['analysis']['paths']:
            for step,event in enumerate(path['trace']):
                transfers={k:deepcopy(event[k]) for k in
                    ('upstream_equal','boolean_transfer','path_predicate','upstream_capture_read') if k in event}
                if transfers:mappings.append({'owner':544,'leaf_pc':path['pc'],'step':step,
                    'pc':event['pc'],'transfers':transfers})
    for analysis in report['parent_continuations']:
        for path in analysis['paths']:
            for step,event in enumerate(path['trace']):
                transfers={k:deepcopy(event[k]) for k in
                    ('pure_builtin_summary','refined_return_binding','path_predicate',
                     'fresh_register_order_failure') if k in event}
                if transfers:mappings.append({'owner':516,'leaf_pc':path['pc'],'step':step,
                    'pc':event['pc'],'transfers':transfers})
    return mappings


def meeting_audit(state,upstream,forward_evidence):
    """Join only explicit SSA dependencies; never join captured addresses to values.

    V@981 has not been reached in this prefix. Keep it an external boundary;
    the frontier's V is NOT a substitute. Test the latter separately as a
    diagnostic, without an edge to the unvisited endpoint.
    """
    if state['pc']!=8521 or any(e['pc']==981 for e in state['trace']):
        raise ValueError('Reviewed unvisited981/8521 boundary changed; re-audit required')
    # The advanced explorer records register writes but no VM state-word trace.
    # Do not fabricate RegisterSlicer V/y observations for that different schema.
    trace=[]
    for event in state['trace']:
        op,a,b,c=event['instruction']
        trace.append({'pc':event['pc'],'variant':228,'opcode':op,
            'operand1':a,'H':b,'operand3':c,'register_writes':deepcopy(event['writes'])})
    graph=dependency_graph(664,trace);nodes={};edges=[]
    scope='root664:guarded8521:'
    # Real V/y SSA from the earlier pinned root prefix, rather than synthetic
    # observations added to the advanced explorer's incompatible trace schema.
    forward=RegisterSlicer(664,forward_evidence['root_analysis']['trace'])
    early='root664:guarded-prefix:'
    for node in forward.nodes:nodes[early+str(node['id'])]=deepcopy(node)
    for node in forward.nodes:
        for dep in node['deps']:
            edges.append({'source':early+str(dep),'target':early+str(node['id']),
                'kind':'copy' if node['op']=='copy' else 'data',
                'predicate':{'atom':'pinned-root-prefix-activation-and-code-epoch'}})
    for name,record in graph['nodes'].items():
        nodes[scope+name]=deepcopy(record)
        if record['kind']=='fresh_frame_nil':
            nodes[scope+name]['kind']='unresolved_resumed_root_register'
    for name,record in graph['nodes'].items():
        for dep in record['dependencies']:
            nodes.setdefault(scope+dep,{'kind':'unresolved_external_definition'})
            edges.append({'source':scope+dep,'target':scope+name,'kind':'data'})
    root_versions=graph['register_versions']
    endpoint=scope+'V@981:unvisited'
    nodes[endpoint]={'kind':'unvisited_reaching_definition','pc':981}
    sinks=[]
    for summary_index,summary in enumerate(upstream['summaries']):
        for graph_index,row in enumerate(summary['backward_graphs']):
            graph=row['graph'];prefix=f'call{summary_index}:path{graph_index}:'
            # Missing/unknown SSA leaves stay leaves, rather than silently
            # becoming an assignment from a root register with the same index.
            for name,record in graph['nodes'].items():nodes[prefix+name]=deepcopy(record)
            for name,record in graph['nodes'].items():
                for dep in record['dependencies']:
                    nodes.setdefault(prefix+dep,{'kind':'unresolved_external_definition'})
                    edges.append({'source':prefix+dep,'target':prefix+name,'kind':'data'})
            binding='root664.r74@8521'
            if prefix+binding in nodes and 74 in root_versions:
                edges.append({'source':scope+root_versions[74],'target':prefix+binding,
                    'kind':'copy','predicate':{'atom':'same-reviewed8521-call-frame-and-prefix'}})
            for sink in graph['effect_and_return_sinks']:
                sinks.append((summary['owner'],prefix+sink))
    frontier=scope+'V@8521:unobserved'
    nodes[frontier]={'kind':'VM_state_word_not_exported_by_advanced_explorer'}
    queries=[{'owner':owner,'root981':reaching_meet(nodes,edges,endpoint,sink),
              'frontier_only_diagnostic':reaching_meet(nodes,edges,frontier,sink),
              'earlier_forward_V_diagnostic':reaching_meet(nodes,edges,early+str(forward.states['V']),sink)}
             for owner,sink in sinks]
    return {'root981_observed':any(e['pc']==981 for e in state['trace']),
        'root981_definition_available':False,'frontier_V_definition_available':False,
        'earlier_forward_V_ssa':forward.nodes[forward.states['V']],
        'earlier_forward_frontier_pc':forward_evidence['root_analysis']['pc'],
        'unproved_projection_obligations':[
            'normal return from reviewed8521 route','root981 arrival in same activation',
            'all intervening V writes and code/cache epochs'],
        'queries':queries,'node_count':len(nodes),'edge_count':len(edges),
        'positive_bridge_proved':False,'scope':'finite exported guarded SSA graph, not global absence'}


def run(source,data,output):
    protected={source.resolve(),data.resolve()}
    if any(p.resolve()in protected for p in (output,output/'constraint-inversion.json')):
        raise ValueError('Output aliases input')
    states=[]
    prior=refine(source,data,output/'refinement',boundary_observer=lambda state,reason:states.append(state))
    upstream=json.loads((output/'refinement/upstream/upstream-analysis.json').read_text(encoding='utf-8'))
    forward=checkpoint_run(source,data,output/'forward',include_provenance=True)
    inversions=[inversion_queries(c) for c in prior['guarded_route_certificates']]
    meetings=[meeting_audit(state,upstream,forward['provenance_inputs']) for state in states]
    writers=[]
    for s in upstream['summaries']:
        if s['owner']==258:
            writers.append({'owner':258,'arguments':s['arguments'],
                'graphs':s['backward_graphs'],
                'frontiers':[p['frontier'] for p in s['analysis']['paths']]})
    result={'source_sha256':prior['source_sha256'],'data_sha256':prior['data_sha256'],
        'inversion_audits':inversions,'ssa_transfer_mappings':trace_mappings(prior),
        'body258_operand_provenance':writers,'meeting_audits':meetings,
        'candidate_solution':prior['candidate_solution'],'numeric_filters_admitted':[],
        'global_gate_matrix':prior['global_gate_matrix'],'verified_hierarchy':None,
        'formal_promotion_patch':{'applicable':False,'operations':[]},
        'positive_bridge_proved':False,'network_requests':0,'application_calls_executed':0,'factory_invocations':0}
    output.mkdir(parents=True,exist_ok=True)
    (output/'constraint-inversion.json').write_text(json.dumps(result,indent=2,allow_nan=False)+'\n',encoding='utf-8')
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,default=Path('output/stage1-vm-source.lua.txt'))
    p.add_argument('--data',type=Path,default=Path('output/stage1-vm-data.bin'))
    p.add_argument('--output',type=Path,default=Path('output/phase32'))
    a=p.parse_args();r=run(a.source,a.data,a.output)
    print(json.dumps({'candidates':r['candidate_solution']['model_count'],
        'global_gates':len(r['global_gate_matrix']),'positive_bridge_proved':r['positive_bridge_proved']}))
