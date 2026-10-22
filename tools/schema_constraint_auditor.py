"""Phase22 directory-backed alignment, predicate constraints and lifetime gates.

Pinned offline static analysis; never run Lua, factories, __index or networking.
"""
import argparse
import json
from pathlib import Path
import struct
import tempfile

import obligation_resolver as phase14
from lazy_tracer import PRIMITIVES, tag_path
from predicate_solver import constrain, path_constraints
from prototype_mapper import parse_descriptors
from reader_scope_auditor import (DIRECTORY_XOR, LENGTH_LEAVES, lifetime_audit,
                                 raw_prefix, source_contract, typed_probe)
from reader_tracer import decrypt_record, parse_loader
from scope_tracer import instruction
from string_resolver import read_length_payload
from symbolic_resolver import PROOFS
from lineage_auditor import BRANCH


ACTIVATION = ('reachable_call','callee_identity','arguments_valid','capture_cells_at_call',
              'live_template_cache_identity','normal_constructor_continuation')
LIFETIME = ('frame_slot_defined_before_capture','cell_creation_order_verified','all_alias_writes_covered','call_time_capture_values_accounted_for',
            'close_or_rebind_paths_covered','storage_identity_at_call','escape_effects_covered')
TREE = ('unique_incoming_owner','complete_node_coverage','cycle_free_verified_edges')


def record_span(backing, entries, reference, parity=0):
    if type(parity) is not int or parity not in (0,1): raise ValueError('Expected directory parity')
    if type(reference) is not int or not 1<=reference<=len(entries): raise ValueError('Reference outside directory')
    view = list(entries)
    position = entries[reference-1]['value'] ^ (DIRECTORY_XOR if parity else 0)
    view[reference-1] = {'value':position}
    result = typed_probe(backing,view,reference)
    result.update(directory_parity_hypothesis=parity,end_exclusive=None)
    if result['status']=='outside_backing': return result
    leaf = result['leaf_state']
    if leaf in PRIMITIVES:
        size = struct.calcsize(PRIMITIVES[leaf][1])
        if position+1+size<=len(backing): result['end_exclusive']=position+1+size
    elif leaf in LENGTH_LEAVES:
        if result['prefix']['status']=='bounded':
            result['end_exclusive']=result['prefix']['prefix_end']+result['prefix']['length']
        if leaf==95 and result['end_exclusive'] is not None:
            encoded,_ = read_length_payload(backing,position)
            raw,_ = decrypt_record(encoded,reference,83)
            try: result['descriptor']=parse_descriptors(raw)
            except ValueError as error: result['descriptor_error']=str(error)
    result['offset_boundary_scope']='reviewed reader shape and parity only; activation and cache state unproved'
    return result


def neighborhood(backing, entries, center=134543, radius=32):
    if type(radius) is not int or not 1<=radius<=256 or not 0<=center<len(backing):
        raise ValueError('Invalid neighborhood bounds')
    records=[]
    for reference,entry in enumerate(entries,1):
        for parity in (0,1):
            position=entry['value']^(DIRECTORY_XOR if parity else 0)
            if abs(position-center)<=radius:
                records.append(record_span(backing,entries,reference,parity))
    records.sort(key=lambda row:(row['position'],row['reference_id'],row['directory_parity_hypothesis']))
    boundaries=[]
    for left,right in zip(records,records[1:]):
        end=left['end_exclusive']
        boundaries.append({'left':left['reference_id'],'right':right['reference_id'],
            'left_end':end,'right_begin':right['position'],
            'relation':'unknown_span' if end is None else 'exact_adjacency' if end==right['position']
                       else 'gap' if end<right['position'] else 'overlap',
            'both_directory_parities_exported':left['directory_parity_hypothesis']==right['directory_parity_hypothesis']==0})
    forced=raw_prefix(backing,center)
    prefix_end=forced.get('prefix_end',center+1)
    intersections=[]
    for row in records:
        start,end=row['position'],row['end_exclusive']
        if end is not None and max(start,center+1)<min(end,prefix_end):
            intersections.append({'reference_id':row['reference_id'],
                'overlap_half_open':[max(start,center+1),min(end,prefix_end)],
                'part':'includes tag/header' if start>=center+1 else 'primitive payload',
                'directory_parity_hypothesis':row['directory_parity_hypothesis']})
    return {'center':center,'radius':radius,'records':records,'boundaries':boundaries,
            'forced_raw_prefix':forced,'forced_prefix_intersections':intersections,
            'scope':'only directory-backed starts; no arbitrary byte/tag scan or inferred global packing'}


def equation_search(report):
    rows=[]
    for mask in report['mask_audit']:
        if mask['reference_id']==192: continue
        for site in mask['sites']:
            if site['word_variable'] is None: continue
            arrays=report['analysis_arrays'][str(site['owner'])]
            op,a,b,c=instruction(arrays,site['pc'],site['variant'])
            expected=(site['word_variable'],mask['reference_id'],site['operand'])
            actual=phase14.patch_equation({'variant':site['variant'],'opcode':op,'operand1':a,'H':b,'operand3':c})
            paths=path_constraints(arrays,site['pc'],site['variant'],site['word_variable'])
            solutions=[{'path':path,'finite_constraints':constrain(path,site['operand'])} for path in paths['paths']]
            combined=sorted({state for row in solutions for state in row['finite_constraints']['states']})
            rows.append({'reference_id':mask['reference_id'],'owner':site['owner'],'pc':site['pc'],
                'variant':site['variant'],'expected_equation':expected,'actual_instruction':[op,a,b,c],
                'equation_identity_verified':actual==expected,
                'state_domain_union':combined,'state_count':len(combined),
                'state_domain_scope':'necessary mixer-local candidates on enumerated conditional paths, not witnessed runtime states',
                'paths':solutions,'path_cap_hit':paths['path_cap_hit'],
                'scope':paths['guard'],'all_incoming_edges_known':False,
                'unconditional_state':None,'promoted_keys':[],
                'promotion_blockers':['entry reachability and rewrite history','live reader/cache activation']+
                     ([] if actual==expected else ['selected slot is not the hypothesized patch equation'])})
    if len(rows)!=5: raise ValueError('Expected exactly five reviewed state-dependent hypotheses')
    return rows


def promotion_gate(criteria, activation, lifetime, tree):
    """All obligations are conjunctive; UNKNOWN is never coerced to PASS."""
    groups={'structural':(PROOFS,criteria),'activation':(ACTIVATION,activation),
            'lifetime':(LIFETIME,lifetime),'tree':(TREE,tree)}
    missing=[]
    for group,(names,values) in groups.items():
        for name in names:
            value=values.get(name)
            if value is not None and type(value) is not bool: raise ValueError('Proof values must be bool or None')
            if value is not True: missing.append(f'{group}:{name}')
    return {'eligible':not missing,'missing_or_failed':missing,
            'rule':'all structural, activation, lifetime and global tree obligations require explicit True'}


def activation_conditions(bindings, trace, candidates, criteria):
    audit=lifetime_audit(bindings,trace,candidates,criteria)
    conditions=[]
    for row in audit['closures']:
        births=[]
        creation=next(index for index,event in enumerate(trace) if event['pc']==row['construction_pc']
                      and event.get('symbolic_closure_creation',{}).get('child')==row['child'])
        for capture in row['capture_cells']:
            definitions=[step for step,event in enumerate(trace[:creation])
                         if capture['frame']==row['constructing_frame']
                         and any(write['register']==capture['register'] for write in event.get('register_writes',[]))]
            births.append({'cell':capture['cell'],'last_direct_definition_step':definitions[-1] if definitions else None})
        activation=dict.fromkeys(ACTIVATION,None)
        lifetime=dict.fromkeys(LIFETIME,None)
        lifetime['frame_slot_defined_before_capture']=True if all(item['last_direct_definition_step'] is not None for item in births) else None
        tree=dict.fromkeys(TREE,None)
        gate=promotion_gate(row['criteria'],activation,lifetime,tree)
        conditions.append({'child':row['child'],'slot_definition_evidence':births,'activation':activation,
            'lifetime':lifetime,'tree':tree,'gate':gate,
            'quantified_stability_condition':'for every reachable alias path from capture to call, account for writes/close/rebind and preserve binding identity; derive call-time values instead of freezing the frontier',
            'captured_values_must_be_immutable':False,
            'activation_condition':'a reachable call resolves to this closure with its exact live template, arguments and captured cells',
            'scope':'known construction facts only; no actual invocation inferred'})
    return {'scope_audit':audit,'conditions':conditions,
            'formal_promotion_patch':{'applicable':False,'operations':[]},'verified_hierarchy':None}


def run(source,data,output):
    target=output/'schema-constraints.json'
    if output.resolve() in (source.resolve(),data.resolve()) or target.resolve() in (source.resolve(),data.resolve()):
        raise ValueError('Output aliases input')
    with tempfile.TemporaryDirectory() as temporary:
        root=Path(temporary)
        report=phase14.run(source,data,root/'phase14',include_analysis_arrays=True)
        from reconstructor import run as reconstruct
        reconstruct(source,data,root/'backing',[664])
        backing=(root/'backing/record-664.backing-postfill.bin').read_bytes()
    text=source.read_text(encoding='ascii')
    source_contract(text)
    guard_evidence=[{'offset':text.index(fragment),'text':fragment} for fragment in (BRANCH,phase14.BRANCH_163,
        'else W=if o~=14 then if t[i[W]]<=A[W]then W else H[W]else if t[A[W]]<t[H[W]]then W else i[W];end;end;')]
    entries=parse_loader(data.read_bytes())['lookup_entries']
    result={'source_sha256':report['source_sha256'],'data_sha256':report['data_sha256'],
        'schema_neighborhood':neighborhood(backing,entries),'guard_source_evidence':guard_evidence,
        'state_equation_constraints':equation_search(report),
        'activation_lifetime':activation_conditions(report['guarded_closure_bindings'],report['root_analysis']['trace'],
            report['candidate_entry_analyses'],report['structural_hierarchy_candidates']),
        'verified_hierarchy':None,'input_byte_edits':0,'network_requests':0,
        'application_calls_executed':0,'factory_invocations':0}
    output.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps(result,indent=2,allow_nan=False)+'\n',encoding='utf-8')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=Path('output/stage1-vm-source.lua.txt'))
    parser.add_argument('--data',type=Path,default=Path('output/stage1-vm-data.bin'))
    parser.add_argument('--output',type=Path,default=Path('output/phase22'))
    args=parser.parse_args()
    result=run(args.source,args.data,args.output)
    print('Directory-backed neighbors:',len(result['schema_neighborhood']['records']))
    print('State equation hypotheses:',len(result['state_equation_constraints']))
