"""Phase17 bounded local symbolic paths and frame-scoped capture binding.

Unreviewed instructions are barriers. Local arrival, variant and code-version
premises remain explicit; this analyzer does not execute Lua or any payload.
"""
import argparse
import json
from pathlib import Path
import tempfile

import obligation_resolver as phase14
from prologue_analyzer import mix
import payload_decoder


def instruction(arrays, pc, variant):
    names = {157: ('O','j','Z','B'), 163: ('j','B','Z','O'), 228: ('B','j','Z','O')}[variant]
    return tuple(arrays[name][pc-1] for name in names)


def successors(pc, inst, variant):
    op,a,b,c = inst
    pure = {157: {69,34,84,140}, 163: {62,147,109,83,30},
            228: {139,31,23,134,21,122,56,132,70}}
    if op in pure[variant] or (variant==228 and (op==78 or (op>=196 and op!=197))): return [pc+1]
    if (variant,op) == (157,129): return [a+1]
    if (variant,op) == (163,24): return [b+1]
    if (variant,op) == (228,32): return [a+1]
    if (variant,op) == (163,78): return [pc+1,c+1]
    if (variant,op) == (228,13): return [pc+1,b+1]
    return []


def symbolic_path(arrays, variant, path, word):
    regs, states, mutations, predicates = {}, {'V': {'input':'V'}, 'y': {'input':'y'}}, [], []
    def read(index): return regs.get(index, {'register_input':index})
    def add(left,right):
        if type(left) is int and type(right) is int and max(abs(left),abs(right),abs(left+right)) <= 2**53: return left+right
        return {'add':[left,right], 'predicate':'numeric operands and exact arithmetic'}
    for pc,next_pc in zip(path,path[1:]):
        op,a,b,c = instruction(arrays,pc,variant)
        writes = {}
        if (variant,op) == (157,69): writes[a]=b
        elif (variant,op) == (163,62): writes[c]=a
        elif (variant,op) == (228,139): writes[a]=c
        elif (variant,op) == (228,134): writes[c],writes[c+1]=a,b
        elif (variant,op) in ((157,34),(163,147)): writes[a]=read(b)
        elif (variant,op) == (228,31): writes[c]=read(b)
        elif (variant,op) == (157,84): writes[b],writes[b+1]=read(a),read(c)
        elif (variant,op) == (163,109): writes[c],writes[c+1]=read(a),read(b)
        elif (variant,op) == (228,23): writes[c],writes[c+1]=read(a),read(b)
        elif (variant,op) in ((163,83),(228,21)): writes[c]=add(read(a),b)
        elif (variant,op) == (228,122): writes[c]=add(read(a),read(b))
        elif (variant,op) == (228,56): writes[b]=states['y']
        elif (variant,op) == (228,132):
            value=read(b)
            if type(value) is not int: predicates.append({'pc':pc,'requires':'register value is a numeric state', 'value':value})
            states['y']=value
        elif (variant,op) == (228,78):
            states['V']=read(a)
            predicates.append({'pc':pc,'requires':'assigned V is a numeric state','value':states['V']})
        elif variant==228 and op>=196 and op!=197:
            value=read(b)
            writes[a]=value^c if type(value) is int and 0<=value<=0xffffffff and 0<=c<=0xffffffff else {'bit32_bxor':[value,c],'predicate':'numeric operands and uint32 conversion'}
        elif (variant,op) in ((163,78),(228,13)):
            left,right = (read(b),a) if variant==163 else (read(a),c)
            truth = left<=right if type(left) is int else None
            true_pc=pc+1
            false_pc=c+1 if variant==163 else b+1
            possible = [truth] if truth is not None else [True,False]
            possible = [value for value in possible if (true_pc if value else false_pc)==next_pc]
            if not possible: return {'path':path,'status':'refuted_numeric_branch','pc':pc}
            predicates.append({'pc':pc,'operator':'<=','left':left,'right':right,'allowed_truth_values':possible})
        for value in writes.values():
            if type(value) is dict and 'predicate' in value:
                predicates.append({'pc':pc,'requires':value['predicate'],'expression':value})
        regs.update(writes)
        if writes or (variant,op) in ((228,132),(228,78)): mutations.append({'pc':pc,'register_writes':writes,'state_y':states['y'],'state_V':states['V']})
    return {'path':path,'status':'conditional_local_path','state_at_site':states[word],
            'mutations':mutations,'predicates':predicates}


def localized_trace(arrays, target, variant, word, operand, radius=24, depth=12, cap=32):
    if not 1<=radius<=64 or not 1<=depth<=32 or not 1<=cap<=128: raise ValueError('Local budget invalid')
    limit=min(map(len,arrays.values()))
    if not 1<=target<=limit: raise ValueError('Site outside arrays')
    lo,hi=max(1,target-radius),min(limit,target+radius)
    predecessors={pc:[] for pc in range(1,limit+1)}
    for pc in range(1,limit+1):
        for successor in set(successors(pc,instruction(arrays,pc,variant),variant)):
            if successor in predecessors: predecessors[successor].append(pc)
    queue,paths=[[target]],[]
    while queue and len(paths)<cap:
        reversed_path=queue.pop()
        previous=[pc for pc in predecessors[reversed_path[-1]] if pc not in reversed_path]
        if not previous or len(reversed_path)>=depth:
            paths.append(symbolic_path(arrays,variant,list(reversed(reversed_path)),word))
        else: queue.extend([reversed_path+[pc] for pc in previous])
    for path in paths:
        state=path.get('state_at_site')
        path['constant_key']=operand^mix(state) if type(state) is int and 0<=state<=0xffffffff and 0<=operand^mix(state)<=255 else None
    return {'target_pc':target,'variant':variant,'paths':paths,'path_cap_hit':bool(queue),
            'guard':['arrival at local cutpoint','assumed dispatcher','frontier code slots remain unmodified'],
            'entry_reachability_proved':False,'window':[lo,hi],
            'predecessor_scan_scope':'whole snapshot for incoming jumps; bounded backward path depth',
            'fallthrough_barriers':'unreviewed instructions have no assumed successor'}


def bind_captures(frame, captures, incoming=None):
    bindings,errors=[],[]
    for ordinal,capture in enumerate(captures,1):
        index,kind=capture['target_index'],capture['kind']
        if type(index) is not int or index<0 or kind not in (0,1,2,3): raise ValueError('Invalid capture entry')
        if kind==2 and (type(capture.get('span_length')) is not int or capture['span_length']<1): raise ValueError('Invalid capture span')
        if kind==1:
            if incoming is None: value={'unresolved_enclosing_capture':index,'frame':frame}
            elif not 1<=index<=len(incoming):
                errors.append({'ordinal':ordinal,'index':index,'available':len(incoming)})
                value={'invalid_enclosing_capture':index}
            else: value=incoming[index-1]
        elif kind==0: value={'copied_register_value':index,'frame':frame,'value_known':False}
        else: value={'cell_identity':f'frame:{frame}:register:{index}', 'span':capture.get('span_length') if kind==2 else 1}
        bindings.append(value)
    return {'bindings':bindings,'bounds_errors':errors,'incoming_scope_known':incoming is not None}


def run(source,data,output):
    with tempfile.TemporaryDirectory() as temporary:
        root=Path(temporary)
        report=phase14.run(source,data,root/'phase14',include_analysis_arrays=True)
        baseline=payload_decoder.run(source,data,root/'baseline')
    masks=[]
    for row in report['mask_audit']:
        if row['reference_id']==192: continue
        for site in row['sites']:
            if site['word_variable'] is None: continue
            arrays=report['analysis_arrays'][str(site['owner'])]
            local=localized_trace(arrays,site['pc'],site['variant'],site['word_variable'],site['operand'])
            op,a,b,c=instruction(arrays,site['pc'],site['variant'])
            actual=phase14.patch_equation({'variant':site['variant'],'opcode':op,'operand1':a,'H':b,'operand3':c})
            matches=actual==(site['word_variable'],row['reference_id'],site['operand'])
            if not matches:
                for path in local['paths']: path['constant_key']=None
            previous_pc=site['pc']-1
            local['immediate_predecessor_snapshot']=None if previous_pc<1 else {
                'pc':previous_pc,'instruction':instruction(arrays,previous_pc,site['variant']),
                'reviewed_successors':successors(previous_pc,instruction(arrays,previous_pc,site['variant']),site['variant'])}
            masks.append({'reference_id':row['reference_id'],'owner':site['owner'],
                'site_equation_matches_snapshot':matches,
                'expected_equation':[site['word_variable'],row['reference_id'],site['operand']],
                'actual_site_instruction':[op,a,b,c],'actual_patch_equation':actual,
                'mismatch_scope':'current exported code version only; future rewrites remain possible',**local})
    descriptors={row['reference_id']:row['captures'] for row in baseline['capture_descriptors']}
    environments={664:[]}
    for row in report['capture_frame_constraints']:
        environments[row['child']]=[{'cell_identity':item['cell_identity']} for item in row['captures']]
    traces={row['owner']:row['analysis']['trace'] for row in report['candidate_entry_analyses']}
    pairs=[*report['prototype_root_causes'],*report['structural_hierarchy_candidates']]
    scopes=[]
    cell_values={capture['cell_identity']:capture['frontier_value'] for frame in report['capture_frame_constraints'] for capture in frame['captures'] if capture['cell_identity']}
    for pair in pairs:
        parent,child=pair['parent'],pair['child']
        bound=bind_captures(parent,descriptors[pair['descriptor_id']],environments.get(parent))
        reads=[{'pc':event['pc'],'ordinal':event['H'],
                'operation':'cell_address' if event['variant']==157 else 'cell_value'} for event in traces.get(child,[])
               if (event['variant'],event['opcode']) in ((157,44),(163,22))]
        for read in reads:
            if 1<=read['ordinal']<=len(bound['bindings']):
                binding=bound['bindings'][read['ordinal']-1]
                read['resolved_cell_identity']=binding.get('cell_identity')
                read['value_at_root_frontier']=cell_values.get(binding.get('cell_identity'))
                read['value_stability_proved_until_child_activation']=False
        scopes.append({'parent':parent,'child':child,'descriptor_id':pair['descriptor_id'],**bound,
            'child_capture_reads':reads,'out_of_range_reads':[r for r in reads if not 1<=r['ordinal']<=len(bound['bindings'])],
            'scope':'guarded descriptor binding; child trace activation unproved','lexical_parent_verified':False})
    search=[]
    for child,trace in traces.items():
        ordinals=sorted({event['H'] for event in trace if (event['variant'],event['opcode']) in ((157,44),(163,22))})
        search.append({'function':child,'observed_capture_ordinals':ordinals,
            'environment_compatibility':[{'environment_of_closure':owner,'capacity':len(environment),
                'status':'UNKNOWN' if not ordinals else 'PASS' if all(1<=i<=len(environment) for i in ordinals) else 'FAIL',
                'scope':'observed reads only; compatible capacity is not a binding or lexical edge'}
                for owner,environment in environments.items() if owner!=664],
            'complete_upvalue_set_proved':False,'new_parent_edge':None})
    result={'source_sha256':report['source_sha256'],'data_sha256':report['data_sha256'],
            'localized_mask_traces':masks,'upvalue_scope_audit':scopes,'verified_hierarchy':None,
            'extended_environment_search':search,
            'application_calls_executed':0,'factory_invocations':0,'network_requests':0}
    target=output/'scope-traces.json'
    if target.resolve() in {source.resolve(),data.resolve()}: raise ValueError('Output aliases input')
    output.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps(result,indent=2,allow_nan=False)+'\n',encoding='utf-8')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=Path('output/stage1-vm-source.lua.txt'))
    parser.add_argument('--data',type=Path,default=Path('output/stage1-vm-data.bin'))
    parser.add_argument('--output',type=Path,default=Path('output/phase17'))
    args=parser.parse_args()
    result=run(args.source,args.data,args.output)
    print('Local sites:',len(result['localized_mask_traces']),'capture pairs:',len(result['upvalue_scope_audit']))
