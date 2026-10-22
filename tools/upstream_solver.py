"""Phase30: guarded downstream summaries and upstream dependency slicing.

All objects here are Python metadata, never live Lua values. Calls, metatables
and unreviewed effects remain boundaries; a scoped summary is not reachability.
"""
import argparse
from copy import deepcopy
import json
from pathlib import Path

from automated_solver import run as caller_run
from gate_solver import sat
from interprocedural_solver import (capture_inputs,materialize_heap,primitive,
    propagate,propagate_gates,trace_body,truth)


ANCHORS=(
    'if o<154 then t[H[W]]=not t[A[W]];',
    'else if o~=47 then W=if t[w[W]]then A[W]else H[W];',
    'else W=if t[A[W]]then w[W]else H[W];',
    'T=g[A[W]];t[w[W]]=T[6][T[5]][t[H[W]]];',
    'else t[H[W]]=D(A[W]);',
    'T,d,I=i[f],H[f],A[f];m=t[T];K(t,T+1,T+d,I+1,m);',
    'if o<51 then T=g[H[W]];T[6][T[5]][t[A[W]]]=B[W];',
    'if o==91 then T=g[A[W]];T[6][T[5]][t[H[W]]]=t[w[W]];',
    'else t[A[W]]=Z[W];t[A[W+1]]=t[H[W+1]];W+=1;',
    'return t[w[W]];end;else if h<84 then',
    'else t[H[W]]=t[i[W]]<=A[W];',
    'else T=g[A[W]];T[6][T[5]]=t[H[W]];',
    'else t[A[W]]=t[H[W]]>=t[i[W]];',
)


def literal(value):
    if type(value) is dict and 'string_literal' in value:return value['string_literal']
    return value


def lua_truth(value):
    value=literal(value)
    if type(value) is dict and any(k in value for k in ('builtin_type_of','table_handle')):return True
    return truth(value)


def extension(owner):
    """Create independent table/effect state for every replayed guarded path."""
    def factory(context,captures,decisions,frontier,branch):
        tables={}; capture_values=deepcopy(captures)
        for ordinal,value in list(capture_values.items()):
            if type(value) is dict and 'plain_entries' in value:
                identity=f'capture:{owner}:{ordinal}'
                tables[identity]=deepcopy(value['plain_entries'])
                capture_values[ordinal]={'table_handle':identity}
        def transfer(variant,op,a,b,c,regs,event):
            pc=event['pc']
            def write(register,value):regs[register]=deepcopy(value)
            def load(ordinal,destination):
                if ordinal not in capture_values:
                    frontier.update({'kind':'unknown_capture','pc':pc,'ordinal':ordinal});return False
                write(destination,capture_values[ordinal])
                event['upstream_capture_read']={'ordinal':ordinal,'destination':destination,'value':deepcopy(regs[destination])}
                return True
            def read(table,key,dest):
                identity=table.get('table_handle') if type(table) is dict else None
                key=literal(key)
                if identity not in tables:
                    frontier.update({'kind':'unproved_plain_table','pc':pc,'table':table,'key':key});return False
                value=None
                for row in tables[identity]:
                    if type(row['key']) is type(key) and row['key']==key:value=row['value'];break
                if type(key) is dict:
                    value={'table_select':{'table':identity,'entries':deepcopy(tables[identity]),'key':deepcopy(key)}}
                write(dest,value);event['upstream_table_read']={'table':identity,'key':key,'destination':dest,'value':deepcopy(value)}
                return True
            if (variant,op)==(163,153):
                value=lua_truth(regs.get(c))
                if value is None:
                    frontier.update({'kind':'unknown_truth','pc':pc,'value':regs.get(c)});return False
                write(b,not value);event['upstream_not']={'source':c,'destination':b,'value':not value};return True
            if (variant,op) in ((157,44),(163,22),(228,75)):
                ordinal,dest=(b,a) if variant==157 else (b,c) if variant==163 else (a,b)
                return load(ordinal,dest)
            if (variant,op)==(163,12):return read(capture_values.get(c),regs.get(b),a)
            if (variant,op)==(163,50):
                table=capture_values.get(b);identity=table.get('table_handle') if type(table)is dict else None
                key=literal(regs.get(c));constant=primitive(context,a)
                if identity not in tables or type(key) not in (str,int,bool) or constant is None:
                    frontier.update({'kind':'unproved_capture_table_write','pc':pc});return False
                tables[identity]=[r for r in tables[identity] if not(type(r['key'])is type(key) and r['key']==key)]
                tables[identity].append({'key':key,'value':constant['value']})
                event['upstream_table_write']={'capture':b,'key_register':c,'key':key,'constant':constant}
                return True
            if (variant,op)==(163,91):
                table=capture_values.get(c);identity=table.get('table_handle') if type(table)is dict else None
                key=literal(regs.get(b));value=deepcopy(regs.get(a))
                if identity not in tables or type(key) not in (str,int,bool):
                    frontier.update({'kind':'unproved_capture_table_write','pc':pc});return False
                tables[identity]=[r for r in tables[identity] if not(type(r['key'])is type(key) and r['key']==key)]
                if value is not None:tables[identity].append({'key':key,'value':value})
                event['upstream_table_write']={'capture':c,'key_register':b,'value_register':a,'key':key,'value':value}
                return True
            if (variant,op) in ((163,46),(163,49)):
                register=a if op==46 else c
                value=lua_truth(regs.get(register))
                if value is None:
                    if pc not in decisions:
                        branch.update({'pc':pc,'expression':deepcopy(regs.get(register))});return False
                    value=decisions[pc]
                event['upstream_branch']={'register':register,'truth':value}
                return {'next_pc':((c if value else b) if op==46 else (a if value else b))+1}
            if (variant,op)==(228,113):
                if not 0<=c<=10000:
                    frontier.update({'kind':'allocation_bound','pc':pc});return False
                identity=f'fresh:{owner}:{pc}'
                tables[identity]=[];write(b,{'table_handle':identity})
                event['upstream_allocation']={'destination':b,'capacity_hint':c,'identity':identity};return True
            if (variant,op)==(228,148):
                table=regs.get(a);identity=table.get('table_handle') if type(table)is dict else None
                if identity not in tables or not 0<=b<=10000 or not 0<=c<=10000:
                    frontier.update({'kind':'unproved_table_move','pc':pc});return False
                values=[deepcopy(regs.get(a+1+i)) for i in range(b)]
                for i,value in enumerate(values):
                    key=c+1+i;tables[identity]=[r for r in tables[identity] if r['key']!=key]
                    if value is not None:tables[identity].append({'key':key,'value':value})
                event['upstream_move']={'source_registers':[a+1,a+b+1],'target_start':c+1,'values':values};return True
            if (variant,op)==(228,173):
                window=event.get('instruction_window',{})
                constant=primitive(context,b)
                if constant is None and context is not None:
                    text=context.text(b)
                    if text is not None:constant={'reference':b,'kind':'string','value':text}
                if constant is None or any(len(window.get(k,[]))<2 for k in ('O','Z')):
                    frontier.update({'kind':'unproved_fused_literal_copy','pc':pc});return False
                write(c,constant['value'])
                destination,source=window['O'][1],window['Z'][1]
                write(destination,regs.get(source))
                event['upstream_fused_copy']={'constant':constant,'first_destination':c,
                    'second_destination':destination,'second_source':source}
                return {'next_pc':pc+2}
            if (variant,op)==(228,55):
                value=regs.get(a)
                if type(value)is not int:
                    frontier.update({'kind':'unproved_numeric_comparison','pc':pc,'value':value});return False
                write(b,value<=c);event['upstream_compare']={'source':a,'immediate':c,'value':value<=c};return True
            if (variant,op)==(228,51):
                left,right=literal(regs.get(b)),literal(regs.get(a))
                if type(left)is int and type(right)is int:
                    write(c,left>=right);return True
                if {type(left),type(right)}=={int,str}:
                    proof={'pc':pc,'left_register':b,'right_register':a,'left':left,'right':right,
                        'operator':'>=','guard':'standard Luau primitive ordering and reviewed lazy/cache identities'}
                    frontier.update({'kind':'primitive_order_type_error','normal_return_refuted_in_guarded_model':True,**proof})
                    event['upstream_type_error']=proof;return False
                frontier.update({'kind':'unproved_ordering','pc':pc,'left':left,'right':right});return False
            if (variant,op) in ((163,47),(82,81)):
                value=deepcopy(regs.get(a))
                frontier.update({'kind':'return','pc':pc,'results':[value],
                    'guard':'reviewed path has no calls or local capture allocations; source close loops are empty',
                    'tables':deepcopy(tables)})
                event['upstream_return']={'source':a,'results':[value]};return False
            return None
        return transfer
    return factory


def truth_precondition(value,desired=True):
    """Weakest truth condition for a captured plain-table selection.

    This is a typed Lua-value predicate, not a uint32 equation or a claim that
    the condition holds. No finite list of possible runtime type names is used.
    """
    if type(desired)is not bool:raise ValueError('Boolean postcondition required')
    selection=value.get('table_select') if type(value)is dict else None
    if selection is None:return {'unresolved':'not a reviewed table selection'}
    terms=[];seen=[]
    for row in selection['entries']:
        key=row['key'];known=lua_truth(row['value'])
        if type(key)not in (str,int,bool) or known is None:
            return {'unresolved':'symbolic key or entry value'}
        if any(type(k)is type(key) and k==key for k in seen):raise ValueError('Duplicate Lua key')
        seen.append(key)
        if known:terms.append({'typed_equal':[deepcopy(selection['key']),deepcopy(key)]})
    predicate={'any':terms}
    return predicate if desired else {'not':predicate}


def dependency_graph(owner,trace,capture_proofs=(),argument_bindings=()):
    """Trace-order SSA with explicit table-memory versions and scoped leaves.

    Unsupported definitions become unknown leaves. Data flow is never inferred
    from equal numeric values, register numbers in other frames, or PC proximity.
    """
    nodes={};versions={};memory={};sinks=[]
    def node(name,deps=(),**facts):
        nodes[name]={'dependencies':list(dict.fromkeys(deps)),**facts};return name
    def read(register):
        return versions.get(register,node(f'frame{owner}:initial-nil:r{register}',kind='fresh_frame_nil'))
    capture_nodes={}
    for ordinal,proof in enumerate(capture_proofs,1):
        external=node('cell:'+proof['cell'],kind='guarded_call_time_storage',guard=proof['guard'])
        capture_nodes[ordinal]=node(f'frame{owner}:capture{ordinal}',[external],kind='capture_binding')
    def cap(ordinal):return memory.get(ordinal,capture_nodes.get(ordinal,node(f'frame{owner}:unknown-capture{ordinal}',kind='unknown')))
    for step,event in enumerate(trace):
        v,o,a,b,c=(event[k] for k in ('variant','opcode','operand1','H','operand3'))
        pc=event['pc'];before=dict(versions)
        def old(register):return before.get(register,node(f'frame{owner}:initial-nil:r{register}',kind='fresh_frame_nil'))
        for index,write in enumerate(event.get('register_writes',[])):
            deps=[];kind='source_transfer'
            if 'parameter_flow' in event:
                ordinal=write['register']-event['parameter_flow']['destination']
                binding=argument_bindings[ordinal] if ordinal<len(argument_bindings) else f'frame{owner}:argument{ordinal+1}'
                if binding not in nodes:node(binding,kind='argument_binding')
                deps=[binding]
            elif 'upstream_not' in event:deps=[old(c)]
            elif (v,o)==(163,12):deps=[cap(c),old(b)]
            elif 'upstream_capture_read' in event:deps=[cap(event['upstream_capture_read']['ordinal'])]
            elif 'upstream_fused_copy' in event:
                if index==0:deps=[node(f'constant:{b}',kind='guarded_primitive')]
                else:deps=[read(event['upstream_fused_copy']['second_source'])]
            elif 'upstream_return_binding' in event:deps=[event['upstream_return_binding']['dependency']]
            elif 'upstream_compare' in event:deps=[old(event['upstream_compare']['source'])]
            elif (v,o)in ((228,21),(228,140)):deps=[old(a)]
            elif (v,o)==(228,97):deps=[node(f'constant:{a}',kind='guarded_primitive')]
            elif (v,o) in ((157,34),(163,147),(228,31)):deps=[old(b)]
            elif (v,o)==(228,23):deps=[old(a if index==0 else b)]
            elif 'scoped_capture_read' in event:deps=[cap(a)]
            elif 'capture_table_read' in event:deps=[cap(a),old(b)]
            elif 'pure_builtin_summary' in event:deps=[old(event['pure_builtin_summary']['argument_register'])]
            elif 'boolean_transfer' in event:deps=[old(event['boolean_transfer']['source'])]
            elif 'materialized_constant' in event:deps=[node(f'constant:{b}',kind='guarded_lazy_constant')]
            elif (v,o)not in ((157,69),(163,62),(228,139),(228,113)):
                deps=[node(f'frame{owner}:unknown-definition:{step}:{index}',kind='unknown')];kind='unmodeled_definition'
            versions[write['register']]=node(f'frame{owner}:r{write["register"]}@{pc}:{step}:{index}',deps,kind=kind,pc=pc)
        effect=event.get('upstream_table_write')
        if effect:
            ordinal=effect['capture'];deps=[cap(ordinal),old(effect['key_register'])]
            if 'value_register'in effect:deps.append(old(effect['value_register']))
            else:deps.append(node(f'constant:{effect["constant"]["reference"]}',kind='guarded_primitive'))
            memory[ordinal]=node(f'frame{owner}:capture{ordinal}.table-write@{pc}:{step}',deps,kind='guarded_table_write',pc=pc)
            sinks.append(memory[ordinal])
        if 'upstream_return'in event:
            sinks.append(node(f'frame{owner}:return@{pc}',[read(event['upstream_return']['source'])],kind='return',pc=pc))
        if 'upstream_type_error'in event:
            sinks.append(node(f'frame{owner}:type-error@{pc}',[old(b),old(a)],kind='guarded_type_error',pc=pc))
    return {'nodes':nodes,'register_versions':versions,'effect_and_return_sinks':sinks}


def backward_slice(graph,sink,budget=4096):
    if type(budget)is not int or not 1<=budget<=16384:raise ValueError('Slice budget invalid')
    pending=[sink];seen=set();leaves=[]
    while pending and len(seen)<budget:
        current=pending.pop()
        if current in seen:continue
        seen.add(current);record=graph['nodes'].get(current)
        if record is None or not record['dependencies']:leaves.append(current)
        else:pending.extend(record['dependencies'])
    return {'sink':sink,'visited':sorted(seen),'leaves':sorted(leaves),
            'budget_exhausted':bool(pending),'scope':'recorded guarded prefix only'}


def returned_summary(analysis):
    if analysis['unexplored_worklist'] or len(analysis['paths'])!=1:return None
    path=analysis['paths'][0];frontier=path['frontier']
    if frontier.get('kind')!='return' or frontier.get('pc')!=44 or len(frontier['results'])!=1:return None
    # Only this reviewed helper restores both incoming captured tables.
    expected={'capture:544:1':[], 'capture:544:2':[{'key':False,'value':True},{'key':True,'value':False}]}
    if frontier.get('tables')!=expected or analysis.get('initial_capture_tables')!=expected:return None
    return {'value':frontier['results'][0],'dependency':'frame544:return@44',
            'restored_captured_tables':True,'guard':frontier['guard']}


def resume_factory(summary):
    """Only the validated normal-return transfer at516/162; no callee runs."""
    def factory(context,captures,decisions,frontier,branch):
        def transfer(variant,op,a,b,c,regs,event):
            if (variant,op,event['pc'])!=(228,93,162):return None
            callee=regs.get(2)
            window=event.get('instruction_window',{})
            frame_ok=(a,b,c)==(0,2,23) and all(len(window.get(k,[]))>=2 for k in ('j','O','Z'))
            frame_ok=frame_ok and (window['j'][1],window['O'][1],window['Z'][1])==(1,23,2)
            if (not frame_ok or summary.get('restored_captured_tables')is not True
                    or type(callee)is not dict or callee.get('symbolic_closure')!=544
                    or literal(regs.get(24))!='table'
                    or regs.get(25)!={'builtin_type_of':{'symbol':'global.Instance'}}):
                frontier.update({'kind':'summary_binding_mismatch','pc':162});return False
            regs[23]=deepcopy(summary['value'])
            event['upstream_return_binding']={**summary,'destination':23,'next_pc':164,
                'scope':'conditional source93 normal-return transfer, table effects restored'}
            return {'next_pc':164}
        return transfer
    return factory


def run(source,data,output,boundary_observer=None):
    protected={source.resolve(),data.resolve()}
    if any(p.resolve()in protected for p in (output,output/'upstream-analysis.json')):
        raise ValueError('Output aliases input')
    text=source.read_text(encoding='ascii')
    anchors=[{'text':s,'offset':text.index(s)} for s in ANCHORS]
    summaries=[];parent_resumptions=[];invariants=[]
    def observer(state,reason):
        if state['pc']!=8521 or reason!='opaque_call_boundary':return
        metadata=state['metadata'];context=metadata.constants
        heap,_=materialize_heap(state['heap'],context)
        call=state['trace'][-1]['call_metadata']
        if call['callee_expression'].get('symbolic_closure')!=516:return
        parent_captures,parent_proof=capture_inputs(call['callee_expression'],state['registers'],heap)
        argument=primitive(context,112)
        args=[argument['value'],call['argument_expressions'][1]]
        parent=trace_body(metadata.closures.templates[516]['header'],args,parent_captures,context)
        for path in parent['paths']:
            downstream=path['frontier'].get('call',{})
            closure=downstream.get('callee_expression',{})
            owner=closure.get('symbolic_closure') if type(closure)is dict else None
            if owner not in (544,258):continue
            captures,proof=capture_inputs(closure,state['registers'],heap)
            trace=trace_body(metadata.closures.templates[owner]['header'],downstream['arguments'],captures,context,
                             owner=owner,extension_factory=extension(owner),budget=1024,instruction_window=2,
                             enable_variant82=True)
            trace['initial_capture_tables']={f'capture:{owner}:{ordinal}':deepcopy(value['plain_entries'])
                for ordinal,value in captures.items() if type(value)is dict and 'plain_entries'in value}
            prefix_graph=dependency_graph(516,path['trace'],parent_proof,['constant:112','root664.r74@8521'])
            bindings=[prefix_graph['register_versions'][r] for r in (24,25)] if owner==544 else ['constant:8','constant:45']
            graphs=[]
            for child_path in trace['paths']:
                graph=dependency_graph(owner,child_path['trace'],proof,bindings)
                # Retain actual upstream definitions over child external stubs.
                graph['nodes']={**graph['nodes'],**prefix_graph['nodes']}
                graphs.append({'graph':graph,'slices':[backward_slice(graph,sink) for sink in graph['effect_and_return_sinks']]})
            summary={'owner':owner,'caller':516,'caller_pc':path['pc'],'caller_decisions':path['decisions'],
                'arguments':downstream['arguments'],'captures':proof,'analysis':trace,'guards':state['conditions'],
                'backward_graphs':graphs}
            returned=returned_summary(trace) if owner==544 else None
            if returned is not None:
                summary['return_proof']=returned
                summary['truth_precondition']=truth_precondition(returned['value'])
                parent_resumptions.append(trace_body(metadata.closures.templates[516]['header'],args,parent_captures,context,
                    extension_factory=resume_factory(returned),instruction_window=2))
                invariants.append({'name':'body544-return-truth','target':'callee516.call162.result1',
                    'predicate':summary['truth_precondition'],'guard':returned['guard']})
            summaries.append(summary)
        if boundary_observer is not None:
            boundary_observer(deepcopy(state),reason)
    base=caller_run(source,data,output/'caller',boundary_observer=observer)
    propagation=propagate(base['candidate_solution']['models'],base['constraints'],invariants)
    normal_false_refuted=any(s['owner']==258 and len(s['analysis']['paths'])==1 and
        s['analysis']['paths'][0]['frontier'].get('normal_return_refuted_in_guarded_model')is True for s in summaries)
    refutations=[]
    if normal_false_refuted:
        for resumed in parent_resumptions:
            for path in resumed['paths']:
                call=path['frontier'].get('call',{})
                callee=call.get('callee_expression',{})
                if (type(callee)is dict and callee.get('symbolic_closure')==258
                        and call.get('arguments')==[520442978,4] and not path['patches']):
                    refutations.append({'caller':516,'pc':path['pc'],'decisions':path['decisions'],
                        'normal_return_refuted_in_guarded_model':True,'source_summary':'258.pc71',
                        'guard':'same cached258 template, lazy/cache identities and no hidden context effects'})
    # Necessary normal-return conditions, not assumed runtime values. The
    # matching call at102 is reached precisely when the helper result is false.
    local_formula=[[-1,2]] if any(r['pc']==131 for r in refutations) else []
    if any(r['pc']==102 for r in refutations):local_formula.append([-1,3])
    local_query={'variable_ids':{'normal_root8521_return':1,'Instance_truthy':2,'type_Instance_is_table':3},
        'clauses':local_formula,'normal_and_false':sat(local_formula+[[1],[-2]]),
        'normal_and_non_table':sat(local_formula+[[1],[-3]]),
        'normal_and_true':sat(local_formula+[[1],[2]]),
        'scope':'necessary guarded path condition only, SAT is not a runtime witness'}
    gates=propagate_gates(base['gate_queries'],{'guarded8521.false-branch-normal-return-refuted':True} if normal_false_refuted else {})
    result={'source_sha256':base['source_sha256'],'data_sha256':base['data_sha256'],
        'constraints':base['constraints'],
        'source_evidence':anchors,'summaries':summaries,'parent_resumptions':parent_resumptions,
        'invariants':invariants,'constraint_propagation':propagation,'candidate_solution':propagation['solution'],
        'caller_path_refutations':refutations,
        'backward_normal_return_query':local_query,
        'bridge_obligations':['remaining caller516 outcomes/effects','root664 return/continuation to981',
                              'root V@981 same-activation reaching definition','complete context/cache/alias coverage'],
        'gate_queries':gates,'verified_hierarchy':None,'unconditionally_resolved_gates':[],
        'formal_promotion_patch':{'applicable':False,'operations':[]},
        'network_requests':0,'application_calls_executed':0,'factory_invocations':0}
    output.mkdir(parents=True,exist_ok=True)
    (output/'upstream-analysis.json').write_text(json.dumps(result,indent=2,allow_nan=False)+'\n',encoding='utf-8')
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,default=Path('output/stage1-vm-source.lua.txt'))
    p.add_argument('--data',type=Path,default=Path('output/stage1-vm-data.bin'))
    p.add_argument('--output',type=Path,default=Path('output/phase30'))
    a=p.parse_args();r=run(a.source,a.data,a.output)
    print([(s['owner'],[(p['pc'],p['frontier'].get('kind'),p['trace'][-1]['opcode']) for p in s['analysis']['paths']]) for s in r['summaries']])
