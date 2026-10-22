"""Phase29 guarded, frame-scoped metadata transfer; never invoke a callee.

Rebuilds the caller and its private template/cache projection. Only reviewed
Python transfer rules operate on data. A callee constant is never a caller V
constraint without a separately established, same-frame reaching definition.
"""
import argparse
from copy import deepcopy
import json
from pathlib import Path

from automated_solver import run as caller_run
from checkpoint_aligner import checkpoint_factory
from finite_solver import solve
from gate_solver import query_gate
from fused_call_analyzer import summarize_fused_call
from lazy_tracer import inspect_reference
from obligation_resolver import source_transfer
from prologue_analyzer import analyze
from symbolic_resolver import arrays_from_candidate


ANCHORS=(
    'if o==96 then t[H[W]]=not t[i[W]];',
    'else T=g[i[W]];t[A[W]]=T[6][T[5]][t[H[W]]];',
    'else W=if t[i[W]]then A[W]else H[W];end;',
    'else t[i[W]]=_(t[H[W]],A[W]);',
    'else t[i[f]]=t[A[f]](t[H[f]]);',
    '[25]=type,',
    't[i[W+1]](Z[W+1],O[W+1]);',
    'if xJ~=74 then T,d={...},w[W];K(T,1,i[W],d,t);',
)


def primitive(context,reference):
    """Read an effective primitive offset, rejecting pending payload masks."""
    if context is None or type(reference) is not int or not 1<=reference<=len(context.entries): return None
    if context.effects.get(reference,0)!=0: return None
    position=context.positions.get(reference,context.entries[reference-1]['value'])
    entries=list(context.entries); entries[reference-1]={'value':position}
    row=inspect_reference(context.backing,entries,reference)
    if row.get('status')!='explicit_python_primitive_reader': return None
    if type(row.get('value')) not in (int,bool): return None
    return {'reference':reference,'position':position,'kind':row['kind'],'value':row['value']}


def truth(value):
    """Lua truthiness: zero and empty strings are true; symbolic nil is unknown."""
    if value is None or value is False: return False
    if type(value) in (int,float,str,bool): return True
    if type(value) is dict and 'boolean_not' in value:
        nested=truth(value['boolean_not'])
        return None if nested is None else not nested
    if type(value) is dict and 'lua_truth' in value: return truth(value['lua_truth'])
    return None


def boolean_not(value):
    known=truth(value)
    return not known if known is not None else {'boolean_not':deepcopy(value)}


def table_read(table,key):
    """Typed keys: Lua true is distinct from number1. No __index dispatch."""
    if type(table) is not dict or 'plain_entries' not in table: return None
    entries=table['plain_entries']
    for row in entries:
        if type(row['key']) is type(key) and row['key']==key:
            return {'resolved':True,'value':deepcopy(row['value'])}
    # Exact two-key Boolean complement, not an assumed arbitrary lookup.
    if len(entries)==2 and all(type(r['key']) is bool and type(r['value']) is bool for r in entries):
        mapping={r['key']:r['value'] for r in entries}
        if mapping=={False:True,True:False} and type(key) is dict and 'boolean_not' in key:
            value=key['boolean_not']
            known=truth(value)
            return {'resolved':True,'value':known if known is not None else {'lua_truth':value}}
    return None


def materialize_heap(heap,context):
    result={}; evidence=[]
    for identity,entries in heap.items():
        decoded=[]; valid=True
        for key,value in entries.items():
            if not key.startswith('lazy-key:') or 'lazy-value-reference' not in value:
                valid=False; break
            k=primitive(context,int(key.split(':')[1])); v=primitive(context,value['lazy-value-reference'])
            if k is None or v is None: valid=False; break
            # Colliding actual keys invalidate this projection instead of
            # inferring independence from distinct reference identifiers.
            if any(type(r['key']) is type(k['value']) and r['key']==k['value'] for r in decoded):
                valid=False; break
            decoded.append({'key':k['value'],'value':v['value']}); evidence.extend([k,v])
        if valid: result[identity]={'plain_entries':decoded}
    return result,evidence


def capture_inputs(callee,registers,heap):
    captures={}; evidence=[]
    for ordinal,row in enumerate(callee['captures'],1):
        identity=row.get('cell_identity','')
        if identity.startswith('frame:664:register:') and row.get('span')==1:
            register=int(identity.rsplit(':',1)[1])
            value=deepcopy(registers.get(register,{'unknown_register':register}))
            table=value.get('fresh_plain_table') if type(value) is dict else None
            if table in heap: value=deepcopy(heap[table])
            captures[ordinal]=value
            evidence.append({'ordinal':ordinal,'cell':identity,'call_time_value':value,
                             'guard':'caller guarded reaching definitions; no intervening hidden cell writes'})
    return captures,evidence


def trace_body(header,arguments,captures,context,max_paths=8,budget=512,owner=516,extension_factory=None,instruction_window=0,enable_variant82=False):
    """Replay a bounded initializer with explicit Boolean path forks.

    Capture values are call-time projections, not immutable cell contents.
    Calls, unknown capture indexing and missing predicates remain boundaries.
    """
    if type(max_paths) is not int or not 1<=max_paths<=16: raise ValueError('Invalid path budget')
    if type(budget) is not int or not 1<=budget<=2048: raise ValueError('Invalid step budget')
    arrays,words=arrays_from_candidate(header)
    queue=[{}]; results=[]
    while queue and len(results)<max_paths:
        decisions=queue.pop(0); frontier={}; branch={}; truth_facts={}
        local_context=deepcopy(context)
        extension=extension_factory(local_context,captures,decisions,frontier,branch) if extension_factory else None
        def transfer(variant,op,a,b,c,regs,event):
            pc=event['pc']
            if extension is not None:
                handled=extension(variant,op,a,b,c,regs,event)
                if handled is not None: return handled
            if (variant,op)==(157,73):
                if not 0<=a<=10000: return False
                for offset in range(a): regs[c+offset]=deepcopy(arguments[offset] if offset<len(arguments) else None)
                event['parameter_flow']={'argument_count':a,'destination':c,'values':deepcopy(arguments[:a])}
                return True
            if variant==228 and op==96:
                regs[b]=boolean_not(regs.get(a)); event['boolean_transfer']={'source':a,'destination':b,'value':regs[b]}
                return True
            if variant==228 and op==146:
                table=captures.get(a); key=regs.get(b); result=table_read(table,key)
                if result is None:
                    frontier.update({'kind':'unresolved_capture_table_read','capture':a,'key':key,'pc':pc})
                    return False
                regs[c]=result['value']; event['capture_table_read']={'capture':a,'key':key,'destination':c,'value':regs[c]}
                return True
            if variant==228 and op==181:
                value=regs.get(a); condition=truth(value)
                if condition is None:
                    identity=json.dumps(value,sort_keys=True)
                    condition=truth_facts.get(identity)
                    if condition is None and pc not in decisions:
                        branch.update({'pc':pc,'expression':deepcopy(value)})
                        return False
                    if condition is None: condition=decisions[pc]
                    truth_facts[identity]=condition
                    event['path_predicate']={'expression':value,'truth':condition}
                event['truth_branch']={'register':a,'truth':condition}
                return {'next_pc':(c if condition else b)+1}
            if variant==228 and op>=196 and op!=197:
                value=regs.get(b)
                if type(value) is not int or not 0<=value<=0xffffffff or not 0<=c<=0xffffffff:
                    frontier.update({'kind':'unproved_uint32_xor_operand','pc':pc,'value':value}); return False
                regs[a]=value^c
                event['uint32_xor']={'input':value,'immediate':c,'result':regs[a],'destination':a}
                return True
            if (variant,op)==(228,75):
                if a not in captures:
                    frontier.update({'kind':'missing_capture','pc':pc,'ordinal':a}); return False
                regs[b]=deepcopy(captures[a]);event['scoped_capture_read']={'ordinal':a,'destination':b,'value':regs[b]}
                return True
            if (variant,op)==(228,150) and regs.get(c)=={'decoder_context_slot':25}:
                # A symbolic transfer for the source-pinned pure builtin;
                # never call type, look up a global, or assume Instance exists.
                regs[a]={'builtin_type_of':deepcopy(regs.get(b))}
                event['pure_builtin_summary']={'slot':25,'name':'type','argument_register':b,'destination':a,
                    'guard':'decoder context slot25 retains the source builtin type identity'}
                return True
            if (variant,op) in ((228,93),(228,150),(228,194),(228,4),(228,16)):
                frontier.update({'kind':'opaque_call','pc':pc,'registers':deepcopy(dict(regs))})
                return False
            return source_transfer(variant,op,a,b,c,regs,event,constants=local_context,extra=checkpoint_factory(local_context))
        state=analyze(arrays,header['layout']['entry_pc']['value'],*words,budget=budget,
            numeric_constant=lambda r: (primitive(local_context,r) or {}).get('value'),
            text_constant=local_context.text if local_context is not None else None,
            symbolic_environment=True,symbolic_field_reads=True,
            patch_observer=local_context.observe if local_context is not None else None,
            track_register_writes=True,source_transfer=transfer,instruction_window=instruction_window,
            enable_variant82=enable_variant82)
        if frontier.get('kind')=='opaque_call':
            event=state['trace'][-1]; pc=event['pc']; regs=frontier['registers']
            if event['opcode']==93:
                frontier['call']=summarize_fused_call(state['arrays'],pc,regs)
                lo,hi=frontier['call']['argument_range_half_open']
                projected=deepcopy(regs)
                copy=frontier['call']['pre_call_copy']
                projected[copy['destination']]=deepcopy(regs.get(copy['source']))
                frontier['call']['arguments']=[deepcopy(projected.get(r)) for r in range(lo,hi)]
            elif event['opcode']==16 and pc<min(map(len,state['arrays'].values())):
                target=state['arrays']['j'][pc]
                refs=[state['arrays'][name][pc] for name in ('Z','O')]
                frontier['call']={'callee_expression':deepcopy(regs.get(target)),
                    'first_capture_read':{'ordinal':event['operand1'],'destination':event['H']},
                    'target_register':target,'lazy_argument_references':refs,
                    'callee_invoked':False,'deferred':'all effects after first opaque call, including fused capture writes'}
                frontier['call']['arguments']=[(primitive(local_context,r) or {}).get('value',
                    {'lazy_constant_reference':r}) for r in refs]
                # Source16 reads the capture before calling. Apply this local
                # read only to the call summary, never subsequent instructions.
                if target==event['H']:
                    frontier['call']['callee_expression']=deepcopy(captures.get(event['operand1']))
            else:
                frontier['call']={'callee_invoked':False,'semantics':'unmodeled call transfer'}
        results.append({'decisions':decisions,'truth_facts':truth_facts,'branch_frontier':branch,
                        'trace':state['trace'],'frontier':frontier,
                        'pc':state['pc'],'stop':state['stop'],'patches':state['patches']})
        if branch:
            queue.extend([{**decisions,branch['pc']:v} for v in (True,False)])
    return {'paths':results,'unexplored_worklist':len(queue),'all_paths_covered':False,
            'callee_header_words':list(words),'frame':f'callee{owner}, distinct from caller664.V'}


def propagate(domain,constraints,invariants):
    """Only an explicit proven caller-site bridge licenses a numeric filter.

    Scope/gate certificates are separate from numeric equations. An observed
    callee-local invariant cannot constrain V just because it is an integer.
    """
    requirements=['same-activation','reaching-definition','value-flow-relation','complete-effects']
    admitted=[]; residual=[]; audits=[]
    for row in invariants:
        query=query_gate('bridge:'+row['name'],requirements,row.get('bridge_facts',{}))
        audits.append(query)
        if (row.get('target')=='caller664.V@981' and query['status']=='ENTAILED_CERTIFICATE'
                and 'expression' in row):
            admitted.append({'name':row['name'],'expression':row['expression'],
                             'guard_proved':True,'scope':row['target']})
        else: residual.append({'name':row['name'],'reason':'no proved, effect-complete same-activation reaching-definition bridge'})
    return {'solution':solve(domain,constraints+admitted),'admitted':admitted,
            'residual_invariants':residual,'bridge_queries':audits}


def propagate_gates(previous,scoped_facts):
    """Query global obligations afresh; local call facts keep their own names."""
    if any(not name.startswith('guarded8521.') for name in scoped_facts):
        raise ValueError('Call-local facts cannot overwrite global activation obligations')
    return [query_gate(q['gate'],q['requirements'],{**q['known_facts'],**scoped_facts}) for q in previous]


def run(source,data,output):
    output=Path(output)
    protected={source.resolve(),data.resolve()}
    if any(path.resolve() in protected for path in (output,output/'interprocedural-analysis.json')):
        raise ValueError('Output aliases input')
    text=source.read_text(encoding='ascii')
    anchors=[{'offset':text.index(s),'text':s} for s in ANCHORS]
    calls=[]
    def observer(state,reason):
        if reason!='opaque_call_boundary' or state['pc']!=8521: return
        call=state['trace'][-1].get('call_metadata',{})
        callee=call.get('callee_expression')
        if type(callee) is not dict or callee.get('symbolic_closure')!=516: return
        context=state['metadata'].constants
        header=state['metadata'].closures.templates[516]['header']
        heap,heap_evidence=materialize_heap(state['heap'],context)
        captures,capture_evidence=capture_inputs(callee,state['registers'],heap)
        arg=primitive(context,112)
        arguments=[arg['value'] if arg else {'lazy_constant_reference':112},call['argument_expressions'][1]]
        calls.append({'caller_pc':8521,'callee':516,'header_sha256':header['plain_sha256'],
            'arguments':arguments,'primitive_evidence':[arg] if arg else [],'heap_evidence':heap_evidence,
            'captures':capture_evidence,'guards':state['conditions']+[
                {'kind':'atom','name':'call-time-cache-cell-and-plain-table-agreement','truth':True}],
            'analysis':trace_body(header,arguments,captures,context)})
    base=caller_run(source,data,output/'caller',boundary_observer=observer)
    # Interprocedural observations have no established path to caller V@981.
    # Keep them as scoped residuals, not caller-domain numeric constraints.
    invariants=[]
    for call in calls:
        reads=sorted({event['capture_table_read']['capture'] for path in call['analysis']['paths']
                      for event in path['trace'] if 'capture_table_read' in event} |
                     {event['scoped_capture_read']['ordinal'] for path in call['analysis']['paths']
                      for event in path['trace'] if 'scoped_capture_read' in event} |
                     {path['frontier']['call']['first_capture_read']['ordinal'] for path in call['analysis']['paths']
                      if 'first_capture_read' in path['frontier'].get('call',{})})
        call['prefix_effect_summary']={
            'capture_ordinals_read':reads,'capture3_read_before_first_opaque_calls':3 in reads,
            'callee_state_words_unchanged_on_reviewed_prefixes':all(
                event['state_words_before']==call['analysis']['callee_header_words']
                for path in call['analysis']['paths'] for event in path['trace']),
            'caller_V_at981_reaching_definition_proved':False,
            'effects_past_opaque_calls':'unknown; no caller continuation or future cell stability inferred'}
        invariants.extend([
            {'name':'body516.argument1','value':call['arguments'][0],'target':'callee516.argument1'},
            {'name':'body516.capture3','value':call['captures'][2]['call_time_value'],'target':'callee516.capture3'},
            {'name':'body516.boolean-table','target':'callee516.capture1',
             'relation':'capture1[not argument2] = Lua truthiness(argument2)'},
            {'name':'body516.frame-state','target':'callee516.V,y',
             'values':call['analysis']['callee_header_words'],
             'scope':'initialization through first opaque call only; distinct lexical frame from caller V'},
        ])
    propagation=propagate(base['candidate_solution']['models'],base['constraints'],invariants)
    scoped_facts={'guarded8521.callee-is516':True} if calls else {}
    gates=propagate_gates(base['gate_queries'],scoped_facts)
    call_queries=[]
    for call in calls:
        for path in call['analysis']['paths']:
            target=path['frontier'].get('call',{}).get('callee_expression',{})
            body=target.get('symbolic_closure') if type(target) is dict else None
            if type(body) is not int: continue
            query=query_gate(f'body516.pc{path["pc"]}.activates663',['callee-is663'],{'callee-is663':body==663})
            call_queries.append({**query,'observed_body':body,'decisions':path['decisions'],
                                 'scope':'first opaque call on this guarded body516 prefix only'})
    result={'source_sha256':base['source_sha256'],'data_sha256':base['data_sha256'],
        'source_evidence':anchors,'calls':calls,'candidate_solution':propagation['solution'],
        'invariants':invariants,'constraint_propagation':propagation,
        'gate_queries':gates,'guarded_call_queries':call_queries,
        'unconditionally_resolved_gates':[], 'verified_hierarchy':None,
        'formal_promotion_patch':{'applicable':False,'operations':[]},
        'network_requests':0,'factory_invocations':0,'application_calls_executed':0}
    output.mkdir(parents=True,exist_ok=True)
    (output/'interprocedural-analysis.json').write_text(json.dumps(result,indent=2,allow_nan=False)+'\n',encoding='utf-8')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=Path('output/stage1-vm-source.lua.txt'))
    parser.add_argument('--data',type=Path,default=Path('output/stage1-vm-data.bin'))
    parser.add_argument('--output',type=Path,default=Path('output/phase29'))
    args=parser.parse_args()
    report=run(args.source,args.data,args.output)
    print([(c['callee'],[(p['pc'],p['frontier'].get('kind')) for p in c['analysis']['paths']]) for c in report['calls']])
