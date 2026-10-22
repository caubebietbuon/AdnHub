"""Bounded symbolic worklist over a pinned, explicitly guarded snapshot.

Constructor operations parse metadata only. Unknown calls are terminal, field
effects havoc captured slots, and exhausted budgets never mean completeness.
"""
from collections import deque
from copy import copy, deepcopy
import hashlib
import json

from fused_call_analyzer import Closures, Constants
from obligation_resolver import patch_equation
from prologue_analyzer import mix
from reconstructor import apply_fill_copy
from scope_tracer import instruction
from string_resolver import read_length_payload


def reduce_conditions(conditions):
    """Unit propagation over Boolean atoms and typed uint32 interval literals."""
    units, bounds = {}, {}
    for row in conditions:
        if row['kind']=='atom':
            name,truth=row['name'],row['truth']
            if type(name) is not str or type(truth) is not bool: raise ValueError('Typed path atom required')
            if name in units and units[name]!=truth:
                return {'satisfiable':False,'conflict':row,'units':units,'bounds':bounds}
            units[name]=truth
        elif row['kind']=='bv_interval':
            name,lo,hi=row['name'],row['lo'],row['hi']
            if type(name) is not str or type(lo) is not int or type(hi) is not int:
                raise ValueError('Typed uint32 range required')
            old=bounds.get(name,[0,0xffffffff])
            bounds[name]=[max(old[0],lo),min(old[1],hi)]
            if bounds[name][0]>bounds[name][1]:
                return {'satisfiable':False,'conflict':row,'units':units,'bounds':bounds}
        else: raise ValueError('Unknown path constraint')
    return {'satisfiable':True,'conflict':None,'units':units,'bounds':bounds}


class MetadataState:
    def __init__(self,source,backing,entries,defs):
        self.constants=Constants(backing,entries)
        self.closures=Closures(source,self.constants,664,181,defs)

    def fork(self):
        other=object.__new__(MetadataState)
        other.constants=copy(self.constants)
        for name in ('positions','effects','text_cache'): setattr(other.constants,name,dict(getattr(self.constants,name)))
        for name in ('events','violations'): setattr(other.constants,name,deepcopy(getattr(self.constants,name)))
        other.closures=Closures(self.closures.source,other.constants,664,181,self.closures.defs)
        for name in ('templates','bindings','obligations'): setattr(other.closures,name,deepcopy(getattr(self.closures,name)))
        return other

    def replay_prefix(self,evidence):
        """Rebuild source patch order and private template fills; never live cache."""
        patches=iter(evidence['path_local_patch_events'])
        pending=next(patches,None)
        filled=set()
        templates=evidence['guarded_template_evidence']
        for event in evidence['root_analysis']['trace']:
            equation=patch_equation(event)
            if equation:
                word,ref,operand=equation
                key=operand if word is None else operand^mix(event['state_words_before'][0 if word=='V' else 1])
                if pending is None or (pending['pc'],pending['reference_id'],pending['key'])!=(event['pc'],ref,key):
                    raise ValueError('Patch replay disagrees with pinned trace')
                if not self.constants.observe({k:v for k,v in pending.items() if k not in (
                        'directory_before','directory_after','cumulative_payload_xor')}):
                    raise ValueError('Recorded patch is not accepted during replay')
                observed=self.constants.events[-1]
                if any(observed[k]!=pending[k] for k in ('directory_before','directory_after','cumulative_payload_xor')):
                    raise ValueError('Patch epoch mismatch')
                pending=next(patches,None)
            creation=event.get('symbolic_closure_creation')
            if creation and creation['child'] not in filled:
                child=creation['child']
                template=deepcopy(templates.get(child,templates.get(str(child))))
                if template is None: raise ValueError('Missing pre-fill template')
                footer=template['header']['footer']; start,end=footer['backing_slice_range']
                self.constants.backing=apply_fill_copy(self.constants.backing,start,end-start,footer['fill_byte'])
                self.closures.templates[child]=template
                filled.add(child)
        if pending is not None: raise ValueError('Unconsumed patch observations')

    def constructor(self,child,descriptor,pc,registers):
        result=self.closures.build(child,descriptor,pc,228,registers)
        proof=deepcopy(self.closures.bindings[-1] if result is not None else self.closures.obligations[-1])
        if result is not None:
            header=self.closures.templates[child]['header']
            proof['template_evidence']={name:header[name] for name in ('key','format','factory_slot','plain_sha256')}
            proof['template_evidence']['footer_consumed']=header['footer']['remaining_bytes']==0
        return result,proof

    def patch(self,reference,key,pc):
        if not self.constants.observe({'reference_id':reference,'key':key,'pc':pc,'variant':228}):
            return False
        position=self.constants.positions[reference]
        try: read_length_payload(self.constants.backing,position)
        except (ValueError,IndexError): return False
        return True


def state_key(state):
    constants=getattr(state['metadata'],'constants',None)
    templates=getattr(getattr(state['metadata'],'closures',None),'templates',{})
    return json.dumps([state['pc'],state['registers'],state['conditions'],state['heap'],state['effects_epoch'],
                       sorted(state['captured']),
                       getattr(constants,'positions',{}),getattr(constants,'effects',{}),
                       hashlib.sha256(constants.backing).hexdigest() if constants else None,
                       {str(k):(v['header']['plain_sha256'],v.get('cleanup_applied')) for k,v in templates.items()},
                       state['arrays']],sort_keys=True,separators=(',',':'))


def explore(arrays,entry,registers,metadata,captured=(),max_steps=128,max_paths=16,initial_conditions=(),boundary_observer=None):
    """Automatic forks + reduction, with closed-world claims explicitly blocked.

    Unknown ordered comparisons use fresh opaque atoms unless the value is a
    known uint32 expression; NaN/object comparisons never become integer ranges.
    """
    if type(max_steps) is not int or not 1<=max_steps<=512 or type(max_paths) is not int or not 1<=max_paths<=64:
        raise ValueError('Explorer budget invalid')
    limit=min(map(len,arrays.values()))
    if type(entry) is not int or not 1<=entry<=limit: raise ValueError('Entry outside snapshot')
    start={'pc':entry,'registers':deepcopy(registers),'conditions':list(initial_conditions),
           'heap':{},'trace':[],'metadata':metadata,'effects_epoch':0,'arrays':deepcopy(arrays),'captured':list(captured)}
    queue=deque([start]); terminals=[]; pruned=[]; seen=set(); explored=0; dropped_work=0
    state_budget=min(max_steps*max_paths,512)
    def finish(state,reason):
        if boundary_observer is not None:
            snapshot=deepcopy({k:v for k,v in state.items() if k!='metadata'})
            # Callbacks get full isolation, including the directory/definition
            # containers treated as immutable by internal path-local forks.
            snapshot['metadata']=deepcopy(state['metadata'])
            boundary_observer(snapshot,reason)
        terminals.append({k:deepcopy(state[k]) for k in ('pc','conditions','trace','registers','effects_epoch')}|
                         {'reason':reason,'actual_activation_proved':False})
    while queue and len(terminals)<max_paths and explored<state_budget:
        state=queue.popleft()
        check=reduce_conditions(state['conditions'])
        if not check['satisfiable']:
            pruned.append(check); continue
        identity=state_key(state)
        if identity in seen: finish(state,'repeated_abstract_state'); continue
        seen.add(identity)
        if len(state['trace'])>=max_steps: finish(state,'step_budget'); continue
        pc=state['pc']; values=state['registers']; current=state['arrays']
        if not 1<=pc<=limit: finish(state,'outside_snapshot'); continue
        op,a,b,c=instruction(current,pc,228)
        row={'pc':pc,'instruction':[op,a,b,c],'writes':[]}
        state['trace'].append(row); explored+=1; next_pc=pc+1
        def write(register,value):
            values[register]=value; row['writes'].append({'register':register,'value':deepcopy(value)})
        def atom(name): state['conditions'].append({'kind':'atom','name':name,'truth':True})
        if op==82:
            if state['metadata'] is None: finish(state,'constructor_metadata_unavailable'); continue
            result,proof=state['metadata'].constructor(b,c,pc,values)
            row['constructor_metadata']=proof
            if result is None: finish(state,'constructor_metadata_boundary'); continue
            atom(f'constructor-cache-and-context-agreement:{pc}')
            result['symbolic_instance']=f'constructor:{pc}:step:{len(state["trace"])}'
            for capture in proof['captures']:
                identity=capture.get('cell_identity','')
                if identity.startswith('frame:664:register:'):
                    register=int(identity.rsplit(':',1)[1])
                    if register not in state['captured']: state['captured'].append(register)
            write(a,result)
        elif op in (31,23):
            sources=[b] if op==31 else [a,b]
            if any(r not in values for r in sources): finish(state,'unknown_copy_source'); continue
            before=[deepcopy(values[r]) for r in sources]
            for offset,value in enumerate(before): write(c+offset,value)
        elif op in (139,134):
            if op==139: write(a,c)
            else: write(c,a); write(c+1,b)
        elif op==32: next_pc=a+1
        elif op in (89,92):
            target=values.get(a if op==89 else b)
            if type(target) is not int: finish(state,'unknown_register_jump'); continue
            next_pc=target+1
        elif op==95:
            base=deepcopy(values.get(c))
            if base is None: finish(state,'unknown_field_base'); continue
            state['effects_epoch']+=1
            state['heap'].clear()
            for reg in state['captured']:
                if reg in values: values[reg]={'havoc_capture':reg,'epoch':state['effects_epoch']}
            atom(f'field-and-key-read-succeeds:{pc}:{state["effects_epoch"]}')
            atom('no-reflective-frame-code-cache-mutation')
            write(b,{'symbolic_field':{'base':base,'key_reference':a,'epoch':state['effects_epoch']}})
            row['escaping_capture_effects']='havoc; hidden callback outcomes remain unmodeled'
        elif op==149:
            identity=f'fresh-table:{pc}:{len(state["trace"])}'
            state['heap'][identity]={}; write(c,{'fresh_plain_table':identity})
        elif op==154:
            table=values.get(c)
            identity=table.get('fresh_plain_table') if type(table) is dict else None
            if identity not in state['heap']: finish(state,'unproved_table_write_target'); continue
            atom(f'non-nil-non-NaN-lazy-key:{b}:at:{pc}')
            atom('lazy-reader-cache-agreement-and-no-hidden-writes')
            state['heap'][identity][f'lazy-key:{b}']={'lazy-value-reference':a}
            row['private_table_write']={'table':identity,'key_reference':b,'value_reference':a}
        elif op==100:
            if state['metadata'] is None or not state['metadata'].patch(a,c,pc):
                finish(state,'patch_reader_boundary'); continue
            atom('lazy-reader-cache-agreement-and-no-hidden-writes')
            # Exact source100 continuation, not the older numeric-prefix noop70.
            for name,value in (('j',74),('O',144),('Z',178),('B',68)): current[name][pc-1]=value
            row['code_rewrite']={'j':74,'O':144,'Z':178,'B':68}
        elif op==68: pass  # Source-confirmed empty branch.
        elif op in (13,172):
            value=values.get(a)
            if type(value) is int:
                truth=value<=c if op==13 else value<c
                next_pc=pc+1 if truth else b+1
                row['reduced_numeric_branch']=truth
            else:
                # Opaque comparison outcomes remain guarded, not defaulted.
                predicate=f'comparison:{pc}:{len(state["trace"])}:{json.dumps(value,sort_keys=True)}'
                state['effects_epoch']+=1
                state['heap'].clear()
                for reg in state['captured']:
                    if reg in values: values[reg]={'havoc_capture':reg,'epoch':state['effects_epoch']}
                atom('no-reflective-frame-code-cache-mutation')
                for truth in (True,False):
                    if len(queue)+len(terminals)>=max_paths:
                        dropped_work+=1
                        continue
                    branch=deepcopy({k:v for k,v in state.items() if k!='metadata'})
                    branch['metadata']=state['metadata'].fork() if state['metadata'] is not None else None
                    branch['conditions'].append({'kind':'atom','name':predicate,'truth':truth})
                    branch['pc']=pc+1 if truth else b+1
                    queue.append(branch)
                continue
        elif op==44:
            row['call_metadata']={'callee_register':a,'callee_expression':deepcopy(values.get(a)),
                'argument_expressions':[{'lazy_constant_reference':c},deepcopy(values.get(b))],
                'normal_return_pc':pc+1,'effects':'unknown','callee_invoked':False}
            finish(state,'opaque_call_boundary'); continue
        elif op in (4,93,120,150,194): finish(state,'opaque_call_boundary'); continue
        elif op in (99,160): finish(state,'conditional_return_boundary'); continue
        else: finish(state,'unsupported_source_transfer'); continue
        state['pc']=next_pc
        queue.append(state)
    return {'terminal_paths':terminals,'refuted_conditions':pruned,'explored_instructions':explored,
            'unexplored_worklist':len(queue)+dropped_work,'path_budget_exhausted':bool(queue) or bool(dropped_work),
            'dropped_worklist_branches':dropped_work,'state_budget':state_budget,
            'all_application_paths_covered':False,'factory_invocations':0,'application_calls_executed':0}
