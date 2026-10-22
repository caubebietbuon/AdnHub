"""Phase31 path-sensitive alias, predicate and precision-boundary audit.

Only pinned Python metadata transfers are modeled. A local SAT model never
licenses a root V filter or a global hierarchy promotion on its own.
"""
import argparse
from copy import deepcopy
import json
from pathlib import Path

from interprocedural_solver import capture_inputs,materialize_heap,propagate,propagate_gates,trace_body
from interprocedural_solver import primitive as read_primitive
from path_domain import Aliases,Predicates,address,equal,heap_address,negate,truth
from upstream_solver import (extension,literal,returned_summary,resume_factory,run as upstream_run)


META={'builtin_getmetatable_of':{'symbol':'global.Instance'},'protected_value_possible':True}
TYPE_TABLE=equal({'builtin_type_of':{'symbol':'global.Instance'}},'table')
ANCHORS=('[59]=getmetatable,','else t[w[W]]=t[H[W]]==t[A[W]];',
         'else t[i[f]]=t[A[f]](t[H[f]]);','oJ={[6]=t,[5]=OJ};',
         'return O[W];elseif o~=101','return B[W];else W=if t[A[W]]~=t[H[W]]',
         'else W=if A[W]<t[H[W]]then W else i[W];')


def refined_extension(owner,return_summary=None,meta_summary=None):
    def factory(context,captures,decisions,frontier,branch):
        fallback=extension(owner)(context,captures,decisions,frontier,branch)
        resume=resume_factory(return_summary)(context,captures,decisions,frontier,branch) if return_summary else None
        predicates=Predicates();visits={};complement=True
        expected=[{'key':False,'value':True},{'key':True,'value':False}]
        def transfer(variant,op,a,b,c,regs,event):
            nonlocal complement
            pc=event['pc'];visits[pc]=visits.get(pc,0)+1
            if resume:
                handled=resume(variant,op,a,b,c,regs,event)
                if handled is not None:return handled
            if owner==516 and (variant,op,pc)==(228,93,126) and meta_summary is not None:
                window=event.get('instruction_window',{})
                valid=all(len(window.get(k,[]))>=2 for k in ('j','O','Z'))
                valid=valid and (a,b,c)==(0,2,23) and (window['j'][1],window['O'][1],window['Z'][1])==(1,23,2)
                callee=regs.get(2)
                if (not valid or type(callee)is not dict or callee.get('symbolic_closure')!=544
                        or regs.get(24)is not None or regs.get(25)!=META or not meta_summary['coverage_proved']):
                    frontier.update({'kind':'metatable_summary_binding_mismatch','pc':pc});return False
                regs[23]=deepcopy(meta_summary['expression'])
                event['refined_return_binding']={'destination':23,'expression':deepcopy(regs[23]),
                    'guard':'exhaustive reviewed helper partition and restored capture state; cache/context agrees'}
                return {'next_pc':128}
            if owner==516 and (variant,op,pc)==(228,150,123):
                if (regs.get(c)!={'decoder_context_slot':59} or regs.get(b)!={'symbol':'global.Instance'}
                        or predicates.decide(TYPE_TABLE)['value']is not True):
                    frontier.update({'kind':'unproved_getmetatable_binding','pc':pc});return False
                regs[a]=deepcopy(META)
                event['pure_builtin_summary']={'slot':59,'name':'getmetatable','argument_register':b,'destination':a,
                    'guard':'source builtin identity; table argument on this path; protected metatable result stays unknown'}
                return True
            if owner==516 and (variant,op,pc)==(228,123,30):
                if (a,b,c)!=(1,504247841,2) or b in regs:
                    frontier.update({'kind':'unproved_register_order','pc':pc});return False
                frontier.update({'kind':'fresh_register_order_failure','pc':pc,'register':b,'value':None,
                    'comparison':'2 < nil','normal_return_refuted_in_guarded_model':True,
                    'guard':'fresh516 register table; all prior summaries preserve unexposed parent cells; no reflection'})
                event['fresh_register_order_failure']=deepcopy(frontier)
                return False
            if (variant,op)==(163,97):
                left,right=literal(regs.get(b)),literal(regs.get(c))
                if left is not None and right is not None and (type(left)is dict or type(right)is dict):
                    frontier.update({'kind':'possible_equality_metamethod','pc':pc});return False
                regs[a]=equal(left,right)
                event['upstream_equal']={'left_register':b,'right_register':c,'destination':a,'expression':deepcopy(regs[a])}
                return True
            if (variant,op)in ((228,99),(82,111)):
                reference=c if variant==228 else a
                value=read_primitive(context,reference)
                if value is None or type(value['value'])is not bool:
                    frontier.update({'kind':'unproved_constant_return','pc':pc});return False
                frontier.update({'kind':'refined_return','pc':pc,'value':value['value'],
                    'primitive':value,'guard':'fresh helper frame has no allocated local capture cells; source close loops empty'})
                event['refined_return']=deepcopy(frontier)
                return False
            if (variant,op)in ((163,153),(228,96)):
                source=c if variant==163 else a
                regs[b]=negate(truth(regs.get(source)))
                event['boolean_transfer']={'source':source,'destination':b,'value':deepcopy(regs[b])}
                return True
            if variant==163 and op in (50,91) and (b if op==50 else c)==2:complement=False
            complement_read=((variant,op)==(163,12) and c==2 or (variant,op)==(228,146) and a==1)
            ordinal,destination=(2,a) if variant==163 else (1,c)
            if complement_read and complement and captures.get(ordinal)=={'plain_entries':expected}:
                value=regs.get(b)
                if type(value)is bool or type(value)is dict and any(k in value for k in ('not','any','all','typed_equal','atom')):
                    regs[destination]=negate(value)
                    event['upstream_complement_read']={'ordinal':ordinal,'source_register':b,'destination':destination,'value':deepcopy(regs[destination])}
                    return True
            if (variant==163 and op in (46,49)) or (variant,op)==(228,181):
                register=a if variant==228 or op==46 else c
                condition=truth(regs.get(register));choice=condition if type(condition)is bool else predicates.decide(condition)['value']
                token=f'{pc}:{visits[pc]}'
                if choice is None:
                    if token not in decisions:
                        branch.update({'pc':token,'instruction_pc':pc,'expression':deepcopy(condition)});return False
                    choice=decisions[token]
                predicates.assume(condition,choice)
                status=predicates.check()['status']
                event['path_predicate']={'expression':condition,'truth':choice,'status':status,'occurrence':token}
                if status!='SAT':
                    frontier.update({'kind':'predicate_conflict' if status=='UNSAT' else 'predicate_budget_unknown','pc':pc});return False
                if variant==228:next_pc=(c if choice else b)+1
                else:next_pc=((c if choice else b) if op==46 else (a if choice else b))+1
                return {'next_pc':next_pc}
            return fallback(variant,op,a,b,c,regs,event)
        return transfer
    return factory


def certify_meta_helper(analysis):
    """Require coverage and an exact leaf-wise proof, including false versus nil."""
    if analysis['unexplored_worklist']:return {'coverage_proved':False,'reason':'worklist incomplete'}
    leaves=[p for p in analysis['paths'] if not p['branch_frontier']]
    expected=equal(META,None);guards=[];audits=[]
    for path in leaves:
        if path['frontier'].get('kind')!='refined_return':
            return {'coverage_proved':False,'reason':'unmodeled or exceptional leaf'}
        if any('upstream_table_write'in e or 'symbolic_closure_creation'in e for e in path['trace']):
            return {'coverage_proved':False,'reason':'helper effects not covered by return-only certificate'}
        domain=Predicates();terms=[]
        for event in path['trace']:
            guard=event.get('path_predicate')
            if guard:
                domain.assume(guard['expression'],guard['truth'])
                terms.append(guard['expression'] if guard['truth'] else negate(guard['expression']))
        decision=domain.decide(expected)
        if decision['value']is not path['frontier']['value']:
            return {'coverage_proved':False,'reason':'return relation not entailed'}
        guards.append({'all':terms});audits.append({'pc':path['pc'],'result':path['frontier']['value'],'proof':decision})
    if not leaves:return {'coverage_proved':False,'reason':'no return leaves'}
    coverage=Predicates().decide({'any':guards})
    return {'coverage_proved':coverage['value']is True,'coverage_query':coverage,'leaf_proofs':audits,
            'expression':expected,'scope':'reviewed helper invocation only, not global reachability or activation'}


def alias_audit(state):
    memory=Aliases();registers=state['registers'];bindings=[]
    activation='root664:guarded8521'
    for register,value in registers.items():memory.seed(address('664',activation,register),value)
    for register,value in registers.items():
        if type(value)is not dict or 'symbolic_closure'not in value:continue
        for ordinal,capture in enumerate(value['captures'],1):
            cell=capture.get('cell_identity','')
            if not cell.startswith('frame:664:register:') or capture.get('span')!=1:continue
            parent=int(cell.rsplit(':',1)[1]);name=f'root.r{register}.closure{value["symbolic_closure"]}.capture{ordinal}'
            location=address('664',activation,parent)
            memory.bind(name,[(True,location)])
            bindings.append({'pointer':name,'location':location,'call_time_value':memory.load(name)})
    # Dereferencing a register holding a fresh table is a second address space.
    # It does not overwrite the register cell or the VM-local state variable V.
    table=registers[160]['fresh_plain_table']
    scratch=heap_address(table,activation,'table')
    memory.seed(scratch,None);memory.bind('544.scratch[table]',[(True,scratch)])
    before=deepcopy(memory.cells[address('664',activation,160)])
    memory.store('544.scratch[table]',True);snapshot=memory.load('544.scratch[table]')
    memory.store('544.scratch[table]',None)
    root107=[r['pointer'] for r in bindings if r['location']==address('664',activation,107)]
    return {'bindings':bindings,'shared_root107_pointers':root107,
        'root107_value':deepcopy(registers[107]),'scratch_read_before_cleanup':snapshot,
        'root159_current_value':deepcopy(registers[159]),
        'scratch_after_cleanup':memory.load('544.scratch[table]'),
        'register160_unchanged':before==memory.cells[address('664',activation,160)],
        'modeled_helpers_capture_parent516_frame':False,
        'scopes':'guarded call-time aliases only; no future lifetime or close/rebind proof',
        'root_V_at981_assignment_proved':False,'events':memory.events}


def certify_route(analysis,writer_error_proved):
    """Exclude only this guarded normal-return route, never a global V domain."""
    leaves=[p for p in analysis['paths'] if not p['branch_frontier']]
    terms=[];rows=[]
    if analysis['unexplored_worklist']:return {'coverage_proved':False,'reason':'worklist incomplete'}
    for path in leaves:
        frontier=path['frontier'];call=frontier.get('call',{});target=call.get('callee_expression',{})
        known_call=(type(target)is dict and target.get('symbolic_closure')==258
                    and call.get('arguments')==[520442978,4] and not path['patches'] and writer_error_proved)
        failure=frontier.get('kind')=='fresh_register_order_failure'
        if not known_call and not failure:return {'coverage_proved':False,'reason':'unmodeled route leaf'}
        guards=[e['path_predicate'] for e in path['trace'] if 'path_predicate'in e]
        terms.append({'all':[g['expression'] if g['truth'] else negate(g['expression']) for g in guards]})
        rows.append({'pc':path['pc'],'reason':'same258 ordering failure' if known_call else 'fresh516 nil register ordering',
                     'guards':guards,'normal_return_refuted':True})
    if not leaves:return {'coverage_proved':False,'reason':'no leaves'}
    coverage=Predicates().decide({'any':terms})
    return {'coverage_proved':coverage['value']is True,'coverage_query':coverage,'leaf_refutations':rows,
        'conditional_normal_return_excluded':coverage['value']is True,
        'scope':'only the reviewed prefix/cache/alias/native-builtin/no-reflection assumptions; not all program entries',
        'global_V_constraints_admitted':False}


def run(source,data,output,boundary_observer=None):
    if any(p.resolve()in {source.resolve(),data.resolve()} for p in (output,output/'path-refinement.json')):
        raise ValueError('Output aliases input')
    text=source.read_text(encoding='ascii')
    anchors=[{'text':s,'offset':text.index(s)} for s in ANCHORS]
    analyses=[];aliases=[];parents=[];continuations=[]
    def observer(state,reason):
        if boundary_observer is not None:
            boundary_observer(deepcopy(state),reason)
        metadata=state['metadata'];context=metadata.constants
        aliases.append(alias_audit(state))
        heap,_=materialize_heap(state['heap'],context)
        target=next(v for v in state['registers'].values() if type(v)is dict and v.get('symbolic_closure')==544)
        captures,_=capture_inputs(target,state['registers'],heap)
        helper=trace_body(metadata.closures.templates[544]['header'],['table',{'builtin_type_of':{'symbol':'global.Instance'}}],
            captures,context,owner=544,extension_factory=extension(544),instruction_window=2,enable_variant82=True)
        helper['initial_capture_tables']={f'capture:544:{k}':deepcopy(v['plain_entries']) for k,v in captures.items()}
        summary=returned_summary(helper)
        if summary is None:raise ValueError('Reviewed helper return did not validate')
        parent_target=state['trace'][-1]['call_metadata']['callee_expression']
        parent_captures,_=capture_inputs(parent_target,state['registers'],heap)
        first=read_primitive(context,112)
        if first is None:raise ValueError('Root argument112 not materialized in the current metadata epoch')
        arguments=[first['value'],deepcopy(state['trace'][-1]['call_metadata']['argument_expressions'][1])]
        parent=trace_body(metadata.closures.templates[516]['header'],arguments,parent_captures,context,
            extension_factory=refined_extension(516,summary),instruction_window=2,max_paths=16,budget=1024)
        parents.append(parent)
        for path in parent['paths']:
            call=path['frontier'].get('call',{})
            if path['pc']!=126 or call.get('argument_count')!=2:continue
            child=trace_body(metadata.closures.templates[544]['header'],call['arguments'],captures,context,owner=544,
                extension_factory=refined_extension(544),enable_variant82=True,instruction_window=2,max_paths=16,budget=1024)
            analyses.append({'caller':516,'pc':126,'arguments':call['arguments'],
                'parent_decisions':path['decisions'],'parent_trace':path['trace'],'analysis':child})
            certificate=certify_meta_helper(child)
            analyses[-1]['return_certificate']=certificate
            if certificate['coverage_proved']:
                continuations.append(trace_body(metadata.closures.templates[516]['header'],arguments,
                    parent_captures,context,extension_factory=refined_extension(516,summary,certificate),
                    instruction_window=2,max_paths=16,budget=1024))
    prior=upstream_run(source,data,output/'upstream',boundary_observer=observer)
    propagation=propagate(prior['candidate_solution']['models'],prior['constraints'],[])
    writer_error=any(s['owner']==258 and len(s['analysis']['paths'])==1 and
        s['analysis']['paths'][0]['frontier'].get('normal_return_refuted_in_guarded_model')is True for s in prior['summaries'])
    route_certificates=[certify_route(c,writer_error) for c in continuations]
    result={'source_sha256':prior['source_sha256'],'data_sha256':prior['data_sha256'],'source_evidence':anchors,
        'aliases':aliases,'parent_analyses':parents,'metatable_call_analyses':analyses,'parent_continuations':continuations,
        'guarded_route_certificates':route_certificates,
        'bridge_status':'no verified same-activation reaching-definition bridge to V@981',
        'precision_note':'existing worklist has no join/widen operator; guarded alternatives remain separate',
        'candidate_solution':propagation['solution'],'numeric_filters_admitted':[],
        'gate_queries':propagate_gates(prior['gate_queries'],{'guarded8521.call-time-aliases-audited':True}),
        'verified_hierarchy':None,'formal_promotion_patch':{'applicable':False,'operations':[]},
        'network_requests':0,'application_calls_executed':0,'factory_invocations':0}
    result['global_gate_matrix']=[{'gate':g['gate'],'status':g['status'],
        'unproved_requirements':[r for r in g['requirements'] if g['known_facts'].get(r)is not True]}
        for g in result['gate_queries']]
    output.mkdir(parents=True,exist_ok=True)
    (output/'path-refinement.json').write_text(json.dumps(result,indent=2,allow_nan=False)+'\n',encoding='utf-8')
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,default=Path('output/stage1-vm-source.lua.txt'))
    p.add_argument('--data',type=Path,default=Path('output/stage1-vm-data.bin'))
    p.add_argument('--output',type=Path,default=Path('output/phase31'))
    a=p.parse_args();r=run(a.source,a.data,a.output)
    print([[(p['pc'],p['frontier'].get('kind'),p['trace'][-1]['opcode']) for p in row['analysis']['paths']] for row in r['metatable_call_analyses']])
