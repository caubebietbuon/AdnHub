"""Phase33 offline index-space audit. Fitted models are hypotheses, not aliases.

Only source-checked call windows may add guarded data edges. Numeric agreement
never proves identical storage, activation, runtime state or code epoch.
"""
import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import json
from math import gcd
from pathlib import Path
import re

import analyzer
from constraint_inverter import run as invert
from upstream_solver import reaching_meet


ANCHORS=(
    '[4890]=function(x,W,W,b,h,w,j,O,o,S,S,A,B,B,H,i,Z,R)',
    'local V,m,k=W[1];local y,t=W[2],D(h);',
    'x[34],x[88],x[66],x[18],x[90]',
    'local D,e,P,K,X,v,Y,_,J,M,r,L,F,G,p,C,u,f,n=R,N,z,E,Q,I,T,l,a,U,q,s,c,d,V,m,k,y,t;',
    '[18]=table.move,','[34]=table.create,','[20]=bit32.bxor,',
    'if xJ~=74 then T,d={...},w[W];K(T,1,i[W],d,t);',
    'T,d,I=A[W+1],H[W+1],i[W+1];m,R,Q=T+I-1,T+d,e(t[T](P(t,T+1,T+d)));K(Q,1,I,T,t);',
    'Y(_(V,(Y(v(V,29),7))),536870911)',
)


def checked_pairs(pairs,width):
    if type(width)is not int or not 1<=width<=32:raise ValueError('Width must be 1..32')
    if not isinstance(pairs,(list,tuple)) or len(pairs)>4096:raise ValueError('Pair budget exceeded')
    if any(not isinstance(p,(list,tuple)) or len(p)!=2 or
           any(type(v)is not int or not 0<=v<1<<width for v in p) for p in pairs):
        raise ValueError('Exact unsigned input/output pairs required')
    return 1<<width


def affine_hypotheses(pairs,width=32,permutation=True):
    """Solve y=a*x+b mod 2**width as congruences, without enumerating 2**32.

    With permutation=True, a must be odd. This is sample consistency only;
    neither a unique fit nor a full finite-domain fit proves a source transfer.
    """
    modulus=checked_pairs(pairs,width)
    if type(permutation)is not bool:raise ValueError('Boolean permutation flag required')
    if not pairs:return {'status':'UNDERCONSTRAINED','source_transfer_proved':False}
    x0,y0=pairs[0];residue,period=0,1
    for x,y in pairs[1:]:
        dx,dy=(x-x0)%modulus,(y-y0)%modulus;g=gcd(dx,modulus)
        if dy%g:return {'status':'INCONSISTENT','source_transfer_proved':False}
        q=modulus//g
        r=0 if q==1 else (dy//g)*pow(dx//g,-1,q)%q
        if (r-residue)%min(q,period):return {'status':'INCONSISTENT','source_transfer_proved':False}
        if q>period:residue,period=r,q
    if permutation:
        if period==1:residue,period=1,2
        elif residue%2==0:return {'status':'INCONSISTENT','source_transfer_proved':False}
    count=modulus//period
    return {'status':'UNIQUE_FIT' if count==1 else 'UNDERCONSTRAINED',
        'coefficient_residue':residue,'coefficient_period':period,'coefficient_count':count,
        'offset_expression':{'op':'mod','args':[{'op':'subtract','args':[y0,{'op':'multiply','args':['a',x0]}]},modulus]},
        'offset_for_residue':(y0-residue*x0)%modulus,
        'symbolic_rule':'target = (a * source + b) mod 2**width',
        'source_transfer_proved':False}


def rotate(value,shift,width):
    if type(width)is not int or not 1<=width<=32:raise ValueError('Width must be 1..32')
    if type(value)is not int or not 0<=value<1<<width or type(shift)is not int or not 0<=shift<width:
        raise ValueError('Invalid rotate operand')
    return ((value<<shift)|(value>>(width-shift)))&((1<<width)-1)


def bitwise_hypotheses(pairs,width=32):
    """Bounded rotate-left + XOR family, not all possible bit permutations."""
    checked_pairs(pairs,width)
    if not pairs:return {'status':'UNDERCONSTRAINED','models':[],'source_transfer_proved':False}
    models=[]
    for shift in range(width):
        key=rotate(pairs[0][0],shift,width)^pairs[0][1]
        if all(rotate(x,shift,width)^key==y for x,y in pairs):
            models.append({'rotate_left':shift,'xor_key':key})
    return {'status':'UNIQUE_FIT' if len(models)==1 else 'UNDERCONSTRAINED' if models else 'INCONSISTENT',
        'models':models,'source_transfer_proved':False,
        'symbolic_rule':'target = rotate_left(source,s,width) XOR k'}


def slot_translation(source_start,target_start,count):
    """Exact local call-window bijection on integer slots, with no modular wrap."""
    if any(type(v)is not int or not 0<=v<=100000 for v in (source_start,target_start,count)):
        raise ValueError('Exact bounded slot interval required')
    if count>1024 or max(source_start+count,target_start+count)>100000:
        raise ValueError('Slot interval exceeds budget')
    return {'source_interval':[source_start,source_start+count],
        'target_interval':[target_start,target_start+count],
        'offset':target_start-source_start,
        'pairs':[[source_start+i,target_start+i] for i in range(count)],
        'symbolic_proof':'r=source_start+k; q=target_start+k; q=r+(target_start-source_start), 0<=k<count',
        'scope':'argument slots in one source-checked call, not global register identities'}


def mixer_preimages(masked):
    """Exact inverse family of the source's 32->29-bit payload mixer.

    The missing high-three bits remain free; this is not a unique state value.
    """
    if type(masked)is not int or not 0<=masked<1<<29:
        raise ValueError('Exact 29-bit mixer output required')
    return [(masked^high)|(high<<29) for high in range(8)]


def factory_audit(text):
    if hashlib.sha256(text.encode('ascii')).hexdigest()!=analyzer.SOURCE_SHA:
        raise ValueError('Unknown pinned source')
    structure,_=analyzer.source_structure(analyzer.lex(text),text)
    field=next(f for f in structure['field_candidates'] if f['key']=='[4890]')
    start,end=field['offset'],field['candidate_interval_end'];tokens=analyzer.lex(text[start:end])
    expressions=Counter();state_writes=[]
    for p,t in enumerate(tokens[:-1]):
        if t.value=='t' and tokens[p+1].value=='[':
            depth=1;q=p+2
            while q<len(tokens) and depth:
                depth+=(tokens[q].value=='[')-(tokens[q].value==']');q+=1
            if depth:raise ValueError('Unbalanced register subscript')
            expressions[''.join(a.value for a in tokens[p+2:q-1])]+=1
        if t.value in ('V','y') and tokens[p+1].value=='=' and tokens[p+2].value=='t':
            q=p+2
            while q<len(tokens) and tokens[q].value!=';':q+=1
            state_writes.append({'word':t.value,'offset':start+t.start,
                'text':text[start+t.start:start+tokens[q].end],
                'scope':'lexical source assignment candidate; path/epoch arrival unproved'})
    groups=Counter()
    for expression,count in expressions.items():
        kind=('stream_index' if re.fullmatch(r'[HAwi]\[(?:W|f|S|WJ)(?:\+\d+)?\]',expression)
              else 'scalar_index' if re.fullmatch(r'[A-Za-z_]\w*',expression)
              else 'affine_window_index' if expression in ('T+1','T+2','T+3','I+T-1')
              else 'unclassified_index')
        groups[kind]+=count
    return {'factory_interval':[start,end],'anchors':[{'text':a,'offset':text.index(a)} for a in ANCHORS],
        'index_expressions':dict(expressions),'index_categories':dict(groups),
        'state_assignment_candidates':state_writes,
        'header_rule':{'V':'W[1]','y':'W[2]','register_table':'table.create(h)'},
        'mask_mixer':{'expression':'(V XOR ((V >> 29) AND 7)) AND 0x1fffffff',
            'space':'payload key material, not register address','injective_on_uint32':False,
            'preimages_per_29bit_output':8,
            'inverse_family':'V = (masked XOR high) OR (high << 29), 0<=high<8; masked is 29-bit'},
        'global_register_permutation_proved':False,
        'limitations':'syntactic pinned-factory subscript inventory, not a complete semantic alias or indirect-call proof'}


def controlled_intersection(upstream):
    """Recheck existing call SSA with explicit source-window translation edges.

    Parameter entry bindings already exist in these graphs. The local slot
    translation must not add a guessed root-V or capture-value edge.
    """
    rows=[]
    for sidx,summary in enumerate(upstream['summaries']):
        for pidx,(path,backward) in enumerate(zip(summary['analysis']['paths'],summary['backward_graphs'])):
            graph=backward['graph'];scope=f'516:call{summary["caller_pc"]}:{sidx}:path{pidx}:'
            nodes={scope+k:deepcopy(v) for k,v in graph['nodes'].items()};edges=[]
            for name,record in graph['nodes'].items():
                for dep in record['dependencies']:
                    nodes.setdefault(scope+dep,{'kind':'unresolved_external_definition'})
                    edges.append({'source':scope+dep,'target':scope+name,'kind':'data'})
            windows=[];translations=[]
            for step,event in enumerate(path['trace']):
                flow=event.get('parameter_flow')
                if not flow:continue
                if (event['variant'],event['opcode'])!=(157,73):raise ValueError('Parameter transfer changed')
                if summary['owner']==544 and summary['caller_pc']==162:
                    if flow['argument_count']!=2 or len(summary['arguments'])!=2:
                        raise ValueError('Reviewed two-argument call changed')
                    window=slot_translation(24,flow['destination'],2)
                    # The graph must itself confirm the actual pre-call SSA
                    # argument sources; we do not replace them with r24/r25 names.
                    bindings=[]
                    for k in range(len(window['pairs'])):
                        entry=f'frame544:r{flow["destination"]+k}@{event["pc"]}:{step}:{k}'
                        record=graph['nodes'].get(entry)
                        if record is None or len(record['dependencies'])!=1:raise ValueError('Missing entry SSA')
                        dep=record['dependencies'][0]
                        if not dep.startswith(f'frame516:r{24+k}@'):raise ValueError('Call window SSA mismatch')
                        item={'source':scope+dep,'target':scope+entry,'kind':'copy',
                            'predicate':{'atom':'reviewed-call162-native-move-parameter-frame'}}
                        translations.append(item);bindings.append({'from':dep,'to':entry})
                    windows.append({**window,'caller':516,'callee':544,'call_pc':162,'bindings':bindings,
                        'proof':'pinned source93 argument window and source157/73 parameter move',
                        'sample_model_checks':{'affine_uint32':affine_hypotheses(window['pairs']),
                            'rotate_xor_uint32':bitwise_hypotheses(window['pairs'])},
                        'already_represented_as_data_edges':True})
                else:
                    windows.append({'callee':summary['owner'],'call_pc':summary['caller_pc'],
                        'target_interval':[flow['destination'],flow['destination']+flow['argument_count']],
                        'rule':'immediate lazy arguments to local parameters; no parent register permutation inferred'})
            root=scope+'root664:V@981:unvisited';nodes[root]={'kind':'unproved_definition'}
            queries=[]
            for sink in graph['effect_and_return_sinks']:
                queries.append({'sink':sink,'before':reaching_meet(nodes,edges,root,scope+sink),
                    'after':reaching_meet(nodes,edges+translations,root,scope+sink)})
            rows.append({'owner':summary['owner'],'windows':windows,'queries':queries,
                'translation_edges_added':translations,'positive_bridge_proved':False})
    return rows


def run(source,data,output):
    protected={source.resolve(),data.resolve()}
    if any(p.resolve()in protected for p in (output,output/'epoch-mapping.json')):
        raise ValueError('Output aliases input')
    audit=factory_audit(source.read_text(encoding='ascii'))
    prior=invert(source,data,output/'inversion')
    upstream=json.loads((output/'inversion/refinement/upstream/upstream-analysis.json').read_text(encoding='utf-8'))
    intersections=controlled_intersection(upstream)
    result={'source_sha256':prior['source_sha256'],'data_sha256':prior['data_sha256'],
        'factory_audit':audit,'controlled_intersections':intersections,
        'global_translation_hypotheses':{'affine':affine_hypotheses([]),'rotate_xor':bitwise_hypotheses([]),
            'reason':'no source-proved paired root-V/register observations across these epochs'},
        'earlier_meeting_audits':prior['meeting_audits'],
        'candidate_solution':prior['candidate_solution'],'numeric_filters_admitted':[],
        'global_gate_matrix':prior['global_gate_matrix'],'verified_hierarchy':None,
        'formal_promotion_patch':{'applicable':False,'operations':[]},'positive_bridge_proved':False,
        'network_requests':0,'factory_invocations':0,'application_calls_executed':0}
    output.mkdir(parents=True,exist_ok=True)
    (output/'epoch-mapping.json').write_text(json.dumps(result,indent=2,allow_nan=False)+'\n',encoding='utf-8')
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,default=Path('output/stage1-vm-source.lua.txt'))
    p.add_argument('--data',type=Path,default=Path('output/stage1-vm-data.bin'))
    p.add_argument('--output',type=Path,default=Path('output/phase33'))
    a=p.parse_args();r=run(a.source,a.data,a.output)
    print(json.dumps({'candidates':r['candidate_solution']['model_count'],
        'global_gates':len(r['global_gate_matrix']),'positive_bridge_proved':r['positive_bridge_proved']}))
