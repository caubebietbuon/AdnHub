"""Exact local bit-vector CSP with bitset propagation and replay certificates.

No optional solver package, eval or network. A complete finite-model check is
stronger than heuristic scoring: ranking changes cost, never satisfiability.
"""
import hashlib
import json

from checkpoint_filter import uint32


def evaluate(expression, model, depth=0):
    """Whitelist-only uint32/Boolean terms. None means an unbound variable."""
    if depth>32: raise ValueError('Term depth budget exceeded')
    if type(expression) is bool: return expression
    if type(expression) is int: return uint32(expression)
    if type(expression) is not dict or 'op' not in expression:
        raise ValueError('Malformed solver expression')
    op=expression['op']
    if op=='var':
        if set(expression)!={'op','name'} or type(expression['name']) is not str:
            raise ValueError('Malformed variable')
        value=model.get(expression['name'])
        return None if value is None else uint32(value)
    arities={'xor':2,'and':2,'lshr':2,'eq':2,'ule':2,'uge':2,'popcount':1,'not':1,'all':None,'any':None}
    if op not in arities or set(expression)!={'op','args'}:
        raise ValueError('Unreviewed solver operator')
    args=expression['args']
    if not isinstance(args,list) or len(args)>64 or (arities[op] is not None and len(args)!=arities[op]):
        raise ValueError('Invalid operator arity')
    values=[evaluate(arg,model,depth+1) for arg in args]
    if op in ('all','any','not'):
        if any(v is not None and type(v) is not bool for v in values): raise ValueError('Boolean sort required')
        if op=='all': return False if False in values else None if None in values else True
        if op=='any': return True if True in values else None if None in values else False
        return None if values[0] is None else not values[0]
    if any(v is not None and type(v) is not int for v in values): raise ValueError('Bit-vector sort required')
    if None in values: return None
    if op=='xor': return values[0]^values[1]
    if op=='and': return values[0]&values[1]
    if op=='lshr': return values[0]>>values[1] if values[1]<32 else 0
    if op=='eq': return values[0]==values[1]
    if op=='ule': return values[0]<=values[1]
    if op=='uge': return values[0]>=values[1]
    return values[0].bit_count()


def term(op,*args): return {'op':op,'args':list(args)}


def digest(values):
    return hashlib.sha256(json.dumps(values,separators=(',',':'),sort_keys=True).encode()).hexdigest()


def solve(domain,constraints,variable='V'):
    """Truth-vector propagation, ranked by exact rejection count.

    UNKNOWN terms and guards remain residual. UNSAT means no model in THIS
    finite domain under the stated proved constraints, never no program path.
    """
    if not isinstance(domain,(list,tuple)) or len(domain)>65536:
        raise ValueError('Finite domain budget exceeded')
    models=sorted({uint32(v) for v in domain})
    if len(constraints)>128: raise ValueError('Constraint budget exceeded')
    names=set(); tables=[]
    full=(1<<len(models))-1
    for row in constraints:
        name=row['name']
        if type(name) is not str or not name or name in names: raise ValueError('Unique constraint names required')
        names.add(name)
        if not row.get('scope'): raise ValueError('Constraint scope required')
        proved=row.get('guard_proved')
        if proved is not None and type(proved) is not bool: raise ValueError('Typed guard status required')
        values=[evaluate(row['expression'],{variable:v}) for v in models]
        # Validate even empty domains and inactive rules without executing input.
        if not models: evaluate(row['expression'],{})
        if any(v is not None and type(v) is not bool for v in values): raise ValueError('Predicate must be Boolean')
        rejected=sum(1<<i for i,v in enumerate(values) if v is False) if proved is True else 0
        unknown=sum(v is None for v in values)
        tables.append({'name':name,'rejected':rejected,'unknown_count':unknown,
                       'active':proved is True,'entailed_by_domain':bool(models) and proved is True and all(v is True for v in values),
                       'constraint':row})
    remaining=full; proof=[]
    while tables:
        row=max(tables,key=lambda r:((remaining&r['rejected']).bit_count(),r['name']))
        tables.remove(row)
        removed=remaining&row['rejected']
        remaining &= ~row['rejected']
        proof.append({k:row[k] for k in ('name','active','unknown_count','entailed_by_domain')}|
                     {'rejected_count':removed.bit_count(),'rejected_indices':[i for i in range(len(models)) if removed&(1<<i)]})
    accepted=[v for i,v in enumerate(models) if remaining&(1<<i)]
    # Independent row-by-row verification, deliberately not bitset propagation.
    expected=[v for v in models if not any(row.get('guard_proved') is True and evaluate(row['expression'],{variable:v}) is False for row in constraints)]
    if accepted!=expected: raise AssertionError('Model certificate replay failed')
    residual=any(not p['active'] or p['unknown_count'] for p in proof)
    return {'backend':'exact finite bit-vector CSP/bitset propagation','domain_count':len(models),
        'status':'UNSAT_IN_FINITE_MODEL' if not accepted else 'SAT_WITH_RESIDUALS' if residual else 'SAT_IN_FINITE_MODEL',
        'models':accepted,'model_count':len(accepted),'pruned_count':len(models)-len(accepted),
        'domain_sha256':digest(models),'models_sha256':digest(accepted),'proof_steps':proof,
        'certificate_replayed':True,'global_reachability_proved':False}


def mask_constraints(entry_v,bounds=None):
    entry_v=uint32(entry_v)
    if bounds is None:
        from fused_call_analyzer import mask_word_domain
        distances=[(value^entry_v).bit_count() for value in mask_word_domain(4)]
        bounds=[min(distances),max(distances)]
    if (not isinstance(bounds,(list,tuple)) or len(bounds)!=2
            or any(type(value) is not int for value in bounds) or not 0<=bounds[0]<=bounds[1]<=32):
        raise ValueError('Invalid proven Hamming bounds')
    v={'op':'var','name':'V'}
    mixer=term('and',term('xor',v,term('lshr',v,29)),0x1fffffff)
    distance=term('popcount',term('xor',v,entry_v))
    return [
        {'name':'current-byte-key-equation','expression':term('ule',term('xor',4,mixer),255),
         'guard_proved':True,'scope':'necessary local current PC981 byte-mask model'},
        {'name':'derived-hamming-bounds','expression':term('all',term('uge',distance,bounds[0]),term('ule',distance,bounds[1])),
         'guard_proved':True,'scope':'Phase27 entry-to-site bounds in the same local model'},
    ]


def smtlib(expression):
    """Export the supported formula for independent local QF_BV verification."""
    if type(expression) is bool: return 'true' if expression else 'false'
    if type(expression) is int: return f'(_ bv{uint32(expression)} 32)'
    if expression['op']=='var':
        if expression['name']!='V': raise ValueError('Only V is declared in this export')
        return 'V'
    op,args=expression['op'],expression['args']
    if op=='popcount':
        value=smtlib(args[0])
        bits=[f'((_ zero_extend 31) ((_ extract {i} {i}) {value}))' for i in range(32)]
        result=bits[0]
        for bit in bits[1:]: result=f'(bvadd {result} {bit})'
        return result
    names={'xor':'bvxor','and':'bvand','lshr':'bvlshr','eq':'=','ule':'bvule','uge':'bvuge','all':'and','any':'or','not':'not'}
    return '('+names[op]+' '+' '.join(smtlib(arg) for arg in args)+')'


def export_formula(constraints):
    for row in constraints: evaluate(row['expression'],{'V':0})
    return '(set-logic QF_BV)\n(declare-fun V () (_ BitVec 32))\n'+''.join(
        '; '+json.dumps(row['name'])+'\n(assert '+smtlib(row['expression'])+')\n'
        for row in constraints if row.get('guard_proved') is True)+'(check-sat)\n(get-model)\n'
