"""Bounded DPLL certificate-obligation queries; no runtime values are guessed."""
from collections import Counter


def sat(clauses,budget=4096):
    if type(budget) is not int or not 1<=budget<=100000: raise ValueError('DPLL budget invalid')
    if len(clauses)>1024 or any(not isinstance(c,(tuple,list)) or len(c)>128 for c in clauses):
        raise ValueError('CNF budget invalid')
    if any(type(lit) is not int or lit==0 for c in clauses for lit in c):
        raise ValueError('CNF literals must be nonzero signed integers')
    work=[([list(c) for c in clauses],{})]; nodes=0
    while work and nodes<budget:
        rows,model=work.pop();nodes+=1
        while True:
            simplified=[]; conflict=False
            for row in rows:
                if any(model.get(abs(lit))==(lit>0) for lit in row if abs(lit) in model): continue
                reduced=[lit for lit in row if abs(lit) not in model]
                if not reduced: conflict=True;break
                simplified.append(reduced)
            rows=simplified
            if conflict: break
            if not rows:
                # Partial logical valuation; do not fill unassigned variables.
                return {'status':'SAT','model':model,'search_nodes':nodes}
            units=[row[0] for row in rows if len(row)==1]
            if not units: break
            for lit in units:
                key,truth=abs(lit),lit>0
                if key in model and model[key]!=truth: conflict=True;break
                model[key]=truth
            if conflict: break
        if conflict: continue
        # Occurrence heuristic affects search order, never proof conditions.
        variable=Counter(abs(lit) for row in rows for lit in row).most_common(1)[0][0]
        for truth in (False,True): work.append((rows,{**model,variable:truth}))
    return {'status':'UNKNOWN_BUDGET' if work else 'UNSAT','model':None,'search_nodes':nodes}


def query_gate(name,requirements,facts):
    """Is a gate's promotion certificate forced by the recorded fact formula?

    Open evidence is unconstrained, not false. SAT valuations are logical proof
    obligations, not executable environments or witnessed application paths.
    """
    names=[name]+list(dict.fromkeys(requirements+list(facts)))
    if len(names)!=len(set(names)) or not requirements: raise ValueError('Invalid gate variables')
    index={value:i+1 for i,value in enumerate(names)}
    goal=index[name]; clauses=[]
    for req in requirements: clauses.append([-goal,index[req]])
    clauses.append([goal]+[-index[req] for req in requirements])
    for fact,value in facts.items():
        if value is not None and type(value) is not bool: raise ValueError('Fact values must be Boolean or unknown')
        if value is not None: clauses.append([index[fact] if value else -index[fact]])
    base=sat(clauses)
    positive=sat(clauses+[[goal]]);negative=sat(clauses+[[-goal]])
    if base['status']=='UNSAT': status='INCONSISTENT_EVIDENCE'
    elif base['status']=='UNKNOWN_BUDGET': status='UNKNOWN_BUDGET'
    elif positive['status']=='UNSAT': status='REFUTED_CERTIFICATE'
    elif negative['status']=='UNSAT': status='ENTAILED_CERTIFICATE'
    elif positive['status']==negative['status']=='SAT': status='UNDERCONSTRAINED'
    else: status='UNKNOWN_BUDGET'
    return {'gate':name,'status':status,'requirements':requirements,'known_facts':facts,
        'positive_query':positive,'negative_query':negative,'variable_ids':index,
        'scope':'certificate evidence formula only; logical valuations are not runtime witnesses'}
