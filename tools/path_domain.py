"""Finite guarded aliases and a typed Boolean theory for static metadata.

No payload expressions are evaluated. Unknown pointers/calls lose precision
explicitly; frame activations and VM locals occupy distinct address spaces.
"""
from copy import deepcopy
import json
import math

from gate_solver import sat


def key(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)


def primitive(value):
    return value is None or type(value)in (bool,int,str) or type(value)is float and math.isfinite(value)


def equal(left,right):
    if primitive(left) and primitive(right):
        numeric=type(left)in (int,float) and type(right)in (int,float)
        return left==right if numeric or type(left)is type(right) else False
    if primitive(left) and not primitive(right):left,right=right,left
    return {'typed_equal':[deepcopy(left),deepcopy(right)]}


def negate(value):
    if type(value)is bool:return not value
    if type(value)is dict and set(value)=={'not'}:return value['not']
    return {'not':value}


def truth(value):
    if type(value)is dict and 'string_literal'in value:return truth(value['string_literal'])
    if primitive(value):return value is not None and value is not False
    if type(value)is dict:
        if any(k in value for k in ('typed_equal','not','any','all','atom')):return value
        if 'boolean_not'in value:return negate(truth(value['boolean_not']))
        if 'lua_truth'in value:return truth(value['lua_truth'])
        if 'builtin_type_of'in value:return True  # type returns a string, not its argument's type.
        if 'table_select'in value:
            row=value['table_select']
            if all(primitive(r['key']) and type(truth(r['value']))is bool for r in row['entries']):
                return {'any':[equal(row['key'],r['key']) for r in row['entries'] if truth(r['value'])]}
    return {'atom':'LuaTruth:'+key(value)}


class Predicates:
    """Tseitin CNF + only reviewed type/equality implications, no closed type enum."""
    def __init__(self):
        self.variables={};self.clauses=[];self.equalities={};self.conditions=[]

    def fork(self):return deepcopy(self)

    def encode(self,expression,depth=0):
        if depth>32 or len(self.variables)>=256:raise ValueError('Predicate budget exhausted')
        identity=key(expression)
        if identity in self.variables:return self.variables[identity]
        n=len(self.variables)+1;self.variables[identity]=n
        if type(expression)is bool:self.clauses.append([n if expression else -n]);return n
        if type(expression)is not dict:raise ValueError('Boolean term required')
        if set(expression)=={'not'}:
            child=self.encode(expression['not'],depth+1)
            self.clauses.extend([[-n,-child],[n,child]])
        elif set(expression)in ({'all'},{'any'}):
            op=next(iter(expression));args=expression[op]
            if not isinstance(args,list) or len(args)>64:raise ValueError('Boolean arity bound')
            children=[self.encode(arg,depth+1) for arg in args]
            if op=='all':
                self.clauses.extend([[-n,c] for c in children]);self.clauses.append([n]+[-c for c in children])
            else:
                self.clauses.extend([[n,-c] for c in children]);self.clauses.append([-n]+children)
        elif set(expression)=={'typed_equal'}:
            left,right=expression['typed_equal']
            reduced=equal(left,right)
            if type(reduced)is bool:self.clauses.append([n if reduced else -n])
            else:
                if primitive(left) and not primitive(right):left,right=right,left
                if primitive(right):
                    group=self.equalities.setdefault(key(left),[])
                    for previous,constant in group:
                        if equal(constant,right)is False:self.clauses.append([-n,-previous])
                    group.append((n,deepcopy(right)))
                    if right is None or right is False:
                        self.clauses.append([-n,-self.encode(truth(left),depth+1)])
                    else:self.clauses.append([-n,self.encode(truth(left),depth+1)])
                    if type(left)is dict and 'builtin_type_of'in left and type(right)is str:
                        t=self.encode(truth(left['builtin_type_of']),depth+1)
                        if right in ('table','number','string','function','thread','userdata','buffer','vector'):
                            self.clauses.append([-n,t])
                        elif right=='nil':self.clauses.append([-n,-t])
        elif set(expression)!={'atom'} or type(expression['atom'])is not str:
            raise ValueError('Unreviewed Boolean operator')
        return n

    def assume(self,expression,value=True):
        if type(value)is not bool:raise ValueError('Boolean guard required')
        literal=self.encode(expression)
        self.clauses.append([literal if value else -literal])
        self.conditions.append({'expression':deepcopy(expression),'truth':value})

    def check(self):return sat(self.clauses)

    def decide(self,expression):
        probe=self.fork();literal=probe.encode(expression)
        base=sat(probe.clauses)
        if base['status']!='SAT':return {'status':base['status'],'value':None}
        yes=sat(probe.clauses+[[literal]]);no=sat(probe.clauses+[[-literal]])
        return {'status':'ENTAILED' if no['status']=='UNSAT' else 'REFUTED' if yes['status']=='UNSAT' else 'OPEN',
                'value':True if no['status']=='UNSAT' else False if yes['status']=='UNSAT' else None}


def address(frame,activation,index,offset=0):
    if type(frame)is not str or type(activation)is not str or not frame or not activation:
        raise ValueError('Scoped frame activation required')
    if any(type(v)is not int for v in (index,offset)) or abs(index+offset)>2**53:
        raise ValueError('Exact register offset required')
    return (frame,activation,index+offset)


def heap_address(identity,activation,value):
    if not primitive(value) or value is None:raise ValueError('Reviewed non-nil heap key required')
    numeric=type(value)in (int,float)
    if numeric and int(value)==value:value=int(value)
    return ('heap:'+identity,activation,key(['number' if numeric else type(value).__name__,value]))


def ite(condition,yes,no):
    if condition is True:return deepcopy(yes)
    if condition is False:return deepcopy(no)
    if key(yes)==key(no):return deepcopy(yes)
    return {'ite':[deepcopy(condition),deepcopy(yes),deepcopy(no)]}


class Aliases:
    """Guarded pointer alternatives: retain correlation instead of joining values."""
    def __init__(self):self.cells={};self.pointers={};self.events=[];self.unknown_epoch=0
    def fork(self):return deepcopy(self)

    def seed(self,location,value):self._location(location);self.cells[location]=deepcopy(value)

    @staticmethod
    def _location(location):
        if not isinstance(location,tuple) or len(location)!=3:raise ValueError('Scoped address required')
        frame,activation,index=location
        if type(frame)is not str or type(activation)is not str:raise ValueError('Scoped address required')
        if frame.startswith('heap:'):
            if type(index)is not str:raise ValueError('Typed heap key required')
        else:address(frame,activation,index)

    def bind(self,name,cases):
        if type(name)is not str or not 1<=len(cases)<=64:raise ValueError('Pointer alternatives bound')
        for guard,location in cases:
            if type(guard)not in (bool,dict):raise ValueError('Boolean pointer guard required')
            self._location(location)
        self.pointers[name]=deepcopy(cases)

    def copy(self,destination,source):self.pointers[destination]=deepcopy(self.pointers.get(source))

    def offset(self,destination,source,offset):
        cases=self.pointers.get(source)
        if cases is None or type(offset)is not int or any(p[1][0].startswith('heap:') for p in cases):
            self.pointers[destination]=None;return
        self.bind(destination,[(guard,address(*location,offset)) for guard,location in cases])

    def store(self,pointer,value,guard=True):
        if type(guard)not in (bool,dict):raise ValueError('Boolean store guard required')
        if guard is False:
            self.events.append({'pointer':pointer,'kind':'inactive_store'});return
        cases=self.pointers.get(pointer)
        if cases is None:
            self.unknown_epoch+=1
            for location,old in list(self.cells.items()):
                self.cells[location]=ite(guard,{'unknown_indirect_store':self.unknown_epoch,'location':location},old)
            self.events.append({'pointer':pointer,'kind':'unknown_store','guard':guard});return
        # Coalesce equal targets before updating to retain the old memory version.
        grouped={}
        for choice,location in cases:grouped.setdefault(location,[]).append(choice)
        for location,choices in grouped.items():
            condition=guard if True in choices else {'all':[guard,{'any':choices}]}
            old=self.cells.get(location,{'unknown_initial_cell':location,'epoch':self.unknown_epoch})
            self.cells[location]=ite(condition,value,old)
        self.events.append({'pointer':pointer,'kind':'guarded_store','cases':deepcopy(cases),'guard':guard})

    def load(self,pointer):
        cases=self.pointers.get(pointer)
        if cases is None:return {'unknown_indirect_load':pointer,'epoch':self.unknown_epoch}
        value={'uncovered_pointer_case':pointer}
        for guard,location in reversed(cases):
            current=self.cells.get(location,{'unknown_initial_cell':location,'epoch':self.unknown_epoch})
            value=ite(guard,current,value)
        return value

    @staticmethod
    def join(branches):
        if not 1<=len(branches)<=64:raise ValueError('Guarded merge bound')
        if any(type(g)not in (bool,dict) for g,m in branches):raise ValueError('Boolean merge guards required')
        return [{'guard':deepcopy(guard),'memory':memory.fork()} for guard,memory in branches]
