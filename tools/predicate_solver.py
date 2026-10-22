"""Exact finite mask-state constraints over reviewed local symbolic paths.

No solver packages, eval, Lua or payload execution. Unrelated/unsupported
predicates remain residual obligations; local uniqueness is not reachability.
"""
from fused_call_analyzer import mask_word_domain
from prologue_analyzer import mix
from scope_tracer import instruction, successors, symbolic_path
from obligation_resolver import patch_equation


def affine(expression):
    """Normalize literal/input/add expressions to one symbol, scale, offset."""
    if type(expression) is int:
        return (None,0,expression) if abs(expression)<=2**53 else None
    if type(expression) is not dict: return None
    if set(expression)=={'register_input'}: return f'r{expression["register_input"]}',1,0
    if set(expression)=={'input'}: return f'state:{expression["input"]}',1,0
    if 'add' not in expression or len(expression['add'])!=2: return None
    left,right = map(affine,expression['add'])
    if left is None or right is None: return None
    if left[0] is not None and right[0] is not None and left[0]!=right[0]: return None
    offset=left[2]+right[2]
    if abs(offset)>2**53: return None
    return left[0] or right[0],left[1]+right[1],offset


def evaluate(expression, environment):
    # Check intermediates individually: large rounded Lua-number arithmetic
    # must not become an exact integer proof through algebraic cancellation.
    if type(expression) is int: return expression if abs(expression)<=2**53 else None
    if type(expression) is not dict: return None
    if set(expression)=={'register_input'}: return environment.get(f'r{expression["register_input"]}')
    if set(expression)=={'input'}: return environment.get(f'state:{expression["input"]}')
    if 'add' in expression and len(expression['add'])==2:
        left,right = (evaluate(value,environment) for value in expression['add'])
        if left is not None and right is not None and max(abs(left),abs(right),abs(left+right))<=2**53:
            return left+right
    return None


def constrain(path, operand):
    """Intersect all 2048 exact uint32 preimages with evaluable path guards."""
    domain = mask_word_domain(operand)
    if path.get('status')=='refuted_numeric_branch':
        return {'state_count_before':len(domain),'state_count_after':0,'states':[],
                'status':'refuted_local_path','unconditional_state':None,'residual_predicates':[]}
    expression = path['state_at_site']
    normalized = affine(expression)
    retained,residual = [],set()
    for state in sorted(domain):
        environment = {}
        if normalized is not None:
            symbol,scale,offset = normalized
            if symbol is None:
                if offset!=state: continue
            elif scale in (-1,1):
                value = (state-offset)//scale
                if abs(value)<=2**53: environment[symbol]=value
            else:
                # r+r can equal an odd integer for a fractional r. Do not
                # impose an unproved integer-register restriction.
                residual.add('non-unit state expression; no inverse-register binding')
        else: residual.add('unmodeled state expression')
        check = evaluate(expression,environment)
        if check is not None and check!=state: continue
        if check is None:
            residual.add('state expression needs exact numeric provenance')
            environment={}  # An inexact inverse is not a register-binding proof.
        rejected = False
        for index,predicate in enumerate(path.get('predicates',[])):
            if predicate.get('operator') not in ('<=','<'):
                residual.add(f'predicate:{index}:type/effect guard')
                continue
            left,right = evaluate(predicate['left'],environment),evaluate(predicate['right'],environment)
            if left is None or right is None:
                residual.add(f'predicate:{index}:unbound or inexact input')
                continue
            truth = left<=right if predicate['operator']=='<=' else left<right
            if truth not in predicate['allowed_truth_values']:
                rejected = True
                break
        if not rejected: retained.append(state)
    keys = sorted({operand^mix(state) for state in retained})
    return {'state_count_before':len(domain),'state_count_after':len(retained),'states':retained,
            'key_domain':keys,'conditional_unique_state':retained[0] if len(retained)==1 else None,
            'conditional_unique_key':keys[0] if len(keys)==1 else None,
            'unconditional_state':None,'residual_predicates':sorted(residual),
            'status':'refuted_local_path' if not retained else 'conditional_finite_domain',
            'scope':'same snapshot/dispatcher and local arrival; exact integer arithmetic where evaluated'}


def constrain_boundaries(path, operand, obligations):
    """Keep algebraic domains separate from applicability in a named model.

    A failed code/data boundary rejects that conditional path/model, not every
    future activation or the numerical key itself. Unknown boundaries never
    select a word. The caller must supply explicit scoped proof observations.
    """
    local=constrain(path,operand)
    failed,unknown=[],[]
    for row in obligations:
        value=row['proved']
        if value is not None and type(value) is not bool: raise ValueError('Expected boolean or unknown boundary proof')
        if not row.get('scope'): raise ValueError('Boundary scope required')
        if value is False: failed.append(row['name'])
        if value is None: unknown.append(row['name'])
    return {'local':local,'boundary_obligations':obligations,
            'rejected_boundaries':failed,'unknown_boundaries':unknown,
            'admissible_in_declared_model':[] if failed else local['states'],
            'model_status':'refuted_declared_model' if failed or not local['states'] else
                           'conditional_model' if unknown else 'local_boundaries_satisfied',
            'global_reachability_proved':False,'unconditional_state':None,
            'note':'rejection is scoped; algebraic candidates remain separate from runtime proof'}


def normal_successors(pc, inst, variant):
    op,a,b,c = inst
    if variant==228 and op==172: return sorted({pc+1,b+1})
    equation = patch_equation({'variant':variant,'opcode':op,'operand1':a,'H':b,'operand3':c})
    return [pc+1] if equation else successors(pc,inst,variant)


def path_constraints(arrays, target, variant, word, depth=16, cap=32):
    """Whole-snapshot incoming-edge scan, bounded local path expansion."""
    limit = min(map(len,arrays.values()))
    if not 1<=target<=limit or not 1<=depth<=64 or not 1<=cap<=128:
        raise ValueError('Invalid local search bounds')
    pred = {pc:[] for pc in range(1,limit+1)}
    for pc in pred:
        for next_pc in normal_successors(pc,instruction(arrays,pc,variant),variant):
            if next_pc in pred: pred[next_pc].append(pc)
    pending,paths = [[target]],[]
    while pending and len(paths)<cap:
        reverse = pending.pop()
        incoming = pred[reverse[-1]]
        previous = [pc for pc in incoming if pc not in reverse]
        cut = 'depth_limit' if len(reverse)>=depth else 'open_predecessor_frontier' if not incoming else 'cycle_cut' if not previous else None
        if cut:
            path = list(reversed(reverse))
            result = symbolic_path(arrays,variant,path,word)
            # Phase17 handles <= branches. Add the reviewed strict branch172
            # using a second prefix slice, before that branch's instruction.
            for position,(pc,next_pc) in enumerate(zip(path,path[1:])):
                op,a,b,c = instruction(arrays,pc,variant)
                if variant==228 and op==172:
                    prefix = symbolic_path(arrays,variant,path[:position+1],word)
                    values = {}
                    for mutation in prefix.get('mutations',[]): values.update(mutation['register_writes'])
                    truth = [True,False] if pc+1==b+1 else [next_pc==pc+1]
                    result.setdefault('predicates',[]).append({'pc':pc,'operator':'<',
                        'left':values.get(a,{'register_input':a}),'right':c,'allowed_truth_values':truth})
            result['cutpoint_reason'] = cut
            result['normal_patch_completion_pcs'] = [pc for pc in path[:-1]
                if patch_equation(dict(zip(('variant','opcode','operand1','H','operand3'),
                   (variant,*instruction(arrays,pc,variant))))) is not None]
            paths.append(result)
        else:
            if len(pending)+len(previous)>4096: raise ValueError('Predecessor worklist budget exceeded')
            pending.extend(reverse+[pc] for pc in previous)
    return {'paths':paths,'path_cap_hit':bool(pending),'entry_reachability_proved':False,
            'all_incoming_edges_known':False,'guard':'fixed snapshot/dispatcher; unknown effects and rewrites remain barriers'}
