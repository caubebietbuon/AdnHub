"""Frame-qualified checkpoint constraints and closure663 proof obligations.

Only Python parsers and finite integer relations run. A checkpoint in another
frame is not a reaching definition for the root VM state word.
"""
import argparse
from copy import deepcopy
import json
from pathlib import Path
import tempfile

from checkpoint_aligner import run as checkpoint_run
from fused_call_analyzer import mask_word_domain


def uint32(value):
    if type(value) is not int or not 0 <= value < 2**32:
        raise ValueError('Expected uint32, not a default/coerced value')
    return value


def mix(value):
    value = uint32(value)
    return (value ^ (value >> 29)) & 0x1fffffff


def project_constraints(candidates, target, observations):
    """Project conjunctions of qualified constant equalities onto one variable.

    Identity = (frame/body, program point or entry epoch, storage kind, slot).
    Different identities are independent in THIS relation, not proved
    independent in the entire application. Unknown inter-frame relations are
    obligations; they are never manufactured from equal numeric values.
    """
    def identity(value):
        if (not isinstance(value, (list, tuple)) or len(value) != 4
                or type(value[0]) is not int or value[0] <= 0
                or any(type(item) is not str or not item for item in value[1:])):
            raise ValueError('Malformed qualified identity')
        return tuple(value)
    target = identity(target)
    domain = sorted({uint32(value) for value in candidates})
    bindings, rejected = {}, []
    for row in observations:
        name, value = identity(row['identity']), uint32(row['value'])
        if row.get('guard_satisfied') is not True:
            rejected.append({'identity':list(name),'reason':'activation/cache guard not discharged'})
            continue
        bindings.setdefault(name, set()).add(value)
    inconsistent = [list(name) for name, values in bindings.items() if len(values) != 1]
    allowed = bindings.get(target)
    projected = [] if inconsistent else [value for value in domain if allowed is None or value in allowed]
    return {'input_count':len(domain),'projected_count':len(projected),'projected_candidates':projected,
            'pruned_count':len(domain)-len(projected),'matching_identity_constraint':allowed is not None,
            'inconsistent_equalities':inconsistent,'undischarged_observations':rejected,
            'scope':'qualified finite equality relation only; not global reachability or a runtime key proof'}


def argument_certificate(checkpoint):
    """Check the independently recorded forward/backward arithmetic and packing."""
    if checkpoint['owner'] != 663:
        raise ValueError('Expected closure663')
    rows = [row for row in checkpoint['arithmetic'] if row['pc'] == 546]
    if len(rows) != 1:
        raise ValueError('Unique arithmetic checkpoint required')
    row = rows[0]
    definition, primitive, sliced = row['register_input_definition'], row['primitive'], row['result_slice']
    call = checkpoint['parallel_fused_call_boundary']
    if not (row['operation'] == 'subtract' and row['input_register'] == 6 and row['destination'] == 8
            and type(row['left']) is int and type(row['right']) is int
            and row['left'] - row['right'] == row['result'] == sliced['constant']
            and abs(row['left']) <= 2**53 and abs(row['right']) <= 2**53
            and abs(row['result']) <= 2**53
            and primitive['value'] == row['right']
            and definition['pc'] == 545 and definition['value'] == row['left']
            and definition['state_word_read']['word'] == 'y'
            and sliced['owner'] == 663 and not sliced['unresolved_leaves']
            and call['pc'] == 547 and call['opcode'] == 4
            and call['argument_expressions'] == [row['result']]
            and call['parallel_pre_call_copies'][1] == {'destination':7,'source':8,'value':row['result']}):
        raise ValueError('Arithmetic/provenance/argument certificate disagrees')
    return {'identity':[663,'pc547-precall','register','r7'],'value':uint32(row['result']),
            'guard_satisfied':False,
            'equation':{'left':row['left'],'operator':'subtract','right':row['right']},
            'source_identity':[663,'pc545','state','y'],
            'primitive_reference':primitive['reference_id'],
            'arithmetic_verified':True,'runtime_activation_verified':False,
            'guard':row['normal_completion_guard'],
            'root_V_connection':None}


def lifetime_ledger(report):
    """Keep evidence coverage and call outcome partitions separate from truth."""
    conditions = next(row for row in report['activation_lifetime']['conditions'] if row['child'] == 663)
    structure = next(row for row in report['activation_lifetime']['scope_audit']['closures'] if row['child'] == 663)
    exits = next(row for row in report['scope_exits'] if row['owner'] == 663)
    call = exits['fused_call_boundary']
    if call['callee_invoked'] or call['actual_activation_proved']:
        raise ValueError('Unexpected execution/activation claim in static boundary')
    matrix = []
    for group, values in (('structural',structure['criteria']),('activation',conditions['activation']),
                          ('lifetime',conditions['lifetime']),('tree',conditions['tree'])):
        for name, value in values.items():
            if value is not None and type(value) is not bool:
                raise ValueError('Invalid proof status')
            matrix.append({'group':group,'criterion':name,'value':value,
                           'status':'proved' if value is True else 'not_established'})
    # These are universal proof obligations, NOT assertions that any outcome
    # or mutation is concretely reachable in this obfuscated application.
    outcomes = [
        {'outcome':'normal_return','continuation':call['normal_return_pc'],
         'needed':['callee identity at invocation','returned values for r6/r7',
                   'all escaping cell effects','complete continuation/close-path coverage']},
        {'outcome':'error','continuation':None,
         'needed':['protected/unprotected caller context','unwinding and escaping-cell semantics']},
        {'outcome':'nonreturn','continuation':None,
         'needed':['termination or nonreturn characterization','alias effects on any finite prefix']},
    ]
    return {'criteria':matrix,'capture_cells':structure['capture_cells'],
            'conditional_outcome_partition':outcomes,'actual_outcomes_proved':[],
            'reviewed_exit_sites':[row['pc'] for row in exits['reviewed_exit_candidates']],
            'reached_exit_sites':deepcopy(exits['reached_exit_instruction_boundaries']),
            'coverage_complete':exits['exit_reachability_complete'],
            'root_to_663_activation_witness':None,
            'warning':'663 calling capture1 does not prove that root invoked663 or that379 is a lexical child',
            'promotion_eligible':conditions['gate']['eligible'],
            'remaining_obligations':conditions['gate']['missing_or_failed']}


def analyze(report):
    root = next(row for row in report['aligned_models'] if row['owner'] == 664)
    if root['pc'] != 981 or tuple(root['expected_equation']) != ('V',74,4):
        raise ValueError('Unreviewed root equation')
    if not root['alignment']['current_algebraic_domain_applicable']:
        raise ValueError('Root equation is not current')
    frame = next(row for row in report['checkpoint_proofs'] if row['owner'] == 663)
    certificate = argument_certificate(frame)
    domain = mask_word_domain(4)
    projection = project_constraints(domain,[664,'pc981-entry','state','V'],[certificate])
    # Even supposing the checkpoint guard were discharged, its qualified
    # identity is distinct. Demonstrate this without inventing a dataflow edge.
    guarded = dict(certificate,guard_satisfied=True)
    conditional = project_constraints(domain,[664,'pc981-entry','state','V'],[guarded])
    conflict_bits = [bit for bit in range(8,29) if certificate['value'] & (1 << bit)]
    return {'source_sha256':report['source_sha256'],'data_sha256':report['data_sha256'],
            'checkpoint_certificate':certificate,'candidate_projection':projection,
            'conditional_checkpoint_guard_discharged':conditional,
            'mixer_domain_proof':{'equation':'key = 4 XOR ((V XOR (V >> 29)) AND 0x1fffffff)',
                'key_assumption':'0 <= key <= 255; necessary local byte-mask model only',
                'zero_bits':list(range(8,29)),'free_bits':list(range(8))+[29,30,31],
                'cardinality':2**11,
                'enumeration_verified':all((v & 0x1fffff00)==0 and 0 <= (4 ^ mix(v)) <= 255 for v in domain)},
            'counterfactual_root_V_equals_argument':{'assumption_proved':False,
                'value':certificate['value'],'derived_key':4 ^ mix(certificate['value']),
                'conflicting_zero_bits':conflict_bits,'surviving_candidates':sum(v==certificate['value'] for v in domain),
                'applied_to_actual_domain':False},
            'existing_boundary_results':deepcopy(root['current_paths']),
            'closure663_proof_ledger':lifetime_ledger(report),
            'promoted_string_keys':[],'verified_hierarchy':None,
            'formal_promotion_patch':{'applicable':False,'operations':[]},
            'network_requests':0,'factory_invocations':0,'application_calls_executed':0,'input_byte_edits':0}


def run(source, data, output):
    target = output/'checkpoint-filter.json'
    if output.resolve() in (source.resolve(),data.resolve()) or target.resolve() in (source.resolve(),data.resolve()):
        raise ValueError('Output aliases input')
    with tempfile.TemporaryDirectory() as temporary:
        result = analyze(checkpoint_run(source,data,Path(temporary)))
    output.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps(result,indent=2,allow_nan=False)+'\n',encoding='utf-8')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=Path('output/stage1-vm-source.lua.txt'))
    parser.add_argument('--data',type=Path,default=Path('output/stage1-vm-data.bin'))
    parser.add_argument('--output',type=Path,default=Path('output/phase25'))
    args = parser.parse_args()
    result = run(args.source,args.data,args.output)
    print('Candidates retained:',result['candidate_projection']['projected_count'])
    print('Hierarchy promotion:',result['formal_promotion_patch']['applicable'])
