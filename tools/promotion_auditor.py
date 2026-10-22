"""Phase16: scoped string promotion and explicit proxy proof obligations.

Static equations can populate a site-indexed table without asserting runtime
activation. No Lua, factory, metatable, payload or network execution.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile

import layer_decomposer
import payload_decoder
import reconstructor
from reader_tracer import decrypt_record, parse_loader
from string_resolver import read_length_payload
from symbolic_resolver import PROOFS, validate_tree


def parse_matrix(markdown):
    """Read only the numeric/status table, never interpret prose as commands."""
    result = {}
    for line in markdown.splitlines():
        cells = [part.strip() for part in line.strip().strip('|').split('|')]
        if not cells or not re.fullmatch(r'\d+→\d+', cells[0]): continue
        if len(cells) != 7 or any(value not in ('PASS', 'FAIL', 'UNKNOWN') for value in cells[1:]):
            raise ValueError("Malformed diagnostic matrix row")
        pair = tuple(map(int, cells[0].split('→')))
        if pair in result: raise ValueError("Duplicate diagnostic pair")
        result[pair] = dict(zip(layer_decomposer.CRITERIA, cells[1:]))
    if not result: raise ValueError("No diagnostic rows")
    return result


def solve_direct(reference, site, intermediate):
    decoder = site['core_decoder']
    if decoder['kind'] != 'direct_xor': raise ValueError("Not a direct equation")
    key = decoder['key']
    if type(key) is not int or not 0 <= key <= 255: raise ValueError("Not a byte key")
    plain = payload_decoder.xor_bytes(intermediate, key)
    if payload_decoder.xor_bytes(plain, key) != intermediate: raise ValueError("XOR inverse disagrees")
    if plain.hex() != decoder['decoded_bytes_hex']: raise ValueError("Prior core result disagrees")
    try: text = plain.decode('utf-8')
    except UnicodeDecodeError: text = None
    return {'site_key': [site['owner'], site['pc'], reference, site['variant']],
            'reference_id': reference, 'constant_key': key, 'bytes_hex': plain.hex(), 'utf8': text,
            'intermediate_sha256': hashlib.sha256(intermediate).hexdigest(),
            'proof': 'each byte p=c XOR k; (p XOR k)=c; source operand fixes k at this candidate site',
            'algebra_verified': True, 'table_scope': 'site-indexed static equation result',
            'activation_predicates': site['activation_predicates'], 'runtime_constant_verified': False}


def state_certificate(site):
    """Never substitute a frontier value into an unvisited instruction."""
    cases = site['reached_state_slices']
    supported = [case for case in cases if case.get('input_slice') and
                 type(case['input_slice'].get('constant')) is int and
                 0 <= case['input_slice']['constant'] <= 0xffffffff]
    return {'owner': site['owner'], 'pc': site['pc'], 'variant': site['variant'],
            'equation': site['core_decoder']['equation'],
            'state_domain_size': site['core_decoder']['state_domain_size'],
            'at_site_proofs': supported, 'core_state_resolved': bool(supported),
            'frontier_slice': site['frontier_state_slice_context_only'],
            'frontier_to_site_equality_proved': False,
            'missing_proof': 'reaching definition across intervening paths, calls and instruction rewrites',
            'activation_predicates': site['activation_predicates'], 'runtime_key_promoted': False}


def proxy_proof(row, proxy, matrix_row):
    if any(matrix_row[key] != row['criteria'][key]['status'] for key in layer_decomposer.CRITERIA):
        raise ValueError("Archived diagnostics disagree with regenerated evidence")
    legacy = row['unchanged_validator_proofs']
    missing = [name for name in PROOFS if legacy.get(name) is not True]
    return {'parent': row['parent'], 'child': row['child'], 'descriptor_id': row['descriptor_id'],
            'diagnostic_results': matrix_row, 'validator_proofs': legacy,
            'constructor_route': proxy['nodes'], 'route_status': proxy['status'],
            'formal_statement': 'if activation, slot identity and cache lifecycle guards hold, descriptor binds this constructor use to the proposed frame',
            'unproved_premises': missing,
            'cache_identity_proved': proxy['cache_hit_or_miss_proved'],
            'unique_ancestry_proved': legacy.get('ancestry_unconditional') is True,
            'admissible_parent_edge': not missing and proxy['cache_hit_or_miss_proved'] is True,
            'shared_factory_is_parent_evidence': False}


def build(report, matrix, backing, entries):
    expected = {(row['parent'], row['child']) for row in report['prototype_diagnostic_matrix']}
    if set(matrix) != expected: raise ValueError("Matrix inventory differs from regenerated evidence")
    table, states = [], []
    for string in report['string_decomposition']:
        ref = string['reference_id']
        encoded, _ = read_length_payload(backing, entries[ref - 1]['value'] ^ 306486104)
        intermediate, _ = decrypt_record(encoded, ref, 83)
        for site in string['sites']:
            if site['core_decoder']['kind'] == 'direct_xor': table.append(solve_direct(ref, site, intermediate))
            else: states.append({'reference_id': ref, **state_certificate(site)})
    by_id = {}
    for row in table: by_id.setdefault(row['reference_id'], []).append(row)
    conflicts = [{'reference_id': ref, 'keys': sorted({row['constant_key'] for row in rows}),
                  'reason': 'distinct guarded sites; no unconditional merge'}
                 for ref, rows in by_id.items() if len({row['bytes_hex'] for row in rows}) > 1]
    proxies = {(row['parent'], row['child']): row for row in report['proxy_linkages']}
    proofs = [proxy_proof(row, proxies[(row['parent'], row['child'])], matrix[(row['parent'], row['child'])])
              for row in report['prototype_diagnostic_matrix']]
    accepted = [{'parent': p['parent'], 'child': p['child'], 'proofs': p['validator_proofs']}
                for p in proofs if p['admissible_parent_edge']]
    graph = report['candidate_graph_checks']
    nodes = set(graph['reachable']) | set(graph['missing'])
    validation = validate_tree(664, nodes, accepted)
    return {'source_sha256': report['source_sha256'], 'data_sha256': report['data_sha256'],
            'static_string_table': table, 'conflicting_reference_results': conflicts,
            'state_certificates': states, 'proxy_binding_proofs': proofs,
            'accepted_parent_edges': accepted, **validation,
            'runtime_string_table_promotions': [], 'application_calls_executed': 0,
            'factory_invocations': 0, 'network_requests': 0}


def run(source, data, matrix_path, output):
    matrix = parse_matrix(matrix_path.read_text(encoding='utf-8'))
    with tempfile.TemporaryDirectory() as temporary:
        temp = Path(temporary)
        previous = layer_decomposer.run(source, data, temp / 'phase15')
        reconstructor.run(source, data, temp / 'base', [664])
        backing = (temp / 'base/record-664.backing-postfill.bin').read_bytes()
    report = build(previous, matrix, backing, parse_loader(data.read_bytes())['lookup_entries'])
    targets = [output / 'promotion-proofs.json', output / 'static-string-table.json']
    if any(target.resolve() in {source.resolve(), data.resolve(), matrix_path.resolve()} for target in targets):
        raise ValueError("Output aliases input")
    output.mkdir(parents=True, exist_ok=True)
    targets[0].write_text(json.dumps(report, indent=2, allow_nan=False)+'\n', encoding='utf-8')
    targets[1].write_text(json.dumps({'scope': 'site-indexed algebra; activation guards retained',
        'strings': report['static_string_table']}, indent=2)+'\n', encoding='utf-8')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path('output/stage1-vm-source.lua.txt'))
    parser.add_argument('--data', type=Path, default=Path('output/stage1-vm-data.bin'))
    parser.add_argument('--matrix', type=Path, default=Path('research/layer-decomposition-2026-10-22/DIAGNOSTIC_MATRIX.md'))
    parser.add_argument('--output', type=Path, default=Path('output/phase16'))
    args = parser.parse_args()
    try: report = run(args.source, args.data, args.matrix, args.output)
    except (ValueError, OSError, KeyError, IndexError, TypeError) as failure:
        print(f'Promotion audit failed: {failure}', file=sys.stderr)
        return 1
    print('Static site strings:', len(report['static_string_table']), 'accepted parent edges:', len(report['accepted_parent_edges']))
    return 0


if __name__ == '__main__': raise SystemExit(main())
