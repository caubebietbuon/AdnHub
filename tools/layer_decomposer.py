"""Phase15: independent decoder equations, backward slices and typed proxies.

Pinned offline Python data analysis only; no payload, Lua, factory or network.
"""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import sys
import tempfile

import analyzer
from fused_call_analyzer import constructor_contract
import obligation_resolver as phase14
import payload_decoder
import reconstructor
from reader_tracer import decrypt_record, parse_loader
from register_slicer import RegisterSlicer
from string_resolver import read_length_payload


CRITERIA = ("capture_bounds", "upvalue_mappings", "child_headers", "control_flow", "coverage", "cycle_checks")
COPY_163 = "else T=A[W];t[T],t[T+1]=t[w[W]],t[H[W]];end;end;end;end;else if o>=87"


def result(status, reason, scope):
    if status not in ("PASS", "FAIL", "UNKNOWN"): raise ValueError("Invalid diagnostic status")
    return {"status": status, "passed": status == "PASS", "reason": reason, "scope": scope}


def graph_checks(root, expected, edges):
    adjacency = collections.defaultdict(set)
    for edge in edges: adjacency[edge["parent"]].add(edge["child"])
    active, done, cycles = set(), set(), []
    def visit(node, path):
        if node in active:
            cycles.append(path[path.index(node):] + [node])
            return
        if node in done: return
        active.add(node)
        for child in sorted(adjacency[node]): visit(child, path + [node])
        active.remove(node)
        done.add(node)
    for node in sorted(set(expected) | set(adjacency)): visit(node, [])
    reachable, pending = set(), [root]
    while pending:
        node = pending.pop()
        if node in reachable: continue
        reachable.add(node)
        pending.extend(adjacency[node])
    return {"reachable": sorted(reachable), "missing": sorted(set(expected) - reachable), "cycles": cycles,
            "scope": "enumerated candidate graph; candidate reachability is not verified activation"}


def indirect_paths(parent, child, edges, max_depth=8):
    """Prototype-only alternative paths; common factory identity is not an edge."""
    adjacency = collections.defaultdict(set)
    for edge in edges: adjacency[edge["parent"]].add(edge["child"])
    found, pending = [], [[parent]]
    while pending:
        path = pending.pop()
        if len(path) > max_depth: continue
        for target in sorted(adjacency[path[-1]]):
            if target in path: continue
            extended = path + [target]
            if target == child:
                if len(extended) >= 3: found.append(extended)
            else: pending.append(extended)
        if len(pending) + len(found) > 10000: raise ValueError("Proxy search budget exhausted")
    return found


def diagnostic_matrix(report, expected_nodes):
    originals = {(edge["parent"], edge["child"]): edge for edge in report["prototype_root_causes"]}
    guarded = {(edge["parent"], edge["child"]): edge for edge in report["structural_hierarchy_candidates"]}
    edges = list(originals.values()) + list(guarded.values())
    graph = graph_checks(664, expected_nodes, edges)
    rows = []
    for pair in sorted(set(originals) | set(guarded)):
        edge = originals.get(pair, guarded.get(pair))
        binding = guarded.get(pair, {}).get("conditional_evidence")
        local = edge["proofs"]["capture_indices_fit_owner"]
        empty = not edge.get("capture_index_audit", [None])
        captures = result("PASS" if local else "UNKNOWN",
            "local indices fit allocation hint, or descriptor empty" if local else "enclosing capture bounds missing",
            "descriptor and proposed frame only; allocation fit is not ownership")
        upvalues = result("PASS" if binding or empty else "UNKNOWN",
            "capture ordinals map to recorded frame cells" if binding else "empty capture list" if empty else "no observed owner-to-capture binding",
            "guarded binding" if binding else "descriptor schema")
        headers = result("PASS" if binding else "UNKNOWN",
            "child header read with path-local key at guarded constructor transfer" if binding else "layout hypothesis/source mask alone does not prove live selection/cache identity",
            "guarded prefix" if binding else "candidate bytes")
        contradiction = next((proof for proof in report["projected_frontier_proofs"]
            if proof["owner"] == pair[0] and proof["status"].startswith("normal continuation refuted")), None)
        flow_status = "PASS" if binding else "FAIL" if contradiction else "UNKNOWN"
        flow = result(flow_status,
            "source transfer observed" if binding else f"projected normal prefix refuted at{contradiction['pc']} under reviewed contracts" if contradiction else "site not reached before recorded frontier",
            "guarded prefix; no unconditional activation claim")
        coverage = result("FAIL" if graph["missing"] else "PASS",
            f"{len(graph['missing'])} expected nodes absent from candidate root reachability",
            "global candidate graph, not a local claim that this edge is invalid")
        cycle = result("FAIL" if graph["cycles"] else "PASS",
            "cycle detected" if graph["cycles"] else "no cycles in enumerated candidates",
            "enumerated graph only; unseen links are unknown")
        cells = dict(zip(CRITERIA, (captures, upvalues, headers, flow, coverage, cycle)))
        rows.append({"parent": pair[0], "child": pair[1], "descriptor_id": edge["descriptor_id"],
            "criteria": cells, "all_diagnostic_checks_pass": all(cell["passed"] for cell in cells.values()),
            "unchanged_validator_proofs": edge["proofs"],
            "indirect_prototype_paths": indirect_paths(*pair, edges)})
    return rows, graph


def proxy_chains(matrix, report, factories):
    bindings = {(b["parent"], b["child"]): b for b in report["guarded_closure_bindings"]}
    chains = []
    for row in matrix:
        parent, child, descriptor = row["parent"], row["child"], row["descriptor_id"]
        binding = bindings.get((parent, child))
        slot = binding["child_factory"] if binding else factories.get(child)
        use = f"{parent}:{child}:{descriptor}"
        nodes = [{"id": f"prototype:{parent}", "kind": "proposed_owner"},
                 {"id": f"wrapper_use:{use}", "kind": "lazy_wrapper_use"},
                 {"id": f"cache_lookup:{child}", "kind": "shared_cache_lookup"},
                 {"id": f"template:{child}", "kind": "decoded_template"},
                 {"id": f"constructor_use:{use}", "kind": "constructor_instance"},
                 {"id": f"closure:{use}", "kind": "capture_bound_body"}]
        chains.append({"parent": parent, "child": child, "descriptor_id": descriptor,
            "factory_slot": slot, "factory_role": "shared implementation, not a prototype parent",
            "factory_family": "VM_constructor" if slot == 4890 else "native_factory_boundary" if slot == 4916 else "unclassified",
            "nodes": nodes, "edges": [{"from": nodes[i]["id"], "to": nodes[i + 1]["id"],
                "relation": relation} for i, relation in enumerate(("loads_reference", "consults_cache", "materializes_template", "constructs_capture_factory", "binds_descriptor"))],
            "status": "guarded_source_transfer" if binding else "source_family_hypothesis",
            "path_scope": "possible cache-miss constructor route; not proof that every hop occurred",
            "cache_hit_alternative": "reuse cached reader/constructor result only after proving cached value identity/type",
            "capture_input": {"descriptor_node": f"descriptor:{descriptor}", "binds_to": nodes[-1]["id"]},
            "cache_hit_or_miss_proved": False,
            "indirect_lexical_owner_proved": False,
            "rule": "do not traverse shared factory implementation as a prototype ancestry edge"})
    return chains


def core_decoder(site, intermediate, state=None):
    """Solve algebra separately from activation/dispatcher/cache predicates."""
    word, operand = site["word_variable"], site["operand"]
    if word and state is None:
        return {"kind": "xor_mixer", "equation": f"key={operand} XOR mix({word}_at_site)",
                "key_domain_inclusive": [0, 255], "state_domain_size": site["inverse_domain_count"],
                "state_input_resolved_at_site": False, "decoded_bytes_hex": None}
    key = operand
    if word:
        if type(state) is not int or not 0 <= state <= 0xffffffff: raise ValueError("Unproved uint32 state")
        key = operand ^ phase14.mix(state)
        if not 0 <= key <= 255:
            return {"kind": "xor_mixer", "algebra_satisfiable": False, "computed_key": key}
    if type(key) is not int or not 0 <= key <= 255: raise ValueError("Invalid byte key")
    raw = payload_decoder.xor_bytes(intermediate, key)
    try: text = raw.decode("utf-8")
    except UnicodeDecodeError: text = None
    return {"kind": "xor_mixer" if word else "direct_xor", "equation": f"key={operand} XOR mix({state})" if word else f"key={operand}", "key": key,
            "decoded_bytes_hex": raw.hex(), "utf8": text,
            "algebra_solved": True, "activation_proved": False}


def decomposition(report, backing, entries):
    traces = {664: report["root_analysis"]["trace"]}
    traces.update({entry["owner"]: entry["analysis"]["trace"] for entry in report["candidate_entry_analyses"]})
    slicers = {owner: RegisterSlicer(owner, trace) for owner, trace in traces.items()}
    wanted = set(report["still_without_trace_equation"])
    rows = []
    for mask in report["mask_audit"]:
        reference = mask["reference_id"]
        if reference not in wanted: continue
        position = entries[reference - 1]["value"] ^ 306486104
        encoded, _ = read_length_payload(backing, position)
        intermediate, _ = decrypt_record(encoded, reference, 83)
        sites = []
        for site in mask["sites"]:
            owner, word = site["owner"], site["word_variable"]
            visits = [(index, event) for index, event in enumerate(traces[owner]) if event["pc"] == site["pc"]]
            gate = [{"predicate": name, "status": "UNKNOWN"} for name in
                    ("owner_activation", "dispatcher_and_unmodified_slot", "directory_payload_lifecycle", "cache_hit_or_miss")]
            state_slice = slicers[owner].slice(word=word) if word else None
            reached_cases = []
            for index, event in visits:
                if phase14.patch_equation(event) != (word, reference, site["operand"]): continue
                provenance = slicers[owner].slice(word=word, before_step=index) if word else None
                known = provenance["constant"] if provenance else None
                reached_cases.append({"trace_step": index, "input_slice": provenance,
                    "core_decoder": core_decoder(site, intermediate, state=known)})
            sites.append({"owner": owner, "pc": site["pc"], "variant": site["variant"],
                "core_decoder": core_decoder(site, intermediate), "activation_predicates": gate,
                "recorded_visits": [{"trace_step": index, "variant": event["variant"], "opcode": event["opcode"]} for index, event in visits],
                "reached_state_slices": reached_cases,
                "immediate_key_inputs": "key operands are stream literals; register dependencies enter through state-word assignments",
                "frontier_state_slice_context_only": state_slice,
                "frontier_value_may_be_used_at_site": False,
                "guard": site["guard"]})
        rows.append({"reference_id": reference, "intermediate_sha256": hashlib.sha256(intermediate).hexdigest(),
                     "sites": sites, "selected_key": None,
                     "no_site_reason": None if sites else "no source-reviewed equation exposed in current scan"})
    # A reached control case proves the slicer can resolve state/register chains;
    # it is not promoted as evidence for any unvisited string site.
    root = slicers[664]
    controls = {"root_y_at_frontier": root.slice(word="y"),
                "root_register2_at_frontier": root.slice(register=2),
                "root_register107_at_frontier": root.slice(register=107)}
    return rows, controls


def render_matrix(rows):
    lines = ["# Prototype diagnostic matrix", "", "PASS is scoped evidence; UNKNOWN means not proved, not an observed failure.",
             "The historical six-proof validator is unchanged. Coverage is global; cycle checks cover the enumerated graph only.", "",
             "| Pair | " + " | ".join(CRITERIA) + " |", "| --- | " + " | ".join(["---"] * 6) + " |"]
    for row in rows:
        lines.append(f"| {row['parent']}→{row['child']} | " + " | ".join(row["criteria"][key]["status"] for key in CRITERIA) + " |")
    for row in rows:
        lines.extend(["", f"## {row['parent']}→{row['child']}", ""])
        for key, value in row["criteria"].items():
            lines.append(f"- {key}: **{value['status']}** — {value['reason']}. Scope: {value['scope']}.")
    return "\n".join(lines) + "\n"


def run(source_path, data_path, output):
    source, data = analyzer.bounded_read(source_path), analyzer.bounded_read(data_path)
    if hashlib.sha256(source).hexdigest() != analyzer.SOURCE_SHA or hashlib.sha256(data).hexdigest() != analyzer.DATA_SHA:
        raise ValueError("Unknown pinned source/data")
    if COPY_163 not in source.decode("ascii"): raise ValueError("Parallel copy source anchor missing")
    with tempfile.TemporaryDirectory() as temporary:
        temp = Path(temporary)
        previous = phase14.run(source_path, data_path, temp / "phase14")
        baseline = payload_decoder.run(source_path, data_path, temp / "baseline")
        reconstructor.run(source_path, data_path, temp / "base", [664])
        backing = (temp / "base/record-664.backing-postfill.bin").read_bytes()
    entries = parse_loader(data)["lookup_entries"]
    strings, controls = decomposition(previous, backing, entries)
    expected = {664} | {row["reference_id"] for row in baseline["functions"]} | {row["child"] for row in previous["prototype_root_causes"]}
    matrix, graph = diagnostic_matrix(previous, expected)
    factories = {row["reference_id"]: row["candidates"][0]["factory_slot"] for row in baseline["functions"] if row["candidates"]}
    # These two additional header hypotheses were already source/reader checked
    # in Phase12. Reinspect rather than hard-coding their factory identities.
    from gw_aligner import definitions
    defs, _ = definitions(source.decode("ascii"))
    for row in matrix:
        child = row["child"]
        if child in factories: continue
        position = entries[child - 1]["value"]
        if position >= len(backing): position ^= 306486104
        candidate = payload_decoder.function_candidate(backing, entries,
            {"function_reference_id": child, "candidate_offset": position}, defs, source.decode("ascii"))
        if len(candidate["candidates"]) == 1: factories[child] = candidate["candidates"][0]["factory_slot"]
    result_data = {"source_sha256": analyzer.SOURCE_SHA, "data_sha256": analyzer.DATA_SHA,
        "string_decomposition": strings, "backward_slice_controls": controls,
        "prototype_diagnostic_matrix": matrix, "candidate_graph_checks": graph,
        "proxy_linkages": proxy_chains(matrix, previous, factories),
        "proxy_source_evidence": {"factory4890_prefix_contract": constructor_contract(source.decode("ascii"), 4890),
            "closure_consumers": [{"offset": source.decode("ascii").index(fragment), "text": fragment} for fragment in
                ("t[i[W]]=Z[W](f,nil,nil)", "t[A[W]]=Z[W](f,nil,nil)", "t[i[W]]=B[W](WJ,nil,nil)")]},
        "copy_order_correction": {"variant": 163, "opcode": 109, "source_offset": source.decode("ascii").index(COPY_163),
            "source": COPY_163, "correct_order": "r[c],r[c+1] = old(r[a]),old(r[b])"},
        "verified_hierarchy": previous["verified_hierarchy"], "network_requests": 0,
        "factory_invocations": 0, "application_calls_executed": 0,
        "limits": "Conditional algebra is separate from activation. Trace slices do not reach unvisited PCs. Typed proxies do not imply lexical ancestry."}
    targets = (output / "layer-decomposition.json", output / "DIAGNOSTIC_MATRIX.md")
    if any(target.resolve() in (source_path.resolve(), data_path.resolve()) for target in targets): raise ValueError("Output aliases input")
    output.mkdir(parents=True, exist_ok=True)
    targets[0].write_text(json.dumps(result_data, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    targets[1].write_text(render_matrix(matrix), encoding="utf-8")
    return result_data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("output/stage1-vm-source.lua.txt"))
    parser.add_argument("--data", type=Path, default=Path("output/stage1-vm-data.bin"))
    parser.add_argument("--output", type=Path, default=Path("output/phase15"))
    args = parser.parse_args()
    try: report = run(args.source, args.data, args.output)
    except (ValueError, OSError, KeyError, IndexError, TypeError) as failure:
        print(f"Layer decomposition failed: {failure}", file=sys.stderr)
        return 1
    print("String targets:", len(report["string_decomposition"]), "prototype pairs:", len(report["prototype_diagnostic_matrix"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
