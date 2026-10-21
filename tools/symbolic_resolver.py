"""Phase12: symbolic environment, guarded cross-record masks and ownership checks.

No dummy runtime defaults, application calls, Lua, factory or network execution.
"""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile

import analyzer
from gw_aligner import initial_header, definitions
from lazy_tracer import inspect_reference, tag_path
import payload_decoder
from prologue_analyzer import analyze
import reconstructor
from reader_tracer import custom_uint, decrypt_record, parse_loader
from string_resolver import read_length_payload, resolve_string


def arrays_from_candidate(candidate):
    raw = bytes.fromhex(candidate["plain_hex"])
    streams = {}
    for name, array in zip(("j", "O", "Z", "B"), candidate["layout"]["arrays"]):
        cursor, values = array["values_start"], []
        for _ in range(array["slots"]):
            value, cursor = custom_uint(raw, cursor)
            values.append(value)
        if cursor != array["values_end"]: raise ValueError("Candidate stream mismatch")
        streams[name] = values
    header = initial_header(raw)
    words = struct.unpack_from("<II", raw, header["u32_words_offset"])
    return streams, words


def explore(streams, entry, words, numeric, text, max_paths=4):
    """Replay bounded alternative constraints; never substitute concrete defaults."""
    queue, results = [{}], []
    while queue and len(results) < max_paths:
        decisions = queue.pop(0)
        state = analyze(streams, entry, *words, budget=2000, numeric_constant=numeric,
                        text_constant=text, symbolic_environment=True,
                        branch_decisions=decisions, snapshot_pcs=(9062, 9063, 9251))
        condition = state["trace"][-1].get("unresolved_condition") if state["trace"] else None
        results.append({"constraints": decisions, **state})
        if condition and state["pc"] not in decisions:
            queue.extend([{**decisions, state["pc"]: truth} for truth in (True, False)])
    return results, bool(queue)


def enumerate_masks(intermediate, equations):
    """Exhaustive byte search. String length markers do not constrain byte values."""
    variants = []
    for key in range(256):
        raw = payload_decoder.xor_bytes(intermediate, key)
        try: text = raw.decode("utf-8")
        except UnicodeDecodeError: text = None
        variants.append({"key": key, "sha256": hashlib.sha256(raw).hexdigest(),
                         "utf8_valid": text is not None,
                         "printable": text is not None and all(c.isprintable() or c in "\r\n\t" for c in text)})
    conditional = []
    for key in sorted({e["key"] for e in equations}):
        raw = payload_decoder.xor_bytes(intermediate, key)
        try: text = raw.decode("utf-8")
        except UnicodeDecodeError: text = None
        conditional.append({"key": key, "bytes_hex": raw.hex(), "utf8": text,
                            "guards": [e for e in equations if e["key"] == key]})
    return {"all_masks": variants, "unconditional_mask_domain": list(range(256)),
            "intermediate_bytes_hex": intermediate.hex(), "byte_entropy_invariant_under_xor": True,
            "conditional_plaintexts": conditional, "resolved_unconditionally": False,
            "note": "No known plaintext bytes/header inside these strings; UTF8 or entropy cannot prove a key"}


PROOFS = ("source_consumer_verified", "descriptor_parsed_exactly", "capture_indices_fit_owner",
          "child_header_verified", "control_flow_verified", "ancestry_unconditional")


def validate_tree(root, expected_nodes, edges):
    """Require evidence, unique ownership, reachability and acyclicity, not overlap."""
    expected_nodes = set(expected_nodes) | {root}
    reasons, parents, adjacency = [], {}, collections.defaultdict(list)
    for edge in edges:
        parent, child = edge["parent"], edge["child"]
        missing = [proof for proof in PROOFS if edge.get("proofs", {}).get(proof) is not True]
        if missing: reasons.append({"edge": [parent, child], "missing_proofs": missing})
        if parent not in expected_nodes or child not in expected_nodes:
            reasons.append({"edge": [parent, child], "error": "unknown node"})
        if child == root or child in parents and parents[child] != parent:
            reasons.append({"edge": [parent, child], "error": "root owned or multiple parents"})
        parents[child] = parent
        adjacency[parent].append(child)
    visited, active = set(), set()
    def visit(node):
        if node in active:
            reasons.append({"node": node, "error": "cycle"})
            return
        if node in visited: return
        active.add(node)
        for child in adjacency[node]: visit(child)
        active.remove(node)
        visited.add(node)
    # Visit every component for cycles; separately calculate root reachability.
    for node in sorted(expected_nodes): visit(node)
    reachable, pending = set(), [root]
    while pending:
        node = pending.pop()
        if node in reachable: continue
        reachable.add(node)
        pending.extend(adjacency[node])
    missing_nodes = sorted(expected_nodes - reachable)
    if missing_nodes: reasons.append({"error": "unreachable or unassigned nodes", "nodes": missing_nodes})
    return {"verified_hierarchy": {"root": root, "parents": parents} if not reasons else None,
            "validation_issues": reasons}


def ownership_candidates(owner, streams, descriptors, backing, entries, capacity):
    # Exact source closure consumers. Variant at a candidate slot is a guard.
    patterns = [(157, "O", 132, "B", "Z"), (163, "j", 38, "Z", "B"),
                (228, "B", 82, "Z", "O"), (82, "j", 78, "Z", "B")]
    found = []
    for variant, opcode_array, opcode, fn_array, desc_array in patterns:
        for ix in range(min(map(len, streams.values()))):
            if streams[opcode_array][ix] != opcode: continue
            child, descriptor = streams[fn_array][ix], streams[desc_array][ix]
            if descriptor not in descriptors or not 1 <= child <= len(entries): continue
            position = entries[child - 1]["value"]
            position = position if 0 <= position < len(backing) else position ^ 306486104
            if not 0 <= position < len(backing) or tag_path(backing[position])[0] != 24: continue
            captures = descriptors[descriptor]["captures"]
            local = [c for c in captures if c["kind"] in (0, 2, 3)]
            fits = all(0 <= c["target_index"] < capacity and
                       (c["kind"] != 2 or c["target_index"] + c["span_length"] <= capacity) for c in local)
            found.append({"parent": owner, "child": child, "pc": ix + 1, "variant_guard": variant,
                          "descriptor_id": descriptor, "capture_count": len(captures),
                          "local_register_ranges_fit": fits,
                          "unvalidated_enclosing_capture_indices": [c["target_index"] for c in captures if c["kind"] == 1],
                          "proofs": {"source_consumer_verified": True, "descriptor_parsed_exactly": True,
                                     "capture_indices_fit_owner": fits and not any(c["kind"] == 1 for c in captures), "child_header_verified": False,
                                     "control_flow_verified": False, "ancestry_unconditional": False}})
    return found


def run(source_path, data_path, output):
    source, data = analyzer.bounded_read(source_path), analyzer.bounded_read(data_path)
    if hashlib.sha256(source).hexdigest() != analyzer.SOURCE_SHA or hashlib.sha256(data).hexdigest() != analyzer.DATA_SHA:
        raise ValueError("Unknown g/d snapshot")
    # Source patterns are pinned as well as the snapshot hash.
    source_text = source.decode("ascii")
    anchors = ("t[i[W]]=B[W](WJ,nil,nil)", "t[A[W]]=Z[W](f,nil,nil);T=f",
               "t[i[W]]=Z[W](f,nil,nil);T=f", "t[A[W]]=Z[W](z,nil,nil)", "t[i[W]]=F[O[W]]")
    for anchor in anchors:
        if anchor not in source_text: raise ValueError("Symbolic/closure source anchor missing")
    with tempfile.TemporaryDirectory() as temporary:
        staging = Path(temporary)
        baseline = payload_decoder.run(source_path, data_path, staging / "phase11")
        reconstructor.run(source_path, data_path, staging / "base", [664])
        backing = (staging / "base/record-664.backing-postfill.bin").read_bytes()
        root_streams = json.loads((staging / "base/record-664.streams.json").read_text())
        root_plain = (staging / "base/record-664.transformed.bin").read_bytes()
    loader = parse_loader(data)
    texts = {s["reference_id"]: s.get("utf8") for s in baseline["combined_string_candidates"]}
    def text(ref):
        if ref in texts: return texts[ref]
        if not 1 <= ref <= loader["lookup_count"]: return None
        position = loader["lookup_entries"][ref - 1]["value"]
        if not 0 <= position < len(backing): return None
        try: return resolve_string(backing, ref, position).get("utf8")
        except (ValueError, IndexError): return None
    def numeric(ref):
        if not 1 <= ref <= loader["lookup_count"]: return None
        row = inspect_reference(backing, loader["lookup_entries"], ref)
        value = row.get("value")
        return value if type(value) is int else None
    root_words = struct.unpack_from("<II", root_plain, initial_header(root_plain)["u32_words_offset"])
    root_paths, truncated = explore(root_streams, 9942, root_words, numeric, text)
    descriptors = {d["reference_id"]: d for d in baseline["capture_descriptors"]}
    edges = ownership_candidates(664, root_paths[0]["arrays"], descriptors, backing,
                                 loader["lookup_entries"], 181)
    unresolved_ids = {s["reference_id"] for s in baseline["strings"] if s["status"] == "unresolved_mask"}
    equations = collections.defaultdict(list)
    child_reports, native_reports = [], []
    for function in baseline["functions"]:
        owner = function["reference_id"]
        for candidate in function["candidates"]:
            if candidate["format"] == 2:
                native_reports.append({"reference_id": owner, "factory_slot": candidate["factory_slot"],
                                       "factory_source_offset": candidate["factory_source_offset"],
                                       "declaration_preview": source_text[candidate["factory_source_offset"]:candidate["factory_source_offset"] + 160],
                                       "preview_is_complete_body": False,
                                       "factory_invoked": False, "ownership": "unverified"})
                continue
            streams, words = arrays_from_candidate(candidate)
            paths, capped = explore(streams, candidate["layout"]["entry_pc"]["value"], words, numeric, text)
            child_reports.append({"reference_id": owner, "input_confidence": candidate["verification"],
                                  "paths_capped": capped, "paths": [{k: v for k, v in p.items() if k != "arrays"} for p in paths]})
            edges.extend(ownership_candidates(owner, streams, descriptors, backing, loader["lookup_entries"],
                                               candidate["layout"]["register_capacity"]["value"]))
            for path in paths:
                for patch in path["patches"]:
                    ref = patch["reference_id"]
                    if ref in unresolved_ids:
                        equations[ref].append({"key": patch["key"], "owner_candidate": owner,
                                               "pc": patch["pc"], "equation_kind": "entry-trace",
                                               "branch_constraints": path["constraints"],
                                               "guard": "parent bytes correct and abstract normal-continuation assumptions hold",
                                               "parent_confidence": candidate["verification"]})
            # Enumerate source-equation sites, not just whichever branch ran first.
            for ix in range(min(map(len, streams.values()))):
                op = streams["O"][ix]
                if op not in (11, 76, 14): continue
                ref = streams["B"][ix] if op == 14 else streams["j"][ix]
                key = streams["Z"][ix] if op == 14 else streams["Z"][ix] ^ payload_decoder.mixer(words[1] if op == 11 else words[0])
                if ref in unresolved_ids and 0 <= key <= 255:
                    equations[ref].append({"key": key, "owner_candidate": owner, "pc": ix + 1,
                                           "equation_kind": "initial-state-only site hypothesis",
                                           "guard": "variant157, initial state words unchanged and site reachable",
                                           "parent_confidence": candidate["verification"]})
    strings = []
    for ref in sorted(unresolved_ids):
        position = loader["lookup_entries"][ref - 1]["value"] ^ 306486104
        encoded, _ = read_length_payload(backing, position)
        intermediate, _ = decrypt_record(encoded, ref, 83)
        strings.append({"reference_id": ref, **enumerate_masks(intermediate, equations[ref])})
    known_ids = {f["reference_id"] for f in baseline["functions"]}
    discovered_ids = {e["child"] for e in edges} - known_ids
    additional_nodes = []
    if discovered_ids:
        defs, _ = definitions(source_text)
        for ref in sorted(discovered_ids):
            position = loader["lookup_entries"][ref - 1]["value"]
            position = position if position < len(backing) else position ^ 306486104
            additional_nodes.append(payload_decoder.function_candidate(backing, loader["lookup_entries"],
                {"function_reference_id": ref, "candidate_offset": position}, defs, source_text))
    nodes = {664} | known_ids | discovered_ids
    report = {"source_sha256": analyzer.SOURCE_SHA, "data_sha256": analyzer.DATA_SHA,
              "source_consumer_evidence": [{"offset": source_text.index(a), "text": a} for a in anchors],
              "symbolic_environment": "named unknowns; no dummy defaults, no API dispatch",
              "root_paths": [{k: v for k, v in p.items() if k != "arrays"} for p in root_paths],
              "root_paths_capped": truncated, "vm_record_analysis": child_reports,
              "native_factory_references": native_reports, "string_mask_search": strings,
              "additional_node_header_hypotheses": additional_nodes,
              "candidate_capture_ownership": edges, **validate_tree(664, nodes, edges),
              "application_calls_executed": 0, "factory_invocations": 0, "network_requests": 0,
              "limits": "Conditional equations/structural edges are not verified lexical ownership. Path caps and opaque calls remain explicit. No 1:1 script or OS air gap claimed."}
    target = output / "symbolic-resolution.json"
    if target.resolve() in {source_path.resolve(), data_path.resolve()}: raise ValueError("Output aliases input")
    output.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return report


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--source", type=Path, default=Path("output/stage1-vm-source.lua.txt"))
    cli.add_argument("--data", type=Path, default=Path("output/stage1-vm-data.bin"))
    cli.add_argument("--output", type=Path, default=Path("output/phase12"))
    args = cli.parse_args()
    try: result = run(args.source, args.data, args.output)
    except (ValueError, OSError, IndexError, KeyError, TypeError) as failure:
        print(f"Symbolic analysis failed: {failure}", file=sys.stderr)
        return 1
    print(f"Root stop: {result['root_paths'][0]['pc']}; conditional mask sites for {sum(bool(s['conditional_plaintexts']) for s in result['string_mask_search'])}/29 strings")
    print(f"Capture-owner candidates: {len(result['candidate_capture_ownership'])}; verified hierarchy: {result['verified_hierarchy']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
