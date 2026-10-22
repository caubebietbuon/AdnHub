"""Phase14 offline proof obligations, mask-domain intersections and link audit.

Only data readers and explicit symbolic transfer rules are used. No Lua,
application function, factory, metatable, network or shell payload is invoked.
"""
import argparse
import collections
from functools import partial
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile

import analyzer
import fused_call_analyzer as phase13
from gw_aligner import definitions, initial_header
import payload_decoder
from prologue_analyzer import analyze, mix
from reader_tracer import decrypt_record, parse_loader
import reconstructor
import symbolic_resolver
from string_resolver import read_length_payload


CONTEXT_READ = "if o>=130 then if o~=131 then t[H[W]]=t[i[W]]~=O[W];else t[i[W]]=x[H[W]];end;"
CONSTANT_READ = "if o>=114 then if o>=115 then if o==116 then T=g[H[W]];t[i[W]]=T[6][T[5]][O[W]];else t[A[W]]=t[H[W]]==t[i[W]];end;else t[A[W]]=Z[W];end;"
BRANCH_163 = "if o<80 then if o~=79 then W=if t[H[W]]<=w[W]then W else A[W];"
FRAME_INIT = "local y,t=W[2],D(h);"
XOR_163 = "t[A[W]]=Z[W](f,nil,nil);T=f;else t[w[W]]=_(t[H[W]],t[A[W]]);"
FIELD_157 = "elseif xJ==108 then t[H[W]]=t[w[W]][i[W]];"
ADD_163 = "else t[A[W]]=t[w[W]]+H[W];end;end;else if o<80 then"


def source_transfer(variant, opcode, a, b, c, registers, event, constants=None):
    """A context-table read is a symbolic alias, never a context function call."""
    if variant == 228 and opcode == 131:
        registers[a] = {"decoder_context_slot": b}
        event["context_alias"] = {"slot": b, "destination": a}
        event["normal_completion_assumption"] = "reviewed plain decoder-context table identity"
        return True
    if variant == 228 and opcode == 114 and constants is not None:
        text, number = constants.text(b), constants.number(b)
        if text is None and number is None: return False
        registers[c] = {"string_literal": text, "reference_id": b} if text is not None else number
        event["materialized_constant"] = {"reference_id": b, "destination": c}
        return True
    if variant == 163 and opcode == 78:
        left = registers.get(b)
        if type(left) is not int: return False
        condition = left <= a
        event["exact_branch"] = {"left": left, "operator": "<=", "right": a, "result": condition}
        return {"next_pc": event["pc"] + 1 if condition else c + 1}
    if variant == 163 and opcode == 83:
        left = registers.get(a)
        if type(left) is not int or max(abs(left), abs(b), abs(left + b)) > 2**53: return False
        registers[c] = left + b
        event["exact_integer_addition"] = [left, b, left + b]
        return True
    return False


def patch_equation(event):
    """Return state variable, reference and operand for reviewed patch handlers."""
    patterns = {157: {11: ("y", event["operand1"], event["H"]),
                      76: ("V", event["operand1"], event["H"]),
                      14: (None, event["operand3"], event["H"])},
                163: {84: ("y", event["operand1"], event["H"]),
                      96: ("V", event["operand1"], event["H"]),
                      141: (None, event["operand3"], event["operand1"])},
                228: {74: ("y", event["operand1"], event["H"]),
                      125: ("V", event["operand1"], event["H"]),
                      100: (None, event["operand1"], event["operand3"])}}
    return patterns.get(event["variant"], {}).get(event["opcode"])


def evaluate_mask_site(site, observations):
    """Intersect the exact inverse with same-site, same-dispatch state evidence.

    A mismatching observation rules out that visit, never every future visit.
    Header words and cross-function allocation overlaps are not state evidence.
    """
    word, operand = site["word_variable"], site["operand"]
    allowed = phase13.mask_word_domain(operand) if word else None
    rows = []
    for event in observations:
        if event["pc"] != site["pc"]: continue
        if event["variant"] != site["variant"]:
            rows.append({"status": "pruned_observed_visit", "reason": "different dispatcher", "event": event})
            continue
        actual = patch_equation(event)
        if actual != (word, site["reference_id"], operand):
            rows.append({"status": "pruned_observed_visit", "reason": "opcode/operands differ after transforms", "event": event})
            continue
        if word is None:
            key, state = operand, None
        else:
            state = event["state_words_before"][0 if word == "V" else 1]
            if type(state) is not int or not 0 <= state <= 0xffffffff:
                rows.append({"status": "unproved_uint32_state", "value": state})
                continue
            if state not in allowed:
                rows.append({"status": "pruned_observed_visit", "reason": "inverse domain excludes observed state", "state": state})
                continue
            key = operand ^ mix(state)
            if state not in phase13.inverse_mix(operand ^ key):
                raise ValueError("Inverse/forward mixer proof disagrees")
        rows.append({"status": "guarded_trace_equation", "key": key, "state": state,
                     "pc": event["pc"], "guard": "all preceding activation/context/normal-completion obligations"})
    witnesses = []
    if word:
        for key in (0, 255):
            image = operand ^ key
            if 0 <= image < 1 << 29:
                state = phase13.inverse_mix(image)[0]
                witnesses.append({"key": key, "state": state, "forward_key": operand ^ mix(state)})
    return {"observed_visit_results": rows, "inverse_domain_count": len(allowed) if word else None,
            "local_equation_satisfiable": bool(allowed) if word else 0 <= operand <= 255,
            "local_equation_witnesses": witnesses,
            "witness_scope": "local equation only; not proof of whole-program satisfiability",
            "unconditional_key": None}


def mask_audit(previous, root, parent_traces):
    traces = {owner: trace["trace"] for owner, trace in parent_traces}
    traces[664] = root["trace"]
    reports = []
    for row in previous["remaining_string_constraints"]:
        sites = []
        for original in row["potential_sites"]:
            site = {**original, "reference_id": row["reference_id"]}
            sites.append({**site, **evaluate_mask_site(site, traces.get(site["owner"], []))})
        reports.append({"reference_id": row["reference_id"], "sites": sites,
            "new_guarded_trace_equations": row["guarded_trace_equations"],
            "unconditional_key": None, "unconditional_domain_inclusive": [0, 255],
            "reason": "guarded entry equation; activation/cache still unproved" if row["guarded_trace_equations"] else
                      "no complete reachable state equation" if sites else "no reviewed patch site in scanned arrays",
            "missing_constraints": ["exact activation/dispatcher", "instruction rewrite provenance", "state at patch", "prior patch/cache lifecycle"]})
    return reports


def root_cause_audit(previous, root):
    """Expand the six obligations without turning family matches into edges."""
    reports = []
    for audit in previous["ownership_audits"]:
        edge = {k: audit[k] for k in ("parent", "child", "pc", "descriptor_id", "variant_guard")}
        missing = [key for key in symbolic_resolver.PROOFS if audit["proofs"].get(key) is not True]
        explanations = {
            "source_consumer_verified": "pinned source family matches; actual slot dispatcher still a separate obligation",
            "descriptor_parsed_exactly": "triplets consume descriptor bytes exactly; descriptor carries no parent prototype ID",
            "capture_indices_fit_owner": "local index fit only; allocation size cannot identify owner; enclosing bounds unproved",
            "child_header_verified": "layout parsing does not establish live child selection, cumulative mask or cached-template identity",
            "control_flow_verified": "candidate site not reached before current frontier in this activation context",
            "ancestry_unconditional": "no complete proof of parent activation, shared-cache lifecycle and unique incoming owner"}
        observed = [e for e in root["trace"] if audit["parent"] == 664 and e["pc"] == audit["pc"]]
        reports.append({**edge, "proofs": audit["proofs"], "failed_or_unproved_criteria": missing,
            "criterion_explanations": explanations, "capture_index_audit": audit["capture_index_audit"],
            "frontier": {"pc": root["pc"], "reason": root["stop"]} if audit["parent"] == 664 else audit["frontier"],
            "candidate_visit_observed": bool(observed), "incoming_capture_bound_proofs": [],
            "owner_inference_from_register_overlap": "rejected: register indices are frame-relative",
            "descriptor_parent_inference": "rejected: the same descriptor may be consumed by multiple closures"})
    return reports


def projected_frontier_proof(owner, trace):
    """Refute only the concrete abstract prefix under explicit source contracts."""
    last = trace["trace"][-1]
    writes = collections.defaultdict(list)
    for event in trace["trace"][:-1]:
        for write in event.get("register_writes", []):
            writes[write["register"]].append({"pc": event["pc"], "value": write["value"]})
    if owner == 137 and (last["variant"], last["opcode"]) == (163, 39):
        operands = [last["H"], last["operand3"]]
        # No argument transfer, opaque operation or callback was silently used.
        unmodeled_writes = [event for event in trace["trace"][:-1]
                            if "normal_completion_assumption" in event and event.get("opcode") != 17]
        reviewed = {(157, op) for op in (69, 14, 71, 57, 129, 22, 20)} | {(163, op) for op in (62, 24, 2, 17)}
        unreviewed_effects = [event for event in trace["trace"][:-1]
                              if (event.get("variant"), event.get("opcode")) not in reviewed]
        absent = [index for index in operands if not writes[index]]
        return {"owner": owner, "pc": last["pc"], "operation": "bit32.bxor",
                "read_registers": operands, "unwritten_operands": absent,
                "opaque_prior_transfers": unmodeled_writes,
                "unreviewed_prior_frame_effects": unreviewed_effects,
                "status": "normal continuation refuted under stated contracts" if len(absent) == 2 and not unmodeled_writes and not unreviewed_effects else "pending",
                "contracts": ["candidate plaintext and dispatcher transformations are correct",
                              "reviewed table.create initializes absent entries to nil",
                              "reviewed bit32.bxor requires numeric operands",
                              "no hidden frame writes outside the reviewed prefix"],
                "consequence": "do not simplify XOR(r0,r0) to zero without first proving numeric type; this prefix does not establish PC33 reachability",
                "scope": "conditional source-prefix contradiction, not global proof that function137 can never execute"}
    if owner == 704:
        return {"owner": owner, "pc": last["pc"], "operation": "argument field read",
                "source_equation": "r2 = r10[6]", "base_provenance": writes[10],
                "status": "pending caller input/type and field resolution",
                "consequence": "argument1 is not interchangeable with enclosing capture1 or parent register10"}
    if owner == 237:
        return {"owner": owner, "pc": last["pc"], "operation": "numeric addition",
                "source_equation": "r1 = r1 + 1", "input_provenance": writes[1],
                "status": "pending numeric input provenance",
                "consequence": "exact branch78 was evaluated using11<=8=false; subsequent add cannot use an invented numeric default"}
    return {"owner": owner, "pc": last["pc"], "status": "unreviewed frontier"}


def capture_constraints(bindings, root):
    """Instantiate capture ordinals into frame cells, never equal-numbered regs."""
    values = {}
    for event in root["trace"]:
        for write in event.get("register_writes", []):
            values[write["register"]] = write["value"]
    rows = []
    for binding in bindings:
        captures = []
        for ordinal, capture in enumerate(binding["captures"], 1):
            identity = capture.get("cell_identity")
            register = int(identity.rsplit(":", 1)[1]) if identity else None
            captures.append({"capture_ordinal": ordinal, "cell_identity": identity,
                "parent_register": register, "frontier_value": values.get(register),
                "scope": "guarded root frame at current frontier; later mutations invalidate value snapshots"})
        rows.append({"parent": binding["parent"], "child": binding["child"],
                     "descriptor_id": binding["descriptor_id"], "captures": captures,
                     "capture_count": len(captures),
                     "mask_word_dependency_proved": False,
                     "missing_dependency": "no proved def-use chain from these cells into the selected child patch state V/y"})
    return rows


def local_ambiguity_certificate(backing, entries, reference):
    """Verify the remaining byte ambiguity without scoring candidate plaintext."""
    position = entries[reference - 1]["value"] ^ 306486104
    encoded, _ = read_length_payload(backing, position)
    intermediate, _ = decrypt_record(encoded, reference, 83)
    hashes = {hashlib.sha256(payload_decoder.xor_bytes(intermediate, key)).hexdigest() for key in range(256)}
    return {"reference_id": reference, "payload_bytes": len(intermediate),
            "intermediate_sha256": hashlib.sha256(intermediate).hexdigest(),
            "distinct_local_plaintexts": len(hashes),
            "proof": "for nonempty bytes, different XOR keys change the first byte; length is outside masked payload and gives no key equation",
            "scope": "payload and mixer-local constraints only, not every full program path",
            "utf8_or_readability_used_as_proof": False}


def scan_candidate_entries(baseline, root_context, source, defs):
    """Bounded hypothetical activations; no sibling state or actual call inferred."""
    results = []
    for function in baseline["functions"]:
        for candidate in function["candidates"]:
            if candidate["format"] != 0: continue
            arrays, words = symbolic_resolver.arrays_from_candidate(candidate)
            context = phase13.Constants(root_context.backing, root_context.entries)
            context.positions, context.effects = dict(root_context.positions), dict(root_context.effects)
            owner = function["reference_id"]
            live_header_matches = False
            position = context.positions.get(owner, context.entries[owner - 1]["value"])
            if 0 <= position < len(context.backing):
                live = payload_decoder.function_candidate(context.backing, context.entries,
                    {"function_reference_id": owner, "candidate_offset": position}, defs, source,
                    {"key": context.effects.get(owner, 0), "confidence": "current guarded root-prefix mask"})
                live_header_matches = any(c["plain_sha256"] == candidate["plain_sha256"] for c in live["candidates"])
            start, end = candidate["footer"]["backing_slice_range"]
            context.backing = reconstructor.apply_fill_copy(context.backing, start, end - start, candidate["footer"]["fill_byte"])
            closures = phase13.Closures(source, context, owner, candidate["layout"]["register_capacity"]["value"], defs)
            state = analyze(arrays, candidate["layout"]["entry_pc"]["value"], *words,
                budget=2000, numeric_constant=context.number, text_constant=context.text,
                symbolic_environment=True, symbolic_field_reads=True, track_register_writes=True,
                patch_observer=context.observe, closure_builder=closures.build,
                source_transfer=partial(source_transfer, constants=context))
            strings = []
            # analyze() retains attempted patches even if the observer rejects
            # their directory transition. Only accepted transitions are evidence.
            for patch in context.events:
                ref = patch["reference_id"]
                if ref not in phase13.UNMODELED_STRINGS: continue
                end_prefix = next(index + 1 for index, event in enumerate(state["trace"])
                    if event["pc"] == patch["pc"] and patch_equation(event) is not None
                    and patch_equation(event)[1] == ref)
                before = state["trace"][end_prefix - 1]
                word, _, operand = patch_equation(before)
                proof = evaluate_mask_site({"reference_id": ref, "pc": before["pc"], "variant": before["variant"],
                    "operand": operand, "word_variable": word}, [before])
                strings.append({"reference_id": ref, "key": patch["key"], "pc": patch["pc"],
                    "utf8": context.text(ref), "guard": "hypothetical entry, current directory/cache lifecycle, all preceding source transformations",
                    "exact_equation_proof": proof,
                    "prefix_steps_to_patch": end_prefix,
                    "unknown_branch_constraints_before_patch": [event for event in state["trace"][:end_prefix]
                        if "assumed_branch_constraint" in event]})
            results.append({"owner": owner, "state": state, "bindings": closures.bindings,
                "live_header_matches_root_context": live_header_matches,
                "new_guarded_strings": strings, "path_local_patch_events": context.events,
                "patch_violations": context.violations, "header_confidence": candidate["verification"],
                "guard": "hypothetical activation at root frontier with unknown arguments/captures; source/header/cache constraints pending",
                "all_paths_explored": False})
    return results


def run(source_path, data_path, output, include_analysis_arrays=False):
    raw_source, data = analyzer.bounded_read(source_path), analyzer.bounded_read(data_path)
    if hashlib.sha256(raw_source).hexdigest() != analyzer.SOURCE_SHA or hashlib.sha256(data).hexdigest() != analyzer.DATA_SHA:
        raise ValueError("Unknown g/d snapshot")
    source = raw_source.decode("ascii")
    fragments = (CONTEXT_READ, CONSTANT_READ, BRANCH_163, FRAME_INIT, XOR_163, FIELD_157, ADD_163,
                 "[109]=assert", "[34]=table.create", "[20]=bit32.bxor")
    if any(fragment not in source for fragment in fragments):
        raise ValueError("Source transfer evidence missing")
    with tempfile.TemporaryDirectory() as temporary:
        temp = Path(temporary)
        previous = phase13.run(source_path, data_path, temp / "phase13")
        baseline = payload_decoder.run(source_path, data_path, temp / "baseline")
        reconstructor.run(source_path, data_path, temp / "base", [664])
        backing = (temp / "base/record-664.backing-postfill.bin").read_bytes()
        streams = json.loads((temp / "base/record-664.streams.json").read_text(encoding="utf-8"))
        plain = (temp / "base/record-664.transformed.bin").read_bytes()
    entries = parse_loader(data)["lookup_entries"]
    context = phase13.Constants(backing, entries)
    defs, _ = definitions(source)
    closures = phase13.Closures(source, context, 664, 181, defs)
    words = struct.unpack_from("<II", plain, initial_header(plain)["u32_words_offset"])
    root = analyze(streams, 9942, *words, numeric_constant=context.number, text_constant=context.text,
                   symbolic_environment=True, symbolic_field_reads=True, patch_observer=context.observe,
                   track_register_writes=True, closure_builder=closures.build, source_transfer=partial(source_transfer, constants=context),
                   snapshot_pcs=tuple(range(8395, 8406)))
    audits, parent_traces = phase13.audit_ownership(
        {"candidate_capture_ownership": previous["previous_ownership_candidates"]}, baseline,
        root, context, source, defs, source_transfer_factory=lambda ctx: partial(source_transfer, constants=ctx))
    updated_previous = {**previous, "ownership_audits": audits}
    entries_analysis = scan_candidate_entries(baseline, context, source, defs)
    traces = [(entry["owner"], {**entry["state"], "patches": entry["path_local_patch_events"]})
              for entry in entries_analysis]
    mask_sites = phase13.string_constraints(baseline["functions"], root, traces)
    masks = mask_audit({"remaining_string_constraints": mask_sites}, root, traces)
    causes = root_cause_audit(updated_previous, root)
    structural = []
    for binding in closures.bindings:
        structural.append({"parent": binding["parent"], "child": binding["child"],
            "descriptor_id": binding["descriptor_id"], "pc": binding["pc"],
            "proofs": {"source_consumer_verified": True, "descriptor_parsed_exactly": True,
                       "capture_indices_fit_owner": all(b.get("fits") is True for b in binding["capture_bounds"]),
                       "child_header_verified": False, "control_flow_verified": False, "ancestry_unconditional": False},
            "conditional_evidence": binding,
            "not_promoted_because": "guarded source transfer does not prove unconditional activation/cache identity or unique ancestry"})
    expected_nodes = {664} | {f["reference_id"] for f in baseline["functions"]} | {e["child"] for e in audits}
    validation = symbolic_resolver.validate_tree(664, expected_nodes, [*audits, *structural])
    report = {"source_sha256": analyzer.SOURCE_SHA, "data_sha256": analyzer.DATA_SHA,
              "source_evidence": [{"offset": source.index(s), "text": s} for s in fragments],
              "root_analysis": {k: v for k, v in root.items() if k != "arrays"},
              "path_local_patch_events": context.events,
              "guarded_closure_bindings": closures.bindings, "closure_obligations": closures.obligations,
              "mask_audit": masks, "prototype_root_causes": causes,
              "structural_hierarchy_candidates": structural,
              "capture_frame_constraints": capture_constraints(closures.bindings, root),
              "local_ambiguity_certificates": [local_ambiguity_certificate(backing, entries, ref) for ref in phase13.UNMODELED_STRINGS],
              "projected_frontier_proofs": [projected_frontier_proof(owner, trace) for owner, trace in parent_traces if owner != 664],
              "candidate_entry_analyses": [{**{k: v for k, v in entry.items() if k != "state"},
                  "analysis": {k: v for k, v in entry["state"].items() if k != "arrays"}} for entry in entries_analysis],
              "prefix_mask_coverage": {"target_ids": list(phase13.UNMODELED_STRINGS),
                  "patch_ids_observed": sorted({e["reference_id"] for e in context.events}),
                  "remaining_ids_patched_in_prefix": sorted(set(phase13.UNMODELED_STRINGS) & {e["reference_id"] for e in context.events}),
                  "consequence": "root prefix alone cannot establish these18 keys; frontier state is not state at unvisited sites"},
              "parent_activation_analyses": [{"owner": owner, **{k: v for k, v in trace.items() if k != "arrays"}} for owner, trace in parent_traces if owner != 664],
              **validation, "network_requests": 0, "application_calls_executed": 0,
              "factory_invocations": 0}
    report["new_conditional_string_results"] = [{"owner": entry["owner"], **string}
        for entry in entries_analysis for string in entry["new_guarded_strings"]]
    if include_analysis_arrays:
        report['analysis_arrays'] = {str(entry['owner']): entry['state']['arrays'] for entry in entries_analysis}
        report['analysis_arrays']['664'] = root['arrays']
    report["still_without_trace_equation"] = [row["reference_id"] for row in masks if not row["new_guarded_trace_equations"]]
    last = root["trace"][-1]
    if last["variant"] == 228 and last["opcode"] == 93:
        report["fused_call_frontier"] = phase13.summarize_fused_call(root["arrays"], root["pc"], last["registers_before"])
        frame = report["fused_call_frontier"]
        start, end = frame["argument_range_half_open"]
        frame["argument_expressions"] = [last["registers_before"].get(register) for register in range(start, end)]
        frame["context_slot109_source_binding"] = "assert"
        frame["pending_contracts"] = ["context slot109 still denotes the reviewed standard assertion",
                                      "global.debug is truthy for normal assertion return"]
    report["limits"] = "All state equations and capture snapshots retain path guards. No library behavior is executed or environmental precondition assumed true. Complete decompilation and verified hierarchy remain unproved."
    target = output / "obligation-resolution.json"
    if target.resolve() in {source_path.resolve(), data_path.resolve()}: raise ValueError("Output aliases input")
    output.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return report


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--source", type=Path, default=Path("output/stage1-vm-source.lua.txt"))
    cli.add_argument("--data", type=Path, default=Path("output/stage1-vm-data.bin"))
    cli.add_argument("--output", type=Path, default=Path("output/phase14"))
    args = cli.parse_args()
    try: report = run(args.source, args.data, args.output)
    except (ValueError, OSError, KeyError, IndexError, TypeError) as failure:
        print(f"Obligation audit failed: {failure}", file=sys.stderr)
        return 1
    print("Root frontier:", report["root_analysis"]["pc"])
    print("New conditional string IDs:", [row["reference_id"] for row in report["new_conditional_string_results"]])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
