"""Phase13: exact dispatch audit, register provenance and proof-obligation reports.

All operations are bounded Python data analysis. No Lua, factory, application API,
network request or original-input mutation is performed.
"""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import tempfile

import analyzer
from gw_aligner import initial_header, definitions
from lazy_tracer import inspect_reference, tag_path
import payload_decoder
from prologue_analyzer import analyze
import reconstructor
from reader_tracer import decrypt_record, parse_loader
import symbolic_resolver
from string_resolver import read_length_payload
from prototype_mapper import parse_descriptors


DISPATCH_FRAGMENT = "if o>=92 then if o>=95 then if o<97 then if o==96 then t[H[W]]=not t[i[W]];else t[H[W]]=t[A[W]][j[W]];end;elseif o~=98 then t[H[W]]=j[W]+O[W];else t[A[W]]=t[i[W]]-Z[W];end;else if o<93 then W=t[H[W]];else if o==94 then t[H[W]]=i[W]*t[A[W]];else t[A[W]]=t[H[W]];T,d,I=A[W+1],H[W+1],i[W+1];m,R,Q=T+I-1,T+d,e(t[T](P(t,T+1,T+d)));K(Q,1,I,T,t);W=W+1;end;end;end;"


def classify_228(op):
    """Truth table for the exact pinned 92..98 source subtree."""
    if type(op) is not int or not 92 <= op <= 98: raise ValueError("Outside audited subtree")
    proof = [{"predicate": "o>=92", "value": True}, {"predicate": "o>=95", "value": op >= 95}]
    if op >= 95:
        proof.append({"predicate": "o<97", "value": op < 97})
        if op < 97:
            proof.append({"predicate": "o==96", "value": op == 96})
            kind = "not" if op == 96 else "field_lookup"
        else:
            proof.append({"predicate": "o~=98", "value": op != 98})
            kind = "constant_add" if op != 98 else "subtract"
    else:
        proof.append({"predicate": "o<93", "value": op < 93})
        if op < 93: kind = "indirect_jump"
        else:
            proof.append({"predicate": "o==94", "value": op == 94})
            kind = "multiply" if op == 94 else "fused_call"
    return {"opcode": op, "handler": kind, "numeric_path_proof": proof}


def summarize_fused_call(streams, pc, registers):
    """Source variant228/op93 normal-return transfer; never call a callee."""
    if not 1 <= pc < min(map(len, streams.values())): raise ValueError("Missing fused lookahead cell")
    ix = pc - 1
    if streams["B"][ix] != 93: raise ValueError("Only opcode93 is the audited fused call")
    before = dict(registers)
    copy_to, copy_from = streams["O"][ix], streams["Z"][ix]
    before[copy_to] = before.get(copy_from)
    target, argc, resultc = streams["O"][ix + 1], streams["Z"][ix + 1], streams["j"][ix + 1]
    if any(type(n) is not int or not 0 <= n <= 100000 for n in (target, argc, resultc)):
        raise ValueError("Fused frame bounds not accepted")
    return {"pc": pc, "opcode": 93, "pre_call_copy": {"destination": copy_to, "source": copy_from},
            "callee_register": target, "callee_expression": before.get(target),
            "argument_count": argc, "argument_range_half_open": [target + 1, target + argc + 1],
            "requested_results": resultc, "result_range_half_open": [target, target + resultc],
            "pack": "table.pack retains actual result count in n, including nil positions",
            "move": "copy requested results1..I to t[T..T+I-1], pad missing values with nil",
            "normal_return_pc": pc + 2, "exception_or_nonreturn_pc": None,
            "callee_invoked": False, "effects": "unknown until callee and alias effects are proven"}


class Constants:
    """Path-local directory/XOR view; future patch keys are never pre-applied."""
    def __init__(self, backing, entries):
        self.backing, self.entries = backing, entries
        self.positions, self.effects, self.events, self.violations = {}, {}, [], []
        self.text_cache = {}

    def observe(self, patch):
        ref, key = patch["reference_id"], patch["key"]
        if type(ref) is not int or not 1 <= ref <= len(self.entries) or type(key) is not int or not 0 <= key <= 255:
            self.violations.append({"reference_id": ref, "error": "patch ID/key outside validated domain"})
            return False
        previous = self.positions.get(ref, self.entries[ref - 1]["value"])
        position = previous ^ 306486104
        if not 0 <= position < len(self.backing):
            self.violations.append({"reference_id": ref, "error": "directory toggle leaves backing bounds"})
            return False
        self.positions[ref] = position
        self.effects[ref] = self.effects.get(ref, 0) ^ key
        self.events.append({**patch, "directory_before": previous, "directory_after": position,
                            "cumulative_payload_xor": self.effects[ref]})
        return True

    def text(self, ref):
        if ref in self.text_cache: return self.text_cache[ref]
        if not 1 <= ref <= len(self.entries): return None
        position = self.positions.get(ref, self.entries[ref - 1]["value"])
        if not 0 <= position < len(self.backing): return None
        if tag_path(self.backing[position])[0] not in (55, 98): return None
        try:
            encoded, _ = read_length_payload(self.backing, position)
            raw = decrypt_record(encoded, ref, 83)[0] if tag_path(self.backing[position])[0] == 98 else encoded
            result = payload_decoder.xor_bytes(raw, self.effects.get(ref, 0)).decode("utf-8")
            self.text_cache[ref] = result
            return result
        except (ValueError, IndexError, UnicodeDecodeError): return None

    def number(self, ref):
        if not 1 <= ref <= len(self.entries): return None
        row = inspect_reference(self.backing, self.entries, ref)
        value = row.get("value")
        return value if type(value) is int else None


def constructor_contract(source, slot):
    """Prove only the two closure-construction prefixes, never the function body."""
    match = re.search(r'\[' + str(slot) + r'\]=function\([^)]*\)', source)
    if not match: raise ValueError("Missing factory declaration")
    start = match.end()
    outer = re.search(r'return\s*function\([^)]*\)', source[start:start + 4000])
    if not outer: raise ValueError("Outer closure prefix unrecognized")
    first_prefix = source[start:start + outer.start()]
    second_start = start + outer.end()
    inner = re.search(r'return\s*function\([^)]*\)', source[second_start:second_start + 4000])
    if not inner: raise ValueError("Inner closure prefix unrecognized")
    second_prefix = source[second_start:second_start + inner.start()]
    atom = r'[A-Za-z_]\w*(?:\[\d+\]|\.[A-Za-z_]\w*)?'
    local = r'local\s+[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*\s*=\s*' + atom + r'(?:\s*,\s*' + atom + r')*\s*;'
    for prefix in (first_prefix, second_prefix):
        if re.sub(local, '', prefix).strip(): raise ValueError("Non-alias operation in constructor prefix")
    return {"factory_slot": slot, "source_offset": match.start(),
            "outer_alias_prefix": first_prefix, "capture_alias_prefix": second_prefix,
            "proof": "both prefixes contain only local alias assignments and return a function literal",
            "body_executed": False}


class Closures:
    def __init__(self, source, constants, owner, capacity, defs):
        self.source, self.constants, self.owner, self.capacity, self.defs = source, constants, owner, capacity, defs
        self.templates, self.bindings, self.obligations = {}, [], []

    def build(self, child, descriptor, pc, variant, registers):
        try:
            if type(child) is not int or not 1 <= child <= len(self.constants.entries):
                raise ValueError("Child ID outside directory")
            position = self.constants.positions.get(child, self.constants.entries[child - 1]["value"])
            if not 1 <= child <= len(self.constants.entries) or not 0 <= position < len(self.constants.backing):
                raise ValueError("Child directory/mask not established on this path")
            if child not in self.templates:
                result = payload_decoder.function_candidate(self.constants.backing, self.constants.entries,
                    {"function_reference_id": child, "candidate_offset": position}, self.defs, self.source,
                    {"key": self.constants.effects.get(child, 0), "confidence": "path-local source equation"})
                if len(result["candidates"]) != 1: raise ValueError("Child header did not have one accepted candidate")
                candidate = result["candidates"][0]
                contract = constructor_contract(self.source, candidate["factory_slot"])
                self.templates[child] = {"header": candidate, "constructor_contract": contract}
            if not 1 <= descriptor <= len(self.constants.entries): raise ValueError("Descriptor outside directory")
            dp = self.constants.positions.get(descriptor, self.constants.entries[descriptor - 1]["value"])
            if not 0 <= dp < len(self.constants.backing) or tag_path(self.constants.backing[dp])[0] != 95:
                raise ValueError("Descriptor encoding not reviewed")
            encoded, _ = read_length_payload(self.constants.backing, dp)
            raw, _ = decrypt_record(encoded, descriptor, 83)
            raw = payload_decoder.xor_bytes(raw, self.constants.effects.get(descriptor, 0))
            parsed = parse_descriptors(raw)
            captures, bounds = [], []
            for capture in parsed["captures"]:
                index, kind = capture["target_index"], capture["kind"]
                end = index + (capture["span_length"] if kind == 2 else 1)
                if kind == 1:
                    captures.append({"enclosing_capture": index, "frame": self.owner, "bound_verified": False})
                    bounds.append({"kind": kind, "index": index, "status": "enclosing input capacity unknown"})
                else:
                    fits = 0 <= index < end <= self.capacity
                    if not fits: raise ValueError("Capture exceeds advertised allocation")
                    bounds.append({"kind": kind, "index_range": [index, end], "advertised_allocation": self.capacity, "fits": True})
                    if kind == 0: captures.append({"copied_register": index, "value": registers.get(index)})
                    else: captures.append({"cell_identity": f"frame:{self.owner}:register:{index}", "span": end - index})
            # Only a newly read template triggers its validated cleanup. Avoid
            # pretending to execute either factory prefix or the returned body.
            template = self.templates[child]
            if not template.get("cleanup_applied"):
                footer = template["header"]["footer"]
                start, end = footer["backing_slice_range"]
                self.constants.backing = reconstructor.apply_fill_copy(self.constants.backing, start, end - start, footer["fill_byte"])
                template["cleanup_applied"] = True
            binding = {"parent": self.owner, "child": child, "descriptor_id": descriptor,
                       "pc": pc, "variant": variant, "capture_bounds": bounds,
                       "captures": captures, "child_factory": template["header"]["factory_slot"],
                       "scope": "source transfer established on guarded abstract path; unconditional ancestry not proved"}
            binding["constructor_alias_guard"] = "decoder context is the reviewed plain table; alias reads do not invoke metamethods"
            self.bindings.append(binding)
            return {"symbolic_closure": child, "owner": self.owner, "creation_pc": pc,
                    "captures": captures, "capture_argument_is_nil": parsed["count"] == 0}
        except (ValueError, IndexError, KeyError, TypeError) as failure:
            self.obligations.append({"pc": pc, "child": child, "descriptor": descriptor, "reason": str(failure)})
            return None


UNMODELED_STRINGS = (74, 141, 160, 192, 196, 203, 267, 269, 432, 457, 476, 485, 512, 545, 580, 616, 632, 702)


def inverse_mix(value):
    """All eight uint32 preimages; high three bits determine low-bit XOR."""
    if type(value) is not int or not 0 <= value < 1 << 29:
        raise ValueError("Mixer image must fit29 bits")
    return [(high << 29) | (value ^ high) for high in range(8)]


def mask_word_domain(operand, allowed_keys=range(256)):
    """Exact uint32 domain for key=operand XOR mix(word), given byte keys."""
    if type(operand) is not int or not 0 <= operand <= 0xffffffff:
        raise ValueError("Operand must be uint32")
    keys = sorted(set(allowed_keys))
    if any(type(k) is not int or not 0 <= k <= 255 for k in keys):
        raise ValueError("Mask outside byte domain")
    return sorted({word for key in keys if 0 <= operand ^ key < 1 << 29
                   for word in inverse_mix(operand ^ key)})


def audit_ownership(previous, baseline, root, root_constants, source, defs, source_transfer_factory=None):
    """Audit each nominated edge, keeping activation, ancestry and input guards."""
    functions = {f["reference_id"]: f for f in baseline["functions"]}
    descriptors = {d["reference_id"]: d for d in baseline["capture_descriptors"]}
    reports, traces = [], []
    for edge in previous["candidate_capture_ownership"]:
        owner = edge["parent"]
        if owner == 664:
            analysis, closures, input_guard = root, None, "root pinned bytes; guarded abstract normal continuation"
            capacity = 181
        else:
            candidate = functions[owner]["candidates"][0]
            streams, words = symbolic_resolver.arrays_from_candidate(candidate)
            context = Constants(root_constants.backing, root_constants.entries)
            context.positions, context.effects = dict(root_constants.positions), dict(root_constants.effects)
            # Hypothetical child activation has its own read/fill lifecycle. It
            # does not establish that the parent was actually called by root.
            footer = candidate["footer"]
            start, end = footer["backing_slice_range"]
            context.backing = reconstructor.apply_fill_copy(context.backing, start, end - start, footer["fill_byte"])
            capacity = candidate["layout"]["register_capacity"]["value"]
            closures = Closures(source, context, owner, capacity, defs)
            analysis = analyze(streams, candidate["layout"]["entry_pc"]["value"], *words,
                numeric_constant=context.number, text_constant=context.text,
                symbolic_environment=True, symbolic_field_reads=True,
                patch_observer=context.observe, track_register_writes=True,
                closure_builder=closures.build, snapshot_pcs=(edge["pc"],),
                source_transfer=source_transfer_factory(context) if source_transfer_factory else None)
            input_guard = candidate["verification"] + "; hypothetical activation in root-prefix directory context; enclosing captures unknown"
        seen = [e for e in analysis["trace"] if e["pc"] == edge["pc"]]
        matching = [e for e in seen if e["variant"] == edge["variant_guard"]]
        captures = descriptors[edge["descriptor_id"]]["captures"]
        ranges = [{"kind": c["kind"], "index": c["target_index"],
                   "end_exclusive": c["target_index"] + (c["span_length"] if c["kind"] == 2 else 1),
                   "owner_allocation_hint": capacity,
                   "enclosing_bound_known": False if c["kind"] == 1 else None} for c in captures]
        transfers = [e for e in matching if e.get("symbolic_closure_creation", {}).get("child") == edge["child"]]
        proofs = dict(edge["proofs"])
        # Reachability in one guarded model is not unconditional reachability.
        proofs["control_flow_verified"] = False
        proofs["ancestry_unconditional"] = False
        reports.append({**edge, "proofs": proofs, "capture_index_audit": ranges,
            "bounds_caveat": "table.create size is an allocation hint, not a Lua table index limit",
            "input_guard": input_guard, "events_at_candidate_pc": seen,
            "guarded_transfer_observed": bool(transfers), "guarded_transfer_evidence": transfers,
            "frontier": {"pc": analysis["pc"], "reason": analysis["stop"]},
            "closure_obligations": closures.obligations if closures else [],
            "missing_proof": "unconditional activation and ancestry; exact input masks/lazy-cache state; enclosing capture bounds where present"})
        traces.append((owner, analysis))
    return reports, traces


def string_constraints(functions, root, extra_traces):
    """Potential sites retain dispatcher/rewrite guards; no guessed strings."""
    sites = collections.defaultdict(list)
    candidates = [(664, root["arrays"], "root arrays at current frontier")]
    for function in functions:
        for candidate in function["candidates"]:
            if candidate["format"] == 0:
                arrays, _ = symbolic_resolver.arrays_from_candidate(candidate)
                candidates.append((function["reference_id"], arrays, candidate["verification"]))
    # Variant157 uses H XOR mix(y/V); variants163 and228 patch directly.
    patterns = [(157, "O", 11, "j", "Z", "y"), (157, "O", 76, "j", "Z", "V"),
                (157, "O", 14, "B", "Z", None),
                (163, "j", 84, "B", "Z", "y"), (163, "j", 96, "B", "Z", "V"),
                (163, "j", 141, "O", "B", None),
                (228, "B", 74, "j", "Z", "y"), (228, "B", 125, "j", "Z", "V"),
                (228, "B", 100, "j", "O", None)]
    for owner, arrays, confidence in candidates:
        for variant, op_array, opcode, ref_array, key_array, word in patterns:
            for ix in range(min(map(len, arrays.values()))):
                if arrays[op_array][ix] != opcode: continue
                ref, operand = arrays[ref_array][ix], arrays[key_array][ix]
                if ref not in UNMODELED_STRINGS: continue
                if word is None and not 0 <= operand <= 255: continue
                domain = mask_word_domain(operand) if word else []
                sites[ref].append({"owner": owner, "pc": ix + 1, "variant": variant,
                    "equation": f"key = {operand} XOR mix({word}_at_pc)" if word else f"key = {operand}",
                    "word_variable": word, "operand": operand,
                    "uint32_word_domain_size": len(domain) if word else None,
                    "word_domain_sha256": hashlib.sha256(b''.join(struct.pack('<I', n) for n in domain)).hexdigest() if word else None,
                    "guard": "correct dispatcher, source slot not rewritten, site reachable, owner payload valid: " + confidence})
    traced = collections.defaultdict(list)
    for owner, trace in [(664, root), *extra_traces]:
        for patch in trace["patches"]:
            if patch["reference_id"] in UNMODELED_STRINGS:
                traced[patch["reference_id"]].append({"owner": owner, **patch,
                    "guard": "normal continuation on audited abstract path, activation/context assumptions remain"})
    return [{"reference_id": ref, "potential_sites": sites[ref], "guarded_trace_equations": traced[ref],
             "unconditional_key": None, "unconditional_domain": list(range(256)),
             "status": "guarded equation only" if traced[ref] else "no reachable equation proved"} for ref in UNMODELED_STRINGS]


def run(source_path, data_path, output):
    source_bytes, data = analyzer.bounded_read(source_path), analyzer.bounded_read(data_path)
    if hashlib.sha256(source_bytes).hexdigest() != analyzer.SOURCE_SHA or hashlib.sha256(data).hexdigest() != analyzer.DATA_SHA:
        raise ValueError("Unknown g/d snapshot")
    source = source_bytes.decode("ascii")
    if DISPATCH_FRAGMENT not in source: raise ValueError("Audited dispatcher subtree missing")
    with tempfile.TemporaryDirectory() as temporary:
        staging = Path(temporary)
        previous = symbolic_resolver.run(source_path, data_path, staging / "phase12")
        baseline = payload_decoder.run(source_path, data_path, staging / "phase11")
        reconstructor.run(source_path, data_path, staging / "base", [664])
        backing = (staging / "base/record-664.backing-postfill.bin").read_bytes()
        streams = json.loads((staging / "base/record-664.streams.json").read_text())
        plain = (staging / "base/record-664.transformed.bin").read_bytes()
    loader = parse_loader(data)
    constants = Constants(backing, loader["lookup_entries"])
    defs, _ = definitions(source)
    closures = Closures(source, constants, 664, 181, defs)
    words = struct.unpack_from("<II", plain, initial_header(plain)["u32_words_offset"])
    root = analyze(streams, 9942, *words, numeric_constant=constants.number, text_constant=constants.text,
                   symbolic_environment=True, symbolic_field_reads=True, patch_observer=constants.observe,
                   snapshot_pcs=(9063, 9251, 9252, 9253, 9254), track_register_writes=True,
                   closure_builder=closures.build)
    snapshots = [e for e in root["trace"] if "registers_before" in e]
    field_event = next(e for e in snapshots if e["pc"] == 9251)
    counterfactual_arrays = {name: list(values) for name, values in root["arrays"].items()}
    counterfactual_arrays["B"][9250] = 93
    # An explicit contradictory hypothesis illustrates why the old call decode
    # would consume the real9252 patch. It is never used to continue the model.
    rejected_call = summarize_fused_call(counterfactual_arrays, 9251, field_event["registers_before"])
    provenance = [{"pc": e["pc"], "variant": e["variant"], "opcode": e["opcode"], "write": w}
                  for e in root["trace"] for w in e.get("register_writes", [])
                  if w["register"] in (72, 57, 14)]
    ownership, parent_traces = audit_ownership(previous, baseline, root, constants, source, defs)
    constraints = string_constraints(baseline["functions"], root, parent_traces)
    report = {"source_sha256": analyzer.SOURCE_SHA, "data_sha256": analyzer.DATA_SHA,
              "dispatcher_evidence": {"offset": source.index(DISPATCH_FRAGMENT), "text": DISPATCH_FRAGMENT},
              "dispatch_truth_table": [classify_228(op) for op in range(92, 99)],
              "correction": "PC9251 is opcode95 field lookup task.cancel, not a fused call. Opcode93 is the fused call.",
              "root_analysis": {k: v for k, v in root.items() if k != "arrays"},
              "focused_register_snapshots": snapshots, "path_local_patch_events": constants.events,
              "focused_register_provenance": provenance,
              "rejected_9251_fused_call_hypothesis": rejected_call,
              "patch_violations": constants.violations,
              "guarded_closure_bindings": closures.bindings, "closure_obligations": closures.obligations,
              "ownership_audits": ownership, "remaining_string_constraints": constraints,
              "mixer_inverse_proof": "For n=(h<<29)|l, mix(n)=l XOR h. Thus n=(h<<29)|(m XOR h), h=0..7. Exactly eight preimages; byte key gives at most2048 word candidates, not a unique mask.",
              "previous_ownership_candidates": previous["candidate_capture_ownership"],
              "previous_tree_validation_issues": previous["validation_issues"],
              "verified_hierarchy": None, "application_calls_executed": 0, "factory_invocations": 0,
              "network_requests": 0, "limits": "Static source transfer proofs and guarded traces only. No runtime equivalence or complete prototype tree claimed."}
    target = output / "fused-call-analysis.json"
    if target.resolve() in {source_path.resolve(), data_path.resolve()}: raise ValueError("Output aliases input")
    output.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return report


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--source", type=Path, default=Path("output/stage1-vm-source.lua.txt"))
    cli.add_argument("--data", type=Path, default=Path("output/stage1-vm-data.bin"))
    cli.add_argument("--output", type=Path, default=Path("output/phase13"))
    args = cli.parse_args()
    try: report = run(args.source, args.data, args.output)
    except (ValueError, OSError, IndexError, KeyError, TypeError) as failure:
        print(f"Fused-call audit failed: {failure}", file=sys.stderr)
        return 1
    print(f"9251 classification: field_lookup; new stop {report['root_analysis']['pc']}; patches {len(report['path_local_patch_events'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
