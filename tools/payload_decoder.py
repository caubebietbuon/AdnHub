"""Phase11: source-grounded prologue masks and bounded structural hypotheses.

No Lua/application/factory/opcode execution, network or original-input writes.
Header-constrained hypotheses are never promoted to source-proven runtime keys.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile

import analyzer
from gw_aligner import definitions, initial_header, normalized_primary_layout
from gw_reader_model import ReaderModel, Opaque, Boundary
from lazy_tracer import inspect_reference, tail_descriptor
from reader_tracer import custom_uint, decrypt_record, parse_loader
import prototype_mapper
import reconstructor
from string_resolver import read_length_payload, resolve_string
from prologue_analyzer import analyze


def mixer(word):
    return (word ^ ((word >> 29) & 7)) & 0x1fffffff


def source_prologue_masks(source, plain, streams):
    """Constant propagation at pinned straight-line source/data sites only.

    Does not dispatch instructions. The six equations carry source offsets and
    a precondition that their reviewed prologue sites are reached unchanged.
    """
    fragments = ["local V,m,k=W[1];local y,t=W[2],D(h);",
                 "local WJ,bJ,hJ=i[W],_(H[W],(Y(_(y,(Y(v(y,29),7))),536870911))),b[5];",
                 "local bJ,hJ,wJ=i[W],_(H[W],(Y(_(V,(Y(v(V,29),7))),536870911))),b[5];"]
    anchors = [{"offset": source.index(text), "text": text} for text in fragments]
    header = initial_header(plain)
    start = header["u32_words_offset"]
    import struct
    first, second = struct.unpack_from("<II", plain, start)
    sites = [(9943, 11, second), (9944, 11, second), (9945, 76, first),
             (9950, 76, first), (9952, 11, second), (9954, 76, first)]
    result = {}
    for pc, opcode, seed_word in sites:
        if streams["O"][pc - 1] != opcode:
            raise ValueError("Prologue patch opcode snapshot mismatch")
        ref, encoded = streams["j"][pc - 1], streams["Z"][pc - 1]
        key = encoded ^ mixer(seed_word)
        if not 0 <= key <= 255: raise ValueError("Source patch mask is not a byte")
        result[ref] = {"key": key, "pc": pc, "encoded_word": encoded,
                       "seed_word": seed_word, "confidence": "source-derived prologue equation",
                       "guard": "reviewed patch site reached with initial V/y; no runtime reachability asserted"}
    return result, anchors


def xor_bytes(data, key):
    if type(key) is not int or not 0 <= key <= 255: raise ValueError("Mask must be a byte")
    return bytes(value ^ key for value in data)


def native_reader_boundary(plain, defs, backing, entries):
    model = ReaderModel(defs)
    context, directory = model.table(), model.table()
    directory.data = {i + 1: row["value"] for i, row in enumerate(entries)}
    context.data = {4: backing, 5: directory, 6: Opaque("blocked lazy reader"), 7: False}
    try:
        model.function("GW", [model, context, plain])
    except Boundary as stop:
        if not isinstance(stop.slot, int): raise ValueError("Unexpected non-factory reader boundary")
        return {"factory_slot": stop.slot,
                "reader_end": max(row["offset"] + row["width"] for row in model.reads),
                "source_offset": stop.offset, "factory_invoked": False}
    raise ValueError("Native reader did not reach a factory boundary")


def function_candidate(backing, entries, target, defs, source, known_mask=None):
    ref, position = target["function_reference_id"], target["candidate_offset"]
    encoded, begin = read_length_payload(backing, position)
    intermediate, _ = decrypt_record(encoded, ref, 91)
    # Only source-reviewed formats0 and2 are tested. Arbitrary other formats are
    # not ruled out; first-byte assumptions remain explicit hypotheses.
    formats = [2] if len(intermediate) == 8 else [0]
    candidates, errors = [], []
    for fmt in formats:
        key = known_mask["key"] if known_mask else intermediate[0] ^ fmt
        plain = xor_bytes(intermediate, key)
        try:
            if plain[0] != fmt: raise ValueError("Source key conflicts with candidate format")
            if fmt == 0:
                layout = normalized_primary_layout(plain)
                if layout.get("status") != "normalized_primary_sequence_parsed": raise ValueError("Unsupported primary header")
                factory = initial_header(plain)["factory_slot"]
                cursor = layout["reader_end"]
                # PC arrays can have different lengths; bound PC to opcode array.
                if not 1 <= layout["entry_pc"]["value"] <= layout["arrays"][1]["slots"]:
                    raise ValueError("Entry PC outside opcode stream")
            else:
                layout = native_reader_boundary(plain, defs, backing, entries)
                factory, cursor = layout["factory_slot"], layout["reader_end"]
            match = re.search(r'\[' + str(factory) + r'\]=function\(', source)
            if not match: raise ValueError("Factory definition absent from source")
            footer = tail_descriptor(plain, cursor, begin, len(backing))
            if footer["remaining_bytes"] != 0: raise ValueError("Reader/footer do not consume the record")
            candidates.append({"key": key, "format": fmt, "factory_slot": factory,
                               "factory_source_offset": match.start(), "layout": layout, "footer": footer,
                               "plain_sha256": hashlib.sha256(plain).hexdigest(), "plain_hex": plain.hex(),
                               "verification": "source-mask plus reader-structure" if known_mask else "header-constrained structural hypothesis; runtime mask unproven"})
        except (ValueError, IndexError, KeyError, TypeError) as failure:
            errors.append(str(failure))
    return {"reference_id": ref, "source_mask": known_mask, "candidates": candidates, "errors": errors,
            "lexical_owner": None, "factory_invocations": 0}


def string_candidates(backing, target, known_mask=None):
    ref = target["reference_id"]
    encoded, _ = read_length_payload(backing, target["candidate_offset"])
    intermediate, _ = decrypt_record(encoded, ref, 83)
    if known_mask:
        raw = xor_bytes(intermediate, known_mask["key"])
        try: text = raw.decode("utf-8")
        except UnicodeDecodeError: text = None
        return {"reference_id": ref, "status": "source_mask_string_candidate", "source_mask": known_mask,
                "bytes_hex": raw.hex(), "utf8": text, "length": len(raw)}
    # Readability is only a ranking hint. Lua strings may be arbitrary bytes and
    # every byte mask remains possible until a source equation constrains it.
    readable = []
    for key in range(256):
        raw = xor_bytes(intermediate, key)
        try: text = raw.decode("utf-8")
        except UnicodeDecodeError: continue
        if all(c.isprintable() or c in "\r\n\t" for c in text):
            readable.append({"key": key, "text_preview": text[:160], "truncated": len(text) > 160})
    return {"reference_id": ref, "status": "unresolved_mask", "possible_masks": 256,
            "readability_hints_not_verified": readable, "unique_readability_is_not_key_proof": True}


def run(source_path, data_path, output):
    source_bytes, data = analyzer.bounded_read(source_path), analyzer.bounded_read(data_path)
    if hashlib.sha256(source_bytes).hexdigest() != analyzer.SOURCE_SHA or hashlib.sha256(data).hexdigest() != analyzer.DATA_SHA:
        raise ValueError("Unknown g/d snapshot")
    source = source_bytes.decode("ascii")
    with tempfile.TemporaryDirectory() as temp:
        temp = Path(temp)
        synthesis = prototype_mapper.run(source_path, data_path, temp / "synthesis")
        reconstructor.run(source_path, data_path, temp / "base", [664])
        streams = json.loads((temp / "base/record-664.streams.json").read_text())
        plain = (temp / "base/record-664.transformed.bin").read_bytes()
        backing = (temp / "base/record-664.backing-postfill.bin").read_bytes()
    masks, anchors = source_prologue_masks(source, plain, streams)
    loader = parse_loader(data)
    def numeric(ref):
        if not 1 <= ref <= loader["lookup_count"]: return None
        item = inspect_reference(backing, loader["lookup_entries"], ref)
        value = item.get("value")
        return value if item["status"] == "explicit_python_primitive_reader" and type(value) is int else None
    def text(ref):
        if not 1 <= ref <= loader["lookup_count"]: return None
        try: return resolve_string(backing, ref, loader["lookup_entries"][ref - 1]["value"]).get("utf8")
        except (ValueError, IndexError): return None
    import struct
    header = initial_header(plain)
    first, second = struct.unpack_from("<II", plain, header["u32_words_offset"])
    initialization = analyze(streams, 9942, first, second, numeric_constant=numeric, text_constant=text)
    for patch in initialization["patches"]:
        ref = patch["reference_id"]
        if ref in masks and masks[ref]["key"] != patch["key"]: raise ValueError("Conflicting source mask equations")
        masks[ref] = {**patch, "guard": "conditional normal continuation of restricted abstract initialization; opaque operands and runtime reachability unverified"}
    # Decoded initialization instructions expose IDs absent from raw encrypted
    # stream surveys. Preserve that provenance rather than silently changing totals.
    function_targets = list(synthesis["prototype_mapping"]["conditional_function_edges"])
    string_targets = list(synthesis["prototype_mapping"]["conditional_string_targets"])
    old_ids = {x["function_reference_id"] for x in function_targets} | {x["reference_id"] for x in string_targets}
    added = []
    for ref in masks:
        if ref in old_ids: continue
        if not 1 <= ref <= loader["lookup_count"]: raise ValueError("Derived patch ID outside directory")
        position = loader["lookup_entries"][ref - 1]["value"] ^ prototype_mapper.DIRECTORY_MASK
        if not 0 <= position < len(backing): raise ValueError("Derived patch target outside backing")
        from lazy_tracer import tag_path
        leaf, _ = tag_path(backing[position])
        added.append({"reference_id": ref, "leaf_state": leaf, "candidate_offset": position,
                      "origin": "restricted decoded initialization trace"})
        if leaf == 24: function_targets.append({"function_reference_id": ref, "candidate_offset": position})
        elif leaf == 98: string_targets.append({"reference_id": ref, "candidate_offset": position})
    defs, _ = definitions(source)
    functions = [function_candidate(backing, loader["lookup_entries"], target, defs, source,
                                    masks.get(target["function_reference_id"]))
                 for target in function_targets]
    strings = [string_candidates(backing, target, masks.get(target["reference_id"]))
               for target in string_targets]
    records = [inspect_reference(backing, loader["lookup_entries"], 1),
               resolve_string(backing, 2, loader["lookup_entries"][1]["value"])]
    report = {"source_sha256": analyzer.SOURCE_SHA, "data_sha256": analyzer.DATA_SHA,
              "source_evidence": anchors, "prologue_masks": masks, "functions": functions, "strings": strings,
              "initialization_analysis": {k: v for k, v in initialization.items() if k != "arrays"},
              "new_reference_targets": added,
              "root_metadata": synthesis["root"],
              "primitive_candidates": synthesis["constant_candidates"]["primitives"],
              "combined_string_candidates": synthesis["constant_candidates"]["strings"] +
                  [s for s in strings if s["status"] == "source_mask_string_candidate"],
              "capture_descriptors": synthesis["descriptors"],
              "record_1_2_reclassification": records,
              "record_probe_correction": "IDs1/2 are uint32/string, not function records. Format85 was an invalid aux91 function-probe artifact.",
              "verified_hierarchy": None,
              "control_flow_limit": "Restricted numeric initialization abstract interpretation only; unknown application/table effects stop. Not a general VM or runtime trace.",
              "lua_executed": False, "factory_invocations": 0, "index_invocations": 0,
              "application_opcodes_executed": 0, "network_requests": 0,
              "limits": "Structural hypotheses do not prove runtime keys or lexical ownership. No complete decompilation or OS-enforced air gap claimed."}
    target = output / "payload-analysis.json"
    if target.resolve() in {source_path.resolve(), data_path.resolve()}: raise ValueError("Output aliases input")
    output.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return report


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--source", type=Path, default=Path("output/stage1-vm-source.lua.txt"))
    cli.add_argument("--data", type=Path, default=Path("output/stage1-vm-data.bin"))
    cli.add_argument("--output", type=Path, default=Path("output/phase11"))
    args = cli.parse_args()
    try: report = run(args.source, args.data, args.output)
    except (ValueError, OSError, IndexError, KeyError, TypeError) as failure:
        print(f"Payload analysis failed: {failure}", file=sys.stderr)
        return 1
    print(f"Functions with structural candidates: {sum(bool(f['candidates']) for f in report['functions'])}/{len(report['functions'])}")
    print(f"Source-mask strings: {sum(s['status']=='source_mask_string_candidate' for s in report['strings'])}/{len(report['strings'])}")
    print("Numeric initialization modeled only; no Lua/application/factory/network execution. Hierarchy unverified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
