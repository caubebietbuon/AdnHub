"""Pinned offline string readers and conservative prototype-reference mapping.

No Lua, __index, factories, payload, opcode, network or original-input writes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

import analyzer
from gw_aligner import normalized_primary_layout
from lazy_tracer import evidence, tag_path, tail_descriptor
from reader_tracer import custom_uint, decrypt_record, parse_loader
from reconstructor import apply_fill_copy, materialize_candidates, record_probe


def digest(data):
    return hashlib.sha256(data).hexdigest()


def string_evidence(source):
    anchors = ["p<=98 then local j=WJ[n];if j then p,n=125,j;else p=64;end;",
               "p<=64 then local j=xJ+1;local O=o(hJ,j);",
               "RJ=(n+83)%256;local H,Q,g=Z(bJ),1397969747,bJ-bJ%4;",
               "R(AJ,iJ,(B(N(hJ,iJ+xJ),BJ,z[wJ])))",
               "RJ=(wJ*oJ+SJ)%256;S(AJ,bJ,(B(jJ,o(hJ,xJ+bJ),RJ)))",
               "p<=66 then local j,O=C[5],OJ(AJ);WJ[n]=O;",
               "[85]=buffer.tostring", "[79]=buffer.readstring",
               "local j,O=C[4],o(oJ,bJ);p,C,n=128>O and 164 or 145,j,O;",
               "p<=164 then p,xJ=39,1;", "elseif 0>=n then p,n=125,Q;else p=156;end;"]
    return [{"offset": source.index(a), "text": a} for a in anchors]


def read_length_payload(backing, position, max_bytes=1048576):
    if type(position) is not int or not 0 <= position < len(backing):
        raise ValueError("Tag position outside backing")
    length, begin = custom_uint(backing, position + 1)
    if not 0 <= length <= max_bytes or length > len(backing) - begin:
        raise ValueError("String/descriptor length outside backing or allocation limit")
    return backing[begin:begin + length], begin


def resolve_string(backing, reference_id, position):
    if not 0 <= position < len(backing):
        return {"reference_id": reference_id, "status": "opaque_directory_value"}
    tag = backing[position]
    leaf, _ = tag_path(tag)
    result = {"reference_id": reference_id, "tag": tag, "leaf_state": leaf}
    if leaf not in (55, 98):
        return {**result, "status": "not_supported_string_branch"}
    encoded, begin = read_length_payload(backing, position)
    raw = decrypt_record(encoded, reference_id, 83)[0] if leaf == 98 else encoded
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        text = None  # Luau strings are byte sequences, not necessarily UTF-8.
    return {**result, "status": "resolved_string_candidate", "length": len(raw),
            "input_range": [position, begin + len(encoded)], "payload_offset": begin,
            "encoding": "LCG83_then_buffer_tostring" if leaf == 98 else "raw_readstring",
            "bytes_hex": raw.hex(), "sha256": digest(raw), "utf8": text,
            "utf8_valid": text is not None, "cache_key": reference_id,
            "runtime_reachability": "unproven; candidate reference from root stream"}


def descriptor_preview(backing, reference_id, position):
    encoded, begin = read_length_payload(backing, position)
    raw, _ = decrypt_record(encoded, reference_id, 83)
    if not raw:
        raise ValueError("Empty descriptor payload has no count marker")
    count, cursor = custom_uint(raw, 0)
    return {"reference_id": reference_id, "status": "decoded_descriptor_header_only",
            "decoded_bytes": len(raw), "count_marker": count, "header_end": cursor,
            "sha256": digest(raw), "parent_child_meaning": "unverified; no edges inferred"}


def function_reference_edges(backing, entries, streams, parent=664):
    """Only tag0..15 supports a v reference. No factory or recursive decoder."""
    edges, opaque = [], set()
    for wrapper, values in streams.items():
        for index, ref in enumerate(values, 1):
            if not 1 <= ref <= len(entries):
                continue
            position = entries[ref - 1]["value"]
            if not 0 <= position < len(backing):
                opaque.add(ref)
                continue
            if tag_path(backing[position])[0] == 24:
                edges.append({"parent_candidate": parent, "child_reference_id": ref,
                              "wrapper": wrapper, "index_1_based": index,
                              "relation": "potential_function_reference; lexical parenthood and execution unverified",
                              "initial_seed": (ref + 91) % 256})
    return {"root": parent, "candidate_reference_edges": edges,
            "opaque_directory_ids": sorted(opaque), "verified_hierarchy": None,
            "note": "No candidate edges does not establish absence of child prototypes"}


def run(source_path, data_path, output):
    source_bytes, data = analyzer.bounded_read(source_path), analyzer.bounded_read(data_path)
    if digest(source_bytes) != analyzer.SOURCE_SHA or digest(data) != analyzer.DATA_SHA:
        raise ValueError("Unknown g/d snapshot")
    source = source_bytes.decode("ascii")
    evidence(source)
    anchors = string_evidence(source)
    loader = parse_loader(data)
    backing = data[loader["slice_offset"]:loader["slice_end"]]
    _, plain, begin = record_probe(backing, loader["lookup_entries"], 664)
    if plain is None: raise ValueError("Reviewed root unavailable")
    layout = normalized_primary_layout(plain)
    if layout.get("status") != "normalized_primary_sequence_parsed": raise ValueError("Unsupported root layout")
    footer = tail_descriptor(plain, layout["reader_end"], begin, len(backing))
    fill_start, fill_end = footer["backing_slice_range"]
    postfill = apply_fill_copy(backing, fill_start, fill_end - fill_start, footer["fill_byte"])
    streams = {}
    for name, array in zip(("j", "O", "Z", "B"), layout["arrays"]):
        cursor, values = array["values_start"], []
        for _ in range(array["slots"]):
            value, cursor = custom_uint(plain, cursor)
            values.append(value)
        streams[name] = values
    mapping = materialize_candidates(backing, postfill, loader["lookup_entries"], streams, (fill_start, fill_end))
    unresolved_ids = [row["reference_id"] for row in mapping["unresolved"]]
    strings, descriptors, unresolved = [], [], []
    for ref in unresolved_ids:
        position = loader["lookup_entries"][ref - 1]["value"]
        if not 0 <= position < len(postfill):
            unresolved.append({"reference_id": ref, "status": "opaque_directory_value"})
            continue
        leaf, _ = tag_path(postfill[position])
        try:
            if leaf in (55, 98):
                item = resolve_string(postfill, ref, position)
                start, end = item["input_range"]
                if start < fill_end and fill_start < end:
                    unresolved.append({"reference_id": ref, "status": "input_overlaps_fill_not_promoted"})
                else:
                    strings.append(item)
            elif leaf == 95:
                descriptors.append(descriptor_preview(postfill, ref, position))
            else:
                unresolved.append({"reference_id": ref, "leaf_state": leaf, "status": "other_reader_unresolved"})
        except (ValueError, IndexError) as failure:
            unresolved.append({"reference_id": ref, "status": "bounded_reader_rejected", "reason": str(failure)})
    string_ids = {row["reference_id"] for row in strings}
    uses = {name: [{"index_1_based": index, "string_reference_id": ref}
                   for index, ref in enumerate(values, 1) if ref in string_ids]
            for name, values in streams.items()}
    report = {"source_sha256": digest(source_bytes), "data_sha256": digest(data),
              "root": 664, "source_evidence": anchors, "phase8_unresolved_count": len(unresolved_ids),
              "strings": strings, "wrapper_string_uses": uses, "descriptor_headers": descriptors,
              "unresolved": unresolved, "prototype_mapping": function_reference_edges(postfill, loader["lookup_entries"], streams),
              "cache": {"actual_initial_entries": {}, "analysis_candidate_keys": sorted(string_ids),
                        "note": "candidate index keyed by reference ID, not a fabricated runtime cache or access order"},
              "lua_executed": False, "factory_invocations": 0, "index_invocations": 0,
              "opcode_executions": 0, "network_requests": 0,
              "limits": "Custom reader data, not native Luau bytecode validation. Descriptor bodies and child hierarchy unresolved. No OS air gap asserted."}
    target = output / "string-resolution.json"
    if target.resolve() in {source_path.resolve(), data_path.resolve()}:
        raise ValueError("Output aliases input")
    output.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return report


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--source", type=Path, default=Path("output/stage1-vm-source.lua.txt"))
    cli.add_argument("--data", type=Path, default=Path("output/stage1-vm-data.bin"))
    cli.add_argument("--output", type=Path, default=Path("output/phase9"))
    args = cli.parse_args()
    try:
        report = run(args.source, args.data, args.output)
    except (ValueError, OSError, IndexError, KeyError) as failure:
        print(f"String resolution failed: {failure}", file=sys.stderr)
        return 1
    print(f"Strings: {len(report['strings'])}; descriptor headers: {len(report['descriptor_headers'])}; unresolved: {len(report['unresolved'])}")
    print("No Lua, factory, __index, opcode or network calls. Child hierarchy remains unverified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
