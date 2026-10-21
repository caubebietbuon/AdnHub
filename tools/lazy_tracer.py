"""Phase 7: pinned, offline metadata inspection; never invoke Lua or __index.

Only explicit Python data readers below run. The tag decision tree is a reviewed
translation of predicates, not an interpreter for the lazy-reader body.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import struct
import sys

import analyzer
from gw_aligner import normalized_primary_layout
from reader_tracer import custom_uint, decrypt_record, parse_loader


# state: (source predicate, true destination, false destination).
# The first split is EJ<=167; subsequent predicates inspect unchanged tag wJ.
DECISIONS = {
    77: ("wJ<=63", 117, 124), 117: ("16>=wJ", 103, 150),
    103: ("16<=wJ", 88, 24), 150: ("wJ<=28", 73, 3),
    3: ("wJ>53", 21, 82), 124: ("96>=wJ", 89, 135),
    89: ("wJ==70", 161, 84), 135: ("wJ<=104", 17, 166),
    166: ("wJ==167", 155, 33), 119: ("wJ>203", 107, 92),
    107: ("219>=wJ", 37, 159), 37: ("wJ>218", 95, 58),
    159: ("wJ>237", 142, 140), 142: ("244~=wJ", 55, 70),
    92: ("174>=wJ", 101, 6), 101: ("wJ>169", 98, 136),
    6: ("195<wJ", 28, 130), 28: ("wJ~=197", 65, 68),
}

# Only straight numeric readers with independently established buffer aliases.
# Aux values are type-local, and MUST NOT be replaced with the root aux91.
PRIMITIVES = {
    73: (83, "<f", "float32"), 58: (70, "<I", "uint32"),
    155: (134, "<i", "int32"), 65: (62, "<d", "float64"),
    130: (255, "<B", "uint8"), 161: (216, "<B", "negative_uint8"),
    17: (187, "<h", "int16"), 140: (78, "<H", "uint16"),
    70: (162, "<B", "boolean_not_206"),
}
LEAVES = {
    24: "recursive_v_reference_boundary", 88: "Vector3_constructor_blocked",
    82: "Vector2_constructor_blocked", 21: "triplet_table_reader_unresolved",
    84: "table_create_reader_unresolved", 33: "compound_reader_unresolved",
    136: "fill_buffer_reader_unresolved", 98: "shared_cache_then_encoded_buffer_unresolved",
    68: "fill_buffer_reader_unresolved", 95: "encoded_string_reader_unresolved",
    55: "shared_cache_then_raw_string",
}


def predicate(text, tag):
    """Evaluate ONLY a comparison of the literal tag and an integer; no eval."""
    import re
    match = re.fullmatch(r"(wJ|[0-9]+)(<=|>=|==|~=|<|>)(wJ|[0-9]+)", text)
    if not match:
        raise ValueError("Unsupported tag predicate")
    left, op, right = match.groups()
    a = tag if left == "wJ" else int(left)
    b = tag if right == "wJ" else int(right)
    return {"<=": a <= b, ">=": a >= b, "==": a == b,
            "~=": a != b, "<": a < b, ">": a > b}[op]


def tag_path(tag):
    if type(tag) is not int or not 0 <= tag <= 255:
        raise ValueError("Tag outside byte range")
    state, path = (77 if tag <= 167 else 119), []
    while state in DECISIONS:
        text, yes, no = DECISIONS[state]
        result = predicate(text, tag)
        path.append({"state": state, "predicate": text, "result": result})
        state = yes if result else no
    return state, path


def evidence(source):
    anchors = ["G=u[-1][f]", "local j,O,F,zJ=g[G],w,u[-2],0;",
               "H(x,WJ,n,91)", "u[f]=n;p=152;", "WJ[n]=j;p,n=125,j;",
               "n[1+WJ]=wJ;n[WJ+3]=bJ;n[2+WJ]=hJ;", "I(n*3)",
               "local W,B=S[b+3],S[b+2];", "A[w]={[5]=B,[6]=h[B]}",
               "A[w]=h[B][B]", "A[w]=j[B]", "[78]=buffer.fill",
               "local h,N,z=x:GW(w,A);local E=x[46](A,z);",
               "x[78](b,o+w,S,j);return 13,O,w,o;",
               "return 34,1+j,w,b", "return 19,3+b,x;",
               "local j=a(hJ,xJ,bJ);WJ[n]=j;", "p=244~=wJ and 55 or 70;",
               "h[-1]=N;w[-1]=E;Z[-1]=H;z[-1]=o;",
               "h[-2]=S;w[-2]=S;Z[-2]=S;z[-2]=S;",
               "x[B](x,nil,T,A,R,o,Z,w,i,nil,j,E,W,z,N,H,h)",
               "[4890]=function(x,W,W,b,h,w,j,O,o,S,S,A,B,B,H,i,Z,R)",
               "[71]=buffer.readf32", "[122]=buffer.readf64", "[39]=buffer.readi32",
               "[93]=buffer.readi16", "[13]=buffer.readu16", "[79]=buffer.readstring"]
    anchors += [f"p={text} and {yes} or {no};" for text, yes, no in DECISIONS.values()]
    missing = [text for text in anchors if text not in source]
    if missing:
        raise ValueError(f"Missing source evidence: {missing}")
    return [{"offset": source.index(text), "text": text} for text in anchors]


def tail_descriptor(plain, cursor, source_start, slice_size):
    """Normalize zW32 -> oW25 -> uint reader -> DW19, no buffer fill."""
    start = cursor
    offset, cursor = custom_uint(plain, cursor)
    length, cursor = custom_uint(plain, cursor)
    if cursor >= len(plain):
        raise ValueError("Truncated fill directive")
    fill = plain[cursor]
    cursor += 1
    begin = source_start + offset
    end = begin + length
    if not 0 <= begin <= end <= slice_size:
        raise ValueError("Fill directive outside backing slice")
    return {"offset": start, "hex": plain[start:cursor].hex(),
            "source_state_path": ["zW32", "oW25", "zW34", "QW2", "oW26", "iW11", "DW19", "KW13"],
            "relative_source_offset": offset, "length": length, "fill_byte": fill,
            "backing_slice_range": [begin, end], "reader_end": cursor,
            "remaining_bytes": len(plain) - cursor,
            "meaning": "post-GW source-buffer fill directive, not applied",
            "scope": "backing ciphertext slice, not transformed plaintext",
            "purpose": "overwrite is source-supported; motivation not established"}


def inspect_reference(sliced, entries, ref_id):
    """Read explicitly selected data, never a metatable or function constructor.

    Out-of-directory values are opaque stream slots; they are not all constants.
    """
    if not 1 <= ref_id <= len(entries):
        return {"reference_id": ref_id, "status": "outside_directory_not_followed"}
    position = entries[ref_id - 1]["value"]
    if not 0 <= position < len(sliced):
        return {"reference_id": ref_id, "status": "opaque_directory_value_not_followed"}
    tag = sliced[position]
    leaf, path = tag_path(tag)
    item = {"reference_id": ref_id, "slice_offset": position, "tag": tag,
            "leaf_state": leaf, "decision_path": path,
            "runtime_reachability": "not established; potential stream reference only"}
    if leaf == 24:
        return {**item, "status": LEAVES[leaf], "auxiliary": 91,
                "initial_seed": (ref_id + 91) % 256,
                "factory_invoked": False, "prototype_constructed": False}
    if leaf in PRIMITIVES:
        aux, fmt, kind = PRIMITIVES[leaf]
        size = struct.calcsize(fmt)
        if position + 1 + size > len(sliced):
            return {**item, "status": "primitive_out_of_bounds"}
        raw, _ = decrypt_record(sliced[position + 1:position + 1 + size], ref_id, aux)
        value = struct.unpack(fmt, raw)[0]
        if kind == "negative_uint8": value = -value
        if kind == "boolean_not_206": value = value != 206
        if isinstance(value, float) and not math.isfinite(value):
            value = repr(value)  # strict JSON, preserve non-finite observations as text
        return {**item, "status": "explicit_python_primitive_reader", "kind": kind,
                "auxiliary": aux, "value": value, "plain_hex": raw.hex()}
    if leaf == 55:
        # Empty-cache branch55->62->varuint->72. No cache is mutated here.
        length, begin = custom_uint(sliced, position + 1)
        if length > len(sliced) - begin:
            return {**item, "status": "raw_string_out_of_bounds", "length": length}
        raw = sliced[begin:begin + length]
        return {**item, "status": "explicit_python_raw_string_reader", "length": length,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "preview_utf8": raw[:160].decode("utf-8", errors="backslashreplace"),
                "preview_hex": raw[:160].hex(), "preview_truncated": length > 160}
    return {**item, "status": LEAVES[leaf]}


def run(source_path, data_path, output, sample_limit=64):
    if not 1 <= sample_limit <= 748:
        raise ValueError("Sample limit must be1..748")
    source_bytes = analyzer.bounded_read(source_path)
    data = analyzer.bounded_read(data_path)
    if hashlib.sha256(source_bytes).hexdigest() != analyzer.SOURCE_SHA or hashlib.sha256(data).hexdigest() != analyzer.DATA_SHA:
        raise ValueError("Unknown g/d snapshot")
    source = source_bytes.decode("ascii")
    anchors = evidence(source)
    loader = parse_loader(data)
    record_id = loader["selected_id"]
    if record_id != 664:
        raise ValueError("Only reviewed root664 layout supported")
    sliced = data[loader["slice_offset"]:loader["slice_end"]]
    position = loader["lookup_entries"][record_id - 1]["value"]
    length, begin = custom_uint(sliced, position + 1)
    if length > len(sliced) - begin: raise ValueError("Root outside backing slice")
    plain, _ = decrypt_record(sliced[begin:begin + length], record_id, 91)
    layout = normalized_primary_layout(plain)
    if layout.get("status") != "normalized_primary_sequence_parsed":
        raise ValueError("Unsupported root layout")
    wrappers, selected, seen = [], [], set()
    for name, array in zip(("j", "O", "Z", "B"), layout["arrays"]):
        cursor, values = array["values_start"], []
        for _ in range(array["slots"]):
            value, cursor = custom_uint(plain, cursor)
            values.append(value)
        histogram, valid = {}, []
        for index, ref in enumerate(values, 1):
            if 1 <= ref <= loader["lookup_count"]:
                target = loader["lookup_entries"][ref - 1]["value"]
                if 0 <= target < len(sliced):
                    tag = sliced[target]
                    histogram[str(tag)] = histogram.get(str(tag), 0) + 1
                    valid.append({"stream_index": index, "reference_id": ref})
                    if ref not in seen and len(selected) < sample_limit:
                        selected.append(ref)
                        seen.add(ref)
        wrappers.append({"factory_parameter": name, "raw_stream_ordinal": array["ordinal"],
                         "raw_slots": len(values), "positive_materialized_keys_at_boundary": 0,
                         "metadata": {"-1": f"raw_stream_{array['ordinal']}", "-2": "shared_cache"},
                         "directory_in_bounds_slots": len(valid), "potential_tag_histogram": histogram,
                         "first_reference_uses": valid[:12],
                         "caution": "Slots are not proven constants or executed references"})
    tag_map = []
    for tag in range(256):
        leaf, path = tag_path(tag)
        tag_map.append({"tag": tag, "leaf_state": leaf,
                        "reader": PRIMITIVES[leaf][2] if leaf in PRIMITIVES else LEAVES[leaf]})
    report = {"source_sha256": analyzer.SOURCE_SHA, "data_sha256": analyzer.DATA_SHA,
              "record_id": record_id, "method": "pinned source predicates + explicit bounded Python data readers",
              "network_requests": 0, "lua_executed": False, "index_metamethod_invocations": 0,
              "factory_invocations": 0, "opcode_executions": 0, "buffer_writes": 0,
              "source_evidence": anchors, "wrappers": wrappers,
              "cache": {"shared_initially_empty": True, "wrapper_store": "u[f]=n",
                        "shared_string_store": "WJ[n]=j", "probe_semantics": "Lua truthy check; not key-presence test",
                        "mutated_by_this_tool": False},
              "tag_map": tag_map,
              "sampled_potential_references": [inspect_reference(sliced, loader["lookup_entries"], ref) for ref in selected],
              "leading_descriptors": {
                  "word_count": struct.unpack_from("<I", plain, 3)[0], "count_range": [3, 7],
                  "root_factory_binding": "argument12 is shadowed by later duplicate formal B in factory4890",
                  "triplet_producer": "lazy state69 writes three fields; state156 allocates3*n",
                  "HW_consumer": {"stride": 3, "kind_3": "{[5]=B,[6]=h[B]}",
                                  "kind_0": "h[B][B]", "kind_1": "j[B]"},
                  "conclusion": "capture-like triplet consumer exists; direct edge from root leading list to HW not established",
                  "verified_upvalue_count": None},
              "tail": tail_descriptor(plain, layout["reader_end"], begin, len(sliced)),
              "limits": "No reachable constant count or complete child-prototype graph inferred. Compound readers remain unresolved. No OS air gap asserted; this tool has no network API."}
    output.mkdir(parents=True, exist_ok=True)
    target = output / "lazy-analysis.json"
    if target.resolve() in {source_path.resolve(), data_path.resolve()}:
        raise ValueError("Output aliases input")
    target.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return report


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--source", type=Path, default=Path("output/stage1-vm-source.lua.txt"))
    cli.add_argument("--data", type=Path, default=Path("output/stage1-vm-data.bin"))
    cli.add_argument("--output", type=Path, default=Path("output/phase7"))
    cli.add_argument("--sample-limit", type=int, default=64)
    args = cli.parse_args()
    try:
        report = run(args.source, args.data, args.output, args.sample_limit)
    except (ValueError, OSError, IndexError, KeyError, struct.error) as failure:
        print(f"Lazy metadata analysis failed: {failure}", file=sys.stderr)
        return 1
    print(f"Root664: {len(report['wrappers'])} wrappers; {len(report['sampled_potential_references'])} potential references sampled")
    print(f"Tail: {report['tail']}")
    print("No Lua, __index, factory, opcode, network or buffer-write operation invoked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
