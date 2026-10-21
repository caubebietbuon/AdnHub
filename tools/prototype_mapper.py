"""Offline descriptor parsing, conditional function links and static synthesis.

No Lua, factory, __index, opcode execution, network API or original-input writes.
"""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import sys
import tempfile

import analyzer
from lazy_tracer import tag_path
from reader_tracer import custom_uint, decrypt_record, parse_loader
import reconstructor
import string_resolver

DIRECTORY_MASK = 306486104
CAPTURE_KINDS = {0: "register_value", 1: "enclosing_capture", 2: "register_span", 3: "register_cell"}


def parse_descriptors(raw, max_count=100000):
    """Translate states172/39/156/87/0/63/79/69 as bounded data reads."""
    count, cursor = custom_uint(raw, 0)
    if not 0 <= count <= max_count or count > len(raw) - cursor:
        raise ValueError("Descriptor count exceeds remaining bytes or limit")
    items = []
    for index in range(count):
        start = cursor
        packed, cursor = custom_uint(raw, cursor)
        kind, target = packed & 3, packed >> 2
        first = 7030
        if kind == 2:
            extra, cursor = custom_uint(raw, cursor)
            first = extra + 1
        items.append({"ordinal": index + 1, "encoded_range": [start, cursor],
                      "packed_word": packed, "triplet": [first, target, kind],
                      "kind": kind, "capture_category": CAPTURE_KINDS[kind], "target_index": target,
                      "span_length": first if kind == 2 else None,
                      "prototype_id": None})
    if cursor != len(raw):
        raise ValueError("Trailing descriptor bytes: schema not accepted")
    return {"count": count, "reader_end": cursor, "bytes": len(raw), "captures": items,
            "status": "fully_parsed_triplet_encoding; owner_binding_unverified"}


def source_evidence(source):
    anchors = ["local zJ,EJ,QJ=j(3,bJ),O(bJ,2),7030;",
               "if zJ~=2 then p,bJ,hJ,wJ=69,zJ,EJ,QJ;else p,bJ,hJ=63,zJ,EJ;end;",
               "n[1+WJ]=wJ;n[WJ+3]=bJ;n[2+WJ]=hJ;", "local j=1+wJ;p,wJ=69,j;",
               "local bJ=Z[W];if bJ then local hJ=#bJ/3;",
               "WJ[OJ]=t[SJ]", "WJ[OJ]=g[SJ]", "AJ={[6]=t,[5]=SJ}",
               "oJ={[6]=t,[4]=bJ[hJ+1],[5]=SJ}", "t[i[W]]=B[W](WJ,nil,nil)",
               "local wJ=_(hJ[WJ],306486104);hJ[WJ]=wJ;hJ,WJ=b[4],wJ+1;",
               "WJ,wJ=bJ*16843009,OJ+jJ;", "M(hJ,jJ,(_(r(hJ,jJ),WJ)))"]
    return [{"offset": source.index(text), "text": text} for text in anchors]


def conditional_links(backing, entries, streams, parent=664):
    """Directory-mask hypotheses have explicit guards; never simulate opcodes."""
    uses = collections.defaultdict(list)
    for wrapper, values in streams.items():
        for index, ref in enumerate(values, 1):
            if 1 <= ref <= len(entries):
                uses[ref].append({"wrapper": wrapper, "index_1_based": index})
    functions, strings, rejected = [], [], []
    for ref, references in sorted(uses.items()):
        original = entries[ref - 1]["value"]
        if 0 <= original < len(backing):
            position, guard = original, "direct directory offset; use/reachability unproven"
        else:
            position, guard = original ^ DIRECTORY_MASK, "requires source directory-unmask operation for this ID; execution not established"
        if not 0 <= position < len(backing):
            rejected.append({"reference_id": ref, "status": "offset_not_validated_after_xor"})
            continue
        leaf, _ = tag_path(backing[position])
        if original != position and leaf == 98:
            strings.append({"reference_id": ref, "candidate_offset": position, "guard": guard,
                            "status": "conditional_string_target; additional_payload_mask_unresolved"})
        if leaf != 24:
            continue
        try:
            length, begin = custom_uint(backing, position + 1)
            if not 0 < length <= len(backing) - begin:
                raise ValueError("Function payload outside backing")
        except (ValueError, IndexError) as failure:
            rejected.append({"reference_id": ref, "status": "function_bounds_rejected", "reason": str(failure)})
            continue
        functions.append({"parent_candidate": parent, "function_reference_id": ref,
                          "original_directory_value": original, "candidate_offset": position,
                          "tag": backing[position], "payload_bytes": length,
                          "payload_sha256": hashlib.sha256(backing[begin:begin + length]).hexdigest(),
                          "root_stream_uses": references, "guard": guard,
                          "relation": "conditional function-reference edge; lexical ownership unverified",
                          "status": "payload_mask_and_child_header_unresolved",
                          "factory_invoked": False})
    return {"root": parent, "conditional_function_edges": functions,
            "conditional_string_targets": strings, "rejected": rejected,
            "verified_parent_child_edges": [], "verified_hierarchy": None,
            "complete": False,
            "limitation": "Directory XOR is source-supported, but opcode reachability, payload mask and lexical ownership are not established"}


def run(source_path, data_path, output):
    source_bytes, data = analyzer.bounded_read(source_path), analyzer.bounded_read(data_path)
    if hashlib.sha256(source_bytes).hexdigest() != analyzer.SOURCE_SHA or hashlib.sha256(data).hexdigest() != analyzer.DATA_SHA:
        raise ValueError("Unknown g/d snapshot")
    anchors = source_evidence(source_bytes.decode("ascii"))
    # Recompute previous phases from pinned inputs; generated JSON is not trusted input.
    with tempfile.TemporaryDirectory() as temp:
        staging = Path(temp)
        base = reconstructor.run(source_path, data_path, staging / "base", [664, 1, 2])
        resolved = string_resolver.run(source_path, data_path, staging / "strings")
        mapping = json.loads((staging / "base/record-664.mapping.json").read_text())
        streams = json.loads((staging / "base/record-664.streams.json").read_text())
        backing = (staging / "base/record-664.backing-postfill.bin").read_bytes()
    loader = parse_loader(data)
    descriptors, failures = [], []
    for header in resolved["descriptor_headers"]:
        ref = header["reference_id"]
        position = loader["lookup_entries"][ref - 1]["value"]
        try:
            encoded, _ = string_resolver.read_length_payload(backing, position)
            raw, _ = decrypt_record(encoded, ref, 83)
            descriptors.append({"reference_id": ref, **parse_descriptors(raw)})
        except (ValueError, IndexError) as failure:
            failures.append({"reference_id": ref, "reason": str(failure)})
    links = conditional_links(backing, loader["lookup_entries"], streams)
    root = base["records"][0]
    report = {"schema_version": 1, "source_sha256": analyzer.SOURCE_SHA, "data_sha256": analyzer.DATA_SHA,
              "method": "bounded Python data readers and guarded source cross-references; no opcode dispatch",
              "root": {"record_id": 664, "factory_slot": 4890,
                       "register_capacity": root["layout"]["register_capacity"]["value"],
                       "entry_pc": root["layout"]["entry_pc"]["value"],
                       "transformed_sha256": root["transformed_sha256"]},
              "constant_candidates": {"primitives": mapping["candidate_constants"], "strings": resolved["strings"],
                                      "runtime_reachability": "unproven; not a native Luau serialized constant pool"},
              "wrapper_uses": {"primitives": mapping["candidate_wrapper_materializations"],
                               "strings": resolved["wrapper_string_uses"]},
              "descriptors": descriptors, "descriptor_failures": failures,
              "prototype_mapping": links, "remaining_phase9_references": resolved["unresolved"],
              "comparison_records": base["records"][1:], "source_evidence": anchors,
              "cache": resolved["cache"], "lua_executed": False, "factory_invocations": 0,
              "index_invocations": 0, "opcode_executions": 0, "network_requests": 0,
              "limits": "Final synthesis of recovered static evidence, not complete deobfuscation or a verified lexical prototype tree. No OS air gap asserted."}
    target = output / "static-synthesis.json"
    if target.resolve() in {source_path.resolve(), data_path.resolve()}: raise ValueError("Output aliases input")
    output.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return report


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--source", type=Path, default=Path("output/stage1-vm-source.lua.txt"))
    cli.add_argument("--data", type=Path, default=Path("output/stage1-vm-data.bin"))
    cli.add_argument("--output", type=Path, default=Path("output/phase10"))
    args = cli.parse_args()
    try:
        result = run(args.source, args.data, args.output)
    except (ValueError, OSError, IndexError, KeyError) as failure:
        print(f"Prototype synthesis failed: {failure}", file=sys.stderr)
        return 1
    print(f"Descriptors: {len(result['descriptors'])}; conditional function edges: {len(result['prototype_mapping']['conditional_function_edges'])}")
    print("No Lua, factory, __index, opcode or network execution; lexical hierarchy remains unverified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
