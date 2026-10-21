"""Bounded source-derived GW data-reader alignment; no Lua/payload execution.

Only numeric/table/read primitives are modeled. Unknown function factories and
all lazy metatable calls are hard stops, never invoked.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

import analyzer
from gw_reader_model import HELPERS, Boundary, ModelError, Opaque, Parser, ReaderModel, Table
from reader_tracer import custom_uint, decrypt_record, header_checks, parse_loader, source_evidence


def definitions(source: str) -> tuple[dict, dict]:
    structure, _ = analyzer.source_structure(analyzer.lex(source), source)
    fields = {}
    for field in structure["field_candidates"]:
        # Named locals inside application code can produce later lexical candidates.
        # Pin to the first definition, then parse and enforce the reader subset.
        fields.setdefault(field["key"], field)
    result, manifest = {}, {}
    for key in sorted(HELPERS):
        field = fields[key]
        parser = Parser(source[field["offset"]:field["candidate_interval_end"]], field["offset"])
        result[key] = parser.definition(key)
        manifest[key] = {"offset": field["offset"], "parameters": result[key][0]}
    for slot, api in ((8, "buffer.readu32"), (46, "buffer.readu8"), (34, "table.create"), (97, "setmetatable")):
        if f"[{slot}]={api}" not in source: raise ModelError("Reader API alias mismatch")
    return result, manifest


def table_summary(value):
    if isinstance(value, Opaque): return {"type": "opaque_unexecuted_metadata", "label": value.label}
    if isinstance(value, Table):
        positive = {key: item for key, item in value.data.items() if isinstance(key, int) and key >= 1}
        integer_values = [item for item in positive.values() if isinstance(item, int) and not isinstance(item, bool)]
        return {"table_id": value.id, "capacity_hint": value.capacity_hint,
                "positive_key_count": len(positive), "metadata_keys": [str(k) for k in value.data if k not in positive],
                "created_at_source_offset": value.created_at, "created_after_read_offset": value.created_after_read,
                "first_value_read_end": value.first_value_read_end, "last_value_read_end": value.last_value_read_end,
                "integer_range": [min(integer_values), max(integer_values)] if integer_values else None,
                "metatable_metadata_present": value.metatable is not None}
    if isinstance(value, bytes): return {"type": "bytes", "length": len(value)}
    if isinstance(value, (int, float, str, bool)) or value is None: return value
    return {"type": "reader_receiver"}


def factory_bindings(source, slot, args):
    match = re.search(r'\[' + str(slot) + r'\]=function\(([^)]*)\)', source)
    if not match: return {"status": "factory_formals_not_found"}
    names = match[1].split(",")
    actual = {name: args[index] if index < len(args) else None for index, name in enumerate(names)}
    report = {"slot": slot, "formal_parameters_including_duplicates": names,
              "effective_bindings": {key: table_summary(value) for key, value in actual.items()}}
    if slot == 4890:
        factory = source[match.start():match.start() + 2000]
        for fragment in ("local xJ=A[W]", "W,h=S,o", "local y,t=W[2],D(h)"):
            if fragment not in factory: raise ModelError("Interpreter-role evidence mismatch")
        report["source_supported_roles"] = {
            "opcode_slot_array_parameter": "A", "opcode_slots": table_summary(actual.get("A")),
            "entry_pc_parameter": "S", "entry_pc": actual.get("S"),
            "dispatch_variant_parameter": "o", "dispatch_variant": actual.get("o"),
            "register_allocation_parameter": "h", "register_capacity": actual.get("h"),
            "other_raw_arrays": {key: table_summary(actual.get(key)) for key in ("i", "H", "w")},
            "lazy_reference_wrappers": {key: table_summary(actual.get(key)) for key in ("j", "O", "Z", "B")},
        }
    return report


def initial_header(plain):
    """Independent prefix cross-check, not a universal record parser."""
    if not plain: raise ModelError("Record empty")
    if plain[0] != 0:
        return {"format_byte_offset": 0, "format_byte": plain[0],
                "layout": "alternate_or_unvalidated_GW_path; no primary header interpretation"}
    if len(plain) < 8:
        return {"format_byte": 0, "layout": "truncated_primary_header"}
    selector, cursor = custom_uint(plain, 1)
    if cursor + 4 > len(plain): raise ModelError("Leading descriptor count out of bounds")
    descriptor_count = struct.unpack_from("<I", plain, cursor)[0]
    count_offset = cursor; cursor += 4
    result = {"format_byte_offset": 0, "format_byte": plain[0], "dispatch_selector": selector,
              "leading_descriptor_word_count": descriptor_count, "leading_count_offset": count_offset,
              "upvalue_meaning": "unverified; descriptor words must not be relabeled upvalues yet"}
    if plain[0] == 0 and descriptor_count == 0:
        slot, cursor = custom_uint(plain, cursor)
        key_count, cursor = custom_uint(plain, cursor)
        if key_count > 100000 or cursor + key_count * 4 > len(plain): raise ModelError("Header u32 list out of bounds")
        result.update(factory_slot=slot, u32_seed_or_parameter_word_count=key_count,
                      u32_words_offset=cursor, first_raw_array_count_offset=cursor + 4 * key_count)
    return result


def normalized_primary_layout(plain):
    """Independent translation of the observed format0/count0 sequence.

    Refuse other variants instead of guessing an eager constant/prototype table.
    """
    header = initial_header(plain)
    if header.get("format_byte") != 0 or header.get("leading_descriptor_word_count") != 0:
        return {"status": "unsupported_variant_not_guessed"}
    cursor = header["first_raw_array_count_offset"]
    arrays = []
    scalar = register_capacity = None
    for index in range(4):
        count_offset = cursor
        encoded, cursor = custom_uint(plain, cursor)
        count = encoded - 20231
        if not 0 <= count <= 100000: raise ModelError("Biased array count out of bounds")
        values_start = cursor
        for _ in range(count): _, cursor = custom_uint(plain, cursor)
        arrays.append({"ordinal": index + 1, "count_offset": count_offset, "encoded_count": encoded,
                       "bias": 20231, "slots": count, "values_start": values_start, "values_end": cursor})
        if index == 0:
            scalar_start = cursor
            scalar, cursor = custom_uint(plain, cursor)
            register_start = cursor
            register_capacity, cursor = custom_uint(plain, cursor)
    entry_start = cursor
    entry_pc, cursor = custom_uint(plain, cursor)
    return {"status": "normalized_primary_sequence_parsed",
            "arrays": arrays, "unclassified_scalar": {"offset": scalar_start, "value": scalar},
            "register_capacity": {"offset": register_start, "value": register_capacity},
            "entry_pc": {"offset": entry_start, "value": entry_pc}, "reader_end": cursor,
            "unread_tail_bytes": len(plain) - cursor}


def inspect_record(source, data, loader, defs, record_id, auxiliary):
    if not 1 <= record_id <= loader["lookup_count"]: raise ModelError("Record ID outside lookup table")
    value = loader["lookup_entries"][record_id - 1]["value"]
    sliced = data[loader["slice_offset"]:loader["slice_end"]]
    report = {"id": record_id, "auxiliary": auxiliary,
              "selection": "loader-selected root" if record_id == loader["selected_id"] else "explicit structural-comparison ID; runtime reachability unproven"}
    if not 0 <= value + 1 < len(sliced):
        return {**report, "status": "opaque_lookup_reference_not_followed", "lookup_value": value}, None
    length, start = custom_uint(sliced, value + 1)
    if not 0 < length <= len(sliced) - start: return {**report, "status": "record_bounds_not_validated", "length": length}, None
    plain, crypto = decrypt_record(sliced[start:start + length], record_id, auxiliary)
    model = ReaderModel(defs)
    context, directory = model.table(), model.table()
    directory.data = {row["index_1_based"]: row["value"] for row in loader["lookup_entries"]}
    # v establishes w[6] before handing the buffer to GW. Retain its existence
    # without constructing or invoking its __index decoder.
    context.data = {4: sliced, 5: directory, 6: Opaque("v lazy __index metatable"), 7: loader["flag_byte"] != 0}
    boundary = None
    try:
        result = model.function("GW", [model, context, plain])
        report.update(status="reader_returned_without_factory", result=[table_summary(v) for v in result])
    except Boundary as stop:
        boundary = stop
        report.update(status="stopped_before_function_factory_or_lazy_read", stop_reason=stop.reason,
                      stopped_at_source_offset=stop.offset, factory_slot=stop.slot,
                      factory=factory_bindings(source, stop.slot, stop.arguments or []) if isinstance(stop.slot, int) else None)
    except (ModelError, TypeError, ZeroDivisionError, KeyError) as failure:
        report.update(status="reader_model_stopped_unresolved", stop_reason=f"{type(failure).__name__}: {failure}")
    consumed = max((read["offset"] + read["width"] for read in model.reads), default=0)
    covered = bytearray(length)
    for read in model.reads: covered[read["offset"]:read["offset"] + read["width"]] = b"\1" * read["width"]
    report.update(record_input_offset=loader["slice_offset"] + start, record_bytes=length,
                  plaintext_sha256=hashlib.sha256(plain).hexdigest(), header_checks=header_checks(plain),
                  initial_header=initial_header(plain), seed=crypto["initial_state"], submask_hex=crypto["submask_hex"],
                  reader_steps=model.steps, bytes_read_through=consumed, unread_tail_bytes=length - consumed,
                  distinct_bytes_read=sum(covered), contiguous_coverage_to_cursor=all(covered[:consumed]),
                  tables=[table_summary(table) for table in model.tables[2:]],
                  helper_calls=model.calls, first_buffer_reads=model.reads[:20],
                  constant_count="not_an_eager_flat_table; lazy reference wrappers retained without evaluation",
                  child_prototype_count="unresolved; lookup count is not a verified prototype count",
                  upvalue_list="leading descriptor data observed, semantics not verified",
                  native_instruction_byte_width="not applicable to these custom virtual arrays",
                  decoded_vm_instructions_executed=0)
    if boundary is not None and boundary.slot == 4890:
        report["header_crosscheck"] = report["initial_header"].get("factory_slot") == boundary.slot
        normalized = normalized_primary_layout(plain)
        report["normalized_layout"] = normalized
        if normalized["status"] == "normalized_primary_sequence_parsed":
            roles = report["factory"]["source_supported_roles"]
            streams = [roles["other_raw_arrays"]["i"], roles["opcode_slots"], roles["other_raw_arrays"]["H"], roles["other_raw_arrays"]["w"]]
            aligned = (normalized["reader_end"] == consumed and normalized["register_capacity"]["value"] == roles["register_capacity"]
                and normalized["entry_pc"]["value"] == roles["entry_pc"]
                and all(array["slots"] == stream["positive_key_count"] and array["values_start"] == stream["created_after_read_offset"]
                        and array["values_end"] == stream["last_value_read_end"] for array, stream in zip(normalized["arrays"], streams)))
            if not aligned: raise ModelError("Independent normalized reader disagrees with GW IR")
            report["normalized_reader_crosscheck"] = "counts_ranges_pc_register_size_and_cursor_match"
            report["virtual_function_header"] = {
                "format": "custom_GW_constructor_not_native_Luau_header", "factory_slot": boundary.slot,
                "dispatch_variant": roles["dispatch_variant"], "entry_pc": roles["entry_pc"],
                "register_capacity": roles["register_capacity"], "opcode_array_slots": roles["opcode_slots"]["positive_key_count"],
                "instruction_width_bytes": None, "eager_constant_count": None,
                "child_prototype_count": None, "verified_upvalue_count": None}
    artifacts = {"plaintext": plain,
                 "tables": [{"id": t.id, "capacity_hint": t.capacity_hint,
                    "entries": [{"key": k, "value": table_summary(v)} for k, v in t.data.items()]} for t in model.tables[2:]],
                 "buffer_reads": model.reads}
    return report, artifacts


def run(source_path, data_path, output, record_ids):
    source_bytes, data = analyzer.bounded_read(source_path), analyzer.bounded_read(data_path)
    if hashlib.sha256(source_bytes).hexdigest() != analyzer.SOURCE_SHA or hashlib.sha256(data).hexdigest() != analyzer.DATA_SHA:
        raise ModelError("Unknown g/d snapshot")
    if not 1 <= len(record_ids) <= 4 or len(set(record_ids)) != len(record_ids): raise ModelError("Select one to four distinct IDs")
    source = source_bytes.decode("ascii")
    evidence = source_evidence(source)
    # Both syntactically identified v entry paths pass91; no missing-argument guess.
    if ("H(x,WJ,n,91)" not in source or "local j,O,o,S,A,B,H,i,Z" not in source
            or "x[74],x.W,x[20],x.v,x[85]" not in source): raise ModelError("Recursive callsite evidence missing")
    if "w[6]=h;y,P=12,h;" not in source: raise ModelError("Lazy-reader metadata setup anchor missing")
    auxiliary = evidence["root_auxiliary_byte"]
    defs, manifest = definitions(source)
    loader = parse_loader(data)
    report = {"source_sha256": analyzer.SOURCE_SHA, "data_sha256": analyzer.DATA_SHA,
              "network_used": False, "lua_executed": False, "vm_opcodes_executed": 0,
              "method": "bounded numeric/table reader IR; API whitelist readu8/readu32/table.create; metatables metadata-only; factory calls blocked",
              "helper_definitions": manifest,
              "auxiliary_scope": "91 is observed at root and recursive v callsites in this snapshot; not an assertion about all possible records/snapshots",
              "v_callsite_evidence": [{"offset": source.index("x:v(h,S,91)"), "kind": "root", "auxiliary": 91},
                                      {"offset": source.index("H(x,WJ,n,91)"), "kind": "recursive_alias_H", "auxiliary": 91}],
              "seed_rule": "(record_id+auxiliary)%256; depends on ID modulo256, not necessarily unique; auxiliary mask stays constant only within the observed91 callsite family",
              "GW_name": "reader method in g; not evidence of a separate global-data buffer",
              "records": [],
              "limits": "No opcode mapping/execution, lazy constant evaluation or unreviewed function factory calls. Unread bytes and unresolved field meanings remain explicit."}
    output.mkdir(parents=True, exist_ok=True)
    if (output / "gw-alignment.json").resolve() in {source_path.resolve(), data_path.resolve()}: raise ModelError("Output aliases input")
    for record_id in record_ids:
        item, artifacts = inspect_record(source, data, loader, defs, record_id, auxiliary)
        report["records"].append(item)
        if artifacts:
            paths = [output / f"record-{record_id}.transformed.bin", output / f"record-{record_id}.reader-data.json"]
            if any(path.resolve() in {source_path.resolve(), data_path.resolve()} for path in paths): raise ModelError("Output aliases input")
            paths[0].write_bytes(artifacts.pop("plaintext"))
            paths[1].write_text(json.dumps(artifacts, indent=2) + "\n", encoding="utf-8")
    (output / "gw-alignment.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--source", type=Path, default=Path("output/stage1-vm-source.lua.txt"))
    cli.add_argument("--data", type=Path, default=Path("output/stage1-vm-data.bin"))
    cli.add_argument("--output", type=Path, default=Path("output/phase6"))
    cli.add_argument("--record-ids", default="664,1,2")
    args = cli.parse_args()
    try: report = run(args.source, args.data, args.output, [int(i) for i in args.record_ids.split(",")])
    except (ValueError, OSError, KeyError) as failure:
        print(f"GW alignment failed: {failure}", file=sys.stderr); return 1
    for record in report["records"]:
        print(f"ID {record['id']}: {record['status']}; factory={record.get('factory_slot')}; read={record.get('bytes_read_through')}/{record.get('record_bytes')}")
    print("No Lua, application callback or VM opcode executed. Lazy constants/prototype counts remain unresolved.")
    return 0


if __name__ == "__main__": raise SystemExit(main())
