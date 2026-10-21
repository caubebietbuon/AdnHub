"""Offline record664 reconstruction with an isolated backing-slice fill copy.

No Lua, factory, metatable, opcode, network API or original-file mutation.
Constants are analysis candidates, not a recovered native bytecode serialization.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

import analyzer
from gw_aligner import normalized_primary_layout
from lazy_tracer import PRIMITIVES, evidence, inspect_reference, tail_descriptor
from reader_tracer import custom_uint, decrypt_record, parse_loader


def sha(data):
    return hashlib.sha256(data).hexdigest()


def apply_fill_copy(backing, start, length, value):
    """One bounded copy; input and transformed plaintext are never overwritten."""
    if any(type(n) is not int for n in (start, length, value)):
        raise ValueError("Fill arguments must be integers")
    if not 0 <= start <= len(backing) or not 0 <= length <= len(backing) - start:
        raise ValueError("Fill outside backing slice")
    if not 0 <= value <= 255:
        raise ValueError("Fill byte outside range")
    result = bytearray(backing)
    result[start:start + length] = bytes([value]) * length
    return bytes(result)


def record_probe(backing, entries, record_id):
    """Bounded format probe, not general validation of a function record."""
    if type(record_id) is not int or not 1 <= record_id <= len(entries):
        return {"id": record_id, "status": "id_outside_directory"}, None, None
    position = entries[record_id - 1]["value"]
    if not 0 <= position < len(backing) - 1:
        return {"id": record_id, "status": "opaque_directory_value"}, None, None
    try:
        length, begin = custom_uint(backing, position + 1)
    except (ValueError, IndexError):
        return {"id": record_id, "status": "truncated_length"}, None, None
    if not 0 < length <= len(backing) - begin:
        return {"id": record_id, "status": "record_bounds_not_validated", "length": length}, None, None
    plain, _ = decrypt_record(backing[begin:begin + length], record_id, 91)
    result = {"id": record_id, "bytes": length, "format_byte": plain[0],
              "auxiliary_assumption": "91 only for the reviewed v call family"}
    if record_id != 664:
        return {**result, "status": "unvalidated_record_not_reconstructed"}, None, None
    return {**result, "status": "reviewed_root_layout"}, plain, begin


def observation_span(item, backing):
    """Known byte dependencies only; compound-reader extents remain unknown."""
    start = item.get("slice_offset")
    if start is None:
        return None
    leaf = item.get("leaf_state")
    if leaf in PRIMITIVES:
        return start, start + 1 + struct.calcsize(PRIMITIVES[leaf][1])
    if item["status"] == "explicit_python_raw_string_reader":
        size, begin = custom_uint(backing, start + 1)
        return start, begin + size
    return None


def materialize_candidates(backing, postfill, entries, streams, fill_range):
    """Static candidate index. Never impersonates an actual populated Lua cache."""
    ids = sorted({ref for values in streams.values() for ref in values if 1 <= ref <= len(entries)})
    observations, constants, prototype_refs, unresolved = [], [], [], []
    for ref in ids:
        try:
            before = inspect_reference(backing, entries, ref)
            after = inspect_reference(postfill, entries, ref)
        except (ValueError, IndexError, struct.error) as failure:
            unresolved.append({"reference_id": ref, "status": "bounded_reader_failure", "reason": str(failure)})
            continue
        span = observation_span(before, backing)
        overlaps = None if span is None else span[0] < fill_range[1] and fill_range[0] < span[1]
        row = {"reference_id": ref, "before_fill": before, "after_fill": after,
               "known_input_range": span, "overlaps_fill": overlaps,
               "observation_changed": before != after}
        observations.append(row)
        if overlaps is False and before == after and before["status"] in (
                "explicit_python_primitive_reader", "explicit_python_raw_string_reader"):
            category = "string" if "length" in before else "boolean" if before["kind"] == "boolean_not_206" else "number"
            constants.append({"reference_id": ref, "category": category, "observation": after,
                              "verification": "source-reader-compatible candidate; runtime use unproven"})
        elif before.get("leaf_state") == 24:
            prototype_refs.append({"reference_id": ref, "status": "unresolved_function_reference",
                                   "postfill_tag": after.get("tag"), "factory_invoked": False})
        else:
            unresolved.append({"reference_id": ref, "status": before["status"],
                               "overlaps_fill": overlaps,
                               "reason": "overwritten input" if overlaps else "unresolved extent, reader or record semantics"})
    constant_ids = {c["reference_id"] for c in constants}
    uses = {name: [{"index_1_based": index, "candidate_reference_id": ref}
                   for index, ref in enumerate(values, 1) if ref in constant_ids]
            for name, values in streams.items()}
    return {"observations": observations, "candidate_constants": constants,
            "candidate_wrapper_materializations": uses,
            "shared_cache": {"actual_initial_entries": {},
                             "note": "Phase7 observations do not populate runtime -2; numeric leaves only store in individual wrappers",
                             "runtime_access_order": "unknown; no runtime cache state fabricated"},
            "prototype_mapping": {"root": 664, "unresolved_function_references": prototype_refs,
                                  "verified_child_hierarchy": None},
            "unresolved": unresolved}


def run(source_path, data_path, output, record_ids):
    if not record_ids or len(record_ids) > 8 or len(set(record_ids)) != len(record_ids):
        raise ValueError("Select1..8 distinct record IDs")
    source, data = analyzer.bounded_read(source_path), analyzer.bounded_read(data_path)
    if sha(source) != analyzer.SOURCE_SHA or sha(data) != analyzer.DATA_SHA:
        raise ValueError("Unknown g/d snapshot")
    evidence(source.decode("ascii"))
    loader = parse_loader(data)
    backing = data[loader["slice_offset"]:loader["slice_end"]]
    report = {"source_sha256": sha(source), "data_sha256": sha(data), "records": [],
              "lua_executed": False, "factory_invocations": 0, "index_invocations": 0,
              "opcode_executions": 0, "network_requests": 0,
              "limits": "No native Luau serialization, complete constants, reachable child hierarchy or OS-enforced air gap claimed"}
    artifacts = {}
    for record_id in record_ids:
        item, plain, begin = record_probe(backing, loader["lookup_entries"], record_id)
        report["records"].append(item)
        if plain is None:
            continue
        layout = normalized_primary_layout(plain)
        if layout.get("status") != "normalized_primary_sequence_parsed":
            raise ValueError("Reviewed root layout mismatch")
        footer = tail_descriptor(plain, layout["reader_end"], begin, len(backing))
        start, end = footer["backing_slice_range"]
        postfill = apply_fill_copy(backing, start, end - start, footer["fill_byte"])
        footer["meaning"] = "post-GW source-buffer fill directive applied to isolated backing copy"
        streams = {}
        for name, array in zip(("j", "O", "Z", "B"), layout["arrays"]):
            cursor, values = array["values_start"], []
            for _ in range(array["slots"]):
                value, cursor = custom_uint(plain, cursor)
                values.append(value)
            if cursor != array["values_end"]:
                raise ValueError("Raw stream range mismatch")
            streams[name] = values
        mapping = materialize_candidates(backing, postfill, loader["lookup_entries"], streams, (start, end))
        item.update(layout=layout, footer=footer, transformed_sha256=sha(plain),
                    prefill_backing_sha256=sha(backing), postfill_backing_sha256=sha(postfill),
                    transformed_bytes_preserved=True, fully_materialized=False,
                    fill_changed_bytes=sum(a != b for a, b in zip(backing, postfill)),
                    distinct_observations=len(mapping["observations"]),
                    primitive_observations_before_fill=sum(o["before_fill"]["status"] == "explicit_python_primitive_reader" for o in mapping["observations"]),
                    eligible_constant_candidates=len(mapping["candidate_constants"]),
                    observations_changed_after_fill=sum(o["observation_changed"] for o in mapping["observations"]),
                    unresolved_references=len(mapping["unresolved"]),
                    verified_child_hierarchy=None,
                    type_check="custom reader kinds compatible with number/boolean/string value categories; not native Luau constant tags")
        artifacts.update({"record-664.transformed.bin": plain, "record-664.backing-postfill.bin": postfill,
                          "record-664.streams.json": streams, "record-664.mapping.json": mapping})
    report["artifacts_this_run"] = list(artifacts) + ["reconstruction.json"]
    artifacts["reconstruction.json"] = report
    # Validate every destination before publishing any artifact.
    inputs = {source_path.resolve(), data_path.resolve()}
    if any((output / name).resolve() in inputs for name in artifacts):
        raise ValueError("Output aliases input")
    output.mkdir(parents=True, exist_ok=True)
    for name, value in artifacts.items():
        path = output / name
        if isinstance(value, bytes):
            path.write_bytes(value)
        else:
            path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return report


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--source", type=Path, default=Path("output/stage1-vm-source.lua.txt"))
    cli.add_argument("--data", type=Path, default=Path("output/stage1-vm-data.bin"))
    cli.add_argument("--output", type=Path, default=Path("output/phase8"))
    cli.add_argument("--record-ids", default="664,1,2")
    args = cli.parse_args()
    try:
        report = run(args.source, args.data, args.output, [int(n) for n in args.record_ids.split(",")])
    except (ValueError, OSError, IndexError, KeyError, struct.error) as failure:
        print(f"Reconstruction failed: {failure}", file=sys.stderr)
        return 1
    for item in report["records"]:
        print(f"ID{item['id']}: {item['status']}; candidates={item.get('eligible_constant_candidates')}")
    print("Backing fill applied to a copy only; no Lua, factory, __index, opcode or network calls.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
