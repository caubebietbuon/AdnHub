"""Source-derived, bounded reader translation for one audited g/d snapshot.

This executes Python byte/arithmetic operations only, not Lua or VM opcodes.
It decodes the selected record prefix, not every record/constant in d.
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
from decryption_finder import mask_tables
from state_separator import trim_region

OW, VW = mask_tables(61, 123)


def custom_uint(data: bytes, cursor: int) -> tuple[int, int]:
    """CW reader: 1..4 bytes, with PERMUTED significance, not generic ULEB128."""
    def at(relative: int) -> int:
        if not 0 <= cursor + relative < len(data): raise ValueError("Truncated custom integer")
        return data[cursor + relative]
    a = at(0)
    if a < 128: return a, cursor + 1
    b = at(1)
    if b < 128: return a - 128 + 128 * b, cursor + 2
    c = at(2)
    if c < 128: return a - 128 + 16384 * (b - 128) + 128 * c, cursor + 3
    d = at(3)
    value = ((a - 128) * 2097152 + (b - 128) + (c - 128) * 16384
             + (d % 128) * 128 + (d - d % 128) * 2097152)
    return value, cursor + 4


def parse_loader(data: bytes) -> dict:
    """Normalize CW's initial data reader up to sW; no closure invocation."""
    encoded_count, cursor = custom_uint(data, 0)
    count = encoded_count - 94747
    if not 1 <= count <= 4096 or cursor >= len(data): raise ValueError("Invalid loader count")
    flag_offset = cursor
    flag = data[cursor]; cursor += 1
    selected_id_offset = cursor
    selected_id, cursor = custom_uint(data, cursor)
    if not 1 <= selected_id <= count: raise ValueError("Selected lookup index out of bounds")
    entries = []
    for index in range(1, count + 1):
        start = cursor
        value, cursor = custom_uint(data, cursor)
        entries.append({"index_1_based": index, "input_offset": start, "end_offset": cursor, "value": value})
    length_offset = cursor
    slice_length, cursor = custom_uint(data, cursor)
    if not 0 < slice_length <= len(data) - cursor: raise ValueError("Loader slice exceeds input")
    selected_value = entries[selected_id - 1]["value"]
    # wW starts at b[5][selected]+1. The skipped byte's meaning is unproven.
    record_header = selected_value + 1
    sliced = data[cursor:cursor + slice_length]
    if not 0 <= selected_value < record_header < len(sliced): raise ValueError("Selected lookup target is not in slice")
    record_length, encrypted_start = custom_uint(sliced, record_header)
    if not 64 <= record_length <= len(sliced) - encrypted_start: raise ValueError("Selected record length exceeds slice")
    return {"encoded_count": encoded_count, "count_bias": 94747, "lookup_count": count,
            "flag_offset": flag_offset, "flag_byte": flag, "selected_id_offset": selected_id_offset,
            "selected_id": selected_id, "lookup_entries": entries,
            "slice_length_field_offset": length_offset, "slice_offset": cursor, "slice_length": slice_length,
            "slice_end": cursor + slice_length, "unexamined_bytes_after_slice": len(data) - cursor - slice_length,
            "selected_lookup_value": selected_value, "selected_record_skipped_byte": sliced[selected_value],
            "record_header_slice_offset": record_header, "record_payload_slice_offset": encrypted_start,
            "record_payload_input_offset": cursor + encrypted_start, "record_length": record_length,
            "limitations": "Other lookup values can be encoded references, not necessarily plain in-slice offsets. Skipped-byte meaning and subsequent input sections are unresolved."}


def decrypt_record(ciphertext: bytes, selected_id: int, auxiliary_byte: int) -> tuple[bytes, dict]:
    """Exact rW/zW mask branch for supplied, source-derived record parameters."""
    if not isinstance(selected_id, int) or selected_id < 0 or not 0 <= auxiliary_byte <= 255:
        raise ValueError("Invalid record state")
    state = (selected_id + auxiliary_byte) % 256
    initial_state = state
    submask = auxiliary_byte * 0x01010101
    output = bytearray()
    word_trace, tail_trace = [], []
    aligned = len(ciphertext) - len(ciphertext) % 4
    for offset in range(0, aligned, 4):
        value = struct.unpack_from("<I", ciphertext, offset)[0]
        before = state
        mask = OW[before]
        decoded = value ^ mask ^ submask
        output.extend(struct.pack("<I", decoded))
        state = VW[before]
        # Keep traces bounded even if called with a large record by a future client.
        if len(word_trace) < 16:
            word_trace.append({"relative_offset": offset, "state_before": before,
                               "OW_hex": f"{mask:08x}", "submask_hex": f"{submask:08x}",
                               "input_word_hex": f"{value:08x}", "output_word_hex": f"{decoded:08x}",
                               "state_after": state})
    for offset in range(aligned, len(ciphertext)):
        before = state
        state = (123 + 61 * state) % 256
        decoded = ciphertext[offset] ^ auxiliary_byte ^ state
        output.append(decoded)
        tail_trace.append({"relative_offset": offset, "state_before": before, "state_after": state,
                           "auxiliary_byte": auxiliary_byte, "output_byte": decoded})
    return bytes(output), {"selected_id": selected_id, "auxiliary_byte": auxiliary_byte,
        "initial_state": initial_state, "submask_hex": f"{submask:08x}", "final_state": state,
        "bytes": len(ciphertext), "word_trace_first16": word_trace, "tail_trace": tail_trace,
        "word_trace_truncated": aligned // 4 > 16}


def header_checks(data: bytes) -> dict:
    checks = {"standard_lua_signature": data.startswith(b"\x1bLua"),
              "gzip_signature": data.startswith(b"\x1f\x8b\x08"),
              "xz_signature": data.startswith(b"\xfd7zXZ\x00"),
              "lz4_frame_signature": data.startswith(b"\x04\x22\x4d\x18"),
              "luau_or_luraph_prototype_header": "not_validated_no_universal_header_assumed"}
    return checks


def source_evidence(source: str) -> dict:
    structure, _ = analyzer.source_structure(analyzer.lex(source), source)
    fields = {field["key"]: field for field in structure["field_candidates"]}
    regions = {}
    for name in ("zW", "rW", "v", "wW", "sW", "AW", "xW", "jW", "XW", "CW", "UW", "DW"):
        field = fields[name]
        regions[name] = trim_region(source[field["offset"]:field["candidate_interval_end"]])[0]
    anchors = {
        "word_mask_replication": ("rW", "S*16843009"),
        "initial_seed": ("rW", "(j+S)%256"),
        "loop_coefficients": ("rW", "Z,S,w,o,61,123,R,N,z"),
        "word_xor": ("zW", "x[20](x.OW[W],H,N)"),
        "word_read": ("zW", "x[8](Z,B+O)"),
        "word_next_state": ("zW", "x.VW[W]"),
        "tail_update": ("zW", "(o+W*b)%256"),
        "tail_xor": ("zW", "x[20](i,x[46](Z,S+B),h)"),
        "rW_argument_mapping": ("v", "x:rW(_,w,y,X,e,r,v,P,Y,M,t,J)"),
        "zW_argument_mapping": ("v", "x:zW(e,Y,r,D,y,L,_,v,J,X,M,P,K,t)"),
        "root_auxiliary": ("sW", "x:v(h,S,91)(x.K,nil,nil)"),
        "lookup_and_tag": ("wW", "local h,w=b[5][W],b[4];W=h+1;b=x[46](w,W)"),
        "count_bias": ("XW", "b-94747"),
        "three_byte_permutation": ("xW", "local A,B=j-128,16384*(O-128);local H=128*w+B+A"),
        "four_byte_permutation": ("AW", "local W=A%128*128+(H+(B+(A-A%128)*2097152))+i"),
        "root_length_byte2_branch": ("v", "x:UW(w,t,_,X,Y,K,P,y)"),
        "root_length_byte3_branch": ("v", "x:DW(y,K,t,X,Y,P,v,_,J)"),
        "root_P_initial_value": ("v", "local D,e,P,K,X,v,Y,_,J,M,r,L=W,b,h"),
        "length_byte2_threshold": ("UW", "return 128>A and 28 or 4,b,o,A,h;"),
        "length_byte3_threshold": ("UW", "return A>=128 and 14 or 18,b,o,j,A;"),
        "record_length_formula": ("DW", "local B=o-128;local H=16384*(j-128)+(128*S+B);return 27,O,w+3,H;"),
    }
    offsets = {}
    for label, (field, fragment) in anchors.items():
        if regions[field].count(fragment) != 1: raise ValueError(f"Missing/ambiguous source evidence: {label}")
        offsets[label] = {"field": field, "offset": fields[field]["offset"] + regions[field].index(fragment), "bytes": len(fragment)}
    ztokens = analyzer.lex(regions["zW"])
    zvalues = [token.value for token in ztokens]
    shifts = [fields["zW"]["offset"] + ztokens[index].start for index in range(len(zvalues) - 1)
              if zvalues[index:index + 2] in (["<", "<"], [">", ">"]) ]
    constants = sorted({int(token.value) for token in ztokens if token.kind == "number" and token.value.isdecimal()})
    zcode = "".join(token.value if token.kind not in {"string", "long_string"} else "<literal>" for token in ztokens)
    band_calls = len(re.findall(r'(?:bit32\.band|x\[99\])\(', zcode))
    auxiliary = re.search(r'x:v\(h,S,(\d+)\)\(x.K,nil,nil\)', regions["sW"])
    if not auxiliary: raise ValueError("Root auxiliary argument not found")
    return {"anchors": offsets, "zW_numeric_literals": constants,
            "root_auxiliary_byte": int(auxiliary[1]),
            "zW_shift_operator_offsets": shifts, "zW_band_calls": band_calls,
            "zW_bitwise_notes": "The pinned zW branch uses bxor aliases, arithmetic and mod256, not band or << / >>. 128/16384/2097152 also occur in integer-read branches and are not XOR keys.",
            "aliases": {"[8]": "buffer.readu32", "[20]": "bit32.bxor", "[46]": "buffer.readu8", "[69]": "buffer.writeu32", "[74]": "buffer.writeu8"},
            "rW_state_mapping": {"j": "v.e (selected lookup id on this path)", "S": "v.P (91 on this path)", "o": "record_length"},
            "zW_state_mapping": {"W": "rolling LCG state", "H": "replicated auxiliary byte", "i": "auxiliary byte", "B": "source start", "O": "word offset"}}


def run(source_path: Path, data_path: Path, output: Path) -> dict:
    source_bytes, data = analyzer.bounded_read(source_path), analyzer.bounded_read(data_path)
    if hashlib.sha256(source_bytes).hexdigest() != analyzer.SOURCE_SHA or hashlib.sha256(data).hexdigest() != analyzer.DATA_SHA:
        raise ValueError("Unknown g/d snapshot")
    evidence = source_evidence(source_bytes.decode("ascii"))
    loader = parse_loader(data)
    # Additional known-snapshot cross-checks on the normalized loader path.
    expected = (748, 664, 2242, 152177, 41168, 43414, 53886)
    observed = tuple(loader[key] for key in ("lookup_count", "selected_id", "slice_offset", "slice_length", "selected_lookup_value", "record_payload_input_offset", "record_length"))
    if observed != expected: raise ValueError("Normalized loader path no longer matches reviewed snapshot")
    start = loader["record_payload_input_offset"]
    prefix, trace = decrypt_record(data[start:start + 64], loader["selected_id"], evidence["root_auxiliary_byte"])
    report = {"source_sha256": analyzer.SOURCE_SHA, "data_sha256": analyzer.DATA_SHA,
              "payload_executed": False, "network_used": False,
              "status": "source_derived_selected_record_transform_not_complete_VM_deobfuscation",
              "source_evidence": evidence, "loader": loader,
              "original_d_first64": {"hex": data[:64].hex(), "header_checks": header_checks(data[:64]),
                   "interpretation": "Loader integer/lookup prefix, not the selected record ciphertext; not blindly XORed"},
              "selected_record_first64": {"input_offset": start, "ciphertext_hex": data[start:start + 64].hex(),
                   "decoded_hex": prefix.hex(), "decoded_sha256": hashlib.sha256(prefix).hexdigest(),
                   "input_entropy": analyzer.entropy(data[start:start + 64]), "output_entropy": analyzer.entropy(prefix),
                   "header_checks": header_checks(prefix), "trace": trace},
              "root_path": ["v starts y10 with e=selected_id, P=91", "wW tag byte254 -> state5",
                            "UW reads byte131 -> state4", "UW reads byte36 -> state18",
                            "DW length53886, cursor41172 -> state27", "rW seed=(664+91)%256=243; mask91*0x01010101",
                            "KW word-loop counter -> zW state33; word XOR; repeat"],
              "limits": "Only 64 selected-record bytes transformed. Length53886 describes that encrypted record, not an opcode count. Constants/prototypes remain unparsed, later d segments and lazy readers not traced. Header magic absence does not imply another cipher."}
    names = ["reader-trace.json", "selected-record-prefix.bin"]
    output.mkdir(parents=True, exist_ok=True)
    if any((output / name).resolve() in {source_path.resolve(), data_path.resolve()} for name in names): raise ValueError("Output aliases input")
    (output / names[0]).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (output / names[1]).write_bytes(prefix)
    return report


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--source", type=Path, default=Path("output/stage1-vm-source.lua.txt"))
    cli.add_argument("--data", type=Path, default=Path("output/stage1-vm-data.bin"))
    cli.add_argument("--output", type=Path, default=Path("output/phase5"))
    args = cli.parse_args()
    try: report = run(args.source, args.data, args.output)
    except (ValueError, OSError) as exc:
        print(f"Reader tracing failed: {exc}", file=sys.stderr); return 1
    trace = report["selected_record_first64"]["trace"]
    print(f"Selected record offset={report['loader']['record_payload_input_offset']}, length={report['loader']['record_length']}")
    print(f"Derived seed={trace['initial_state']}, auxiliary={trace['auxiliary_byte']}, word mask=0x{trace['submask_hex']}")
    print("64 bytes transformed; standard magic not found; prototype/constant schema unresolved. No Lua executed.")
    return 0


if __name__ == "__main__": raise SystemExit(main())
