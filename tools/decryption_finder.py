"""Snapshot-pinned static reader/decryption evidence. Never run Lua."""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys

import analyzer

TARGETS = {"CW", "MW", "xW", "aW", "TW", "BW", "jW", "sW", "v", "UW", "QW", "KW", "DW", "rW", "zW", "wW", "GW"}


def mask_tables(multiplier: int, increment: int) -> tuple[list[int], list[int]]:
    """Algebraic translation of TW's observed four-byte mask expansion."""
    words, next_states = [], []
    for seed in range(256):
        a = (increment + multiplier * seed) % 256
        b = (multiplier * a + increment) % 256
        c = (multiplier * b + increment) % 256
        d = (multiplier * c + increment) % 256
        words.append(a | b << 8 | c << 16 | d << 24)
        next_states.append(d)
    return words, next_states


def find(source_path: Path, output: Path) -> dict:
    data = analyzer.bounded_read(source_path)
    if hashlib.sha256(data).hexdigest() != analyzer.SOURCE_SHA:
        raise ValueError("Unknown source snapshot; rules must be reviewed first")
    source = data.decode("ascii")
    tokens = analyzer.lex(source)
    structure, _ = analyzer.source_structure(tokens, source)
    fields = {field["key"]: field for field in structure["field_candidates"]}
    evidence = []
    for name in sorted(TARGETS):
        field = fields[name]
        body = source[field["offset"]:field["candidate_interval_end"]]
        # Mask strings/comments before searching arithmetic/reader references.
        chars = [" "] * len(body)
        for token in analyzer.lex(body):
            if token.kind not in {"string", "long_string"}:
                chars[token.start:token.end] = token.value
        code = "".join(chars)
        numbers = Counter(token.value for token in analyzer.lex(body) if token.kind == "number")
        references = []
        for match in re.finditer(r"x\[(?:46|8|13|122|71|79|20|24|99|69|74|55|67|104)\]|x\.(?:OW|VW|U)\b", code):
            references.append({"offset": field["offset"] + match.start(), "reference": match[0]})
        evidence.append({"field": name, "offset": field["offset"],
                         "candidate_interval_end": field["candidate_interval_end"],
                         "references": references, "numeric_literals": dict(numbers),
                         "method_calls": field["method_call_candidates"]})

    # These are exact, separately reviewed fragments of the pinned snapshot.
    # Missing evidence fails, rather than silently applying a generic key guess.
    fragments = {
        "initial_state": "MW=function(x)return true,33,",
        "init_coefficients": "return 6,{A,nil,0-A,255+0,o},61,123,j,O,W;",
        "counter_increment": "local w,A,B=S[3],S[1],S[4];",
        "mask_recurrence": "local b=(h+O*S)%256;local A=(O*b+h)%256;local B=(O*A+h)%256;",
        "mask_pack": "i[S]=H*16777216+(Z+R)+b;x.VW[S]=H;",
        "word_xor": "h(A,O,(x[20](x.OW[W],H,N)));",
        "byte_xor": "local h=(o+W*b)%256;x[74](A,S,(x[20](i,x[46](Z,S+B),h)));",
        "payload_boundary": "return 12,x:v(h,S,91)(x.K,nil,nil),o;",
    }
    anchors = {}
    for name, fragment in fragments.items():
        offset = source.find(fragment)
        if offset < 0: raise ValueError(f"Missing reviewed anchor: {name}")
        anchors[name] = {"offset": offset, "bytes": len(fragment)}
    words, states = mask_tables(61, 123)
    report = {
        "source_sha256": analyzer.SOURCE_SHA, "payload_executed": False, "network_used": False,
        "offset_convention": "zero-based ASCII byte offsets in g",
        "anchors": anchors, "fields": evidence,
        "confirmed_arithmetic": {
            "multiplier": 61, "increment": 123, "modulus": 256,
            "seed_range": [0, 255],
            "formula": "s1=(123+61*seed)%256; s2=(123+61*s1)%256; s3=(123+61*s2)%256; s4=(123+61*s3)%256",
            "OW": "s1 + 256*s2 + 65536*s3 + 16777216*s4",
            "VW": "s4",
            "example_seed0_word_hex": f"{words[0]:08x}",
            "example_seed0_next_state": states[0],
            "word_transform": "output_u32 = bxor(OW[index], other_mask, input_u32); index/other_mask depend on reader state",
            "byte_transform": "next_state=(addend+state*multiplier)%256; output_u8=bxor(other_mask,input_u8,next_state)",
        },
        "initialization_path": [
            "CW receives MW -> loop=true,state=33",
            "state33 xW -> state6,counter=[1,nil,-1,255,...],multiplier61,increment123",
            "state6 aW -> increments counter then state22 while counter<=255",
            "state22 TW -> writes OW[counter],VW[counter], returns state6",
        ],
        "interpretation": "State-dependent masks and XOR are observed. No single global XOR key or full d schema is established.",
        "other_constants_in_v": [83, 187, 1397969747, 1179010630, 1044266558, 3755991007, 2930683566],
        "other_constants_status": "Numeric constants occur in lazy-reader branches; not universal keys or proven d offsets.",
        "trace_gate": {
            "full_source_execution_allowed": False,
            "reason": "sW immediately invokes the function returned by v. No globally validated pre-dispatch constant-table checkpoint exists yet.",
            "required": "Reviewed decoder-only adapter; explicitly identified table/cursor and stop before invoking generated closures.",
        },
        "limitations": "Candidate intervals are lexical, not AST/dataflow proofs. Init-path and transform anchors are manually reviewed for this hash only. Lazy __index decoding may occur during dispatch; a pre-dispatch dump need not contain every constant.",
    }
    output.mkdir(parents=True, exist_ok=True)
    for name in ("decryption-findings.json", "mask-tables.json"):
        if (output / name).resolve() == source_path.resolve(): raise ValueError("Output aliases input")
    (output / "decryption-findings.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (output / "mask-tables.json").write_text(json.dumps({"OW": words, "VW": states, "index_base": 0,
        "status": "algebraic_TW_translation_not_a_decoded_constant_table"}, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--source", type=Path, default=Path("output/stage1-vm-source.lua.txt"))
    cli.add_argument("--output", type=Path, default=Path("output/phase3"))
    args = cli.parse_args()
    try: report = find(args.source, args.output)
    except (ValueError, OSError) as exc:
        print(f"Discovery failed: {exc}", file=sys.stderr); return 1
    print("Observed init masks: multiplier=61, increment=123, modulus=256; OW[0]=0x" + report["confirmed_arithmetic"]["example_seed0_word_hex"])
    print("Global d key/schema: unresolved. Full-source tracing gate: CLOSED.")
    return 0


if __name__ == "__main__": raise SystemExit(main())
