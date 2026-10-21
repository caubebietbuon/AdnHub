"""Bounded hypothesis tests for the audited binary; NOT a verified d decoder.

No Lua execution. Experiments omit the unresolved extra XOR mask and assume a
continuous LCG stream within each window. Seeds are tried independently per window.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import random
import re
import struct
import sys

import analyzer
from decryption_finder import mask_tables

MULTIPLIER, INCREMENT, MODULUS = 61, 123, 256
INVERSE_MULTIPLIER = pow(MULTIPLIER, -1, MODULUS)
OW, VW = mask_tables(MULTIPLIER, INCREMENT)


def step(state: int) -> int:
    return (MULTIPLIER * state + INCREMENT) % MODULUS


def inverse_step(state: int) -> int:
    """Reverse PRNG state, not encrypted data or a serialized record."""
    return ((state - INCREMENT) * INVERSE_MULTIPLIER) % MODULUS


def unxor(data: bytes, seed: int, extra_word_mask: int = 0) -> tuple[bytes, int]:
    if not 0 <= seed <= 255 or not 0 <= extra_word_mask <= 0xFFFFFFFF:
        raise ValueError("Seed/mask out of range")
    result = bytearray()
    state = seed
    aligned = len(data) - len(data) % 4
    for offset in range(0, aligned, 4):
        word = struct.unpack_from("<I", data, offset)[0]
        result.extend(struct.pack("<I", word ^ OW[state] ^ extra_word_mask))
        state = VW[state]
    mask = OW[state] ^ extra_word_mask
    for shift, byte in enumerate(data[aligned:]):
        result.append(byte ^ ((mask >> (shift * 8)) & 255))
        state = step(state)
    return bytes(result), state


def metrics(data: bytes) -> dict:
    runs = list(re.finditer(rb"[\x20-\x7e]{6,}", data))
    zlib_candidate = (len(data) >= 2 and data[0] & 15 == 8 and data[0] >> 4 <= 7
                      and ((data[0] << 8) | data[1]) % 31 == 0)
    signatures = [name for name, magic in (("gzip", b"\x1f\x8b\x08"), ("xz", b"\xfd7zXZ\x00"),
                   ("lz4_frame", b"\x04\x22\x4d\x18"), ("standard_lua_bytecode", b"\x1bLua")) if data.startswith(magic)]
    return {"bytes": len(data), "entropy_bits_per_byte": analyzer.entropy(data),
            "ascii_printable_ratio": sum(32 <= byte <= 126 for byte in data) / len(data) if data else 0,
            "ascii_runs_min6": len(runs), "longest_ascii_run_min6": max((len(m[0]) for m in runs), default=0),
            "prefix_signature_candidates": signatures, "zlib_header_candidate_only": zlib_candidate}


def scan_window(data: bytes, offset: int, size: int, top: int, extra_mask: int) -> tuple[dict, list[tuple[int, bytes]]]:
    block = data[offset:offset + size]
    baseline = metrics(block)
    candidates = []
    best = []
    # A deterministic random negative control undergoes the identical seed search.
    rng = random.Random(0xAD0000 + offset)
    control = bytes(rng.randrange(256) for _ in block)
    control_best_entropy = 8.0
    for seed in range(256):
        decoded, final_state = unxor(block, seed, extra_mask)
        score = metrics(decoded)
        row = {"seed_before_first_byte": seed, "final_state": final_state, **score,
               "entropy_drop_vs_input": baseline["entropy_bits_per_byte"] - score["entropy_bits_per_byte"]}
        candidates.append(row)
        best.append((row, decoded))
        best.sort(key=lambda pair: (pair[0]["entropy_bits_per_byte"], -pair[0]["ascii_printable_ratio"], pair[0]["seed_before_first_byte"]))
        del best[top:]
        control_result, _ = unxor(control, seed, extra_mask)
        control_best_entropy = min(control_best_entropy, analyzer.entropy(control_result))
    constant_xor_entropy = analyzer.entropy(bytes(byte ^ 0xA5 for byte in block))
    report = {"input_offset": offset, "window_bytes": len(block), "baseline": baseline,
              "fixed_xor_control_entropy": constant_xor_entropy,
              "negative_random_control": {"generator": "random.Random deterministic, not cryptographic",
                  "input_entropy": analyzer.entropy(control), "best_entropy_after_same_256_seed_search": control_best_entropy},
              "ranking": "ascending empirical entropy, then descending printable ratio; no candidate accepted",
              "top_candidates": [{**row, "output_sha256": hashlib.sha256(decoded).hexdigest(),
                                  "output_file": f"offset-{offset}-seed-{row['seed_before_first_byte']:03d}.hypothesis.bin"} for row, decoded in best],
              "candidate_metrics": candidates, "validated_constant_records": 0, "verified_decryption": False}
    return report, [(row["seed_before_first_byte"], decoded) for row, decoded in best]


def run(data_path: Path, output: Path, offsets: list[int], size: int, top: int, extra_mask: int) -> dict:
    data = analyzer.bounded_read(data_path)
    if hashlib.sha256(data).hexdigest() != analyzer.DATA_SHA:
        raise ValueError("Unknown d snapshot")
    if not 64 <= size <= 16384 or not 1 <= top <= 8 or not 1 <= len(offsets) <= 8:
        raise ValueError("Limits: size64..16384, top1..8, one to eight windows")
    if len(set(offsets)) != len(offsets) or any(offset < 0 or offset + size > len(data) for offset in offsets):
        raise ValueError("Window offsets must be distinct and fully within d")
    if not 0 <= extra_mask <= 0xFFFFFFFF: raise ValueError("Word mask exceeds uint32")
    report = {"input_sha256": analyzer.DATA_SHA, "input_bytes": len(data),
              "full_input_entropy": analyzer.entropy(data), "payload_executed": False, "network_used": False,
              "verified_decryption": False, "mode": "hypothesis_only",
              "lcg": {"multiplier": 61, "increment": 123, "modulus": 256, "inverse_multiplier": INVERSE_MULTIPLIER,
                      "OW0_hex": f"{OW[0]:08x}", "VW0": VW[0]},
              "assumptions": ["continuous post-update LCG keystream inside each window",
                              "each window seed is independent; offset is not known record alignment",
                              "word and byte versions use identical keystream, not independent evidence",
                              "reader extra XOR mask assumed as supplied; real state schedule unresolved"],
              "seed_ambiguity": "Seeds differing by 128 produce streams differing by fixed XOR 0x80; entropy cannot distinguish them.",
              "extra_word_mask_assumption_hex": f"{extra_mask:08x}",
              "limitations": "A minimum over 256 seeds is selection-biased. Entropy/signatures/runs do not validate schema or decrypt constants. No decompression or candidate execution is attempted.",
              "windows": []}
    artifacts = []
    for offset in offsets:
        window, best = scan_window(data, offset, size, top, extra_mask)
        report["windows"].append(window)
        artifacts.extend((f"offset-{offset}-seed-{seed:03d}.hypothesis.bin", content) for seed, content in best)
    output.mkdir(parents=True, exist_ok=True)
    for name in [name for name, _ in artifacts] + ["lcg-experiments.json"]:
        if (output / name).resolve() == data_path.resolve(): raise ValueError("Output aliases input")
    for name, content in artifacts: (output / name).write_bytes(content)
    (output / "lcg-experiments.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--data", type=Path, default=Path("output/stage1-vm-data.bin"))
    cli.add_argument("--output", type=Path, default=Path("output/phase4/lcg"))
    cli.add_argument("--offsets", default="0,4096,8192")
    cli.add_argument("--size", type=int, default=4096)
    cli.add_argument("--top", type=int, default=3)
    cli.add_argument("--word-mask", type=lambda value: int(value, 0), default=0)
    args = cli.parse_args()
    try:
        report = run(args.data, args.output, [int(item) for item in args.offsets.split(",")], args.size, args.top, args.word_mask)
    except (OSError, ValueError) as exc:
        print(f"LCG experiment failed: {exc}", file=sys.stderr); return 1
    for window in report["windows"]:
        top = window["top_candidates"][0]
        print(f"offset={window['input_offset']}: H={window['baseline']['entropy_bits_per_byte']:.6f} -> {top['entropy_bits_per_byte']:.6f}; seed={top['seed_before_first_byte']}; HYPOTHESIS ONLY")
    print("Constants/opcodes recovered: not established.")
    return 0


if __name__ == "__main__": raise SystemExit(main())
