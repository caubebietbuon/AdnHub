"""Bounded, static inspection of the two audited stage-one artifacts.

No Lua execution, network access, guessed decryption keys or inferred opcode map.
The lexer is not a Luau AST parser. Function/call/loop results are candidates.
"""
from __future__ import annotations

import argparse
from bisect import bisect_left
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import re
import struct
import sys

SOURCE_SHA = "1bc1f3c9df9aed79ff79a392423a5f59e41b04f7c326c90c4e0603362c745ed8"
DATA_SHA = "0131f80c4b90b7a49aeaf5d44707ab90575321ebd2b7d0587ea56484a8c56a13"
MAX_FILE = 2 * 1024 * 1024


@dataclass
class Token:
    kind: str
    value: str
    start: int
    end: int


def lex(source: str) -> list[Token]:
    """Keep strings/comments out of structural searches, preserving offsets."""
    tokens = []
    pos = 0
    while pos < len(source):
        start = pos
        if source[pos].isspace():
            pos += 1
            continue
        comment = source.startswith("--", pos)
        opening = pos + 2 if comment else pos
        long = re.match(r"\[(=*)\[", source[opening:opening + 32])
        if long:
            content = opening + long.end()
            closing = "]" + long[1] + "]"
            end = source.find(closing, content)
            if end < 0:
                raise ValueError(f"Unterminated long literal at {start}")
            pos = end + len(closing)
            if not comment:
                tokens.append(Token("long_string", source[content:end], start, pos))
            continue
        if comment:
            end = source.find("\n", pos)
            pos = len(source) if end < 0 else end + 1
            continue
        if source[pos] in "\"'":
            quote = source[pos]
            pos += 1
            while pos < len(source):
                if source[pos] == "\\":
                    pos += 2
                elif source[pos] == quote:
                    pos += 1
                    break
                else:
                    pos += 1
            else:
                raise ValueError(f"Unterminated quoted string at {start}")
            tokens.append(Token("string", source[start:pos], start, pos))
            continue
        match = re.match(r"[A-Za-z_][A-Za-z_0-9]*|(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)", source[pos:pos + 256])
        if match:
            value = match[0]
            pos += len(value)
            kind = "identifier" if value[0].isalpha() or value[0] == "_" else "number"
            tokens.append(Token(kind, value, start, pos))
        else:
            pos += 1
            tokens.append(Token("symbol", source[start:pos], start, pos))
    return tokens


def decode_literal(token: Token) -> str:
    if token.kind == "long_string":
        return token.value[2:] if token.value.startswith("\r\n") else token.value[1:] if token.value.startswith("\n") else token.value
    text = token.value[1:-1]
    result = []
    pos = 0
    escapes = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v", "\\": "\\", '"': '"', "'": "'"}
    while pos < len(text):
        if text[pos] != "\\":
            result.append(text[pos]); pos += 1; continue
        pos += 1
        if pos >= len(text):
            raise ValueError("Incomplete string escape")
        char = text[pos]
        if char.isdigit():
            match = re.match(r"[0-9]{1,3}", text[pos:])
            number = int(match[0])
            if number > 255:
                raise ValueError("Lua decimal escape exceeds byte range")
            result.append(chr(number)); pos += len(match[0])
        elif char == "z":
            pos += 1
            while pos < len(text) and text[pos].isspace(): pos += 1
        elif char == "x" and re.match(r"[0-9a-fA-F]{2}", text[pos + 1:pos + 3]):
            result.append(chr(int(text[pos + 1:pos + 3], 16))); pos += 3
        elif char in escapes:
            result.append(escapes[char]); pos += 1
        elif char == "\n":
            result.append("\n"); pos += 1
        else:
            raise ValueError(f"Unsupported escape: {char!r}")
    return "".join(result)


def entropy(data: bytes) -> float:
    return -sum(count / len(data) * math.log2(count / len(data)) for count in Counter(data).values()) if data else 0.0


def binary_strings(data: bytes, minimum: int = 6) -> list[dict]:
    entries = []
    patterns = [("ascii", rb"[\x20-\x7e]{%d,}" % minimum),
                ("utf16le_ascii_subset", rb"(?:[\x20-\x7e]\x00){%d,}" % minimum)]
    for encoding, pattern in patterns:
        for match in re.finditer(pattern, data):
            value = match[0].decode("ascii" if encoding == "ascii" else "utf-16le")
            entries.append({"offset": match.start(), "byte_length": len(match[0]),
                            "encoding": encoding, "text": value[:4096], "truncated": len(value) > 4096,
                            "status": "printable_run_only_not_a_validated_constant"})
    return sorted(entries, key=lambda row: row["offset"])


def uleb_probe(data: bytes, limit: int = 64) -> dict:
    """Generic probe, deliberately not used to define a format or decrypt."""
    rows = []
    offset = 0
    for _ in range(limit):
        start = offset
        value = 0
        for shift in range(0, 35, 7):
            if offset >= len(data):
                return {"status": "hypothesis_only", "stop": "end_of_buffer", "values": rows}
            byte = data[offset]; offset += 1
            value |= (byte & 127) << shift
            if byte < 128:
                rows.append({"offset": start, "bytes": offset - start, "value": value})
                break
        else:
            return {"status": "hypothesis_only", "stop": "exceeds_five_bytes", "offset": start, "values": rows}
    return {"status": "hypothesis_only", "stop": "probe_limit", "values": rows}


def source_structure(tokens: list[Token], source: str) -> tuple[dict, list[dict]]:
    values = [token.value if token.kind not in ("string", "long_string") else "<literal>" for token in tokens]
    fields = []
    aliases = []
    braces = parens = brackets = 0
    for i, token in enumerate(tokens):
        # Structural top-table depth excludes nested table literals and arguments.
        if braces == 1 and parens == 1 and brackets == 0:
            key = None
            eq = None
            if i + 2 < len(tokens) and token.kind == "identifier" and values[i + 1] == "=":
                key, eq = token.value, i + 1
            elif i + 4 < len(tokens) and values[i:i + 1] == ["["] and tokens[i + 1].kind == "number" and values[i + 2:i + 4] == ["]", "="]:
                key, eq = "[" + values[i + 1] + "]", i + 3
            if key is not None and (i == 0 or values[i - 1] in ("{", ",", ";")):
                if values[eq + 1] == "function":
                    fields.append({"key": key, "offset": token.start, "token_index": eq + 1})
                elif eq + 3 < len(tokens) and tokens[eq + 1].kind == "identifier" and values[eq + 2] == ".":
                    api = "".join(values[eq + 1:eq + 4])
                    if key.startswith("[") and api.split(".")[0] in {"buffer", "bit32", "string", "table", "coroutine"}:
                        aliases.append({"key": key, "api": api, "offset": token.start})
        if token.kind in ("string", "long_string"): continue
        if token.value == "{": braces += 1
        elif token.value == "}": braces -= 1
        elif token.value == "(": parens += 1
        elif token.value == ")": parens -= 1
        elif token.value == "[": brackets += 1
        elif token.value == "]": brackets -= 1
    # Candidate field intervals are lexical boundaries, not an AST/control-flow graph.
    starts = [token.start for token in tokens]
    for index, field in enumerate(fields):
        end = fields[index + 1]["offset"] if index + 1 < len(fields) else len(source)
        field["candidate_interval_end"] = end
        field["candidate_interval_bytes"] = end - field["offset"]
        first, last = bisect_left(starts, field["offset"]), bisect_left(starts, end)
        field["method_call_candidates"] = sorted({values[i + 2] for i in range(first, max(first, last - 3))
            if values[i:i + 2] == ["x", ":"] and tokens[i + 2].kind == "identifier" and values[i + 3] == "("})
        del field["token_index"]
    dispatch = []
    for i in range(len(tokens) - 9):
        if values[i:i + 4] == ["while", "true", "do", "local"]:
            # while true do local opcode = instructions[pc]
            if (tokens[i + 4].kind == "identifier" and values[i + 5] == "="
                    and tokens[i + 6].kind == "identifier" and values[i + 7] == "["
                    and tokens[i + 8].kind == "identifier" and values[i + 9] == "]"):
                offset = tokens[i].start
                owner = next((f["key"] for f in reversed(fields) if f["offset"] <= offset), None)
                dispatch.append({"offset": offset, "candidate_owner": owner,
                                 "opcode_variable": values[i + 4], "instruction_table": values[i + 6],
                                 "pc_variable": values[i + 8], "status": "interpreter_candidate_not_opcode_mapping"})
    strings = []
    for token in tokens:
        if token.kind not in ("string", "long_string"): continue
        try:
            value = decode_literal(token)
            status = "literal_decoded"
        except ValueError:
            value = token.value
            status = "unsupported_escape_raw_literal"
        strings.append({"offset": token.start, "source_end_exclusive": token.end,
                        "decoded_characters": len(value), "value": value[:4096],
                        "truncated": len(value) > 4096, "status": status})
    return {"token_count": len(tokens), "keyword_counts": dict(Counter(v for v in values if v in {"function", "while", "repeat", "if", "return"})),
            "field_candidates": fields, "api_alias_candidates": aliases,
            "dispatch_candidates": dispatch,
            "entrypoint": {"method": "CW", "evidence": source.endswith("):CW(...);")},
            "limitations": "Lexical candidates, not an AST, validated CFG or resolved call graph. Field intervals may include non-function entries. Method calls are unresolved."}, strings


def bounded_read(path: Path) -> bytes:
    with path.open("rb") as stream: data = stream.read(MAX_FILE + 1)
    if len(data) > MAX_FILE: raise ValueError(f"File exceeds limit: {path}")
    return data


def analyze(source_path: Path, data_path: Path, output: Path) -> dict:
    source_bytes, data = bounded_read(source_path), bounded_read(data_path)
    source_sha, data_sha = hashlib.sha256(source_bytes).hexdigest(), hashlib.sha256(data).hexdigest()
    if (source_sha, data_sha) != (SOURCE_SHA, DATA_SHA):
        raise ValueError("Artifact SHA-256 mismatch; run parser on the audited snapshot first")
    source = source_bytes.decode("ascii")
    tokens = lex(source)
    structure, literals = source_structure(tokens, source)
    runs = binary_strings(data)
    report = {
        "phase": "static_structure_survey", "network_used": False, "payload_executed": False,
        "source": {"bytes": len(source_bytes), "sha256": source_sha, **structure,
                   "literal_count": len(literals)},
        "binary": {"bytes": len(data), "sha256": data_sha, "entropy_bits_per_byte": entropy(data),
                   "prefix_64_bytes_hex": data[:64].hex(),
                   "printable_run_count": len(runs),
                   "u32_le_prefix_probe": [{"offset": i, "value": struct.unpack_from("<I", data, i)[0]} for i in range(0, min(64, len(data) - 3), 4)],
                   "uleb128_prefix_probe": uleb_probe(data),
                   "entropy_windows": [{"offset": i, "bytes": len(data[i:i + 4096]), "entropy": entropy(data[i:i + 4096])} for i in range(0, len(data), 4096)],
                   "verified_fields": [], "constant_table": "unresolved", "prototype_table": "unresolved",
                   "opcode_map": "unresolved", "decryption": "not_inferred",
                   "limitations": "High entropy and printable runs do not establish encryption, compression, constant boundaries or opcode semantics. Integer probes are not a schema."},
        "evidence_notes": [
            "CW calls MW and delegates state transitions to named methods; MW returns true and initial state 33.",
            "jW assigns varargs to x.U; readu8 alias [46] and cursor [104] occur in loader helpers.",
            "sW contains buffer allocation/copy, x[104] cursor update and x:v(...) invocation.",
            "Numeric function fields include readable application functions as well as interpreter code.",
            "No complete binary schema is established by these lexical observations.",
        ],
    }
    output.mkdir(parents=True, exist_ok=True)
    artifacts = {"analysis-report.json": report, "source-literals.json": literals, "binary-printable-runs.json": runs}
    for name in [*artifacts, "source-call-candidates.mmd"]:
        if (output / name).resolve() in {source_path.resolve(), data_path.resolve()}:
            raise ValueError("Output aliases input")
    for name, value in artifacts.items():
        (output / name).write_text(json.dumps(value, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    fields = structure["field_candidates"]
    ids = {field["key"]: f"n{i}" for i, field in enumerate(fields)}
    lines = ["flowchart TD", "%% Lexical method call candidates only; NOT a validated CFG."]
    for field in fields:
        if not field["method_call_candidates"]: continue
        lines.append(f'  {ids[field["key"]]}["{field["key"]} @ {field["offset"]}"]')
        for target in field["method_call_candidates"]:
            if target in ids:
                lines.append(f'  {ids[field["key"]]} --> {ids[target]}["{target}"]')
    (output / "source-call-candidates.mmd").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--source", type=Path, default=Path("output/stage1-vm-source.lua.txt"))
    cli.add_argument("--data", type=Path, default=Path("output/stage1-vm-data.bin"))
    cli.add_argument("--output", type=Path, default=Path("output/phase2"))
    args = cli.parse_args()
    try: report = analyze(args.source, args.data, args.output)
    except (OSError, ValueError) as exc:
        print(f"Analysis failed: {exc}", file=sys.stderr); return 1
    print(f"Source literals: {report['source']['literal_count']}; dispatch candidates: {len(report['source']['dispatch_candidates'])}")
    print(f"Binary entropy: {report['binary']['entropy_bits_per_byte']:.6f}; printable runs: {report['binary']['printable_run_count']}")
    print("Binary field schema, constants and opcode mapping: unresolved. No Lua executed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
