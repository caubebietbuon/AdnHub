"""Statically unpack the audited StealAnEggg snapshot. Never execute Lua.

Python 3.10+, standard library only. This is a snapshot-specific extractor,
not a universal Luraph deobfuscator or a Luau bytecode parser.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import lzma
from pathlib import Path
import re
import struct
import sys

EXPECTED_SHA256 = "0b7d0741f10fd211b2ce18fb33f3814f845f703b942bff32cd354a20dfcf8809"
MAX_INPUT = 2 * 1024 * 1024
MAX_UNPACKED = 8 * 1024 * 1024


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def detect_header(data: bytes) -> dict:
    """Recognize evidence at offset zero, never infer an XOR key."""
    zlib_candidate = (
        len(data) >= 2 and data[0] & 15 == 8 and data[0] >> 4 <= 7
        and ((data[0] << 8) | data[1]) % 31 == 0
    )
    return {
        "first_32_bytes_hex": data[:32].hex(),
        "lua_bytecode_signature": data.startswith(b"\x1bLua"),
        "lz4_frame_signature": data.startswith(b"\x04\x22\x4d\x18"),
        "gzip_signature": data.startswith(b"\x1f\x8b"),
        "xz_signature": data.startswith(b"\xfd7zXZ\x00"),
        "zlib_header_candidate_only": zlib_candidate,
        "note": "Raw LZMA has no self-identifying magic; configuration comes from the wrapper.",
    }


def lua_quoted_bytes(token: str) -> bytes:
    """Decode only literal escapes needed by this snapshot; no eval/load."""
    if len(token) < 2 or token[0] != '"' or token[-1] != '"':
        raise ValueError("Expected double-quoted Lua literal")
    result = bytearray()
    index = 1
    escapes = {"n": 10, "r": 13, "t": 9, '"': 34, "\\": 92}
    while index < len(token) - 1:
        char = token[index]
        if char == "\\":
            index += 1
            if token[index] not in escapes:
                raise ValueError("Unsupported Lua literal escape")
            result.append(escapes[token[index]])
        else:
            result.append(ord(char))
        index += 1
    return bytes(result)


def substitution_table(source: str) -> dict[int, bytes]:
    match = re.search(r"\bY=\{(.*?)\},\[127\]=string\.gsub", source, re.S)
    if not match:
        raise ValueError("Snapshot substitution table not found")
    quoted = r'"(?:\\.|[^"\\])*"'
    entry = re.compile(rf'(?:\[({quoted})\]|([a-z]))=({quoted})')
    table = {}
    for item in entry.finditer(match[1]):
        key = lua_quoted_bytes(item[1]) if item[1] else item[2].encode("ascii")
        value = lua_quoted_bytes(item[3])
        if len(key) != 1 or len(value) != 5 or key[0] in table:
            raise ValueError("Invalid shorthand substitution")
        table[key[0]] = value
    if set(table) != set(range(ord("u"), ord("~") + 1)):
        raise ValueError("Expected the complete [u-~] shorthand table")
    return table


def extract_blob(source: str, field: str) -> tuple[bytes, dict]:
    # The accepted input hash pins this syntax. Arbitrary Lua is not parsed.
    match = re.search(rf'\b{re.escape(field)}=\[(=*)\[', source)
    if not match:
        raise ValueError(f"Missing field {field}")
    closing = "]" + match[1] + "]"
    end = source.find(closing, match.end())
    if end < 0:
        raise ValueError("Unterminated Lua long string")
    blob = source[match.end():end].encode("ascii")
    return blob, {"start_offset": match.end(), "end_offset_exclusive": end,
                  "literal_bytes": len(blob)}


def decode_radix85(blob: bytes, table: dict[int, bytes]) -> bytes:
    if blob[:4] not in (b"LPH~", b"LPH#"):
        raise ValueError("Missing snapshot LPH marker")
    body = b"".join(table.get(char, bytes([char])) for char in blob[4:])
    if len(body) % 5:
        raise ValueError("Expanded radix85 length is not divisible by five")
    result = bytearray()
    for offset in range(0, len(body), 5):
        a, b, c, d, e = body[offset:offset + 5]
        if not all(32 <= char <= 116 for char in (a, b, c, d, e)):
            raise ValueError(f"Invalid radix85 digit at group offset {offset}")
        # Wrapper swaps the final two base85 digits, then buffer.writeu32 LE.
        value = ((a - 32) * 85**4 + (b - 32) * 85**3
                 + (c - 32) * 85**2 + (e - 32) * 85 + (d - 32))
        if value > 0xFFFFFFFF:
            raise ValueError("Radix85 word exceeds unsigned 32-bit range")
        result.extend(struct.pack("<I", value))
    return bytes(result)


def decompress_raw(data: bytes, expected: int) -> tuple[bytes, int]:
    if not 0 < expected <= MAX_UNPACKED:
        raise ValueError("Declared output size exceeds the extraction limit")
    decoder = lzma.LZMADecompressor(
        format=lzma.FORMAT_RAW,
        filters=[{"id": lzma.FILTER_LZMA1, "dict_size": MAX_UNPACKED,
                  "lc": 3, "lp": 0, "pb": 0}],
    )
    result = decoder.decompress(data, max_length=expected + 1)
    if len(result) != expected or not decoder.eof:
        raise ValueError("Raw LZMA output size/EOS does not match wrapper")
    # writeu32 groups pad each compressed stream to a multiple of four bytes.
    trailing = len(decoder.unused_data)
    if trailing > 3:
        raise ValueError("Unexpected data after raw LZMA stream")
    return result, trailing


def parse(input_path: Path, output_dir: Path) -> dict:
    with input_path.open("rb") as stream:
        original = stream.read(MAX_INPUT + 1)
    if len(original) > MAX_INPUT:
        raise ValueError("Input exceeds snapshot size limit")
    digest = sha256(original)
    if digest != EXPECTED_SHA256:
        raise ValueError("Unknown snapshot SHA-256; review its wrapper before adding support")
    source = original.decode("ascii")
    sizes = re.search(r'j\(i,e,(\d+)\),j\(i,M,(\d+)\)', source)
    if not sizes:
        raise ValueError("Cannot locate the wrapper's decompression sizes")
    table = substitution_table(source)
    report = {
        "input_bytes": len(original), "input_sha256": digest,
        "source_header": detect_header(original),
        "declared_protection": "Luraph Obfuscator v15.1 (source comment)",
        "method": "literal extraction -> shorthand expansion -> custom radix85 -> raw LZMA1",
        "lzma_parameters": {"lc": 3, "lp": 0, "pb": 0,
                            "decoder_dictionary_limit_bytes": MAX_UNPACKED},
        "payload_executed": False, "network_used": False,
        "verified_vm_instruction_bytes": None,
        "limitations": "Binary output is VM input data, not yet a validated opcode/constant layout.",
        "streams": [],
    }
    artifacts = {}
    for field, expected in zip(("g", "d"), map(int, sizes.groups())):
        blob, offsets = extract_blob(source, field)
        packed = decode_radix85(blob, table)
        unpacked, trailing = decompress_raw(packed, expected)
        name = "stage1-vm-source.lua.txt" if field == "g" else "stage1-vm-data.bin"
        if field == "g" and not unpacked.startswith(b"return setmetatable("):
            raise ValueError("Unexpected second-stage Lua source prefix")
        artifacts[name] = unpacked
        artifacts[f"{field}-compressed.bin"] = packed
        report["streams"].append({
            "field": field, **offsets, "marker": blob[:4].decode(),
            "compressed_word_buffer_bytes": len(packed),
            "compressed_stream_bytes": len(packed) - trailing,
            "trailing_word_padding_bytes": trailing,
            "declared_unpacked_bytes": expected,
            "actual_unpacked_bytes": len(unpacked),
            "output_file": name, "output_sha256": sha256(unpacked),
            "compressed_sha256": sha256(packed),
            "decoded_header": detect_header(unpacked),
        })
    # Validate both streams before publishing any result; never overwrite input.
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = [output_dir / name for name in [*artifacts, "parser-report.json"]]
    if any(path.resolve() == input_path.resolve() for path in paths):
        raise ValueError("An output path aliases the input")
    for name, data in artifacts.items():
        (output_dir / name).write_bytes(data)
    (output_dir / "parser-report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("input", nargs="?", type=Path, default=Path("input/StealAnEggg.lua"))
    cli.add_argument("--output", type=Path, default=Path("output"))
    args = cli.parse_args()
    try:
        report = parse(args.input, args.output)
    except (OSError, ValueError, lzma.LZMAError) as exc:
        print(f"Extraction failed: {exc}", file=sys.stderr)
        return 1
    for stream in report["streams"]:
        print(f"{stream['field']}: {stream['compressed_word_buffer_bytes']:,} -> "
              f"{stream['actual_unpacked_bytes']:,} bytes; {stream['output_file']}")
    print("Verified VM instruction size: unknown (layout not parsed). No Lua executed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
