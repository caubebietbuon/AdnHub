"""Extract hash-pinned reader regions as TEXT; do not construct a runnable VM."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

import analyzer

FIELDS = ("MW", "CW", "xW", "aW", "TW", "jW", "sW", "v", "zW", "rW", "GW")
INVOKE = "x:v(h,S,91)(x.K,nil,nil)"
HALT_VIEW = '{__analysis_boundary="BEFORE_V_NO_CALL",data=h,descriptor=S,parser_state=91}'


def trim_region(candidate: str) -> tuple[str, str]:
    """Trim only the pinned style of trailing scalar aliases. Not a Lua parser."""
    end = candidate.rfind("end,")
    if end < 0: raise ValueError("Cannot identify a reviewed region boundary")
    definition, tail = candidate[:end + 3], candidate[end + 3:]
    if not re.fullmatch(r'(?:,\[\d+\]=[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)*,', tail):
        raise ValueError("Unexpected trailing metadata; refuse to guess a function boundary")
    return definition, tail


def separate(source_path: Path, output: Path) -> dict:
    data = analyzer.bounded_read(source_path)
    if hashlib.sha256(data).hexdigest() != analyzer.SOURCE_SHA: raise ValueError("Unknown g snapshot")
    source = data.decode("ascii")
    structure, _ = analyzer.source_structure(analyzer.lex(source), source)
    fields = {field["key"]: field for field in structure["field_candidates"]}
    regions, manifest = {}, []
    for name in FIELDS:
        field = fields[name]
        definition, tail = trim_region(source[field["offset"]:field["candidate_interval_end"]])
        regions[name] = definition
        manifest.append({"field": name, "offset": field["offset"], "end_offset_exclusive": field["offset"] + len(definition),
                         "bytes": len(definition), "sha256": hashlib.sha256(definition.encode()).hexdigest(),
                         "scalar_metadata_trimmed": tail, "method_calls_unresolved": field["method_call_candidates"]})
    if regions["sW"].count(INVOKE) != 1: raise ValueError("Invocation boundary not unique")
    view = regions["sW"].replace(INVOKE, HALT_VIEW)
    if "x:v(" in view: raise ValueError("Unexpected remaining v call")
    report = {"source_sha256": analyzer.SOURCE_SHA, "payload_executed": False, "network_used": False,
              "status": "view_only_text_extraction_not_standalone_decoder",
              "regions": manifest, "removed_invocation": {"offset": source.index(INVOKE), "bytes": len(INVOKE),
                  "view_behavior": "returns a descriptor BEFORE v, neither v nor its returned closure is called"},
              "sW_observed_operations": [
                  {"operation": "allocate", "size_expression": "O"},
                  {"operation": "copy", "source": "j", "source_offset": "W", "bytes": "O", "target_offset": "0"},
                  {"operation": "store_slice", "target": "h[b]"},
                  {"operation": "advance_cursor", "expression": "x[104]=W+O"},
                  {"operation": "parse", "expression": "v(h,S,91)", "executed": False},
                  {"operation": "invoke_returned_closure", "arguments": "x.K,nil,nil", "executed": False}],
              "limitations": "Lexically extracted definitions may contain lazy closures and unreviewed operations. No dependency closure, semantic equivalence, live state extraction or safe execution adapter is claimed. Never execute text outputs."}
    output.mkdir(parents=True, exist_ok=True)
    names = ["reader-regions.lua.txt", "sW-before-v.view.txt", "separation-report.json", "reader-flow.mmd"]
    if any((output / name).resolve() == source_path.resolve() for name in names): raise ValueError("Output aliases input")
    text = "-- VIEW ONLY: untrusted source excerpts. Do not execute.\n"
    for name, definition in regions.items():
        text += f"\n-- Region {name}; source offset {fields[name]['offset']}\n" + definition + "\n"
    (output / names[0]).write_text(text, encoding="utf-8")
    (output / names[1]).write_text("-- VIEW ONLY: semantics intentionally changed; not an executable adapter.\n" + view + "\n", encoding="utf-8")
    (output / names[2]).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (output / names[3]).write_text('''flowchart TD
  CW --> MW
  CW --> xW
  xW --> aW
  aW --> TW
  TW --> aW
  CW --> jW
  CW --> sW
  sW --> slice["allocate / copy / cursor update"]
  slice --> cut["VIEW CUT: before calling v"]
  cut -. "original only" .-> v
  v --> lazy["lazy reader closures; unresolved dependencies"]
  v -. "original sW invokes returned value" .-> dispatch["VM execution: not entered"]
''', encoding="utf-8")
    return report


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--source", type=Path, default=Path("output/stage1-vm-source.lua.txt"))
    cli.add_argument("--output", type=Path, default=Path("output/phase4/separation"))
    args = cli.parse_args()
    try: report = separate(args.source, args.output)
    except (OSError, ValueError) as exc:
        print(f"Separation failed: {exc}", file=sys.stderr); return 1
    print(f"Extracted {len(report['regions'])} reader regions as TEXT. v/VM were not executed.")
    return 0


if __name__ == "__main__": raise SystemExit(main())
