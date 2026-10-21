# Static outer-wrapper extraction

## Run
Python 3.10+ standard library only (including lzma). From repository root:

```powershell
python tools/parser.py input/StealAnEggg.lua --output output
python -m unittest discover -s tools -p test_parser.py -v
```

Place the audited snapshot at input/StealAnEggg.lua. Its SHA-256 must be
0b7d0741f10fd211b2ce18fb33f3814f845f703b942bff32cd354a20dfcf8809.
Other inputs fail closed; do not remove the hash check to pretend other Luraph
builds use the same layout. input/ and output/ are local, Git-ignored directories.
No network calls, source evaluation, Lua interpreter, or executor is used.

## What the wrapper actually does
The input starts with a Lua comment, not a binary compression header. The comment
claims Luraph v15.1; this alone does not authenticate a tool version.
Field g contains a Lua long string with LPH~; d has LPH#. The four-character
marker is skipped. Y is the literal substitution table used by string.gsub with
pattern [u-~]. Each matched character expands to five printable characters.
These are single-pass substitutions, not recursive replacements.

For each resulting five-byte group a,b,c,d,e (ASCII byte values), the wrapper
computes:

```text
v = (a-32)*85^4 + (b-32)*85^3 + (c-32)*85^2 + (e-32)*85 + (d-32)
```

It writes v as a little-endian uint32. The last two radix digits are swapped;
ordinary Ascii85 decoding is not a drop-in replacement.

The _ decompressor has range-coded probability models and literal contexts.
Raw LZMA1 with lc=3, lp=0, pb=0 reproduces both streams, reaches EOS, and matches
the sizes in j(i,e,1261603),j(i,M,373666). Python uses an 8 MiB dictionary limit;
this is a chosen decoder configuration, not an original dictionary-size header.
Trailing word alignment bytes are reported (3 for g, 1 for d), not silently
counted as compressed data. Raw LZMA has no magic identifying it by header alone.
No XOR key or zlib/lz4 layer has been established for this snapshot.

## Verified results
| Field | Encoded literal bytes, including LPH marker | Word buffer bytes | Decompressed bytes | Meaning |
| --- | ---: | ---: | ---: | --- |
| g | 349290 | 279464 | 1261603 | Next-stage Lua VM source, still obfuscated |
| d | 471024 | 376816 | 373666 | Binary input to the next stage; layout unparsed |

Output: g-compressed.bin, d-compressed.bin, stage1-vm-source.lua.txt,
stage1-vm-data.bin and parser-report.json. The report includes offsets, hashes,
exact sizes and limitations. These are untrusted extracted artifacts: do not
execute them. A .txt suffix is intentional for extracted Lua source.

373666 bytes is the size of the entire decoded binary stream. It is NOT a
verified instruction-array length: constants, metadata, operands or other
sections may share the stream. Constant/string tables, opcode mapping, dynamic
tracing and clean source reconstruction are not implemented in this parser.
The Lua bytecode magic check concerns standard Lua's ESC-Lua header, not a
universal Luau bytecode identifier.

## Limits and checks
Input capped at 2 MiB; declared decoded streams capped at 8 MiB. Validate SHA-256,
radix digits, uint32 bounds, compressed EOS, output sizes and alignment. Both
streams are decoded before outputs are written. Unit tests cover the custom
digit order, invalid input, decompression limits and the known snapshot hashes.
Luau standalone is not installed in this workspace; this static phase does not
require it. Do not treat the local Lua 5.1 CLI as Luau.

The earlier closed audit/handover remains an immutable historical record.
This phase was reopened by the user's explicit request for a static parser;
source 2 fetching and dynamic payload execution remain inactive.

## Phase 2 analyzer

```powershell
python tools/analyzer.py --source output/stage1-vm-source.lua.txt --data output/stage1-vm-data.bin --output output/phase2
python -m unittest discover -s tools -p "test_*.py" -v
```

Reads only the two hash-pinned artifacts. Outputs analysis-report.json,
source-literals.json, binary-printable-runs.json, source-call-candidates.mmd.
Lexer removes comments/literals from structural matching; supported Lua literal
escapes are decoded, unsupported escapes remain marked raw. Values over 4096
characters are truncated explicitly. This is a survey, not a Luau AST/CFG,
a constant-table decoder, an XOR solver or an opcode mapper. See
research/static-analysis-2026-10-21/FINDINGS.md for evidence and unresolved fields.

## Phase 3 reader discovery and tracer blueprint
See PHASE3.md for source evidence, per-function explanations and offline-container
requirements. Run python tools/decryption_finder.py for static findings. Run
python tools/run_tracer.py --demo to PREPARE a synthetic bundle only. Runtime
requires an independently provisioned, pinned local Luau image and OS isolation.
No full-g tracing or complete constant-table checkpoint has been validated.

## Phase 4 LCG mock / state separation

```powershell
python tools/lcg_decoder.py --offsets 0,4096,8192 --size 4096 --top 3
python tools/state_separator.py
```

LCG tests are hypotheses with independent per-window seeds and an assumed extra
word mask (default0, configurable --word-mask). Inverse multiplier is21; this
reverses PRNG state, not a whole record. Results/candidate binaries are local in
output/phase4; empirical entropy does not verify decryption. Seed pairs differing
by128 cannot be distinguished by entropy. See research/lcg-experiments-2026-10-21/
FINDINGS.md and experiment-summary.json for measured results and controls.
state_separator emits view-only source excerpts, a cut BEFORE v, region hashes
and operation metadata. It does not produce a runnable or proven-safe decoder.

## Phase 5 targeted reader

```powershell
python tools/reader_tracer.py
```

Source-pinned CW integer reader (permuted digits, not ULEB128) locates selected
record ID664 at d offset43414, length53886. The rW/zW parameter chain yields
auxiliary91, replicated word0x5b5b5b5b, starting state243. Only64 selected-record
bytes are transformed; no Lua runs, no whole-d decryption/schema is claimed.
See research/targeted-reader-2026-10-21/FINDINGS.md. Local reader-trace.json
contains exact masks and byte previews; committed summary excludes raw bytes.

## Phase 6 GW alignment

```powershell
python tools/gw_aligner.py --record-ids 664
python tools/gw_aligner.py --record-ids 664,1,2
```

Uses gw_reader_model.py's bounded numeric/table IR from44 reviewed reader helpers;
no Lua, application factory, VM opcode or lazy __index is invoked. Record664
aligns to factory4890: opcode slots9965, entry PC9942, register capacity181;
reader end53881/53886 with5 bytes unresolved. Independent normalized parser agrees.
Constant/prototype/upvalue counts remain unresolved. IDs1/2 are unvalidated
structural comparisons, not accepted prototypes. Source callsites passaux91;
seed depends on ID modulo256, not fixed243. See research/gw-alignment-2026-10-21/
FINDINGS.md; dumps stay in ignored output/phase6.
