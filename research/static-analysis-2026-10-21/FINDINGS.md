# Phase 2 — Static internal-structure survey

Snapshot: g SHA-256 1bc1f3c9df9aed79ff79a392423a5f59e41b04f7c326c90c4e0603362c745ed8;
d SHA-256 0131f80c4b90b7a49aeaf5d44707ab90575321ebd2b7d0587ea56484a8c56a13.
Offsets below are zero-based ASCII byte offsets in g, not original wrapper lines.
No network fetch or execution of Lua/payload. Python reads the data as bytes/text.

## Observed code organization
The next layer mixes interpreter/reader helpers and application functions; it is
not exclusively a compressed blob or a collection of opcode handlers.
There are 9224 string literals (including empty/duplicates), 4004 function keyword
occurrences, 212 while and 23 repeat keywords outside strings/comments. These
are lexical counts, not a count of reachable functions or runtime iterations.
Some application UI strings are already readable. Extracting those does not mean
all encrypted string tables have been recovered.

| Source offset | Observed structure | Implication / limit |
| --- | --- | --- |
| 442763 | CW entry; calls MW, then delegates by state to uW/aW/XW/sW/AW/FW/TW/BW/jW/xW | Loader/control-state loop; call edges are lexical candidates |
| 73244 | MW returns true,33 followed by nil values | Initial CW loop flag/state visible in source |
| 6276 | jW assigns varargs to x.U and reads via x[46] with cursor x[104] | Connects entry arguments and byte reader; no full field schema yet |
| 205900 | sW allocates a buffer, copies bytes, updates x[104], calls x:v(...) | Byte slice and parser handoff visible, not proof of opcode layout |
| 347409 | v aliases band/rshift/readu8/bxor/readu32/readstring/readf32/readf64; constructs __index functions | Consistent with deserialization/lazy decoding; exact field meanings unresolved |
| 7929 | numeric field [4890] contains instruction-table indexed dispatch loops | Interpreter candidate, not proven native Luau opcode mapping |

Seven matching interpreter loop patterns were found:
- [4890]: offsets 8367, 23729, 57003.
- [4327]: offsets 1179126, 1188485, 1198063, 1207885.

Pattern: while true do local opcode = instruction_table[pc]. This supports
interpreter identification but does not establish which loop is selected at
runtime or which virtual opcode corresponds to MOVE/CALL/etc. Other dispatch
forms can be missed. No native opcode mapping is claimed.

## Binary d: structural observations
Length: 373666 bytes. Whole-buffer entropy: 7.9993081833 bits/byte.
569 printable ASCII/ASCII-subset UTF-16LE runs with minimum six characters.
These are raw byte runs, not decrypted/validated string constants.

analysis-report.json records prefix bytes, 4 KiB entropy windows, little-endian
u32 prefix probes and a bounded generic ULEB128 prefix probe. All numerical
probes are hypotheses; they are not used to establish field boundaries.
A high entropy score does not distinguish encrypted, compressed, packed or
otherwise high-variation data. No XOR key is guessed.

| Proposed semantic section | Status | Missing evidence |
| --- | --- | --- |
| Header/count/offset directory | Unresolved | Must derive cursor progression and reader transforms |
| Constant/string table | Unresolved | Type tags, string lengths and decoding routine not mapped |
| Prototype table | Unresolved | Prototype count, parent/child layout and references not mapped |
| Instruction/opcode table | Unresolved | Instruction widths, operands and virtual handler mapping not mapped |

There are zero verified semantic fields in the binary report. The tool reports
that explicitly instead of treating incidental u32/varint values as a schema.
The current report therefore does NOT answer that d is exclusively one of
constant table/prototypes/opcodes; it may carry multiple sections.

## Deliverables and limits
- tools/analyzer.py: pinned static lexer, literal decoder, byte/run scans and
  candidate source call graph. No evaluation, no Lua hooks.
- output/phase2/source-literals.json: local literals with offsets, supported Lua
  decimal/hex escapes decoded; unsupported escapes marked raw, values above
  4096 characters truncated with a flag.
- output/phase2/binary-printable-runs.json: local unclassified runs with offsets.
- analysis-report.json and source-call-candidates.mmd: metadata shared in Git.
- The call graph is NOT a basic-block CFG or a resolved execution trace. Field
  intervals are lexical candidates and can include non-function table entries.

Input/output source data and extracted strings remain Git-ignored. The old
closed audit/handover is historical and has not been rewritten.

## Next evidence-producing step
Normalize the CW state transitions and reader helpers into an explicit cursor
model, then follow v and its helper calls. Establish record tags and bounded
lengths from those readers before parsing d into semantic sections. Only after
that can prototype, constant and instruction counts be verified. This task did
not execute or dynamically trace those functions.

## Verification
11 tests pass across parser and analyzer: literals/comments cannot generate fake
dispatch/call edges, Lua string escapes, byte-run offsets, bounded varint reads,
hash mismatch without publishing output, plus known snapshot counts/hashes.
