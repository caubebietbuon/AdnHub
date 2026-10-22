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

## Phase 7 lazy tags and footer

```powershell
python tools/lazy_tracer.py --sample-limit 748
```

Maps the four wrappers' -1 backing streams / -2 shared cache from factory4890;
translates only reviewed tag predicates and bounded primitive/raw-string readers
to Python. No Lua, __index, factory, vector constructor, opcode or buffer write
is invoked. Default cap64; cap748 covers503 potential references in root664.
Potential references are not proven runtime constants or reachable prototypes.
Leading descriptor count0 remains semantically unresolved. The5-byte footer is
a source-buffer fill directive (offset5,length53869,byte0xdd), reported without
applying it. See research/lazy-analysis-2026-10-21/FINDINGS.md. Full local output
is ignored output/phase7/lazy-analysis.json. No network API is used; OS air-gap
enforcement is outside this tool.

## Phase 8 backing reconstruction and candidate mapping

```powershell
python tools/reconstructor.py --record-ids 664,1,2
```

Applies the footer to a copy of the backing ciphertext slice, preserving the
transformed plaintext and both inputs. Exports raw arrays, before/after data
observations, 281 unchanged number/boolean candidates and their wrapper-index
uses. Unknown readers, strings and child hierarchy remain explicit unresolved
metadata; no runtime cache or complete native bytecode stream is fabricated.
ID1 fails bounds; ID2 remains an unvalidated format85 comparison. No payload,
factory, __index, opcode or network API runs. See research/reconstruction-2026-10-22/
FINDINGS.md; generated artifacts stay ignored in output/phase8.

## Phase 9 string resolution

```powershell
python tools/string_resolver.py
```

Source-pinned Python translations of length-prefixed shared-cache string readers;
172 candidates decoded losslessly (3836bytes). Exports hex, strict UTF-8 views,
hashes and wrapper-index uses in output/phase9/string-resolution.json. Leaf95/
tag219 is corrected to an encoded descriptor branch;32 headers decoded, bodies
unresolved.99 references remain unsupported/opaque/rejected. No direct recursive-v
candidate edges observed for root664; verified prototype hierarchy remains null.
No factory/__index/Lua/opcode/network calls or input writes. See
research/string-resolution-2026-10-22/FINDINGS.md for algorithms and limitations.

## Phase 10 descriptor bodies and static synthesis

```powershell
python tools/prototype_mapper.py
```

Rebuilds pinned Phase8/9 data locally; parses all32 descriptor bodies exactly
(163 captures). Source directory XOR306486104 gives conditional offsets for81
opaque referenced IDs:34 function targets and47 string targets. Additional
payload masks/reachability/lexical ownership remain unresolved; these are guarded
references, not a verified child hierarchy. Unified output/phase10/static-synthesis.json
contains281 primitives,172 strings, wrapper uses, captures, register capacity181,
entryPC9942 and link provenance. Factory/__index/opcodes remain unexecuted; no
network/input mutation. See research/prototype-synthesis-2026-10-22/FINDINGS.md.

## Phase 11 payload masks and restricted initialization model

```powershell
python tools/payload_decoder.py
```

Uses prologue_analyzer.py for bounded numeric initialization abstraction across
variants157/163/228.236 abstract steps yield38 conditional mask equations; stop
at PC9063 task-global environment dependency. Outputs38 structurally consistent function
candidates (17 source equations/21 header hypotheses),21 new string candidates
(193combined) and29 unresolved string masks. Record1 is uint32; Record2 is
EnumType string, not format85 function data. No factory/__index/application calls
or network. Hierarchy remains null. See research/payload-masks-2026-10-22/FINDINGS.md
for normal-continuation assumptions and limitations. Full output stays ignored
in output/phase11/payload-analysis.json.

## Phase 12 symbolic environment and ownership validation

```powershell
python tools/symbolic_resolver.py
```

Uses named environment symbols, not dummy defaults: passes task read9063, stops
at9251 in its historical mode (Phase13 corrected this to a field lookup, not a
fused call). Analyzes31 VM records/7 native declarations with
bounded branch constraints. Exhaustive7424 XOR candidates for29 strings; ten
strings have entry-trace equations, one further initial-state-only hypothesis,
18noequations. All guards remain explicit; entropy/printability not key proof.
Four capture-owner candidate edges and two new structural function targets506/572.
Tree validator checks source/path/capture/header/ancestry evidence and graph
coverage; current verified_hierarchy staysnull. No Lua/API/factory/network calls.
See research/symbolic-resolution-2026-10-22/FINDINGS.md and ignored
output/phase12/symbolic-resolution.json.

## Phase 13 / 14: exact dispatcher and proof obligations

```powershell
python tools/fused_call_analyzer.py
python tools/obligation_resolver.py
```

Phase13 proves PC9251 reads task.cancel, models guarded closure captures and
derives the exact mask mixer inverse. Phase14 follows source-checked transfers
to real fused call8398, where context-slot109 aliases assert with debug as its
first argument. It does not execute that call or assume its success.
All31 VM candidate entries are bounded hypothetical analyses; ID192 gains the
guarded key5/rawlen equation at711:938. Seventeen other IDs lack reached trace
equations; all18 unconditional keys remainnull. The six prototype verification
rules and complete-coverage gate remain unchanged; verified_hierarchy=null.
See research/obligation-audit-2026-10-22/FINDINGS.md for the candidate137 nil/XOR
contradiction, capture-frame maps, remaining guards and reproduction commands.
Detailed output/phase14/obligation-resolution.json stays ignored. No payload,
factory, __index, application or network execution; demo/ESP work stays paused.

## Phase 15: backward slices, independent decoders and diagnostic matrix

```powershell
python tools/layer_decomposer.py
```

Builds trace-order SSA with register_slicer.py. Reconstructs literal/copy/XOR/
addition/state dependencies, preserves unknown writes and capture addresses.
Separates14 potential core equations for17 pending IDs from activation/cache
predicates. Nine direct keys produce unfiltered bytes; five mixer equations
retain unknown site state. No frontier-to-unvisited-PC substitution.
Outputs six scoped diagnostic columns for8 prototype pairs and typed proxy
routes through lazy wrappers, cache lookups and constructor instances. The
historical validator is unchanged; verified_hierarchy remainsnull. Full output
is ignored in output/phase15; tracked matrix and findings are under
research/layer-decomposition-2026-10-22. No payload or network execution.

## Phase 16: static table promotion and proxy proof admission

```powershell
python tools/promotion_auditor.py
```

Regenerates Phase15 and checks the tracked diagnostic Markdown against fresh
evidence. Nine direct equations populate a site-indexed static string table;
activation predicates and competing ID203 outputs remain distinct. Five state
certificates expose missing reaching definitions. Eight proxy proofs retain
explicit premises; no edge currently qualifies for the unchanged validator.
Outputs stay ignored under output/phase16. See
research/promotion-proofs-2026-10-22/FINDINGS.md. No payload/network execution.

## Phase 17: local symbolic paths and capture scopes

Run `python tools/scope_tracer.py`. Rebuilds exported post-prefix arrays and
checks the five candidate site equations against their current slots. Four
mismatch this code version; root981 retains an opaque predecessor. Local
numeric/state paths remain guarded and bounded. Audits eight capture bindings
and31 prefixes against known environment shapes without inferring ancestry
from capacity. See research/scope-tracing-2026-10-22/FINDINGS.md. No payload or
network execution; outputs remain ignored under output/phase17.

## Phase 18: dispatcher fallback and closure567 proof

Run `python tools/predecessor_auditor.py`. Source predicates classify root980
opcode14842 as the variant228 XOR fallback: r13=bxor(r9,38);197 is excluded.
Rechecks all five equation signatures and same-reference candidate locations.
Four mismatches have no justified relocation in the current exported code.
Closure567's cell107 binding and prefix direct-write stability are verified
under guards; activation/lifetime and hierarchy remain unproved. See
research/predecessor-audit-2026-10-22/FINDINGS.md; output/phase18 stays ignored.

## Phase 19: numeric lineage and activation/lifetime

Run `python tools/lineage_auditor.py`. Exports r9's prefix provenance, proves
the conditional relation k74=k101 XOR49, and checks the directory guard at978.
The unchanged directory fails that local path contract; no numeric default or
site V is invented. Audits567 creation, activation witnesses and shared cells
with258/379. Promotion remains non-applicable. See
research/lineage-audit-2026-10-22/FINDINGS.md; output/phase19 is ignored.

## Phase 20: inter-block lineage and root107 cluster

Run `python tools/interblock_auditor.py`. Combines trace-order SSA with a bounded
snapshot predecessor worklist, separates numeric shared-V guard witnesses from
reader/activation guards, and checks the root107 construction intervals and
captured body aliases for567/258/379. Directory-only repair at134543 also fails
the length reader. No numeric input or lifetime promotion is invented. See
research/interblock-audit-2026-10-22/FINDINGS.md and summary.json. Rebuilt output
is ignored under output/phase20; hierarchy remains null.

## Phase 21: typed prefix diagnosis and closure663 scope

Run `python tools/reader_scope_auditor.py`. Corrects the reader selection at
offset134543: tag195 is uint8/reference101/value4, not a damaged string length.
Exports raw patch-length rejection separately, directory parity, source-proven
prefix exclusion from payload XOR, and a bounded copy-only payload patch model.
Audits root664 construction intervals, the663-to379 captured body alias and
close-cell storage semantics. No byte repair, state key or hierarchy promotion
is claimed without provenance. See research/reader-scope-audit-2026-10-22/
FINDINGS.md and summary.json; full generated evidence stays in output/phase21.

## Phase 22: adjacent schemas and predicate constraints

Run `python tools/schema_constraint_auditor.py`. Maps directory-backed typed
spans around134543 and proves the forced prefix crosses reference101/251.
tools/predicate_solver.py narrows exact mixer domains using reviewed local
predicate/register dependencies; unrelated or inexact expressions stay unknown.
All five real domains remain2048 candidates; four sites lack current equation
identity. Explicit activation/lifetime/tree gates reject promotion for the
closure663 cluster. See research/schema-constraints-2026-10-22/FINDINGS.md and
summary.json; generated output/phase22 remains ignored.

## Phase 23: code/data boundaries and scope-exit contracts

Run `python tools/boundary_auditor.py`. Optional watched-slot logging in
prologue_analyzer/obligation_resolver anchors exact normalization revisions.
All four mismatches are initial-version patterns overwritten on recorded
prefixes; current-model boundary rejection is separated from algebraic keys.
An opt-in source transfer models228/75 capture reads symbolically, extending
663 to546 and379 to1852. Return99/tailcall102 are exit candidates, not lifetime
witnesses. No state or hierarchy promotion. See
research/boundary-audit-2026-10-22/FINDINGS.md and summary.json; full evidence
is ignored under output/phase23. Earlier tool defaults remain unchanged.

## Phase 24: epoch alignment and arithmetic checkpoints

Run `python tools/checkpoint_aligner.py`. Epoch alignment retains root981's
current equation and retires four packed initial patterns from current-domain
accounting. Checked primitive reads and opt-in228/97/98/140 arithmetic prove
663's206490123 argument and further379/258 constants. A parallel fused-call4
summary stops663 at547 without invoking capture1; the379 target is conditional
on root159 lifetime/cache identity. No key or hierarchy promotion is inferred.
See research/checkpoint-alignment-2026-10-22/FINDINGS.md and summary.json;
full generated evidence is ignored under output/phase24. Older defaults stay
unchanged; obligation_resolver accepts an optional context-bound transfer factory.
