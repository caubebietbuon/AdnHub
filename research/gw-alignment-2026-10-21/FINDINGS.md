# Phase 6 — GW alignment and custom virtual-function header

## Reproduce offline

```powershell
python tools/gw_aligner.py --record-ids 664
python tools/gw_aligner.py --record-ids 664,1,2
python -m unittest discover -s tools -p "test_*.py" -v
```

Reads the existing local, hash-pinned g/d files. No downloads, network APIs,
Lua compiler/runtime, application callback, virtual opcode or lazy decoder is
executed. The host's physical network configuration is not changed by this tool.

GW is a method name in g, not proof of a separate global-data memory buffer.
This phase reads the full transformed record through GW's numeric/table reader
logic. It does not treat the 64-byte prefix as a native Luau prototype header.

## Model and stopping boundary
- gw_aligner.py validates input hashes, source anchors and the two observed v
  callsites; follows lookup entries, transforms bytes, aligns reader results and
  records unresolved fields. Batch IDs are explicit and limited to four.
- gw_reader_model.py parses only a small numeric/table reader subset from44
  approved GW helper definitions. It is a bounded reader IR, not a general Lua
  interpreter. It models assignments, lexical scopes, multi-return, conditions
  and GW's control-state loop. No native/virtual instruction handler is loaded.
- Permitted primitive slots: readu8, readu32, table.create. setmetatable records
  metadata only. Any attempt to use a lazy __index or call an unknown function
  factory raises a boundary before that operation can run.
- v installs lazy metadata at w[6] before GW. The context represents that as an
  opaque, non-callable placeholder; it is not replaced with a working decoder.
- Reader limits:16M expression/statement steps,100000 read events,10000 tables,
 100000 entries/capacity per table. Buffer reads are bounds-checked.

The source field search can have later lexical false positives from named
application locals. The model uses the first reviewed definitions in the pinned
snapshot and parses only their function bodies. It must not be used unpinned as
a universal or safe interpreter for arbitrary source.

## Verified record664 header
Transform parameters remain ID664,aux91,seed243,mask0x5b5b5b5b. Full transformed
record length53886. The reader reaches factory4890 at g offset429293 and stops
BEFORE its call. That source factory contains the interpreter construction.
The model never constructs or invokes the returned executable closure.

An independent normalized format0 reader agrees with the source-reader IR on
all four stream counts/boundaries, entry PC, register size and final cursor.

| Field | Value / offset in transformed record |
| --- | --- |
| Custom format byte | 0 at0 |
| Dispatch variant | 157 at1..3 |
| Leading descriptor word count | 0 at3..7; upvalue meaning unverified |
| Function-factory slot | 4890 at7..9 |
| u32 seed/parameter word count | 2 at9..10 |
| Two u32 words |10..18; role is not an eager constant table |
| Unclassified scalar |0 at13270 |
| Register allocation capacity |181 at13271..13273 |
| Entry PC |9942 at53879..53881 |

Source role evidence is based on factory4890's effective formal bindings,
including duplicate formal parameter names. A is read as A[pc] inside the dispatch
loop; S is assigned to entry PC; h is passed to table.create through its captured
alias. The parameter binding is inspected, not executed.

| Stream | Source factory parameter | Slots | Values start | Values end |
| --- | --- | ---: | ---: | ---: |
| Raw stream1 | i |9963 |21 |13270 |
| Opcode-slot stream | A |9965 |13276 |26883 |
| Raw stream3 | H |9962 |26886 |39602 |
| Raw stream4 | w |9962 |39605 |53879 |

Each stream count is custom_uint minus source-defined bias20231. These are
custom virtual slot arrays;9965 is NOT a native Luau instruction-byte length or
a count of instructions that have executed. No opcode semantic mapping is done.
The streams have different lengths, so they must not be naively zipped into a
fixed-width native instruction array.

The reader covers bytes0..53881 contiguously and leaves5 trailing bytes unread.
Their purpose is unresolved; the tool does not silently drop them or claim full
record EOF validation. A complete virtual-function/record deserializer is not
yet established beyond this construction boundary.

## Constant / prototype / upvalue limits
Four wrappers j/O/Z/B contain metadata keys-1/-2 pointing to backing streams and
a shared cache, and carry the opaque lazy-reader metatable. Their positive-key
counts are zero at this pre-execution boundary. Their capacity hints are NOT
validated constant counts. No __index access is forced to materialize them.

No verified child-prototype count or fully classified upvalue list has been
recovered. The leading descriptor count0 must not be relabeled zero upvalues
without following its consumers. The loader's748 lookup entries are not748
proven prototypes; entries can represent other data/references.

No standard Lua signature was found. No universal Luau/Luraph prototype magic
is assumed. The validation achieved here is against this custom GW reader and
constructor, not a native Luau bytecode deserializer.

## Auxiliary and seed scope / batch results
Both syntactically identified v entry paths pass91: root sW and recursive aliasH.
Thus 0x5b5b5b5b is supported for those function-reader call paths in this snapshot.
Initial state is (record_id+91)%256, which depends on ID modulo256; it is not a
globally fixed243 nor necessarily unique across IDs. Other lookup entry kinds,
contexts and snapshots are not assigned auxiliary91 by assertion.

| Comparison ID | Result |
| --- | --- |
|664 | Source-aligned custom virtual-function constructor; blocked at4890 |
|1 | Assumed function-record length exceeds slice; not followed |
|2 | With the function-call-family auxiliary, format byte85 makes GW return after1/8 bytes; no validated function header |

IDs1/2 are explicit structural comparisons, not source-proven reachable child
prototypes. These failures prevent claiming successful generalization to every
lookup entry. The batch interface accepts additional selected IDs but preserves
per-entry unresolved results. No seed/aux brute-force search is performed.

## Outputs and tests
Local output/phase6/: gw-alignment.json, record-ID.transformed.bin and
record-ID.reader-data.json. Local reader-data contains raw streams and read events;
these dumps are ignored by Git. The committed alignment-summary.json keeps
counts, ranges, source offsets, boundaries and limitations, not complete streams.

41 tests pass: previous33 plus8 covering duplicate parameters/local scopes,
Lua truth0, buffer/step limits, denied factory and metatable calls, a synthetic
normalized layout, wrong hashes and real-snapshot cross-checks. Existing Lua
files retain successful luac syntax checks; no Luau runtime test is claimed.

## Next steps
Trace the lazy __index tag readers against each backing stream and cache before
calling any value a decoded constant or prototype reference. Preserve source
offsets, type tags, record IDs, auxiliary arguments and exact cursor bounds.
Investigate the5 unread bytes and the leading descriptor consumers separately.
Any future decoder model must keep application factories/opcode dispatch blocked.
