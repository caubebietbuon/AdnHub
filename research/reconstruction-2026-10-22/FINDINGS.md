# Phase 8: isolated backing reconstruction and candidate mapping

## Operation and scope

`tools/reconstructor.py` reads the hash-pinned g/d snapshot and validates Phase7
source anchors. It reconstructs the existing plaintext record664 and retains its
53,886 bytes unchanged. It applies the footer **only to an in-memory copy of the
backing ciphertext slice**. Applying it to plaintext would destroy the decoded
arrays and contradict the DW19 source operation.

No payload, factory4890, __index, opcode, vector constructor or network API runs.
Inputs are never modified. This does not establish an OS-enforced air gap.

```powershell
python tools/reconstructor.py --record-ids 664,1,2
python -m unittest discover -s tools -p "test_*.py" -v
```

## Functions and outputs

1. `record_probe` checks directory/length bounds. Only reviewed root664 is
   accepted for reconstruction; other IDs receive explicit comparison statuses.
2. `apply_fill_copy` checks integer arguments, value range and destination bounds,
   then fills a copy. Slice [41177,95046) receives byte0xdd. The directive covers
   53,869 bytes; 53,668 actually differ from their original values.
3. `observation_span` establishes exact primitive/raw-string input dependencies.
   Unknown compound extents remain unknown.
4. `materialize_candidates` compares pre/post-fill observations, excludes known
   overwritten dependencies, and exports candidate values with wrapper/index
   references. It never merges decoded values into an invented binary schema.
5. `run` validates all output destinations against input paths before writing.
   `reconstruction.json` lists artifacts belonging to the current run.

Generated files under ignored `output/phase8/`:

| File | Meaning |
|---|---|
| record-664.transformed.bin | Preserved decrypted record; not fully deobfuscated bytecode |
| record-664.backing-postfill.bin | Full backing slice with the isolated fill applied |
| record-664.streams.json | All four raw numeric arrays, preserved in order |
| record-664.mapping.json | Candidate constants, wrapper-index uses, cache boundary and unresolved references |
| reconstruction.json | Hashes, fill coverage, record statuses and artifact manifest |

The transformed SHA256 remains
`662f0f35fe18e7a992c0f0db81f186c4dd314b6e0c346c779153782b178901d3`.
Post-fill backing SHA256:
`969c1df78c95963fbd1751de7c4eb882f69d9fc190d689fb7afa4b660e279f60`.

## Mapping results and limits

The four arrays contain 584 distinct IDs within directory-index bounds. Of those,
503 also have an in-bounds backing offset (Phase7's narrower population). The
remaining 81 have opaque out-of-slice directory values and are not dereferenced.

All 281 primitive observations survive the fill unchanged and have known input
ranges outside the filled region: 279 number candidates and 2 boolean candidates.
Their kinds are compatible with Lua number/boolean value categories. These custom
tag predicates are **not standard Luau serialized constant tags**; native bytecode
validity and runtime use have not been demonstrated. Source-defined floating
nonfinite values, if encountered, retain raw bytes and a textual JSON value.

303 IDs remain unresolved, including opaque directory values, compound readers,
constructor boundaries and the rejected raw-string length from Phase7. No valid
string candidate is recovered by the currently implemented readers in this root.
No reachable child-prototype hierarchy is verified; the hierarchy field is null,
not an assertion that there are zero child functions. Recursive function-reference
tags remain explicit boundaries and are never constructed.

The initial shared -2 cache remains empty. Primitive observations from a separate
Python survey were never actual Lua cache entries. Numeric lazy leaves store
individual wrapper slots; the shared cache has separate string/buffer paths.
The tool therefore exports an **analysis candidate index** and wrapper uses,
without fabricating runtime cache contents, access order or a complete eager
constant table. Fully materialized status remains false.

## Comparison records

- ID1: claimed length1,477,608 exceeds backing bounds; rejected before decryption.
- ID2: assumed v/aux91 probe yields8 bytes and format85. It is explicitly unvalidated
  and not reconstructed, filled or parsed using the root schema.
- Other IDs also require independent source-backed validation; valid length or
  format alone never authorizes the root664 interpretation.

## Verification and next work

Tests cover copy isolation and fill bounds, overwritten-value invalidation,
candidate deduplication versus per-wrapper uses, cache separation, unknown-hash
rejection, unsupported IDs and the actual pinned snapshot. Payload/runtime checks
are separate and have not been performed.

All 53 Python tests passed (47 existing plus 6 new). Lua syntax checks for
AdnHub.lua/Loader.lua and `git diff --check` passed. This phase is committed
locally without pushing, honoring the current no-network requirement.

Complete strings/prototypes still require reviewed translations of compound
length/mask readers and source-proven consumer edges. No fill or concatenation of
the recovered scalar values can manufacture that missing serialization schema.
