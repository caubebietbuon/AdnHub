# Phase 22: directory-backed schemas and predicate constraints

Base `31aabac`; pinned g/d input hashes are preserved in summary.json. The tools
perform offline Python text/data analysis only. No Lua, payload, factory,
__index, application call, network access or input edits are performed.

```powershell
python tools/schema_constraint_auditor.py
python -m unittest discover -s tools -p 'test_*.py'
luac -p AdnHub.lua Loader.lua
git diff --check
```

The full generated report is ignored at output/phase22/schema-constraints.json.
This directory retains compact evidence and the remaining proof obligations.

## Schema remapping and adjacent alignment

The mapper follows directory-backed starts under explicitly labeled XOR parity
hypotheses. It does not scan every byte for plausible tags or assume all chunks
have lengths. Within32 bytes of134543 it finds nine directory-backed records:

| Reference | Position | Reader family | End, exclusive | Directory parity |
| --- | --- | --- | --- | --- |
| 483 | 134512 | encoded string | 134526 | XOR hypothesis |
| 21 | 134526 | encoded string | 134532 | exported |
| 691 | 134532 | unresolved fill reader | unknown | exported |
| 436 | 134538 | uint32 | 134543 | exported |
| 101 | 134543 | uint8, value4 | 134545 | exported |
| 251 | 134545 | encoded descriptor | 134562 | exported |
| 36 | 134562 | negative uint8 | 134564 | exported |
| 275 | 134564 | encoded string | 134571 | exported |
| 713 | 134571 | encoded string | 134581 | exported |

Each end is computed from its reviewed reader, not inferred from the next
directory entry. Reference691's unknown shape deliberately stays unknown.
Adjacency is established for436→101→251→36→275→713 on exported offsets; it is
not a global packing or runtime-activation proof.

Reference251 has tag219, a one-byte length15, and15 encrypted payload bytes.
Aux83 decoding followed by the existing exact descriptor parser consumes all15
bytes and produces seven capture entries. This does not identify its lexical
owner or change any prototype proof.

The rejected raw length prefix at134544..134547 spans two records:

```text
134543: c3       tag195, uint8 reference101
134544: b4       reference101 ciphertext; decoded uint8 is4
134545: db       tag219, descriptor reference251
134546: 0f       descriptor payload length15
134547..134562   descriptor payload
```

Interpreting `b4 db 0f` as one integer mixes a primitive payload with the next
record's tag and length. The mapper records these intersections explicitly.
There is no length corruption assumption and no byte correction.

## Alternative solver: predicate-constrained finite state domains

tools/predicate_solver.py scans the complete fixed snapshot for reviewed normal
successors, then enumerates bounded predecessor paths. It preserves strict
branch172 and reviewed <= branches, state assignments, literal/copy/add
provenance and the exact uint32 mask inverse. Patches introduce an explicit
normal-reader-completion guard; they are not forced through failed reads.

The solver intersects the2048-state mixer-local domain with predicates whose
inputs can be derived from a unit-affine register/state expression. Unrelated
inputs, non-unit inverses with possible fractional registers, unknown effects
and arithmetic outside the exact-number range remain residual obligations.
Large intermediate additions cannot become proofs through algebraic cancellation.
Cycle cuts, depth/path limits and unknown incoming edges remain explicit.

Positive synthetic tests isolate V=7 from6<r10<=7, or from3<r10<=4 andV=r10+3.
These prove the solver can narrow a domain when a dependency exists. Conditional
uniqueness is never labeled actual activation or an unconditional runtime state.

Real findings:

| Owner | Site | Current equation identity | Local domain |
| --- | --- | --- | --- |
| 664 | 981 | matches V/reference74/operand4 | 2048 candidates |
| 402 | 83 | mismatched rewritten slot | 2048 hypothetical candidates |
| 711 | 269 | mismatched rewritten slot | 2048 hypothetical candidates |
| 593 | 393 | mismatched rewritten slot | 2048 hypothetical candidates |
| 379 | 686 | mismatched rewritten slot | 2048 hypothetical candidates |

For the root site the reviewed predecessor path is976→977→978→979→980→981.
Strict predicates are `r123<120` at976 and `r88<66` at979. Numeric XOR operands
at977 and980 also need proof. No reviewed def-use connection from those predicate
inputs to V exists on this local path, so neither branch narrows its V domain.
Normal patch978 completion remains an unmet data guard from Phase21.

For the other four hypotheses, no reviewed predecessor reaches the old site
within this snapshot graph, and the site is not the expected patch instruction.
No key is promoted. These are necessary local candidates, not2048 witnessed
runtime states or a complete whole-program domain. Other handlers, future
rewrites and different activation contexts remain open.

## Precise activation and lifetime conditions

The new promotion gate is conjunctive and accepts explicit booleans/UNKNOWN,
never truthy substitutes. It retains all six existing structural criteria and
adds explicit ledgers for:

- Activation: reachable call, exact callee, valid arguments, captured cells at
  call, live template/cache identity and normal constructor continuation.
- Lifetime: defined frame slots, cell-creation order, all alias writes,
  accounted-for call-time values, close/rebind paths, storage identity and
  escape effects.
- Global tree: unique owner, complete node coverage and cycle checks on verified
  edges.

Prior root-frame slot definitions are observed for all captures in this cluster.
That fact does not prove the allocation order of the shared cell wrappers or a
future call. The stored root107/root159 frontier values are not frozen into
later activations. Captured values may legally mutate: their effects must be
accounted for while preserving the proven binding/storage contract.

The guarded scope graph remains663→cell159→body379→cell107 shared with567/258.
Activation, all alias effects, cell close/rebind coverage and global ownership
remain unproved. The gate rejects promotion for all four closures;
verified_hierarchy remains null and the formal patch has no operations.

## Validation

New tests exercise exact positive and negative constraints, independent inputs,
affine propagation, floating-point/fractional-register traps, strict branches,
cycle boundaries, schema spans, descriptor alignment, proof gating and pinned
integration. Full regression counts are recorded in PROJECT_MEMORY.md. Lua
syntax checks concern repository entry scripts; no Roblox runtime test is run.
Final result:195 Python tests passed (181 prior +14 new), including pinned
integration. Lua syntax, Python module compilation and Git diff checks passed.
