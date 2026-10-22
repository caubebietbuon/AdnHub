# Phase 20: inter-block lineage and root107 scope obligations

Base: local commit `20bff5d`. All analysis is offline Python over pinned source
and data; no Lua, payload, application, factory or network execution. Demo/ESP
files are untouched. This phase does not claim complete decompilation.

## Reproduce

```powershell
python tools/interblock_auditor.py
python -m unittest discover -s tools -p 'test_*.py'
luac -p AdnHub.lua Loader.lua
git diff --check
```

`output/phase20/interblock-proofs.json` is ignored. The tracked `summary.json`
retains compact results. The tool rebuilds backing and arrays from pinned
inputs and validates the source contracts and precise978..981 window.

## Inter-block lineage

`recorded_blocks` segments the abstract prefix by trace order, variant changes
and non-sequential transitions. Repeated PCs retain separate occurrences.
`interblock_slice` annotates the SSA dependency graph with segment IDs and
cross-segment dependencies, preserving pre-event values for parallel copies.
It traverses the complete recorded prefix, rather than stopping atPC9910 or
sorting PCs numerically. Unknown writes kill earlier numeric definitions.

At rootPC9910, variant163/op109 transfers `r8 <- r30`, `r9 <- r35` in parallel.
Backward tracing before that event, across all recorded predecessor segments,
finds no reaching definition of r35. The reviewed fresh-frame entry is absent
(nil), not numeric zero. The argument prologue at9942 does not assign r35.
This conclusion belongs to the recorded prefix, not the unvisited PC980.

`snapshot_lineage` additionally scans the whole fixed snapshot for reviewed
predecessors, then walks the `(PC-before-instruction, register)` product graph.
It traverses literal jumps and copies across blocks, stops on unreviewed
transfers or arithmetic definitions, and bounds cyclic searches. Normal patch
completion and selected branch predicates remain explicit guards. Missing
predecessor edges are open-world boundaries, never initialized values.
Post-prefix instructions differ from earlier observed versions; candidates
cannot replace entry-path proof without rewrite history. No numeric value of
r9 at980 is promoted. The summary retains the exact predecessor endpoints.
The current variant163 snapshot search visits seven states, preserves r35
through9909..9904, and reaches an open predecessor frontier at9904. The recorded
path covers the variant transition separately; the fixed-snapshot graph does
not prove that unknown incoming handlers or future rewrites are absent.

## Shared-V constraints and the stronger reader obstruction

Source-validated window under variant228:

| PC | Normal-path constraint |
| --- | --- |
| 978 | reference101 key `53 XOR mix(V)` and directory reader completion |
| 979 | numeric `r88 < 66` falls through to980; otherwise113 |
| 980 | numeric bit32 conversion of r9, then `r13 = bxor(r9,38)` |
| 981 | reference74 key `4 XOR mix(V)` and reader completion |

No V assignment occurs within this window. Under the same uint32 V and byte-key
contracts, the exact inverse yields2048 V states and256 pairs, with
`k74 = k101 XOR49`. Numeric constraints are satisfiable in isolation:

| V | r88 | r9 | r13 | key101 | key74 |
| --- | --- | --- | --- | --- | --- |
| 0 | 0 | 0 | 38 | 53 | 4 |
| 3758096639 | 0 | 0 | 38 | 205 | 252 |

These are conditional SAT witnesses, **not** defaults fed into an interpreter
or inferred reaching assignments. The tool separates `numeric_models` from
`local_models`, which additionally require a bounded length-prefixed payload.
Neither field proves tag/cache activation, reachability or patch74 validity.

Reference101 has directory value134543. XOR306486104 gives306616023, outside
backing length152177. Even a hypothetical previous directory toggle would only
return the reader to134543. A fresh check of the post-fill backing at134543
fails `read_length_payload`: the declared length exceeds the backing/allocation
limit. A directory-only repair is insufficient under this unchanged backing
and length-reader contract.

For a validated target p, a necessary directory precondition would be
`D101_before = p XOR306486104`, plus tag/cache/length and reaching-register
conditions. Synthetic tests prove local witnesses for bounded payloads; none
is promoted for the actual134543 target. Wider word-mask layers, future backing
mutations, different incoming paths and other payload positions remain open.

## Root107 cluster: scoped stability, not lifetime promotion

| Child | Construction PC | Descriptor | root107 capture | Last direct value | Later recorded direct writes |
| --- | --- | --- | --- | --- | --- |
| 567 | 8390 | 486 | ordinal1 | 0 | none |
| 258 | 8391 | 486 | ordinal1 | 0 | none |
| 379 | 8393 | 462 | ordinal1 | 0 | none |

All three use cell `frame:664:register:107`; this does not freeze its value.
The guarded construction-to-frontier intervals have no direct root-register
writes to107. Child567's hypothetical entry reads capture1 atPC23; this is not
an invocation witness. All three child traces stop before full effect coverage.

There is also a concrete body alias: closure663's capture1 references root159,
whose frontier value is symbolic closure379. A lifetime audit must include this
holder and its effects. This is a scoped captured alias, not evidence of an
actual external escape or a proven write by663.

The root frontier remains the assert/debug call at8398, not proof of activation
of567/258/379. Invocation order, all alias/capture writer effects, close/rebinding
behavior and complete lifetime coverage remain unproved. `whole_lifetime_stable`
stays unknown. No verification rule is relaxed: `verified_hierarchy` stays null;
the formal promotion patch has `applicable=false, operations=[]`.

## Validation

Phase20 tests cover cross-block copies, repeated PCs, overlapping parallel
copies, unknown-write kills, branch predicates, bounded cyclic searches,
length rejection, independent numeric witnesses, direct-write instability,
captured body aliases and pinned integration. Final counts are recorded in
PROJECT_MEMORY.md. Lua syntax checks concern repository entry scripts only;
no Roblox or payload runtime check is performed. Final verification:167 Python
tests passed (155 prior +12 Phase20); Lua syntax, Python module compilation and
working/staged Git diff checks passed.
