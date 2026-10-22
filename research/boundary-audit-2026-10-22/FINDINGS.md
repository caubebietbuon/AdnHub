# Phase 23: code-version boundaries and scope exits

Base `8b75233`. This phase analyzes pinned text, bytes and restricted symbolic
prefixes offline. No Lua, factory, __index, application call, payload execution,
network request or input-byte edit occurs. Demo/ESP files are unchanged.

```powershell
python tools/boundary_auditor.py
python -m unittest discover -s tools -p 'test_*.py'
luac -p AdnHub.lua Loader.lua
git diff --check
```

Full evidence is regenerated under ignored output/phase23/boundary-proofs.json.
The tracked summary retains scoped counts, revisions and lifetime obligations.

## Strict boundaries: reject a model without inventing a key

`constrain_boundaries` keeps the finite mixer domain separate from code/data
applicability. Boundary observations require explicit boolean/UNKNOWN values
and a declared scope. False rejects that conditional model; UNKNOWN cannot
select a state. Global reachability and unconditional state remain unproved.

All five algebraic hypotheses still have2048 mixer-local states. Their
admissible counts in the declared current models are now zero:

- Root664/981: the local normal path passes patch978, whose bounded reader
  fails with the unchanged reconstructed backing and exported directory101.
- The other four: the current normalized instruction is not the hypothesized
  patch equation. The independent rewrite history below explains why.

Zero admissible states **in those models** is not a zero-element global key
domain, a solved key, or proof excluding future code/directory histories. No
state or string key is promoted. Entry/cutpoint/code epochs remain unproved.

## Four instruction mismatches explained by recorded normalization

The prologue analyzer now optionally watches selected code slots. It logs every
changed array field with its before/after values, source instruction, trace
step and state words. The report also exports independent initial slot anchors
from decoded input arrays. `slot_revisions` reverses the writes, checks the
initial anchor, replays per-event revisions atomically, and checks final arrays.
Intermediate partial multi-array writes are never treated as instruction visits.

| Owner/site | Initial tuple under hypothesis dispatcher | Rewrite source PC/opcode | Normalized tuple |
| --- | --- | --- | --- |
| 402/83, variant163 | (84,74,7,42) | 210/op57 | (0,53,51,91) |
| 711/269, variant163 | (96,141,2,17) | 16/op57 | (54,130,122,74) |
| 593/393, variant157 | (11,141,121,38) | 590/op197 | (0,254,0,32) |
| 379/686, variant228 | (125,702,52,56) | 2106/op33 | (2,645,40,99) |

All four initial tuples match the old equation pattern. A recorded rewrite
changes each before any observed visit to its selected slot. No same-reference
patch appears in the final arrays across the three reviewed dispatchers.
The mismatches are therefore explained as initial-version patterns invalidated
on the recorded normalized prefix. They are not established current patches
requiring a guessed PC relocation. Future rewrites or different activations
remain open; this is not an unconditional whole-program refutation.

Root981 shows the opposite evolution: six recorded revisions create the current
matching tuple (125,74,4,47), with the final change at root9792/op197, trace
step274. Its current equation identity is valid under the snapshot guard;
normal entry-to-site and data-reader completion still need proof.

Watching is observational: default output/behavior remains unchanged, and the
tests compare watched and ordinary arrays/traces. Reusing exported watched
arrays strips logging contexts. Invalid indices, mixed bool/int indices,
missing anchor changes and inconsistent after-values are tested.

## Newly modeled capture reader and refined frame frontiers

Pinned source shows variant228/op75 is:

```text
T = enclosing_captures[i[PC]]
registers[H[PC]] = T[6][T[5]]
```

The Phase23-only transfer writes a symbolic capture-value expression, never
dereferences a real cell, and retains an explicit normal-read assumption.
Backward slicing records its ordinal without assigning a numeric value.

| Frame | Additional symbolic reads | Previous frontier | New frontier |
| --- | --- | --- | --- |
| 663 | PC544: capture1 → r4, guarded binding root159 | 544 | 546/op98 |
| 379 | PC1849: capture2 → r15/root106; PC1850: capture1 → r16/root107 | 1849 | 1852/op97 |
| 567 | none added | 24 | 24/op83, variant163 |
| 258 | none added | 37 | 37/op97, variant228 |
| 664 | none added | 8398 | 8398/op93, variant228 |

The663/root159 binding is the same captured-body alias to379 recorded earlier,
but its invocation-time value is not frozen to that frontier observation.
No actual invocation is inferred from a symbolic capture read. The new blockers
require arithmetic/value provenance before further normal continuation.

## Strict exit contracts and remaining lifetime proof

The audit recognizes source-reviewed variant228 exits:

- op99: close open cells/spans, then return the lazy constant O[PC].
- op102: close open cells/spans, then evaluate a tail call and packed arguments.

These are conditional source contracts, not executed returns. Scanning final
arrays for these opcodes produces candidates under a variant228/code-version
guard. It does not establish reachability, dominance or coverage of other
dispatchers, error unwinding, nonreturning calls or unknown handlers.

The close-cell transfer preserves cell identity while rebasing storage to
self/slot4; open spans similarly require their source copy/close order.
Storage rebasing is not destruction of all aliases. Neither the presence of
an exit instruction nor a right-censored register interval proves the lifetime
of root107/root159 across activation and exit.

All prior activation/lifetime/global-tree gates remain explicit. No complete
caller/callee proof, all-path scope exit, close/rebind ordering or alias-effect
coverage is established. `verified_hierarchy=null`; the formal promotion patch
has `applicable=false, operations=[]`. No six-criterion rule is relaxed.

## Validation

Twelve new tests cover observational logging, independent revision anchors,
tampered histories, scoped boundary rejection, unknown boundaries, symbolic
capture ordinals, guarded exit contracts and pinned integration. Full test
counts are recorded in PROJECT_MEMORY.md. Lua syntax checks concern repository
entry scripts only; no Roblox or payload runtime checks are performed.
Final verification:207 tests passed (195 prior +12 new); the latest12 also
passed after stricter index validation. Lua syntax, Python compilation and Git
diff checks passed.
