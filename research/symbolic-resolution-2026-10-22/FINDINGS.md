# Phase 12: symbolic environment, mask domains and capture-owner checks

## Reproduce

```powershell
python tools/symbolic_resolver.py
python -m unittest discover -s tools -p "test_*.py" -v
```

Output: output/phase12/symbolic-resolution.json. All prerequisites are rebuilt
from the same hash-pinned g/d inputs, not stale output JSON. No Lua, dynamic
__index, factory, application call, network or original-file mutation runs.
Reviewed initialization operations are abstractly modeled in Python. There is
no claim of OS-enforced air-gap isolation and no remote push.

## Named unknown environment; no dummy defaults

Optional symbolic mode in prologue_analyzer.py now represents environment reads
as named unknowns. At PC9063, variant228/op111, register72 becomes
`{"symbol":"global.task"}`. This does not resolve the host's task API, fabricate
an empty table, set a boolean or schedule a callback.

The model passes9063 and reaches PC9251's unsupported fused call. Register
snapshots at9062/9063/9251 retain numeric values, unknowns and the task symbol.
For example, before9251 register126 is9250, register72 holds global.task, and
register57 is unresolved. The fused instruction's call operands are not all
known. No mock callback is invoked and no invented successful return is used to
continue. The new boundary is concrete evidence of an unresolved effect, not
proof that the real program cannot execute.

Symbolic mode also handles argument symbols, capture-cell symbols and selected
numeric/truthiness conditions. `explore` preserves alternative boolean constraints
instead of substituting a default. Unknown indirect jump targets remain stops.
The current child-record analysis emits37 bounded path/frontier summaries across
31 VM records, with two records reaching the four-path exploration cap. These
are over-approximations/frontiers, not37 proven feasible executions. Repeated
branch sites reuse a site constraint; loop completeness is not claimed.

Earlier normal-continuation assumptions remain visible, including opaque lazy
operands that have not been type-checked. An absent abstract value is unknown,
not evidence of Lua nil. Source equations derived after an assumed continuation
remain conditional.

## Cross-record byte-mask search

The tool analyzes all31 previous VM-record candidates and records the seven
native-factory declarations without invoking them. Dependencies on parent mask
hypotheses propagate into child evidence; they are not silently upgraded.

All29 unresolved strings are searched over all256 XOR bytes:7424 alternatives.
Hashes and UTF-8/printability indicators are saved for every key, along with the
intermediate bytes needed to reproduce it. Every unconditional key domain remains
256 values unless independent source evidence establishes a stronger result.

**Entropy cannot identify a single-byte XOR mask:** XOR permutes byte values and
preserves the histogram/entropy exactly. The length markers are outside this
payload mask. These string bodies do not have an established header/magic to
test as if they were function records. Binary Lua strings are valid, so filtering
only printable UTF-8 is insufficient.

Two evidence classes are preserved:

- Entry-trace equations: ten string IDs have masks from bounded, guarded child
  paths, including current state-word updates. IDs13,62,190,230,294,375,605,613,
  661,674 have conditional plaintexts. Examples: `Unit`, `offset`, `Abs`,
  `ToEulerAnglesYXZ`, `Magnitude`, `UpVector`, `lookAlong`.
- Initial-state-only site hypotheses: six IDs have candidate equations obtained
  by projecting the header's initial state onto patch sites. Five overlap the
  trace-derived set; ID119 has only this weaker evidence.

Thus11 IDs have some conditional equation, ten of them entry-traced;18 have none.
This does not mean all11 masks are verified. A concrete counterexample is ID13:
the initial-state projection gives key13 and control characters, whereas the
entry trace accounts for a state change and gives key76, decoding `Unit`.
Both results and guards are retained. ID119's projected text is also not promoted.

These conditional strings are not merged into the193-candidate Phase11 count as
unconditional recoveries. Remaining branch/ancestor assumptions are explicit.

## Capture-owner candidates and additional nodes

Four exact factory-text closure-consumer families are indexed:

| Dispatch variant | Opcode array / opcode | Function wrapper | Descriptor wrapper |
|---|---|---|---|
|157|raw O /132|B|Z|
|163|raw j /38|Z|B|
|228|raw B /82|Z|O|
|82|raw j /78|Z|B|

The tool checks the target tag, descriptor identity and exact descriptor parse.
Local register/span captures are checked against the owner's capacity. Enclosing
capture indices remain unvalidated unless their enclosing capture capacity is
known; local register overlap alone does not establish ownership.

The resulting source-consumer candidates are:

| Parent candidate | Child candidate | PC | Variant guard | Descriptor | Captures |
|---:|---:|---:|---:|---:|---:|
|664|506|9554|228|251|7|
|137|747|33|163|58|0|
|237|572|257|163|181|5|
|704|288|10|163|299|11|

IDs506 and572 were not in the previous38-target list. Header-constrained data
reading yields an additional format0/factory4890 candidate for506 and a
format2/factory4916 candidate for572. Their masks are still hypotheses and their
factories remain uninvoked. This expands the structural candidate inventory to
40 function targets, not40 fully verified functions.

Candidate variant/PC associations are guards: each record can rewrite arrays and
switch dispatchers. Merely finding an opcode number does not prove that the
associated handler runs at that site. No complete capture-owner map is asserted.

## Proof-gated tree construction

`validate_tree` requires all of the following per edge: verified source consumer,
exact descriptor parse, valid capture indices, verified child header, verified
control flow and unconditional ancestry. It also rejects missing nodes, unknown
nodes, multiple parents and cycles, and requires root reachability for all
expected nodes. Tests demonstrate acceptance of a fully proven synthetic tree
and rejection when only register overlap is supplied.

Current data fails these obligations. The report retains candidate edges and
specific validation issues; verified_hierarchy remains null. Setting it non-null
would be an unsupported claim, not successful reconstruction. A function-reference
graph may also contain shared or recursive relationships and must not be forced
into a tree without lexical-ownership evidence.

## Remaining work

The unresolved9251 call must be modeled with proven operands/effects or analyzed
across all relevant possibilities. Additional dispatch handlers, path feasibility,
parent mask proofs and enclosing capture bounds are needed. Eighteen string masks
have no source equation; the other conditional equations still need their guards
discharged. No1:1 functional script or complete decompilation is claimed.

Validation: all83 Python tests passed (76 existing plus7 new), including symbolic
environment handling, alternative branch constraints, complete mask enumeration,
proof-gated tree acceptance/rejection and the pinned snapshot. Lua syntax checks
for AdnHub.lua/Loader.lua and `git diff --check` passed. No runtime test or push.
