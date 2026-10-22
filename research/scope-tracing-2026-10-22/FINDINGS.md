# Phase 17: localized control flow and upvalue environments

All analysis is offline Python processing of pinned data. No Lua, payload,
factory, metatable or application is invoked. No network calls or demo/ESP edits.

## Reproduce

```powershell
python tools/scope_tracer.py
python -m unittest discover -s tools
luac -p AdnHub.lua Loader.lua
git diff --check
```

`scope_tracer.py` rebuilds Phase14 with an optional export of its post-prefix
instruction arrays. Default Phase14 outputs remain unchanged. The optional
arrays are temporary local data, not executable source. Detailed evidence is
written to ignored `output/phase17/scope-traces.json`; summary.json here preserves
the results. Input files are unchanged.

## Five symbolic site checks

The analyzer scans the exported snapshot for reviewed predecessor edges,
including incoming jumps outside a site's lexical neighborhood. Backward paths
are bounded to12 instructions/32 candidates by default. Only reviewed literal,
copy, exact-addition, state-read/write and numeric-branch transfers are modeled.
Unknown instructions and indirect unresolved control flow are barriers, never
assumed fall-through. Local entry state remains symbolic. Impossible concrete
numeric branches are pruned; unknown predicates are recorded, not forced true.

Each local path is conditional on arrival at its cutpoint, the assumed dispatcher
and stable code slots. It does not prove function-entry reachability. Paths can
derive a constant state from local literal assignments in unit tests, but never
from another frontier's value. The actual site equation is checked against the
exported code before any candidate key is accepted.

| ID | Owner / PC | Equation matches current slot? | Result |
| --- | --- | --- | --- |
| 74 | 664 /981 | yes | predecessor980 has opcode14842, outside reviewed transfers; V remains symbolic |
| 74 | 402 /83 | no | original potential equation is stale in this post-prefix snapshot |
| 141 | 711 /269 | no | same code-version obligation |
| 141 | 593 /393 | no | same code-version obligation |
| 702 | 379 /686 | no | same code-version obligation |

All five bounded local paths currently terminate at the site itself: no reviewed
predecessor route reaches them in the assumed dispatcher. This does not prove
unreachability in the program: indirect jumps and future rewrites remain open.
The four mismatches refute the old equations only for this exported version.
They are not permanent invalidation of the reference IDs.

No final constant key is derived. The immediate blocker is partly instruction
normalization/code-version provenance, rather than simply a missing scalar seed.
The JSON includes expected equations, actual operands, predecessor instructions,
symbolic inputs and explicit assumptions. `verified_hierarchy` remains null.

## Upvalue scope and extended environment search

Bindings use descriptor ordinals separately from register indexes. Kind3 binds
a frame/register cell; kind0 copies a register value; kind2 binds a span; kind1
forwards a parent environment entry with explicit one-based bounds. A known
parent environment preserves the exact cell identity through forwarding.
An unknown environment remains unresolved; it is never reconstructed by using
the capture index as a same-numbered local register.

Eight proposed/source-observed pairs are audited. Root bindings567/258/379/663
provide known guarded environment capacities2/2/6/2. Original parent237 and704
still lack the incoming environment bounds needed for capture ordinals8..10
and1..9. Zero reported bounds errors does not imply these unknown scopes pass.

Concrete new def-use evidence: function567's recorded PC23 reads capture ordinal1
as a cell value. Descriptor486 maps that ordinal to `frame:664:register:107`.
The root frontier value of this cell is0. Value stability until a hypothetical
child activation is unproved, so the analyzer does not replace the child read
with literal0 or derive a mask from it.

The extended search audits observed capture consumers across31 VM function
prefixes against the four known guarded environment shapes. It emits PASS/FAIL/
UNKNOWN capacity compatibility per environment. No observed read is not proof
that a function has zero upvalues; compatible capacity is not lexical ownership.
All31 rows retain `new_parent_edge=null` and an incomplete-read-set flag.

No candidate has unconditional activation, capture lifetime, unique parent and
complete coverage proof. No hierarchy edge is promoted. This preserves the
existing verification rules while exposing the missing scope evidence.

## Verification

142 Python tests (133 previous +9 new), Lua syntax and Git diff checks pass.
Tests cover local state reset/key derivation, branch contradiction, unknown-op
barriers, nonlocal incoming jumps, transitive capture forwarding, unknown and
out-of-bounds environments, bounded search and pinned evidence. No Roblox or
payload runtime tests were performed. Offline analysis does not establish a
physical air gap on the host.
