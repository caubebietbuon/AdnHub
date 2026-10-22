# Phase30: upstream backward constraints

Baseline: local7ada2ba. Run `python tools/upstream_solver.py` from the repository.
The tool regenerates pinned inputs and caller metadata; previous output files
are not proof inputs. Full evidence is ignored under
`output/phase30/upstream-analysis.json`; this directory contains the handover.

## What was proved, and its scope

For the reviewed guarded invocation, body544 returns true exactly when
`type(Instance) == "table"`, otherwise nil, and restores its captured scratch
table. Substituting this normal-return summary into body516 reaches the next
opaque call at123, through decoder-context slot59 (source `getmetatable`).

The alternate calls to258 at516/131 and516/102 have the same arguments,
`(520442978,4)`. Their reviewed prefix reaches258/71 with an ordering comparison
`4 >= "slnaf"`. Standard Luau primitive ordering rejects number versus string.
Thus those two paths cannot return normally **in this guarded model**. This
does not prove the actual environment takes either branch, that all invocations
of258 fail, or that all runtime cache entries agree with the static projection.

These are genuine local path exclusions and a return/data-flow bridge from544
into516. They are **not a reaching-definition bridge to root664.V@981**.
The finite model retains2048 candidates, all19 global gates remain
UNDERCONSTRAINED, verified_hierarchy stays null, and no promotion is emitted.

## body544: captured-table memory and return

Its arguments are `"table"` and symbolic `type(global.Instance)`, placed in
r31/r32. Its captured tables are root160 (fresh and empty) and root111 (Boolean
complement). Both source/cache/plain-table identities remain explicit premises.

| Site | Source-supported effect |
| --- | --- |
| 64/163153 and related initializer | Boolean normalization; known string arguments are truthy |
| 17/16350 | capture1[r31] = primitive reference16, true |
| 18/16312 | r2 = capture1[r32], preserving the table state at this read |
| 19/16391 | capture1[r31] = r18, fresh-frame nil: removes the scratch key |
| subsequent copy | r31 = r2 |
| 43/163144 | transition to dispatch82, PC44 |
| 44/82/81 | close local cells and return r31 |

The returned value is a snapshot of the lookup before cleanup, not a delayed
read of the now-empty table. With only the key `"table"` holding true, its typed
weakest truth condition is `type(Instance) == "table"`. Negating that condition
describes a false/nil return; neither predicate is assumed to hold.

The return adapter checks both incoming and outgoing captured table contents,
an unexhausted single return path, exact return PC44, caller/callee identity,
arguments, source93 operands and rewritten lookahead frame `(results1,target23,
argc2)`. It writes the symbolic result to516 r23 and advances to164, consuming
the fused lookahead. No function is invoked. Source close loops are empty only
under the reviewed fresh-frame/no-local-capture-allocation prefix conditions.

Resumed516 copies that value to r1 and branches at167. Its true outcome reaches
PC123's getmetatable call; its false outcome reaches the second258 call at102.
No getmetatable result, downstream call effect or root continuation is guessed.

## body258: upstream dependencies of the ordering failure

The tool follows initialization, source normalization, bounded local allocation,
table.move metadata and the sequential fused literal/copy operations. Instruction
windows are read from the current rewritten arrays, not stale raw tuples.

| Site | Relevant mutation |
| --- | --- |
| entry105 | arguments -> r20=520442978, r21=4 |
| 39/22821 | r4 = r21 + 0 = 4 |
| 113/228173 | r1 = primitive reference5 (1953789044); then r2 = r4 = 4 |
| 115/228173 | r4 = decoded string reference3 (`"slnaf"`); then r1 = r2 = 4 |
| 117/22855 | numeric comparison writes false to r2 |
| 70/22896 | r5 = not r2 = true |
| 71/22851 | r6 = r1 >= r4: number/string ordering failure |

The sequential order of173 matters. A parallel-copy model would give incorrect
lineage when its second source overlaps its first destination.

The backward SSA slice of the failure ends at references3 and45 (argument2),
not reference8 (argument1), root107, root106, or either frame's V. No captured
cell is read or written before this boundary on the reviewed prefix. String
contents are not needed for the ordering argument; its string type suffices,
subject to the reviewed lazy/shared-cache binding. Unknown operand types produce
an unresolved boundary instead of a type-error proof.

## Backward graph and DPLL results

SSA nodes are qualified by frame, PC, trace step and write index. Table writes
have separate memory versions; a read depends on the version before cleanup.
Argument bindings connect544 r31/r32 to516's actual argument definitions and
ultimately constant28 and root r74. Equal numbers or equal register indexes in
different frames never create data-flow edges. Unmodeled definitions become
explicit unknown leaves; incomplete slices retain budget exhaustion.

The normal-return DPLL query uses two necessary guarded implications:

1. normal root8521 return -> LuaTruth(Instance).
2. normal root8521 return -> type(Instance) == "table".

Adding the negation of either required condition is UNSAT in that **local
necessary-condition formula**. The compatible formula is SAT, which is not a
runtime witness, a sufficient condition for return, or global path coverage.
The constraints say nothing numeric about V@981 and are not recast as uint32
equations. The existing bridge adapter admits zero new root V filters.

## Remaining bridge and global obligations

- body516's getmetatable call at123, its later outcomes and effects remain opaque.
- Root664's normal-return continuation from8521 to981 is not established.
- No same-activation V@981 reaching definition or effect-complete numeric relation
  follows from either downstream summary.
- Closure663's actual activation, live cache/context, alias, scope-exit and
  lifetime coverage obligations remain global; local nonreturn does not solve them.

The source93 return substitution narrows local control-flow explanations, not
the2048 numeric domain. No verification rule or hierarchy requirement is relaxed.

## Verification and maintenance

New tests cover epoch windows, opt-in dispatch82 and fallback blocking, typed
truth/ordering, bounded table operations, sequential fused copies, restored
scratch storage, weakest predicates, SSA and memory slicing, frame separation,
unknown definitions, budgets, exact return bindings and pinned end-to-end replay.
All314 regression tests passed in301.791s. After final exact-frame/initial-table
return-binding hardening, all18 Phase30 tests passed again in21.146s. Python
compilation, Lua entry syntax and working/staged whitespace checks passed.

No Lua/payload/factory/__index/application execution, network calls, installs,
input edits, demo/ESP changes, Git push or Roblox runtime testing are performed.
