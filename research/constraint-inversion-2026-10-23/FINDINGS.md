# Phase32: predicate inversion and bounded reaching-definition meeting

Baseline: ac10bc3. Reproduce offline with `python tools/constraint_inverter.py`.
Fresh full evidence: ignored output/phase32/constraint-inversion.json, with
regenerated Phase31/upstream reports and pinned forward checkpoint evidence.
Tracked summary.json includes hashes, inversion queries and the 19-gate ledger.

## Result and logical scope

No unconditional positive bridge to root V@981 was established. All 2,048
numeric candidates and 19 UNDERCONSTRAINED global gates remain locked.
verified_hierarchy is null; the promotion patch remains false/empty.

Let G be Phase31's reviewed prefix, cache, code epoch, native and no-reflection
premises. Its source-backed failure leaves cover the invocation:

- !T: 516/131 -> 258(520442978,4), primitive ordering failure at 258/71.
- T & !Q: 516/102 -> the same guarded 258 failure.
- T & Q & N: 516/30 tests 2 < nil in the reviewed fresh frame.
- T & Q & !N: 516/213 -> the same guarded 258 failure.

Here T=LuaTruth(Instance), Q=(type(Instance)=="table"), N=(M==nil).
The helper proof remains body544(nil,M) == (M==nil), including M=false.

The new routine negates each recorded branch occurrence independently, keeps
its original prefix, discards its old suffix, and checks compatibility with
every source-backed failure leaf. It does not negate a primitive exception
into a normal-return instruction or invent a continuation.

Across 18 occurrence queries, 9 inverted prefixes are Boolean SAT and 9 are
UNSAT (including attempts to flip already determined/redundant predicates).
Each SAT prefix selects other blocked leaves. All 18 queries conjoined with
avoidance of every certified failure are UNSAT **under G**. This is a scoped
partition result, not UNSAT for the numeric V domain.

The exact contrapositive is NormalReturn -> !G. The converse !G -> NormalReturn
is not established: the separate predicate query is OPEN. Dropping cache or
native premises cannot itself serve as a positive path witness.

## SSA and meeting trace

The report retains 86 occurrence/step-qualified source transfer annotations
from helper544 and parent516 (nil comparisons, branch conditions, pure builtin
summary and the r23 return binding). For258 it retains the actual backward
operand graphs and the numeric arguments leading to the PC71 type failure.
No address binding is reinterpreted as a captured value definition.

upstream_solver.reaching_meet performs bounded forward and backward searches
over qualified SSA identities. It combines path predicates at each meeting,
retains alternatives at merges, and ignores address/control edges as numeric
data definitions. Truncation yields UNKNOWN; even a compatible abstract path
is not an unconditional runtime or numeric-equality certificate.

The regenerated graph has 446 nodes and 228 data/copy edges. Four downstream
effect/return sinks are queried (three544, one258). No meeting is found with
V@981 in this exported graph, nor with the earlier root V definition.

An important schema boundary is explicit: the advanced explorer's 8481..8521
trace exports register writes, not VM state-word observations. It cannot be
passed to RegisterSlicer as if it contained V/y values. The tool instead rebuilds
the earlier pinned root prefix (frontier8398), whose V SSA is header4179906283,
and keeps that prefix distinct from the guarded8521 register snapshot.
The latter's incoming registers are unresolved resumed-frame definitions,
not newly initialized nil cells. Missing definitions are not supplied from
equal register numbers, matching values or historical closure constructors.

V@981 remains an unvisited definition boundary. V@8521 is not exported, and
there is no established intervening-write/arrival relation. The endpoint is
therefore deliberately unconnected. This is an incomplete-graph diagnosis,
not proof of globally empty intersection or a constraint on all loader entries.
Source-backed prefix reconciliation and cache/code-epoch auditing at516/30 and
258/71 are still needed before a positive reaching-definition claim is possible.

## Tools and safety

- constraint_inverter.py: fresh evidence generation, prefix inversion, helper
  and writer SSA diagnostics, and bounded two-direction meeting queries.
- upstream_solver.py: additive reaching_meet helper; existing transfers unchanged.
- path_refiner.py: optional isolated boundary observer for fresh Phase32 metadata.
- test_phase32.py: inversion, nil/false, guard correlation, scope isolation,
  incompatible meetings, bounds/cycles, source protection and pinned integration.

Only local Python metadata analysis runs. No payload, interpreter factory,
__index, Lua or application execution; no network, dependencies installed,
demo/ESP modifications or hierarchy promotion. Roblox runtime checks were not run.

## Verification

All 355 tests passed in 323.394s: the existing337 plus18 Phase32 tests.
The fresh pinned integration test rebuilds the evidence and checks inversion,
meeting queries, exact candidate/gate locks and null hierarchy. Standalone
Phase32 regeneration, Python compilation, `luac -p AdnHub.lua`,
`luac -p Loader.lua` and working/staged `git diff --check` also passed.
Changes are committed locally; no push is performed in this phase.
