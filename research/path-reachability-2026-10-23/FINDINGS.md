# Phase34: guarded control-flow reachability

Baseline bfa6ece. Reproduce offline: `python tools/path_reachability.py`.
Full fresh evidence: ignored output/phase34/path-reachability.json, plus
regenerated epoch, inversion, root-prefix and caller reports beneath phase34.
Tracked summary.json contains hashes, branch expressions, assumptions and gates.
BRANCH_LEDGER.md lists the recorded root branches in execution order.

## Result and the missing endpoint

No unconditional positive path or V@981 reaching-definition bridge is proved.
All 2,048 candidates and 19 UNDERCONSTRAINED gates remain unchanged;
verified_hierarchy is null and the promotion patch remains false/empty.

The actual reviewed entry is PC9942. The recorded prefix has363 instruction
observations and stops at8398. It does not visit981. Therefore an exact branch
sequence **from981 to516** is unavailable in this evidence. PC numbers alone
do not establish temporal order:981 may not be presumed to precede8521 merely
because its number is smaller. No path edge from that unvisited endpoint is added.

The effective981 stream tuple is j=74,O=47,Z=4,B=125 in the exported root epoch.
That is an epoch-specific payload-mask instruction observation, not a complete
outgoing control-flow edge. Missing state/cache/normalization premises are not
filled by choosing a candidate V or a default numeric register.

## Exact recorded branch sequence and assumptions

tools/path_reachability.py reconstructs reaching register versions from recorded
writes, and re-evaluates reviewed228/13 and228/14 comparisons using exact
integers within2**53. Missing values remain symbolic; bool is not an integer.
Each branch records its source operands, truth choice, occurrence identity,
both successor PCs and its next observed successor. A mismatch raises an error.
Rewrites revisiting the same PC are preserved in trace order; repeated reads
correlate only when their symbolic register definitions agree.

There are24 numeric branch decisions in the pinned root prefix. All24 successor
checks pass. The branch ledger is a source-model certificate under retained
initialization/reader/cache/native contracts, not independently verified runtime
values and not a new set of constraints on root V@981.

An independent integer-bound check groups those branches by their reaching
SSA definition. Each group has eight decisions. For an integer x, taking
x<=c imposes an upper bound c; taking its false edge imposes lower bound c+1.
The three intersections are respectively [28,28], [165,165] and [130,130],
agreeing with the recorded r87 values. The exact defining IDs and branch steps
are retained in summary.json/root_branch_integer_domains. These are distinct
r87 SSA versions, not values assigned to V@981 and not grounds for pruning it.

Eighteen root environment/normal-completion observations are retained explicitly:
11 environment lookup boundaries, six normal-completion assumptions and one
reviewed decorative metadata assignment. These are open premises. A label in
the report is not proof that its native binding or field operation succeeds.

The route to the516 call has three separately guarded segments:

| Segment | Start | End/boundary | Remaining premise |
| --- | ---: | ---: | --- |
| Pinned root initialization | 9942 | 8398 | prefix/native/reader/cache contracts |
| Reviewed assertion-return projection | 8400 | 8481 | slot109 is standard assert; debug argument truthy; field reads succeed |
| Advanced symbolic projection | 8481 | 8521 | same snapshot/metadata; guarded constructors, lazy reads and capture havoc |

8398->8400 is a conditional normal-return seam from the exact fused call frame.
No assertion is invoked. Its argument is global.debug, represented symbolically;
LuaTruth(global.debug) is included as a necessary guard, not assumed known data.
The context-slot109 binding is distinct from root register109/closure258.
The8481 seam is an overlapping boundary observation, not a second execution of
that constructor. Matching PCs alone cannot establish unconditional continuity.

## Interprocedural constraint queries

The reviewed8521 call to516 has64 Boolean guard entries, including the24
evaluated root branches, explicit prefix/environment premises and the necessary
debug truth condition. Their conjunction is SAT in the bounded Boolean theory.
Non-Boolean conditions would remain separate obligations; no integer range is
silently converted into an unconstrained Boolean fact.

Five distinct callee-entry projections are source-traced and checked:

| Call in516 | Callee | Entry-guard result | Global reachability |
| ---: | ---: | --- | --- |
| 162 | 544 | SAT | OPEN |
| 131 | 258 | SAT | OPEN |
| 126 | 544 | SAT | OPEN |
| 102 | 258 | SAT | OPEN |
| 213 | 258 | SAT | OPEN |

The full local branch sequence for each is stored with step/occurrence IDs in
summary.json. Predicates evaluated after a call are excluded from that call's
entry query, even when its trace includes a reviewed helper-return summary.

For call162, Phase33's source-checked r24..25 -> r31..32 rule with offset+7
is combined with the guard evidence. It is an already proved finite slot
arithmetic identity and adds no new numeric restriction to the Boolean domain.
Its actual call-frame/native/activation premises remain open. That proof is
not automatically reused for the separate126 invocation.258's immediate/lazy
arguments likewise do not establish an identity with caller V.

SAT here means compatible reviewed guard projections, not a source-complete
execution witness. Missing981 arrival/order, same-activation definitions,
intervening state writes and native/cache/alias/code-epoch coverage keep all
queries OPEN. No absolute barrier from981 is proved either: an absent endpoint
in an incomplete trace cannot establish global unreachability.

## Callee entry versus normal return

Phase31's negative route certificate is preserved separately. Under its G
premises,131/102/213 reach258's primitive ordering failure and30 reaches a
fresh-frame nil ordering failure. Those conditions exclude normal return from
the reviewed516 invocation; they do not exclude reaching those call sites or
entering258. Reaching544 under a compatible branch also does not establish the
later root continuation or a unique definition of V. This distinction prevents
misusing a return failure as an absolute entry-reachability barrier.

## Tools and safety

tools/path_reachability.py adds the branch/SSA ledger, source-successor checks,
temporal occurrence queries, explicit guarded seams and interprocedural guard
queries. tools/test_phase34.py covers contradictions, unknown definitions,
Boolean/numeric separation, repeated expressions, successor mismatches,
missing/reversed temporal endpoints, seams and fresh pinned integration.

Only static local Python metadata transfers run. No payload, factory, __index,
Lua or application execution, network, dependency installation or source input
mutation. Demo/ESP features are untouched; Roblox runtime checks were not run.

## Verification

All400 tests passed in401.019s:378 retained tests plus22 Phase34 tests. Fresh
standalone report generation, all24 root successor checks, three independent
r87 integer-bound intersections, Python compilation, entry Lua syntax checks
and working/staged `git diff --check` passed. Only a local commit is made;
no push is performed in this phase.
