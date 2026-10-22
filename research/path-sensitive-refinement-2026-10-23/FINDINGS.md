# Phase31: path-sensitive alias and predicate refinement

Baseline: b5711da. Reproduce with `python tools/path_refiner.py`.
Full regenerated evidence: ignored `output/phase31/path-refinement.json` plus
its freshly rebuilt upstream/caller evidence. No previous output is trusted
as an input proof. Pinned g/d hashes are retained in summary.json.

**The requested final positive V@981 bridge is not established.** The new
result is a conditional negative route certificate, not an equation identifying
V and not permission to remove its2048 local models. All19 global gates remain
UNDERCONSTRAINED; no hierarchy promotion is applicable.

## Precision model

The existing worklist does not merge or widen branches. Thus join-point widening
was not an observed cause of the earlier boundary. The new tools add:

- `path_domain.py`: frame/activation-qualified register addresses, typed heap
  keys, copied pointers, exact offsets, guarded may-alias stores, unknown-store
  havoc, immutable read snapshots and explicit guarded alternatives at joins.
- `Predicates`: bounded Tseitin CNF/DPLL with typed constant equality, repeated
  expression correlation, type/truth implications and mutually exclusive
  literal equalities. No runtime type is selected and no complete type-name
  enumeration is assumed. Symbolic self-equality is not presumed: NaN matters.
- `path_refiner.py`: source-checked transfers, occurrence-qualified branch
  decisions, helper return partition/coverage certificates and scoped route audit.

The proven byte-key/Hamming conditions are retained. They are necessary
conditions for the current local numeric model, not arbitrary range bounds to
discard when a different Boolean path model becomes inconsistent.

## Alias findings

At the guarded8521 snapshot, known closures567 and258 share root107 storage.
Their pointer names resolve to the same root664 frame and activation address.
Closure379's earlier construction is known, but root159's current value is a
havoc observation; its current call-time identity is not recovered by declaring
the historical binding live. Root107's own current value also remains havoc.
Neither is replaced by an earlier zero or a fabricated numeric default.

A root register cell containing a fresh table and that table's properties occupy
different address spaces. Replaying544's scratch `table` key write/read/cleanup
retains the earlier read while restoring nil and leaving root160's register cell
unchanged. Captured root664 cells do not become body516 frame cells just because
their register indexes coincide. An offset preserves its original pointer-choice
guard; an unknown pointer receives a weak/havoc treatment, never a strong update.

These are call-time, guarded alias facts. They do not prove all future aliases,
cell closure/rebasing, unique lexical owners or lifetime stability for663.

## Symbolic getmetatable and second helper invocation

The validated544 return from Phase30 is reused at516/162, with exact rewritten
call-frame and argument checks. On its compatible path, slot59 is the source
`getmetatable` builtin and the argument is constrained to a table. PC123 is
modeled as a pure symbolic transfer under that builtin-identity condition.

Its result M stays unknown, including a possible protected metatable value.
In particular, false is not silently treated as nil. No actual getmetatable,
metatable method, Lua or application function is called.

At516/126, source93 calls544 with `(nil,M)`. Source163/97 compares values to nil;
potential equality between unknown table values remains a boundary because it
could involve a metamethod. The complement-table reader and Boolean predicates
are refined without executing any `__index` function.

| Helper guard | Return site | Result |
| --- | --- | --- |
| LuaTruth(M) | 93/22899, ref111 | false |
| not LuaTruth(M), M==nil | 96/22899, ref16 | true |
| not LuaTruth(M), M~=nil | 127/82/111, ref111 | false |

The solver proves each leaf agrees with `M==nil` and that their disjunction
covers the reviewed helper invocation. Constant returns require the actual
effective primitive readers. No budget-exhausted, unsupported or effectful leaf
can qualify for this return-only certificate.

The resulting Boolean is bound to516 r23 and execution is projected to128,
again checking the exact call frame, callee and arguments. This is symbolic
metadata transfer, not execution of a body or a VM factory.

## New route boundary:516 PC30

For the M==nil path, the current rewritten tuple at516/30 is
`228: (123,1,504247841,2)`. The source123 handler tests `A[PC] < t[H[PC]]`, so
this is `2 < frame516[504247841]`. That register is unassigned in the fresh
reviewed frame. The known helper captures refer to root664 storage, and the
pure builtin/return summaries do not expose or write that body516 frame cell.
Its value is nil, yielding a standard primitive-ordering failure in this model.

This is **not** rejection because an index exceeds a prototype allocation hint.
Lua tables can have large keys. The proof requires fresh-frame initialization,
an absence of reaching writes on this reviewed path and the retained
no-reflection/native-builtin conditions. An observed/unknown reaching write
causes an unresolved boundary instead of this failure proof.

## Guarded negative route certificate

Let T=LuaTruth(Instance), Q=(type(Instance)=="table"), N=(M==nil), and G denote
the retained prefix/code-epoch/plain-context/cache/native-builtin/no-reflection
premises. The four final source paths partition the reviewed invocation:

| Path condition, under G | Site | Reason normal return is excluded |
| --- | --- | --- |
| not T | 516/131 ->258 | same `(520442978,4)` ordering failure at258/71 |
| T and not Q | 516/102 ->258 | same argument/template/epoch proof |
| T and Q and N | 516/30 | fresh register nil ordering above |
| T and Q and not N | 516/213 ->258 | same argument/template/epoch proof |

The DPLL coverage query is ENTAILED. This proves only
`G -> not NormalReturn(root8521 through this modeled invocation)`.
It excludes this conditional continuation as a bridge witness to future981.

It does not prove G holds in the actual loader, that all root invocations use
this route, or that the loader can never reach981. In particular, the live
shared-cache binding and interpretation of the current516/30 code epoch remain
assumptions to audit. A contradiction in this projection is not a diagnosis
that the original script universally fails and is not grounds to force a return.

## Why no numeric pruning or global promotion follows

The local numeric solver still has all2048 values satisfying its original
byte-key equation and entry-to-site Hamming bounds. There is no source-proved
same-activation reaching-definition relation between those V values and T/Q/N.
A Boolean route refutation cannot be re-labelled as UNSAT for that uint32 domain.
Zero new V filters are admitted. Callee V locals, captured root registers and
root V@981 remain distinct named storage/proof objects.

All19 global gates and their exact outstanding requirements are listed in
GLOBAL_GATES.md. Live663 invocation, template/context/cache identity, complete
alias effects, close/rebind/exit coverage and unique owner/tree proofs remain
unproved. verified_hierarchy is null and the promotion patch is false/empty.

Next useful audit: reconcile the guarded cache/reader/code-epoch assumptions
at258/71 and516/30 before attempting a root continuation. Extending this
contradictory route with guessed results would not establish the requested bridge.

## Verification

New tests exercise pointer copies/offsets, frame activation isolation, heap/cell
separation, typed keys, may/unknown stores, correlated joins, Boolean theories,
nil/false handling, NaN conservatism, bounds, unsafe-equality boundaries and
fresh pinned end-to-end certificates. All23 focused tests passed in15.200s;
all337 regression tests passed in301.330s. The337 count includes the314 prior
tests, which already include the18 Phase30 focused tests, plus23 new tests.
Python compilation, Lua entry syntax and working/staged whitespace checks pass.
All analysis remains offline/static. Demo/ESP and original inputs are untouched;
no payload, factory, Lua, __index or application execution, install, Git push or
Roblox runtime validation is performed.
