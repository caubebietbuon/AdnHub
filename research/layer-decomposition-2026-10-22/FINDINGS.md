# Phase 15: backward slices, independent equations and prototype diagnostics

Scope: step-by-step static decomposition. Script reproduction is outside this
phase. No Lua, payload, factory, metatable or application code is executed;
there are no network requests. Demo/ESP files are untouched.

## Reproduce

```powershell
python tools/layer_decomposer.py
python -m unittest discover -s tools
luac -p AdnHub.lua Loader.lua
git diff --check
```

Requires the pinned local g/d artifacts. The runner rebuilds Phase14 and the
backing data in temporary directories. Detailed output is ignored:
`output/phase15/layer-decomposition.json` and `DIAGNOSTIC_MATRIX.md`.
The diagnostic matrix is also retained beside this report; `summary.json`
contains compact metadata. Input files are never modified.

## Backward register slicing

`tools/register_slicer.py` creates bounded SSA definitions from recorded trace
order. Numeric PC order is not execution order: loops and jumps can revisit or
skip smaller PCs. Each query selects a specific trace step or the recorded
frontier. Parallel register assignments read the previous versions, and an
unknown write kills the old definition. Missing frame entries retain their
nil type contract; they never become numeric zero.

The whitelist traces literals, copies, exact integer additions, decoded numeric
XOR inputs, state-word reads and successful state-word assignments. Forward
numeric observations are checked against independently reconstructed arithmetic.
Arguments, environment reads, opaque writes and capture addresses remain
explicit leaves. An address does not become a captured value without a proved
dereference. Unsupported arithmetic or types do not acquire constants from
their logged appearance.

The forward recorder now labels decoded numeric inputs and completed state
writes. An attempted instruction that stops on a type obligation does not
silently become a successful assignment in the backward graph.

Source cross-check also corrected an inherited forward-model error:
variant163/op109 had reversed its two copy sources. At pinned source
offset25174 the assignment is `t[T],t[T+1]=t[w[W]],t[H[W]]`, corresponding to
`r[c],r[c+1]=old(r[a]),old(r[b])`. Both forward and backward models now use that
order. A regression test supplies distinct source values10 and20; equal/unknown
inputs would have concealed the reversal. The pipeline was rebuilt after this
correction; the reported root controls and matrix counts are unchanged.

Concrete control results:

- Root y at the frontier: **2639318406**, reconstructed with9 dependency nodes.
- Root register2 at the frontier: **2639318406**, with8 dependency nodes.
- Root register107: **0**, from its literal definition.

The y graph reaches the header word, two decoded numeric inputs, XOR, addition
and the successful state assignment. These results apply to the recorded root
prefix. They do not establish state at an unvisited string site.

## Decoder equations and activation guards are separate outputs

The17 IDs remain the Phase14 set excluding guarded control192. The current
potential-site scan exposes14 equations across9 IDs:

| Core type | Sites | Treatment |
| --- | --- | --- |
| Direct byte XOR | 9 | exact literal key and decoded bytes, independent of activation predicates |
| Operand XOR mixer(state) | 5 | symbolic state input and exact inverse-domain size2048; no header-word substitution at unvisited sites |
| No reviewed equation exposed | 8 IDs | explicit missing-site result |

The key operands at these patch handlers are stream literals. Register
dependencies enter through assignments to V/y; the backward slicer follows
those assignments when a concrete trace point exists. Each site has a separate
activation-predicate list for owner activation, dispatcher/slot stability,
directory/payload lifecycle and cache hit/miss state.

For a reached matching site, the generic routine queries its pre-instruction
SSA state and evaluates the core equation if the input is a proved uint32.
None of these14 candidate sites was reached in the current prefixes, so their
frontier slices are explicitly context-only. Every selected per-ID key remains
null. This is a valid algebraic decomposition, not a claim of17 recovered keys.

Direct candidates are retained without readability scoring. For ID203, one
site's key110 yields byte81 (invalid standalone UTF8), while another site's
key140 yields byte63 (`c`). Both are retained with distinct activation guards;
the readable candidate does not win by appearance. Binary hex preserves all
results. Mixer inputs with no exact definition remain symbolic.

## Six-column diagnostic matrix

See [DIAGNOSTIC_MATRIX.md](DIAGNOSTIC_MATRIX.md) for all8 pairs: the original4
and the4 guarded root closure bindings. Each pair has a result, explanation
and scope for capture bounds, upvalue mappings, child headers, control flow,
coverage and cycle checks. `UNKNOWN` distinguishes missing proof from an
observed contradiction; a PASS asserts only its stated local scope.

These six diagnostic columns differ from the historical validator's six proof
flags. Both are retained separately. The validator and its rules are unchanged.
For example, a source transfer observed on a guarded prefix passes the scoped
control-flow diagnostic while unconditional ancestry remains unproved.

The137→747 projected control-flow failure retains the Phase14 nil/XOR contracts.
237→572 and704→288 retain unknown incoming capture bounds and mappings. Global
candidate coverage fails for every row: even counting unverified edges, the
root reaches6 of41 expected nodes;35 remain unassigned/unreachable in this
enumerated graph. No cycles appear in the enumerated graph. The latter result
does not establish acyclicity of unseen links. `verified_hierarchy` remains null.

## Intermediate wrappers and factories

Each pair has a typed proxy route: proposed owner → lazy-wrapper use → shared
cache lookup → decoded template → constructor instance → capture-bound body.
The descriptor is a separate input to the binding. This depicts a possible
cache-miss route; the cache-hit alternative needs its own cached-value identity
proof. It is not an assertion that all materialization steps occurred.

Four routes have guarded source-transfer evidence; four remain consumer-family
hypotheses. Seven pairs share factory4890, whose alias-only outer/capture
prefixes are inspected without invocation. The572 candidate reaches native
factory boundary4916. Shared implementations and reused descriptor486 cannot
identify a unique lexical parent. Constructor-use and closure-instance nodes
therefore retain distinct owner/child/descriptor identities.

Prototype-only alternative-path search finds no additional multi-hop path among
the8 enumerated candidate pairs. The tool never turns shared factory identity
into an ancestry edge. Unseen proxy relationships remain open obligations.

## Verification

124 Python tests pass (108 previous +16 new), including execution-order slicing,
parallel copies, unknown-write kills, failed state writes, numeric provenance
consistency, binary decoder candidates, mixer input bounds, cycle/coverage
separation and proxy-search rules. Lua syntax and Git diff checks pass.
No Roblox or payload runtime validation was performed.
