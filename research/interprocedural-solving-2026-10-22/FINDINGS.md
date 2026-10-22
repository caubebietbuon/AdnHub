# Phase29: guarded body516 interprocedural analysis

Baseline: local b2cf133. Reproduction: `python tools/interprocedural_solver.py`.
Full evidence is regenerated from the pinned g/d inputs into ignored
`output/phase29/interprocedural-analysis.json`. No payload, Lua, factory,
metatable, global lookup or application function is executed. The `type` rule
below is a Python symbolic transfer, conditional on the source builtin binding.

## Call-time reconstruction

The optional boundary observer receives a private metadata fork plus copies of
registers, heap, arrays and path conditions. It cannot mutate the parent explorer.
The default Phase28 output and semantics are unchanged. Phase29 rebuilds the
prefix, patch epochs and newly cached body516 template; it does not reuse the
older hypothetical entry analysis or read its ciphertext after cleanup.

At guarded root PC8521/22844, r127 is body516, created at8362 from descriptor579
and payload key111. Cached header SHA256:
`531a23e3614d3da4a980f269f833faf0893bea623de8fd4dc4d53bafd5ca8156`.
Its entry is116; its own V/y words are4177667352/1242051610. These are different
lexical locals from root664.V, including its unvisited PC981 value.

The first argument is effective primitive reference112: offset127107, tag167,
int32, value162944256. No pending payload mask is present. The second argument
is root r74's symbolic `global.Instance`; no environment value is assumed.
The 157/73 parameter copy places these into body516 r20/r21 respectively.

| Capture | Source cell | Call-time guarded projection |
| --- | --- | --- |
| 1 | root111 | Fresh plain Boolean complement table |
| 2 | root109 | Closure258 |
| 3 | root95 | 474124151 |
| 4 | root110 | Closure137 |
| 5 | root54 | Closure544 |

This is a call-time, guarded projection. It does not establish immutable cells,
unique lexical ownership, complete alias coverage or actual invocation.

## Exact opening predicate

The private table is resolved using the effective primitive readers:
reference111=false, reference16=true, both tag244/aux162. Thus the writes at
8357 and8359 establish `{[false]=true,[true]=false}` under the retained plain
table/cache conditions. Actual key identities are checked, rather than assuming
distinct reference IDs imply distinct keys. Boolean true and numeric1 remain
different keys.

At body516 PC47/22896, r4=`not r21`. PC48/228146 reads capture1[r4] into r1.
Consequently, for any Lua value x:

`capture1[not x] = LuaTruth(x)`.

This is a Boolean result: nil/false produce false; zero and empty strings
produce true. PC49/228181 branches on this Boolean. A repeated test at172 uses
the same symbolic truth fact; it cannot fork an incompatible second outcome.
The full guarded paths include the source-reviewed dispatcher transitions.

## Interprocedural frontier summaries

| PC49 condition | Next opaque call | Established argument flow |
| --- | --- | --- |
| Instance truthy | body516 PC162/22893 -> capture5, body544 | `("table", symbolic type(Instance))` |
| Instance nil/false | body516 PC131/22816 -> capture2, body258 | `(520442978, 4)` from references8/45 |

On the truthy route, PC158 aliases context slot25. The source contains
`[25]=type`; PC159/228150 is summarized as a symbolic pure builtin result only
under the additional condition that this slot retains that identity. PC160
reads capture5; PC161 resolves reference28 to `"table"`; PC162 copies the
callee to r23 and packs arguments r24/r25. One result is requested; return PC164
is conditional and is not entered. No result, type string or effects are guessed.

On the false route, PC24 performs the reviewed private-array normalization.
At131 the fused instruction first reads capture2 into r2, then calls r2 with
lazy references8/45. Only that first call is summarized. The later fused capture
writes/reads and zero-argument call remain deferred behind its unknown effects.

Capture ordinals1,2,5 are read on these prefixes. In particular, capture3/root95
is **not read before either opaque call**. Body516's own state words remain
unchanged on the reviewed prefixes. Neither fact describes effects after calls.

Two candidate-specific DPLL queries refute these first calls as calls to663
within their respective guards. They do not exclude future, nested or other
activations of663.

## Constraint propagation and remaining obligations

The finite solver retains **2048/2048** local V@981 candidates. Four scoped
invariants are exported: argument1, capture3, the Boolean-table equation and the
callee frame words. None has a proved same-activation, reaching-definition,
value-flow and effect-completeness bridge to caller664.V@981. The bridge-query
adapter therefore admits **zero** new numeric filters. Equating a callee-local
number, header word or captured root95 with that V would be unsupported.

All **19 global gate queries remain UNDERCONSTRAINED** after fresh DPLL queries.
Call-local evidence is namespaced and cannot overwrite `actual663-invocation`
or any other global obligation. `verified_hierarchy` remains null and the formal
promotion patch remains inapplicable/empty. These are retained obligations,
not fabricated UNSAT results or claims of completed decompilation.

Next evidence needed: source-reviewed summaries of the body544/body258 calls,
their alias/capture writes and return outcomes, followed by a same-invocation
control/data-flow bridge to root PC981. Closure663 still requires its actual
call witnesses and complete cache, context, alias, close/rebind and exit coverage.

## Verification

Tests cover typed effective primitives, payload-mask rejection, exact Boolean
table reduction, alias-key collisions, Lua truthiness, capture frame isolation,
observer isolation, predicate reuse, exhausted budgets, bridge admission and
rejection, local/global gate scope separation, output alias protection, and a
fresh pinned end-to-end replay. All296 regression tests passed in353.963s;
after final observer isolation hardening, all36 affected Phase28/29 tests passed
again in44.389s. Python compilation, Lua entry syntax and diff checks passed.
Roblox runtime checks are not performed. Demo/ESP code is untouched. No network,
package installation or Git push is used.
