# Phase 28: automated finite solving and symbolic exploration

Base: local `6438cc8`. Run `python tools/automated_solver.py`. All evidence is
rebuilt from the pinned local g/d inputs. Full output is ignored under
`output/phase28/automated-analysis.json`; compact evidence is in `summary.json`.

## Results

- Exact finite solving retains **all2,048 candidates**. The current byte-key
  equation and9..20-bit Hamming bound are both entailed by that domain; neither
  adds a new pruning constraint.
- Automated symbolic exploration passes8481 and records **six conditional
  constructor metadata observations**, then stops at **PC8521/op44**, a call.
- That guarded call resolves to constructed body516. The specific candidate
  "8521 activates663" is refuted in the projected context.
- DPLL queries for the19 global open sub-gates remain **UNDERCONSTRAINED**:
  both their positive and negative certificate queries are SAT.
- No global gate, key or hierarchy edge was promoted. `verified_hierarchy=null`.

## Exact finite bit-vector backend

Z3 is not installed locally; no package or network resource was downloaded.
`finite_solver.py` implements a whitelist-only uint32/Boolean term evaluator,
truth-vector/bitset propagation, exact rejection-count ordering, residual unknown
handling and row-by-row model-certificate replay. Search heuristics affect cost,
not acceptance. No readability/entropy score can remove a candidate.

The supplied formula is:

```
V : uint32
key = 4 XOR ((V XOR (V >> 29)) AND 0x1fffffff)
key <= 255
9 <= popcount(V XOR 4179906283) <= 20
```

Every member of the established2,048-state domain satisfies both predicates.
The automatically returned subset is therefore the entire domain. The report
records model/domain hashes, rejection indices/counts per constraint, redundancy
classification and certificate replay. UNKNOWN expressions/guards remain
residual instead of becoming false or numeric defaults. UNSAT results are
explicitly limited to the supplied finite model, not whole-program reachability.

`constraints.smt2` exports a portable QF_BV formula with a typed32-bit popcount
encoding. It is supplied for independent local solver checks; no external SMT
engine was invoked or claimed to have verified it. The exact finite backend was
executed and tested. Tests independently exercise a synthetic256-model subset,
contradiction/UNSAT, missing variables, sorts, shifts and changed entry bounds.

## Bounded symbolic worklist

`automated_explorer.py` rebuilds the path-local directory/XOR view, replays
accepted root patches, and reapplies template footer fills on private copies.
All replayed directory transitions and cumulative effects are checked. Existing
pre-fill templates remain separate from post-fill backing bytes.

The explorer models copies, literals, source-confirmed jumps, fresh private
tables, guarded lazy-key writes, metadata constructors and direct patch100.
It forks unknown comparisons, reduces Boolean units and typed uint32 interval
conditions, and rejects contradictory conditions automatically. Unknown
comparison outcomes do not imply integer provenance or eliminate NaN/object
cases globally. Unmodeled effects and alternative outcomes remain outside its
closed-world coverage claim, which is always false.

Step/path/worklist/state limits are explicit; dropped branches remain
unexplored, never UNSAT. Full register/heap/epoch and metadata identity are
included in state comparisons. Unknown field effects clear private-heap facts
and havoc captured register values, including newly registered captures. The
source/context/cache and no-reflective-mutation premises remain explicit.

Constructor operations use Python metadata parsers and the existing alias-only
source checks; no returned closure, Lua factory or application body runs:

| PC | Body | Descriptor | Header format | Source-derived mask |
| --- | --- | --- | --- | --- |
| 8481 | 137 | 58 | 0 | 117 |
| 8482 | 672 | 212 | 0 | 121 |
| 8361 | 544 | 495 | 0 | 83 |
| 8362 | 516 | 579 | 0 | 111 |
| 8363 | 455 | 58 | 0 | 92 |
| 8520 | 728 | 424 | 0 | 100 |

Each observation includes captures, factory, plaintext hash and complete footer
consumption. These are conditional parse/construction observations, not verified
lexical edges or proof that the runtime cache contains those objects.

The eighteen reviewed instructions follow:
8481,8482,8483,8484,9958,8356,8357,8358,8359,8360,8361,8362,8363,8364,8365,
9958,8520,8521. At8358 direct patch544/key83 is applied to a private model;
its code continuation uses the exact source tuple j74/O144/Z178/B68. The older
numeric initializer's noop70 abstraction is not silently treated as a literal
source68 instruction. Other unsupported transfers remain boundaries.

At8521, source44 is `callee(lazy_constant, register_value)`. Register127 contains
the freshly modeled516 closure. Arguments are retained symbolically; no call,
result, alias effect or normal continuation beyond this call is assumed.

## Automated gate queries

`gate_solver.py` implements bounded DPLL with unit propagation and occurrence
ordering. It returns SAT/UNSAT/UNKNOWN_BUDGET and partial logical valuations,
without filling missing variables with runtime defaults.

For every open sub-gate, the driver encodes the conjunction of its certificate
requirements, recorded local facts, and the target certificate. Missing
invocation, cache identity, alias effects, closure lifetime and global coverage
facts remain unconstrained. Both target=true and target=false queries being SAT
proves underdetermination of this evidence formula. It does not prove both
runtime outcomes feasible or that further static analysis cannot resolve them.

See `GATE_QUERIES.md` for all19 results. The separate call8521 candidate query
is REFUTED_CERTIFICATE under its recorded path conditions because516 differs
from663. This does not exclude663 activation by other calls or later paths.

The next missing static model is the516 callee's results and capture effects at
8521. A source-proven transfer into V at981 and complete invocation/cache/alias
coverage are still needed before narrower candidate or hierarchy claims.

## Verification and compliance

20 new tests cover finite certificates/redundancy/subsets, DPLL units and
branching, unknown-vs-false evidence, branch reduction, global budgets, parallel
copies, fresh capture havoc, private code rewrites, boundaries and pinned end-to-
end metadata exploration. Full-suite results are in PROJECT_MEMORY.md.

All work remained local/static. No network requests, package installation, Lua
VM, payload/factory/__index/application execution or original input edits occurred.
Demo/ESP code remains untouched. Lua entry-script syntax is checked separately;
no Roblox runtime verification or Git push was performed.
