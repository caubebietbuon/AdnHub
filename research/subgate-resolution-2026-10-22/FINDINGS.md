# Phase 27: scoped sub-gate proofs and numeric state handoff

Base: local `c67bb98`. Reproduce with `python tools/subgate_resolver.py`.
Pinned g/d hashes and compact certificates are in `summary.json`; full output
is `output/phase27/subgate-resolution.json` (ignored). Phase24/26 evidence is
rebuilt from the local inputs; the historical matrix is checked as an inventory,
not accepted as a source of executable logic or proof.

## Outcome

All20 open sub-gates were audited individually. One, `open_cell_reuse_and_order`,
has a **conditional construction-prefix proof**;19 lack even that conditional
resolution. None of the20 is discharged unconditionally. The18 parent gates
remain unpromoted, and `verified_hierarchy` remains null.

There is new negative/partial numeric evidence: unchanged-state transport from
root's recorded initialization to PC981 is incompatible with the current two
mask equations. Every site candidate differs from the known entry V in9..20
bits. This constrains a possible handoff; it does not select among the2,048 site
candidates or prove that PC981 is reached.

## Exact arithmetic from the mixed route

At root PC9840, variant163/op96 patches reference231:

```
key95 = 421809843 XOR mix(V)
mix(V) = 421809900
mix(V) = (V XOR (V >> 29)) AND 0x1fffffff
```

The exact eight preimages are:
421809900,958680813,1495551726,2032422639,2569293544,3106164457,
3643035370,4179906283. The pinned entry header selects4179906283; the other
values are algebraic preimages, not new runtime hypotheses for that header.

PC981's current `key = 4 XOR mix(V)` byte-key model admits2,048 states. Its
mixer image is in0..255, so its state bits8..28 are zero. This domain has no
intersection with the eight initialization-mask preimages.

Relative to entryV4179906283, every candidate must change bits
9,10,11,14,18,21,24,27,28. Bits8,12,13,15,16,17,19,20,22,23,25,26
must remain zero in the XOR delta. The remaining11 bits are free, giving exact
Hamming-distance bounds9..20. The tests check these statements for all2,048
candidates and independently verify the mixer inverse.

The rejected model is the conjunction of the recorded initialization equation,
unchanged V, and arrival at the current byte-key site in the same invocation.
It does **not** prove which conjunct fails in the application. A V transition,
different epoch/invocation, wider mask model, or lack of arrival remains open.
No candidates are globally removed and no operand is patched.

## Conditional cell-allocation proof

Pinned factory source initializes `local V,m,k=W[1]`: its fresh local k is nil.
The reviewed228/82 kind3 rule uses a map keyed by register, reuses an existing
cell, and otherwise creates `{[6]=t,[5]=register}`. A Python relation applies
this rule to the four recorded descriptor observations, in trace order:

| Construction | Allocation result |
| --- | --- |
| 567 at8390 | Create107,106 |
| 258 at8391 | Reuse107,106 |
| 379 at8393 | Reuse107,106; create103,92,104,93 |
| 663 at8394 | Create159,105 |

The12 ordered operations preserve explicit symbolic object identities. Cells
159/105 are new under this model; they do not reuse the root107 cluster's cells.
The proof retains the same guarded invocation/descriptors and no unmodeled
close/rebind/map mutation before construction as explicit premises. It neither
inspects real cells nor proves activation, future storage identity or lifetime.

## Assertion cases and bounded symbolic continuation

The baseline root frontier remains PC8398. The new tool separately projects
the normal-return case under the premises that context109 denotes the reviewed
standard assertion and its first argument (`global.debug`) is truthy. The
first requested result is that argument; the actual assertion is never called.

Under the same binding, a false/nil argument has no normal successor. A changed
binding is opaque. Zero and empty strings are truthy; unknown observations are
not coerced into nil, false or zero. Actual `global.debug` truthiness is unknown.

The guarded direct-instruction projection follows:
8400 ->8401 ->8402 ->8403 ->9958 ->8478 ->8479 ->8480 ->8481.
Copies, literals, register jumps and symbolic field expressions are recorded.
Field reads retain key/cache and success predicates; escaping alias effects
remain unmodeled. No capture values are preserved through those effects.

At8481 the tool stops before228/op82 (`destination110, body137, descriptor58`).
It does not construct137 or invoke a factory. No direct call to663 occurs in
the reviewed suffix; hidden field/metamethod effects, aliases and later code
remain open. This is a conditional continuation, not a newly proved runtime
frontier or incoming663 activation witness.

## Twenty-gate audit and rejected models

`SUBGATE_AUDIT.md` lists every open predicate, its scoped result, missing evidence
and rejected inference. Machine-readable certificates separately reject:

- unchanged-V transport across the two incompatible equations;
- normal return for the falsey standard-assertion case;
- preexisting159/105 reuse in the guarded construction plan;
- a direct663 call in the reviewed projected suffix before its boundary.

These results have distinct premises and are not global path exclusions.
Template identity at invocation, incoming values/predicates, complete writer and
exit coverage, close history, all call outcomes and global ownership/coverage
still require additional evidence. Shared byte hashes, a sampled acyclic graph,
or the outgoing206490123 tuple cannot discharge those obligations.

## Verification

12 new tests cover exact inverse/domain intersection, all candidate delta bits,
consistent alternative models, capture reuse/order and malformed metadata,
Lua truthiness, rejected assertion cases, symbolic paths and mutation isolation,
unknown jumps/cycles/budgets, historical matrix validation and pinned integration.
Full-suite results are recorded in PROJECT_MEMORY.md.

Only offline Python static analysis ran. No Lua/payload VM, assertion, field
lookup, __index, factory or application function was invoked. Original inputs
and demo/ESP code were untouched. Lua entry-script syntax is checked separately;
no Roblox runtime verification or Git push was performed.
