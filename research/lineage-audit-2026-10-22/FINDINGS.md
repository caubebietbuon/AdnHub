# Phase 19: numeric lineage and activation/lifetime ledger

This phase remains entirely offline/static. No Lua, payload, factory, metatable
or application calls are executed. Demo/ESP files are untouched.

```powershell
python tools/lineage_auditor.py
python -m unittest discover -s tools
luac -p AdnHub.lua Loader.lua
git diff --check
```

The tool rebuilds pinned post-prefix arrays and validates the exact978..981
window before deriving any cross-site equation. Output stays ignored in
`output/phase19/lineage-proofs.json`; summary.json here retains proof metadata.

## r9: recorded definition and the missing site definition

The only recorded root definition of r9 is variant163/op109 at9910. Its source
is r35. The backward slice ends at an absent fresh-frame entry for r35; the
forward abstract observation is None, not a numeric constant. The source-pinned
argument-transfer contract is also exported: root9942/op80 has T=1,I=7, so
its fixed-argument copy range is empty and its packed-tail destination is r7.
This is not evidence of a numeric argument flowing into r35.

These are recorded-prefix facts. They do not justify substituting nil,0 or any
other value at PC980 across unvisited code. A reaching numeric definition of
r9 on an actual entry-to-980 path is still missing. Under a numeric bit32
normal-return contract, normalized r9 and r13 each range over uint32; no unique
numeric value is deduced. The register's frontier slice remains separate from
its required site input.

## V: relational constraints and a concrete rejected path premise

The source-checked local window under variant228 is:

| PC | Decoded behavior |
| --- | --- |
| 978 | patch reference101 with key53 XOR mix(V) |
| 979 | numeric r88<66 falls through; otherwise successor113 |
| 980 | r13=bit32.bxor(r9,38), on numeric normal completion |
| 981 | patch reference74 with key4 XOR mix(V) |

V is not assigned within this local window. If the same uint32 V is used and
both patches belong to the modeled byte-mask layer, cancellation proves:

```text
k101 = 53 XOR mix(V)
k74  =  4 XOR mix(V)
k74  = k101 XOR 49
```

The exact inverse yields2048 V candidates and256 distinct key pairs. The tool
checks the full finite domain; no pair is chosen for readable output. Root's
recorded frontier V=4179906283 does not yield byte-sized keys at these sites.
This excludes freezing that frontier value in the **byte-key model**. It is not
a proof excluding an unmodeled wider word-mask layer.

There is an additional directory contradiction for the unchanged snapshot:
reference101 currently holds134543; the patch's directory XOR306486104 yields
306616023, outside the152177-byte backing slice. No root-prefix patch changed
ID101. Thus the proposed straight-line normal path through978 fails the bounded
reader contract in this unchanged directory. A prior directory mutation,
different code version or different incoming path needs proof. Other incoming
paths to979/980 are not globally excluded.

This refutes a specific activation premise; it does not provide a final V or
string key. It is stronger than carrying the old initial seed forward by default.

## Four mismatched equations

The tool repeats the same-reference search across the three reviewed variants
and every slot of owners402/711/593/379. The four old sites still expose no
matching patch candidates in the current rewritten arrays. Register lineage
cannot by itself repair a missing instruction identity. All relocation flags
remain false; further normalization/rewrite history is required.

## Closure567 activation and lifetime

The body value is constructed into root register108 at8390. Creation is not
invocation. The current root call frontier is the known symbolic assert/debug
call at8398, not an activation witness for567. The ledger records no witnessed
567 invocation, without asserting that the function can never be called later.

Cell `frame:664:register:107` is shared by closures567,258 and379. Therefore
absence of direct root107 writes in the recorded root prefix does not prove
whole-lifetime stability. Invocation order, cell alias escapes and sibling
capture effects still need summaries. No assumption of immutability is made.

The formal promotion object is emitted with `applicable=false` and an empty
operations list. Activation, lifetime, unconditional ancestry and coverage
remain unproved; `verified_hierarchy` remains null. No speculative patch to the
verified tree is prepared as an applicable change.

## Verification

155 Python tests (148 prior +7 new), Lua syntax and Git diff checks pass.
New tests exercise every coupled key pair, non-byte input rejection, directory
history-dependent guards, creation versus activation, sibling aliasing and
pinned lineage. No Roblox or payload runtime validation was performed. No
network was used; physical host isolation is not claimed.
