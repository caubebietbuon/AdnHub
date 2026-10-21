# Phase 13: dispatcher correction and guarded transfer proofs

This audit supersedes Phase12's classification of PC9251 as a fused call.
It does **not** claim complete decompilation, unconditional ancestry, or a
working equivalent Roblox script. All work is offline Python analysis of the
pinned g/d snapshots; no Lua, payload, factory, task API or network execution.
The machine itself is not claimed to be physically air-gapped.

## Reproduce

```powershell
python tools/fused_call_analyzer.py
python -m unittest discover -s tools
luac -p AdnHub.lua Loader.lua
git diff --check
```

Requires the existing pinned `output/stage1-vm-source.lua.txt` and
`output/stage1-vm-data.bin`. The runner validates both SHA256 hashes before
analysis. It rebuilds prior artifacts in a temporary directory rather than
trusting stale phase reports. Detailed evidence is written to ignored
`output/phase13/fused-call-analysis.json`; `summary.json` here is a compact
handover extract. Inputs are not modified. No Git fetch/push is needed.

## 1. Exact dispatcher and register provenance

The pinned variant228 subtree at source offset49745 has the following truth
table. Each result includes the evaluated numeric predicates in the JSON.

| Opcode | Handler |
| --- | --- |
| 92 | indirect jump |
| 93 | fused call |
| 94 | multiplication |
| 95 | field lookup |
| 96 | boolean negation |
| 97 | constant addition |
| 98 | subtraction |

The `o>=92`, `o>=95`, `o<97`, `o==96` predicates are respectively true, true,
true, false for95. Thus the selected source assignment is
`t[H[W]]=t[A[W]][j[W]]`, not the sibling fused-call assignment.

At9063, register72 receives the symbol `global.task`. At9251, opcode95 has
`j=108, H=57, A=72`: register57 becomes the symbolic expression `task.cancel`.
At9252, opcode100 independently patches ID736 with byte75. At9253, opcode95
has `j=107, H=14, A=72`: register14 becomes `task.spawn`. These are expressions,
not API calls or claims that the runtime lookups cannot fail. The report records
all writes to72/57/14 and full register snapshots around these instructions.

For actual opcode93, the exact transfer is:

1. Copy `t[H[pc]]` into `t[A[pc]]` **before** resolving the callee.
2. Read the next cell: `T=A[pc+1], d=H[pc+1], I=i[pc+1]`.
3. Call the post-copy `t[T]` with registers `T+1 .. T+d`; zero arguments if d=0.
4. `table.pack` preserves actual results, including nil positions; move the
   requested I results to `t[T .. T+I-1]`, including nil for missing results.
5. On normal return only, the handler increment and loop increment give PC+2.
   Exceptions/nonreturn do not have a proven continuation. Callee effects remain
   unknown and are never executed by this analyzer.

The report also records the explicitly rejected counterfactual93 decode at9251:
it would overwrite register72, consume the real9252 patch as call-frame data,
request736 results into registers75..810 and skip that patch. This is rejected
by the numeric dispatch predicates, not by treating181 as a hard register bound.
`table.create(181)` is an allocation hint, not a Lua table index limit.

## 2. Guarded progress and closure transfer

The new optional mode preserves the old Phase11/12 default analysis behavior.
Its path-local directory view applies only patches already observed, preserving
their order. It never preloads future string keys. A repeated directory toggle
that leaves the backing buffer stops analysis. Additional transfers include
exact integer addition (bounded by2^53), state-word reads, fresh plain-table
allocation and bounded register-to-table copies. External tables/metamethods
are never accessed. Normal completion of opaque operations remains a guard.

Root664 now records360 abstract steps and45 patches, stopping at PC8395,
variant228/op131. Compared with the Phase11 prefix, the seven additional patches
are736/75,606/194,349/208,303/12,258/246,672/121,455/92 (ID/key).
The state word y changes from1947447901 to2639318406; subsequent equations use
the updated value rather than assuming the header word persists.

Four source-consistent symbolic closure bindings are observed on this guarded
root path:664→567 at8390,664→258 at8391,664→379 at8393,664→663 at8394. These use
descriptors486,486,462,722 respectively. Child bytes are checked using the
current path's XOR key; reader/footer bounds must consume each record exactly.
Factory4890's two construction prefixes are inspected as local alias assignments
returning function literals. This is a source transfer under the reviewed plain
decoder-table guard, not invocation of a constructor or its returned body.
Validated child fills affect a private backing copy only.

Captures107 and106 of567 and258 share the same frame/register cell identities.
The other captured root cells are103,92,104,93 for379 and159,105 for663. This
establishes alias relationships in the guarded model, not a complete lexical
tree. No relation is promoted to unconditional ancestry.

## 3. Six-criterion audit of the four original candidates

All four match a reviewed source consumer family and fully parsed descriptor.
Actual activation, source-slot stability and exact directory/cache state still
need proof. The candidate PCs have **not** been reached in the audited contexts.

| Candidate / descriptor | Capture audit | Static frontier before candidate |
| --- | --- | --- |
| 664→506 /251, PC9554 | seven local cells53,121,54,109,95,110,111; fit allocation hint181 | root8395 |
| 137→747 /58, PC33 | zero captures; bounds vacuous | 29 |
| 237→572 /181, PC257 | local cells11,4 fit hint18; enclosing captures8,9,10 lack owner bounds | 238 |
| 704→288 /299, PC10 | copied registers4,10 fit hint11; enclosing captures1..9 lack owner bounds | 3 |

The four per-edge reports retain all six fields:
`source_consumer_verified`, `descriptor_parsed_exactly`,
`capture_indices_fit_owner`, `child_header_verified`, `control_flow_verified`,
`ancestry_unconditional`. The last three are not promoted. A header hypothesis
or source-mask-plus-layout check is not proof that that exact child is selected
and constructed at the candidate site. Allocation fit also cannot prove capture
ownership. The two enclosing-capture cases retain explicit unknown bounds.

Parent137/237/704 explorations are separately labeled hypothetical activations
using the root-prefix directory context, their own validated fill, and unknown
incoming captures. They establish neither actual call order nor runtime input
identity. Unique ancestry, rooted coverage and cycles remain subject to the
existing proof-gated validator. `verified_hierarchy` remains null.

## 4. Exact mixer inverse, unresolved strings

For a uint32 state `n=(h<<29)|l`, with0≤h<8 and0≤l<2^29,

```text
mix(n) = l XOR h
mix(n)=m  <=>  n=(h<<29)|(m XOR h), h=0..7
key = operand XOR mix(n)
```

Thus there are exactly eight preimages for every29-bit mixer output. Restricting
key to a byte yields at most2048 state candidates, not a unique key. The utility
can intersect this domain with independently proved allowed keys; tests check
all eight high-bit classes and exact forward substitution. This result assumes
a uint32 state, which must be established at the relevant instruction.

Variant-specific scanning now records15 potential patch sites across nine of
the18 IDs, with explicit dispatcher, unchanged-slot, owner-header and reachability
guards. It records the operand, state variable (V/y), equation and finite-domain
size/hash. These are potential sites; no guard is silently asserted. The other
nine IDs have no sites in the scanned arrays. Self-modifying instructions and
unreached paths mean this is not exhaustive program coverage.

All18 retain the full unconditional byte-key domain:
74,141,160,192,196,203,267,269,432,457,476,485,512,545,580,616,632,702.
No newly reached path in this audit yields an equation for them. Ownership
candidates cannot supply proven cross-frame register identities yet. Inventing
such identities would turn a candidate relation into a false constraint.
UTF8, printability and entropy are not key proofs. No additional strings are
claimed recovered.

## Next proof obligations

Audit the exact variant228/op131 source transfer at root8395 before any further
continuation; inspect the separate29/238/3 frontiers of candidate owners. At
each frontier, retain caller/callee effects, shared lazy caches and capture-cell
identity constraints. Only propagate masks through an established frame mapping.
The new closure bindings provide concrete guarded cells to inspect, while the
four original candidate edges remain unverified. No dummy values or payload
execution are introduced to cross these boundaries.
