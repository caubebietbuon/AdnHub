# Phase 14: mask constraints and prototype root causes

This phase adds `tools/obligation_resolver.py` and automated tests. It extends
the pinned offline Python analysis without Lua, payload, factory, metatable,
network or application calls. Demo/ESP files are untouched. It does **not**
complete decompilation or produce a fully verified prototype tree.

## Reproduce and evidence

```powershell
python tools/obligation_resolver.py
python -m unittest discover -s tools
luac -p AdnHub.lua Loader.lua
git diff --check
```

The runner verifies the g/d SHA256 pins and source transfer fragments, rebuilds
Phases11/13 and the root reconstruction in temporary directories, and writes
ignored `output/phase14/obligation-resolution.json`. Inputs are never modified.
`summary.json` here contains compact results; detailed traces remain local.
No Git fetch/push or external runtime is needed. This is offline analysis, not
a claim that the host machine is physically air-gapped.

## 1. Root prefix: a real fused call at8398

PC8395 is variant228/op131: `t[i[W]]=x[H[W]]`. Its operands5/109 create a
symbolic alias for decoder-context slot109; they do not call register109's
closure. The pinned context initializer contains `[109]=assert`.

PC8396 names `global.debug` in register3. PC8397/op114 reads a bounded constant
into register4: "The debug library is required on Luau platforms. Please open
a support ticket." No runtime debug library is queried.

PC8398/op93 is the real fused-call frontier:

| Transfer | Exact result |
| --- | --- |
| First copy | register2 ← register5 (context slot109 alias) |
| Lookahead T/d/I | 2/2/1 |
| Arguments | register3=`global.debug`; register4=required-library message |
| Requested result | one result into register2 |
| Normal-return continuation | PC8400 |
| Exceptional/nonreturn continuation | not established |

The analyzer does not execute assert or assume `debug` truthy. Identifying the
source binding does not by itself prove runtime slot identity or success. Both
remain explicit contracts. Root reaches363 abstract steps and45 ordered patches;
none of the18 pending string IDs is patched in this root prefix.

## 2. Exact inverse: what it proves, and what it cannot supply

For uint32 `n=(h<<29)|l`, `mix(n)=l XOR h`. Given `m`, all eight preimages are
`(h<<29)|(m XOR h)` for h=0..7. The tool enumerates this exact inverse, then
intersects it **only** with state evidence at the same owner, PC, dispatcher
and unchanged patch operands. A mismatching visit prunes that visit, not a later
visit with a different dispatcher or instruction rewrite. Header seed words are
not silently reused as future patch state.

For `key=operand XOR mix(state)`, a byte key generally leaves2048 uint32 states.
Tests include exact matching, incompatible observed states, rewritten references,
wrong dispatchers, non-uint32 states and an empty inverse domain. Local witnesses
for keys0 and255 demonstrate nonuniqueness of the local equation; they are not
claimed to satisfy all whole-program constraints simultaneously.

The regenerated potential-site scan contains15 sites across10 of the18 IDs.
This supersedes the stale nine-ID count in the Phase13 handover extract. The
scan is not exhaustive: initialization rewrites can expose additional sites.

### New guarded result: ID192 = rawlen

The bounded entry analysis now models variant163/op78 numeric branches and
op83 additions with exact integer type/range checks. All31 format0 candidates
are explored separately from their entries, without inventing caller inputs or
sharing hypothetical sibling mutations. Unknown branches and operations stop;
these are not complete path explorations.

Record711's header is revalidated against the live guarded root context and
matches the prior plaintext hash (root's mask for711 is113, observed at9952).
Its42-step prefix exposes a previously hidden patch at PC938, variant228/op100:

```text
reference = 192
key = A[938] = 5                  # direct byte mask, no PRNG guess
intermediate = 77 64 72 69 60 6b
intermediate XOR 05 = 72 61 77 6c 65 6e = rawlen
```

The path to this patch uses no assumed unknown branch decisions. The spelling
is an output of the source equation, never a readability criterion used to pick
the key. The equation remains guarded by activation of711 and its exact
directory/cache lifecycle. It is not an unconditional whole-program recovery.

Seventeen IDs still lack a reached trace equation:
74,141,160,196,203,267,269,432,457,476,485,512,545,580,616,632,702.
All18 retain null **unconditional** keys. Separately, all18 payloads are nonempty;
enumerating256 XOR bytes yields256 distinct local plaintexts for each. Length
markers outside the masked payload cannot select one key, and UTF8/readability
are not imposed as correctness constraints.

## 3. Why the four original ownership candidates do not pass

The six rules are unchanged. Source-family matching and exact descriptor parsing
pass as structural checks; header selection, control flow and unconditional
ancestry are not promoted. Register allocation fit is not a lexical-owner proof.

| Candidate | Specific missing evidence / root cause |
| --- | --- |
| 664→506, descriptor251, PC9554 | seven local cells fit hint181; source slot not reached before real assert frontier8398; runtime child selection/cache identity and ancestry unproved |
| 137→747, descriptor58, PC33 | empty descriptor makes capture bounds vacuous; projected prefix stops29 with a numeric type contradiction under the reviewed fresh-frame contracts |
| 237→572, descriptor181, PC257 | cells11/4 fit hint18; incoming capture bounds8..10 unknown; exact branch at238 evaluates11<=8=false, later stops152 on unproved `r1+1` |
| 704→288, descriptor299, PC10 | local copied values4/10 fit hint11; incoming captures1..9 unknown; PC3 requires field6 of caller argument1, whose type/value is unknown |

For137, factory4890 initializes a fresh register table via reviewed
`table.create`. Along the inspected prefix there is no write to register0,
argument transfer to it, opaque frame write or application call. PC29/op39
reads `bit32.bxor(r0,r0)` with both entries absent. Under the standard table/
bit32 contracts these are nil, so normal numeric continuation is refuted.
The tool explicitly rejects algebraic cancellation `x XOR x=0` before numeric
type proof. This refutes **that projected normal prefix** under its contracts,
not every possible activation/header/mutation context of137.

The root cause therefore is not just a permissive validator waiting for flags:
these candidates need actual typed frame inputs, source-slot control evidence
and cache/mask identity; one projected route is already contradictory.

## 4. Frame-aware structural map and unchanged tree gate

The four guarded closure bindings remain664→567,258,379,663 with descriptors
486,486,462,722. Capture ordinal1 of567/258 maps to root cell107, ordinal2 to
root cell106. Descriptor reuse is concrete evidence that descriptors do not
uniquely encode an owning parent or child prototype.

For379 the six captures map to root cells107,106,103,92,104,93. The root frontier
snapshots include numeric values0,12,12 and fresh-table identities for these
cells. Capture ordinals are not child register numbers; equal register indices
across frames do not establish aliases. Future writes can invalidate value
snapshots. No proved def-use chain yet connects these captures to the state
word at379's possible ID702 patch. The tool does not use that absent chain to
invent a mask equation.

All four original edges and the four stronger guarded source-transfer candidates
are submitted to the existing six-proof tree validator with the full expected
node inventory. Header/path/ancestry obligations remain explicit, as do incoming
capture bounds where needed. No candidate passes all six rules; rooted coverage
also remains incomplete. `verified_hierarchy` stays null. No root-only tree,
partial tree labeled complete, or artificial parent is emitted.

## Remaining obligations

Establish the assertion/environment contracts at8398 before claiming a concrete
continuation. Audit the new frontiers of the31 hypothetical entry analyses
(including711/op123 at1131) without inventing numeric or runtime defaults.
Prove actual activation and mutation history before promoting ID192's key or
capture-bound source transfers. The seventeen other IDs need new reachable
equations; repeating the mixer inverse alone cannot create those constraints.

Verification:108 Python tests pass (92 previous +16 new); Lua syntax and Git
diff checks pass. No Roblox, LuaU CLI or payload runtime validation was performed.
