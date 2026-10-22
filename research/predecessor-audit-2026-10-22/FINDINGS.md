# Phase 18: high dispatcher fallback and closure567 binding

All work is static/offline Python data analysis. No payload, Lua, factory,
metatable or application is invoked; demo/ESP files are untouched.

```powershell
python tools/predecessor_auditor.py
python -m unittest discover -s tools
luac -p AdnHub.lua Loader.lua
git diff --check
```

The runner rebuilds the pinned Phase14 snapshot, including post-prefix arrays.
Detailed output is ignored `output/phase18/predecessor-proofs.json`; summary.json
here retains the proof data. Source and binary inputs remain unchanged.

## 14842 is a recognized dispatcher fallback

Phase17's classification as an undecoded opcode was incomplete. In variant228
the source predicates for14842 select the following branch:

```text
o>=99, NOT(o<148), NOT(o<173), o>=185, o>=191,
NOT(o<194), NOT(o<196), NOT(o==197)
=> t[i[W]] = _(t[H[W]], A[W])
```

The factory's alias prefixes and source binding `[20]=bit32.bxor` identify `_`.
This fallback covers196 and integers>=198;197 instead selects array rewriting.
The dispatcher does not enforce a byte-sized opcode domain at this branch.
There is therefore no basis to force14842 through an invented packed-instruction
decoder merely because it exceeds255.

Current root PC980 has `(opcode,i,H,A)=(14842,13,9,38)`, so its exact assignment
is **r13=bit32.bxor(r9,38)**. On normal completion its successor is981. It writes
neither V nor y. Tests verify literal numeric transfer, unknown-input numeric
predicates and the197 exception. Bit32 conversion outside proved uint32 operands
remains symbolic; no arbitrary default for r9 is supplied.
This classification assumes arrival under variant228 with the unchanged current
slot; actual entry-to-site reachability is still unproved.

The localized trace now contains980→981, resolving the previous semantic barrier.
It still needs numeric r9 for normal completion and V's reaching definition at981.
The state remains symbolic; no string key is claimed. Register provenance from
the recorded root frontier is supplied as context only, not substituted at980.

## Rewritten-site alignment

The tool searches all slots of each relevant owner snapshot for the exact old
equation signature, then scans all three reviewed dispatcher variants for patch
sites referencing the same ID. These are candidate searches, not identity proofs.

| Owner / old PC | Current tuple under old variant | Exact-signature PCs | Same-reference candidates |
| --- | --- | --- | --- |
| 664 /981 | 125,74,4,47 | 981 | 2 |
| 402 /83 | 0,53,51,91 | none | 0 |
| 711 /269 | 54,130,122,74 | none | 0 |
| 593 /393 | 0,254,0,32 | none | 0 |
| 379 /686 | 2,645,40,99 | none | 0 |

There is no justified relocated address for the four mismatches in this snapshot.
Their references may become visible after other instruction rewrites; the result
does not prove they vanished permanently. Even the root's two same-ID candidates
are not interchangeable: dispatcher and rewrite lineage must establish identity.
The output records `relocation_verified=false`, with current operands and all
candidate sites. No false realignment or state-key promotion is performed.

## Closure567 scoped proof

The regenerated guarded source transfer at root8390 binds descriptor486 through
factory4890. The descriptor contains two local-cell captures within the proposed
root allocation. Capture ordinal1 is exactly `frame:664:register:107`.

The backward slice proves register107 is0 immediately before construction.
Scanning the rest of the recorded root prefix finds no direct register107 write.
This establishes scoped direct-write stability and structural binding, under the
existing root activation/decoder/cache assumptions. It does not establish child
activation order or exclude unmodeled alias effects outside that prefix.

Accordingly, `guarded_binding_structurally_verified=true` and
`prefix_direct_write_stability=true`, while `child_activation_verified`,
`whole_lifetime_alias_stability_verified` and `hierarchy_admissible` remain false.
No historical validator rule is weakened; `verified_hierarchy` stays null.

## Verification and next obligations

148 Python tests pass (142 prior +6 new), including source fallback predicates,
the197 exception, exact and symbolic XOR transfer and pinned binding/alignment.
Lua syntax and Git diff checks pass. No Roblox or payload runtime checks.

Next analysis must establish r9/V at the actual root980/981 path and track the
remaining code normalization lineage for the four hidden sites. For567, prove
actual activation and capture lifetime/alias effects before ancestry promotion.
Offline processing does not imply physical isolation of the host.
