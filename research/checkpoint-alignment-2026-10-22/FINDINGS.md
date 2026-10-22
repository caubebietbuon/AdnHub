# Phase 24: code-epoch alignment and exact capture checkpoints

Base `dcc4181`. The analysis is pinned, offline and static. No Lua, VM factory,
__index, application call, network access or original-input edits occur.
Demo/ESP files are untouched.

```powershell
python tools/checkpoint_aligner.py
python -m unittest discover -s tools -p 'test_*.py'
luac -p AdnHub.lua Loader.lua
git diff --check
```

Full evidence is generated under ignored output/phase24/checkpoint-alignment.json.
This directory retains compact evidence and the outstanding proof obligations.

## Align domains with the actual recorded code epochs

The new model consumes independently anchored slot revisions rather than
applying an initial packed instruction equation to a later normalized slot.
Each epoch records the tuple/equation after its rewrite and before the next
revision. The final epoch remains open to unknown future writes.

| Owner/site | Aligned status | Current mixer-domain interpretation |
| --- | --- | --- |
| 664/981 | current equation V/ref74/operand4 | 2048 necessary local candidates |
| 402/83 | retired initial pattern | no current equation to attach that domain to |
| 711/269 | retired initial pattern | no current equation to attach that domain to |
| 593/393 | retired initial pattern | no current equation to attach that domain to |
| 379/686 | retired initial pattern | no current equation to attach that domain to |

The four historical2048-element domains are retained as provenance, not counted
as four current runtime equations. Retiring an instruction hypothesis does not
recover its key, retire the string target, or exclude future reactivation.
Tests cover a later rewrite restoring a previously matching pattern and JSON
report round-tripping.

Root981 still has no proven entry-to-site V. Its unchanged-backing/exported-dir
normal path fails the patch978 reader contract, leaving zero admissible states
in that **declared model**, not a globally empty key domain. No string/key is
promoted by relabeling this rejection as a numeric solution.

## Checked primitive inputs and exact arithmetic

The opt-in transfer factory binds each symbolic prefix to its own data context.
Primitive reads use the effective directory position and reject unapplied
payload masks. Only independently translated primitive integers enter these
arithmetic rules; unknown capture values, booleans, strings and inexact-number
cases are not replaced with numeric defaults. Source lazy/cache identity remains
a normal-completion guard; no lazy reader is invoked.

Pinned variant228 source supports:

```text
97:  r[H] = constant_j[PC] + immediate_O[PC]
98:  r[A] = r[i] - constant_Z[PC]
140: r[H] = immediate_A[PC] - r[i]
```

The source fragments and offsets are exported. Every integer operand and result
must fit the exact-number range through2^53. Backward slices independently
reconstruct the results and check agreement with forward arithmetic observations.

| Frame/site | Equation | Result |
| --- | --- | --- |
| 663/546 | r6 - primitive735 =871012737 -664522614 | r8=206490123 |
| 379/1852 | primitive56 +19 =1+19 | r4=20 |
| 379/1853 | 0-r4 | r8=-20 |
| 379/1839 | primitive60 +19 =255+19 | r7=274 |
| 258/37 | primitive56 +19 | r5=20 |
| 258/38 | 1-r5 | r6=-19 |

Closure663's r6 definition is PC545's reviewed y-state read, not a frozen
capture or an invented argument. Its subtraction slice leads through the
header y word871012737 and primitive735 at134412. Primitive56 is a uint8 at
101425; primitive60 is a uint8 at487. Code paths retain all activation guards.

## Parallel fused call at closure663/547

The source-proven variant228/op4 performs two parallel copies before reading
the lookahead call metadata. The summary preserves the pre-copy source values,
including overlap cases, and never invokes the callee.

For this checkpoint:

```text
r6 <- old r4 = enclosing capture1's value
r7 <- old r8 =206490123
callee =r6; arguments =[r7]
requested result slots =[r6,r7]
normal-return continuation =PC549
```

Two requested slots are not proof that the function returns two values.
Actual return values and call effects remain unknown.

The guarded constructor binds663 capture1 to root664's cell159, whose root
frontier body candidate is379. Thus the analysis exposes a **conditional**
663→capture1→cell159→body379 call candidate with the exact numeric argument.
It is not a lexical parent edge or an actual activation witness. The required
proofs still include actual663 entry, cell159's value at the call, callee/cache
and captured-environment identity, normal read/call behavior and alias effects.

## Remaining exit and lifetime boundaries

The advanced prefixes now stop at:

| Frame | Frontier | Meaning |
| --- | --- | --- |
| 663 | 547/228op4 | parallel fused call, summarized but never called |
| 379 | 1840/228op113 | next unmodeled allocation transfer |
| 258 | 40/228op113 | next unmodeled allocation transfer |
| 567 | 24/163op83 | numeric capture-dependent addition still unproved |
| root664 | 8398/228op93 | assert/debug call boundary remains guarded |

The reviewed close-before-return/tailcall contracts from Phase23 remain source
contracts. None of these checkpoints proves a complete exit path, actual
invocation order, all alias writes/escapes or unconditional ancestry. Legal
capture mutation is not ruled out; call-time values must be accounted for.
All six structural criteria and activation/lifetime/tree gates remain intact.
`verified_hierarchy=null`; the formal promotion patch remains non-applicable
with an empty operations list. Complete lifetime/activation proofs are not claimed.

## Verification

New tests cover epoch retirement/restoration, JSON compatibility, effective
directory and mask guards, exact arithmetic and unknown/inexact rejection,
context isolation, backward subtraction provenance, parallel-copy call packing,
frame bounds and pinned integration. Final counts are recorded in
PROJECT_MEMORY.md. Lua syntax checks apply to repository entry scripts only;
no Roblox or payload runtime checks are performed.
Final verification:222 tests passed (207 prior +15 new), including pinned
integration and backward/forward agreement. Lua syntax, Python compilation and
Git diff checks passed.
