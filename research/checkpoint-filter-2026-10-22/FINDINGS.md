# Phase 25: qualified checkpoint constraints and closure663 proof audit

Base: local `55affbe`. Reproduce with `python tools/checkpoint_filter.py`.
Inputs are rebuilt through Phase24, including fresh backing reconstruction;
existing output files are not accepted as proof inputs. SHA256 values are in
`summary.json`. Full generated evidence is in `output/phase25/checkpoint-filter.json`.

## Result and exact candidate-domain proof

**No string key or hierarchy edge was promoted. All 2,048 necessary local V
candidates remain.** This is an unresolved result, not completion of decryption.

Let V = h*2^29 + l, with 0 <= h < 8 and 0 <= l < 2^29. The proven mixer is
`mix(V) = l XOR h`. For the current root664:981 equation,
`key = 4 XOR mix(V)`. Under the existing byte-key assumption, bits8..28 of l
must be zero, and its low8 bits are free. Conversely every such V produces a
byte key. Thus exactly 8*256 = 2,048 states remain; enumeration independently
matches the inverse-mixer domain. Wider key models are not excluded globally.

Closure663's checked checkpoint is `871012737 - 664522614 = 206490123`:
PC545 reads that frame's **y**, PC546 subtracts primitive735 into r8, and PC547
copies the old r8 into argument r7. The forward arithmetic, backward slice,
primitive observation, frame identity and parallel copy agree. Its lazy-cache
and activation premises are still explicit.

The variable `(663, pc547-precall, register, r7)` is distinct from
`(664, pc981-entry, state, V)`. The current slice contains no connecting
assignment, call-parameter transfer or state-write proof. Projecting the
checkpoint equality onto the root domain therefore prunes **zero** candidates,
even conditionally assuming the checkpoint's activation/cache guards hold.
This is independence in the reviewed finite relation, not proof of global
independence across all application paths.

As a falsification diagnostic only, the unproved equation V=206490123 would
yield key206490127. The value has forbidden bits9,11,14,15,17,18,19,22,26,27
set in the byte-key model and would reject all candidates. That equation is
**not applied**. An empty domain obtained that way would be an invalid recovery.
Existing patch978 geometry still rejects the unchanged-backing/exported-directory
path model; that scoped rejection is retained separately from the mixer domain.

## Closure663 activation and lifetime

The ledger lists all six structural, six activation, seven lifetime and three
global-tree obligations separately. Three construction/descriptor structural
facts and slot-definition-before-capture pass; the remaining18 conditions are
not established. False upstream flags represent unproved criteria here, not
proof that the application cannot activate this closure.

Root construction captures cells root159 and root105. The hypothetical PC547
call reads capture1; its frontier body candidate379 does not prove the value at
invocation, an actual root-to663 call, or lexical parentage. An outgoing call
from663 is not evidence that663 itself was invoked.

The reviewed call-outcome partition is:

| Conditional outcome | Continuation | Outstanding proof |
| --- | --- | --- |
| Normal return | PC549 | Callee identity, r6/r7 results, alias effects, complete continuation and close-path coverage |
| Error | No normal successor assumed | Caller protection, unwinding and escaped-cell semantics |
| Nonreturn | No normal successor assumed | Termination/nonreturn characterization and effects on finite prefixes |

These are proof cases, not witnesses that each outcome occurs. Reviewed exit
candidates47,431,536 have no reached-exit witness. No complete all-path close,
rebind, alias-effect or activation proof exists. `verified_hierarchy` remains
null and the promotion patch is inapplicable with zero operations.

## Next evidence needed

Trace a source-proven chain from the relevant frame/call parameter to root V at
PC981, including code epoch and guards, before applying checkpoint arithmetic
as a root filter. Separately, prove an incoming663 call with live template/cell
identity and cover its continuation and escaping-cell outcomes. Do not assume
frontier values are immutable or fill missing returns with defaults.

## Verification

New tests exercise qualified equality projection, exact inverse-domain/free-bit
agreement, undischarged guards, inconsistent relations, invalid numeric inputs,
corrupted checkpoint provenance, parallel source versions, pinned reconstruction
and all promotion blocks. Full-suite results are recorded in PROJECT_MEMORY.md.
Only Python static analysis ran; no Lua payload, interpreter factory, application
call, dynamic __index, network request or input-byte modification was performed.
Lua entry-script syntax is checked separately; Roblox runtime remains untested.
