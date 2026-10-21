# Phase 11: deeper static payload masks and initialization transforms

## Reproduction and scope

```powershell
python tools/payload_decoder.py
python -m unittest discover -s tools -p "test_*.py" -v
```

Inputs are the same SHA256-pinned g/d snapshot. Phase10 and its prerequisites are
rebuilt in a temporary local directory. The unified output is
output/phase11/payload-analysis.json. It includes earlier primitives, descriptors,
root metadata and the expanded string/function analysis.

No Lua, factory, dynamic __index, application opcode, remote request or original
input mutation runs. Python does abstractly model reviewed numeric initialization
operations; claiming that no VM operations were modeled would be incorrect.
An OS-enforced air gap is not asserted. No push occurs. AdnHub demo/ESP changes
are paused by user direction; this phase changes only analysis tooling/docs.

## Mask equations from source

The directory XOR306486104 is distinct from the byte mask applied to the payload.
In the reviewed variant157 patch branches, the source byte masks are:

```
mix(n) = (n XOR ((n >> 29) AND 7)) AND 0x1fffffff
op11: key = H[PC] XOR mix(y); reference_id = i[PC]
op76: key = H[PC] XOR mix(V); reference_id = i[PC]
op14: key = H[PC]; reference_id = w[PC]
```

The root header supplies initial V=4179906283, y=1947447901. These yield
mix(V)=421809900 and mix(y)=336835166. For example, PC9943's encoded word336835115
gives key117 for function137; PC9945's421809851 gives key87 for string115 (`Random`).
These are source-derived equations, not keys guessed from English text.

Payload unmasking is bytewise XOR on a **copy**. It commutes with the subsequent
LCG XOR stream, allowing the Python reader to decrypt first and apply the mask
afterward. Function auxiliary is91; string auxiliary is83. Tag and length fields
are outside the patched payload and must not be XORed with that byte.

## Restricted initialization abstract interpreter

`prologue_analyzer.py` copies the four arrays and models a whitelist of numeric
initialization transformations for variants157/163/228. This includes constant
register assignments, known-register jumps, source XOR patch equations,
XOR-shift array rewrites and packed-instruction normalization. No callable
application operation is dispatched. Unknown values remain unknown.

The bulk rewrite starts at operand+1 (one-based); using operand directly would
misalign the entire reconstruction. The PRNG uses the reviewed shifts13/13/14
and29-bit masks. Every rewrite has bounds checks. The model has a10,000-step cap.

The current trace records236 abstract steps and38 unique patch equations. It
stops at PC9063, variant228/op111, a global environment read (`task`). It does not silently skip that effect. The preceding decorative
`x.V` assignment is only abstracted after its key resolves to the pinned string
`V`; no real VM table write is performed.

**Normal-continuation assumptions remain explicit.** At operations such as112,
lazy operands are not materialized/type-checked. Their result becomes unknown.
Subsequent equations describe conditional normal continuation, not proof that the
actual script reaches those sites without an exception. No runtime trace or
complete control-flow reconstruction is claimed. State-changing operations not
in the whitelist are boundaries rather than guessed effects.

Decoded initialization operands expose7 references missing from the original raw
stream scan: four function targets and three string targets. These receive their
own provenance; earlier counts are not silently rewritten.

## Function records: what is checked

The earlier34 function targets expand to38. All38 have structurally consistent
candidates, split into31 format0 VM records and7 format2 native-factory records.

- 17 masks follow source initialization equations under the guards above.
- 21 masks remain **header-constrained hypotheses**, not source-proven keys.

For format0, the hypothesis assumes first plaintext byte0, then independently
checks the leading header, factory4890 definition, all four array ranges, bounded
entry PC and the complete post-GW fill footer. Format2 is tested only for the
short8-byte family. A bounded GW reader model reaches a factory boundary and
stops before invocation; its reader cursor plus footer must consume the record.
Every referenced factory slot must exist in g.

Candidate output includes full decoded bytes as hex, SHA256, source factory
offset, layout and footer. This verifies structural consistency, not opcode
semantics or application equivalence. Only formats0/2 are tested; other possible
interpretations have not been exhaustively excluded. Native factory bodies are
not invoked, and no claim is made that all application function contents are
decompiled into clean Lua.

## Additional strings

Of the original47 masked string targets,18 now have source-derived equations.
The newly exposed three targets add three more, giving21 newly decoded candidates
and193 combined with the earlier172. Examples include `Random` and `IsServer`.

29 string-target masks remain unresolved. For them, all256 XOR bytes remain
possible: Lua strings may contain arbitrary binary bytes. Printable/UTF-8
candidate previews are emitted solely as readability hints. Even a unique
readable candidate is not automatically accepted as the correct key.

## Record1/2 correction

Directory IDs refer to typed records, not uniformly function prototypes:

- ID1: tag218, leaf58, uint32 value2503038408.
- ID2: tag174, leaf98, string `EnumType` (8 bytes).

The old assumed-function length failure for ID1 and format85 for ID2 were artifacts
of applying the aux91 function reader to non-function data. Format85 is **not a
new function schema** to emulate. Phase11 records their correct typed readings;
earlier reports retain their historical probe results.

## Prototype hierarchy and exact remaining blockers

The verified hierarchy remains null. Capture descriptors are still unassigned to
verified owning functions. Structural function headers and conditional references
are insufficient to establish lexical parenthood, execution reachability or the
association between a descriptor slot and a closure-creation operation after
all state/array rewrites.

Further static work must model the PC9063 environment dependency symbolically, then the
remaining state transitions and capture consumers. It must also replace the21
function header-mask hypotheses and29 unresolved string masks with source-derived
equations. The tool deliberately does not fabricate a complete tree or report
these blockers as resolved.

## Tests

New tests cover known mixer vectors, byte-XOR controls, abstract call boundaries,
unknown indirect jumps, budgets, one-based array rewrites, rejection of readability
as key proof, input hashes and the pinned function/string results. Runtime Roblox
and payload validation are not performed.

All76 Python tests passed (68 existing plus8 new); the Phase11 subset passed
again after refining the task-global boundary annotation. Lua syntax checks for
AdnHub.lua/Loader.lua and `git diff --check` passed. Changes remain local.
