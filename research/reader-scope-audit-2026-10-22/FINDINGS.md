# Phase 21: reader-family correction and closure663 scope audit

Base: `12177a5`. Inputs are the same pinned g/d snapshots. Analysis is entirely
offline Python over text and bytes; no Lua, factory, __index, application or
network execution. The original inputs and demo/ESP files are unchanged.

```powershell
python tools/reader_scope_auditor.py
python -m unittest discover -s tools -p 'test_*.py'
luac -p AdnHub.lua Loader.lua
git diff --check
```

Full regenerated evidence is ignored under
`output/phase21/reader-scope-proofs.json`. A compact summary is tracked here.

## Correction: offset134543 is a primitive, not a malformed string record

The post-fill backing has tag195 at134543. The reviewed tag predicates route
it to leaf130, the fixed-width uint8 reader with auxiliary255. For reference101,
the one-byte ciphertext is180 and the independently reviewed decoder produces4.
There is **no length field in that primitive schema**. A length exception from
unconditionally calling `read_length_payload` is not evidence that this record
is corrupt. The corrected analysis selects the primitive reader without editing
any bytes. The value4 is a primitive observation, not a newly recovered string.

For comparison, forcing a raw patch-handler length read at134544 interprets
`b4 db 0f` as1492916 and ends the prefix at134547. Only17630 backing bytes remain.
This counterfactual raw read is kept separate from the correct typed reader.

`typed_probe` performs this schema selection for the reviewed primitive,
length-prefixed and unresolved reader families. Unknown families never receive
an invented layout. `raw_prefix` explicitly labels its result as an untyped
patch-handler read.

## Directory transformations and the limits of a static correction

Directory XOR is306486104. Repeated toggles alternate between two positions:

| Toggle parity from exported directory101 | Position | Result |
| --- | --- | --- |
| even | 134543 | primitive uint8; value4 |
| odd | 306616023 | outside backing length152177 |

These are algebraic parity cases, not asserted mutation histories. The source
variant228/op125 at978 does not dispatch on the target tag: it toggles/writes
the directory, reads a raw length, then masks only the payload after that prefix.
Consequently:

1. With the unchanged directory, the toggled position is out of bounds.
2. With a hypothetical prior toggle, the position returns to134543, where the
   source's raw length read exceeds the backing limit.
3. Neither rejection depends on the byte mask. The mask is used only after
   the length has been read and cannot repair this prefix within that handler.

The exact source fragments and offsets are exported. The known shared-V
relation `key74 = key101 XOR49` remains conditional. No new reaching state,
string key or normal path through978 is proved.

`copy_payload_patch` models the source's bounded XOR transformation on an
independent byte copy. It rejects invalid directory values, lengths and keys,
preserves the prefix and all bytes outside the payload span, and never clamps
a length or mutates an input. All256 byte keys are tested on a synthetic fixture.
Its failure is transactional for the analysis; the source itself writes the
directory before its subsequent read can fail. This distinction is explicit.

No source-proven replacement prefix exists for this snapshot. Fabricating a
shorter length would change the data format rather than recover it. The new
module corrects reader selection and provides guarded patch modeling; it does
not claim to repair payload bytes or unblock the state-dependent equations.
An additional data/directory mutation or different code-version path would
require independent provenance before a repair could be justified.

## Scope and lifetime of closure663 / root107

| Closure | Construction PC | Body register | Direct captures |
| --- | --- | --- | --- |
| 567 | 8390 | root108 | root107,106 |
| 258 | 8391 | root109 | root107,106 |
| 379 | 8393 | root159 | root107,106,103,92,104,93 |
| 663 | 8394 | root85 | root159,105 |

All four are constructed in the same guarded root664 frame. At663 construction,
capture1 points to the cell root159 containing closure379. It does not directly
capture root107. The transitive captured-body graph is:

```text
663 --capture1--> root664 cell159 --current body value--> 379
379 --capture1--> root664 cell107 <--capture1-- 567 / 258
```

This is an alias graph, not a verified lexical prototype tree or invocation
graph. Register numbers in another frame are explicitly excluded as aliases.
Likewise, root register109 containing closure258 is distinct from decoder
context slot109 supplying the assert callee at the current root frontier.

The four observed body-register intervals start at trace steps354,355,357,358
and remain right-censored at the363-step analysis frontier. No later overwrite
is recorded. Their complete lifetimes are not thereby known; a register overwrite
also would not imply destruction of an already captured cell.

The source close-cell assignment rebases a shared cell to self-storage:
`cell[6]=cell; cell[4]=frame_value; cell[5]=4`, then removes the open-cell map entry.
This preserves the cell identity held by existing aliases. Its presence in the
source is not proof that a close event was reached for these closures.

Hypothetical child entries stop at PCs24/37/1849/544 for567/258/379/663. No actual
activation or complete alias-effect/lifetime coverage is established. The six
existing proof flags remain three structural passes and three failed/unproved
obligations for each candidate: live child-header identity, control flow, and
unconditional ancestry. No rule is relaxed. Promotion remains non-applicable,
operations are empty and `verified_hierarchy` remains null.

## Verification

New tests cover schema selection, fixed-width primitives, length boundaries,
truncated prefixes, unknown readers, all byte masks, parity, immutable inputs,
source order, scoped aliasing, overwrite-versus-cell lifetime, ambiguous
construction and pinned integration. Final regression counts are recorded in
PROJECT_MEMORY.md. Lua syntax checks concern the repository entry scripts;
no Roblox or payload runtime test is performed. Final result:181 Python tests
passed (167 prior +14 new), including pinned integration. Lua entry-script
syntax, Python module compilation and working/staged diff checks passed.
