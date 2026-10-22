# Phase 26: provenance bridges and independent closure663 sub-gates

Base: local `a1ef3ca`. Run `python tools/provenance_bridge.py` using the pinned
local g/d files. Their hashes are in `summary.json`. The tool rebuilds Phase24
evidence, including private backing copies; it does not trust saved output JSON.
Full output: `output/phase26/provenance-bridge.json` (ignored).

## Results

- A guarded mixed dependency/control route connects **root's earlier entry V**
  to the hypothetical checkpoint. It is not an equality or a path from V at981.
- No numeric bridge from **root664 PC981 V** to argument206490123 is established
  in the recorded graph. The byte-mask domain remains **2,048 candidates**.
- The cached663 template matches the checkpoint's original plaintext hash and
  header words. A later failed backing reread does not refute that cached header.
- The18 parent gates are decomposed into36 independently named sub-gates:
  **16 local evidence items,20 open obligations, zero discharged parent gates**.
- No string key or hierarchy edge is promoted. `verified_hierarchy=null`.

## Typed path finder

`EvidenceGraph` distinguishes copy equality, general data dependency, control
edges, payload transformations and captured-cell addresses. Nodes identify SSA
versions and trace steps; repeated PC9841 visits remain distinct. Searches are
bounded, directional and cycle-safe. Unknown operations/frames/calls remain
open; no-path and budget-exhausted results never imply global impossibility.

The exported graph contains886 nodes/1021 edges across five separately guarded
frame prefixes (664,663,379,258,567). It is not a whole-program CFG. Prefix
assumptions and invocation/cache conditions are exported alongside queries.

The mixed route has14 edges:

1. Root's entry V is an input to patch9840, variant163/op96.
2. Recorded control edges lead through9841 (two instruction versions),9842,
   9843,9825,9826,9827 to9828.
3. Root9828, variant228/op100, patches663 with the **direct operand227**.
4. The decoded/cached template supplies663's header y871012737.
5. PC545 copies y; PC546 subtracts primitive735=664522614; PC547 packs206490123.

This route combines data, control and payload relations. It does not say that
the incoming V value is preserved as the argument, nor constrain future V at981.
Local template hash agreement and read-before-fill observations discharge two
local evidence guards only. The route retains root/663 prefix assumptions and
the primitive/cache binding guard. Actual invocation and future alias histories
remain unproved. A data dependency through a transformation requires its exact
equation before inversion; a control path alone supplies no numeric equality.

`filter_through_bridge` accepts only fully guarded copy identities plus a
discharged value-observation premise as equality filters. Tests verify valid
synthetic pruning and rejection of arithmetic/control/address shortcuts. The
actual query has no admissible copy bridge, so pruning is not applied.

## Pre-fill template versus post-fill backing

The663 root patch at9828 uses key227; its directory transition is
306569851 ->96547. The guarded constructor at8394 uses descriptor722,
factory4890 and destinationr85. Before its cleanup, the cached plaintext hash is
`e234c9c4ac2f7bca7c526e126939c1f137a97843a0192f1761e332ec4bf11309`.
This exactly matches the checkpoint candidate. Header words are
V2811776362/y871012737, entryPC606; stream lengths j743/O745/Z743/B743.

The existing `live_header_matches_root_context=false` attempts a backing reread
after template cleanup. The saved template and the backing are different
temporal observations. Header/candidate consistency is established locally;
the actual VM's shared-cache identity at invocation is still unknown. No
factory, dynamic cache lookup or child body was invoked to obtain these facts.

## Gate and register audit

See `SUBGATE_MATRIX.md` for every sub-gate and its explicit open predicate.
Full evidence links each relevant gate to register/cell contexts:

- Rootr85 has the guarded663 closure definition at8394.
- Before capture, rootr159 has body379 from8393; rootr105 is10054 from1006.
- Neither159 nor105 has a later direct write in the recorded prefix. This
  excludes direct prefix writes only; it does not exclude alias writes or prove
  their values at invocation.
- Hypothetical663 entry606 copies arguments1..3 into registers1..3. Their values
  remain symbolic; the outgoing constant argument is not an incoming type proof.
- Root's frontier8398 call is still the assert/debug boundary, not a663 call.
- A reviewed228/op4/op93 snapshot scan finds no direct pre-copy callee source85.
  The scan respects both parallel source versions and single-copy overwrites.
  Other call forms, indirect aliases, future rewrites and other dispatchers are
  not excluded; this result is not an absence-of-activation proof.

Global incoming ownership, complete inventory and cycle coverage remain open.
Local observations do not discharge universal lifetime/activation gates, and no
verification rule is relaxed. The promotion patch remains inapplicable/empty.

## Verification and next work

13 new tests cover typed paths, cycles and budgets, alternative unguarded paths,
guard preservation, copy-only filtering, frame separation, call source versions,
cached-header agreement, register lineage and all hierarchy blocks. Full-suite
results are recorded in PROJECT_MEMORY.md.

Next evidence needed is a reaching definition for V at981 and an actual incoming
663 invocation with stable template/cell identity. A newly discovered arithmetic
dependency must be modeled and inverted explicitly; it must not be treated as a
copy. Complete the20 open sub-gates using their recorded predicates.

All work remained offline/Python-static. No payload/Lua VM, interpreter factory,
dynamic __index, application call, network request or original-input modification
was performed. Lua entry-script syntax is checked separately. No Roblox runtime
verification or Git push was performed; demo/ESP code remains untouched.
