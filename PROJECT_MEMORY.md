# AdnHub — project memory

## Purpose and current state
Roblox client UI written in Lua/Luau, for the Steal an Egg project.
Repository: https://github.com/caubebietbuon/AdnHub ; branch: main.
The UI and local graphics toggle work independently of game mechanics.
Farm, Auto Steal, Base Return, Vacuum, egg filter and ESP are UI demos;
no game integration is implemented. Do not report these as operational.

## Files and code map
- AdnHub.lua: standalone script; services and GUI parent helper at the top.
- Themes: shared colors.
- tween: shared TweenService helper; first argument must be an Instance.
- AdnHubLib:Notify: notification ScreenGui, cards and delayed removal.
- AdnHubLib:CreateWindow: main UI, dragging, minimize, close, keyboard input.
- connectInput and ScreenGui.Destroying: lifetime of service/input connections.
- Window:Destroy: unload UI, notifications and restore graphics.
- Window:Reset: restore window position and minimized state.
- Window:CreateTab / TabObj:Activate: navigation and transition animations.
- TabObj:CreateSection: Toggle, Slider, Button, Dropdown, Banner components.
- Bottom of AdnHub.lua: Contact, Farm and Settings screen configuration.
- Loader.lua: download and execute main/AdnHub.lua; report failure accurately.
- README.md: public usage and feature documentation.

## Known fixes — 2026-10-21
- Unable to cast value to Object: oldTab.Button.Name is a string property,
  not the child TextLabel. Keep explicit NameLabel / ActiveIndicator references.
- Preserve LayoutOrder for tabs, sections and controls.
- Disconnect global input subscriptions on GUI destruction; destroy prior window
  before recreating. Cache executor GUI container when protection creates a Folder.
- Minimize callbacks use a version token; keyboard visibility respects minimized state.
- Ignore cancelled outgoing tab tweens when hiding pages.
- Guard delayed button animations after unload.
- Boost FPS saves/restores GlobalShadows and existing particle/trail/fire/smoke/sparkle
  Enabled values. It does not track effects spawned after activation.
- Loader has no fallback; failure text must not claim that a retry occurred.

## Verification and next debugging session
Run `git status --short --branch` before editing. Preserve local changes.
Run `luac -p AdnHub.lua`, `luac -p Loader.lua`, `git diff --check`.
Lua 5.1 parsing checks syntax only; it does not validate Roblox APIs.
In Roblox verify: Contact -> Farm -> Settings; rapid switching; minimize ->
Right Ctrl twice -> restore; rapid hide/show during minimize; reset; toggle FPS
on/off; unload then rerun; verify no retained input callbacks or duplicate UI.
Executor-specific GUI protection and actual Roblox rendering need runtime testing.

## Deployment gotcha
The README loadstring fetches GitHub main, not this local working tree.
Local fixes do not reach that URL until committed and pushed. Record the commit
and exact script URL when comparing a reported stack trace. Line numbers move;
search the function names above instead of relying on old line numbers.

## Source audit — 2026-10-21
See research/source-audit-2026-10-21/REPORT.md and fetch-manifest.json.
Chilli.lua is a router; StealAnEggg is Luraph-obfuscated source, not deobfuscated.
VxEze endpoint returned HTTP 403 (error code 1010); no payload obtained.
SourceInventory.lua is metadata only, not a synthesized feature implementation.
Third-party source snapshots are local ignored TXT files; never execute or bundle.
No verified remote names/arguments or extracted gameplay logic yet.

## Audit closure — 2026-10-21
User instructed SAFE EXIT: stop automatic fetch and deobfuscation of both sources.
Audit CLOSED; analysis PAUSED pending explicit reopening and authorized input.
Do not bypass protection or execute unreviewed payloads. No fetch schedule was created.
See TECHNICAL_AUDIT_SUMMARY.md and HANDOVER.md in the audit directory.
Handover ZIP includes documentation/metadata only, with checksums; ignored raw
third-party snapshots remain local and are excluded from redistribution.

## Static extraction reopened — 2026-10-21
User explicitly reopened work to request tools/parser.py for the local Luraph snapshot.
Previous audit archive remains closed/historical. No network fetch or Lua execution.
Parser is SHA-256-pinned: Y substitution + custom base85 (last digits swapped),
LE uint32 + raw LZMA1 lc3/lp0/pb0. Verified outputs: g=1261603 bytes next-stage
obfuscated Lua; d=373666 bytes binary VM input, NOT verified opcode-array size.
See tools/README.md and research/static-unpack-2026-10-21/parser-report.json.
5 tests pass, including malformed input and snapshot hashes. Python 3.13 present;
Luau CLI absent and not needed for static parsing. input/ and output/ are ignored;
never execute extracted source. Source 2 and dynamic tracing remain inactive.

## Phase 2 static survey — 2026-10-21
User requested tools/analyzer.py; implemented without Lua execution or fetching.
9224 g literal occurrences, 7 indexed dispatch-loop candidates, 569 binary
printable runs; d entropy 7.999308 bits/byte. CW/MW loader and v reader handoff
identified; binary constant/prototype/opcode schema still UNRESOLVED.
See research/static-analysis-2026-10-21/FINDINGS.md and analysis-report.json.
Run python -m unittest discover -s tools -p "test_*.py" -v (11 tests passed).
Generated string dumps stay in ignored output/phase2. Graph is lexical candidate
calls, not verified CFG. Never claim arbitrary printable runs are constants.

## Phase 3 discovery / tracer blueprint — 2026-10-21
User requested discovery and safe tracing framework. decryption_finder.py pins g
hash, records reader aliases/anchors, translates TW mask recurrence with 61/123
mod256; OW[0]=0xe49dca7b,VW[0]=228. This is NOT a global XOR key for d.
CW init state33 -> xW -> aW counter -> TW fills OW/VW. zW XOR sites identified.
sW immediately calls the closure returned by v; full-source tracing remains gated.
Added sandbox_tracer.luau (allowlist, bounded raw JSON snapshots, pre-dispatch stop),
inactive decoder_adapter_template.luau, synthetic demo, run_tracer.py (prepare-only
by default; optional local pinned Docker --network none, limits, no downloads).
See tools/PHASE3.md and research/reader-discovery-2026-10-21/decryption-findings.json.
19 Python tests passed. Lua5.1 syntax check only for Lua/Luau common syntax;
no Luau/Docker installed, no decoder or payload runtime test and no actual
constant-table snapshot. Source2 fetching remains inactive. Air gap cannot be
claimed from environment hooks; runtime needs OS isolation / disconnected VM.

## Phase 4 LCG mock / separation — 2026-10-21
Added lcg_decoder.py: reuse OW/VW, inverse61=21 mod256, XOR windows with optional
extra word mask. Default tests256 seeds in each of3 windows4096 bytes, mask0.
Lowest entropy seed9: offsets0 7.513396->7.937451 (worse),4096 7.951787->7.459914,
8192 7.958400->7.320235. Seed137 ties because keystream differs by XOR0x80;
entropy cannot identify a unique key. No candidate accepted / no constants parsed.
Added state_separator.py:11 pinned view-only reader excerpts, scalar aliases
trimmed; sW view stops BEFORE v (neither parser nor closure invoked). Not a safe
standalone decoder or validated CFG. Raw excerpts/candidate bytes stay ignored.
See research/lcg-experiments-2026-10-21/FINDINGS.md. 27 tests passed; no Lua or
payload runtime, no network. Next: source-derived cursor/seed/extra-mask schedule,
then bounded record parsing; never infer a second encryption layer from entropy.

## Phase 5 targeted record — 2026-10-21
reader_tracer.py translates the reviewed CW custom uint (permuted digit weights,
not ULEB128) and rW/zW mask branch. Encoded count95495-bias94747=748; flag0;
selected ID664; slice2242..154419 (length152177); selected lookup41168; skip1byte,
length fe8324 ->53886, ciphertext begins absolute43414. Other lookup values may
be encoded references; not all are plain offsets. Later d bytes unexamined.
sW passes91 to v; on this branch rW j=e664,S=P91 -> seed243; auxiliary word
91*0x01010101=0x5b5b5b5b. OW/VW updates state; zW extra mask fixed per record.
Transformed64 selected-record bytes, prefix SHA256 fa6871bc0acd37b71207626e55d7e880a87c7b981a3dcf14cbd8170dde5eb243.
No native magic or validated constant/prototype tags yet. Original d first64 are
loader data, not blindly XORed. No Lua/opcodes executed; no network. 33 tests passed.
See research/targeted-reader-2026-10-21/FINDINGS.md. Next source-map GW on decoded
buffer and separately inspect lazy readers; never generalize aux91 to every record.
