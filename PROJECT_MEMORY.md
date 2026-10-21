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
