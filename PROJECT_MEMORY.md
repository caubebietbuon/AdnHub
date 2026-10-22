# AdnHub — project memory

## Purpose and current state
Current user priority: deep Chilli static decryption only; demo/ESP feature work
temporarily paused. Do not resume those feature changes without user direction.
Current scope is layer-by-layer static decomposition; 1:1 reproduction is out
of scope per latest user direction. Keep decoder algebra separate from guards.
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

## Phase 6 GW alignment — 2026-10-21
Added gw_aligner.py + gw_reader_model.py: hash-pinned, bounded reader-only IR
(44 helpers), readu8/readu32/table.create; metatables opaque metadata, unknown
factory/lazy calls stop. No Lua/application/opcode executed; no network requests.
v context[6] is an opaque lazy __index metatable before GW, not nil or runnable.
Record664: customformat0,variant157,leadingdescriptorcount0 (NOT proven upvalues),
factory4890,u32parameterwords2. Raw streams i9963,A9965,H9962,w9962; factory A is
opcode-slot array. Register capacity181,entryPC9942. Independent normalized
reader matches all counts/ranges/cursor. Coverage53881/53886;5 tail bytes unknown.
Lazy wrappers carry[-1]/[-2] metadata and cache: capacities are not constant counts.
Child-prototype/upvalue semantics unresolved. Aux91 observed at root/recursive v
calls; seed=(ID+91)%256, not globally243. Comparison ID1 fails assumed-length
bounds,ID2 returns after1/8 bytes withformat85: neither accepted as prototype.
See research/gw-alignment-2026-10-21/FINDINGS.md.41 tests passed (33+8).
Raw arrays/transformed records stay ignored in output/phase6. GW is a reader
method name, not proof of a separate global-data buffer. Next: lazy tag readers,
leading descriptors and5 unread bytes; keep factory/opcode execution blocked.

## Phase 7 lazy metadata — 2026-10-21
Added lazy_tracer.py: hash-pinned Python-only tag comparison tree (all256 tags),
four wrapper -1 streams / -2 shared cache, bounded primitive/raw-string readers.
No Lua/__index/factory/opcode/vector constructor/buffer writes/network invoked.
Cap748 covers503 distinct potential references acrossroot664 streams:281 numeric/
boolean observations, others unresolved or constructor boundaries;1 invalid raw
string length rejected. Not proven reachable constants; no recursive-v candidates
sampled does NOT mean no child functions. Leading descriptorcount0 @3..7; its
factory4890 arg12 shadowed by later formalB. HW has capture-like tripletconsumer,
but direct leadinglist->HW edge unproven; verified upvaluecount remains unknown.
Resolved footer53881..53886=05ed8324dd: offset5,length53869,fillbyte0xdd. Source
zW32->oW25->zW34->QW2->oW26->iW11->DW19->KW13 consumesall53886 bytes; DW19
would buffer.fill backingcipher slice[41177,95046), absolute d[43419,97288).
Tool only reports; never applies overwrite. Not padding/checksum; purpose unknown.
See research/lazy-analysis-2026-10-21/FINDINGS.md; localdump output/phase7 ignored.
Verification:47 Python tests passed (41 previous+6 new); luac syntax checks for
AdnHub.lua/Loader.lua and git diff --check passed. No Roblox/payload runtime test.
Next: encodedbuffer/string readers and nonempty descriptor->consumer edges,
without factories or dynamic metamethod evaluation.

## Phase 8 backing-copy reconstruction — 2026-10-22
Added reconstructor.py. Critical scope: footer fills backing ciphertext copy,
NOT transformed plaintext. Copy[41177,95046)=0xdd;53668 actual byte changes;
plaintext53886 bytes unchanged. No payload/factory/__index/opcodes/network API.
584 directory-index-bounded IDs in root streams;503 have backing-bounded offsets,
81 opaque out-of-slice values. All281 primitive candidates unchanged (279numbers,
2booleans), mapped to wrapper/index uses;303 unresolved. No valid string candidate
or verified child hierarchy; fully_materialized=false. Initial shared -2 cache
empty, survey observations are not runtime cache; individual wrapper use maps
are candidate analysis metadata only. ID1 length1477608 rejected; ID2 format85
8byte aux91 assumption remains unvalidated, not reconstructed/filled.
Output/phase8: plaintext, postfill backing, streams, mapping, manifest (ignored).
See research/reconstruction-2026-10-22/FINDINGS.md. Need compound decoder and
consumer-edge proof before claiming complete source/native constants/prototypes.
Verification:53 Python tests passed (47previous+6new), luac syntax checks for
AdnHub.lua/Loader.lua and git diff --check passed. No payload/runtime validation.
Phase8 stays local (no push) to honor current explicit no-network constraint.

## Phase 9 strings / reference mapping — 2026-10-22
Added string_resolver.py: source-pinned length-prefixed leaf98 (tags170..174)
aux83 decrypt->buffer.tostring->sharedcache, leaf55 rawstring bounded reader.
No Lua/__index/factory/opcode/network/input writes. Rebuilds backing postfill
from pinned inputs instead of trusting old JSON.303 unresolved->172strings,
32partial descriptorheaders,99still opaque/unsupported/rejected. Strings3836bytes,
allUTF8, max2311; hex+SHA preserve arbitrary bytes, invalidUTF8 yieldsnulltext.
ID2 EnumType,4 Clone,7 Destroy. Wrapper uses and candidate cachekeys recorded;
runtime cache/accessorder not fabricated. Phase7 leaf95/tag219 priorlabel
encoded_string_reader_unresolved corrected: decodedbuffer enters count/triplet
reader, not buffer.tostring. Headercounts0..13, bodies/meaning unresolved.
No root664 direct recursive-v candidateedges;81opaque directoryIDs retained.
verifiedhierarchy=null, NOT proof nochildfunctions. Needtripletbody/consumer and
opaque-directory representation evidence before lexical parenthood claims.
See research/string-resolution-2026-10-22/FINDINGS.md; output/phase9 ignored.
Verification:61 Python tests passed (53previous+8new); luac syntax checks for
AdnHub.lua/Loader.lua and git diff --check passed. No payload/runtime test.
Phase9 committed locally, no push/network per current constraint.

## Phase 10 descriptor bodies / guarded graph — 2026-10-22
prototype_mapper.py rebuilds pinned Phase8/9 offline; emits unified metadata
output/phase10/static-synthesis.json.32 tag219 bodies parse exactly:163capture
triplets, kinds3=142/1=19/0=2/2=0. Packeduint low2bits=kind, >>2=targetindex;
kind2 extra+1 field1span, others7030sentinel. Not prototypeIDs; owners unverified.
Factory source explicitly XORs directoryvalues306486104 then separately XORs
payload with runtime-derived byte mask. Analysis-only XOR of81opaque entries
produces81bounded offsets:34tag1 functiontargets +47tag174 stringtargets.
Guarded root->function referenceedges include streamindices, clear length bounds
and payloadhash. NO actual directory mutation/payloadunmask/opcodeexecution.
Not proven lexical children/reachable: verifiedhierarchy=null, edgesconditional.
Unified281primitives+172strings, wrappers,captures,register181,entry9942,hashes,
comparisonfailures,cache boundaries. No Lua/factory/__index/network/inputwrites.
See research/prototype-synthesis-2026-10-22/FINDINGS.md. Need source mask/state
and capture-owner/reachability proof before verified prototype tree claims.
Verification:68 Python tests passed (61previous+7new), luac syntax checks for
AdnHub.lua/Loader.lua and git diff --check passed. No payload/runtime validation.
Local commit only; no push/network per current constraint.

## Phase 11 payload masks / initialization abstraction — 2026-10-22
Added payload_decoder.py + prologue_analyzer.py. mix(n)=(n^((n>>29)&7))&0x1fffffff;
variant157 patch11 uses H^mix(y),patch76 H^mix(V),patch14 direct H. InitialV
4179906283,y1947447901. Restricted numeric init model variants157/163/228 copies
arrays; bounded jumps, PRNG shifts13/13/14, packedinstruction normalization,
one-based rewrite starts operand+1. No application/Lua/factory/__index/network.
236abstractsteps,38conditional patch equations; unknown lazy operands assumed
normal continuation (not runtime/type proof). Stops PC9063 variant228/op111,
task-global environment read (source dispatcher context checked). Only decorative
x.V key assignment abstracted, no actual VM-table writes. Added7refs from decodedinit:4functions+3strings.
38functioncandidates:31format0/7format2;17source-mask equations underguards,
21header-constrained mask hypotheses. Validate arrays,PC,factoryexists,fullfooter;
nativeGW model stops BEFORE factory. Not proven full semantic decompilation.
21new source-equation string candidates =193combined;29maskedstrings unresolved.
PrintableUTF8 hints never key proof. Hierarchy stillnull; descriptorowner unknown.
CRITICAL correction: directoryID1 tag218 isuint32 2503038408; ID2 tag174 is
EnumType string. Old format85/length failure were wrong-type function probe
artifacts, not new function schema. See research/payload-masks-2026-10-22/FINDINGS.md
and ignored output/phase11/payload-analysis.json. No demo/ESP changes or push.
Verification:76 Python tests passed (68previous+8new); phase11 tests rerun after
task-global boundary refinement. luac syntax checks and git diff --check passed.
No Roblox/payload runtime validation; fulldecompilation remains incomplete.

## Phase 12 symbolic context / proof-gated ownership — 2026-10-22
Added symbolic_resolver.py; optional prologue_analyzer symbolicenv names unknown
globals (task at9063), not dummydefaults. Passes9063, stops9251 unresolved fused
call. Snapshots9062/9063/9251 preserve unknownregisters. No callbacks or APIcalls.
Selected branches preserve constraints;31VM records emit37path/frontier summaries,
2records hit4pathcap;7native factory declarations remain unexecuted metadata.
All29 unresolvedstrings searched256masks=7424; entropy unchanged bysinglebyteXOR,
printabilitynotproof.10IDs have guarded entrytrace equations (13,62,190,230,294,
375,605,613,661,674), ID119 onlyinitialstate hypothesis,18noequations. ID13 initial
guesskey13garbled vsupdatedtracekey76 Unit: neverpromote initialstate heuristics.
Capture-owner candidates664->506/desc251,137->747/58,237->572/181,704->288/299.
Guards required:correctdispatcher,unmodifiedsource slot,path/parentheader/masks.
506format0factory4890,572format2factory4916 newstructuralheader hypotheses;
40functiontargets totalcandidateinventory, notverifiedfunctions. Registerbounds
alone notownership; enclosingcapturebounds unverified. Treevalidator requires
source,descriptor,capture,childheader,path,unconditionalancestry pluscoverage,
uniqueparents andnocycle. Currentdata fails; verified_hierarchy=null retained.
No Lua/__index/factory/applicationcall/network/inputwrites. Demo/ESP untouched.
See research/symbolic-resolution-2026-10-22/FINDINGS.md; output/phase12 ignored.
Verification:83 Python tests passed (76previous+7new); luac checks on AdnHub.lua/
Loader.lua and git diff --check passed. No payload/runtime validation or push.

## Phase 13 dispatcher correction / guarded closure transfers — 2026-10-22
Added tools/fused_call_analyzer.py, tools/test_phase13.py; extended optional
prologue_analyzer mode with register-write provenance, symbolic field reads,
fresh-table heap copies, exact integer additions, state reads and proof-gated
closure construction. Historical default Phase11/12 behavior stays reproducible.
IMPORTANT: Phase12's PC9251 "fused call" label was WRONG. Pinned variant228
subtree at g offset49745 proves opcode95=field lookup, opcode93=fused call.
9063 r72=global.task;9251 r57=task.cancel;9252 patches736/key75;
9253 r14=task.spawn. These are symbolic expressions, no task calls.
Actual93 copies a register before callee lookup, reads next-cell T/d/I,
packs return values incl nil, moves I results; PC+2 only on normal return.
Rejecting the old9251 decode follows predicates, not register181 hardbounds:
table.create capacity is an allocation hint, NOT a Lua index limit.
Root trace360steps45patches, now stops8395 variant228/op131. y evolves from
1947447901 to2639318406. Path-local directory applies only already-observed
patches; no future key injection. Extra patches vsPhase11:736/75,606/194,
349/208,303/12,258/246,672/121,455/92. No claims of unconditional runtime path.
Observed guarded closure transfers664->567/258/379/663 at8390/8391/8393/8394,
descriptors486/486/462/722; first two share capture cells107,106. Source4890
construction prefixes are alias-only; plain decoder context remains a guard.
Bodies/factories never invoked. Header/fill validation uses private byte copies.
Original candidates664->506,137->747,237->572,704->288 remain unverified:
audited frontiers8395/29/238/3 precede their candidate sites9554/33/257/10.
237 has unknown enclosing capture bounds8..10;704 has1..9;137 descriptor empty.
Six criteria retained; no source-family/overlap shortcut to ancestry. Parent
activation/context and shared lazy caches still need proof. verified_hierarchy=null.
Exact uint32 mixer inverse: n=(h<<29)|(m XOR h),h=0..7; eight preimages.
Byte key equation gives at most2048 states, not a unique key. Scan records15
guarded potential patch sites for9of18 remaining strings; no newly reached
equation for any18, all unconditional byte domains remain256. No strings added.
See research/fused-call-audit-2026-10-22/FINDINGS.md and summary.json;
detailed regenerated output/phase13/fused-call-analysis.json is ignored.
Reproduce:python tools/fused_call_analyzer.py;python -m unittest discover -s tools;
luac -p AdnHub.lua Loader.lua;git diff --check. Verification:92 Python tests
passed (83previous+9new), Lua syntax and diff checks passed. No Lua/payload/
factory/__index/API/network execution, no Roblox runtime checks, no Git push.
Demo/ESP work remains paused. Full decompilation and 1:1 script remain incomplete.

## Phase 14 exact-domain obligations / prototype root causes — 2026-10-22
Added tools/obligation_resolver.py and test_phase14.py. prologue_analyzer accepts
optional bounded source-transfer callbacks (nextPC/advance validated); default
historical modes remain unchanged. Phase13 ownership audit optionally accepts
a context-specific transfer factory. No Lua/source evaluation or runtime calls.
Source-pinned rules:228/op131 decoder-context alias,228/op114 constant read,
163/op78 exact numeric branch,163/op83 bounded integer addition. Unknown inputs
stop; no dummy values or asserted environment success. Root363steps45patches,
frontier8398 is actual228/op93 fusedcall: copy r5->r2;T2,d2,I1;args r3=global.debug,
r4=required-debug-library message. Source context109=assert; builtin identity
and debug truthiness remain contracts, never executed. Normal returnPC8400 only.
Exact mixer inverse intersects only same-PC/owner/dispatcher/operand state;
wrong visit/rewritten operand cannot constrain future visits. Root prefix patches
none of18 IDs. Refreshed scan15potentialsites across10IDs (supersedes stale9-ID
count in Phase13 handover), not exhaustive because initialization rewrites code.
Expanded bounded hypothetical entry analyses31VMrecords, no sibling mutation
sharing or invented args/captures. NEW guarded ID192 key5 atrecord711 PC938,
variant228/op100; decodes rawlen.711liveheader matches root mask113 at9952;
42steps to patch, no unknown branch assumptions. Activation/directory/cache
lifecycle not proved, so unconditional key remainsnull. Other17 IDs still lack
reached equations:74,141,160,196,203,267,269,432,457,476,485,512,545,580,616,632,702.
All18nonempty payloads yield256distinct local XOR plaintexts; length/UTF8/entropy
do not select keys. Local ambiguity is not proof of whole-program feasibility.
Six-rule audit original4links retained.664->506 not reached before8398;
137->747 projectedprefix at29 reads XOR(r0,r0) with r0unwritten: nil operands
refute normal continuation under fresh-table/bxornumeric/header contracts;
do NOT simplify XORselfto0 without type proof. Scope is conditional prefix,
not global proof137neverexecutes.237->572 exactbranch238:11<=8=false; nowfrontier
152unprovedr1+1,enclosingcaptures8..10unknown.704->288 frontier3 readsarg1[6],
caller type/value unknown; enclosingcaptures1..9unknown. Allocationfitnotowner.
Frame maps for664->567/258/379/663 retain explicitcaptureordinals,cellidentities
andfrontiervalues; capture1isnotchildregister1.379's capture->maskV/y chain not
proved. All original+newguardededges go through unchanged treevalidator with
fullnodeinventory; no partial/root-only workaround. verified_hierarchy=null.
See research/obligation-audit-2026-10-22/FINDINGS.md and summary.json; detailed
ignored output/phase14/obligation-resolution.json includes all31traces, mask
intersections, localambiguitycertificates, typedfrontierproofs androotcallframe.
Reproduce:python tools/obligation_resolver.py;python -m unittest discover -s tools;
luac -p AdnHub.lua Loader.lua;git diff --check.108 Python tests passed
(92previous+16new), Lua syntax and diff checks passed. No Roblox/payload/Luau
runtime checks, no network/push. Demo/ESP untouched; complete decompile unproved.

## Phase 15 backward slicing / scoped diagnostic matrix — 2026-10-22
Added tools/register_slicer.py (bounded trace-order SSA), layer_decomposer.py
(offline pinned orchestration/core equations/matrix/proxies), test_phase15.py.
prologue_analyzer records numeric constant_inputs and successful state_word_write
only when provenance tracking enabled. Copy-order correction also fixes default mode.
Sourceaudit FIX:163/op109 inherited forwardmodel reversed sources. Pinned
g offset25174 proves r[c],r[c+1]=old(r[a]),old(r[b]); forward and backward now
correct, regression uses distinct10/20 inputs. Pipeline rebuilt; counts unchanged.
Slices follow trace-index definitions, not sortedPC. Parallel copies readold
versions; opaquewrites kill prior constants; nil isnot0; captureaddresses are
notvalues. Only whitelisted numeric arithmetic propagatesconstants; forward
observations checked. Root y2639318406 via9nodes, r2samevia8, r107=0 vialiteral.
Successful statewrite annotation prevents slicing through failed typechecks.
For17IDs (exclude192),14potentialsites across9IDs:9directbyte-XOR equations,
5state-mixer equations,8IDs withnosite. Directresults retainallbytes inclinvalid
UTF8.203key110->81hex andkey140->63hex bothretained; no readability selection.
Core equations independent of activation predicates. V/y inputs traced where
siteactuallyobserved; noneof14sitesreachedcurrently. Frontier slicescontextonly,
never substituted into future/unvisitedsites. All17selectedkeysremainnull.
Matrixcovers8pairs(original4+guardedroot4),sixrequestedcolumns capturebounds,
upvaluemappings,childheaders,controlflow,coverage,cyclechecks. ExplicitPASS/FAIL/
UNKNOWN withscope/reason; UNKNOWN!=observedfalse. These columns differfromold
six-proofvalidator; bothretained,oldrulesunchanged. GuardedcontrolPASSdoesnot
promoteunconditionalancestry.137->747controlFAILunderPhase14nil-XORcontracts.
CoverageFAILglobal:6of41expectednodescandidate-reachable,35missing; nocycle
in8enumeratededgesonly. verified_hierarchy=null, no new ancestry promoted.
Typedproxy routes ownerto wrapper/cachelookup/template/constructoruse/body,
descriptorinputseparate. Cachemissroutecandidate, cachehitidentityunproved.
7pairsreusefactory4890;572nativeboundary4916. Source4890prefixesalias-only,
notexecuted. Sharedfactory/descriptor486isnotparentproof; distinctconstruction
identities maintained. Noadditionalmultihopprototypepathinenumerated8pairs;
unseenproxiesunknown. Do not infer edges by traversing common implementation.
See research/layer-decomposition-2026-10-22/FINDINGS.md,DIAGNOSTIC_MATRIX.md,
summary.json. Detailed ignored output/phase15/layer-decomposition.json rebuilt
by python tools/layer_decomposer.py. Verification:124Python tests(108+16),
luac -p AdnHub.lua Loader.lua,git diff --check passed. No Lua/payload/factory/
API/network execution or Roblox runtime checks; no push; demo/ESP unchanged.

## Phase 16 static equation table / proxy admission — 2026-10-22
Added tools/promotion_auditor.py and test_phase16.py on top of layer_decomposer/
register_slicer APIs. Regenerates Phase15, reconstructs pinned backing, parses
tracked Phase15 DIAGNOSTIC_MATRIX.md table and compares all8pairs/6statuses.
Prose never executed; malformed/duplicate/stale table rows rejected.
Nine exact XOR equations promoted to site-indexed static_string_table with
owner/PC/ID/variant keys; inverse XOR recheck and Phase15 byte equality required.
Keys:74@3238=112;141@4319=43(readf64);203@3921=110(hex81),203@718=140(c);
267@7083=242(lrotate);432@7103=2(fill);457@5095=169(rep);476@4809=80(writei32);
485@4810=146. Allowner664;203@3921variant157,others228. Raw bytes retained.
Activation/cache predicates remain attached. This promotes algebra into a static
site table, NOT the per-ID runtime inventory; conflicting203sites cannotmerge.
Five state certificates74(664:981,402:83),141(711:269,593:393),702(379:686)
retain2048-state localdomains and backward frontier slices. No reached same-site
definition; frontier-to-site equality unproved. Allfive runtimekeys blocked.
Eight formal proxy statements retain conditional premises; admission requires
all historical sixproofs pluscacheidentity, then unchanged treevalidator.
Noeligibleedge; accepted_parent_edges=[]; verified_hierarchy=null. Sharedfactory
notancestry; globalcoverage stillmissing. No NULL replacedspeculatively.
See research/promotion-proofs-2026-10-22/FINDINGS.md and summary.json; ignored
output/phase16/promotion-proofs.json and static-string-table.json generated by
python tools/promotion_auditor.py. Verification:133 tests(124+9), Lua syntax and
git diff --check passed; latest9tests rerun after uint32 state bound check.
No payload/Lua/factory/metatable/API/network execution or runtimechecks; no push.
Demo/ESP unchanged. Continue static decomposition with guards explicit.
