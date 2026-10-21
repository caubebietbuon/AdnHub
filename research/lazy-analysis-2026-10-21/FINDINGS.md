# Phase 7: lazy metadata and post-GW footer

All analysis uses the same hash-pinned local g/d snapshot as Phase 6. No Lua,
metatable callback, application factory, opcode, buffer mutation or network
request runs. Python reads bytes and evaluates reviewed tag comparisons only.
This is an offline tool; an OS-enforced air gap was not configured or claimed.
Source offsets below are zero-based ASCII offsets in g, not line numbers.

## Reproduce

```powershell
python tools/lazy_tracer.py --sample-limit 748
python -m unittest discover -s tools -p "test_*.py" -v
```

Default sampling selects at most 64 distinct directory-in-bounds references, in
stream/index order. The command above raises the cap to cover all 503 distinct
candidate IDs found in these four streams. It does not scan every directory ID
or prove that any candidate is used at runtime. Full local results, including
primitive data observations, stay in ignored output/phase7/lazy-analysis.json.

## Wrapper edges and cache semantics

The t helper constructs four wrappers, attaches the same metatable without
evaluating it, and passes them to factory 4890. Following the effective formal
parameters (including duplicate-name shadowing) gives:

| Factory parameter | Backing stream at key -1 | Slots | Directory-in-bounds candidate slots |
|---|---|---:|---:|
| j | raw stream 1 / i | 9963 | 6316 |
| O | raw stream 2 / A | 9965 | 7049 |
| Z | raw stream 3 / H | 9962 | 7558 |
| B | raw stream 4 / w | 9962 | 8479 |

Key -2 in every wrapper points to one initially empty shared cache. Positive
wrapper keys are initially empty. The lazy body's state5 (g offset348372) reads
`G=u[-1][f]`, resolves directory offset `g[G]`, and reads the tag at that offset
in context[4]. It does not use the root plaintext stream as its backing slice.
State125 stores a materialized result at `u[f]` (offset358915), then returns it.
States55/98 probe `WJ[n]` with a Lua truthiness test; state72 stores a raw string
in that shared cache. The tool never mutates either cache or calls __index.

These are potential references, not an eager constant table. Raw arrays also
contain numeric instruction/operand data. Directory bounds and a matching tag
alone do not prove runtime reachability or that the interpretation is correct
for every possible slot.

## Tag decision map

The script validates all 18 comparison anchors against g, follows the predicates
for each possible tag, and emits a complete 256-tag map. Straight numeric readers
are separately translated to bounded Python byte readers. They use type-local
auxiliary masks, **not** the root function's auxiliary91:

| Tags | Reader / boundary | Auxiliary |
|---|---|---:|
| 0..15 | recursive v reference; construction blocked | 91 |
| 16 | Vector3 constructor blocked | â€” |
| 17..28 | float32 | 83 |
| 29..53 | Vector2 constructor blocked | â€” |
| 54..63 | triplet-table branch, not decoded | â€” |
| 64..96 except70 | table.create branch, not decoded | â€” |
| 70 | negative unsigned byte | 216 |
| 97..104 | signed16 | 187 |
| 105..166 | compound reader, unresolved | â€” |
| 167 | signed32 | 134 |
| 168..169 | fill-buffer branch, unresolved | â€” |
| 170..174 | shared cache / encoded buffer, unresolved | â€” |
| 175..195 | unsigned byte | 255 |
| 196..203 except197 | float64 | 62 |
| 197 | fill-buffer branch, unresolved | â€” |
| 204..218 | unsigned32 | 70 |
| 219 | encoded string branch, unresolved | â€” |
| 220..237 | unsigned16 | 78 |
| 238..255 except244 | shared cache / length-prefixed raw string | â€” |
| 244 | decoded byte !=206 gives boolean | 162 |

The 503 candidate IDs yielded 281 primitive observations, 172 encoded-buffer
boundaries, 32 encoded-string boundaries, 6 fill-buffer boundaries, 4 Vector3
boundaries, 2 compound, 2 table.create, 2 triplet, 1 Vector2, and 1 invalid raw
string length. The invalid length is explicitly rejected, not repaired or
reclassified. No sampled candidate enters the recursive-v tag branch; this is
**not** proof that the root has no child functions. No complete prototype graph
or verified reachable constant count is available.

The 281 primitive observations comprise 94 signed32, 84 unsigned32, 36 float64,
29 unsigned8, 21 float32, 11 negative unsigned8, 3 signed16, 2 boolean and 1
unsigned16. They are source-derived data interpretations, not runtime-validated
constants. Vector constructors remain blocked even when their float fields
could be read independently. Strings are emitted as bounded previews only and
are never compiled, loaded or executed.

## Leading descriptors and consumer boundary

The u32 leading word count at plaintext [3,7) is zero. Factory4890 receives its
empty descriptor table as argument12, but a later duplicate formal `B` shadows
that binding with wrapper B (argument14). Thus the leading table has no effective
formal binding in this particular factory. It must not be relabeled as a proven
upvalue count.

A separate, source-visible triplet producer exists in the lazy reader:
state156 allocates `3*n` slots and state69 writes fields at offsets1,2,3.
HW (offset188767) consumes triplets with `#S/3`, reads field3 as kind and field2
as B, and builds:

- kind3: `{[5]=B,[6]=h[B]}`;
- kind0: `h[B][B]`;
- kind1: `j[B]`.

This resembles capture resolution, but the direct data-flow edge from the root's
empty leading table to HW is not established. Neither HW nor the triplet reader
is invoked. A nonempty descriptor sample and a source-proven call-site binding
are prerequisites for a stronger upvalue/prototype interpretation.

## Five-byte tail resolved

The exact footer at plaintext [53881,53886) is `05 ed 83 24 dd`. Source zW32
(offset112420) reads after GW returns, so Phase6's GW boundary alone was not the
end of the outer reader. The observed path is:

`zW32 -> oW25 -> zW34 -> QW2 -> oW26 -> iW11 -> DW19 -> KW13`

- custom uint offset: 5;
- custom uint length: `(237-128)+(131-128)*16384+36*128 = 53869`;
- fill byte: 221 (`0xdd`);
- final cursor: 53886; no trailing bytes remain.

DW19 (offset129035; fill call offset129189) invokes the source operation
`x[78](b,o+w,S,j)`, where x[78] is buffer.fill. Its destination is the backing
ciphertext slice: start41172+5=41177, exclusive end95046. In absolute d offsets
this is [43419,97288). The bounds fit both that slice and the selected record.
The tool only reports this interval; **it does not apply the overwrite**.

The footer is therefore a source-buffer fill directive on this path, not
unexplained padding or a checksum. Its motivation (for example cleanup) remains
unproven; the byte operation alone does not establish intent.

## Next static work

Translate the encoded-buffer and encoded-string length/mask paths into bounded
data readers; keep all constructors and recursion explicit boundaries. Resolve
nonempty triplet samples and actual HW call arguments before asserting capture
semantics. Preserve input hashes, per-reader bounds and non-execution checks.

Validation: all 47 Python tests passed, including six new checks for tag-boundary
coverage, independent byte/word mask vectors, string bounds, recursion stops and
the footer. `luac -p AdnHub.lua Loader.lua` and `git diff --check` passed. No
Roblox, Luau payload or application runtime validation was performed.
