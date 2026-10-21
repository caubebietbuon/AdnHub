# Phase 10: descriptor bodies, guarded function links and static synthesis

## Reproduce and scope

```powershell
python tools/prototype_mapper.py
python -m unittest discover -s tools -p "test_*.py" -v
```

The tool rebuilds Phases8/9 from pinned g/d in a temporary local staging folder;
old output JSON is not trusted input. The unified artifact is
output/phase10/static-synthesis.json. No Lua, __index, factory4890, opcode
dispatch, network API or original-input mutation runs. Inspecting factory text
does not invoke it. No OS-enforced air gap is claimed. No push is performed.

## Complete descriptor byte grammar

The state172 ->39 ->156 ->87 ->0 ->69 reader is translated to bounded Python:

1. Read the initial custom uint as entry count; cap allocation and require at
   least one remaining byte per entry.
2. Read each packed custom uint. `kind=word&3`; `target_index=word>>2`.
3. For kind2 only, read an extra custom uint and store `extra+1` as field1.
   All other kinds use the source's7030 sentinel in field1.
4. Emit `[field1,target_index,kind]`. Reject trailing bytes and truncated entries.

All32 decrypted tag219 bodies parse exactly to their end. They contain163 entries:

| Kind | Factory-text consumer | Count |
|---|---|---:|
| 0 | `t[SJ]`: register value | 2 |
| 1 | `g[SJ]`: enclosing capture | 19 |
| 2 | register span with field1 stored at cell key4 | 0 |
| 3 | shared cell `{[6]=t,[5]=SJ}` | 142 |

The first field is not automatically a prototype ID. Kind2's field1 is used as
a span length in the factory's capture-cell construction, not a demonstrated
child-record reference. The decoded descriptors still lack verified owners.

The closure consumer visible near g offset17714 uses descriptor wrapper Z and
function wrapper B at a common slot, then calls B with the assembled captures.
This is source evidence for how capture data is consumed. It is not evidence
that any particular opcode slot is reached or remains unchanged: the factory
contains code that rewrites arrays and backing data. The tool never runs it or
labels every syntactic opcode occurrence as a verified closure creation.

## Opaque directory entries: conditional resolution

The factory text explicitly XORs directory values with306486104 before reading
record length. It separately XORs the payload with a replicated byte mask whose
value is computed from runtime state. Both source fragments are pinned in the
generated evidence list.

For the81 previously out-of-backing directory values referenced in root streams,
the separate analysis expression `value ^ 306486104` yields81 in-bounds offsets:

- 34 have tag1, selecting the recursive-v/function-reference branch; their clear
  length fields pass bounds checks. Each gets a conditional root-to-function
  reference edge, payload hash/length, and wrapper/index provenance.
- 47 have tag174, selecting the encoded-string branch. They remain conditional
  string targets because the additional payload mask is unresolved.

The original directory and input files are not changed. The tool does not apply
the payload mask, guess it from a presumed zero header, run an opcode to obtain
it, construct a function, or treat these targets as already materialized values.

Every new edge carries a guard: the source directory-unmask operation must be
applied for that ID before the target is usable. Root stream references alone
do not establish execution, lexical ownership or an opcode/capture association.
`verified_parent_child_edges` is empty and `verified_hierarchy` remains null.
The34 edges therefore form a **conditional reference graph**, not a verified
lexical prototype hierarchy. This is a concrete refinement of Phase9's opaque
references, not a claim of complete deobfuscation.

## Unified recovered evidence

static-synthesis.json includes:

- pinned input hashes and root record664 metadata: factory4890, register capacity
  181, entry PC9942, transformed record SHA256;
- 281 primitive candidates and172 strings, with exact byte representations and
  wrapper/index uses (453 scalar candidates total, runtime use still unproven);
- 32 parsed descriptor bodies and163 captures, with reader coverage;
- 34 conditional function edges and47 conditional string targets;
- original Phase9 unresolved entries, source evidence and unvalidated ID1/2
  comparison outcomes;
- cache boundaries and explicit zero execution/network counters.

These custom data types are not a serialized native Luau constant pool. Root
leading descriptor count0 remains separate from the32 referenced descriptor
tables; neither is relabeled as a verified child count.

## Validation and remaining work

Tests cover all four descriptor kinds, the optional span, multi-byte fields,
empty tables, truncation/count limits/trailing data, directory-XOR guards,
function length bounds, conditional string separation and the pinned synthesis.
No payload/runtime validation is performed.

All68 Python tests passed (61 existing plus7 new). Lua syntax checks for
AdnHub.lua/Loader.lua and `git diff --check` passed. Changes remain local.

To verify lexical child relationships, the missing evidence is source-derived
payload-mask values and valid child headers, followed by capture-owner/call-site
binding with reachability addressed. The synthesis intentionally keeps these
requirements explicit instead of manufacturing a complete tree.
