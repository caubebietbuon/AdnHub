# Phase 9: strings and prototype-reference boundaries

## Run and safety

```powershell
python tools/string_resolver.py
python -m unittest discover -s tools -p "test_*.py" -v
```

This tool reads the pinned g/d snapshot, validates source anchors and rebuilds
Phase8's backing-copy state locally. It does not trust pre-existing JSON dumps.
No Lua, __index, factory4890, opcode, network API or original-input write runs.
There is no claim of OS-enforced air-gap isolation. Results stay in ignored
output/phase9/string-resolution.json; this phase remains local without a push.

## String algorithm and functions

`string_evidence` checks the exact branch98 cache probe, branch64 length reader,
branch56 auxiliary83 setup, word/tail XOR loops and branch66 cache store. It also
checks the descriptor-reader continuation discussed below. Source offsets are
included in the generated report, along with g/d SHA256 values.

`read_length_payload` reads the existing custom uint immediately after the tag,
preserving its permuted digit weights. It rejects truncation, lengths beyond the
backing slice and allocations above1MiB. The backing slice itself is152177 bytes.
This is not ULEB128 and not an assumed UTF-8 character length.

`resolve_string` handles:

- leaf98 (tags170..174): length-prefixed encrypted bytes. Seed is
  `(reference_id+83)%256`, replicated word mask0x53535353, then the reviewed
  OW/VW word reader and byte-tail recurrence. Source calls buffer.tostring on
  the result and stores it in the shared cache at the reference ID.
- leaf55 (tags238..255 except244): length-prefixed raw bytes, read without XOR.
  The current snapshot's sole candidate in this branch fails its length bounds.

Raw byte hex and SHA256 preserve every byte, including embedded NULs and invalid
UTF-8. A separate text field is decoded strictly as UTF-8; invalid text becomes
null rather than replacement characters. These Lua string values are data and
are never compiled, loaded or executed. Known dependencies overlapping the fill
are not promoted to string candidates.

## Results

Of Phase8's303 unresolved candidate references:

| Result | Count |
|---|---:|
| Resolved string candidates | 172 |
| Decoded descriptor headers, bodies unresolved | 32 |
| Remaining opaque/unsupported/rejected references | 99 |

All172 strings are valid UTF-8 in this snapshot. They total3836 bytes; the longest
is2311 bytes. Examples: ID2=`EnumType`, ID4=`Clone`, ID7=`Destroy`,
ID9=`NextInteger`, ID15=`traceback`. Wrapper/index uses are recorded for each
string ID. Repeated uses reference one analysis entry; the tool does not invent
runtime access order or populate a Lua cache. The actual initial -2 cache remains
empty; the analysis cache index contains candidate IDs only.

Together with Phase8, there are453 scalar candidates (281 number/boolean and172
strings), not a proven reachable native Luau constant pool. The32 descriptor
headers are a separate partial result and are not complete materializations.

## Correction: tag219 is not a confirmed string branch

The earlier `encoded_string_reader_unresolved` label for leaf95/tag219 was too
broad and is corrected to `encoded_descriptor_reader_unresolved` in lazy_tracer.
The tag first decodes a length-prefixed buffer with auxiliary83. The continuation
at state172 reads its first byte as a count marker, state164 enters state39,
and state39 selects the triplet-table reader at state156 for positive counts.
This differs from state66's buffer.tostring/cache-store string path.

`descriptor_preview` therefore decodes the buffer and its initial custom uint
only. The32 observed count markers range0..13. The bodies, capture semantics,
referenced function ownership and parenthood remain unverified. They are not
silently reclassified as string constants or child prototypes.

## Prototype mapping and limits

`function_reference_edges` examines each root stream slot against the directory.
Only leaf24/tags0..15 supports the observed recursive-v call with auxiliary91;
such edges are reported as **candidate function references**, not verified lexical
parent-child relations. It neither calls v nor constructs a factory. Duplicate
stream uses retain wrapper/index provenance.

For root664, no such candidate edge is present. Eighty-one distinct referenced
directory IDs have opaque out-of-backing values and are retained explicitly.
The verified hierarchy is null. This does not prove that the script has no child
functions, or that opaque values are prototypes. Assigning all directory entries
or descriptor buffers to root664 would fabricate relationships.

Next required evidence: decode the triplet bodies, resolve their consumers and
call-site bindings, and validate the opaque-directory representation. Only then
can lexical parenthood or a complete prototype tree be asserted without execution.

## Validation

New tests use an independent byte-at-a-time LCG fixture to check word/tail
decoding, two-byte lengths, empty strings, embedded NUL and invalid UTF-8. They
also cover raw strings, truncated/out-of-bounds lengths, descriptor/string
separation, conservative function edges, unknown hashes and the pinned snapshot.
No payload/runtime validation is performed.

All61 Python tests passed (53 existing plus8 new). Lua syntax checks for
AdnHub.lua/Loader.lua and `git diff --check` passed. No remote push was performed.
