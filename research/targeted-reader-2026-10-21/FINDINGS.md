# Phase 5 — Targeted reader and auxiliary-mask derivation

## Run

```powershell
python tools/reader_tracer.py
```

Inputs: existing local g/d artifacts with exact SHA-256 validation. No fetch,
Lua execution, eval/exec, generated closure or opcode dispatch. The tool runs a
reviewed Python translation of byte-read/arithmetic branches, not arbitrary Lua.
This is snapshot-specific; it is not a general Luraph decoder.

## 1. Reader source evidence
source_evidence uses analyzer's lexer and state_separator's checked extraction to
inspect named regions. Exact anchors pin the rW/zW argument mapping, arithmetic,
UW/DW threshold branches and sW call. Reported source offsets are zero-based in g.

The original zW is one state-step helper; v and KW drive repeated word/byte
operations. It does not contain an independent byte-read loop of its own.

| Original operation | Meaning on this reviewed path |
| --- | --- |
| rW: (j+S)%256 | Initial rolling state = (selected ID + auxiliary byte)%256 |
| rW: S*16843009 | Replicate auxiliary byte to all four bytes of a word |
| zW: bxor(OW[W],H,readu32(...)) | XOR ciphertext word, LCG mask, auxiliary word |
| zW: VW[W] | Advance four PRNG steps |
| zW tail: (o+W*b)%256 | Advance one PRNG step with b=61,o=123 |
| zW tail: bxor(i,readu8(...),h) | XOR auxiliary byte, ciphertext byte and next state |

16843009 = 0x01010101. In this selected record the auxiliary mask is constant;
the OW mask changes as the rolling state advances. Other records/call sites
may receive different arguments. There is no single decoded global mask for d.

zW uses the [20]=bit32.bxor alias. This region has no band or << / >> operations;
128,16384,2097152 occur in its integer-read branches, not as XOR keys.
The tool records numeric literals and source references without labeling every
literal (including function slots and branch labels) a cryptographic constant.

## 2. Resolve layout before applying XOR
CW reads a custom variable-length integer representation with permuted digit
significance. It is NOT generic ULEB128. For three-byte form:

```text
value=(byte0-128) + (byte1-128)*16384 + byte2*128
```

The checked four-byte branch also permutes digits, including the final high bit.
Earlier generic ULEB probes were only hypotheses; they must not be treated as
field values. custom_uint implements all four reviewed cases with bounds checks.

The normalized initial CW reader yields:

| Field | Value |
| --- | ---: |
| Encoded count | 95495 |
| Count after source-defined bias94747 | 748 |
| Flag byte | 0 |
| Selected lookup ID | 664 |
| Byte-slice start in d | 2242 |
| Slice length | 152177 |
| Slice end | 154419 |
| Selected lookup value | 41168 |

Other lookup entries are opaque and are NOT all asserted to be plain offsets.
Only the selected entry is followed and bounds-checked. The skipped byte at its
lookup position is recorded without assigning it a meaning. Later d sections
(219247 bytes after this slice) remain unexamined.

wW reads at slice[lookup_value+1]; the three length bytes are fe8324. UW/DW's
reviewed branch yields record length53886 and payload start41172 in the slice,
therefore absolute d offset43414. sW supplies literal91 as v's third argument;
v initially puts it into P, and that value is preserved on the selected branch.

At rW: j=e=selected ID664, S=P=91, o=record length53886. Thus:

```python
initial_state = (664 + 91) % 256  # 243
auxiliary_word = 91 * 0x01010101  # 0x5b5b5b5b
```

This replaces Phase4's zero auxiliary-mask and independently guessed seeds for
this specific record. It does not retroactively validate Phase4's candidates.

## 3. Word and tail translation

```text
word_plain = word_cipher XOR OW[state] XOR auxiliary_word
state = VW[state]
```

Words are little-endian. For remaining bytes:

```text
state = (61*state + 123)%256
byte_plain = byte_cipher XOR auxiliary_byte XOR state
```

The first word provides a concrete check:

```text
input word: 0x9c661339
OW[243]:    0xc73cd562
aux word:   0x5b5b5b5b
output:     0x00019d00  (little-endian bytes 00 9d 01 00)
```

decrypt_record reproduces this bounded rW/zW operation for supplied parameters,
including partial-word tails. It is a complete translation of THAT transform,
not a complete decoder/deserializer for every region of d.

## 4. First64-byte check
The tool preserves and inspects d's original first64 bytes. Those contain loader
integers/lookup values; no whole-file XOR is applied there. The meaningful XOR
check instead uses64 ciphertext bytes from the selected record at43414.

Local output:
- output/phase5/reader-trace.json: source offsets, loader fields, full lookup
  values, original/transformed64-byte hex and first16 word-mask steps.
- output/phase5/selected-record-prefix.bin: transformed64 bytes (untrusted data).

Transformed-prefix SHA-256:
fa6871bc0acd37b71207626e55d7e880a87c7b981a3dcf14cbd8170dde5eb243.
No standard Lua bytecode, gzip, xz or LZ4 magic was found. No universal Luau or
Luraph prototype magic/header is assumed. Prototype and constant tags remain
unparsed. Entropy of64 bytes changes5.769455->5.220714, but such a tiny sample is
not a validation test or evidence of an additional encryption layer.

The committed reader-summary.json excludes raw source excerpts, raw lookup
values and plaintext/ciphertext word values. Complete local output stays ignored.

## 5. Boundaries and next work
1. Map GW and its reader helpers on the transformed buffer. Identify field tags,
   lengths/counts and cursor advancement from source before interpreting bytes.
2. Verify those fields against synthetic fixtures and actual record bounds.
3. Trace separately any lazy __index reader or recursive v call; do not assume
   it has the same auxiliary byte or state schedule as this selected record.
4. Only after that classify constants, prototypes and virtual instructions.

The absence of a native bytecode signature does not justify trying arbitrary
second-layer ciphers. No opcode interpretation or application function was run.

## Verification
33 tests pass, including custom integer known vectors and truncation checks,
word-mask known vector, independent scalar byte reference for every tail size,
wrong-hash rejection and exact64-byte snapshot output hash. AdnHub/Loader still
pass luac syntax checks. This is static-reader arithmetic validation; not Luau
runtime validation or recovery of all original source/constants.
