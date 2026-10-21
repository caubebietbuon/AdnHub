-- Deliberately inactive. Replace only after reviewing a decoder-only slice.
-- Never paste the full stage1 VM source or call a generated VM closure here.
-- Available inputs: DATA (bytes), trace, safe math/string/table/bit32/buffer.
-- 1. Parse validated headers with explicit bounds on cursor and lengths.
-- 2. Apply only transforms established from decryption-findings.json.
-- 3. Build a plain raw table: do not force unknown __index lazy decoders.
-- 4. At a verified boundary BEFORE interpreter execution:
-- trace.before_dispatch(constants, {source_offset=..., cursor=..., role="candidate"})
error("DECODER_ADAPTER_NOT_REVIEWED: no verified constant-table checkpoint yet")
