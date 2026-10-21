-- Synthetic fixture only: no g/d payload and no real recovered constants.
local words, states = {}, {}
for seed = 0, 255 do
    local a = (123 + 61 * seed) % 256
    local b = (123 + 61 * a) % 256
    local c = (123 + 61 * b) % 256
    local d = (123 + 61 * c) % 256
    words[seed], states[seed] = a + b * 256 + c * 65536 + d * 16777216, d
end
trace.record("OW_seed0", words[0])
local environment = getfenv()
assert(environment == _G)
local example = {name = "synthetic-fixture", mask0 = words[0], next0 = states[0], note = DATA}
example.cycle = example
trace.before_dispatch(example, {synthetic = true, role = "fixture_not_recovered_constants"})
error("UNREACHABLE_AFTER_CHECKPOINT")
