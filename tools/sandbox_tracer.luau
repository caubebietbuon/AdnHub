-- Trusted harness. Compile a reviewed decoder adapter, NEVER the complete g.
-- JSON is emitted on stdout; file I/O and OS isolation belong to the host.
-- Environment hooks are defense in depth, not an air gap or a VM escape proof.
local hostCompile, hostSetfenv = loadstring, setfenv
local hostPrint, hostError, hostPcall = print, error, pcall
local hostType, hostNext = type, next
local hostBuffer, hostTable, hostString = buffer, table, string

return function(adapterSource, dataString)
    if hostType(hostTable.freeze) ~= "function" then
        hostError("Luau table.freeze required; Lua 5.1 is not a supported runtime")
    end
    if #adapterSource > 65536 or #dataString > 1048576 then
        hostError("Adapter/data size limit exceeded")
    end
    local MAX_EVENTS, MAX_DEPTH, MAX_ENTRIES = 256, 6, 64
    local MAX_STRING, MAX_BUFFER = 512, 64
    local count, checkpointReached = 0, false
    local env

    local function quote(text)
        -- Byte-preserving JSON: binary/non-ASCII bytes become \u00XX.
        return '"' .. hostString.gsub(text, '[%z\1-\31\127-\255\\"]', function(c)
            return hostString.format("\\u%04x", hostString.byte(c))
        end) .. '"'
    end

    local function encode(value, seen, depth, budget)
        budget.left = budget.left - 1
        if budget.left < 0 or depth > MAX_DEPTH then return '{"truncated":true}' end
        local kind = hostType(value)
        if kind == "nil" then return "null" end
        if kind == "boolean" then return value and "true" or "false" end
        if kind == "number" then
            if value ~= value or value == math.huge or value == -math.huge then
                return '{"type":"nonfinite_number"}'
            end
            return hostString.format("%.17g", value)
        end
        if kind == "string" then
            return '{"type":"bytes","length":' .. #value .. ',"preview":'
                .. quote(hostString.sub(value, 1, MAX_STRING))
                .. ',"truncated":' .. (#value > MAX_STRING and "true" or "false") .. '}'
        end
        if kind == "buffer" then
            local length = hostBuffer.len(value)
            local bytes = {}
            for index = 0, math.min(length, MAX_BUFFER) - 1 do
                bytes[#bytes + 1] = hostString.format("%02x", hostBuffer.readu8(value, index))
            end
            return '{"type":"buffer","length":' .. length .. ',"hex_preview":'
                .. quote(hostTable.concat(bytes)) .. ',"truncated":'
                .. (length > MAX_BUFFER and "true" or "false") .. '}'
        end
        if kind ~= "table" then return '{"type":' .. quote(kind) .. '}' end
        if seen[value] then return '{"reference":' .. seen[value] .. '}' end
        seen.count = seen.count + 1
        local id = seen.count
        seen[value] = id
        local entries, key, visited = {}, nil, 0
        while visited < MAX_ENTRIES do
            local item
            key, item = hostNext(value, key) -- raw iteration: no __index/__pairs.
            if key == nil then break end
            visited = visited + 1
            entries[#entries + 1] = '{"key":' .. encode(key, seen, depth + 1, budget)
                .. ',"value":' .. encode(item, seen, depth + 1, budget) .. '}'
            if budget.left < 0 then break end
        end
        local truncated = key ~= nil and hostNext(value, key) ~= nil
        return '{"type":"table","id":' .. id .. ',"entries":['
            .. hostTable.concat(entries, ",") .. '],"truncated":'
            .. (truncated and "true" or "false") .. '}'
    end

    local function emit(event, value)
        count = count + 1
        if count > MAX_EVENTS then hostError("Trace event limit exceeded", 0) end
        local snapshot = encode(value, {count = 0}, 0, {left = 1024})
        hostPrint('{"event":' .. quote(event) .. ',"sequence":' .. count
            .. ',"data":' .. snapshot .. '}')
    end

    local function pack(...)
        return {n = select("#", ...), ...}
    end

    local function traceCall(name, fn, ...)
        emit("call", {name = name, arguments = pack(...)})
        local results = pack(hostPcall(fn, ...))
        if not results[1] then
            emit("call_error", {name = name, error = results[2]})
            hostError("Wrapped decoder operation failed", 0)
        end
        emit("return", {name = name, values = results})
        return unpack(results, 2, results.n)
    end

    local trace = {}
    trace.record = function(label, value) emit("record", {label = label, value = value}) end
    trace.call = traceCall
    trace.before_dispatch = function(candidate, metadata)
        checkpointReached = true
        emit("pre_dispatch_snapshot", {candidate = candidate, metadata = metadata,
            status = "adapter_claimed_checkpoint_not_automatically_verified"})
        -- pcall/xpcall/coroutine are not exposed to the adapter.
        hostError("STOP_BEFORE_DISPATCH", 0)
    end
    hostTable.freeze(trace)

    local function libraryCopy(library, names)
        local copy = {}
        for _, name in ipairs(names) do copy[name] = library[name] end
        return hostTable.freeze(copy)
    end
    env = {
        assert = assert, error = error, type = type, typeof = typeof,
        tonumber = tonumber, select = select, next = next, pairs = pairs,
        ipairs = ipairs, unpack = unpack, rawget = rawget, rawset = rawset,
        rawequal = rawequal, setmetatable = setmetatable,
        math = libraryCopy(math, {"abs", "floor", "ceil", "min", "max", "huge", "fmod", "ldexp", "frexp"}),
        string = libraryCopy(string, {"byte", "char", "sub", "len", "rep", "format", "pack", "unpack"}),
        table = libraryCopy(table, {"create", "insert", "concat", "pack", "unpack", "move", "clear"}),
        bit32 = libraryCopy(bit32, {"band", "bor", "bxor", "bnot", "rshift", "lshift", "lrotate", "rrotate", "extract", "replace"}),
    }
    local bufferCopy = {}
    for _, name in ipairs({"len", "readu8", "readu16", "readu32", "readi8", "readi16", "readi32", "readf32", "readf64", "readstring", "writeu8", "writeu16", "writeu32", "writei8", "writei16", "writei32", "writef32", "writef64", "writestring", "copy", "fill", "tostring"}) do
        local operation, label = hostBuffer[name], "buffer." .. name
        if operation then bufferCopy[name] = function(...) return traceCall(label, operation, ...) end end
    end
    bufferCopy.create = function(size)
        if hostType(size) ~= "number" or size < 0 or size > 1048576 then hostError("Buffer size denied") end
        return traceCall("buffer.create", hostBuffer.create, size)
    end
    bufferCopy.fromstring = function(value)
        if hostType(value) ~= "string" or #value > 1048576 then hostError("Buffer string denied") end
        return traceCall("buffer.fromstring", hostBuffer.fromstring, value)
    end
    env.buffer = hostTable.freeze(bufferCopy)
    local function blockedCompile(source, name)
        emit("blocked_dynamic_compile", {source = source, name = name})
        hostError("Dynamic compilation denied", 0)
    end
    env.load, env.loadstring = blockedCompile, blockedCompile
    env.getfenv = function(...)
        emit("getfenv", pack(...))
        return env -- never return a caller/host stack environment.
    end
    env.setfenv = function(...)
        emit("blocked_setfenv", pack(...))
        hostError("Changing function environments denied", 0)
    end
    env.print = function(...) emit("adapter_print", pack(...)) end
    env.trace, env.DATA = trace, dataString
    env._G, env._ENV = env, env -- _ENV is ordinary data in Luau, not Lua 5.2 scoping.
    hostTable.freeze(env)

    emit("harness_start", {mode = "reviewed_adapter_only", max_events = MAX_EVENTS,
        string_preview_limit = MAX_STRING, buffer_preview_limit = MAX_BUFFER,
        table_entries_limit = MAX_ENTRIES, network_enforcement = "host_required"})
    local chunk, compileError = hostCompile(adapterSource, "reviewed-decoder-adapter")
    if not chunk then emit("compile_error", compileError); return end
    hostSetfenv(chunk, env)
    local ok, result = hostPcall(chunk)
    emit("harness_end", {ok = ok, result = result, checkpoint_reached = checkpointReached,
        interpretation = checkpointReached and "stopped_at_adapter_checkpoint" or "no_constant_table_checkpoint"})
end
