local exports = {
    name = "fuzz",
    version = "0.0.1",
    description = "Coverage-guided fuzzer for i286",
    license = "BSD-3-Clause",
    author = { name = "flib" },
}
local fuzz = exports

local regs = {
    all = { "IP", "AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "ES", "ESBASE", "ESLIMIT", "ESFLAGS", "CS", "CSBASE", "CSLIMIT", "CSFLAGS", "SS", "SSBASE", "SSLIMIT", "SSFLAGS", "DS", "DSBASE", "DSLIMIT", "DSFLAGS", "GENFLAGS", "GDTRBASE", "GDTRLIMIT", "IDTRBASE", "IDTRLIMIT", "LDTR", "LDTRBASE", "LDTRLIMIT", "LDTRFLAGS", "TR", "TRBASE", "TRLIMIT", "TRFLAGS", "MSW", "V", "HALT" },
    pc = { "IP" },
}
-- TODO: local spacemap = { } for ram devices
local reset_subscription, stop_subscription

function fuzz.startplugin()
    local cpu
    local mut_bps
    local mut_taps
    local sock

    local function pc()
        local cs = cpu.state["CS"].value
        local ip = cpu.state["IP"].value
        return (cs << 4) | ip
    end

    local function cb()
		if not cpu then
			return
		end

        if manager.machine.debugger.execution_state == "stop" then
            local pc = pc()
            if mut_bps[pc] then
                print(string.format("PC = %08x", pc))
            end
            return
        end
    end

    function exists(file)
        local ok, err, code = os.rename(file, file)
        if (not ok) and (code == 13) then
            -- Permission denied, but file exists.
            return true
        end
        return ok
    end

    local function maybe_save_coverage()
        -- On reset: `trace /tmp/f,,noloop`, on start_bp: `:>/tmp/f`
    end

    local function maybe_take_snapshot()
        local path = os.execute(string.format("mkdir -p '%s'", os.getenv("HOME").."/tmp/fuzz/baseline"))
        if not exists(path.."/") then
            take_snapshot("baseline")
        end
    end

    local function hexdump(data, n)
        for i = 0, n - 1 do
            io.write(string.format("%04x: ", i*0x10))
            for j = 1, 0x10 do
                io.write(string.format("%02x ", string.byte(data, i*0x10+j)))
            end
            io.write("\n")
        end
    end

    local function read(k)
		if not sock then
			return nil
		end

        n = k
		local data = ""
		repeat
			local res = sock:read(n)
			data = data .. res
            n = n - #data
		until #res == 0 and #data == k

        return data
    end

    local function read_be(n)
        return string.unpack('>I' .. n, read(n))
    end

    local function take_snapshot(name)
        local b, s, n = os.execute(string.format("mkdir -p '%s/%s'", os.getenv("HOME").."/tmp/fuzz", name))
        if n ~= 0 then
            print(string.format("Failed to create '%s', exit='%d'.", name, n))
            os.exit(1)
        end

        -- manager.machine.memory.regions[region]
        -- manager.machine.memory.shares[tag]
        local mem = cpu.spaces["program"]
        if not mem then
            print("Missing space 'program'.")
            os.exit(1)
        end

        -- Store 0x10000-sized segments.
        -- TODO: Include banked maps.
        local start_addr = 0xf0000
        local data = mem:read_range(start_addr, start_addr + 0xffff, 8, nil)
    end

    local function tap_cb(offset, data, mask)
        -- TODO
    end

    reset_subscription = emu.add_machine_reset_notifier(function ()
        print(string.format("Fuzzer harness started with ROM='%s'.", emu.romname()))

        cpu = manager.machine.devices[":maincpu"]
        mut_bps = { }
        mut_taps = { }

        -- Sanity checks.
        if not manager.machine.debugger then
            error("Missing debugger.")
            os.exit(1)
        end
        if not cpu or not cpu.debug then
            error("Missing or invalid device ':maincpu'.")
            os.exit(1)
        end

        -- Prepare snapshots dir.
        local b, s, n = os.execute(string.format("mkdir -p '%s'", os.getenv("HOME").."/tmp/fuzz"))
        if n ~= 0 then
            error(string.format("Failed to create '/tmp/fuzz', exit='%d'.", n))
            os.exit(1)
        end

        -- Prepare mutation patterns.
        sock = emu.file("rw")
        local err = sock:open("socket.127.0.0.1:1477")
		if err then
			error(string.format("Bad sock: '%s'.", err))
            os.exit(1)
		end

        len_patterns = read_be(4)
		if len_patterns == 0 then
            error("No patterns read.")
            os.exit(1)
		end
        print(string.format("#patterns = '%08x'.", len_patterns))

        for i = 0, len_patterns - 1 do
            local kind = read_be(1)
            local space_n = read_be(4)
            local space = read(space_n)
            local addr_size = read_be(4) // 8
            local addr = read_be(addr_size)
            local data_size = read_be(4) // 8
            print(string.format("@ %s:%04x", space, addr))

            local mem = cpu.spaces[space]
            if not mem then
                error(string.format("Missing space '%s'.", space))
                os.exit(1)
            end

            if kind == 0 then
                local len_vals = read_be(4)
                for j = 0, len_vals - 1 do
                    local val = read_be(data_size)
                    if data_size == 1 then
                        mem:write_u8(addr, val)
                    elseif data_size == 2 then
                        mem:write_u16(addr, val)
                    elseif data_size == 4 then
                        mem:write_u32(addr, val)
                    elseif data_size == 8 then
                        mem:write_u64(addr, val)
                    else
                        error(string.format("Bad data size '%08x'.", data_size))
                        os.exit(1)
                    end
                end

                -- mut_taps[addr] = mem:install_read_tap(addr, addr + data_size, string.format("mem_%04x", addr), tap_cb)
            else
                mut_bps[addr] = { }

                local len_regs = read_be(4)
                for j = 0, len_regs - 1 do
                    local reg = read(read_be(1))
                    local reg_val = read_be(data_size)
                    mut_bps[addr][reg] = reg_val
                end
            end
        end

        -- Break on addresses where state is fuzzed.
        -- luaengine_debug.cpp @ device_debug_type.set_function("bpset", ...);
        for addr, expr in pairs(mut_bps) do
            act = ""
            for lhs, rhs in pairs(expr) do
                act = act .. string.format('%s = %s;g;', lhs, rhs)
            end
            cpu.debug:bpset(addr, nil, act)
        end

        emu.register_periodic(cb)
    end)

    stop_subscription = emu.add_machine_stop_notifier(function ()
        mut_bps = nil

        for i, b in pairs(mut_taps) do
            b:remove()
        end
        mut_taps = nil

        sock:close()
        sock = nil

        cpu.debug:dump()
        cpu = nil

        print(string.format("Fuzzer harness stopped."))
    end)
end

return exports
