-- SPDX-License-Identifier: GPL-3.0-or-later
-- Copyright (C) 2026 Youcef Nabil
-- ce-mcp bridge: lets ce_mcp.py (an MCP server) drive Cheat Engine without the GUI.
--
-- ce_mcp.py keeps a private CE copy in ce-mcp\ce, syncs this file into its autorun folder and starts it
-- hidden and non-elevated (CE_MCP_PARENT = the server's PID); CE then closes when the server exits.
-- The transport is a file mailbox in %LOCALAPPDATA%\ce-mcp, so an elevated CE (run by hand) still works:
-- the client writes `req`, a timer here answers in `resp`.
-- Every request line is `key=<hex of the value bytes>`; the reply is `id=N v=VERSION`, `ok`/`err`, then text.
--
-- When CE is started by hand, the bridge polls only if %LOCALAPPDATA%\ce-mcp\enabled exists; the "ce-mcp"
-- main menu toggles it. Lua inside auto assembler scripts is refused (see the README's Safety section).

local VERSION = 2  -- must match BRIDGE_VERSION in ce_mcp.py
local DIR = os.getenv('LOCALAPPDATA') .. '\\ce-mcp'
-- a CE started by ce-mcp serves that server's own mailbox; one started by hand serves the shared one
local BOX = os.getenv('CE_MCP_MAILBOX') or DIR
local REQ, RESP, RESP_TMP = BOX .. '\\req', BOX .. '\\resp', BOX .. '\\resp.tmp'

local function unhex(s)
  return (s:gsub('%x%x', function(h) return string.char(tonumber(h, 16)) end))
end

local function hexbytes(t, sep)
  local o = {}
  for i = 1, #t do o[i] = string.format('%02X', t[i]) end
  return table.concat(o, sep or '')
end

local function fail(msg) error(msg, 0) end

local function addr(s)
  if not s or s == '' then fail('missing address') end
  local a = getAddressSafe(s)
  if not a then fail('cannot resolve address: ' .. s) end
  return a
end

local function name(a)
  local n = getNameFromAddress(a)
  if n and n:find('+', 1, true) then return string.format('%X (%s)', a, n) end
  return string.format('%X', a)
end

local function need_process()
  if getOpenedProcessID() == 0 then fail('no process attached (use attach)') end
end

local cmd = {}
local bps = {}     -- [address] = {kind, size, total, hits = {[insn] = {n, first, last}}, order = {insn...}}

---------------------------------------------------------------- process

local function proc_name(pid)
  return (getProcesslist() or {})[pid] or '?'
end

local function status_text()
  local pid = getOpenedProcessID()
  if pid == 0 then return 'not attached' end
  local bpn = 0
  for _ in pairs(bps) do bpn = bpn + 1 end
  return string.format('pid %d %s%s, debugger %s, %d breakpoint(s)', pid, proc_name(pid),
    targetIs64Bit() and ' (64-bit)' or ' (32-bit)',
    debug_isDebugging() and ('on, interface ' .. tostring(debug_getCurrentDebuggerInterface())) or 'off', bpn)
end

function cmd.status() return status_text() end

function cmd.attach(r)
  local p = r.process
  local pid = tonumber(p)
  if not pid then
    -- resolve the name ourselves: CE's `process` global is not reliably set
    for id, n in pairs(getProcesslist() or {}) do
      if n:lower() == p:lower() and (not pid or id > pid) then pid = id end
    end
    if not pid then fail(p .. ' is not running') end
  end
  openProcess(pid)
  if getOpenedProcessID() ~= pid then fail(string.format('could not open pid %d', pid)) end
  -- OpenProcess can hand out a handle that cannot read memory (e.g. an elevated target)
  if #(enumModules() or {}) == 0 then
    fail(string.format('opened %s (pid %d) but cannot read its memory: is it running as administrator? '
      .. 'The CE started by ce-mcp is not elevated', proc_name(pid), pid))
  end
  return status_text()
end

function cmd.modules(r)
  need_process()
  local f, out = (r.filter or ''):lower(), {}
  for _, m in ipairs(enumModules()) do
    if f == '' or m.Name:lower():find(f, 1, true) then
      out[#out + 1] = string.format('%X %8X %s', m.Address, getModuleSize(m.Name) or 0, m.Name)
      if #out >= 200 then break end
    end
  end
  return table.concat(out, '\n')
end

function cmd.symbol(r)
  return name(addr(r.addr))
end

---------------------------------------------------------------- memory

function cmd.read(r)
  need_process()
  local a, n = addr(r.addr), tonumber(r.size)
  local t = readBytes(a, n, true)
  if not t or #t ~= n then fail(string.format('cannot read %d bytes at %X', n, a)) end
  return hexbytes(t)
end

function cmd.write(r)
  need_process()
  local a, data = addr(r.addr), r.data
  local t = {}
  for i = 1, #data do t[i] = data:byte(i) end
  local old = readBytes(a, #t, true)
  if not old then fail(string.format('cannot read %X', a)) end
  writeBytes(a, t)
  local new = readBytes(a, #t, true)
  if not new or hexbytes(new) ~= hexbytes(t) then
    fail(string.format('write at %X did not stick (protected page? patch code with aa)', a))
  end
  return hexbytes(old)
end

---------------------------------------------------------------- scans

local VT = { u8 = vtByte, s8 = vtByte, u16 = vtWord, s16 = vtWord, u32 = vtDword, s32 = vtDword,
             u64 = vtQword, s64 = vtQword, f32 = vtSingle, f64 = vtDouble, aob = vtByteArray, str = vtString }
local SO = { exact = soExactValue, between = soValueBetween, bigger = soBiggerThan, smaller = soSmallerThan,
             unknown = soUnknownValue, increased = soIncreasedValue, increasedby = soIncreasedValueBy,
             decreased = soDecreasedValue, decreasedby = soDecreasedValueBy, changed = soChanged,
             unchanged = soUnchanged }

local scans = {}   -- 'main' (scan/next) and 'aob', each {ms=, fl=}

local function scanner(key)
  local s = scans[key]
  if not s then
    s = { ms = createMemScan() }
    s.fl = createFoundList(s.ms)
    scans[key] = s
  end
  return s
end

local function listing(s, off, n)
  local c = s.fl.Count
  local out = { string.format('count=%d', c) }
  for i = off, math.min(c, off + n) - 1 do
    local a = tonumber(s.fl.Address[i], 16)
    out[#out + 1] = (a and name(a) or s.fl.Address[i]) .. ' = ' .. s.fl.Value[i]
  end
  return table.concat(out, '\n')
end

local function range(r)
  if r.module and r.module ~= '' then
    local base = getAddressSafe(r.module)
    if not base then fail('unknown module: ' .. r.module) end
    return base, base + getModuleSize(r.module)
  end
  local lo = (r.start and r.start ~= '') and addr(r.start) or 0
  local hi = (r.stop and r.stop ~= '') and addr(r.stop) or 0x7FFFFFFFFFFFFFFF
  return lo, hi
end

local function first_scan(key, r)
  need_process()
  local vt, so = VT[r.type], SO[r.option]
  if not vt then fail('bad type ' .. tostring(r.type)) end
  if not so then fail('bad scan option ' .. tostring(r.option)) end
  local s = scanner(key)
  if s.type then s.fl.deinitialize() end
  s.type = nil
  s.ms.newScan()
  local lo, hi = range(r)
  local align = (vt == vtByteArray or vt == vtString or vt == vtByte) and '1' or tostring(r.align or '4')
  s.ms.firstScan(so, vt, rtRounded, r.v1 or '', r.v2 or '', lo, hi, r.prot or '+W*X*C',
    align == '1' and fsmNotAligned or fsmAligned, align, vt == vtByteArray, false, false, false)
  s.ms.waitTillDone()
  s.fl.initialize()
  s.type = r.type
  return listing(s, 0, tonumber(r.show) or 20)
end

function cmd.scan(r) return first_scan('main', r) end

function cmd.aob(r)
  r.type, r.option, r.v1, r.prot = 'aob', 'exact', r.pattern, r.prot or '*W*X*C'
  return first_scan('aob', r)
end

function cmd.next(r)
  need_process()
  local s = scans.main
  if not s or not s.type then fail('no first scan yet') end
  local so = SO[r.option]
  if not so then fail('bad scan option ' .. tostring(r.option)) end
  s.fl.deinitialize()
  s.ms.nextScan(so, rtRounded, r.v1 or '', r.v2 or '', s.type == 'aob', false, false, false, false)
  s.ms.waitTillDone()
  s.fl.initialize()
  return listing(s, 0, tonumber(r.show) or 20)
end

function cmd.results(r)
  local s = scans[r.which or 'main']
  if not s or not s.type then fail('no scan yet') end
  return listing(s, tonumber(r.offset) or 0, tonumber(r.show) or 50)
end

---------------------------------------------------------------- breakpoints

local REGS = { 'RAX', 'RBX', 'RCX', 'RDX', 'RSI', 'RDI', 'RBP', 'RSP',
               'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15' }

local function regs()
  local o = {}
  for i, n in ipairs(REGS) do
    local v = _G[n]
    o[i] = string.format('%s=%X', n, v or 0)
  end
  return table.concat(o, ' ')
end

function cmd.bp_set(r)
  need_process()
  local a, kind, size = addr(r.addr), r.kind or 'write', tonumber(r.size) or 4
  local trig = ({ write = bptWrite, access = bptAccess, execute = bptExecute })[kind]
  if not trig then fail('kind must be write, access or execute') end
  if trig == bptExecute then size = 1 end
  if bps[a] then fail(string.format('breakpoint already set at %X (bp_clear first)', a)) end
  local n = 0
  for _ in pairs(bps) do n = n + 1 end
  if n >= 4 then fail('all 4 hardware breakpoints are in use (bp_clear one first)') end
  if not debug_isDebugging() then
    debugProcess(tonumber(r.debugger) or 0)
    if not debug_isDebugging() then fail('could not start the debugger') end
  end
  local rec = { kind = kind, size = size, total = 0, hits = {}, order = {} }
  bps[a] = rec
  debug_setBreakpoint(a, size, trig, bpmDebugRegister, function()
    -- data breakpoints trap after the instruction ran, so report the one before RIP
    local ip = (trig == bptExecute) and RIP or getPreviousOpcode(RIP)
    rec.total = rec.total + 1
    local h = rec.hits[ip]
    if not h and #rec.order < 64 then
      h = { n = 0, first = regs() }
      rec.hits[ip] = h
      rec.order[#rec.order + 1] = ip
    end
    if h then
      h.n = h.n + 1
      if h.n > 1 then h.last = regs() end
      if trig ~= bptExecute then
        local v = readBytes(a, size, true)
        h.value = v and hexbytes(v, ' ') or '?'
      end
    end
    debug_continueFromBreakpoint(co_run)
    return 1
  end)
  return string.format('%s breakpoint on %s (size %d)', kind, name(a), size)
end

local function hits_text(a, rec)
  local out = { string.format('%s %s size %d: %d hit(s), %d instruction(s)', rec.kind, name(a), rec.size,
    rec.total, #rec.order) }
  for _, ip in ipairs(rec.order) do
    local h = rec.hits[ip]
    local d = disassemble(ip)
    out[#out + 1] = string.format('%s x%d  %s', name(ip), h.n, d:match('^.- %- .- %- (.*)$') or d)
    if h.value then out[#out + 1] = '  value after: ' .. h.value end
    out[#out + 1] = '  first: ' .. h.first
    if h.last then out[#out + 1] = '  last:  ' .. h.last end
  end
  return table.concat(out, '\n')
end

function cmd.bp_hits(r)
  local out = {}
  for a, rec in pairs(bps) do
    if not r.addr or r.addr == '' or a == addr(r.addr) then out[#out + 1] = hits_text(a, rec) end
  end
  if #out == 0 then return 'no breakpoints set by ce-mcp' end
  return table.concat(out, '\n\n')
end

function cmd.bp_clear(r)
  local n = 0
  for a in pairs(bps) do
    if not r.addr or r.addr == '' or a == addr(r.addr) then
      debug_removeBreakpoint(a)
      bps[a] = nil
      n = n + 1
    end
  end
  return string.format('removed %d breakpoint(s)', n)
end

---------------------------------------------------------------- code

function cmd.disasm(r)
  need_process()
  local target = addr(r.addr)
  local a = target
  for _ = 1, tonumber(r.before) or 0 do a = getPreviousOpcode(a) end
  local out = {}
  for _ = 1, math.min(tonumber(r.count) or 12, 200) do
    local d = disassemble(a)
    local bytes, op = d:match('^.- %- (.-) %- (.*)$')
    out[#out + 1] = string.format('%s %-30s %-24s %s', a == target and '>' or ' ', getNameFromAddress(a),
      bytes or '', op or d)
    a = a + math.max(getInstructionSize(a) or 1, 1)
  end
  return table.concat(out, '\n')
end

local scripts = {}  -- enabled: [name] = {script, info}
local last = {}     -- [name] = the last script given, so enabling again needs no script

function cmd.aa(r)
  need_process()
  local nm, script = r.name, r.script or ''
  if r.enable == '1' then
    if script == '' then script = last[nm] or fail('no script given for ' .. tostring(nm)) end
    local low = script:lower()
    if low:find('{$lua', 1, true) or low:find('luacall', 1, true) then
      fail('Lua in auto assembler scripts is not allowed through the bridge')
    end
    if scripts[nm] then fail('already enabled: ' .. nm) end
    local ok, info = autoAssemble(script)
    if not ok then fail('auto assembler failed: ' .. tostring(info)) end
    scripts[nm] = { script = script, info = info }
    last[nm] = script
    return 'enabled ' .. nm
  end
  local s = scripts[nm]
  if not s then fail('not enabled: ' .. tostring(nm)) end
  local ok, err = autoAssemble(s.script, s.info)
  if not ok then fail('disable failed: ' .. tostring(err)) end
  scripts[nm] = nil
  return 'disabled ' .. nm
end

---------------------------------------------------------------- mailbox

local function respond(id, ok, text)
  os.remove(RESP_TMP)
  local f = io.open(RESP_TMP, 'wb')
  if not f then return end
  f:write('id=', id, ' v=', VERSION, '\n', ok and 'ok' or 'err', '\n', text or '')
  f:close()
  os.remove(RESP)
  os.rename(RESP_TMP, RESP)
end

local busy = false

local function poll()
  if busy then return end
  local f = io.open(REQ, 'rb')
  if not f then return end
  local text = f:read('*a')
  f:close()
  os.remove(REQ)
  local r = {}
  for k, v in text:gmatch('([%w_]+)=(%x*)\n') do r[k] = unhex(v) end
  local id = r.id or '0'
  local fn = cmd[r.cmd or '']
  if not fn then respond(id, false, 'unknown command: ' .. tostring(r.cmd)) return end
  busy = true
  local ok, res = pcall(fn, r)
  busy = false
  respond(id, ok, tostring(res))
end

local timer = createTimer(nil, false)
timer.Interval = 20
timer.OnTimer = poll

local menu = createMenuItem(MainForm)
MainForm.Menu.Items.add(menu)

local function set_enabled(on)
  timer.Enabled = on
  menu.Caption = on and 'ce-mcp: ON' or 'ce-mcp: off'
end

local toggle = createMenuItem(MainForm)
toggle.Caption = 'Toggle bridge'
toggle.OnClick = function() set_enabled(not timer.Enabled) end
menu.add(toggle)

local parent = tonumber(os.getenv('CE_MCP_PARENT') or '')
if parent then
  set_enabled(true)
  -- close with the MCP server, removing our breakpoints first so the game is left clean
  local watchdog = createTimer(nil, true)
  watchdog.Interval = 3000
  watchdog.OnTimer = function()
    if (getProcesslist() or {})[parent] then return end
    watchdog.Enabled = false
    pcall(cmd.bp_clear, {})
    closeCE()
  end
else
  set_enabled(fileExists(DIR .. '\\enabled'))
end
