-- SPDX-License-Identifier: GPL-3.0-or-later
-- Copyright (C) 2026 Youcef Nabil
-- ce-mcp bridge: lets ce_mcp.py (an MCP server) drive Cheat Engine without the GUI.
--
-- ce_mcp.py keeps a private CE copy in ce-mcp\ce, syncs this file into its autorun folder and starts it
-- hidden and non-elevated (CE_MCP_PARENT = the server's PID); CE then closes when the server exits, which it
-- notices when it can delete CE_MCP_ALIVE, a file the server holds open (unlike a PID, it is never reused).
-- The transport is a file mailbox in %LOCALAPPDATA%\ce-mcp, so an elevated CE (run by hand) still works:
-- the client writes `req`, a timer here answers in `resp`.
-- Every request line is `key=<hex of the value bytes>`; the reply is `id=N v=VERSION`, `ok`/`err`, then text.
--
-- When CE is started by hand, the bridge polls only if %LOCALAPPDATA%\ce-mcp\enabled exists; the "ce-mcp"
-- main menu toggles it. Lua inside auto assembler scripts is refused (see the README's Safety section).

local VERSION = 6  -- must match BRIDGE_VERSION in ce_mcp.py
local PARENT = tonumber(os.getenv('CE_MCP_PARENT') or '')  -- set when ce-mcp started this CE
local ALIVE = os.getenv('CE_MCP_ALIVE')
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

-- `count` instructions from `target`, starting `before` instructions earlier
local function code_lines(target, count, before, with_bytes)
  local a, out = target, {}
  for _ = 1, before do a = getPreviousOpcode(a) end
  for _ = 1, math.min(count, 200) do
    local d = disassemble(a)
    local bytes, op = d:match('^.- %- (.-) %- (.*)$')
    if with_bytes then
      out[#out + 1] = string.format('%s %-30s %-24s %s', a == target and '>' or ' ', getNameFromAddress(a),
        bytes or '', op or d)
    else
      out[#out + 1] = getNameFromAddress(a) .. '  ' .. (op or d)
    end
    a = a + math.max(getInstructionSize(a) or 1, 1)
  end
  return table.concat(out, '\n')
end

local cmd = {}
local bps = {}     -- [address] = {kind, size, total, hits = {[insn] = {n, first, last}}, order = {insn...}}
local attached = {}  -- pid and name given by the last attach, to notice when that process exits
local checked = 0    -- getTickCount() of the last check that the process still runs

---------------------------------------------------------------- process

local function proc_name(pid)
  return (getProcesslist() or {})[pid] or '?'
end

-- The attached process exited (or its PID now belongs to another program): CE keeps the dead handle and
-- breakpoints just never fire, so say so instead. Returns the message, or nil while the process runs.
local function exited()
  local pid = getOpenedProcessID()
  if pid == 0 or pid ~= attached.pid then return nil end
  local list = getProcesslist() or {}
  if list[pid] and list[pid]:lower() == attached.name:lower() then return nil end
  local newer
  for id, n in pairs(list) do
    if n:lower() == attached.name:lower() and (not newer or id > newer) then newer = id end
  end
  return string.format('%s (pid %d) has exited%s; its breakpoints are gone', attached.name, pid,
    newer and string.format(': it runs again as pid %d, attach("%s") again', newer, attached.name) or '')
end

local function need_process()
  if getOpenedProcessID() == 0 then fail('no process attached (use attach)') end
  local now = getTickCount()
  if now - checked < 1000 then return end
  local msg = exited()
  if msg then
    for a in pairs(bps) do bps[a] = nil end
    fail(msg)
  end
  checked = now
end

local function status_text()
  local pid = getOpenedProcessID()
  if pid == 0 then return 'not attached' end
  local msg = exited()
  if msg then return msg end
  local on, stopped = 0, 0
  for _, rec in pairs(bps) do
    if rec.stopped then stopped = stopped + 1 else on = on + 1 end
  end
  return string.format('pid %d %s%s, debugger %s, %d breakpoint(s)%s', pid, proc_name(pid),
    targetIs64Bit() and ' (64-bit)' or ' (32-bit)',
    debug_isDebugging() and ('on, interface ' .. tostring(debug_getCurrentDebuggerInterface())) or 'off', on,
    stopped > 0 and string.format(' (+%d stopped at max_hits)', stopped) or '')
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
  attached.pid, attached.name, checked = pid, proc_name(pid), 0
  -- breakpoints of a process that exited can't be removed any more: forget them
  local list = getProcesslist() or {}
  for a, rec in pairs(bps) do
    if rec.pid ~= pid and not list[rec.pid] then bps[a] = nil end
  end
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

local REGS64 = { 'RAX', 'RBX', 'RCX', 'RDX', 'RSI', 'RDI', 'RBP', 'RSP',
                 'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15' }
local REGS32 = { 'EAX', 'EBX', 'ECX', 'EDX', 'ESI', 'EDI', 'EBP', 'ESP' }
local REGSET = { RIP = true, EIP = true }
for _, n in ipairs(REGS64) do REGSET[n] = true end
for _, n in ipairs(REGS32) do REGSET[n] = true end

-- CE names the registers after the target: RAX..R15/RIP in a 64-bit process, EAX..ESP/EIP in a 32-bit one.
-- Operands may use either spelling; R8..R15 read nil in a 32-bit process.
local TO32, TO64 = { RIP = 'EIP' }, { EIP = 'RIP' }
for i, n in ipairs(REGS32) do TO32[REGS64[i]] = n; TO64[n] = REGS64[i] end

local function regval(n)
  if targetIs64Bit() then return _G[TO64[n] or n] end
  return _G[TO32[n] or n]
end

-- An operand of where/collect/capture/log: a number, a register, or memory at a sum of registers and numbers
-- ([REG], [REG+0x10], [RBX+R11-8], [0x1234]), with an optional :size in bytes (default 8, read little-endian;
-- capture dumps longer ones).
local function operand(text, maxsize)
  local s = text:gsub('%s', '')
  local inner, sz = s:match('^%[(.-)%]:?(%w*)$')
  if not inner then
    local u = s:upper()
    if REGSET[u] then return { text = u, reg = u } end
    local v = tonumber(s)
    if math.type(v) == 'integer' then return { text = s, num = v } end
    fail('bad operand "' .. text .. '": use a number, a register (RAX..R15, RIP; EAX..ESP, EIP) or [REG+offset]:size')
  end
  local size = sz == '' and 8 or tonumber(sz)
  if math.type(size) ~= 'integer' or size < 1 or size > maxsize then
    fail(string.format('bad size in "%s" (1..%d bytes)', text, maxsize))
  end
  local o, bad = { text = s, size = size, terms = {} }, false
  local rest = inner:upper():gsub('([%+%-]?)([^%+%-]+)', function(sign, term)
    local t = { neg = sign == '-' }
    if REGSET[term] then t.reg = term else t.num = tonumber(term) end
    if not t.reg and math.type(t.num) ~= 'integer' then bad = true end
    o.terms[#o.terms + 1] = t
    return ''
  end)
  if bad or rest ~= '' or #o.terms == 0 then
    fail('bad memory operand "' .. text .. '": registers and numbers (hex with 0x) joined by + or -')
  end
  return o
end

local function operands(text, maxsize)
  local list = {}
  for part in (text or ''):gmatch('[^,]+') do
    if part:match('%S') then list[#list + 1] = operand(part, maxsize) end
  end
  return list
end

-- Value of an operand at this moment (in a breakpoint handler): an integer, a hex dump for memory longer
-- than 8 bytes, or nil when the memory can't be read.
local function value(o)
  if o.num then return o.num end
  if not o.terms then return regval(o.reg) end
  local a = 0
  for _, t in ipairs(o.terms) do
    local v = t.num or regval(t.reg)
    if not v then return nil end
    a = t.neg and a - v or a + v
  end
  local b = readBytes(a, o.size, true)
  if not b or #b < o.size then return nil end
  if o.size > 8 then return hexbytes(b, ' ') end
  local v = 0
  for i = #b, 1, -1 do v = (v << 8) | b[i] end
  return v
end

local function show(v)
  if v == nil then return '?' end
  return math.type(v) == 'integer' and string.format('%X', v) or v
end

-- where: comparisons joined by && (or "and"); all must hold. < and > compare unsigned.
local OPS = { '==', '!=', '<=', '>=', '<', '>' }

local function conditions(text)
  local list = {}
  for part in ((text or ''):gsub('%s+[aA][nN][dD]%s+', '&&') .. '&&'):gmatch('(.-)&&') do
    if part:match('%S') then
      local c
      for _, op in ipairs(OPS) do
        local i = part:find(op, 1, true)
        if i then
          c = { op = op, l = operand(part:sub(1, i - 1), 8), r = operand(part:sub(i + #op), 8) }
          break
        end
      end
      if not c then fail('bad condition "' .. part .. '": compare with ==, !=, <, >, <= or >=') end
      list[#list + 1] = c
    end
  end
  return list
end

local function holds(list)
  for _, c in ipairs(list) do
    local a, b = value(c.l), value(c.r)
    if a == nil or b == nil then return false end
    local ok
    if c.op == '==' then ok = a == b
    elseif c.op == '!=' then ok = a ~= b
    elseif c.op == '<' then ok = math.ult(a, b)
    elseif c.op == '>' then ok = math.ult(b, a)
    elseif c.op == '<=' then ok = not math.ult(b, a)
    else ok = not math.ult(a, b) end
    if not ok then return false end
  end
  return true
end

local STACK_BYTES = 0x400  -- stack kept per hit with stack=true; the return addresses in it are picked out on report
local CALLERS_MAX = 10

-- What a hit looked like (in a breakpoint handler): raw values only, the text is made when reporting.
local function snapshot(rec)
  local s = { regs = {} }
  for i, n in ipairs(rec.is64 and REGS64 or REGS32) do s.regs[i] = _G[n] or 0 end
  if #rec.capture > 0 then
    local c = {}
    for i, op in ipairs(rec.capture) do c[i] = op.text .. '=' .. show(value(op)) end
    s.capture = table.concat(c, '  ')
  end
  if rec.stack then
    local sp = regval('RSP')
    s.stack = sp and (readBytes(sp, STACK_BYTES, true) or readBytes(sp, 0x40, true)) or {}
  end
  return s
end

-- True when the bytes before `a` are a call instruction, so `a` on a stack is a return address.
local function after_call(a)
  local b = readBytes(a - 7, 7, true)   -- b[8 - k] is the byte k before a
  if not b or #b < 7 then return false end
  if b[3] == 0xE8 then return true end  -- call rel32
  for _, k in ipairs({ 2, 3, 4, 6, 7 }) do  -- call r/m (FF /2) that is k bytes long
    local modrm = b[9 - k]
    if b[8 - k] == 0xFF and (modrm >> 3) & 7 == 2 then
      local mod, rm = modrm >> 6, modrm & 7
      local sib = mod ~= 3 and rm == 4
      local disp32 = mod == 2 or (mod == 0 and (rm == 5 or (sib and k > 2 and b[10 - k] & 7 == 5)))
      if 2 + (sib and 1 or 0) + (mod == 1 and 1 or 0) + (disp32 and 4 or 0) == k then return true end
    end
  end
  return false
end

-- The return addresses in a stack snapshot, nearest first, as `+slot offset  module+offset`. Works without frame
-- pointers and in code no module owns (JIT); a stale slot that still holds an old return address shows up too.
local function callers(stack, is64)
  local w, out = is64 and 8 or 4, {}
  for o = 0, #stack - w, w do
    local v = 0
    for i = w, 1, -1 do v = (v << 8) | stack[o + i] end
    if v > 0x10000 and after_call(v) then
      out[#out + 1] = string.format('+%X %s', o, getNameFromAddress(v))
      if #out >= CALLERS_MAX then break end
    end
  end
  if #out == 0 then return string.format('none in the %d bytes at the stack pointer', #stack) end
  return table.concat(out, ', ')
end

-- A snapshot as text. With `first` (the instruction's first hit) only what differs from it is shown.
local function snap_text(rec, s, first)
  local o = {}
  for i, n in ipairs(rec.is64 and REGS64 or REGS32) do
    if not first or s.regs[i] ~= first.regs[i] then o[#o + 1] = string.format('%s=%X', n, s.regs[i]) end
  end
  local text = #o > 0 and table.concat(o, ' ') or 'same registers'
  if s.capture and not (first and first.capture == s.capture) then text = text .. '\n    capture: ' .. s.capture end
  if s.stack then
    s.callers = s.callers or callers(s.stack, rec.is64)
    if not (first and first.callers == s.callers) then text = text .. '\n    callers: ' .. s.callers end
  end
  return text
end

local COLLECT_MAX = 32  -- distinct values kept per collected operand and instruction
local LOG_MAX = 20000   -- rows kept per breakpoint with log=
local log_seq = 0       -- hits logged by any breakpoint: orders rows across breakpoints (hits are handled one at a time)

local function tally(h, rec)
  h.col = h.col or {}
  for i, op in ipairs(rec.collect) do
    local t = h.col[i] or { n = {}, order = {}, other = 0 }
    h.col[i] = t
    local v = show(value(op))
    if t.n[v] then t.n[v] = t.n[v] + 1
    elseif #t.order < COLLECT_MAX then t.n[v] = 1; t.order[#t.order + 1] = v
    else t.other = t.other + 1 end
  end
end

local function active_bps()
  local n = 0
  for _, rec in pairs(bps) do
    if not rec.stopped then n = n + 1 end
  end
  return n
end

local function on_hit(a, rec, trig)
  if #rec.where > 0 and not holds(rec.where) then
    rec.skipped = rec.skipped + 1
    return
  end
  -- data breakpoints trap after the instruction ran, so report the one before RIP
  local pc = regval('RIP')
  local ip = (trig == bptExecute) and pc or getPreviousOpcode(pc)
  rec.total = rec.total + 1
  local h = rec.hits[ip]
  if not h and #rec.order < 64 then
    h = { n = 0, first = snapshot(rec) }
    rec.hits[ip] = h
    rec.order[#rec.order + 1] = ip
  end
  if h then
    h.n = h.n + 1
    if h.n > 1 then h.last = snapshot(rec) end
    if trig ~= bptExecute then
      local v = readBytes(a, rec.size, true)
      h.value = v and hexbytes(v, ' ') or '?'
    end
    if #rec.collect > 0 then tally(h, rec) end
  end
  if #rec.log > 0 and #rec.rows < LOG_MAX then
    log_seq = log_seq + 1
    local row = { tostring(getTickCount() - rec.t0), tostring(log_seq) }
    for i, op in ipairs(rec.log) do row[i + 2] = show(value(op)) end
    rec.rows[#rec.rows + 1] = table.concat(row, '\t')
  end
  if rec.max > 0 and rec.total >= rec.max then
    -- keep the hits, free the debug register once this handler has returned
    rec.stopped = true
    createTimer(1, function() debug_removeBreakpoint(a) end)
  end
end

function cmd.bp_set(r)
  need_process()
  local a, kind, size = addr(r.addr), r.kind or 'write', tonumber(r.size) or 4
  local trig = ({ write = bptWrite, access = bptAccess, execute = bptExecute })[kind]
  if not trig then fail('kind must be write, access or execute') end
  if trig == bptExecute then size = 1 end
  if bps[a] then fail(string.format('breakpoint already set at %X (bp_clear first)', a)) end
  if active_bps() >= 4 then fail('all 4 hardware breakpoints are in use (bp_clear one first)') end
  local rec = { kind = kind, size = size, total = 0, skipped = 0, hits = {}, order = {},
                pid = getOpenedProcessID(), is64 = targetIs64Bit(), stack = r.stack == '1',
                max = tonumber(r.max_hits) or 0,
                where = conditions(r.where), collect = operands(r.collect, 8), capture = operands(r.capture, 256),
                log = operands(r.log, 8), rows = {}, t0 = getTickCount() }
  if not debug_isDebugging() then
    -- The VEH debugger's dll stays in the game after its CE is gone (killed by restart(), crashed). Starting it
    -- again runs its InitializeVEH a second time, which in Skyrim with CrashLogger deadlocked: the init thread held
    -- the dll's handler lock while waiting in CrashLogger's exception handler, game threads queued behind it, and
    -- CE sat on "The VEH dll seems to have failed to load". Only a restart of the game clears it.
    if (tonumber(r.debugger) or 0) ~= 1 then
      for _, m in ipairs(enumModules() or {}) do
        if m.Name:lower():find('^vehdebug%-') then
          fail('the VEH debugger of an earlier Cheat Engine is still in this process (' .. m.Name .. '); starting it '
            .. 'again can hang the game. Restart the game, or pass debugger=1 (Windows debugger: the game closes with CE)')
        end
      end
    end
    debugProcess(tonumber(r.debugger) or 0)
    if not debug_isDebugging() then fail('could not start the debugger') end
  end
  bps[a] = rec
  debug_setBreakpoint(a, size, trig, bpmDebugRegister, function()
    if not rec.stopped then
      -- a Lua error must never leave the target stopped at the breakpoint
      local ok, err = pcall(on_hit, a, rec, trig)
      if not ok then rec.err = tostring(err) end
    end
    debug_continueFromBreakpoint(co_run)
    return 1
  end)
  return string.format('%s breakpoint on %s (size %d)', kind, name(a), size)
end

local function hits_text(a, rec)
  local out = { string.format('%s %s size %d: %d hit(s), %d instruction(s)%s%s', rec.kind, name(a), rec.size,
    rec.total, #rec.order, rec.skipped > 0 and string.format(', %d skipped by where', rec.skipped) or '',
    rec.stopped and ', stopped at max_hits' or '') }
  if rec.err then out[#out + 1] = 'handler error: ' .. rec.err end
  for _, ip in ipairs(rec.order) do
    local h = rec.hits[ip]
    local d = disassemble(ip)
    out[#out + 1] = string.format('%s x%d  %s', name(ip), h.n, d:match('^.- %- .- %- (.*)$') or d)
    if h.value then out[#out + 1] = '  value after: ' .. h.value end
    for i, t in ipairs(h.col or {}) do
      local vs = {}
      for j, v in ipairs(t.order) do vs[j] = v end
      table.sort(vs, function(x, y) return t.n[x] > t.n[y] end)
      for j, v in ipairs(vs) do vs[j] = string.format('%s x%d', v, t.n[v]) end
      out[#out + 1] = string.format('  %s: %s%s', rec.collect[i].text, table.concat(vs, ', '),
        t.other > 0 and string.format(' (+%d hits with other values)', t.other) or '')
    end
    out[#out + 1] = '  first: ' .. snap_text(rec, h.first)
    if h.last then out[#out + 1] = '  last (what changed): ' .. snap_text(rec, h.last, h.first) end
  end
  return table.concat(out, '\n')
end

local function log_text(a, rec, file, several)
  local head = { 'ms' }
  head[2] = 'seq'
  for i, op in ipairs(rec.log) do head[i + 2] = op.text end
  local s = string.format('log: %d row(s)%s', #rec.rows, #rec.rows >= LOG_MAX and ' (full)' or '')
  if file and file ~= '' then
    if several then
      local stem, ext = file:match('^(.*)(%.[^%.\\/]*)$')
      file = string.format('%s_%X%s', stem or file, a, ext or '')
    end
    local f = io.open(file, 'w')
    if not f then return s .. ', could not write ' .. file end
    f:write(table.concat(head, '\t'), '\n')
    for _, row in ipairs(rec.rows) do f:write(row, '\n') end
    f:close()
    return s .. ' written to ' .. file
  end
  local out = { s, '  ' .. table.concat(head, '\t') }
  for i = 1, math.min(20, #rec.rows) do out[#out + 1] = '  ' .. rec.rows[i] end
  return table.concat(out, '\n')
end

-- The breakpoints a request is about: the one at r.addr, or all of them.
local function chosen(r)
  if not r.addr or r.addr == '' then return bps end
  local a = addr(r.addr)
  return { [a] = bps[a] }
end

-- How many are still collecting (not stopped at max_hits): bp_hits(wait=) returns early at 0.
function cmd.bp_pending(r)
  need_process()
  local n = 0
  for _, rec in pairs(chosen(r)) do
    if not rec.stopped then n = n + 1 end
  end
  return tostring(n)
end

function cmd.bp_hits(r)
  local out, n = {}, 0
  for _, rec in pairs(chosen(r)) do
    if #rec.log > 0 then n = n + 1 end
  end
  for a, rec in pairs(chosen(r)) do
    local s = hits_text(a, rec)
    if #rec.log > 0 then s = s .. '\n' .. log_text(a, rec, r.log_file, n > 1) end
    out[#out + 1] = s
  end
  if #out == 0 then return 'no breakpoints set by ce-mcp' end
  return table.concat(out, '\n\n')
end

function cmd.bp_clear(r)
  local n = 0
  for a, rec in pairs(chosen(r)) do
    if not rec.stopped then debug_removeBreakpoint(a) end
    bps[a] = nil
    n = n + 1
  end
  return string.format('removed %d breakpoint(s)', n)
end

---------------------------------------------------------------- code

function cmd.disasm(r)
  need_process()
  return code_lines(addr(r.addr), tonumber(r.count) or 12, tonumber(r.before) or 0, true)
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

---------------------------------------------------------------- lua

local LUA_MAX = 20000  -- characters of output

-- Globals for lua() code: what its callers otherwise spell out again in nearly every call. Addresses may be
-- numbers or anything CE resolves ('Game.exe+1234').
local function A(x) return math.type(x) == 'integer' and x or addr(tostring(x)) end

local HELPERS = {
  -- 'HEX (module+offset)', or just the hex outside modules
  name = function(a) return name(A(a)) end,
  -- `n` instructions at `a` as text, one `module+offset  instruction` per line
  dis = function(a, n) return code_lines(A(a), n or 12, 0, false) end,
  -- Addresses holding `value` as a pointer-sized integer (who points at this), as a list of numbers.
  -- lo/hi limit the range; align defaults to the pointer size (1 finds operands inside 32-bit code).
  refs = function(value, lo, hi, align)
    need_process()
    local w = targetIs64Bit() and 8 or 4
    align = align or w
    local ms = createMemScan()
    ms.firstScan(soExactValue, w == 8 and vtQword or vtDword, rtRounded, string.format('%X', A(value)), '',
      lo and A(lo) or 0, hi and A(hi) or 0x7FFFFFFFFFFFFFFF, '*W*X*C', align == 1 and fsmNotAligned or fsmAligned,
      tostring(align), true, false, false, false)
    ms.waitTillDone()
    local fl = createFoundList(ms)
    fl.initialize()
    local out = {}
    for i = 0, math.min(fl.Count, 10000) - 1 do out[i + 1] = tonumber(fl.Address[i], 16) end
    fl.deinitialize()
    fl.destroy()
    ms.destroy()
    return out
  end,
}

-- Runs `code` with CE's whole Lua API; returns what it printed, then its return values.
-- Only in the CE ce-mcp started: that one is not elevated, so this gives no more than the caller already has.
function cmd.lua(r)
  if not PARENT then fail('lua() only runs in the Cheat Engine that ce-mcp starts, not in one started by hand') end
  local chunk, err = load(r.code or '', '=lua', 't')
  if not chunk then fail(err) end
  local out = {}
  local function emit(...)
    local t = table.pack(...)
    for i = 1, t.n do t[i] = tostring(t[i]) end
    out[#out + 1] = table.concat(t, '\t', 1, t.n)
  end
  -- pure-Lua loops are stopped at the deadline; a blocking CE call is not (restart() covers that)
  local deadline = getTickCount() + (tonumber(r.limit) or 10) * 1000
  local saved_print = print
  print = emit
  for k, f in pairs(HELPERS) do _G[k] = f end  -- again each call: earlier code may have reused the names
  debug.sethook(function() if getTickCount() > deadline then error('lua() timed out', 0) end end, '', 10000)
  local res = table.pack(pcall(chunk))
  debug.sethook()
  print = saved_print
  local text = table.concat(out, '\n')
  if not res[1] then fail((text ~= '' and text .. '\n' or '') .. 'error: ' .. tostring(res[2])) end
  if res.n > 1 then
    local ret = {}
    for i = 2, res.n do ret[#ret + 1] = tostring(res[i]) end
    text = text .. (text ~= '' and '\n' or '') .. table.concat(ret, '\t')
  end
  if #text > LUA_MAX then text = text:sub(1, LUA_MAX) .. '\n... (truncated)' end
  return text
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

-- A dialog CE opens during a request (a failed debugger start, a warning) sits on ce-mcp's hidden desktop where
-- nobody can click it, and CE never returns: it is closed (Cancel) and named in the answer instead.
local dialogs = {}
if PARENT then
  registerFormAddNotification(function(f)
    if not busy or f == MainForm then return end
    local t = createTimer(nil, false)
    t.Interval = 200
    t.OnTimer = function()
      if not f.Visible then return end
      t.destroy()
      local texts = {}
      for i = 0, f.ComponentCount - 1 do
        local c = f.Component[i]
        local ok, cap = pcall(function() return c.Caption end)
        if ok and cap and cap ~= '' and not c.ClassName:find('Button') then texts[#texts + 1] = cap end
      end
      dialogs[#dialogs + 1] = string.format("'%s'%s", f.Caption, #texts > 0 and (': ' .. table.concat(texts, ' / ')) or '')
      f.ModalResult = mrCancel
      if f.Visible then pcall(function() f.close() end) end
    end
    t.Enabled = true
  end)
end

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
  dialogs = {}
  local ok, res = pcall(fn, r)
  busy = false
  res = tostring(res)
  if #dialogs > 0 then res = res .. '\n(Cheat Engine showed a dialog, closed with Cancel: ' .. table.concat(dialogs, '; ') .. ')' end
  respond(id, ok, res)
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

if PARENT then
  set_enabled(true)
  -- close with the MCP server, removing our breakpoints first so the game is left clean
  local watchdog = createTimer(nil, true)
  watchdog.Interval = 3000
  watchdog.OnTimer = function()
    if ALIVE and fileExists(ALIVE) and not os.remove(ALIVE) then return end
    watchdog.Enabled = false
    pcall(cmd.bp_clear, {})
    closeCE()
  end
else
  set_enabled(fileExists(DIR .. '\\enabled'))
end
