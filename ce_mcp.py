# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Youcef Nabil
"""ce-mcp: MCP server that drives Cheat Engine through ce_mcp_bridge.lua.

When the bridge does not answer, the server starts its private CE copy (ce\\) non-elevated on a desktop
of its own, so nothing shows on screen, with the bridge synced into its autorun folder; that CE closes
when this server exits. The copy is made on first use from an installed Cheat Engine (or CE_MCP_SOURCE,
a CE folder). Requests go through a file mailbox in %LOCALAPPDATA%\\ce-mcp that the bridge polls.
Addresses are anything Cheat Engine resolves: hex (0x optional), "Game.exe+1234", symbols, or pointer
expressions like "[[Game.exe+10]+8]". Values are little-endian. Output is kept short on purpose.
"""
import ctypes, ctypes.wintypes as wt, glob, itertools, os, re, shutil, struct, threading, time
from mcp.server.fastmcp import FastMCP

HERE = os.path.dirname(os.path.abspath(__file__))
CE_DIR = os.path.join(HERE, 'ce')
CE_EXE = os.path.join(CE_DIR, 'cheatengine-x86_64.exe')
BRIDGE = os.path.join(HERE, 'ce_mcp_bridge.lua')
ROOT = os.path.join(os.environ['LOCALAPPDATA'], 'ce-mcp')
# Each server gets its own mailbox and CE, so concurrent sessions never take each other's requests.
# With ROOT\enabled present, a CE started by hand serves the shared ROOT mailbox instead.
SHARED = os.path.exists(os.path.join(ROOT, 'enabled'))
DIR = ROOT if SHARED else os.path.join(ROOT, str(os.getpid()))
REQ, RESP = os.path.join(DIR, 'req'), os.path.join(DIR, 'resp')
BRIDGE_VERSION = 5  # must match VERSION in ce_mcp_bridge.lua
FMT = {'u8': '<B', 's8': '<b', 'u16': '<H', 's16': '<h', 'u32': '<I', 's32': '<i',
       'u64': '<Q', 's64': '<q', 'f32': '<f', 'f64': '<d', 'ptr': '<Q'}
_seq = itertools.count(int(time.time() * 1000) % 1_000_000_000)
_lock = threading.Lock()  # one request at a time: the mailbox holds a single req/resp pair
_ce = {'proc': None}


def provision_ce():
    """Copy an installed Cheat Engine into ce\\ (reading Program Files needs no admin)."""
    src = os.environ.get('CE_MCP_SOURCE')
    if not src:
        found = sorted(glob.glob(os.path.join(os.environ.get('ProgramFiles', r'C:\Program Files'), 'Cheat Engine*',
                                              'cheatengine-x86_64.exe')))
        src = os.path.dirname(found[-1]) if found else None
    if not src or not os.path.exists(os.path.join(src, 'cheatengine-x86_64.exe')):
        raise RuntimeError('no Cheat Engine found: install it (cheatengine.org) or set CE_MCP_SOURCE to its folder')
    shutil.copytree(src, CE_DIR, ignore=shutil.ignore_patterns('unins*'), dirs_exist_ok=True)


class _SI(ctypes.Structure):
    _fields_ = [('cb', wt.DWORD), ('lpReserved', wt.LPWSTR), ('lpDesktop', wt.LPWSTR), ('lpTitle', wt.LPWSTR),
                ('dwX', wt.DWORD), ('dwY', wt.DWORD), ('dwXSize', wt.DWORD), ('dwYSize', wt.DWORD),
                ('dwXCountChars', wt.DWORD), ('dwYCountChars', wt.DWORD), ('dwFillAttribute', wt.DWORD),
                ('dwFlags', wt.DWORD), ('wShowWindow', wt.WORD), ('cbReserved2', wt.WORD),
                ('lpReserved2', ctypes.c_void_p), ('hStdInput', wt.HANDLE), ('hStdOutput', wt.HANDLE),
                ('hStdError', wt.HANDLE)]


class _PI(ctypes.Structure):
    _fields_ = [('hProcess', wt.HANDLE), ('hThread', wt.HANDLE), ('dwProcessId', wt.DWORD), ('dwThreadId', wt.DWORD)]


_k32 = ctypes.WinDLL('kernel32', use_last_error=True)
_u32 = ctypes.WinDLL('user32', use_last_error=True)
_u32.CreateDesktopW.restype = wt.HANDLE
_u32.CreateDesktopW.argtypes = [wt.LPCWSTR, wt.LPCWSTR, ctypes.c_void_p, wt.DWORD, wt.DWORD, ctypes.c_void_p]
_k32.CreateProcessW.argtypes = [wt.LPCWSTR, wt.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, wt.BOOL, wt.DWORD,
                                ctypes.c_void_p, wt.LPCWSTR, ctypes.POINTER(_SI), ctypes.POINTER(_PI)]
_k32.GetExitCodeProcess.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]
_k32.OpenProcess.restype = wt.HANDLE
_k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
_k32.CloseHandle.argtypes = [wt.HANDLE]
_k32.TerminateProcess.argtypes = [wt.HANDLE, wt.UINT]
_k32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
_k32.QueryFullProcessImageNameW.argtypes = [wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)]
DESKTOP = 'ce-mcp'


class _Proc:
    """The launched CE: just enough of Popen (pid, poll) for the server."""
    def __init__(self, pi):
        self.pid, self._h = pi.dwProcessId, pi.hProcess
        _k32.CloseHandle(pi.hThread)

    def poll(self):
        code = wt.DWORD()
        _k32.GetExitCodeProcess(self._h, ctypes.byref(code))
        return None if code.value == 259 else code.value  # STILL_ACTIVE

    def kill(self):
        _k32.TerminateProcess(self._h, 1)
        _k32.WaitForSingleObject(self._h, 5000)


def _alive(pid):
    h = _k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return False
    code = wt.DWORD()
    alive = bool(_k32.GetExitCodeProcess(h, ctypes.byref(code))) and code.value == 259
    _k32.CloseHandle(h)
    return alive


def _kill_orphan(pid):
    """Kill `pid` if it is still our CE copy (a PID can be reused, so check the executable first)."""
    h = _k32.OpenProcess(0x1001, False, pid)  # PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return
    buf, size = ctypes.create_unicode_buffer(1024), wt.DWORD(1024)
    if (_k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size))
            and os.path.normcase(buf.value) == os.path.normcase(CE_EXE)):
        _k32.TerminateProcess(h, 1)
        _k32.WaitForSingleObject(h, 5000)
    _k32.CloseHandle(h)


def _prune_mailboxes():
    """Remove the mailboxes of servers that are no longer running, and the CE of one that is still open: a CE
    stuck in a blocking call when its server exited cannot run the bridge's watchdog."""
    for name in os.listdir(ROOT) if os.path.isdir(ROOT) else []:
        if name.isdigit() and int(name) != os.getpid() and not _alive(int(name)):
            box = os.path.join(ROOT, name)
            try:
                with open(os.path.join(box, 'ce.pid')) as f:
                    _kill_orphan(int(f.read()))
            except (OSError, ValueError):
                pass
            shutil.rmtree(box, ignore_errors=True)


def launch_ce():
    """Start the private CE copy without UAC (RunAsInvoker), tied to this server's lifetime, on a desktop of
    its own so its splash and windows never appear on screen and it never takes the focus."""
    if not os.path.exists(CE_EXE):
        provision_ce()
    shutil.copyfile(BRIDGE, os.path.join(CE_DIR, 'autorun', 'ce_mcp_bridge.lua'))
    _prune_mailboxes()
    if not _ce.get('alive'):
        # held open (so undeletable) for the server's lifetime: the bridge closes CE once it can delete it,
        # which unlike the server's PID cannot be reused by another process
        _ce['alive'] = open(os.path.join(DIR, f'alive-{next(_seq)}'), 'w')
    env = dict(os.environ, __COMPAT_LAYER='RunAsInvoker', CE_MCP_PARENT=str(os.getpid()), CE_MCP_MAILBOX=DIR,
               CE_MCP_ALIVE=_ce['alive'].name)
    block = ''.join(f'{k}={v}\0' for k, v in sorted(env.items())) + '\0'
    if not _ce.get('desktop'):  # the handle stays open for the server's lifetime
        _ce['desktop'] = _u32.CreateDesktopW(DESKTOP, None, None, 0, 0x10000000, None)  # GENERIC_ALL
        if not _ce['desktop']:
            raise RuntimeError(f'CreateDesktop failed (error {ctypes.get_last_error()})')
    si = _SI(cb=ctypes.sizeof(_SI), lpDesktop=DESKTOP,
             dwFlags=1, wShowWindow=7)  # STARTF_USESHOWWINDOW, SW_SHOWMINNOACTIVE
    pi = _PI()
    cmdline = ctypes.create_unicode_buffer(f'"{CE_EXE}"')
    if not _k32.CreateProcessW(CE_EXE, cmdline, None, None, False, 0x400,  # CREATE_UNICODE_ENVIRONMENT
                               ctypes.create_unicode_buffer(block), CE_DIR, ctypes.byref(si), ctypes.byref(pi)):
        raise RuntimeError(f'starting Cheat Engine failed (error {ctypes.get_last_error()})')
    _ce['proc'] = _Proc(pi)
    with open(os.path.join(DIR, 'ce.pid'), 'w') as f:  # for _prune_mailboxes, should this CE outlive the server
        f.write(str(pi.dwProcessId))


def _remove(p):
    try:
        os.remove(p)
    except FileNotFoundError:
        pass


def _running():
    return bool(_ce['proc']) and _ce['proc'].poll() is None


def call(cmd, timeout=120.0, **kw):
    """Send one request to the bridge and return its text, raising on an error reply."""
    with _lock:
        return _call(cmd, timeout, kw)


def _call(cmd, timeout, kw, patience=10.0, launch=True):
    """`patience`: seconds a running CE gets to take the request before it counts as stuck.
    launch=False: never start CE (used by restart)."""
    os.makedirs(DIR, exist_ok=True)
    rid = str(next(_seq))
    lines = [f'cmd={cmd.encode().hex()}', f'id={rid.encode().hex()}']
    for k, v in kw.items():
        if v is None:
            continue
        b = v if isinstance(v, bytes) else (('1' if v else '0') if isinstance(v, bool) else str(v)).encode()
        lines.append(f'{k}={b.hex()}')
    _remove(RESP)
    _remove(REQ)
    tmp = REQ + '.tmp'
    with open(tmp, 'w', newline='\n') as f:
        f.write('\n'.join(lines) + '\n')
    os.replace(tmp, REQ)
    t0 = time.time()
    started = None   # when this call started CE
    while True:
        waited = time.time() - t0
        if os.path.exists(RESP):
            try:
                with open(RESP, 'rb') as f:
                    text = f.read().decode('utf-8', 'replace')
            except OSError:
                time.sleep(0.01)
                continue
            head, _, rest = text.partition('\n')
            fields = dict(f.split('=', 1) for f in head.split() if '=' in f)
            _remove(RESP)
            if fields.get('id') != rid:
                continue     # the late answer to an earlier request that timed out
            if fields.get('v') != str(BRIDGE_VERSION):
                raise RuntimeError(f'the bridge in that Cheat Engine is version {fields.get("v", "1")}, the server '
                                   f'needs {BRIDGE_VERSION}: copy {BRIDGE} into its autorun folder and restart it')
            status, _, body = rest.partition('\n')
            if status != 'ok':
                raise RuntimeError(body)
            return body
        if os.path.exists(REQ):
            stuck = None
            if SHARED:
                if waited > 1.5:
                    stuck = ('the Cheat Engine started by hand did not take the request: is it running with the '
                             'bridge on (ce-mcp menu)? Without %LOCALAPPDATA%\\ce-mcp\\enabled, ce-mcp starts its own')
            elif started is not None:
                if time.time() - started > 30:
                    stuck = f'Cheat Engine started but its bridge did not answer within 30s ({CE_EXE})'
            elif _running():
                if waited > patience:
                    stuck = (f'Cheat Engine (pid {_ce["proc"].pid}) is running but not answering: busy with an '
                             'earlier request, or stuck on a dialog on its hidden desktop. Retry, or restart()')
            elif not launch:
                stuck = 'Cheat Engine is not running'
            elif waited > 1.5:
                launch_ce()  # the request stays queued until the new CE's bridge picks it up
                started = time.time()
            if stuck:
                _remove(REQ)
                raise RuntimeError(stuck)
        elif not SHARED and _ce['proc'] and _ce['proc'].poll() is not None and not os.path.exists(RESP):
            code = _ce['proc'].poll()
            _ce['proc'] = None
            raise RuntimeError(f'Cheat Engine exited (code {code:#x}) while handling {cmd}; '
                               'the next call starts a new one (attach again)')
        if waited > timeout:
            _remove(REQ)
            raise RuntimeError(f'{cmd} timed out after {timeout:.0f}s')
        time.sleep(0.01)


def A(addr):
    """CE parses bare hex, so drop 0x prefixes (also inside expressions)."""
    return re.sub(r'\b0[xX]([0-9a-fA-F]+)', r'\1', str(addr).strip())


def _num(x, t):
    """Scan input for CE: decimal for integers (so 0x.. works), as-is for floats."""
    x = x.strip()
    if t in ('aob', 'str') or t.startswith('f'):
        return x
    return str(int(x, 0))


def _show(v, t):
    if t == 'ptr':
        return f'{v:#x}'
    if t.startswith('f'):
        return f'{v:.6g}'
    return f'{v} ({v & ((1 << (8 * struct.calcsize(FMT[t]))) - 1):#x})' if v < 0 or v > 9 else str(v)


mcp = FastMCP('ce-mcp', instructions=(
    'Drive a running Cheat Engine (scans, memory, hardware breakpoints, disassembly, auto assembler) '
    'through its Lua bridge. Attach first. Typical flow: scan -> scan_next until few results -> '
    'find_writers(addr) while the user triggers the change in game -> disasm around the instruction -> '
    'aa(name, script) to test a patch. For anything the tools do not cover, such as walking engine structures '
    'or many reads at once, lua(code) runs Lua with CE\'s whole API in one call.'))


@mcp.tool(structured_output=False)
def attach(process: str) -> str:
    """Open a process in Cheat Engine by name ("Game.exe") or PID."""
    out = call('attach', process=process)
    _ce['attached'] = int(out.split()[1])  # 'pid N name ...': restart() attaches it again
    return out


@mcp.tool(structured_output=False)
def status() -> str:
    """Attached process, debugger state, breakpoint count. Also tells whether the bridge is up."""
    return call('status', timeout=60)


@mcp.tool(structured_output=False)
def modules(filter: str = '') -> str:
    """List modules as `base size name` (substring filter)."""
    return call('modules', filter=filter)


@mcp.tool(structured_output=False)
def symbol(addr: str) -> str:
    """Resolve an address or expression to `hex (module+offset)`."""
    return call('symbol', addr=A(addr))


@mcp.tool(structured_output=False)
def read(addr: str, type: str = 'u32', count: int = 1) -> str:
    """Read `count` values of u8/s8/u16/s16/u32/s32/u64/s64/f32/f64/ptr, or 'str' (count = max length)
    or 'bytes' (count = length, hex)."""
    if type in ('str', 'bytes'):
        raw = bytes.fromhex(call('read', addr=A(addr), size=64 if type == 'str' and count == 1 else count))
        return raw.hex(' ') if type == 'bytes' else repr(raw.split(b'\0')[0].decode('latin-1'))
    f = FMT[type]
    n = struct.calcsize(f)
    raw = bytes.fromhex(call('read', addr=A(addr), size=n * count))
    vals = [struct.unpack_from(f, raw, i * n)[0] for i in range(count)]
    if count == 1:
        return _show(vals[0], type)
    return '\n'.join(f'+{i * n:#x}: {_show(v, type)}' for i, v in enumerate(vals))


@mcp.tool(structured_output=False)
def hexdump(addr: str, size: int = 0x100) -> str:
    """Hex + ASCII dump (max 0x1000 bytes)."""
    size = min(size, 0x1000)
    raw = bytes.fromhex(call('read', addr=A(addr), size=size))
    out = []
    for o in range(0, size, 16):
        c = raw[o:o + 16]
        out.append(f'+{o:04x}  {c.hex(" "):<47}  ' + ''.join(chr(b) if 32 <= b < 127 else '.' for b in c))
    return '\n'.join(out)


@mcp.tool(structured_output=False)
def write(addr: str, value: str, type: str = 'u32') -> str:
    """Write one value of `type` (as for read), or 'bytes' (hex string) / 'str'. Returns old -> new.
    Code pages may be read-only: patch code with aa() instead."""
    if type == 'bytes':
        data = bytes.fromhex(value.replace(' ', ''))
    elif type == 'str':
        data = value.encode('latin-1')
    else:
        f = FMT[type]
        v = float(value) if type.startswith('f') else int(value, 0)
        data = struct.pack(f, v)
    old = bytes.fromhex(call('write', addr=A(addr), data=data))
    if type in ('bytes', 'str'):
        return f'{old.hex(" ")} -> {data.hex(" ")}'
    return f'{_show(struct.unpack(FMT[type], old)[0], type)} -> {_show(struct.unpack(FMT[type], data)[0], type)}'


def _first(value):
    v = value.strip()
    if v in ('', '?'):
        return 'unknown', '', ''
    if '..' in v:
        lo, hi = v.split('..', 1)
        return 'between', lo, hi
    if v[0] in '<>':
        return ('bigger' if v[0] == '>' else 'smaller'), v[1:], ''
    return 'exact', v.lstrip('='), ''


@mcp.tool(structured_output=False)
def scan(value: str = '?', type: str = 'u32', module: str = '', start: str = '', end: str = '',
         writable_only: bool = True, show: int = 20) -> str:
    """First scan (replaces the previous scan). value: '5', '=5', '>5', '<5', '1..8', or '?' for an
    unknown initial value. type: u8/u16/u32/u64 (signed input is fine), f32/f64, str, aob ('8B ?? 05').
    Restrict to a module or a start/end range; writable_only=False also scans read-only memory."""
    opt, v1, v2 = _first(value)
    if opt != 'unknown':
        v1 = _num(v1, type)
        v2 = _num(v2, type) if v2 else ''
    out = call('scan', type=type, option=opt, v1=v1, v2=v2, module=module, start=A(start) if start else '',
               stop=A(end) if end else '', prot='+W*X*C' if writable_only else '*W*X*C',
               align=struct.calcsize(FMT[type]) if type in FMT else 1, show=show)
    _ce['scan_type'] = type
    return out


@mcp.tool(structured_output=False)
def scan_next(condition: str, show: int = 20) -> str:
    """Filter the current scan: '5' / '=5', '>5', '<5', '1..8', 'increased', 'decreased',
    'changed', 'unchanged', '+=N' (increased by N), '-=N' (decreased by N)."""
    c = condition.strip()
    if c in ('increased', 'decreased', 'changed', 'unchanged'):
        opt, v1, v2 = c, '', ''
    elif c.startswith('+='):
        opt, v1, v2 = 'increasedby', c[2:], ''
    elif c.startswith('-='):
        opt, v1, v2 = 'decreasedby', c[2:], ''
    else:
        opt, v1, v2 = _first(c)
        if opt == 'unknown':
            raise ValueError('empty condition')
    t = _ce.get('scan_type', 'u32')
    return call('next', option=opt, v1=_num(v1, t) if v1 else '', v2=_num(v2, t) if v2 else '', show=show)


@mcp.tool(structured_output=False)
def results(offset: int = 0, show: int = 50, aob: bool = False) -> str:
    """Page through the current scan results (or the last aob_scan results)."""
    return call('results', which='aob' if aob else 'main', offset=offset, show=show)


@mcp.tool(structured_output=False)
def aob_scan(pattern: str, module: str = '', show: int = 20) -> str:
    """Find a byte pattern ('48 8B ?? ?? 89') in all memory or one module. Does not touch the main scan."""
    return call('aob', pattern=pattern, module=module, show=show)


@mcp.tool(structured_output=False)
def bp_set(addr: str, kind: str = 'write', size: int = 4, debugger: int = 2, stack: bool = False,
           max_hits: int = 0, where: str = '', collect: str = '', capture: str = '', log: str = '') -> str:
    """Hardware breakpoint that logs and continues (max 4). kind: write / access (data, size 1/2/4/8)
    or execute (code). Hits are grouped by instruction with registers of the first and last hit.
    stack=True also logs the 6 qwords at RSP as module+offset where they point into code (callers; [RSP]
    is the return address only at a function's first instruction). max_hits > 0 stops the breakpoint
    after that many hits and keeps what it caught, for addresses hit every frame (each hit slows the
    game). debugger: 2 = VEH (default; the game survives CE closing), 1 = Windows, 0 = CE's setting.
    Only used when the debugger is not running yet.
    Operands below: a number, a register (RAX..R15, RIP) or memory [REG], [REG+0x10], [REG-8], [0x1234]
    with an optional :size in bytes (default 8, little-endian), all read at the moment of the hit.
    where: only count hits where all comparisons hold, e.g. 'RAX==0x35FC5F20 && [RBP+0x30]:4!=0'
    (==, !=, <, >, <=, >=; < and > unsigned). Skipped hits are counted apart and don't use up max_hits.
    collect: comma-separated operands whose distinct values are counted per instruction, e.g. 'RAX, [RSP]'.
    capture: comma-separated operands shown with the first and last hit; memory up to 256 bytes is dumped
    in hex, e.g. '[RBP+0x460], [RSI]:0x40'.
    log: comma-separated operands recorded as one row per hit, in hit order (up to 20000 rows), after the ms
    since the breakpoint was set, e.g. 'EAX, R14, [R14+0x30]' (log RSP to tell threads apart); bp_hits(log_file=...) writes them."""
    return call('bp_set', addr=A(addr), kind=kind, size=size, debugger=debugger, stack=stack, max_hits=max_hits,
                where=where, collect=collect, capture=capture, log=log)


@mcp.tool(structured_output=False)
def bp_hits(addr: str = '', clear: bool = False, log_file: str = '') -> str:
    """Show what the breakpoints caught so far (all, or one address). clear=True also removes them.
    log_file: write the rows of breakpoints set with log= there (tab-separated, header first; with several
    breakpoints, one file each: the address is added to the name); otherwise the first 20 rows are shown."""
    out = call('bp_hits', addr=A(addr) if addr else '', log_file=log_file)
    if clear:
        call('bp_clear', addr=A(addr) if addr else '')
    return out


@mcp.tool(structured_output=False)
def bp_clear(addr: str = '') -> str:
    """Remove ce-mcp breakpoints (all, or one address)."""
    return call('bp_clear', addr=A(addr) if addr else '')


@mcp.tool(structured_output=False)
def find_writers(addr: str, seconds: float = 10, size: int = 4, kind: str = 'write', stack: bool = False,
                 where: str = '', collect: str = '', capture: str = '') -> str:
    """'Find out what writes/accesses this address': breakpoint for `seconds` (the user triggers the
    change in game meanwhile), then report the instructions and remove the breakpoint. stack, where,
    collect and capture as in bp_set."""
    a = A(addr)
    call('bp_set', addr=a, kind=kind, size=size, debugger=2, stack=stack, where=where, collect=collect,
         capture=capture)
    try:
        time.sleep(seconds)
        return call('bp_hits', addr=a)
    finally:
        call('bp_clear', addr=a)


@mcp.tool(structured_output=False)
def disasm(addr: str, count: int = 12, before: int = 0) -> str:
    """Disassemble `count` instructions from addr, starting `before` instructions earlier (marked '>')."""
    return call('disasm', addr=A(addr), count=count, before=before)


@mcp.tool(structured_output=False)
def aa(name: str, script: str = '', enable: bool = True) -> str:
    """Auto assembler. enable=True runs `script` (its [ENABLE] part if it has sections) and remembers it
    under `name`; without a script it re-enables the last one given for `name`. enable=False runs the
    [DISABLE] part of the remembered script. Patches stay in the target when CE closes. {$lua} is refused."""
    return call('aa', name=name, script=script if enable else '', enable=enable)


@mcp.tool(structured_output=False)
def lua(code: str, timeout: float = 10) -> str:
    """Run Lua in Cheat Engine with its whole API (readQword, readString, getAddress, disassemble,
    AOBScan, ...): returns what the code printed, then its return values (tostring'd, max 20000 chars).
    Use it to walk structures or batch reads in one call. Only in the CE that ce-mcp starts (not
    elevated). Lua loops stop after `timeout` seconds; a blocking CE call does not (use restart())."""
    if SHARED:
        raise RuntimeError('lua() only runs in the Cheat Engine that ce-mcp starts, not in one started by hand')
    return call('lua', timeout=timeout + 30, code=code, limit=timeout)


@mcp.tool(structured_output=False)
def restart() -> str:
    """Kill the Cheat Engine that ce-mcp started (when it stops answering) and start a fresh one, attached
    to the same process if it is still running. Its breakpoints are removed first if it still answers;
    scans, aa scripts and Lua globals do not carry over."""
    if SHARED:
        raise RuntimeError('ce-mcp uses a Cheat Engine started by hand (the enabled file): restart that one')
    with _lock:
        if _running():
            try:
                _call('bp_clear', 5, {}, patience=2, launch=False)
            except RuntimeError:
                pass
            _ce['proc'].kill()
        _ce['proc'] = None
        _remove(REQ)
        _remove(RESP)
        out = _call('status', 60, {})
        pid = _ce.get('attached')
        if pid and _alive(pid):
            out = _call('attach', 60, {'process': str(pid)})
        return out


if __name__ == '__main__':
    mcp.run()
