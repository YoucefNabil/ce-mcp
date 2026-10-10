# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Youcef Nabil
"""ce-mcp: MCP server that drives Cheat Engine through ce_mcp_bridge.lua.

When the bridge does not answer, the server starts its private CE copy (ce\\) hidden and non-elevated,
with the bridge synced into its autorun folder; that CE closes when this server exits. The copy is made
on first use from an installed Cheat Engine (or CE_MCP_SOURCE, a CE folder). Requests go
through a file mailbox in %LOCALAPPDATA%\\ce-mcp that the bridge polls. Addresses are anything Cheat
Engine resolves: hex (0x optional), "Game.exe+1234", symbols, or pointer expressions like
"[[Game.exe+10]+8]". Values are little-endian. Output is kept short on purpose.
"""
import glob, os, re, shutil, struct, subprocess, time
from mcp.server.fastmcp import FastMCP

HERE = os.path.dirname(os.path.abspath(__file__))
CE_DIR = os.path.join(HERE, 'ce')
CE_EXE = os.path.join(CE_DIR, 'cheatengine-x86_64.exe')
BRIDGE = os.path.join(HERE, 'ce_mcp_bridge.lua')
DIR = os.path.join(os.environ['LOCALAPPDATA'], 'ce-mcp')
REQ, RESP = os.path.join(DIR, 'req'), os.path.join(DIR, 'resp')
FMT = {'u8': '<B', 's8': '<b', 'u16': '<H', 's16': '<h', 'u32': '<I', 's32': '<i',
       'u64': '<Q', 's64': '<q', 'f32': '<f', 'f64': '<d', 'ptr': '<Q'}
_seq = [int(time.time() * 1000) % 1_000_000_000]
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


def launch_ce():
    """Start the private CE copy hidden, without UAC (RunAsInvoker), tied to this server's lifetime."""
    if _ce['proc'] and _ce['proc'].poll() is None:
        return
    if not os.path.exists(CE_EXE):
        provision_ce()
    shutil.copyfile(BRIDGE, os.path.join(CE_DIR, 'autorun', 'ce_mcp_bridge.lua'))
    env = dict(os.environ, __COMPAT_LAYER='RunAsInvoker', CE_MCP_PARENT=str(os.getpid()))
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 7  # SW_SHOWMINNOACTIVE: don't take focus from the game
    _ce['proc'] = subprocess.Popen([CE_EXE], cwd=os.path.dirname(CE_EXE), env=env, startupinfo=si)


def call(cmd, timeout=120.0, **kw):
    """Send one request to the bridge and return its text, raising on an error reply."""
    os.makedirs(DIR, exist_ok=True)
    _seq[0] += 1
    rid = str(_seq[0])
    lines = [f'cmd={cmd.encode().hex()}', f'id={rid.encode().hex()}']
    for k, v in kw.items():
        if v is None:
            continue
        b = v if isinstance(v, bytes) else (('1' if v else '0') if isinstance(v, bool) else str(v)).encode()
        lines.append(f'{k}={b.hex()}')
    for p in (RESP, REQ):
        if os.path.exists(p):
            os.remove(p)
    tmp = REQ + '.tmp'
    with open(tmp, 'w', newline='\n') as f:
        f.write('\n'.join(lines) + '\n')
    os.replace(tmp, REQ)
    t0 = time.time()
    pickup = 1.5     # seconds the bridge gets to take the request before CE is started
    while True:
        if os.path.exists(RESP):
            try:
                with open(RESP, 'rb') as f:
                    text = f.read().decode('utf-8', 'replace')
            except OSError:
                time.sleep(0.01)
                continue
            head, _, rest = text.partition('\n')
            if head == f'id={rid}':
                os.remove(RESP)
                status, _, body = rest.partition('\n')
                if status != 'ok':
                    raise RuntimeError(body)
                return body
        elif os.path.exists(REQ) and time.time() - t0 > pickup:
            if pickup < 30:
                launch_ce()          # the request stays queued until the new CE's bridge picks it up
                pickup = 30
            else:
                os.remove(REQ)
                raise RuntimeError(f'Cheat Engine bridge did not start within 30s ({CE_EXE})')
        if time.time() - t0 > timeout:
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
    'aa(name, script) to test a patch.'))


@mcp.tool()
def attach(process: str) -> str:
    """Open a process in Cheat Engine by name ("Game.exe") or PID."""
    return call('attach', process=process)


@mcp.tool()
def status() -> str:
    """Attached process, debugger state, breakpoint count. Also tells whether the bridge is up."""
    return call('status', timeout=60)


@mcp.tool()
def modules(filter: str = '') -> str:
    """List modules as `base size name` (substring filter)."""
    return call('modules', filter=filter)


@mcp.tool()
def symbol(addr: str) -> str:
    """Resolve an address or expression to `hex (module+offset)`."""
    return call('symbol', addr=A(addr))


@mcp.tool()
def read(addr: str, type: str = 'u32', count: int = 1) -> str:
    """Read `count` values of u8/s8/u16/s16/u32/s32/u64/s64/f32/f64/ptr, or 'str' (count = max length)
    or 'bytes' (count = length, hex)."""
    if type in ('str', 'bytes'):
        raw = bytes.fromhex(call('read', addr=A(addr), size=count if count > 1 else 64))
        return raw.hex(' ') if type == 'bytes' else repr(raw.split(b'\0')[0].decode('latin-1'))
    f = FMT[type]
    n = struct.calcsize(f)
    raw = bytes.fromhex(call('read', addr=A(addr), size=n * count))
    vals = [struct.unpack_from(f, raw, i * n)[0] for i in range(count)]
    if count == 1:
        return _show(vals[0], type)
    return '\n'.join(f'+{i * n:#x}: {_show(v, type)}' for i, v in enumerate(vals))


@mcp.tool()
def hexdump(addr: str, size: int = 0x100) -> str:
    """Hex + ASCII dump (max 0x1000 bytes)."""
    size = min(size, 0x1000)
    raw = bytes.fromhex(call('read', addr=A(addr), size=size))
    out = []
    for o in range(0, size, 16):
        c = raw[o:o + 16]
        out.append(f'+{o:04x}  {c.hex(" "):<47}  ' + ''.join(chr(b) if 32 <= b < 127 else '.' for b in c))
    return '\n'.join(out)


@mcp.tool()
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


@mcp.tool()
def scan(value: str = '?', type: str = 'u32', module: str = '', start: str = '', end: str = '',
         writable_only: bool = True, show: int = 20) -> str:
    """First scan (replaces the previous scan). value: '5', '=5', '>5', '<5', '1..8', or '?' for an
    unknown initial value. type: u8/u16/u32/u64 (signed input is fine), f32/f64, str, aob ('8B ?? 05').
    Restrict to a module or a start/end range; writable_only=False also scans read-only memory."""
    opt, v1, v2 = _first(value)
    if opt != 'unknown':
        v1 = _num(v1, type)
        v2 = _num(v2, type) if v2 else ''
    return call('scan', type=type, option=opt, v1=v1, v2=v2, module=module, start=A(start) if start else '',
                stop=A(end) if end else '', prot='+W*X*C' if writable_only else '*W*X*C',
                align=struct.calcsize(FMT[type]) if type in FMT else 1, show=show)


@mcp.tool()
def scan_next(condition: str, show: int = 20) -> str:
    """Filter the current scan: '5' / '=5', '>5', '<5', '1..8', 'increased', 'decreased',
    'changed', 'unchanged', '+=N' (increased by N), '-=N' (decreased by N)."""
    c = condition.strip()
    words = {'increased': 'increased', 'decreased': 'decreased', 'changed': 'changed', 'unchanged': 'unchanged'}
    if c in words:
        opt, v1, v2 = words[c], '', ''
    elif c.startswith('+='):
        opt, v1, v2 = 'increasedby', c[2:], ''
    elif c.startswith('-='):
        opt, v1, v2 = 'decreasedby', c[2:], ''
    else:
        opt, v1, v2 = _first(c)
        if opt == 'unknown':
            raise ValueError('empty condition')
    conv = lambda x: str(int(x, 0)) if re.fullmatch(r'-?(0x[0-9a-fA-F]+|\d+)', x.strip()) else x.strip()
    return call('next', option=opt, v1=conv(v1) if v1 else '', v2=conv(v2) if v2 else '', show=show)


@mcp.tool()
def results(offset: int = 0, show: int = 50, aob: bool = False) -> str:
    """Page through the current scan results (or the last aob_scan results)."""
    return call('results', which='aob' if aob else 'main', offset=offset, show=show)


@mcp.tool()
def aob_scan(pattern: str, module: str = '', show: int = 20) -> str:
    """Find a byte pattern ('48 8B ?? ?? 89') in all memory or one module. Does not touch the main scan."""
    return call('aob', pattern=pattern, module=module, show=show)


@mcp.tool()
def bp_set(addr: str, kind: str = 'write', size: int = 4, debugger: int = 2) -> str:
    """Hardware breakpoint that logs and continues (max 4). kind: write / access (data, size 1/2/4/8)
    or execute (code). Hits are grouped by instruction with registers of the first and last hit.
    debugger: 2 = VEH (default; the game survives CE closing), 1 = Windows, 0 = CE's setting.
    Only used when the debugger is not running yet."""
    return call('bp_set', addr=A(addr), kind=kind, size=size, debugger=debugger)


@mcp.tool()
def bp_hits(addr: str = '', clear: bool = False) -> str:
    """Show what the breakpoints caught so far (all, or one address). clear=True also removes them."""
    out = call('bp_hits', addr=A(addr) if addr else '')
    if clear:
        call('bp_clear', addr=A(addr) if addr else '')
    return out


@mcp.tool()
def bp_clear(addr: str = '') -> str:
    """Remove ce-mcp breakpoints (all, or one address)."""
    return call('bp_clear', addr=A(addr) if addr else '')


@mcp.tool()
def find_writers(addr: str, seconds: float = 10, size: int = 4, kind: str = 'write') -> str:
    """'Find out what writes/accesses this address': breakpoint for `seconds` (the user triggers the
    change in game meanwhile), then report the instructions and remove the breakpoint."""
    a = A(addr)
    call('bp_set', addr=a, kind=kind, size=size, debugger=2)
    try:
        time.sleep(seconds)
        return call('bp_hits', addr=a)
    finally:
        call('bp_clear', addr=a)


@mcp.tool()
def disasm(addr: str, count: int = 12, before: int = 0) -> str:
    """Disassemble `count` instructions from addr, starting `before` instructions earlier (marked '>')."""
    return call('disasm', addr=A(addr), count=count, before=before)


@mcp.tool()
def aa(name: str, script: str = '', enable: bool = True) -> str:
    """Auto assembler. enable=True runs `script` (its [ENABLE] part if it has sections) and remembers it
    under `name`; enable=False runs the [DISABLE] part of the remembered script. {$lua} is refused."""
    return call('aa', name=name, script=script if enable else '', enable=enable)


@mcp.tool()
def window(show: bool = True) -> str:
    """Show or hide the Cheat Engine window (it starts hidden when the server launched it)."""
    return call('window', show=show)


if __name__ == '__main__':
    mcp.run()
