# SPDX-License-Identifier: GPL-3.0-or-later
"""ce-mcp tests. `python tests/run.py` starts real CEs (Cheat Engine must be installed) against tests/target.py;
`--offline` runs only the mailbox checks against a fake bridge. Each run is its own server, with its own mailbox."""
import ctypes, ctypes.wintypes as wt, os, subprocess, sys, tempfile, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import ce_mcp as c  # noqa: E402

passed, failed = [], []
NL = '\n'


def check(name, fn, expect):
    try:
        out = str(fn())
    except Exception as e:
        out = f'ERROR {e}'
    ok = bool(expect(out))
    (passed if ok else failed).append(name)
    print(f'{"PASS" if ok else "FAIL"} {name}' + ('' if ok else f'\n     {out[:400]}'))
    return out


def start_target(seconds=120):
    t = subprocess.Popen([sys.executable, '-u', os.path.join(HERE, 'target.py'), str(seconds)],
                         stdout=subprocess.PIPE, text=True)
    return t, t.stdout.readline().strip()


# ---------------------------------------------------------------- fake bridge (no CE)

def offline():
    saved = (c.DIR, c.REQ, c.RESP, c.SHARED, c._ce['proc'])
    tmp = tempfile.mkdtemp()
    c.DIR, c.REQ, c.RESP = tmp, os.path.join(tmp, 'req'), os.path.join(tmp, 'resp')

    def fake(replies):
        """Answer the next request with each (header, body); '{id}' is the request's id."""
        def run():
            while not os.path.exists(c.REQ):
                time.sleep(0.005)
            text = open(c.REQ).read()
            os.remove(c.REQ)
            rid = bytes.fromhex(dict(l.split('=') for l in text.split())['id']).decode()
            for head, body in replies:
                with open(c.RESP + '.tmp', 'w', newline='\n') as f:
                    f.write(head.format(id=rid) + '\nok\n' + body)
                while os.path.exists(c.RESP):
                    time.sleep(0.005)
                os.replace(c.RESP + '.tmp', c.RESP)
        threading.Thread(target=run, daemon=True).start()

    v = c.BRIDGE_VERSION
    import asyncio
    check('tools answer in plain text (no JSON wrapping)',
          lambda: [t.name for t in asyncio.run(c.mcp.list_tools()) if t.outputSchema],
          lambda o: o == '[]')
    try:
        fake([(f'id=1 v={v}', 'stale'), (f'id={{id}} v={v}', 'fresh')])
        check('stale reply is skipped', lambda: c.call('status'), lambda o: o == 'fresh')
        fake([('id={id}', 'old bridge')])
        check('mismatched bridge is refused', lambda: c.call('status'), lambda o: 'version 1' in o)

        class Running:
            pid = 4242
            def poll(self): return None
        c._ce['proc'] = Running()
        check('running CE that never answers', lambda: c._call('status', 30, {}, patience=1),
              lambda o: 'running but not answering' in o)

        class DiesOnRequest:
            pid = 4242
            def poll(self): return None if os.path.exists(c.REQ) else 0xC0000005
        def take():
            while not os.path.exists(c.REQ):
                time.sleep(0.005)
            time.sleep(0.2)
            os.remove(c.REQ)
        c._ce['proc'] = DiesOnRequest()
        threading.Thread(target=take, daemon=True).start()
        t0 = time.time()
        check('CE dying mid-request fails fast', lambda: c.call('status'),
              lambda o: 'exited (code 0xc0000005)' in o and time.time() - t0 < 5 and c._ce['proc'] is None)
        c._ce['proc'], c.SHARED = None, True
        check('shared mode never launches CE', lambda: c.call('status'),
              lambda o: 'started by hand' in o and c._ce['proc'] is None)
        check('lua refused in shared mode', lambda: c.lua('return 1'), lambda o: 'started by hand' in o)
    finally:
        c.DIR, c.REQ, c.RESP, c.SHARED, c._ce['proc'] = saved


# ---------------------------------------------------------------- real CE

_u32 = ctypes.WinDLL('user32')
_u32.GetForegroundWindow.restype = wt.HWND
_u32.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
_EnumProc = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)


def windows_of(pid):
    """Top-level windows of `pid` on this (the user's) desktop."""
    found = []
    def cb(h, _):
        p = wt.DWORD()
        _u32.GetWindowThreadProcessId(h, ctypes.byref(p))
        if p.value == pid:
            found.append(h)
        return True
    _u32.EnumWindows(_EnumProc(cb), 0)
    return found


def launch_watched():
    """First call (launches CE) while watching the user's desktop: no CE window, no focus change."""
    fg = _u32.GetForegroundWindow()
    seen, stole, done = set(), [], threading.Event()
    def watch():
        while not done.is_set():
            if c._ce['proc']:
                seen.update(windows_of(c._ce['proc'].pid))
            if _u32.GetForegroundWindow() != fg:
                stole.append(_u32.GetForegroundWindow())
            time.sleep(0.005)
    w = threading.Thread(target=watch)
    w.start()
    try:
        out = c.status()
        time.sleep(1.5)  # CE finishes building its main window after the bridge answers
    finally:
        done.set()
        w.join()
    return f'{out} | windows on user desktop: {len(seen)} | focus changes: {len(stole)}'


def online():
    tgt, addr = start_target()
    base = int(addr, 16)
    try:
        check('launch is headless (no window, no focus change)', launch_watched,
              lambda o: o.endswith('windows on user desktop: 0 | focus changes: 0'))
        check('attach', lambda: c.attach(str(tgt.pid)), lambda o: f'pid {tgt.pid}' in o)
        other, oaddr = start_target()
        check('attach a second process', lambda: c.attach(str(other.pid)), lambda o: f'pid {other.pid}' in o)
        other.kill()
        other.wait()
        time.sleep(1.2)
        check('exited process is reported', lambda: c.read(oaddr), lambda o: 'has exited' in o)
        check('status says it exited', c.status, lambda o: 'has exited' in o)
        check('attach back', lambda: c.attach(str(tgt.pid)), lambda o: f'pid {tgt.pid}' in o)
        v = int(check('read u32', lambda: c.read(addr), lambda o: o.split()[0].isdigit()).split()[0])
        check('read bytes count=1', lambda: c.read(addr, 'bytes', 1), lambda o: len(o) == 2)
        check('read bytes count=3', lambda: c.read(addr, 'bytes', 3), lambda o: len(o.split()) == 3)
        check('scan exact', lambda: c.scan(str(v), 'u32', show=50), lambda o: addr[2:].upper() in o.upper())
        time.sleep(2.2)
        check('scan_next increased', lambda: c.scan_next('increased', show=50), lambda o: addr[2:].upper() in o.upper())
        check('scan_next hex input', lambda: c.scan_next('>0x10', show=50), lambda o: addr[2:].upper() in o.upper())
        check('write', lambda: c.write(addr, '5000000'), lambda o: o.endswith('-> 5000000 (0x4c4b40)'))
        check('find_writers', lambda: c.find_writers(addr, 2.5), lambda o: 'hit(s), 1 instruction' in o)
        check('aob_scan in a module', lambda: c.aob_scan('4D 5A 90 00', 'python.exe', show=3), lambda o: 'count=1' in o)

        script = ('[ENABLE]\nalloc(cemcpt,64)\nregistersymbol(cemcpt)\ncemcpt:\ndb 11 22 C3\n'
                  '[DISABLE]\nunregistersymbol(cemcpt)\ndealloc(cemcpt)\n')
        check('aa with no script yet', lambda: c.aa('t'), lambda o: 'no script given' in o)
        check('aa enable', lambda: c.aa('t', script), lambda o: o == 'enabled t')
        check('disasm', lambda: c.disasm('cemcpt', 3), lambda o: o.startswith('>'))
        check('aa disable', lambda: c.aa('t', enable=False), lambda o: o == 'disabled t')
        check('aa re-enable reuses the script', lambda: (c.aa('t'), c.read('cemcpt', 'bytes', 2))[1],
              lambda o: o == '11 22')
        check('aa disable again', lambda: c.aa('t', enable=False), lambda o: o == 'disabled t')
        check('aa refuses Lua', lambda: c.aa('bad', '{$lua}\nprint(1)\n{$asm}\n'), lambda o: 'not allowed' in o)

        check('lua return value', lambda: c.lua('return 1 + 1'), lambda o: o == '2')
        check('lua print then return', lambda: c.lua('print("a") print("b", 2) return 3'),
              lambda o: o == 'a\nb\t2\n3')
        check('lua reads the target', lambda: c.lua(f'return readInteger({addr})'),
              lambda o: o.isdigit() and abs(int(o) - int(c.read(addr).split()[0])) <= 1)  # it ticks every second
        check('lua error', lambda: c.lua('print("before") error("boom")'),
              lambda o: 'before' in o and 'boom' in o)
        check('lua loop stops at the timeout', lambda: c.lua('while true do end', timeout=1),
              lambda o: 'timed out' in o)
        check('CE fine after the timeout, print restored', lambda: c.lua('print("x")'), lambda o: o == 'x')

        check('bp with stack', lambda: (c.bp_set(addr, stack=True), time.sleep(2.5), c.bp_hits(addr, clear=True))[2],
              lambda o: 'stack: ' in o and '+' in o.split('stack: ')[1].split('\n')[0])
        check('bp max_hits', lambda: (c.bp_set(addr, max_hits=2), time.sleep(4), c.bp_hits(addr))[2],
              lambda o: ' 2 hit(s)' in o and 'stopped at max_hits' in o)
        check('stopped bp frees its slot', lambda: [c.bp_set(hex(base + 8 + 8 * i)) for i in range(4)][-1],
              lambda o: 'breakpoint on' in o)
        check('status counts the stopped bp apart', c.status, lambda o: '4 breakpoint(s) (+1 stopped' in o)
        check('bp_clear (stopped one included)', c.bp_clear, lambda o: 'removed 5' in o)

        check('bp where that never holds', lambda: (c.bp_set(addr, where='RIP==0'), time.sleep(2.5),
                                                     c.bp_hits(addr, clear=True))[2],
              lambda o: ' 0 hit(s)' in o and 'skipped by where' in o)
        check('bp where on memory', lambda: (c.bp_set(addr, where=f'[{addr}]:4 != 0 and RIP != 0', max_hits=2),
                                              time.sleep(3.5), c.bp_hits(addr, clear=True))[2],
              lambda o: ' 2 hit(s)' in o and 'skipped' not in o)
        check('bp collect counts distinct values', lambda: (c.bp_set(addr, collect=f'[{addr}]:4'), time.sleep(3.5),
                                                             c.bp_hits(addr, clear=True))[2],
              lambda o: o.split(f'[{addr}]:4: ')[1].split(NL)[0].count(' x1') >= 2)
        check('bp capture dumps memory', lambda: (c.bp_set(addr, capture=f'[{addr}]:4, [{addr}]:16'),
                                                   time.sleep(2.5), c.bp_hits(addr, clear=True))[2],
              lambda o: 'capture: ' in o and len(o.split('capture: ')[1].split(NL)[0].split('=')[-1].split()) == 16)
        log_file = os.path.join(tempfile.gettempdir(), 'ce_mcp_log.tsv')
        check('bp log records rows in order', lambda: (c.bp_set(addr, log=f'RIP, [{addr}]:4'), time.sleep(3.5),
                                                       c.bp_hits(addr, clear=True, log_file=log_file))[2],
              lambda o: 'written to' in o and open(log_file).read().count(NL) >= 3
              and open(log_file).readline().startswith('ms\tRIP'))
        check('bp bad operand is refused', lambda: c.bp_set(addr, where='RAX=1'), lambda o: 'bad condition' in o)
        check('bp bad size is refused', lambda: c.bp_set(addr, collect='[RAX]:16'), lambda o: 'bad size' in o)
        check('no bp left after refusals', c.bp_clear, lambda o: 'removed 0' in o)

        for i in range(4):
            check(f'bp {i + 1} of 4', lambda i=i: c.bp_set(hex(base + 8 * i)), lambda o: 'breakpoint on' in o)
        check('5th bp is refused', lambda: c.bp_set(hex(base + 64)), lambda o: 'all 4' in o)
        check('bp_clear', c.bp_clear, lambda o: 'removed 4' in o)

        errors = []
        def reader():
            for _ in range(30):
                try:
                    c.read(addr)
                except Exception as e:
                    errors.append(e)
        ts = [threading.Thread(target=reader) for _ in range(3)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        check('parallel calls (3 threads x 30 reads)', lambda: f'{90 - len(errors)}/90', lambda o: o == '90/90')

        old = c._ce['proc'].pid
        out = []
        check('restart gives a new CE', lambda: (out.append(c.restart()), c._ce['proc'].pid)[1],
              lambda o: o != str(old))
        check('restart attaches the same process again', lambda: out[0], lambda o: f'pid {tgt.pid}' in o)
        check('works after restart', lambda: c.read(addr), lambda o: o.split()[0].isdigit())
    finally:
        tgt.kill()


def two_servers():
    """Two servers at once, each with its own mailbox and CE, each reading its own target."""
    kids = [subprocess.Popen([sys.executable, __file__, '--child', str(tag)], stdout=subprocess.PIPE, text=True)
            for tag in (111111, 222222)]
    outs = [k.communicate(timeout=120)[0].strip() for k in kids]
    check('two servers at once', lambda: ' / '.join(outs), lambda o: o.count('40/40') == 2)

    def closed():
        ces = [int(o.split('ce=')[1]) for o in outs if 'ce=' in o]
        end = time.time() + 10  # the watchdog checks every 3s
        while time.time() < end and any(map(c._alive, ces)):
            time.sleep(0.2)
        return f'{len(ces)} CE(s), {sum(map(c._alive, ces))} still running'
    check('each CE closes after its server exits', closed, lambda o: o == '2 CE(s), 0 still running')


def orphan():
    """A server exits while its CE is blocked in a long call: the watchdog cannot run, so the next launch's
    cleanup kills that CE."""
    kid = subprocess.Popen([sys.executable, __file__, '--hang'], stdout=subprocess.PIPE, text=True)
    ce = int(kid.communicate(timeout=60)[0].split('ce=')[1])
    time.sleep(6)  # two watchdog periods
    check('a blocked CE outlives its server', lambda: c._alive(ce), lambda o: o == 'True')
    c._prune_mailboxes()
    check('the next launch kills it', lambda: c._alive(ce), lambda o: o == 'False')


def hang():
    c.status()
    threading.Thread(target=lambda: c.lua('sleep(600000)', timeout=1), daemon=True).start()
    time.sleep(2)
    print(f'ce={c._ce["proc"].pid}', flush=True)
    os._exit(0)


def child(tag):
    t = subprocess.Popen([sys.executable, '-u', '-c', f'import ctypes, time\nv = ctypes.c_uint32({tag})\n'
                          'print(hex(ctypes.addressof(v)), flush=True)\ntime.sleep(60)'], stdout=subprocess.PIPE, text=True)
    a = t.stdout.readline().strip()
    try:
        c.attach(str(t.pid))
        good = sum(c.read(a).split()[0] == str(tag) for _ in range(40))
        print(f'{good}/40 ce={c._ce["proc"].pid}')
    finally:
        t.kill()


if __name__ == '__main__':
    if sys.argv[1:2] == ['--child']:
        child(int(sys.argv[2]))
        sys.exit()
    if sys.argv[1:2] == ['--hang']:
        hang()
    offline()
    if '--offline' not in sys.argv:
        online()
        two_servers()
        orphan()
    print(f'\n{len(passed)} passed, {len(failed)} failed' + (f': {", ".join(failed)}' if failed else ''))
    sys.exit(1 if failed else 0)
