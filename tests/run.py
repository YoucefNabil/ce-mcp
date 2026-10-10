# SPDX-License-Identifier: GPL-3.0-or-later
"""ce-mcp tests. `python tests/run.py` starts real CEs (Cheat Engine must be installed) against tests/target.py;
`--offline` runs only the mailbox checks against a fake bridge. Each run is its own server, with its own mailbox."""
import ctypes, ctypes.wintypes as wt, os, subprocess, sys, tempfile, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import ce_mcp as c  # noqa: E402

passed, failed = [], []


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
        c._ce['proc'], c.SHARED = None, True
        check('shared mode never launches CE', lambda: c.call('status'),
              lambda o: 'started by hand' in o and c._ce['proc'] is None)
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
        check('restart gives a new CE', lambda: (c.restart(), c._ce['proc'].pid)[1], lambda o: o != str(old))
        check('works after restart', lambda: c.attach(str(tgt.pid)), lambda o: f'pid {tgt.pid}' in o)
    finally:
        tgt.kill()


def two_servers():
    """Two servers at once, each with its own mailbox and CE, each reading its own target."""
    kids = [subprocess.Popen([sys.executable, __file__, '--child', str(tag)], stdout=subprocess.PIPE, text=True)
            for tag in (111111, 222222)]
    outs = [k.communicate(timeout=120)[0].strip() for k in kids]
    check('two servers at once', lambda: ' / '.join(outs), lambda o: o.count('40/40') == 2)


def child(tag):
    t = subprocess.Popen([sys.executable, '-u', '-c', f'import ctypes, time\nv = ctypes.c_uint32({tag})\n'
                          'print(hex(ctypes.addressof(v)), flush=True)\ntime.sleep(60)'], stdout=subprocess.PIPE, text=True)
    a = t.stdout.readline().strip()
    try:
        c.attach(str(t.pid))
        good = sum(c.read(a).split()[0] == str(tag) for _ in range(40))
        print(f'{good}/40')
    finally:
        t.kill()


if __name__ == '__main__':
    if sys.argv[1:2] == ['--child']:
        child(int(sys.argv[2]))
        sys.exit()
    offline()
    if '--offline' not in sys.argv:
        online()
        two_servers()
    print(f'\n{len(passed)} passed, {len(failed)} failed' + (f': {", ".join(failed)}' if failed else ''))
    sys.exit(1 if failed else 0)
