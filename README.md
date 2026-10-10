# ce-mcp

An [MCP](https://modelcontextprotocol.io) server that drives a running **Cheat Engine 7.5** through a small Lua bridge,
so an assistant such as Claude Code can scan memory, set logging hardware breakpoints ("find out what writes this
address"), disassemble and test auto assembler patches with short tool calls.

## How it works

`ce/` is a private copy of Cheat Engine, made on first use from an installed Cheat Engine (`Program Files\Cheat
Engine*`, or the folder in `CE_MCP_SOURCE`); it is not part of this repo. When a tool call finds no bridge answering,
the server copies `ce_mcp_bridge.lua` into `ce/autorun/` and starts `ce/cheatengine-x86_64.exe` **non-elevated**
(`__COMPAT_LAYER=RunAsInvoker`, so no UAC prompt) on a **Windows desktop of its own** (`CreateDesktop`), so its splash
screen and windows never appear on yours, with `CE_MCP_PARENT` set to its own PID. The bridge enables itself and
closes CE (after removing its breakpoints) when the server process is gone. Nothing to start by hand, nothing on
screen, and the focus never moves.

Requests go through a file mailbox in `%LOCALAPPDATA%\ce-mcp` (`req` / `resp`, written via rename), which also works
with an elevated CE started by hand (an elevated process's named pipe would be read-only for the server). For that
case copy the bridge into that CE's `autorun` folder; it polls only if `%LOCALAPPDATA%\ce-mcp\enabled` exists, and the
**ce-mcp** main-menu entry toggles it.

Each server has its own mailbox (`%LOCALAPPDATA%\ce-mcp\<server pid>`) and its own CE, so several sessions can run
at once; mailboxes of servers that are gone are removed at the next launch. With the `enabled` file present, servers
use the shared mailbox of the hand-started CE instead, and never start a CE of their own.

Requests are answered one at a time. The bridge tags each reply with its protocol version, and the server refuses a
bridge that does not match (a hand-started CE with an old copy of the bridge). If the launched CE stops answering,
for example because a dialog opened on its hidden desktop, calls fail with a message saying so and `restart()`
replaces it. If it exits mid-request, that call fails at once and the next one starts a new CE.

## Install

1. Install [Cheat Engine](https://www.cheatengine.org) 7.5 (tested), or point `CE_MCP_SOURCE` at a CE folder.
2. `pip install mcp`
3. `claude mcp add --scope user ce-mcp -- <python.exe> <path>/ce-mcp/ce_mcp.py`
4. The target must not run elevated (the launched CE is not).

Windows only, 64-bit targets.

Breakpoints default to CE's VEH debugger, so the target keeps running when CE closes.

## Tools

Addresses are whatever CE resolves: hex (`0x` optional), `Game.exe+1234`, symbols, `[[Game.exe+10]+8]`.

| Tool | What it does |
|---|---|
| `attach(process)` / `status()` | Open a process by name or PID / show process, debugger and bridge state. |
| `modules(filter)` / `symbol(addr)` | Module list (`base size name`) / address to `module+offset`. |
| `read(addr, type, count)` / `write(addr, value, type)` | `u8..u64`, `s8..s64`, `f32`, `f64`, `ptr`, `str`, `bytes`. Write returns old -> new. |
| `hexdump(addr, size)` | Hex + ASCII. |
| `scan(value, type)` | First scan: `5`, `>5`, `<5`, `1..8`, `?` (unknown). Types as above plus `aob`. Optional `module` / range. |
| `scan_next(condition)` | `5`, `>5`, `<5`, `1..8`, `increased`, `decreased`, `changed`, `unchanged`, `+=N`, `-=N`. |
| `results(offset, show)` | Page through results. |
| `aob_scan(pattern, module)` | Byte pattern search, separate from the main scan. |
| `bp_set(addr, kind, size, stack, max_hits)` / `bp_hits` / `bp_clear` | Logging hardware breakpoints (write / access / execute, max 4). Hits grouped by instruction with registers of first and last hit and the value after a write. `stack=True` adds the qwords at RSP (callers, as `module+offset`); `max_hits` stops a breakpoint on a hot address and keeps its hits. |
| `find_writers(addr, seconds, stack)` | bp_set + wait + report + clear: CE's "find out what writes this address". |
| `lua(code, timeout)` | Lua with CE's whole API, one call: walk structures, batch reads, anything the tools don't cover. Returns what it printed and returned. Only in the CE ce-mcp starts. |
| `disasm(addr, count, before)` | Disassembly with `module+offset` names. |
| `aa(name, script, enable)` | Run an auto assembler script ([ENABLE] part), and later its [DISABLE] part. Enabling again without a script reuses the last one. Patches stay in the target when CE closes. |
| `restart()` | Replace a launched CE that stopped answering and attach the same process again (its breakpoints are removed first if it still can). |

## Tests

`python tests/run.py` needs Cheat Engine installed (it starts real CEs on the hidden desktop against a small test
target); `python tests/run.py --offline` runs only the mailbox checks against a fake bridge.

## Safety

The launched CE runs non-elevated with the same rights as the server, so the mailbox gives no process more than it
already has; that is why `lua()` is allowed there and refused in a CE started by hand.

An **elevated** CE started by hand with the bridge enabled is different: any process of your user can then drive it
through the mailbox, with admin rights on whatever process it has attached. That is effectively admin access. The
bridge refuses `{$lua}` / `luaCall` in auto assembler scripts, so that Lua does not run inside elevated CE, but plain
auto assembler (`loadlibrary`, `createthread`, code writes) can still run code in an elevated target. Only enable
the bridge in an elevated CE while you use it.

## License

GPL v3 or later, see [LICENSE](LICENSE). Cheat Engine itself is not included; it is copied from your own install.
