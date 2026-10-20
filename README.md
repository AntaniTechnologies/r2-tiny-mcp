# r2-tiny-mcp

A tiny [MCP](https://modelcontextprotocol.io) server that exposes a generic tool,
`r2()`, which runs a [radare2](https://radare.org) command against a live radare2
**HTTP (r2pipe) server**, plus a batch `r2_multi()` tool and a small `open_file()`
tool to switch targets safely. It is a thin proxy that talks to the endpoint over a
raw socket from the Python standard library — no curl, no shell-out, no third-party
HTTP client, no radare2 linking, no r2mcp.

## Why

radare2 ships a built-in HTTP server (`=h`). Start it once against any target, keep it
open, and let an agent drive it through a single `r2(command)` tool. The session is
**stateful**: analysis, seeks, flags and opened files persist across calls, so the model
builds up state incrementally (e.g. `aa` then `afl`).

## Requirements

- Python 3.10+
- `mcp` (official MCP Python SDK) — **pin to `mcp>=1,<2`** (see note below)
- `radare2` (`r2`) available on `PATH` — used in step 1 to start the HTTP server, and by
  the `open_file()` tool to start a fresh one.

The HTTP transport uses only the Python standard library (a raw `socket`), so there is
**no `curl` and no third-party HTTP client** to install. r2's `=h` webserver speaks
`HTTP/1.0` with `Connection: close`, and on Windows it aborts the connection (Winsock
error 10053) right after the server closes it; the built-in reader treats that abort as
end-of-response, so the bytes r2 already wrote are kept. (urllib/httpx lose those bytes,
which is why a hand-rolled reader is used instead of a high-level client.)

```bash
pip install -r requirements.txt   # installs mcp>=1,<2
```

> **Why pin `mcp<2`?** This server targets the v1 SDK, which exposes `FastMCP`
> (`mcp.server.fastmcp.FastMCP`). In mcp 2.x that class was renamed to `MCPServer`
> (`mcp.server.mcpserver.MCPServer`), so `pip install mcp` today (2.x) fails to import
> with `No module named 'mcp.server.fastmcp'`. Pinning `mcp>=1,<2` keeps the v1 API.
> To use mcp 2.x instead, migrate to `MCPServer` and drop the pin.

## 1. Start the radare2 HTTP server

Pick a free port (8080 is often busy). Quote `"=h <port>"` as a single argument.

```bash
# Linux / macOS / Git Bash
r2 -qc "=h 9090" /path/to/target.bin
```

```bat
:: Windows cmd
r2 -qc "=h 9090" C:\path\to\target.exe
```

Keep that terminal open. If you launch it from a script/background job, keep stdin open
so r2 does not exit on EOF, e.g.:

```bash
yes | r2 -qc "=h 9090" /path/to/target.bin
```

## 2. Run / register the MCP server

The server speaks MCP over **stdio**. Point it at the radare2 endpoint with `--url`
(or the `R2_URL` env var).

```bash
python server.py --url http://127.0.0.1:9090/cmd/
```

### OpenCode (`opencode.jsonc`)

```jsonc
{
  "mcp": {
    "servers": {
      "radare2": {
        "type": "local",
        "command": ["python", "/abs/path/to/r2-tiny-mcp/server.py"],
        "env": { "R2_URL": "http://127.0.0.1:9090/cmd/" }
      }
    }
  }
}
```

The tool then appears as `radare2_r2` (server name + tool name).

## The `r2()` tool

- **Input:** `command` (string) — one radare2 command, or several joined with `;`/newlines.
- **Input (optional):** `timeout` (seconds) — per-call timeout for expensive commands;
  defaults to `--timeout`. Note that `aa` (analyze-all) is expensive: run it **once**, then
  read the result with the cheap follow-ups `afl` (function list) / `pdf` (one function)
  rather than re-running `aa` on every call.
- **Output:** the text output of the command, with safety handling applied (see below).
- Commands with spaces or special chars (`?`, etc.) are sent as the raw POST body, so they
  work regardless of URL-escaping.
- **Whitelist:** the tool is intended for the read-only inspection commands
  `i  aa afl pdf pd px s /x pm izz is`. For **searching, use `/x` or `pm`, not `?`** —
  `?` is r2's interactive help and is not a query. (The guards below only block the
  session-killers; they are not a substitute for staying on these commands.)

## The `r2_multi(commands)` tool

Runs several commands in **one round-trip** (a single POST with the commands separated
server-side by an `echo` sentinel), then splits the response back into per-command
sections. This is the cheap way to fetch a batch of related facts (e.g. `["i","is","izz"]`)
without paying a transport round-trip per command. Session-terminating commands in the
list are refused exactly as in `r2()`.

- **Input:** `commands` (list of strings) + optional `timeout`.
- **Output:** the sections joined and labelled `=== [n] <command> ===`, each with the same
  `(no matches)` / truncation handling as `r2()`.

### Safety & output handling

The raw `r2()` proxy is hardened so a bad command can neither kill the live session nor
flood the model's context:

1. **Session self-destruction is blocked.** Commands that would terminate or reload the
   live radare2 session are refused *before* they are forwarded, so the session stays
   alive and you get a clear, actionable message instead of a dead connection:
   - `q` / `Q` (quit) — would terminate the HTTP server.
   - `o <file>` / `oo` / `o+` / `oc` / `of` / `ot` … (open/reopen) — reload or reset the session.
     Only the pure list/report subcommands (`o`, `o*`, `oj`, `oq`, `ob`, `oL`, `o.`) are allowed.
   - `|` (pipe/pager) — blocks the HTTP server waiting for interactive input.
   To switch targets, use the **`open_file(path)`** tool instead of sending `o`/`oo`.
2. **Empty results are explicit.** Query commands (`pm`, `/x`, `/c`, and any `/…` search)
   that return nothing yield `(no matches)` instead of an empty string, so "no hits" is
   distinguishable from "server broken" or "bad syntax".
3. **Output is bounded server-side.** Results longer than `--maxout` bytes (default 6000)
   are truncated with a `… truncated (N bytes total)` marker plus a hint to narrow the
   query (e.g. use `pd N @ addr` / `px N @ addr` instead of `p`/`px` over everything).
4. **Transport is classified and retried.** r2's Windows `=h` webserver intermittently
   refuses (10061) or aborts (10053) a fresh connection even while the session is alive.
   The client classifies *connection refused*, *connection aborted*, *HTTP error* and
   *timeout*, but decides **alive vs dead by re-probing the endpoint, not by the error
   kind** — on Windows a refused connect is often just the re-listen race, so it is retried
   like an abort. Transient refusals/aborts are retried with a backoff that spans r2's
   re-accept window, so most calls succeed on the first `r2()`/`r2_multi()` invocation. On
   a hard failure the endpoint is re-probed and the result says whether the session is still
   **ALIVE** (with an `i` summary — just re-run the command) or **DEAD** (with the
   `r2 -qc "=h <port>" <target>` command to restart it). At startup the server pings the
   endpoint once and prints a loud warning if it is not answering, so a misconfigured
   `--url` fails visibly instead of silently.

### `open_file(path, port=0)` tool

Starts a **fresh** radare2 HTTP server against `path` and repoints this MCP server at it —
the safe alternative to sending the unsafe `o`/`oo` commands. Analysis state from the
previous target does **not** carry over (it is a brand-new session). `port` selects the
port for the new server; if omitted (`0`) it reuses the current endpoint's port (fine when
the old session is already dead). If a live server still occupies that port, pass an
explicit different `port`. Requires `radare2` on `PATH` (or `--r2bin` / `R2_BIN`).

Examples the model can call:

| command | meaning |
|---|---|
| `i` | file info (format, arch, bits, entrypoint) |
| `aa` | analyze everything (run before `afl`/`pdf`) |
| `afl` | list functions |
| `pdf @ 0x1000` | disassemble a whole function |
| `pd 20 @ 0x1000` | disassemble 20 instructions at an address |
| `izz` | print all strings |
| `is` | section info |

## Config

| flag | env | default |
|---|---|---|
| `--url` | `R2_URL` | `http://127.0.0.1:9090/cmd/` |
| `--timeout` | `R2_TIMEOUT` | `60` |
| `--maxout` | `R2_MAXOUT` | `6000` (bytes; output beyond this is truncated) |
| `--r2bin` | `R2_BIN` | `r2` (radare2 binary used by `open_file()`) |

`--url` accepts `host:port`, `.../cmd`, or `.../cmd/` and normalizes to `.../cmd/`.

## Layout

```
r2-tiny-mcp/
  server.py        # the MCP server (r2(), r2_multi(), open_file() tools)
  README.md        # this file
  requirements.txt # deps
```
