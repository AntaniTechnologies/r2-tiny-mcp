# r2-tiny-mcp

A tiny [MCP](https://modelcontextprotocol.io) server that exposes **one** generic tool,
`r2()`, which runs a [radare2](https://radare.org) command against a live radare2
**HTTP (r2pipe) server**. It is a thin proxy that shells out to `curl` — no radare2
linking, no r2mcp.

## Why

radare2 ships a built-in HTTP server (`=h`). Start it once against any target, keep it
open, and let an agent drive it through a single `r2(command)` tool. The session is
**stateful**: analysis, seeks, flags and opened files persist across calls, so the model
builds up state incrementally (e.g. `aa` then `afl`).

## Requirements

- Python 3.10+
- `mcp` (official MCP Python SDK)
- `curl` available on `PATH` — the server shells out to `curl` to reach the radare2 HTTP
  endpoint (this avoids httpx's connection-abort failure against r2's `HTTP/1.0` server on
  Windows). If `curl` is missing, `r2()` returns an error.
- `radare2` (`r2`) available on `PATH` — used in step 1 to start the HTTP server.

```bash
pip install mcp
```

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
- **Output:** the raw text output of the command.
- Commands with spaces or special chars (`?`, etc.) are sent as the raw POST body, so they
  work regardless of URL-escaping.

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

`--url` accepts `host:port`, `.../cmd`, or `.../cmd/` and normalizes to `.../cmd/`.

## Layout

```
r2-tiny-mcp/
  server.py        # the MCP server (one r2() tool)
  README.md        # this file
  requirements.txt # deps
```
