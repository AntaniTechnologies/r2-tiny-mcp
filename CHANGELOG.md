# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added

- **Session self-destruction protection, explicit empty results, and bounded
  output** (feedback items 2, 3 and 4).
  - **Item 2 — protect the session.** `r2()` now refuses, *before forwarding*, any
    command that would terminate or reload the live radare2 session: `q`/`Q`
    (quit), the `o`/`oo`/`o+`/`oc`/`of`/`ot`/… open-reopen family, and `|`
    (pipe/pager). Previously these were forwarded and killed the HTTP server,
    after which every later call returned a misleading `curl exited 56` /
    "start the server first" message. Refusing them keeps the session alive and
    returns an actionable message. Only the pure list/report `o` subcommands
    (`o`, `o*`, `oj`, `oq`, `ob`, `oL`, `o.`) are still allowed. A new
    **`open_file(path, port=0)`** tool is the safe way to switch targets: it
    starts a fresh radare2 HTTP server and repoints the endpoint, instead of
    sending the unsafe `o`/`oo`.
  - **Item 3 — make empty results explicit.** Query commands (`pm`, `/x`, `/c`,
    and any `/…` search) that return nothing now yield `(no matches)` instead of
    an empty string, so "no hits" is distinguishable from "server broken" or
    "bad syntax". Non-query commands that legitimately produce no output (e.g.
    `s`, `aa`) are left untouched.
  - **Item 4 — bound the output.** Results longer than `--maxout` bytes
    (default 6000, env `R2_MAXOUT`) are truncated server-side with a
    `… truncated (N bytes total)` marker plus a hint to narrow the query
    (e.g. `pd N @ addr` / `px N @ addr` instead of `p`/`px` over everything).
    This prevents commands like `?` or a whole-file `izz`/`p` from dumping
    thousands of tokens into the model's context.
  - New config flags: `--maxout` / `R2_MAXOUT` (output cap) and `--r2bin` /
    `R2_BIN` (radare2 binary used by `open_file()`). `README.md` documents the
    safety behavior and the `open_file()` tool.
- **Batch round-trip, health reporting, per-call timeout, and a command whitelist**
  (feedback items 5, 6, 7 and 8).
  - **Item 5 — batch in one round-trip.** A new `r2_multi(commands)` tool runs a list of
    commands in a single POST (separated server-side by an `echo <nonce>` sentinel) and
    splits the response back into per-command `=== [n] <cmd> ===` sections, so a batch of
    related facts costs one transport round-trip instead of N. Session-terminating commands
    in the list are refused exactly as in `r2()`.
  - **Item 6 — health reporting.** At startup the server pings the `/cmd/` endpoint and, if
    it is not answering, prints a loud warning so a wrong `--url` fails visibly instead of
    silently. On any request error the endpoint is re-probed and the result reports whether
    the session is still **ALIVE** (with an `i` summary, so the caller can just re-run the
    command) or **DEAD** (with the `r2 -qc "=h <port>" <target>` restart command). Alive-vs-
    dead is decided by that re-probe, not by the error kind, because on Windows a refused
    connect is usually just the re-listen race rather than a genuinely dead session.
  - **Item 7 — per-call timeout + cost hint.** `r2()` and `r2_multi()` accept an optional
    `timeout` (seconds) for expensive commands. The tool description notes that `aa`
    (analyze-all) is expensive and should be run **once**, then read with the cheap
    follow-ups `afl` / `pdf` rather than re-run on every call.
  - **Item 8 — command whitelist + search hint.** The tool description advertises the
    intended read-only commands (`i aa afl pdf pd px s /x pm izz is`) and states that for
    searching you should use `/x` or `pm`, not `?` (r2's interactive help, not a query).

### Changed

- **Pin `mcp` to `mcp>=1,<2`.**
  - `requirements.txt` now installs `mcp>=1,<2` (previously just `mcp`) with an
    explanatory comment.
  - This server targets the **v1** MCP SDK, which exposes `FastMCP`
    (`mcp.server.fastmcp.FastMCP`). In `mcp` 2.x that class was renamed to
    `MCPServer` (`mcp.server.mcpserver.MCPServer`), so a plain
    `pip install mcp` today (2.x) fails with
    `No module named 'mcp.server.fastmcp'`. Pinning `mcp>=1,<2` keeps the v1 API.
    To use mcp 2.x instead, migrate to `MCPServer` and drop the pin.
  - `README.md` updated accordingly: the requirements list now notes the pin, the
    install command points at `pip install -r requirements.txt`, and a callout box
    explains why `mcp<2` is pinned.
- **Native HTTP client replaces the `curl` shell-out (feedback item 1).** The `/cmd/`
  endpoint is now reached with a raw `socket` from the Python standard library instead of
  shelling out to `curl`. The reader accumulates response bytes and treats a socket close/
  abort as end-of-response, so the bytes r2 already wrote survive the Windows connection-
  abort (Winsock 10053) that a high-level client (urllib/httpx) discards. Transport errors
  are classified into connection-refused (10061) / connection-aborted (10053) / HTTP-error /
  timeout, and transient aborts/refusals are retried with a backoff that spans r2's Windows
  re-accept window (this is what makes `r2()` and `r2_multi()` reliable despite the flaky
  `=h` webserver). `curl` is no longer a dependency; the `README.md` requirements list drops
  it and explains the raw-socket transport.
