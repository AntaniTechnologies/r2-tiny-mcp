#!/usr/bin/env python3
"""
r2-tiny-mcp - a tiny MCP server that exposes a generic r2() tool (plus a batch
r2_multi() tool and an open_file() tool) which run radare2 commands against a
live radare2 HTTP (r2pipe) server.

Start the radare2 HTTP server first (any target, any port):

    r2 -qc "=h 9090" /path/to/target.bin

This server forwards every r2() call to that server's /cmd/ endpoint over HTTP
using a raw socket from the Python standard library (no curl, no shell-out, no
third-party HTTP client). It reads the whole response itself and treats a socket
close/abort as EOF, so bytes r2 already wrote survive the Windows connection-
abort (10053) that urllib/httpx would otherwise lose.

The radare2 session is STATEFUL: analysis, seeks, flags and opened files persist
across calls, so the model can build up state incrementally (e.g. "aa" then "afl").

Safety / output handling (see README "Safety" section):
  * Session-terminating commands (q/Q quit, o/oo open-reopen, | pager) are
    refused BEFORE they are forwarded, so the live session cannot self-destruct.
    Use the open_file() tool to switch targets instead of sending o/oo.
  * Empty results from query commands (pm, /x, /c, /...) return "(no matches)"
    instead of an empty string, so callers can tell "no hits" from "broken".
  * Long results are truncated server-side (--maxout / R2_MAXOUT, default 6000
    bytes) with a "… truncated (N bytes total)" marker plus a narrowing hint.
  * Transport errors are classified (connection refused vs connection aborted
    vs HTTP error vs timeout). A transient connection abort is retried; on any
    hard error the endpoint is re-probed and the result says whether the session
    is still alive (with an 'i' summary) or dead.

Configuration (CLI flags, or environment variables):
  --url / R2_URL          radare2 HTTP endpoint (default http://127.0.0.1:9090/cmd/)
  --timeout / R2_TIMEOUT  default per-command timeout in seconds (default 60)
  --maxout / R2_MAXOUT    max bytes of command output returned (default 6000)
  --r2bin / R2_BIN        radare2 binary used by open_file() (default "r2")

  Copyright (C) Antani Technologies BV 2026. Distributed under MIT license.

"""

import argparse
import os
import re
import shutil
import socket
import subprocess
import time

from mcp.server.fastmcp import FastMCP

DEFAULT_URL = "http://127.0.0.1:9090/cmd/"
DEFAULT_TIMEOUT = 60.0
DEFAULT_MAXOUT = 6000
DEFAULT_R2BIN = "r2"

# Resolved at startup from --url / R2_URL (see _main()).
_ENDPOINT = DEFAULT_URL
_TIMEOUT = DEFAULT_TIMEOUT
_MAXOUT = DEFAULT_MAXOUT
_R2BIN = DEFAULT_R2BIN

# A radare2 HTTP server we spawned via open_file(), kept referenced so it (and
# its still-open stdin pipe) is not garbage-collected and does not exit on EOF.
_SPAWNED = None

# 'o' subcommands that only LIST / report state and never open, reload or close
# a file, so they are safe to forward. Anything else in the 'o' family is refused.
_SAFE_O = {"o", "o*", "o**", "oj", "oq", "oqq", "ob", "oL", "o."}


def _normalize(url: str) -> str:
    """Accept 'host:port', '.../cmd' or '.../cmd/' and return a '.../cmd/' endpoint."""
    url = url.strip()
    if url.endswith("/cmd/"):
        return url
    if url.endswith("/cmd"):
        return url + "/"
    return url.rstrip("/") + "/cmd/"


def _port_of(url: str) -> int:
    """Extract the port from an endpoint URL (default 9090 if absent)."""
    m = re.search(r":(\d+)(?:/|$)", url)
    return int(m.group(1)) if m else 9090


def _split(command: str):
    """Split a command string the way r2 does: ';' and newlines separate commands."""
    return re.split(r"[;\n]", command)


def _session_guard(command: str):
    """Return a refusal message if `command` would terminate/destabilize the
    live session, else None. Checked BEFORE anything is forwarded."""
    if "|" in command:
        return (
            "ERROR: refusing to send a pipe/pager ('|'). Pagers block the radare2 "
            "HTTP server waiting for interactive input and can hang or kill the "
            "session. Use a query that returns text directly instead (e.g. 'pd', "
            "'px', '/x', 'pm')."
        )
    for raw in _split(command):
        c = raw.strip()
        if not c:
            continue
        tok = c.split()[0]
        rest = c[len(tok):].strip()
        if tok[0] in "qQ":
            return (
                "ERROR: refusing to send %r (quit). 'q'/'Q' terminates the radare2 "
                "HTTP server and kills the live session. The session is meant to "
                "stay open - just keep issuing commands; there is no need to quit."
                % (c,)
            )
        if tok[0] == "o":
            pure_list = tok in _SAFE_O and not (tok == "o" and rest)
            if not pure_list:
                return (
                    "ERROR: refusing to send %r (open/reopen). Opening or reopening "
                    "a file reloads or resets the live session and can kill it. To "
                    "switch targets, call the open_file(path) tool instead (it "
                    "starts a fresh radare2 HTTP server)." % (c,)
                )
    return None
def _is_query(command: str) -> bool:
    """True if any subcommand is a search/query (pm, /x, /c, or any '/' search)."""
    for raw in _split(command):
        c = raw.strip()
        if not c:
            continue
        tok = c.split()[0]
        if tok.startswith("/") or tok.startswith("pm"):
            return True
    return False


def _kind_of(exc) -> str:
    """Classify a transport exception into a stable error kind."""
    if isinstance(exc, str):
        s = exc.lower()
        if "refus" in s or "10061" in s:
            return "conn_refused"
        if "abort" in s or "10053" in s or "disconnect" in s or "closed" in s:
            return "conn_aborted"
        if "timeout" in s or "timed out" in s:
            return "timeout"
        return "other"
    if isinstance(exc, ConnectionRefusedError):
        return "conn_refused"
    if isinstance(exc, TimeoutError) or type(exc).__name__ in ("timeout", "socket.timeout"):
        return "timeout"
    if isinstance(exc, ConnectionError):  # aborted, remote-disconnected, broken pipe
        return "conn_aborted"
    return "other"


def _parse_url(url: str):
    """Return (host, port, path) from an endpoint URL like http://h:port/cmd/."""
    m = re.match(r"https?://([^:/]+):(\d+)(/.*)?$", url)
    if not m:
        return None
    return m.group(1), int(m.group(2)), (m.group(3) or "/cmd/")


def _parse_http(got: bytes, aborted: bool, timed_out: bool) -> dict:
    """Parse a raw HTTP/1.0 response we accumulated, tolerating a truncated tail."""
    sep = got.find(b"\r\n\r\n")
    if sep < 0:
        if aborted:
            return {"kind": "conn_aborted", "body": b"", "status": 0,
                    "detail": "connection aborted before a complete response"}
        if timed_out:
            return {"kind": "timeout", "body": b"", "status": 0,
                    "detail": "timed out before a complete response"}
        return {"kind": "other", "body": got, "status": 0, "detail": "malformed response"}
    header = got[:sep]
    body = got[sep + 4:]
    first = header.split(b"\r\n", 1)[0]
    parts = first.split()
    status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
    kind = "ok" if 200 <= status < 300 else "http_error"
    return {"kind": kind, "body": body, "status": status, "detail": ""}


def _http(command: str, timeout: float = None, url: str = None) -> dict:
    """POST `command` to `url` (default _ENDPOINT) over a raw socket. Returns a
    dict {kind, body, status, detail} where kind is one of:
    'ok','http_error','conn_refused','conn_aborted','timeout','other'.

    We read the whole response ourselves and treat a socket close / abort as EOF,
    so bytes r2 already wrote are kept even when Windows reports the connection
    was aborted (10053) right after the server closed it. This is what makes the
    native client robust where urllib loses those bytes."""
    t = timeout if (timeout and timeout > 0) else _TIMEOUT
    target = url or _ENDPOINT
    parsed = _parse_url(target)
    if not parsed:
        return {"kind": "other", "body": b"", "status": 0, "detail": "bad endpoint %r" % (target,)}
    host, port, path = parsed
    body = command.encode("utf-8", "surrogatepass")
    head = ("POST %s HTTP/1.0\r\nHost: %s\r\nContent-Length: %d\r\n\r\n"
            % (path, host, len(body))).encode("ascii")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(t)
    got = b""
    timed_out = False
    aborted = False
    try:
        s.connect((host, port))
        s.sendall(head + body)
        while True:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                timed_out = True
                break
            except (ConnectionAbortedError, ConnectionResetError, OSError):
                aborted = True
                break
            if not chunk:
                break
            got += chunk
            if len(got) > 16 * 1024 * 1024:
                break
    except ConnectionRefusedError as e:
        try:
            s.close()
        except Exception:
            pass
        return {"kind": "conn_refused", "body": b"", "status": 0, "detail": str(e)}
    except socket.timeout:
        timed_out = True
    except (ConnectionAbortedError, ConnectionResetError, OSError) as e:
        aborted = True
    finally:
        try:
            s.close()
        except Exception:
            pass
    if got:
        return _parse_http(got, aborted, timed_out)
    if timed_out:
        return {"kind": "timeout", "body": b"", "status": 0, "detail": "timed out after %ss" % (t,)}
    if aborted:
        return {"kind": "conn_aborted", "body": b"", "status": 0,
                "detail": "connection aborted before any response"}
    return {"kind": "conn_refused", "body": b"", "status": 0, "detail": "no connection"}


def _post_retry(command: str, timeout: float = None, tries: int = 10) -> dict:
    """POST with retry on transient transport errors.

    On Windows, r2's HTTP/1.0 webserver (r_socket_http_accept) blocks in
    r_socket_accept and only closes the *client* socket, but its re-accept/re-
    listen timing means a fresh connection is refused or aborted most of the
    time (a good window recurs only every couple of seconds). So we retry on
    conn_refused / conn_aborted / timeout with a capped backoff that spans that
    window, and only report a hard failure after exhausting the retries (the
    caller then re-probes to decide alive vs dead). Returns the last result."""
    last = None
    for k in range(tries):
        res = _http(command, timeout)
        last = res
        if res["kind"] in ("ok", "http_error"):
            return res
        time.sleep(min(0.3 * (k + 1), 2.0))
    return last


def _ping(url: str) -> bool:
    """Reachability probe with retry: True if the /cmd/ endpoint answers at all.
    A transient refusal/abort still counts as alive once any attempt answers; we
    retry a few times with a backoff that spans r2's Windows re-accept window so
    a momentary socket-close race is not mistaken for dead."""
    for k in range(6):
        res = _http("i", timeout=5.0, url=url)
        if res["kind"] in ("ok", "http_error", "conn_aborted"):
            return True
        time.sleep(min(0.3 * (k + 1), 2.0))
    return False


def _format(raw: bytes, command: str) -> str:
    """Turn raw command output into a safe, bounded, explicit result."""
    if raw.strip() == b"":
        if _is_query(command):
            return "(no matches)"
        return ""
    total = len(raw)
    if total > _MAXOUT:
        head = raw[:_MAXOUT].decode("utf-8", "replace")
        return (
            head
            + "\n\n… truncated (%d bytes total). Narrow the query (use a range, "
              "or 'pd N @ addr' / 'px N @ addr' instead of 'p'/'px' over "
              "everything) and re-run." % (total,)
        )
    return raw.decode("utf-8", "replace")
mcp = FastMCP("r2-tiny-mcp")


def _error_report(command: str, res: dict) -> str:
    """Build a helpful message for a failed request: classify the error, re-probe
    the endpoint, and report whether the session is still alive (with an 'i'
    summary) or dead.

    On Windows, r2's =h webserver can REFUSE a fresh connection even while the
    session is alive (a re-listen race), so 'alive' is decided by re-probing the
    endpoint, NOT by the error kind: a refused connect on a session that still
    answers is transient (just re-run), and only a session that no longer answers
    at all is DEAD.
    """
    kind = res["kind"]
    head = "ERROR: could not run %r over %s (%s)." % (command, _ENDPOINT, kind)
    if not _ping(_ENDPOINT):
        return (
            head + "\nThe endpoint is now DEAD (no response on re-probe): the session "
            "has gone. Start a fresh one with open_file(path) or restart the HTTP "
            "server (r2 -qc \"=h <port>\" <target>)."
        )
    # Session still answers: the failure was a transient transport error.
    info = _http("i", timeout=10.0)
    summary = _format(info["body"], "i") if info["kind"] == "ok" else "(info unavailable)"
    if kind == "conn_refused":
        hint = "The connection was REFUSED (a transient Windows/r2 re-listen race; the server is still there). "
    elif kind == "conn_aborted":
        hint = "The connection was ABORTED mid-response (a known Windows/r2 transport race). "
    else:
        hint = "The command TIMED OUT. "
    return (
        head + "\nThe session is still ALIVE. " + hint +
        "The command may or may not have run. Re-run it, or narrow it. Current "
        "session file info ('i'):\n" + summary
    )


@mcp.tool()
def r2(command: str, timeout: float = None) -> str:
    """Run a radare2 command against the live radare2 session.

    The session is STATEFUL: analysis, seeks, flags and opened files persist
    across calls, so you can build up state incrementally (e.g. "aa" then "afl").

    Send one command, or several joined with ';' or newlines. Prefer the batch
    tool r2_multi([...]) when you have several commands: it runs them in ONE
    round-trip and returns each command's output separately.

    Stick to this command whitelist (other commands waste context or are unsafe):
      i  aa  afl  pdf  pd  px  s  /x  pm izz  is
    For SEARCHING use '/x' or 'pm' (or '/a', '/v'), NOT '?'. The '?' command
    prints a huge multi-page help/eval table and wastes context.

    'aa' (analyze-all) is EXPENSIVE: run it once, then use afl/pdf/pd to read
    results. Do not repeat 'aa'.

    Session-terminating commands are refused up-front so the live session cannot
    self-destruct: 'q'/'Q' (quit), 'o'/'oo' (open/reopen a file), and '|' (pager).
    To switch targets, use the open_file(path) tool instead of sending o/oo.

    Output handling: empty results from query commands (pm, /x, /c, /...) return
    "(no matches)"; results longer than the configured max are truncated with a
    "… truncated (N bytes total)" marker and a hint to narrow the query. On a
    transport error the endpoint is re-probed and the result says whether the
    session is still alive (with an 'i' summary) or dead.

    `timeout` (seconds) optionally overrides the default per-command timeout for
    this call only (use a larger value for 'aa' on big binaries).

    Common commands:
      i                 file info (format, arch, bits, entrypoint)
      aa                analyze everything (expensive: run once, then afl/pdf)
      afl               list functions
      pdf @ 0xADDR      disassemble a whole function
      pd N @ 0xADDR     disassemble N instructions at an address
      s 0xADDR          seek to an address
      px @ 0xADDR       hexdump at an address
      izz               print all strings in the binary
      is                section info
      pm <str>          search for a string/printable match
      /x <hex>          search for a byte pattern

    Returns the (possibly truncated) text output of the command.
    """
    guard = _session_guard(command)
    if guard:
        return guard

    res = _post_retry(command, timeout)
    if res["kind"] != "ok":
        return _error_report(command, res)
    return _format(res["body"], command)
@mcp.tool()
def r2_multi(commands: list, timeout: float = None) -> str:
    """Run SEVERAL radare2 commands in ONE round-trip (batch mode).

    This is the efficient way to ask multiple things at once: all commands run
    against the same live session in a single HTTP request, and the output of
    each is returned separately, in order. Use it instead of many separate r2()
    calls to save round-trips (e.g. ["i", "is", "izz"] or ["aa", "afl"]).

    `commands` is a list of command strings. Each is checked by the same safety
    guard as r2() (quit/open/pipe are refused). `timeout` (seconds) optionally
    overrides the default per-command timeout for the whole batch.

    Returns a block per command:
      === [1] i ===
      <output or (no matches) or truncated marker>
    """
    if not commands:
        return "ERROR: no commands given."
    if isinstance(commands, str):
        commands = [commands]

    # Refuse the whole batch if any command would destabilize the session.
    for c in commands:
        guard = _session_guard(c)
        if guard:
            return guard

    # Unique sentinel so command output can never collide with the separator.
    marker = "__R2MCP_%08x_SEP__" % (id(tuple(commands)) & 0xFFFFFFFF)
    combined = "".join("echo %s\n%s\n" % (marker, c) for c in commands)

    res = _post_retry(combined, timeout)
    if res["kind"] != "ok":
        return _error_report("batch of %d commands" % (len(commands),), res)

    body = res["body"].decode("utf-8", "replace")
    parts = body.split(marker)
    # A leading empty segment exists because the batch starts with 'echo marker'.
    if parts and parts[0].strip() == "":
        parts = parts[1:]

    out = []
    for i, c in enumerate(commands):
        seg = parts[i] if i < len(parts) else ""
        out.append("=== [%d] %s ===\n%s" % (i + 1, c, _format(seg.encode("utf-8", "replace"), c)))
    return "\n\n".join(out)
@mcp.tool()
def open_file(path: str, port: int = 0) -> str:
    """Safely switch the live session to a new target file.

    Instead of sending the unsafe 'o'/'oo' commands (which reload/reset the
    session and can kill it), this starts a FRESH radare2 HTTP server against
    `path` and repoints this MCP server at it. Analysis state from the previous
    target does NOT carry over (it is a brand-new session).

    `path` is the target binary/file (absolute or ~-relative). `port` selects the
    port for the new server; if omitted (0) it reuses the current endpoint's port,
    which is fine when the old session is already dead. If a live server still
    occupies that port, pass an explicit different `port`.

    Returns file info ('i') for the newly opened target on success.
    """
    global _ENDPOINT, _SPAWNED

    r2bin = shutil.which(_R2BIN) or shutil.which("radare2")
    if r2bin is None:
        return (
            "ERROR: radare2 binary not found on PATH (looked for %r then 'radare2'). "
            "Set --r2bin / R2_BIN to its path." % (_R2BIN,)
        )

    target = os.path.abspath(os.path.expanduser(path))
    if not os.path.isfile(target):
        return "ERROR: file not found: %s" % (target,)

    new_port = int(port) if port else _port_of(_ENDPOINT)
    new_url = "http://127.0.0.1:%d/cmd/" % (new_port,)

    # We cannot stop an externally-started server; if one is still answering on
    # the port we are about to use, a fresh spawn would collide with it.
    if new_url == _ENDPOINT and _ping(_ENDPOINT):
        return (
            "ERROR: a live radare2 server already occupies port %d and we cannot "
            "stop an externally-started one. Call open_file again with an explicit "
            "different 'port' to switch targets." % (new_port,)
        )

    # Stop a server we previously spawned so we do not leak r2 processes.
    if _SPAWNED is not None:
        try:
            _SPAWNED.terminate()
        except Exception:
            pass
        _SPAWNED = None

    try:
        # Keep stdin open (never written/closed) so r2 does not exit on EOF and
        # the HTTP server thread stays alive; _SPAWNED keeps it referenced.
        proc = subprocess.Popen(
            [r2bin, "-qc", "=h %d" % (new_port,), target],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as exc:  # noqa: BLE001
        return "ERROR: failed to spawn radare2: %r" % (exc,)
    _SPAWNED = proc

    # Wait until the new endpoint answers.
    deadline = time.time() + 15.0
    while time.time() < deadline:
        if _ping(new_url):
            break
        time.sleep(0.3)
    else:
        return (
            "ERROR: new radare2 HTTP server on port %d did not come up within 15s. "
            "The endpoint %s is not answering." % (new_port, new_url)
        )

    _ENDPOINT = new_url
    res = _post_retry("i")
    info = _format(res["body"], "i") if res["kind"] == "ok" else "(file opened; 'i' info unavailable: %s)" % (res["detail"],)
    return "Opened %s on port %d (new session). File info:\n%s" % (target, new_port, info)


def _main() -> None:
    parser = argparse.ArgumentParser(
        description="Tiny MCP server exposing r2()/r2_multi()/open_file() over radare2's HTTP server."
    )
    parser.add_argument(
        "--url",
        default=os.environ.get("R2_URL", DEFAULT_URL),
        help="radare2 HTTP endpoint (default: env R2_URL or %(default)s)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(os.environ.get("R2_TIMEOUT", DEFAULT_TIMEOUT)),
        help="default per-command timeout in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--maxout",
        type=int,
        default=int(os.environ.get("R2_MAXOUT", DEFAULT_MAXOUT)),
        help="max bytes of command output returned before truncating (default: %(default)s)",
    )
    parser.add_argument(
        "--r2bin",
        default=os.environ.get("R2_BIN", DEFAULT_R2BIN),
        help="radare2 binary used by open_file() (default: env R2_BIN or %(default)s)",
    )
    args = parser.parse_args()

    global _ENDPOINT, _TIMEOUT, _MAXOUT, _R2BIN
    _ENDPOINT = _normalize(args.url)
    _TIMEOUT = args.timeout
    _MAXOUT = args.maxout
    _R2BIN = args.r2bin

    # Startup health ping: fail loudly if the endpoint is not answering, so the
    # model is not left to discover a dead session through failed tool calls.
    if not _ping(_ENDPOINT):
        import sys
        sys.stderr.write(
            "\n*** r2-tiny-mcp WARNING ***\n"
            "No radare2 HTTP server is answering at %s.\n"
            "Start one and keep it running before using r2(), e.g.:\n"
            '  r2 -qc "=h %d" <target>\n'
            "Or call open_file(path) to start a fresh session. Use --url / R2_URL "
            "if your server is on a different port.\n"
            "Continuing to start so open_file() can still be used.\n\n"
            % (_ENDPOINT, _port_of(_ENDPOINT))
        )
        sys.stderr.flush()

    mcp.run(transport="stdio")


if __name__ == "__main__":
    _main()
