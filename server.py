#!/usr/bin/env python3
"""
r2-tiny-mcp - a tiny MCP server that exposes ONE generic tool, r2(), which runs a
radare2 command against a live radare2 HTTP (r2pipe) server.

Start the radare2 HTTP server first (any target, any port):

    r2 -qc "=h 9090" /path/to/target.bin

This server forwards every r2() call to that server's /cmd/ endpoint over HTTP
(via curl). The radare2 session is STATEFUL: analysis, seeks, flags and opened
files persist across calls, so the model can build up state incrementally (e.g.
"aa" then "afl").

Configuration (CLI flags, or environment variables):
  --url / R2_URL          radare2 HTTP endpoint (default http://127.0.0.1:9090/cmd/)
  --timeout / R2_TIMEOUT  per-command timeout in seconds (default 60)
"""

import argparse
import os
import shutil
import subprocess

from mcp.server.fastmcp import FastMCP

DEFAULT_URL = "http://127.0.0.1:9090/cmd/"
DEFAULT_TIMEOUT = 60.0

# Resolved at startup from --url / R2_URL (see _main()).
_ENDPOINT = DEFAULT_URL
_TIMEOUT = DEFAULT_TIMEOUT


def _normalize(url: str) -> str:
    """Accept 'host:port', '.../cmd' or '.../cmd/' and return a '.../cmd/' endpoint."""
    url = url.strip()
    if url.endswith("/cmd/"):
        return url
    if url.endswith("/cmd"):
        return url + "/"
    return url.rstrip("/") + "/cmd/"


mcp = FastMCP("r2-tiny-mcp")


@mcp.tool()
def r2(command: str) -> str:
    """Run a radare2 command against the live radare2 session.

    The session is STATEFUL: analysis, seeks, flags and opened files persist across
    calls, so you can build up state incrementally (e.g. "aa" then "afl").

    Send one command, or several joined with ';' or newlines.

    Common commands:
      i                 file info (format, arch, bits, entrypoint)
      aa                analyze everything (run this before afl/pdf)
      afl               list functions
      pdf @ 0xADDR      disassemble a whole function
      pd N @ 0xADDR     disassemble N instructions at an address
      s 0xADDR          seek to an address
      px @ 0xADDR       hexdump at an address
      izz               print all strings in the binary
      is                section info

    Returns the raw text output of the command.
    """
    curl = shutil.which("curl")
    if curl is None:
        return "ERROR: 'curl' not found on PATH; this server shells out to curl."
    try:
        proc = subprocess.run(
            [curl, "-s", "-m", str(_TIMEOUT), "-X", "POST",
             "--data-binary", "@-", _ENDPOINT],
            input=command.encode("utf-8", "surrogatepass"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except Exception as exc:  # noqa: BLE001 - surface any subprocess failure
        return "ERROR: failed to run curl: %r" % (exc,)

    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        return (
            "ERROR: curl exited %d reaching %s.\n"
            "Start the radare2 HTTP server first and keep it running, e.g.:\n"
            '  r2 -qc "=h 9090" <target>\n'
            "If you use a different port, pass --url or set R2_URL.\n"
            "curl stderr: %s"
        ) % (proc.returncode, _ENDPOINT, err)

    return proc.stdout.decode("utf-8", "replace")


def _main() -> None:
    parser = argparse.ArgumentParser(
        description="Tiny MCP server exposing one r2() tool over radare2's HTTP server."
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
        help="per-command timeout in seconds (default: %(default)s)",
    )
    args = parser.parse_args()

    global _ENDPOINT, _TIMEOUT
    _ENDPOINT = _normalize(args.url)
    _TIMEOUT = args.timeout

    mcp.run(transport="stdio")


if __name__ == "__main__":
    _main()
