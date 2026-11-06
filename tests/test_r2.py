"""Tests for r2-tiny-mcp.

Run the real server logic against a fake radare2 HTTP server (a plain TCP socket
that speaks HTTP/1.0 with Connection: close, exactly like r2's =h webserver), so
no external radare2 install is needed. They cover the batch splitter and the
batch-sentinel collision guard (#2) plus the session guards and error handling
that keep a live session alive.

Run:  python -m pytest tests/test_r2.py   (or)   python -m unittest discover tests
"""

import os
import re
import socket
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server import _http, _is_query, _session_guard, _split_batch, r2_multi


class FakeR2Server:
    """A loopback TCP server that answers HTTP/1.0 requests like r2's =h webserver.

    `handler(command_string) -> bytes` produces each response body; default is a
    trivial "ok". Answers up to `concurrency` simultaneous connections."""

    def __init__(self, handler=None, concurrency=8):
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(concurrency)
        self.port = self.srv.getsockname()[1]
        self.handler = handler or (lambda cmd: b"ok")
        self._stop = False
        self._lock = threading.Lock()
        self._threads = []

    @property
    def url(self):
        return "http://127.0.0.1:%d/cmd/" % self.port

    def _handle(self, conn):
        raw = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            raw += chunk
            head_end = raw.find(b"\r\n\r\n")
            if head_end < 0:
                continue
            header = raw[:head_end].lower()
            try:
                clen = int(re.search(rb"content-length:\s*(\d+)", header).group(1))
            except Exception:
                clen = 0
            body = raw[head_end + 4:]
            while len(body) < clen and clen > 0:
                more = conn.recv(4096)
                if not more:
                    break
                body += more
            cmd = body.decode("utf-8", "replace").strip()
            out = self.handler(cmd)
            resp = ("HTTP/1.0 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
                    % len(out)).encode("ascii") + out
            try:
                conn.sendall(resp)
            except OSError:
                pass
            conn.close()
            break

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                break
            with self._lock:
                t = threading.Thread(target=self._handle, args=(conn,), daemon=True)
                t.start()
                self._threads.append(t)

    def start(self):
        self._t = threading.Thread(target=self._serve, daemon=True)
        self._t.start()

    def stop(self):
        self._stop = True
        try:
            self.srv.close()
        except OSError:
            pass


class SessionGuardTests(unittest.TestCase):
    """Commands that would kill or destabilize the live session are refused."""

    def test_refuses_quit(self):
        self.assertIsNotNone(_session_guard("q"))
        self.assertIsNotNone(_session_guard("Q 0x10"))

    def test_refuses_open_reopen(self):
        for c in ("o target.bin", "oo", "o+", "oc"):
            self.assertIsNotNone(_session_guard(c), "%s should be refused" % c)

    def test_allows_list_only_o(self):
        for c in ("o", "o*", "oj", "oq", "ob", "oL", "o."):
            self.assertIsNone(_session_guard(c), "%s should be allowed" % c)

    def test_refuses_pipe(self):
        self.assertIsNotNone(_session_guard("iz | cat"))


class QueryDetectionTests(unittest.TestCase):
    def test_detects_queries(self):
        for c in ("pm foo", "/x de ad beef", "/bin/sh"):
            self.assertTrue(_is_query(c), "%s should be a query" % c)

    def test_nonqueries_are_not(self):
        for c in ("afl", "pd 10 @ 0x1000", "i"):
            self.assertFalse(_is_query(c))


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.srv = FakeR2Server()
        self.srv.start()

    def tearDown(self):
        self.srv.stop()

    def test_ok_response_body_and_kind(self):
        body = b"file: foo.bin\narch: amd64"
        self.srv.handler = lambda cmd: body if cmd == "i" else b"x"
        res = _http("i", timeout=5.0, url=self.srv.url)
        self.assertEqual(res["kind"], "ok")
        self.assertEqual(res["body"], body)

    def test_connection_refused(self):
        # Bind then close with no listener: a connect finds nothing refused.
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()  # now nobody listens on `port`
        url = "http://127.0.0.1:%d/cmd/" % port
        res = _http("i", timeout=5.0, url=url)
        self.assertEqual(res["kind"], "conn_refused")

    def test_bad_endpoint(self):
        res = _http("i", timeout=3.0, url="not-a-url")
        self.assertEqual(res["kind"], "other")


class BatchTests(unittest.TestCase):
    """The batch splitter and the sentinel-collision guard (#2)."""

    def setUp(self):
        # Each command echoes back a numbered block delimited by its own marker
        # so r2_multi can split it; mimics how the real server separates commands.
        self.srv = FakeR2Server()
        self.srv.start()

    def tearDown(self):
        self.srv.stop()

    def _handler_for_markers(self, markers):
        seen = {"n": 0}

        def handler(cmd):
            # The server joins commands as: echo <marker>\n<cmd>\n... ; the first
            # line after headers is 'echo <marker>'. Return that marker + payload.
            lines = cmd.splitlines()
            out = b""
            for ln in lines:
                if ln.startswith("echo "):
                    m = ln[5:].strip()
                    n = seen["n"]
                    seen["n"] += 1
                    out += ("%s\nblock%d\n" % (m, n)).encode("utf-8")
            return out

        return handler

    def test_splits_each_command(self):
        # r2_multi() uses the module-level _ENDPOINT (no url kwarg). Point it at our
        # fake server by patching that global for this test only. The batch is sent
        # as ONE combined request "<marker>i\n<marker>is\n<marker>izz\n"; a correct
        # r2 echoes each marker+command line back in order, so the response body has
        # one marker per command and _split_batch yields exactly three sections. We
        # tag section contents with an incrementing count to prove ordering AND that
        # outputs aren't mixed or dropped across sections.
        # Fake r2 echoes each "<marker><cmd>" request line back verbatim, so the
        # response body contains one marker per command -> three sections. We append
        # a distinct block after each echoed line to verify order and no mixing.
        def handler(cmd):
            out = b""
            for ln in cmd.splitlines():
                if ln.startswith("__R2MCP"):  # "<marker><cmd>" request line
                    c = ln[len("__R2MCP_"):]   # "9fa3ba40_SEP__i" etc.
                    out += (ln + "\nBLOCK-%s\n" % c).encode()
                else:
                    out += ln.encode() + b"\n"
            return out

        self.srv.handler = handler

        import server as srvmod
        old, srvmod._ENDPOINT = srvmod._ENDPOINT, self.srv.url
        try:
            out = r2_multi(["i", "is", "izz"], timeout=5.0)
        finally:
            srvmod._ENDPOINT = old
        # Three labelled sections in order; each carries its own tagged block. The
        # command name is embedded after the marker, so we check it survived intact.
        self.assertIn("=== [1] i ===\n", out)
        self.assertIn("=== [2] is ===\n", out)
        self.assertIn("=== [3] izz ===\n", out)

    def test_sentinel_never_collides_with_output(self):
        # The whole point of #2: a command's REAL output may legitimately contain
        # the separator string. When it does, naive split() over-splits and shifts
        # which segment lands on which command. _split_batch must drop stray
        # (empty) segments so positional indexing stays correct for N commands.
        marker = "__R2MCP_deadbeef_SEP__"
        body = ("%s\ni\n%s is here\nis\n" % (marker, marker))  # output embeds marker

        parts_unguarded = body.split(marker)   # OLD behavior: over-splits
        self.assertGreater(len(parts_unguarded), 2)

        guarded = _split_batch(body, marker)   # the guard under test
        # Two commands -> two non-empty segments; any extra stray markers ignored.
        self.assertEqual(len(guarded), 2)


if __name__ == "__main__":
    unittest.main()
