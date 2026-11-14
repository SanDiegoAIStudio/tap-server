#!/usr/bin/env python3
"""source: loopback tap server rules, each one over real HTTP."""
from __future__ import annotations

import http.client
import json
import os
import secrets
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote

ENV_KEYS = (
    "TAP_TOKEN_FILE",
    "TAP_PAGE_TOKEN_FILE",
    "TAP_COMMANDS_FILE",
    "TAP_PAGE_LOG",
    "TAP_PORT",
)


def load_tap_server():
    import importlib.util
    import sys

    path = os.environ.get("TAP_SERVER_FILE")
    if not path:
        path = str(Path(__file__).resolve().parent.parent / "tap_server.py")
    spec = importlib.util.spec_from_file_location("tap_server_under_test", path)
    if spec is None or spec.loader is None:
        raise ImportError("could not load tap server")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TapServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.saved_env = {key: os.environ.get(key) for key in ENV_KEYS}
        cls.tmp = tempfile.TemporaryDirectory(prefix="tap-server-test-")
        root = Path(cls.tmp.name)
        cls.token_file = root / "token"
        cls.page_token_file = root / "page-token"
        cls.commands_file = root / "commands.json"
        cls.page_log = root / "page.jsonl"
        cls.token = secrets.token_hex(24)
        cls.page_token = secrets.token_hex(24)
        cls.token_file.write_text(cls.token, encoding="utf-8")
        cls.page_token_file.write_text(cls.page_token, encoding="utf-8")
        cls.commands_file.write_text(
            json.dumps({"echo": ["/bin/echo", "tap-ok"]}),
            encoding="utf-8",
        )
        os.environ["TAP_TOKEN_FILE"] = str(cls.token_file)
        os.environ["TAP_PAGE_TOKEN_FILE"] = str(cls.page_token_file)
        os.environ["TAP_COMMANDS_FILE"] = str(cls.commands_file)
        os.environ["TAP_PAGE_LOG"] = str(cls.page_log)
        os.environ.pop("TAP_PORT", None)
        cls.server = None
        try:
            cls.tap = load_tap_server()
            cls.server = cls.tap.make_server(0)
            cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
            cls.thread.start()
            cls.wait_until_up()
        except Exception:
            if cls.server is not None:
                cls.server.shutdown()
                cls.server.server_close()
            cls.tmp.cleanup()
            raise

    @classmethod
    def wait_until_up(cls):
        deadline = time.time() + 2
        last = None
        url = "http://127.0.0.1:%s/health" % cls.server.server_port
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(url, timeout=0.2) as response:
                    response.read()
                    return
            except urllib.error.HTTPError:
                return
            except Exception as error:
                last = error
                time.sleep(0.02)
        raise RuntimeError("server did not answer /health: %s" % last)

    @classmethod
    def tearDownClass(cls):
        try:
            if cls.server is not None:
                cls.server.shutdown()
                cls.server.server_close()
            if getattr(cls, "thread", None) is not None:
                cls.thread.join(timeout=5)
        finally:
            cls.tmp.cleanup()
            for key, value in cls.saved_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def setUp(self):
        self.page_log.write_text("", encoding="utf-8")

    def point_token_files_at(self, directory):
        """Send the running server to a fresh pair of token files for one test."""
        names = ("TAP_TOKEN_FILE", "TAP_PAGE_TOKEN_FILE")
        previous = {name: os.environ.get(name) for name in names}

        def restore():
            for name, value in previous.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

        self.addCleanup(restore)
        os.environ["TAP_TOKEN_FILE"] = str(directory / "token")
        os.environ["TAP_PAGE_TOKEN_FILE"] = str(directory / "page-token")

    def request(self, path, method, headers, body):
        target = "http://127.0.0.1:%s%s" % (self.server.server_port, path)
        req = urllib.request.Request(target, data=body, headers=headers or {}, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            try:
                return error.code, error.read()
            finally:
                error.close()

    def request_full(self, path, method, headers, body):
        """Like request, but also returns the response headers."""
        target = "http://127.0.0.1:%s%s" % (self.server.server_port, path)
        req = urllib.request.Request(target, data=body, headers=headers or {}, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status, response.headers, response.read()
        except urllib.error.HTTPError as error:
            try:
                return error.code, error.headers, error.read()
            finally:
                error.close()

    def set_commands(self, commands):
        """Rewrite the commands file for one test and put the old text back after."""
        old = self.commands_file.read_text(encoding="utf-8")
        self.addCleanup(self.commands_file.write_text, old, encoding="utf-8")
        self.commands_file.write_text(json.dumps(commands), encoding="utf-8")

    def page_lines(self):
        return [line for line in self.page_log_text().splitlines() if line]

    def post_tap(self, cmd, token, origin):
        headers = {}
        if origin is not None:
            headers["Origin"] = origin
        if token is not None:
            headers["X-Tap-Token"] = token
        return self.request("/tap?cmd=" + quote(cmd), "POST", headers, b"")

    def post_page(self, payload, token, origin):
        headers = {"Content-Type": "application/json"}
        if origin is not None:
            headers["Origin"] = origin
        if token is not None:
            headers["X-Tap-Token"] = token
        raw = json.dumps(payload).encode("utf-8")
        return self.request("/page", "POST", headers, raw)

    def page_log_text(self):
        return self.page_log.read_text(encoding="utf-8")

    def test_token_missing_on_tap(self):
        """source: a tap with no token header is refused."""
        code, body = self.post_tap("echo", token=None, origin="null")
        self.assertEqual(code, 403)
        self.assertIn(b"bad or missing tap token", body)
        self.assertNotIn(b"tap-ok", body)

    def test_token_wrong_on_tap(self):
        """source: a tap with the wrong token is refused."""
        code, body = self.post_tap("echo", token="not-the-token", origin="null")
        self.assertEqual(code, 403)
        self.assertIn(b"bad or missing tap token", body)
        self.assertNotIn(b"tap-ok", body)

    def test_web_origin_refused_on_tap(self):
        """source: a web Origin is refused on /tap even with the right token."""
        code, body = self.post_tap("echo", token=self.token, origin="https://web.invalid")
        self.assertEqual(code, 403)
        self.assertIn(b"web origins are not allowed", body)
        self.assertNotIn(b"tap-ok", body)

    def test_web_origin_refused_on_page(self):
        """source: a web Origin is refused on /page even with the right token."""
        code, body = self.post_page(
            {"slug": "alpha", "kind": "note", "text": "nope"},
            token=self.page_token,
            origin="https://web.invalid",
        )
        self.assertEqual(code, 403)
        self.assertIn(b"web origins are not allowed", body)
        self.assertEqual(self.page_log_text(), "")

    def test_origin_null_accepted(self):
        """source: Origin null, which a disk page can send, is accepted."""
        code, _body = self.post_tap("echo", token=self.token, origin="null")
        self.assertEqual(code, 200)

    def test_file_origin_accepted(self):
        """source: a file origin, which a disk page can send, is accepted."""
        code, _body = self.post_tap("echo", token=self.token, origin="file://")
        self.assertEqual(code, 200)

    def test_unknown_command_refused(self):
        """source: a command name that is not in the list is refused."""
        code, body = self.post_tap("not-listed", token=self.token, origin="null")
        self.assertEqual(code, 400)
        self.assertIn(b"invalid tap", body)
        self.assertNotIn(b"tap-ok", body)

    def test_listed_command_returns_output(self):
        """source: a listed command runs and its output is the response."""
        code, body = self.post_tap("echo", token=self.token, origin="null")
        self.assertEqual(code, 200)
        self.assertEqual(body, b"tap-ok")

    def test_oversized_body_refused(self):
        """source: a body over the size cap is refused and not written."""
        payload = {
            "slug": "demo",
            "kind": "note",
            "text": "hi",
            "pad": "x" * (self.tap.MAX_BODY + 1),
        }
        raw = json.dumps(payload).encode("utf-8")
        self.assertGreater(len(raw), self.tap.MAX_BODY)
        code, body = self.post_page(payload, token=self.page_token, origin="null")
        self.assertEqual(code, 400)
        self.assertIn(b"body too large", body)
        self.assertEqual(self.page_log_text(), "")

    def test_command_token_refused_on_page(self):
        """source: the command token does not open /page."""
        code, body = self.post_page(
            {"slug": "alpha", "kind": "note", "text": "cross"},
            token=self.token,
            origin="null",
        )
        self.assertEqual(code, 403)
        self.assertIn(b"bad or missing page token", body)
        self.assertEqual(self.page_log_text(), "")
        code, _body = self.post_page(
            {"slug": "alpha", "kind": "note", "text": "own token"},
            token=self.page_token,
            origin="null",
        )
        self.assertEqual(code, 204)
        saved = json.loads(self.page_log_text())
        self.assertEqual(saved["slug"], "alpha")
        self.assertEqual(saved["kind"], "note")
        self.assertEqual(saved["text"], "own token")
        self.assertTrue(saved.get("received_ts"))

    def test_page_token_refused_on_tap(self):
        """source: the page token does not open /tap."""
        code, body = self.post_tap("echo", token=self.page_token, origin="null")
        self.assertEqual(code, 403)
        self.assertIn(b"bad or missing tap token", body)
        self.assertNotIn(b"tap-ok", body)

    def test_page_checks_token_before_body(self):
        """source: /page checks the token before it reads the body."""
        code, body = self.request(
            "/page",
            "POST",
            {"Origin": "null", "Content-Type": "application/json"},
            b"{",
        )
        self.assertEqual(code, 403)
        self.assertIn(b"bad or missing page token", body)
        self.assertNotIn(b"JSON", body)
        code, body = self.request(
            "/page",
            "POST",
            {
                "Origin": "null",
                "Content-Type": "application/json",
                "X-Tap-Token": self.token,
            },
            b"{",
        )
        self.assertEqual(code, 403)
        self.assertNotIn(b"JSON", body)
        self.assertEqual(self.page_log_text(), "")

    def test_health_answers(self):
        """source: GET /health answers ok without a token."""
        code, body = self.request("/health", "GET", {}, None)
        self.assertEqual(code, 200)
        self.assertEqual(body, b"ok")

    def test_unknown_route_refused(self):
        """source: an unknown path is refused."""
        code, body = self.request("/not-a-route", "POST", {"Origin": "null"}, b"")
        self.assertEqual(code, 404)
        self.assertIn(b"unknown endpoint", body)

    def test_malformed_body_refused(self):
        """source: a page body that is not JSON is refused when the token is right."""
        code, body = self.request(
            "/page",
            "POST",
            {
                "Origin": "null",
                "Content-Type": "application/json",
                "X-Tap-Token": self.page_token,
            },
            b"{",
        )
        self.assertEqual(code, 400)
        self.assertIn(b"body must be JSON", body)
        self.assertEqual(self.page_log_text(), "")

    def test_check_without_origin_needs_a_note(self):
        """source: a check with no browser Origin is refused unless it carries a note."""
        slug = "cli"
        code, body = self.post_page(
            {"slug": slug, "kind": "check", "text": "checked"},
            token=self.page_token,
            origin=None,
        )
        self.assertEqual(code, 400)
        self.assertIn(
            b"a check without a browser Origin needs a note naming whose words it carries",
            body,
        )
        self.assertEqual(self.page_log_text(), "")
        code, body = self.post_page(
            {"slug": slug, "kind": "check", "text": "checked", "note": "reviewed"},
            token=self.page_token,
            origin=None,
        )
        self.assertEqual(code, 204, body)
        saved = json.loads(self.page_log_text())
        self.assertEqual(saved["note"], "reviewed")
        self.page_log.write_text("", encoding="utf-8")
        code, body = self.post_page(
            {"slug": slug, "kind": "check"},
            token=self.page_token,
            origin="null",
        )
        self.assertEqual(code, 204, body)

    def test_binds_loopback(self):
        """source: the listening address is 127.0.0.1."""
        self.assertEqual(self.server.server_address[0], "127.0.0.1")

    def test_missing_token_files_are_created_mode_600(self):
        """source: each missing token file is created with mode 600 and is not a guessable value."""
        fresh = Path(self.tmp.name) / "fresh-mode"
        self.point_token_files_at(fresh)
        code, _body = self.post_tap("echo", token="not-the-token", origin="null")
        self.assertEqual(code, 403)
        code, _body = self.post_page(
            {"slug": "alpha", "kind": "note", "text": "x"},
            token="not-the-token",
            origin="null",
        )
        self.assertEqual(code, 403)
        made = []
        for name in ("token", "page-token"):
            path = fresh / name
            self.assertTrue(path.is_file(), name)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600, name)
            value = path.read_text(encoding="utf-8")
            self.assertEqual(len(value), 48, name)
            int(value, 16)
            made.append(value)
        self.assertNotEqual(made[0], made[1])

    def test_token_js_files_are_written_beside_the_token_files(self):
        """source: each token script file sits beside its token file, has the exact text and mode 600."""
        fresh = Path(self.tmp.name) / "fresh-js"
        self.point_token_files_at(fresh)
        self.post_tap("echo", token="x", origin="null")
        self.post_page({"slug": "a", "kind": "note", "text": "x"}, token="x", origin="null")
        tap_token = (fresh / "token").read_text(encoding="utf-8")
        page_token = (fresh / "page-token").read_text(encoding="utf-8")
        tap_js = fresh / "tap-token.js"
        page_js = fresh / "page-token.js"
        self.assertEqual(
            tap_js.read_bytes(),
            ('window.TAP_TOKEN = "%s";\n' % tap_token).encode("utf-8"),
        )
        self.assertEqual(
            page_js.read_bytes(),
            ('window.PAGE_TOKEN = "%s";\n' % page_token).encode("utf-8"),
        )
        self.assertEqual(tap_js.stat().st_mode & 0o777, 0o600)
        self.assertEqual(page_js.stat().st_mode & 0o777, 0o600)

    def test_token_js_files_follow_a_replaced_token_file(self):
        """source: replacing a token file changes the token and its script file with no restart."""
        fresh = Path(self.tmp.name) / "fresh-follow"
        self.point_token_files_at(fresh)
        self.post_tap("echo", token="x", origin="null")
        self.post_page({"slug": "a", "kind": "note", "text": "x"}, token="x", origin="null")
        new_tap = secrets.token_hex(24)
        new_page = secrets.token_hex(24)
        (fresh / "token").write_text(new_tap + "\n", encoding="utf-8")
        (fresh / "page-token").write_text(new_page + "\n", encoding="utf-8")
        code, _body = self.post_tap("echo", token=new_tap, origin="null")
        self.assertEqual(code, 200)
        code, _body = self.post_page(
            {"slug": "a", "kind": "note", "text": "after"},
            token=new_page,
            origin="null",
        )
        self.assertEqual(code, 204)
        self.assertEqual(
            (fresh / "tap-token.js").read_bytes(),
            ('window.TAP_TOKEN = "%s";\n' % new_tap).encode("utf-8"),
        )
        self.assertEqual(
            (fresh / "page-token.js").read_bytes(),
            ('window.PAGE_TOKEN = "%s";\n' % new_page).encode("utf-8"),
        )
        self.assertEqual((fresh / "tap-token.js").stat().st_mode & 0o777, 0o600)
        code, _body = self.post_tap("echo", token=self.token, origin="null")
        self.assertEqual(code, 403)

    def test_no_route_returns_a_token(self):
        """source: no GET route returns either token in its body."""
        paths = (
            "/health",
            "/token",
            "/page-token",
            "/tap-token.js",
            "/run/tap-token.js",
            "/run/page-token.js",
        )
        for path in paths:
            code, body = self.request(path, "GET", {}, None)
            self.assertNotIn(self.token.encode("utf-8"), body, path)
            self.assertNotIn(self.page_token.encode("utf-8"), body, path)
            if path != "/health":
                self.assertIn(code, (403, 404), path)


    def test_preflight_allows_the_token_header(self):
        """source: the CORS preflight answer allows the token header, Content-Type and POST."""
        for path in ("/tap?cmd=echo", "/page"):
            code, headers, _body = self.request_full(
                path,
                "OPTIONS",
                {
                    "Origin": "null",
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "x-tap-token, content-type",
                },
                None,
            )
            self.assertEqual(code, 204, path)
            allowed = headers.get("Access-Control-Allow-Headers") or ""
            self.assertIn("X-Tap-Token", allowed, path)
            self.assertIn("Content-Type", allowed, path)
            self.assertIn("POST", headers.get("Access-Control-Allow-Methods") or "", path)
            self.assertIsNotNone(headers.get("Access-Control-Allow-Origin"), path)

    def test_command_timeout_answers_504(self):
        """source: a command that outlives the timeout is stopped and answered with 504."""
        previous = self.tap.COMMAND_TIMEOUT

        def restore():
            self.tap.COMMAND_TIMEOUT = previous

        self.addCleanup(restore)
        self.tap.COMMAND_TIMEOUT = 1
        self.set_commands({"slow": [sys.executable, "-c", "import time; time.sleep(5)"]})
        started = time.time()
        code, body = self.post_tap("slow", token=self.token, origin="null")
        elapsed = time.time() - started
        self.assertEqual(code, 504)
        self.assertIn(b"command timed out", body)
        self.assertLess(elapsed, 4)

    def test_commands_file_is_read_on_every_request(self):
        """source: the commands file is read again on every request, so an edit needs no restart."""
        self.set_commands({"old": ["/bin/echo", "old-ok"]})
        code, body = self.post_tap("old", token=self.token, origin="null")
        self.assertEqual(code, 200)
        self.assertEqual(body, b"old-ok")
        self.commands_file.write_text(
            json.dumps({"fresh": ["/bin/echo", "fresh-ok"]}),
            encoding="utf-8",
        )
        code, body = self.post_tap("old", token=self.token, origin="null")
        self.assertEqual(code, 400)
        self.assertNotIn(b"old-ok", body)
        code, body = self.post_tap("fresh", token=self.token, origin="null")
        self.assertEqual(code, 200)
        self.assertEqual(body, b"fresh-ok")

    def test_text_longer_than_4000_refused(self):
        """source: note text over 4000 characters is refused and not written."""
        code, body = self.post_page(
            {"slug": "demo", "kind": "note", "text": "a" * 4001},
            token=self.page_token,
            origin="null",
        )
        self.assertEqual(code, 400)
        self.assertIn(b"4000", body)
        self.assertEqual(self.page_lines(), [])
        code, _body = self.post_page(
            {"slug": "demo", "kind": "note", "text": "a" * 4000},
            token=self.page_token,
            origin="null",
        )
        self.assertEqual(code, 204)
        self.assertEqual(len(self.page_lines()), 1)

    def test_check_note_longer_than_1000_refused(self):
        """source: the note on a check over 1000 characters is refused and not written."""
        code, body = self.post_page(
            {"slug": "demo", "kind": "check", "text": "checked", "note": "n" * 1001},
            token=self.page_token,
            origin="null",
        )
        self.assertEqual(code, 400)
        self.assertIn(b"1000", body)
        self.assertEqual(self.page_lines(), [])
        code, _body = self.post_page(
            {"slug": "demo", "kind": "check", "text": "checked", "note": "n" * 1000},
            token=self.page_token,
            origin="null",
        )
        self.assertEqual(code, 204)
        self.assertEqual(len(self.page_lines()), 1)

    def test_note_requires_text(self):
        """source: a note with no text, or only spaces, is refused and not written."""
        code, body = self.post_page(
            {"slug": "demo", "kind": "note"},
            token=self.page_token,
            origin="null",
        )
        self.assertEqual(code, 400)
        self.assertIn(b"note requires text", body)
        code, _body = self.post_page(
            {"slug": "demo", "kind": "note", "text": "     "},
            token=self.page_token,
            origin="null",
        )
        self.assertEqual(code, 400)
        self.assertEqual(self.page_lines(), [])

    def test_invalid_slug_refused(self):
        """source: a slug that is missing or breaks the slug rule is refused and not written."""
        bad = [
            {"kind": "note", "text": "x"},
            {"slug": "Upper", "kind": "note", "text": "x"},
            {"slug": "a/b", "kind": "note", "text": "x"},
            {"slug": ".dot", "kind": "note", "text": "x"},
            {"slug": "a" * 122, "kind": "note", "text": "x"},
        ]
        for payload in bad:
            code, body = self.post_page(payload, token=self.page_token, origin="null")
            self.assertEqual(code, 400, payload)
            self.assertIn(b"invalid slug", body, payload)
        self.assertEqual(self.page_lines(), [])
        code, _body = self.post_page(
            {"slug": "a" * 121, "kind": "note", "text": "x"},
            token=self.page_token,
            origin="null",
        )
        self.assertEqual(code, 204)
        self.assertEqual(len(self.page_lines()), 1)

    def test_invalid_kind_refused(self):
        """source: a kind that is missing or not check or note is refused and not written."""
        for payload in (
            {"slug": "demo", "text": "x"},
            {"slug": "demo", "kind": "delete", "text": "x"},
        ):
            code, body = self.post_page(payload, token=self.page_token, origin="null")
            self.assertEqual(code, 400, payload)
            self.assertIn(b"invalid kind", body, payload)
        self.assertEqual(self.page_lines(), [])

    def test_invalid_card_id_refused(self):
        """source: a card_id with a space, a slash or over 80 characters is refused and not written."""
        for card_id in ("has space", "has/slash", "c" * 81):
            code, body = self.post_page(
                {"slug": "demo", "kind": "note", "text": "x", "card_id": card_id},
                token=self.page_token,
                origin="null",
            )
            self.assertEqual(code, 400, card_id)
            self.assertIn(b"invalid card_id", body, card_id)
        self.assertEqual(self.page_lines(), [])
        code, _body = self.post_page(
            {"slug": "demo", "kind": "note", "text": "x", "card_id": "card-1.a:b_c"},
            token=self.page_token,
            origin="null",
        )
        self.assertEqual(code, 204)
        lines = self.page_lines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["card_id"], "card-1.a:b_c")

    def test_bad_content_length_refused(self):
        """source: a Content-Length that is not a number is refused and nothing is written."""
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        try:
            conn.putrequest("POST", "/page")
            conn.putheader("Content-Length", "abc")
            conn.putheader("Origin", "null")
            conn.putheader("X-Tap-Token", self.page_token)
            conn.endheaders()
            response = conn.getresponse()
            code = response.status
            body = response.read()
        finally:
            conn.close()
        self.assertEqual(code, 400)
        self.assertIn(b"bad Content-Length", body)
        self.assertEqual(self.page_lines(), [])

    def test_page_row_carries_the_accepted_fields(self):
        """source: a saved row carries the fields the page sent and a ts that is not ISO has no client_ts."""
        code, _body = self.post_page(
            {
                "slug": "demo",
                "kind": "note",
                "text": "hello",
                "card_id": "c-1",
                "ts": "2026-11-13T10:00:00Z",
                "queued": True,
                "sid": "session-1",
                "id": "item-1",
            },
            token=self.page_token,
            origin="null",
        )
        self.assertEqual(code, 204)
        code, _body = self.post_page(
            {"slug": "demo", "kind": "note", "text": "second", "ts": "not a time"},
            token=self.page_token,
            origin="null",
        )
        self.assertEqual(code, 204)
        lines = self.page_lines()
        self.assertEqual(len(lines), 2)
        first = json.loads(lines[0])
        self.assertEqual(first["slug"], "demo")
        self.assertEqual(first["kind"], "note")
        self.assertTrue(first.get("received_ts"))
        self.assertEqual(first["card_id"], "c-1")
        self.assertEqual(first["text"], "hello")
        self.assertEqual(first["ts"], "2026-11-13T10:00:00Z")
        self.assertEqual(first["client_ts"], "2026-11-13T10:00:00Z")
        self.assertIs(first["queued"], True)
        self.assertEqual(first["sid"], "session-1")
        self.assertEqual(first["id"], "item-1")
        second = json.loads(lines[1])
        self.assertEqual(second["ts"], "not a time")
        self.assertNotIn("client_ts", second)

    def test_get_is_handled_as_post(self):
        """source: a GET to a route is handled as the same path under POST, token rules included."""
        code, body = self.request(
            "/tap?cmd=echo", "GET", {"Origin": "null", "X-Tap-Token": self.token}, None
        )
        self.assertEqual(code, 200)
        self.assertEqual(body, b"tap-ok")
        code, body = self.request("/tap?cmd=echo", "GET", {"Origin": "null"}, None)
        self.assertEqual(code, 403)
        self.assertNotIn(b"tap-ok", body)


if __name__ == "__main__":
    unittest.main()
