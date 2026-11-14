#!/usr/bin/env python3
"""Loopback HTTP server for a page opened from disk on this machine.

A listed command can be run, and a checkbox tick or a note can be saved.
The server binds to 127.0.0.1. It keeps two tokens in two files: the command
token opens POST /tap and the page token opens POST /page. Neither opens the
other route. A page loads the tokens from two small local script files that the
server keeps in step with the token files. No route returns a token.
"""
from __future__ import annotations

import datetime
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

BIND_HOST = "127.0.0.1"
DEFAULT_PORT = 7373
MAX_BODY = 120_000
COMMAND_TIMEOUT = 90
TOKEN_FILE_MODE = 0o600
TOKEN_JS_MODE = 0o600
PAGE_LOG_MODE = 0o600
MAX_REPLY = 100_000
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,120}$")
PAGE_KINDS = {"check", "note"}
CARD_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,80}$")

_TOKEN_LOCK = threading.Lock()
_PAGE_LOCK = threading.Lock()


def _env_path(name, default):
    return Path(os.environ.get(name) or default)


def token_path():
    return _env_path("TAP_TOKEN_FILE", os.path.join("run", "token"))


def page_token_path():
    return _env_path("TAP_PAGE_TOKEN_FILE", os.path.join("run", "page-token"))


def commands_path():
    return _env_path("TAP_COMMANDS_FILE", os.path.join("run", "commands.json"))


def page_log_path():
    return _env_path("TAP_PAGE_LOG", os.path.join("run", "page.jsonl"))


def listen_port():
    raw = os.environ.get("TAP_PORT") or str(DEFAULT_PORT)
    try:
        port = int(raw)
    except ValueError:
        raise SystemExit("TAP_PORT must be a port number")
    if port < 0 or port > 65535:
        raise SystemExit("TAP_PORT must be a port number")
    return port


def _write_private(path, text, mode):
    """Write text to path and leave the file at exactly this mode.

    The text goes into a new file beside path and is moved into place, so a
    reader sees the old file or the whole new one, never half of it.
    """
    tmp = path.parent / (".%s.tmp.%s" % (path.name, secrets.token_hex(4)))
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        try:
            os.fchmod(fd, mode)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                fd = -1
                handle.write(text)
            os.replace(str(tmp), str(path))
        finally:
            if fd != -1:
                os.close(fd)
    except BaseException:
        try:
            os.unlink(str(tmp))
        except OSError:
            pass
        raise


def _sync_token_js(js_path, variable, token):
    """Keep the script file a page loads in step with its token file.

    A failed write is swallowed: the page then reports that it has no token.
    """
    want = 'window.%s = "%s";\n' % (variable, token)
    try:
        if not js_path.exists() or js_path.read_text(encoding="utf-8") != want:
            js_path.parent.mkdir(parents=True, exist_ok=True)
            _write_private(js_path, want, TOKEN_JS_MODE)
        elif (js_path.stat().st_mode & 0o777) != TOKEN_JS_MODE:
            os.chmod(str(js_path), TOKEN_JS_MODE)
    except OSError:
        pass


def _load_token(path, js_name, variable):
    """Return the token in path, creating the file when it is missing.

    The file is read again on every call, so replacing it changes the token
    with no restart. The script file beside it is brought in step each time.
    """
    with _TOKEN_LOCK:
        path.parent.mkdir(parents=True, exist_ok=True)
        token = ""
        if path.exists():
            if (path.stat().st_mode & 0o777) != TOKEN_FILE_MODE:
                os.chmod(str(path), TOKEN_FILE_MODE)
            token = path.read_text(encoding="utf-8").strip()
        if not token:
            token = secrets.token_hex(24)
            _write_private(path, token, TOKEN_FILE_MODE)
        _sync_token_js(path.parent / js_name, variable, token)
        return token


def load_command_token():
    """Token that opens POST /tap and nothing else."""
    return _load_token(token_path(), "tap-token.js", "TAP_TOKEN")


def load_page_token():
    """Token that opens POST /page and nothing else."""
    return _load_token(page_token_path(), "page-token.js", "PAGE_TOKEN")


def token_matches(presented, expected):
    if presented is None or presented == "":
        return False
    return secrets.compare_digest(
        presented.encode("utf-8"),
        expected.encode("utf-8"),
    )


def origin_is_web(origin):
    """True when Origin names a web page.

    A missing Origin, the string null, and a file origin do not.
    A page opened from disk sends one of those.
    """
    if origin is None or origin == "null":
        return False
    if origin.startswith("file:"):
        return False
    return True


def _page_client_ts(raw):
    """Body ts kept as client_ts only when it is a short ISO timestamp.

    A trailing Z is read as UTC. Anything else is dropped, never an error.
    """
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if not text or len(text) > 40:
        return None
    parsed = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        datetime.datetime.fromisoformat(parsed)
    except ValueError:
        return None
    return text


def load_commands():
    data = json.loads(commands_path().read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("commands file must be an object")
    commands = {}
    for name, argv in data.items():
        if not isinstance(name, str) or name == "":
            raise ValueError("bad command name")
        if (
            not isinstance(argv, list)
            or not argv
            or any((not isinstance(part, str) or part == "") for part in argv)
        ):
            raise ValueError("bad command")
        commands[name] = list(argv)
    return commands


def append_page_row(row):
    path = page_log_path()
    line = json.dumps(row, ensure_ascii=False) + "\n"
    try:
        with _PAGE_LOCK:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(path), os.O_WRONLY | os.O_APPEND | os.O_CREAT, PAGE_LOG_MODE)
            try:
                os.fchmod(fd, PAGE_LOG_MODE)
                with os.fdopen(fd, "a", encoding="utf-8") as handle:
                    fd = -1
                    handle.write(line)
            finally:
                if fd != -1:
                    os.close(fd)
    except OSError:
        return 500, "page log append failed"
    return 204, ""


class Handler(BaseHTTPRequestHandler):
    server_version = "tap-server/1"
    timeout = 30

    def _send(self, code, body):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def _content_length(self):
        """Declared body size, or None when the header is not a plain number."""
        length = self.headers.get("Content-Length")
        if length is None or length == "":
            return 0
        if not (length.isascii() and length.isdigit()) or len(length) > 7:
            return None
        return int(length)

    def _drain_body(self):
        """Read and drop a small unread body so the refusal reaches the client.

        Closing a socket with unread bytes can reset the connection and lose
        the reply that was just sent.
        """
        size = self._content_length()
        remaining = size if size and size <= 1_000_000 else 0
        try:
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    break
                remaining -= len(chunk)
        except OSError:
            pass

    def _reject(self, code, message):
        self._drain_body()
        self._send(code, message)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "X-Tap-Token, Content-Type")
        self.send_header("Access-Control-Max-Age", "600")
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            self._send(200, "ok")
            return
        # No route returns a token. A page gets its tokens from the two local
        # script files beside the token files, which a web page cannot load.
        self.do_POST()

    def read_body(self):
        size = self._content_length()
        if size is None:
            self._send(400, "bad Content-Length")
            return None
        if size > MAX_BODY:
            self._drain_body()
            self._send(400, "body too large")
            return None
        if size <= 0:
            return ""
        return self.rfile.read(size).decode("utf-8", errors="replace").strip()

    def read_json_object(self):
        raw = self.read_body()
        if raw is None:
            return None
        try:
            body = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            self._send(400, "body must be JSON")
            return None
        except RecursionError:
            self._send(400, "body must be JSON")
            return None
        if not isinstance(body, dict):
            self._send(400, "body must be a JSON object")
            return None
        return body

    def _route_token(self, loader):
        """Token for the route, or None after answering 500 when its file is unreadable."""
        try:
            return loader()
        except (OSError, UnicodeDecodeError):
            self._reject(500, "token file is unreadable")
            return None

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/page":
            self.handle_page()
            return
        if parsed.path == "/tap":
            self.handle_tap(parsed)
            return
        self._reject(404, "unknown endpoint")

    def handle_tap(self, parsed):
        if origin_is_web(self.headers.get("Origin")):
            self._reject(403, "web origins are not allowed to tap")
            return
        token = self._route_token(load_command_token)
        if token is None:
            return
        presented = self.headers.get("X-Tap-Token")
        if not token_matches(presented, token):
            self._reject(403, "bad or missing tap token")
            return
        if self.read_body() is None:
            return
        cmd = (parse_qs(parsed.query).get("cmd") or [""])[0]
        try:
            commands = load_commands()
        except (OSError, ValueError, json.JSONDecodeError):
            self._send(500, "commands file is unreadable")
            return
        argv = commands.get(cmd)
        if argv is None:
            self._send(400, "invalid tap: cmd=%r" % cmd)
            return
        try:
            proc = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                errors="replace",
                start_new_session=True,
            )
            try:
                stdout, stderr = proc.communicate(timeout=COMMAND_TIMEOUT)
            except subprocess.TimeoutExpired:
                # Stop the whole group, or a grandchild holding the pipe keeps us waiting.
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
                self._send(504, "command timed out")
                return
        except Exception as error:
            self._send(500, "tap failed: %s" % type(error).__name__)
            return
        reply = stdout.strip() or stderr.strip() or "(no reply)"
        if len(reply) > MAX_REPLY:
            reply = reply[:MAX_REPLY] + "\n(reply cut at 100000 characters)"
        self._send(200, reply)

    def handle_page(self):
        if origin_is_web(self.headers.get("Origin")):
            self._reject(403, "web origins are not allowed")
            return
        token = self._route_token(load_page_token)
        if token is None:
            return
        presented = self.headers.get("X-Tap-Token")
        if not token_matches(presented, token):
            self._reject(403, "bad or missing page token")
            return
        body = self.read_json_object()
        if body is None:
            return
        slug = str(body.get("slug") or "").strip()
        if not SLUG_RE.match(slug):
            self._send(400, "invalid slug: %r" % slug)
            return
        kind = str(body.get("kind") or "").strip()
        if kind not in PAGE_KINDS:
            self._send(400, "invalid kind: %r (want check|note)" % kind)
            return
        card_id = body.get("card_id")
        if card_id is not None:
            card_id = str(card_id).strip()
            if not CARD_ID_RE.match(card_id):
                self._send(400, "invalid card_id: %r" % card_id)
                return
        text = body.get("text")
        if text is not None:
            text = " ".join(str(text).split())
            if len(text) > 4000:
                self._send(400, "text must be at most 4000 chars")
                return
            if kind == "note" and len(text) < 1:
                self._send(400, "note text must be non-empty")
                return
        elif kind == "note":
            self._send(400, "note requires text")
            return
        note = body.get("note")
        if kind == "check" and note is not None:
            if not isinstance(note, str):
                self._send(400, "note must be text")
                return
            note = " ".join(note.split())
            if len(note) > 1000:
                self._send(400, "note must be at most 1000 chars")
                return
        cli = self.headers.get("Origin") is None
        if cli and kind == "check" and not note:
            self._send(400, "a check without a browser Origin needs a note naming whose words it carries")
            return
        row = {
            "slug": slug,
            "kind": kind,
            "received_ts": datetime.datetime.now().isoformat(timespec="seconds"),
        }
        if card_id is not None:
            row["card_id"] = card_id
        if text is not None:
            row["text"] = text
        if kind == "check" and note:
            row["note"] = note
        ts = body.get("ts")
        if ts is not None:
            ts = str(ts).strip()[:64]
        if ts:
            row["ts"] = ts
        if body.get("queued") is True:
            row["queued"] = True
        client_ts = _page_client_ts(body.get("ts"))
        if client_ts:
            row["client_ts"] = client_ts
        for key in ("sid", "id"):
            if key in body and body[key] is not None:
                val = str(body[key]).strip()[:80]
                if val:
                    row[key] = val
        code, msg = append_page_row(row)
        self._send(code, msg)

    def log_message(self, fmt, *args):
        sys.stdout.write("[tap] " + (fmt % args) + "\n")
        sys.stdout.flush()


class TapHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def make_server(port):
    return TapHTTPServer((BIND_HOST, port), Handler)


def main():
    command_file = token_path()
    page_file = page_token_path()
    load_command_token()
    load_page_token()
    server = make_server(listen_port())
    host, port = server.server_address[:2]
    print(
        "tap-server on %s:%s (command token file: %s, page token file: %s)"
        % (host, port, command_file, page_file)
    )
    sys.stdout.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
