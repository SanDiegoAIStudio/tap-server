#!/usr/bin/env python3
"""source: each security check must fail its named test when that one line is broken."""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "tap_server.py"
TESTS = ROOT / "tests" / "test_tap_server.py"

MUTATIONS = [
    (
        "token missing",
        "test_token_missing_on_tap",
        '    if presented is None or presented == "":\n        return False\n',
        '    if presented is None or presented == "":\n        return True\n',
    ),
    (
        "token wrong",
        "test_token_wrong_on_tap",
        "    return secrets.compare_digest(\n"
        '        presented.encode("utf-8"),\n'
        '        expected.encode("utf-8"),\n'
        "    )\n",
        "    return True\n",
    ),
    (
        "token check on /tap",
        "test_token_missing_on_tap",
        "        if not token_matches(presented, token):\n"
        '            self._reject(403, "bad or missing tap token")\n',
        "        if False:\n"
        '            self._reject(403, "bad or missing tap token")\n',
    ),
    (
        "origin rule on /tap",
        "test_web_origin_refused_on_tap",
        '        if origin_is_web(self.headers.get("Origin")):\n'
        '            self._reject(403, "web origins are not allowed to tap")\n',
        '        if False:\n'
        '            self._reject(403, "web origins are not allowed to tap")\n',
    ),
    (
        "origin rule on /page",
        "test_web_origin_refused_on_page",
        '        if origin_is_web(self.headers.get("Origin")):\n'
        '            self._reject(403, "web origins are not allowed")\n',
        '        if False:\n'
        '            self._reject(403, "web origins are not allowed")\n',
    ),
    (
        "web origin test",
        "test_web_origin_refused_on_tap",
        '    if origin.startswith("file:"):\n        return False\n    return True\n',
        '    if origin.startswith("file:"):\n        return False\n    return False\n',
    ),
    (
        "origin null",
        "test_origin_null_accepted",
        '    if origin is None or origin == "null":\n        return False\n',
        "    if False:\n        return False\n",
    ),
    (
        "file origin",
        "test_file_origin_accepted",
        '    if origin.startswith("file:"):\n        return False\n',
        "    if False:\n        return False\n",
    ),
    (
        "command list lookup",
        "test_unknown_command_refused",
        "        argv = commands.get(cmd)\n",
        '        argv = commands.get("echo")\n',
    ),
    (
        "unknown command branch",
        "test_unknown_command_refused",
        "        if argv is None:\n",
        "        if False:\n",
    ),
    (
        "listed command",
        "test_listed_command_returns_output",
        "            proc = subprocess.Popen(\n"
        "                argv,\n"
        "                stdout=subprocess.PIPE,\n"
        "                stderr=subprocess.PIPE,\n"
        "                stdin=subprocess.DEVNULL,\n"
        "                text=True,\n"
        '                encoding="utf-8",\n'
        '                errors="replace",\n'
        "                start_new_session=True,\n"
        "            )\n",
        "            proc = subprocess.Popen(\n"
        '                ["/bin/echo", "x"],\n'
        "                stdout=subprocess.PIPE,\n"
        "                stderr=subprocess.PIPE,\n"
        "                text=True,\n"
        '                encoding="utf-8",\n'
        '                errors="replace",\n'
        "            )\n",
    ),
    (
        "body size cap",
        "test_oversized_body_refused",
        "        if size > MAX_BODY:\n",
        "        if False:\n",
    ),
    (
        "page token check accepts the command token",
        "test_command_token_refused_on_page",
        "        if not token_matches(presented, token):\n"
        '            self._reject(403, "bad or missing page token")\n',
        "        if not (token_matches(presented, token)"
        " or token_matches(presented, load_command_token())):\n"
        '            self._reject(403, "bad or missing page token")\n',
    ),
    (
        "command token check accepts the page token",
        "test_page_token_refused_on_tap",
        "        if not token_matches(presented, token):\n"
        '            self._reject(403, "bad or missing tap token")\n',
        "        if not (token_matches(presented, token)"
        " or token_matches(presented, load_page_token())):\n"
        '            self._reject(403, "bad or missing tap token")\n',
    ),
    (
        "token before body on /page",
        "test_page_checks_token_before_body",
        '        presented = self.headers.get("X-Tap-Token")\n'
        "        if not token_matches(presented, token):\n"
        '            self._reject(403, "bad or missing page token")\n'
        "            return\n"
        "        body = self.read_json_object()\n"
        "        if body is None:\n"
        "            return\n",
        "        body = self.read_json_object()\n"
        "        if body is None:\n"
        "            return\n"
        '        presented = self.headers.get("X-Tap-Token")\n'
        "        if not token_matches(presented, token):\n"
        '            self._reject(403, "bad or missing page token")\n'
        "            return\n",
    ),
    (
        "health",
        "test_health_answers",
        '        if path == "/health":\n',
        "        if False:\n",
    ),
    (
        "unknown route",
        "test_unknown_route_refused",
        '        self._reject(404, "unknown endpoint")\n',
        '        self._reject(200, "unknown endpoint")\n',
    ),
    (
        "malformed body",
        "test_malformed_body_refused",
        "        except json.JSONDecodeError:\n"
        '            self._send(400, "body must be JSON")\n'
        "            return None\n",
        "        except json.JSONDecodeError:\n"
        "            body = {}\n",
    ),
    (
        "check without origin",
        "test_check_without_origin_needs_a_note",
        '        if cli and kind == "check" and not note:\n',
        "        if False:\n",
    ),
    (
        "loopback",
        "test_binds_loopback",
        'BIND_HOST = "127.0.0.1"\n',
        'BIND_HOST = "0.0.0.0"\n',
    ),
    (
        "token file mode",
        "test_missing_token_files_are_created_mode_600",
        "TOKEN_FILE_MODE = 0o600\n",
        "TOKEN_FILE_MODE = 0o644\n",
    ),
    (
        "token javascript file mode",
        "test_token_js_files_are_written_beside_the_token_files",
        "TOKEN_JS_MODE = 0o600\n",
        "TOKEN_JS_MODE = 0o644\n",
    ),
    (
        "token javascript file content",
        "test_token_js_files_are_written_beside_the_token_files",
        """    want = 'window.%s = "%s";\\n' % (variable, token)\n""",
        """    want = 'var %s = "%s";\\n' % (variable, token)\n""",
    ),
    (
        "token javascript file follows the token file",
        "test_token_js_files_follow_a_replaced_token_file",
        '        if not js_path.exists() or js_path.read_text(encoding="utf-8") != want:\n',
        "        if not js_path.exists():\n",
    ),
    (
        "token returned by a route",
        "test_no_route_returns_a_token",
        '            self._send(200, "ok")\n',
        '            self._send(200, "ok " + load_command_token())\n',
    ),
    (
        "preflight no longer allows the token header",
        "test_preflight_allows_the_token_header",
        '"X-Tap-Token, Content-Type"',
        '"Content-Type"',
    ),
    (
        "command timeout argument removed",
        "test_command_timeout_answers_504",
        "                stdout, stderr = proc.communicate(timeout=COMMAND_TIMEOUT)\n",
        "                stdout, stderr = proc.communicate()\n",
    ),
    (
        "commands file kept after the first read",
        "test_commands_file_is_read_on_every_request",
        '    data = json.loads(commands_path().read_text(encoding="utf-8"))\n',
        '    cache = load_commands.__dict__.setdefault("c", {})\n'
        "    key = str(commands_path())\n"
        "    if key not in cache:\n"
        '        cache[key] = commands_path().read_text(encoding="utf-8")\n'
        "    data = json.loads(cache[key])\n",
    ),
    (
        "text cap raised out of reach",
        "test_text_longer_than_4000_refused",
        "            if len(text) > 4000:\n",
        "            if len(text) > 4000000:\n",
    ),
    (
        "check note cap raised out of reach",
        "test_check_note_longer_than_1000_refused",
        "            if len(note) > 1000:\n",
        "            if len(note) > 1000000:\n",
    ),
    (
        "note requires text branch removed",
        "test_note_requires_text",
        '        elif kind == "note":\n'
        '            self._send(400, "note requires text")\n'
        "            return\n",
        "",
    ),
    (
        "slug rule off",
        "test_invalid_slug_refused",
        "        if not SLUG_RE.match(slug):\n",
        "        if False:\n",
    ),
    (
        "kind rule off",
        "test_invalid_kind_refused",
        "        if kind not in PAGE_KINDS:\n",
        "        if False:\n",
    ),
    (
        "card_id rule off",
        "test_invalid_card_id_refused",
        "            if not CARD_ID_RE.match(card_id):\n",
        "            if False:\n",
    ),
    (
        "content length that is not a number read as zero",
        "test_bad_content_length_refused",
        "        if not (length.isascii() and length.isdigit()) or len(length) > 7:\n"
        "            return None\n",
        "        if not (length.isascii() and length.isdigit()) or len(length) > 7:\n"
        "            return 0\n",
    ),
    (
        "sid and id copy loop removed",
        "test_page_row_carries_the_accepted_fields",
        '        for key in ("sid", "id"):\n',
        "        for key in ():\n",
    ),
    (
        "every GET answered ok",
        "test_get_is_handled_as_post",
        '        if path == "/health":\n'
        '            self._send(200, "ok")\n'
        "            return\n",
        "        if True:\n"
        '            self._send(200, "ok")\n'
        "            return\n",
    ),
    (
        "token file chmod removed",
        "test_a_loose_token_file_is_set_back_to_600",
        "                os.chmod(str(path), TOKEN_FILE_MODE)\n",
        "                pass\n",
    ),
    (
        "token script file chmod removed",
        "test_a_loose_token_script_file_is_set_back_to_600",
        "            os.chmod(str(js_path), TOKEN_JS_MODE)\n",
        "            pass\n",
    ),
    (
        "token file written in place with the temporary file left behind",
        "test_a_token_rewrite_leaves_no_temporary_file",
        "            os.replace(str(tmp), str(path))\n",
        '            path.write_text(text, encoding="utf-8")\n',
    ),
    (
        "unreadable token file answer removed",
        "test_an_unreadable_token_file_answers_500",
        "        except (OSError, UnicodeDecodeError):\n",
        "        except ZeroDivisionError:\n",
    ),
    (
        "recursion error not caught",
        "test_deeply_nested_json_answers_400",
        "        except RecursionError:\n",
        "        except ZeroDivisionError:\n",
    ),
    (
        "timeout stops only the direct child",
        "test_a_timeout_also_stops_the_processes_the_command_started",
        "                    os.killpg(proc.pid, signal.SIGKILL)\n",
        "                    proc.kill()\n",
    ),
    (
        "reply cut removed",
        "test_a_long_reply_is_cut_with_a_note",
        "        if len(reply) > MAX_REPLY:\n",
        "        if False:\n",
    ),
    (
        "page log opened with mode 644 and no fchmod",
        "test_the_page_log_is_mode_600",
        "            fd = os.open(str(path), os.O_WRONLY | os.O_APPEND | os.O_CREAT, PAGE_LOG_MODE)\n"
        "            try:\n"
        "                os.fchmod(fd, PAGE_LOG_MODE)\n",
        "            fd = os.open(str(path), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)\n"
        "            try:\n"
        "                pass\n",
    ),
    (
        "output is decoded strictly",
        "test_output_that_is_not_utf8_is_shown_with_the_replacement_character",
        '                errors="replace",\n',
        "",
    ),
    (
        "output is decoded strictly, so a timeout after it answers 500",
        "test_a_timeout_answers_504_even_after_output_that_is_not_utf8",
        '                errors="replace",\n',
        "",
    ),
    (
        "output decoded with the locale encoding",
        "test_output_is_decoded_as_utf8_whatever_the_locale",
        '                encoding="utf-8",\n',
        "",
    ),
]


def test_names():
    names = re.findall(r"^    def (test_[a-z0-9_]+)\(", TESTS.read_text(encoding="utf-8"), re.M)
    return names


def run_suite(server_file):
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.pop("TAP_SERVER_FILE", None)
    env.pop("TAP_TOKEN_FILE", None)
    env.pop("TAP_PAGE_TOKEN_FILE", None)
    env.pop("TAP_COMMANDS_FILE", None)
    env.pop("TAP_PAGE_LOG", None)
    env.pop("TAP_PORT", None)
    if server_file is not None:
        env["TAP_SERVER_FILE"] = str(server_file)
    try:
        result = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-q"],
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired as error:
        out = (error.stdout or "") + "\n" + (error.stderr or "")
        return False, out
    return result.returncode == 0, (result.stdout or "") + "\n" + (result.stderr or "")


def named_test_failed(output, test_name):
    if ("FAIL: " + test_name) in output or ("ERROR: " + test_name) in output:
        return True
    return False


def main():
    source = SOURCE.read_text(encoding="utf-8")
    names = test_names()
    mapped = [item[1] for item in MUTATIONS]
    missing = [name for name in names if name not in mapped]
    extra = [name for name in mapped if name not in names]
    if missing or extra:
        for name in missing:
            print("survived: %s" % name)
        for name in extra:
            print("survived: %s" % name)
        return 1
    ok, output = run_suite(None)
    if not ok:
        sys.stderr.write(output)
        print("could not do it: unmutated suite failed")
        return 1
    failed = False
    for label, test_name, old, new in MUTATIONS:
        if source.count(old) != 1:
            print("survived: %s" % label)
            failed = True
            continue
        mutated = source.replace(old, new, 1)
        try:
            compile(mutated, "tap_server.py", "exec")
        except SyntaxError:
            print("survived: %s" % label)
            failed = True
            continue
        with tempfile.TemporaryDirectory(prefix="tap-mutation-") as temporary:
            copy_path = Path(temporary) / "tap_server.py"
            copy_path.write_text(mutated, encoding="utf-8")
            suite_ok, suite_output = run_suite(copy_path)
        if (not suite_ok) and named_test_failed(suite_output, test_name):
            print("killed: %s" % label)
        else:
            print("survived: %s" % label)
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
