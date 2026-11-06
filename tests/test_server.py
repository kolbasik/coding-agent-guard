"""The scoring server and guard.py's client for it, with a fake classifier: no ONNX needed."""
import contextlib
import io
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import guard  # noqa: E402
import server  # noqa: E402


class FakeModel:
    name = "fake"

    def __init__(self):
        self.calls = 0

    def score(self, text):
        self.calls += 1
        return 0.95 if "MARKER_HIGH" in text else 0.1


class FakeJudge:
    """An OpenAI-compatible chat endpoint that always answers with a fixed verdict."""

    def __init__(self, verdict):
        self.calls = 0
        judge = self

        class Handler(server.BaseHTTPRequestHandler):
            def do_POST(self):
                judge.calls += 1
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                body = json.dumps({"choices": [{"message": {"content": json.dumps({"injection": verdict})}}]}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.server = server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/v1"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


class Running:
    """A scoring server on a free local port for the length of a with-block."""

    def __init__(self, token="", judge_url=None, judge_above=0.0, confirmers=(), confirm_above=0.5,
                 claude_cmd=None, claude_token_file=None, screens=(), screen_above=0.5, claude_above=0.9,
                 codex_cmd=None, chat_url=None, agy_cmd=None, deciders=(), anonymize=(), ollama_above=0.1, screen_fallback=False):
        self.model = FakeModel()
        self.cwd = tempfile.mkdtemp()
        args = SimpleNamespace(host="127.0.0.1", port=0, judge_url=judge_url, judge_model="fake-judge" if judge_url else None,
                               judge_timeout=5, judge_above=judge_above, confirm_above=confirm_above,
                               claude_model="haiku" if claude_cmd else None, claude_cmd=claude_cmd, claude_above=claude_above,
                               screen_above=screen_above,
                               claude_timeout=30, claude_token_file=claude_token_file,
                               claude_cwd=os.path.join(self.cwd, "judge-cwd"), claude_config=os.path.join(self.cwd, "judge-config"),
                               codex_model="gpt-test" if codex_cmd else None, codex_cmd=codex_cmd, codex_timeout=30,
                               codex_cwd=os.path.join(self.cwd, "codex-judge", "cwd"),
                               chat_model="gemma-test" if chat_url else None, chat_url=chat_url, chat_timeout=5,
                               agy_model="gemini-test" if agy_cmd else None, agy_cmd=agy_cmd, agy_timeout=30,
                               agy_dir=os.path.join(self.cwd, "agy-judge"), anonymize=anonymize,
                               ollama_above=ollama_above, screen_fallback=screen_fallback)
        with mock.patch.dict(os.environ, {"CODING_AGENT_GUARD_TOKEN": token}):
            self.server = server.build_server(args, [self.model], confirmers, screens, deciders)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


def post(url, text, token=None, agent=None):
    headers = {"Content-Type": "application/json", **({"Authorization": f"Bearer {token}"} if token else {})}
    req = urllib.request.Request(url + "/score", json.dumps({"text": text, "agent": agent}).encode(), headers)
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.load(r)


def guard_rules(url, token=""):
    cfg = guard.default_config()
    cfg["classifier_url"] = url
    with mock.patch.dict(os.environ, {"CODING_AGENT_GUARD_TOKEN": token}):
        return guard.build_rules(cfg, [])


def web_output(text):
    return {"tool_name": "WebFetch", "tool_input": {"url": "https://example.com"}, "tool_response": text}


class ServerTests(unittest.TestCase):
    def test_score_returns_each_model(self):
        # Arrange
        with Running() as s:
            # Act
            reply = post(s.url, "MARKER_HIGH in a page")
        # Assert
        self.assertEqual(reply["scores"], {"fake": 0.95})

    def test_token_is_required_when_set(self):
        # Arrange
        with Running(token="t0ken-for-test") as s:
            # Act
            with self.assertRaises(urllib.error.HTTPError) as err:
                post(s.url, "text")
        # Assert
        self.assertEqual(err.exception.code, 401)

    def test_right_token_is_accepted(self):
        # Arrange
        with Running(token="t0ken-for-test") as s:
            # Act
            reply = post(s.url, "text", token="t0ken-for-test")
        # Assert
        self.assertIn("fake", reply["scores"])


class FakeConfirmer:
    name = "second"

    def __init__(self, value=0.97, fail=False):
        self.calls, self.value, self.fail = 0, value, fail

    def score(self, text):
        self.calls += 1
        if self.fail:
            raise ConnectionError("down")
        return self.value


class ConfirmTests(unittest.TestCase):
    def test_suspect_text_gets_second_opinion(self):
        # Arrange
        second = FakeConfirmer()
        with Running(confirmers=[second]) as s:
            # Act
            reply = post(s.url, "MARKER_HIGH in a page")
        # Assert
        self.assertEqual(reply["scores"], {"fake": 0.95, "second": 0.97})

    def test_plain_text_skips_second_opinion(self):
        # Arrange
        second = FakeConfirmer()
        with Running(confirmers=[second]) as s:
            # Act
            post(s.url, "an ordinary page")
        # Assert
        self.assertEqual(second.calls, 0)

    def test_second_opinion_down_is_reported_not_fatal(self):
        # Arrange
        second = FakeConfirmer(fail=True)
        with Running(confirmers=[second]) as s:
            # Act
            reply = post(s.url, "MARKER_HIGH in a page")
        # Assert
        self.assertEqual(reply["scores"], {"fake": 0.95, "second_error": "ConnectionError"})


FAKE_CLAUDE = r'''
import json, os, sys
text = sys.stdin.read()
def reply(**out):
    print(json.dumps(out)); sys.exit(0)
expected = os.environ.get("FAKE_CLAUDE_EXPECT_TOKEN")
if expected and os.environ.get("CLAUDE_CODE_OAUTH_TOKEN") != expected:
    reply(is_error=True, result="Not logged in - Please run /login", terminal_reason="api_error")
if os.listdir("."):
    reply(is_error=True, result="working folder is not empty", terminal_reason="test")
if not os.environ.get("CLAUDE_CONFIG_DIR", "").endswith("judge-config") or os.environ.get("DISABLE_TELEMETRY") != "1":
    reply(is_error=True, result="judge not isolated from the user config", terminal_reason="test")
injection = ("MARKER_HIGH" in text or "MARKER_CLAUDE_YES" in text) and "MARKER_ORDINARY" not in text
reply(is_error=False, result=json.dumps({"injection": injection}))
'''


def fake_claude():
    path = os.path.join(tempfile.mkdtemp(), "fake_claude.py")
    with open(path, "w", encoding="utf-8") as f:
        f.write(FAKE_CLAUDE)
    return [sys.executable, path]


class ClaudeJudgeTests(unittest.TestCase):
    def test_command_is_locked_down(self):
        # Arrange
        cli = ["claude"]
        # Act
        cmd = server.claude_command(cli, "haiku")
        # Assert
        joined = " ".join(f"[{a}]" for a in cmd)
        self.assertTrue(all(flag in joined for flag in ("[--thinking] [disabled]", "[--tools] []", "[--strict-mcp-config]",
                                                        "[--setting-sources] []", "[--disable-slash-commands]",
                                                        "[--no-session-persistence]")))

    def test_flagged_text_gets_claude_verdict(self):
        # Arrange
        with Running(claude_cmd=fake_claude()) as s:
            # Act
            reply = post(s.url, "MARKER_HIGH in a page")
        # Assert
        self.assertEqual(reply["scores"]["claude"], 1.0)

    def test_plain_text_never_reaches_claude(self):
        # Arrange
        with Running(claude_cmd=fake_claude()) as s:
            # Act
            reply = post(s.url, "an ordinary page")
        # Assert
        self.assertEqual(set(reply["scores"]), {"fake"})

    def test_not_logged_in_is_reported(self):
        # Arrange
        with Running(claude_cmd=fake_claude()) as s, mock.patch.dict(os.environ, {"FAKE_CLAUDE_EXPECT_TOKEN": "tok-for-test"}):
            # Act
            reply = post(s.url, "MARKER_HIGH in a page")
        # Assert
        self.assertIn("Not logged in", reply["scores"]["claude_error"])

    def test_token_file_logs_claude_in(self):
        # Arrange
        token_file = os.path.join(tempfile.mkdtemp(), "token")
        with open(token_file, "w") as f:
            f.write("tok-for-test\n")
        with Running(claude_cmd=fake_claude(), claude_token_file=token_file) as s, \
                mock.patch.dict(os.environ, {"FAKE_CLAUDE_EXPECT_TOKEN": "tok-for-test"}):
            # Act
            reply = post(s.url, "MARKER_HIGH in a page")
        # Assert
        self.assertEqual(reply["scores"]["claude"], 1.0)

    def test_disagreeing_claude_annotates_but_keeps_warning(self):
        # Arrange
        with Running(claude_cmd=fake_claude()) as s:
            event = web_output("A long enough page body with MARKER_HIGH and MARKER_ORDINARY in it.")
            # Act
            result = guard.on_output(event, guard_rules(s.url))
        # Assert
        note = result["hookSpecificOutput"]["additionalContext"]
        self.assertEqual(("model:fake" in note, "claude-judge:ordinary-data" in note), (True, True))

    def test_failing_claude_keeps_the_note_and_marks_the_flag_unjudged(self):
        # Arrange
        with Running(claude_cmd=fake_claude()) as s, mock.patch.dict(os.environ, {"FAKE_CLAUDE_EXPECT_TOKEN": "tok-for-test"}):
            event = web_output("A long enough page body with MARKER_HIGH in it.")
            # Act
            result = guard.on_output(event, guard_rules(s.url))
        # Assert
        note = result["hookSpecificOutput"]["additionalContext"]
        self.assertEqual(("model:fake" in note, "claude-judge:unavailable" in note), (True, True))

    def test_long_text_is_judged_around_its_most_suspect_window(self):
        # Arrange
        text = "x" * 50_000 + " MARKER_HIGH " + "y" * 50_000
        # Act
        window = server.judge_window(text, (50_000, 50_013))
        # Assert
        self.assertEqual((len(window), "MARKER_HIGH" in window), (server.JUDGE_CHARS, True))

    def test_window_near_the_end_stays_full_length(self):
        # Arrange
        text = "x" * 50_000 + " MARKER_HIGH"
        # Act
        window = server.judge_window(text, (49_990, 50_012))
        # Assert
        self.assertEqual((len(window), window.endswith("MARKER_HIGH")), (server.JUDGE_CHARS, True))

    def test_text_that_fits_is_judged_whole(self):
        # Arrange
        text = "short page with MARKER_HIGH"
        # Act
        window = server.judge_window(text, (16, 27))
        # Assert
        self.assertEqual(window, text)

    def test_server_sends_the_judge_the_flagged_part_of_a_long_text(self):
        # Arrange
        seen = []
        with Running(claude_cmd=fake_claude()) as s, \
                mock.patch.object(server, "claude_judge", lambda text, args: seen.append(text) or False):
            s.model.span = (60_000, 60_011)
            # Act
            post(s.url, "x" * 60_000 + "MARKER_HIGH" + "y" * 20_000)
        # Assert
        self.assertEqual(("MARKER_HIGH" in seen[0], len(seen[0])), (True, server.JUDGE_CHARS))

    def test_top_ignores_error_entries(self):
        # Arrange
        scores = {"a": 0.3, "b_error": "ConnectionError"}
        # Act
        result = server.top(scores)
        # Assert
        self.assertEqual(result, 0.3)


FAKE_CODEX = r'''
import json, os, sys
text = sys.stdin.read()
if os.environ.get("FAKE_CODEX_FAIL"):
    sys.stderr.write("user\n" + text + "\nERROR: Not logged in\n"); sys.exit(1)
args = sys.argv[1:]
if args[0] != "exec" or "--ignore-user-config" not in args or args[-1] != "-" or os.listdir("."):
    sys.exit(2)
injection = "MARKER_HIGH" in text and "MARKER_ORDINARY" not in text
print(json.dumps({"injection": injection}))
'''


def fake_codex():
    path = os.path.join(tempfile.mkdtemp(), "fake_codex.py")
    with open(path, "w", encoding="utf-8") as f:
        f.write(FAKE_CODEX)
    return [sys.executable, path]


class CodexJudgeTests(unittest.TestCase):
    def test_command_is_locked_down(self):
        # Arrange
        cli = ["codex"]
        # Act
        cmd = server.codex_command(cli, "gpt-test", "schema.json")
        # Assert
        joined = " ".join(f"[{a}]" for a in cmd)
        self.assertTrue(all(flag in joined for flag in ("[--ephemeral]", "[--ignore-user-config]", "[--ignore-rules]",
                                                        "[--disable] [hooks]", "[--disable] [plugins]", "[--disable] [apps]",
                                                        "[-c] [skills.bundled.enabled=false]",
                                                        "[-c] [skills.include_instructions=false]",
                                                        "[--disable] [shell_tool]", "[--disable] [unified_exec]",
                                                        "[--disable] [multi_agent]", "[--disable] [code_mode_host]",
                                                        "[--sandbox] [read-only]", "[--output-schema] [schema.json]")))

    def test_codex_session_gets_codex_verdict(self):
        # Arrange
        with Running(claude_cmd=fake_claude(), codex_cmd=fake_codex()) as s:
            # Act
            reply = post(s.url, "MARKER_HIGH in a page", agent="codex")
        # Assert
        self.assertEqual((reply["scores"].get("codex"), "claude" in reply["scores"]), (1.0, False))

    def test_claude_session_still_gets_claude_verdict(self):
        # Arrange
        with Running(claude_cmd=fake_claude(), codex_cmd=fake_codex()) as s:
            # Act
            reply = post(s.url, "MARKER_HIGH in a page", agent="claude")
        # Assert
        self.assertEqual((reply["scores"].get("claude"), "codex" in reply["scores"]), (1.0, False))

    def test_codex_session_without_codex_judge_falls_back_to_claude(self):
        # Arrange
        with Running(claude_cmd=fake_claude()) as s:
            # Act
            reply = post(s.url, "MARKER_HIGH in a page", agent="codex")
        # Assert
        self.assertEqual(reply["scores"].get("claude"), 1.0)

    def test_codex_error_never_carries_the_text(self):
        # Arrange
        with Running(codex_cmd=fake_codex()) as s, mock.patch.dict(os.environ, {"FAKE_CODEX_FAIL": "1"}):
            # Act
            reply = post(s.url, "MARKER_HIGH secret page text", agent="codex")
        # Assert
        self.assertEqual(reply["scores"]["codex_error"], "RuntimeError: codex exit 1")

    def test_disagreeing_codex_annotates_codex_session_note(self):
        # Arrange
        with Running(claude_cmd=fake_claude(), codex_cmd=fake_codex()) as s:
            event = {**web_output("A long enough page body with MARKER_HIGH and MARKER_ORDINARY in it."), "turn_id": "t1"}
            # Act
            result = guard.on_output(event, guard_rules(s.url))
        # Assert
        note = result["hookSpecificOutput"]["additionalContext"]
        self.assertEqual(("model:fake" in note, "codex-judge:ordinary-data" in note), (True, True))


FAKE_AGY = r'''
import json, os, sys
args = sys.argv[1:]
line = json.loads(sys.stdin.readline())
text = line["message"]["content"]
if os.environ.get("FAKE_AGY_FAIL"):
    sys.stderr.write("prompt: " + text + "\nERROR: not signed in\n"); sys.exit(1)
home = os.environ["HOME"]
if (args[args.index("--agent") + 1] != "injection-judge" or args[-1] != "-p=" or line["event"] != "user"
        or os.environ["USERPROFILE"] != home or not os.path.isfile(os.path.join(".agents", "agents", "injection-judge.md"))):
    sys.exit(2)
cid = "conv-1"
root = os.path.join(home, ".gemini", "antigravity-cli")
for folder in ("conversations", "brain/" + cid):
    os.makedirs(os.path.join(root, folder), exist_ok=True)
open(os.path.join(root, "conversations", cid + ".db"), "w").write(text)
open(os.path.join(root, "brain", cid, "transcript.jsonl"), "w").write(text)
result = {"conversation_id": cid, "status": "SUCCESS"}
if not os.environ.get("FAKE_AGY_TIMEOUT"):
    result["structured_output"] = {"injection": "MARKER_HIGH" in text and "MARKER_ORDINARY" not in text}
print(json.dumps({"event": "init", "conversation_id": cid}))
print(json.dumps({"event": "result", "result": result}))
'''


def fake_agy():
    path = os.path.join(tempfile.mkdtemp(), "fake_agy.py")
    with open(path, "w", encoding="utf-8") as f:
        f.write(FAKE_AGY)
    return [sys.executable, path]


class AgyJudgeTests(unittest.TestCase):
    def test_command_is_locked_down(self):
        # Arrange
        cli = ["agy"]
        # Act
        cmd = server.agy_command(cli, "gemini-test", "schema.json", 60)
        # Assert
        joined = " ".join(f"[{a}]" for a in cmd)
        self.assertTrue(all(flag in joined for flag in ("[--agent] [injection-judge]", "[--disable-slash-commands]",
                                                        "[--input-format] [stream-json]", "[--json-schema] [schema.json]",
                                                        "[--print-timeout] [60s]", "[-p=]")))

    def test_agent_has_no_tools_or_customizations(self):
        # Arrange
        agent = server.AGY_AGENT
        # Act
        flags = [line for line in agent.splitlines() if ":" in line]
        # Assert
        self.assertTrue(all(f in flags for f in ("excludeDefaultComponents: true", "inheritCustomizations: false",
                                                 "inheritMcp: false", "tools: [finish]")))

    def test_agy_model_decides_in_place_of_claude(self):
        # Arrange
        with Running(agy_cmd=fake_agy()) as s:
            # Act
            reply = post(s.url, "MARKER_HIGH in a page", agent="claude")
        # Assert
        self.assertEqual((reply["scores"].get("agy"), "claude" in reply["scores"]), (1.0, False))

    def test_codex_session_keeps_its_codex_judge(self):
        # Arrange
        with Running(agy_cmd=fake_agy(), codex_cmd=fake_codex()) as s:
            # Act
            reply = post(s.url, "MARKER_HIGH in a page", agent="codex")
        # Assert
        self.assertEqual((reply["scores"].get("codex"), "agy" in reply["scores"]), (1.0, False))

    def test_judged_text_is_not_kept(self):
        # Arrange
        with Running(agy_cmd=fake_agy()) as s:
            root = os.path.join(s.cwd, "agy-judge", "home", ".gemini", "antigravity-cli")
            # Act
            post(s.url, "MARKER_HIGH secret page text")
        # Assert
        self.assertEqual((os.listdir(os.path.join(root, "conversations")), os.listdir(os.path.join(root, "brain"))), ([], []))

    def test_timeout_without_verdict_is_an_error(self):
        # Arrange
        with Running(agy_cmd=fake_agy()) as s, mock.patch.dict(os.environ, {"FAKE_AGY_TIMEOUT": "1"}):
            # Act
            reply = post(s.url, "MARKER_HIGH in a page")
        # Assert
        self.assertEqual(reply["scores"]["agy_error"], "RuntimeError: agy exit 0")

    def test_agy_error_never_carries_the_text(self):
        # Arrange
        with Running(agy_cmd=fake_agy()) as s, mock.patch.dict(os.environ, {"FAKE_AGY_FAIL": "1"}):
            # Act
            reply = post(s.url, "MARKER_HIGH secret page text")
        # Assert
        self.assertEqual(reply["scores"]["agy_error"], "RuntimeError: agy exit 1")

    def test_disagreeing_agy_annotates_the_note(self):
        # Arrange
        with Running(agy_cmd=fake_agy()) as s:
            event = web_output("A long enough page body with MARKER_HIGH and MARKER_ORDINARY in it.")
            # Act
            result = guard.on_output(event, guard_rules(s.url))
        # Assert
        note = result["hookSpecificOutput"]["additionalContext"]
        self.assertEqual(("model:fake" in note, "agy-judge:ordinary-data" in note), (True, True))

    def test_claude_and_agy_model_together_are_refused(self):
        # Arrange
        argv = ["server.py", "--model", "m", "--claude-model", "claude-sonnet-5", "--agy-model", "gemini-3.8-flash-low"]
        err = io.StringIO()
        # Act
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
            server.main()
        # Assert
        self.assertIn("pick one", err.getvalue())


class FakeScreen:
    name = "screen-model"

    def __init__(self, fail=False):
        self.calls, self.fail = 0, fail

    def score(self, text):
        self.calls += 1
        if self.fail:
            raise ConnectionError("down")
        return 0.95 if "MARKER_SCREEN" in text else 0.1


class ScreenTests(unittest.TestCase):
    def test_screen_scores_every_text(self):
        # Arrange
        with Running(claude_cmd=fake_claude(), screens=[FakeScreen()]) as s:
            # Act
            reply = post(s.url, "an ordinary page")
        # Assert
        self.assertEqual(reply["scores"], {"fake": 0.1, "screen:screen-model": 0.1})

    def test_screen_hit_sends_text_to_claude(self):
        # Arrange
        with Running(claude_cmd=fake_claude(), screens=[FakeScreen()]) as s:
            # Act
            reply = post(s.url, "MARKER_SCREEN and MARKER_CLAUDE_YES in a page")
        # Assert
        self.assertEqual((reply["scores"]["fake"], reply["scores"]["claude"]), (0.1, 1.0))

    def test_screen_hit_alone_never_flags(self):
        # Arrange
        with Running(claude_cmd=fake_claude(), screens=[FakeScreen()]) as s:
            event = web_output("A long enough page body where only MARKER_SCREEN fires.")
            # Act
            result = guard.on_output(event, guard_rules(s.url))
        # Assert
        self.assertIsNone(result)

    def test_screen_hit_confirmed_by_claude_flags_as_claude(self):
        # Arrange
        with Running(claude_cmd=fake_claude(), screens=[FakeScreen()]) as s:
            event = web_output("A long enough page body with MARKER_SCREEN and MARKER_CLAUDE_YES in it.")
            # Act
            result = guard.on_output(event, guard_rules(s.url))
        # Assert
        note = result["hookSpecificOutput"]["additionalContext"]
        self.assertEqual(("model:claude" in note, "screen" in note), (True, False))

    def test_classifier_band_goes_to_claude_below_old_threshold(self):
        # Arrange
        with Running(claude_cmd=fake_claude(), screens=[FakeScreen()], claude_above=0.5) as s:
            # Act
            reply = post(s.url, "MARKER_HIGH in a page")
        # Assert
        self.assertEqual(reply["scores"]["claude"], 1.0)

    def test_screen_down_is_reported_not_fatal(self):
        # Arrange
        with Running(claude_cmd=fake_claude(), screens=[FakeScreen(fail=True)]) as s:
            # Act
            reply = post(s.url, "an ordinary page")
        # Assert
        self.assertEqual(reply["scores"], {"fake": 0.1, "screen:screen-model_error": "ConnectionError"})

    def test_top_keeps_screens_apart(self):
        # Arrange
        scores = {"a": 0.3, "screen:b": 0.97, "c_error": "X"}
        # Act
        result = (server.top(scores), server.top(scores, screens=True))
        # Assert
        self.assertEqual(result, (0.3, 0.97))


class FakeDecider:
    name = "decider"

    def __init__(self, fail=False):
        self.texts, self.fail = [], fail

    def score(self, text):
        self.texts.append(text)
        if self.fail:
            raise ConnectionError("down")
        return 0.95 if "MARKER_DECIDE" in text else 0.1


class DeciderTests(unittest.TestCase):
    def test_decider_scores_every_text(self):
        # Arrange
        with Running(deciders=[FakeDecider()]) as s:
            # Act
            reply = post(s.url, "an ordinary page")
        # Assert
        self.assertEqual(reply["scores"], {"fake": 0.1, "decider": 0.1})

    def test_decider_reads_anonymized_text(self):
        # Arrange
        decider = FakeDecider()
        with Running(deciders=[decider], anonymize=["Acme"]) as s:
            # Act
            post(s.url, "Mail bob@acme.example about ACME-12 in the Acme portal at https://intra.acme.example/x")
        # Assert
        self.assertEqual(decider.texts, ["Mail user@example.com about KEY-12 in the [NAME] portal at https://example.com/x"])

    def test_decider_hit_flags_in_guard(self):
        # Arrange
        with Running(deciders=[FakeDecider()]) as s:
            event = web_output("A long enough page body where only MARKER_DECIDE fires.")
            # Act
            result = guard.on_output(event, guard_rules(s.url))
        # Assert
        self.assertIn("model:decider", result["hookSpecificOutput"]["additionalContext"])

    def test_decider_hit_sends_text_to_claude(self):
        # Arrange
        with Running(claude_cmd=fake_claude(), deciders=[FakeDecider()], claude_above=0.5) as s:
            # Act
            reply = post(s.url, "MARKER_DECIDE and MARKER_CLAUDE_YES in a page")
        # Assert
        self.assertEqual((reply["scores"]["fake"], reply["scores"]["claude"]), (0.1, 1.0))

    def test_decider_runs_while_classifier_scores(self):
        # Arrange
        started, decider = threading.Event(), FakeDecider()
        score = decider.score
        decider.score = lambda text: (started.set(), score(text))[1]
        with Running(deciders=[decider]) as s:
            s.model.score = lambda text: 0.95 if started.wait(2) else 0.0
            # Act
            reply = post(s.url, "an ordinary page")
        # Assert
        self.assertEqual(reply["scores"], {"fake": 0.95, "decider": 0.1})

    def test_decider_low_score_at_ollama_above_goes_to_claude(self):
        # Arrange
        with Running(claude_cmd=fake_claude(), deciders=[FakeDecider()], ollama_above=0.1) as s:
            # Act
            reply = post(s.url, "an ordinary page")
        # Assert
        self.assertEqual(reply["scores"].get("claude"), 0.0)

    def test_decider_below_ollama_above_skips_claude(self):
        # Arrange
        with Running(claude_cmd=fake_claude(), deciders=[FakeDecider()], ollama_above=0.5) as s:
            # Act
            reply = post(s.url, "an ordinary page")
        # Assert
        self.assertNotIn("claude", reply["scores"])

    def test_long_text_decider_reads_judge_window(self):
        # Arrange
        decider = FakeDecider()
        with Running(deciders=[decider]) as s:
            # Act
            post(s.url, "x" * (server.JUDGE_CHARS + 500))
        # Assert
        self.assertEqual(len(decider.texts[0]), server.JUDGE_CHARS)

    def test_decider_down_is_reported_not_fatal(self):
        # Arrange
        with Running(deciders=[FakeDecider(fail=True)]) as s:
            # Act
            reply = post(s.url, "an ordinary page")
        # Assert
        self.assertEqual(reply["scores"], {"fake": 0.1, "decider_error": "ConnectionError"})

    def test_fallback_screen_skipped_while_decider_works(self):
        # Arrange
        screen = FakeScreen()
        with Running(claude_cmd=fake_claude(), deciders=[FakeDecider()], screens=[screen], screen_fallback=True) as s:
            # Act
            post(s.url, "MARKER_SCREEN in an ordinary page")
        # Assert
        self.assertEqual(screen.calls, 0)

    def test_fallback_screen_stands_in_when_decider_fails(self):
        # Arrange
        with Running(claude_cmd=fake_claude(), deciders=[FakeDecider(fail=True)], screens=[FakeScreen()],
                     screen_fallback=True) as s:
            # Act
            reply = post(s.url, "MARKER_SCREEN and MARKER_CLAUDE_YES in a page")
        # Assert
        self.assertEqual((reply["scores"]["screen:screen-model"], reply["scores"]["claude"]), (0.95, 1.0))


class JudgeTests(unittest.TestCase):
    def test_judge_verdict_is_reported(self):
        # Arrange
        with FakeJudge(True) as j, Running(judge_url=j.url) as s:
            # Act
            reply = post(s.url, "MARKER_HIGH in a page")
        # Assert
        self.assertEqual(reply["scores"]["judge"], 1.0)

    def test_judge_skipped_below_threshold(self):
        # Arrange
        with FakeJudge(True) as j, Running(judge_url=j.url, judge_above=0.5) as s:
            # Act
            post(s.url, "an ordinary page")
        # Assert
        self.assertEqual(j.calls, 0)

    def test_judge_down_is_reported_not_fatal(self):
        # Arrange
        with Running(judge_url="http://127.0.0.1:9/v1") as s:
            # Act
            reply = post(s.url, "MARKER_HIGH in a page")
        # Assert
        self.assertEqual((reply["scores"]["fake"], "judge_error" in reply["scores"]), (0.95, True))


class ChatDeciderTests(unittest.TestCase):
    def test_chat_model_decides_in_place_of_claude(self):
        # Arrange
        with FakeJudge(True) as j, Running(chat_url=j.url) as s:
            # Act
            reply = post(s.url, "MARKER_HIGH in a page", agent="claude")
        # Assert
        self.assertEqual((reply["scores"].get("chat"), "claude" in reply["scores"]), (1.0, False))

    def test_plain_text_never_reaches_the_chat_model(self):
        # Arrange
        with FakeJudge(True) as j, Running(chat_url=j.url) as s:
            # Act
            post(s.url, "an ordinary page")
        # Assert
        self.assertEqual(j.calls, 0)

    def test_codex_session_keeps_its_codex_judge(self):
        # Arrange
        with FakeJudge(True) as j, Running(chat_url=j.url, codex_cmd=fake_codex()) as s:
            # Act
            reply = post(s.url, "MARKER_HIGH in a page", agent="codex")
        # Assert
        self.assertEqual((reply["scores"].get("codex"), "chat" in reply["scores"]), (1.0, False))

    def test_chat_model_down_is_reported_not_fatal(self):
        # Arrange
        with Running(chat_url="http://127.0.0.1:9/v1") as s:
            # Act
            reply = post(s.url, "MARKER_HIGH in a page")
        # Assert
        self.assertEqual((reply["scores"]["fake"], "chat_error" in reply["scores"]), (0.95, True))

    def test_disagreeing_chat_model_annotates_the_note(self):
        # Arrange
        with FakeJudge(False) as j, Running(chat_url=j.url) as s:
            event = web_output("A long enough page body that mentions MARKER_HIGH somewhere in it.")
            # Act
            result = guard.on_output(event, guard_rules(s.url))
        # Assert
        note = result["hookSpecificOutput"]["additionalContext"]
        self.assertEqual(("model:fake" in note, "chat-judge:ordinary-data" in note), (True, True))

    def test_claude_and_chat_model_together_are_refused(self):
        # Arrange
        argv = ["server.py", "--model", "m", "--claude-model", "claude-sonnet-5", "--chat-model", "gemma4:cloud"]
        err = io.StringIO()
        # Act
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
            server.main()
        # Assert
        self.assertIn("pick one", err.getvalue())


class GuardClientTests(unittest.TestCase):
    def test_high_score_from_outside_is_flagged(self):
        # Arrange
        with Running() as s:
            event = web_output("A long enough page body that mentions MARKER_HIGH somewhere in it.")
            # Act
            result = guard.on_output(event, guard_rules(s.url))
        # Assert
        self.assertIn("model:fake", result["hookSpecificOutput"]["additionalContext"])

    def test_low_score_adds_nothing(self):
        # Arrange
        with Running() as s:
            event = web_output("A long enough page body with nothing unusual in it at all.")
            # Act
            result = guard.on_output(event, guard_rules(s.url))
        # Assert
        self.assertIsNone(result)

    def test_local_command_output_is_not_sent(self):
        # Arrange
        with Running() as s:
            event = {"tool_name": "Bash", "tool_input": {"command": "cat notes.md"},
                     "tool_response": {"stdout": "Local notes long enough to be worth scoring, MARKER_HIGH."}}
            # Act
            guard.on_output(event, guard_rules(s.url))
        # Assert
        self.assertEqual(s.model.calls, 0)

    def test_server_down_falls_back_to_patterns(self):
        # Arrange
        event = web_output("A long enough page body that mentions MARKER_HIGH somewhere in it.")
        # Act
        result = guard.on_output(event, guard_rules("http://127.0.0.1:9"))
        # Assert
        self.assertIsNone(result)

    def test_client_sends_the_token(self):
        # Arrange
        with Running(token="t0ken-for-test") as s:
            event = web_output("A long enough page body that mentions MARKER_HIGH somewhere in it.")
            # Act
            result = guard.on_output(event, guard_rules(s.url, token="t0ken-for-test"))
        # Assert
        self.assertIn("model:fake", result["hookSpecificOutput"]["additionalContext"])

    def test_scalar_config_replaces_default(self):
        # Arrange
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, ".claude", "coding-agent-guard"))
            with open(os.path.join(tmp, ".claude", "coding-agent-guard", "settings.json"), "w") as f:
                json.dump({"classifier_url": "http://10.0.0.1:8765", "classifier_threshold": 0.8}, f)
            with mock.patch.dict(os.environ, {"CLAUDE_PROJECT_DIR": tmp}):
                # Act
                cfg = guard.load_config()
        # Assert
        self.assertEqual((cfg["classifier_url"], cfg["classifier_threshold"]), ("http://10.0.0.1:8765", 0.8))


if __name__ == "__main__":
    unittest.main()
