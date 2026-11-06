"""Fake tokens are assembled at runtime so secret scanners never see a literal one here."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import leaks  # noqa: E402
import transcript  # noqa: E402

GITHUB = "gh" + "p_" + "A1b2C3d4" * 5
QUOTED = 's3cret"Kn\\own-Value'


def row(value):
    """One transcript line the way Claude Code writes it: compact JSON, raw UTF-8, newline at the end."""
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def hook_row(output):
    """A PostToolUse hook's stdout as the transcript keeps it: the hook's JSON reply, with the raw output inside."""
    reply = {"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                    "updatedToolOutput": {"stdout": output, "stderr": "", "interrupted": False}}}
    return row({"type": "attachment", "uuid": "u2", "attachment": {
        "type": "hook_success", "hookName": "PostToolUse:Bash", "exitCode": 0, "stderr": "",
        "stdout": json.dumps(reply, separators=(",", ":"))}})


def hook_output(line):
    return json.loads(json.loads(line)["attachment"]["stdout"])["hookSpecificOutput"]["updatedToolOutput"]["stdout"]


USER_ROW = row({"type": "user", "uuid": "u1", "message": {"role": "user", "content": "show the token"}})


class TranscriptScrubTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "session.jsonl")
        self.state = os.path.join(self.dir.name, "state", "session")

    def tearDown(self):
        self.dir.cleanup()

    def write(self, data):
        with open(self.path, "wb") as f:
            f.write(data)

    def read(self):
        with open(self.path, "rb") as f:
            return f.read()

    def scrub(self, known=(), mask=True):
        return transcript.scrub(self.path, self.state, list(known), leaks.DEFAULT, mask=mask)

    def test_secret_in_hook_stdout_row_is_masked(self):
        # Arrange
        self.write(USER_ROW + hook_row(f"token {GITHUB}"))
        # Act
        self.scrub()
        # Assert
        data = self.read()
        self.assertEqual((GITHUB.encode() in data, b"*" * len(GITHUB) in data), (False, True))

    def test_masked_row_still_parses_as_json(self):
        # Arrange
        self.write(USER_ROW + hook_row(f"token {GITHUB}"))
        # Act
        self.scrub()
        # Assert
        self.assertEqual(hook_output(self.read().splitlines()[1]), "token " + "*" * len(GITHUB))

    def test_transcript_keeps_its_byte_size(self):
        # Arrange
        self.write(USER_ROW + hook_row(f"token {GITHUB}"))
        size = os.path.getsize(self.path)
        # Act
        self.scrub()
        # Assert
        self.assertEqual(os.path.getsize(self.path), size)

    def test_partial_trailing_line_is_left_as_written(self):
        # Arrange
        partial = hook_row(f"token {GITHUB}")[:-20]
        self.write(USER_ROW + partial)
        # Act
        self.scrub()
        # Assert
        self.assertEqual(self.read(), USER_ROW + partial)

    def test_second_run_changes_nothing(self):
        # Arrange
        self.write(USER_ROW + hook_row(f"token {GITHUB}"))
        self.scrub()
        once = self.read()
        # Act
        found = self.scrub()
        # Assert
        self.assertEqual((found, self.read()), (None, once))

    def test_rows_before_the_recorded_offset_are_not_read(self):
        # Arrange
        first = hook_row(f"token {GITHUB}")
        self.write(first + USER_ROW)
        os.makedirs(os.path.dirname(self.state))
        with open(self.state, "w") as f:
            f.write(str(len(first)))
        # Act
        found = self.scrub()
        # Assert
        self.assertEqual((found, self.read()), (None, first + USER_ROW))

    def test_shrunk_transcript_is_read_from_the_start(self):
        # Arrange
        self.write(hook_row(f"token {GITHUB}"))
        os.makedirs(os.path.dirname(self.state))
        with open(self.state, "w") as f:
            f.write("999999")
        # Act
        self.scrub()
        # Assert
        self.assertNotIn(GITHUB.encode(), self.read())

    def test_detect_only_reports_the_kind_and_leaves_the_file_as_written(self):
        # Arrange
        original = USER_ROW + hook_row(f"token {GITHUB}")
        self.write(original)
        # Act
        found = self.scrub(mask=False)
        # Assert
        self.assertEqual((found["found"], found["masked"], self.read()), (["github-token"], False, original))

    def test_rows_only_counted_are_masked_once_masking_is_switched_on(self):
        # Arrange
        self.write(USER_ROW + hook_row(f"token {GITHUB}"))
        self.scrub(mask=False)
        # Act
        self.scrub()
        # Assert
        self.assertNotIn(GITHUB.encode(), self.read())

    def test_count_mode_counts_each_row_once(self):
        # Arrange
        self.write(USER_ROW + hook_row(f"token {GITHUB}"))
        self.scrub(mask=False)
        # Act
        found = self.scrub(mask=False)
        # Assert
        self.assertIsNone(found)

    def test_shrunk_transcript_is_counted_once_in_count_mode(self):
        # Arrange
        self.write(hook_row(f"token {GITHUB}"))
        os.makedirs(os.path.dirname(self.state))
        with open(self.state, "w") as f:
            f.write("999999")
        self.scrub(mask=False)
        # Act
        found = self.scrub(mask=False)
        # Assert
        self.assertIsNone(found)

    def test_without_state_whole_file_is_read_and_no_offset_is_recorded(self):
        # Arrange
        self.write(hook_row(f"token {GITHUB}") + USER_ROW)
        os.makedirs(os.path.dirname(self.state))
        with open(self.state, "w") as f:
            f.write(str(len(self.read())))
        # Act
        found = transcript.scrub(self.path, None, [], leaks.DEFAULT)
        # Assert
        self.assertEqual((found["rows"], GITHUB.encode() in self.read(), os.listdir(os.path.dirname(self.state))),
                         (1, False, ["session"]))

    def test_known_value_with_quotes_is_masked_inside_nested_json(self):
        # Arrange
        self.write(USER_ROW + hook_row(f"value {QUOTED} end"))
        # Act
        self.scrub(known=[QUOTED])
        # Assert
        output = hook_output(self.read().splitlines()[1])
        self.assertEqual((QUOTED in output, output.startswith("value *"), output.endswith("* end")), (False, True, True))

    def test_thinking_block_is_left_as_written_while_text_is_masked(self):
        # Arrange
        thinking = {"type": "thinking", "thinking": f"the user pasted {GITHUB}", "signature": "c2lnbmVk"}
        self.write(row({"type": "assistant", "uuid": "u3", "message": {"role": "assistant", "content": [
            thinking, {"type": "text", "text": f"token {GITHUB}"}]}}))
        # Act
        found = self.scrub()
        # Assert
        line = self.read()
        content = json.loads(line)["message"]["content"]
        self.assertEqual((row(thinking)[:-1] in line, content[1]["text"], found["left_in_thinking"]),
                         (True, "token " + "*" * len(GITHUB), 1))


if __name__ == "__main__":
    unittest.main()
