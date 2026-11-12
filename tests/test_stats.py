"""scripts/stats.py: the what-if arithmetic and the report running end to end on a small log."""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import stats  # noqa: E402


def read(cls, screen=None, claude=None, **extra):
    scores = {"horizon-guard-base": cls}
    if screen is not None:
        scores["screen:ollaya-laya-en"] = screen
    if claude is not None:
        scores["claude"] = claude
    return {"direction": "in", "external": True, "scores": scores, "claude_asked": claude is not None, **extra}


# Flagged alone; unsure and confirmed; screened and confirmed; screened and cleared; clean; unsure, never judged.
LOG = [read(0.95, 0.9, 1.0), read(0.6, 0.1, 1.0), read(0.2, 0.8, 1.0), read(0.1, 0.6, 0.0), read(0.1, 0.2), read(0.4, 0.1)]
SCORED = [stats.scores_of(r) for r in LOG]


class WhatIfTests(unittest.TestCase):
    def test_current_thresholds_keep_every_confirmed_injection(self):
        # Arrange
        h, sc = 0.5, 0.5
        # Act
        result = stats.at(SCORED, h, sc)
        # Assert
        self.assertEqual(result, {"sent": 4, "never_judged": 0, "kept": 3, "confirmed": 3})

    def test_stricter_classifier_loses_a_confirmed_injection(self):
        # Arrange
        h, sc = 0.7, 0.5
        # Act
        result = stats.at(SCORED, h, sc)
        # Assert
        self.assertEqual((result["sent"], result["kept"]), (3, 2))

    def test_dropping_the_screen_loses_what_only_it_found(self):
        # Arrange
        h, sc = 0.5, None
        # Act
        result = stats.at(SCORED, h, sc)
        # Assert
        self.assertEqual((result["sent"], result["kept"]), (2, 2))

    def test_looser_classifier_shows_texts_claude_never_saw(self):
        # Arrange
        h, sc = 0.3, 0.5
        # Act
        result = stats.at(SCORED, h, sc)
        # Assert
        self.assertEqual((result["sent"], result["never_judged"]), (5, 1))


class ProjectLogTests(unittest.TestCase):
    def test_log_is_found_from_a_directory_below_the_project(self):
        # Arrange
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, ".coding-agent-guard"))
            os.makedirs(os.path.join(tmp, "code", "repo"))
            with open(os.path.join(tmp, ".coding-agent-guard", "settings.json"), "w", encoding="utf-8") as f:
                json.dump({"log_file": ".coding-agent-guard/events.jsonl"}, f)
            env = {k: v for k, v in os.environ.items() if k != "CLAUDE_PROJECT_DIR"}
            cwd = os.getcwd()
            os.chdir(os.path.join(tmp, "code", "repo"))
            try:
                # Act
                with mock.patch.dict(os.environ, env, clear=True):
                    path = stats.project_log()
            finally:
                os.chdir(cwd)
        # Assert
        # realpath: on macOS the temp folder is a /var symlink to /private/var, and the cwd comes back resolved
        self.assertEqual(os.path.normcase(path), os.path.normcase(os.path.join(os.path.realpath(tmp), ".coding-agent-guard/events.jsonl")))


class ReportTests(unittest.TestCase):
    def test_report_runs_on_a_log_and_prints_no_text(self):
        # Arrange
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "events.jsonl")
            with open(path, "w", encoding="utf-8") as f:
                for i, r in enumerate(LOG):
                    f.write(json.dumps({"ts": f"2026-09-29T1{i}:00:00+02:00", "tool": "WebFetch", "host": "example.com",
                                        "hook_ms": 100 + i, "injection": ["model:claude"] if r["scores"].get("claude") == 1.0 else [],
                                        **r}) + "\n")
            out = io.StringIO()
            # Act
            with mock.patch.object(sys, "argv", ["stats.py", "--log", path, "--days", "3650"]), contextlib.redirect_stdout(out):
                stats.main()
        # Assert
        text = out.getvalue()
        self.assertEqual(("2026-09-29" in text, "What-if" in text, "Top sources flagged: example.com 3" in text), (True, True, True))

    def test_torn_log_line_is_skipped(self):
        # Arrange
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "events.jsonl")
            with open(path, "w", encoding="utf-8") as f:
                f.write(json.dumps({"ts": "2026-09-29T10:00:00+02:00", **LOG[0]}) + "\n")
                f.write('de_asked": false, "confirmed": false}\n')
                f.write(json.dumps({"ts": "2026-09-29T11:00:00+02:00", **LOG[1]}) + "\n")
            # Act
            with contextlib.redirect_stderr(io.StringIO()):
                rows = list(stats.load(path, 3650))
        # Assert
        self.assertEqual(len(rows), 2)


if __name__ == "__main__":
    unittest.main()
