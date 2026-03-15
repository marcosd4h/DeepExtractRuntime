"""Tests for json_extract.py envelope unwrapping and key lookup."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

_AGENT_DIR = Path(__file__).resolve().parent.parent
_SCRIPT = _AGENT_DIR / "helpers" / "json_extract.py"


def _run(file_path: str, *extra_args: str) -> tuple[int, str, str]:
    """Run json_extract.py and return (exit_code, stdout, stderr)."""
    cmd = [sys.executable, str(_SCRIPT), file_path, *extra_args]
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(_AGENT_DIR.parent))
    return result.returncode, result.stdout.strip(), result.stderr.strip()


class TestEnvelopeUnwrapping:
    """Workspace results.json envelope is auto-unwrapped."""

    def test_unwraps_workspace_envelope(self, tmp_path):
        data = {
            "output_type": "json",
            "captured_at": "2026-01-01T00:00:00Z",
            "stdout": {"status": "ok", "stats": {"nodes": 100}},
            "stdout_char_count": 42,
        }
        f = tmp_path / "results.json"
        f.write_text(json.dumps(data))
        rc, out, _ = _run(str(f), "stats")
        assert rc == 0
        parsed = json.loads(out)
        assert parsed == {"nodes": 100}

    def test_unwraps_for_keys_mode(self, tmp_path):
        data = {
            "output_type": "json",
            "stdout": {"alpha": 1, "beta": 2, "gamma": 3},
            "stdout_char_count": 10,
        }
        f = tmp_path / "results.json"
        f.write_text(json.dumps(data))
        rc, out, _ = _run(str(f), "--keys")
        assert rc == 0
        parsed = json.loads(out)
        assert "alpha" in parsed["keys"]
        assert "output_type" not in parsed["keys"]

    def test_raw_flag_disables_unwrapping(self, tmp_path):
        data = {
            "output_type": "json",
            "stdout": {"inner": True},
            "stdout_char_count": 5,
        }
        f = tmp_path / "results.json"
        f.write_text(json.dumps(data))
        rc, out, _ = _run(str(f), "--raw", "--keys")
        assert rc == 0
        parsed = json.loads(out)
        assert "output_type" in parsed["keys"]
        assert "stdout" in parsed["keys"]

    def test_non_envelope_not_unwrapped(self, tmp_path):
        data = {"status": "ok", "results": [1, 2, 3]}
        f = tmp_path / "data.json"
        f.write_text(json.dumps(data))
        rc, out, _ = _run(str(f), "results")
        assert rc == 0
        assert json.loads(out) == [1, 2, 3]

    def test_dotted_path_after_unwrap(self, tmp_path):
        data = {
            "output_type": "json",
            "stdout": {"a": {"b": {"c": 42}}},
            "stdout_char_count": 10,
        }
        f = tmp_path / "results.json"
        f.write_text(json.dumps(data))
        rc, out, _ = _run(str(f), "a.b.c")
        assert rc == 0
        assert json.loads(out) == 42


class TestKeyLookup:
    """Basic key lookup without envelope."""

    def test_top_level_key(self, tmp_path):
        f = tmp_path / "data.json"
        f.write_text(json.dumps({"foo": "bar"}))
        rc, out, _ = _run(str(f), "foo")
        assert rc == 0
        assert json.loads(out) == "bar"

    def test_missing_key_errors(self, tmp_path):
        f = tmp_path / "data.json"
        f.write_text(json.dumps({"foo": 1}))
        rc, _, err = _run(str(f), "missing")
        assert rc == 1
        parsed = json.loads(err)
        assert parsed["code"] == "NOT_FOUND"

    def test_grep_mode(self, tmp_path):
        f = tmp_path / "data.json"
        f.write_text(json.dumps({"abc_123": 1, "abc_456": 2, "xyz": 3}))
        rc, out, _ = _run(str(f), "--grep", "abc")
        assert rc == 0
        parsed = json.loads(out)
        assert parsed["match_count"] == 2
