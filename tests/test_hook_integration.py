"""Integration tests for hook system edge cases.

Tests concurrent scratchpad creation, corrupted file handling,
and session-scoped isolation.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import threading
import time
from pathlib import Path

import pytest

# Load grind-until-done module (hyphenated filename)
_AGENT_DIR = Path(__file__).resolve().parent.parent
_HOOK_PATH = _AGENT_DIR / "hooks" / "grind-until-done.py"
if str(_AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENT_DIR))

spec = importlib.util.spec_from_file_location("grind_hook", _HOOK_PATH)
_grind_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(_grind_mod)

_parse_scratchpad = _grind_mod._parse_scratchpad
_validate_scratchpad_format = _grind_mod._validate_scratchpad_format
_find_scratchpad = _grind_mod._find_scratchpad

from helpers.session_utils import resolve_session_id, scratchpad_path


# ---------------------------------------------------------------------------
# Concurrent scratchpad creation
# ---------------------------------------------------------------------------


class TestConcurrentScratchpadCreation:
    """Test that multiple sessions can create scratchpads simultaneously."""

    def test_parallel_scratchpad_creation(self, tmp_path):
        """Multiple threads creating different scratchpads should not conflict."""
        scratchpads_dir = tmp_path / "scratchpads"
        scratchpads_dir.mkdir()

        results = {}
        errors = []

        def create_scratchpad(session_id: str):
            try:
                path = scratchpads_dir / f"{session_id}.md"
                content = (
                    f"# Task: Session {session_id}\n\n"
                    f"## Items\n"
                    f"- [ ] Item for {session_id}\n\n"
                    f"## Status\nIN_PROGRESS\n"
                )
                path.write_text(content, encoding="utf-8")
                results[session_id] = True
            except Exception as e:
                errors.append((session_id, str(e)))

        threads = []
        for i in range(10):
            t = threading.Thread(target=create_scratchpad, args=(f"session_{i}",))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=5)

        assert len(errors) == 0, f"Errors during parallel creation: {errors}"
        assert len(results) == 10
        assert len(list(scratchpads_dir.glob("*.md"))) == 10

    def test_same_session_overwrite(self, tmp_path):
        """Writing to the same scratchpad from two threads -- last write wins."""
        scratchpads_dir = tmp_path / "scratchpads"
        scratchpads_dir.mkdir()
        path = scratchpads_dir / "shared.md"

        def write_scratchpad(value: str):
            content = (
                f"# Task: {value}\n\n"
                f"## Items\n- [ ] {value}\n\n"
                f"## Status\nIN_PROGRESS\n"
            )
            path.write_text(content, encoding="utf-8")

        t1 = threading.Thread(target=write_scratchpad, args=("first",))
        t2 = threading.Thread(target=write_scratchpad, args=("second",))
        t1.start()
        t2.start()
        t1.join(timeout=2)
        t2.join(timeout=2)

        # File should exist and be valid (one of the two values)
        assert path.exists()
        content = path.read_text(encoding="utf-8")
        assert "first" in content or "second" in content


# ---------------------------------------------------------------------------
# Corrupted scratchpad handling
# ---------------------------------------------------------------------------


class TestCorruptedScratchpad:
    """Test handling of corrupted or malformed scratchpad files.

    _parse_scratchpad returns (completed: list, pending: list, status: str).
    """

    def test_empty_file(self, tmp_path):
        """Empty scratchpad should be treated as no items / done."""
        path = tmp_path / "empty.md"
        path.write_text("", encoding="utf-8")
        completed, pending, status = _parse_scratchpad(path.read_text(encoding="utf-8"))
        assert len(completed) == 0
        assert len(pending) == 0

    def test_binary_content(self, tmp_path):
        """Binary (non-UTF8) content should not crash the parser."""
        path = tmp_path / "binary.md"
        path.write_bytes(b"\x80\x81\x82\xff\xfe\xfd")
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            completed, pending, status = _parse_scratchpad(content)
            assert len(completed) + len(pending) == 0
        except UnicodeDecodeError:
            pytest.skip("Platform doesn't support errors='replace'")

    def test_no_items_section(self, tmp_path):
        """Scratchpad with header but no items should parse safely."""
        content = "# Task: Test\n\n## Status\nIN_PROGRESS\n"
        completed, pending, status = _parse_scratchpad(content)
        assert len(completed) == 0
        assert len(pending) == 0

    def test_no_status_section(self, tmp_path):
        """Scratchpad with items but no Status section defaults to empty status."""
        content = (
            "# Task: Test\n\n"
            "## Items\n"
            "- [ ] Something\n"
        )
        completed, pending, status = _parse_scratchpad(content)
        assert len(pending) == 1
        assert len(completed) == 0

    def test_malformed_checkbox_lines(self, tmp_path):
        """Lines that look like checkboxes but aren't should be handled."""
        content = (
            "# Task: Test\n\n"
            "## Items\n"
            "- [ ] Valid item\n"
            "- [x] Done item\n"
            "- Not a checkbox\n"
            "- [?] Invalid marker\n"
            "Random text\n\n"
            "## Status\nIN_PROGRESS\n"
        )
        completed, pending, status = _parse_scratchpad(content)
        assert len(completed) == 1
        assert len(pending) == 1
        assert status.upper() == "IN_PROGRESS"

    def test_status_done_recognized(self):
        """When Status is DONE, status field should be DONE."""
        content = (
            "# Task: Test\n\n"
            "## Items\n"
            "- [ ] Unchecked but DONE\n\n"
            "## Status\nDONE\n"
        )
        completed, pending, status = _parse_scratchpad(content)
        assert status.upper() == "DONE"


# ---------------------------------------------------------------------------
# Session isolation
# ---------------------------------------------------------------------------


class TestSessionIsolation:
    """Test that session-scoped scratchpads are properly isolated."""

    def test_different_sessions_different_paths(self):
        """Different session IDs should produce different scratchpad paths."""
        p1 = scratchpad_path("session-aaa")
        p2 = scratchpad_path("session-bbb")
        assert p1 != p2
        assert p1.name != p2.name

    def test_session_id_from_env(self, monkeypatch):
        """AGENT_SESSION_ID env var should take priority."""
        monkeypatch.setenv("AGENT_SESSION_ID", "env-session-123")
        sid = resolve_session_id({})
        assert sid == "env-session-123"

    def test_session_id_from_conversation(self, monkeypatch):
        """conversation_id from stdin should be used when env var is absent."""
        monkeypatch.delenv("AGENT_SESSION_ID", raising=False)
        sid = resolve_session_id({"conversation_id": "conv-456"})
        assert sid == "conv-456"

    def test_session_id_fallback(self, monkeypatch):
        """With no env or stdin data, a UUID should be generated."""
        monkeypatch.delenv("AGENT_SESSION_ID", raising=False)
        sid = resolve_session_id({})
        assert len(sid) > 0
        # Should be a UUID-like string
        assert "-" in sid or len(sid) >= 32


# ---------------------------------------------------------------------------
# Validate scratchpad format
# ---------------------------------------------------------------------------


class TestValidateScratchpadFormat:
    """Test the format validator catches issues.

    _validate_scratchpad_format returns (is_valid: bool, issues: list[str]).
    """

    def test_valid_format(self):
        content = (
            "# Task: Lift class\n\n"
            "## Items\n"
            "- [ ] Method A\n"
            "- [x] Method B\n\n"
            "## Status\nIN_PROGRESS\n"
        )
        is_valid, issues = _validate_scratchpad_format(content)
        assert is_valid is True
        assert issues == []

    def test_missing_task_header(self):
        content = (
            "## Items\n"
            "- [ ] Something\n\n"
            "## Status\nIN_PROGRESS\n"
        )
        is_valid, issues = _validate_scratchpad_format(content)
        # Should not crash even without # Task header
        assert isinstance(is_valid, bool)
