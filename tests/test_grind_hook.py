"""Tests for grind-until-done hook scratchpad parsing.

Target: .agent/hooks/grind-until-done.py
"""

from __future__ import annotations

import importlib.util
import json
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

# Load grind-until-done module (hyphenated filename)
_AGENT_DIR = Path(__file__).resolve().parent.parent
_HOOK_PATH = _AGENT_DIR / "hooks" / "grind-until-done.py"
if str(_AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENT_DIR))

spec = importlib.util.spec_from_file_location("grind_hook", _HOOK_PATH)
_grind_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(_grind_mod)

_strip_fenced_code_blocks = _grind_mod._strip_fenced_code_blocks
_validate_scratchpad_format = _grind_mod._validate_scratchpad_format
_parse_scratchpad = _grind_mod._parse_scratchpad
_find_scratchpad = _grind_mod._find_scratchpad
_cleanup_stale = _grind_mod._cleanup_stale


# ===================================================================
# _strip_fenced_code_blocks
# ===================================================================


class TestStripFencedCodeBlocks:
    def test_no_fence(self):
        text = "line1\nline2"
        assert _strip_fenced_code_blocks(text) == text

    def test_fenced_block_removed(self):
        text = """line1
```code
inside fence
```
line2"""
        result = _strip_fenced_code_blocks(text)
        assert "inside fence" not in result
        assert "line1" in result
        assert "line2" in result

    def test_nested_fence_toggle(self):
        text = """a
```
b
```
c"""
        result = _strip_fenced_code_blocks(text)
        assert "b" not in result
        assert "a" in result
        assert "c" in result


# ===================================================================
# _validate_scratchpad_format
# ===================================================================


class TestValidateScratchpadFormat:
    def test_empty_invalid(self):
        valid, issues = _validate_scratchpad_format("")
        assert valid is False
        assert "empty" in issues[0].lower()

    def test_missing_items_section(self):
        text = """# Task
## Status
DONE"""
        valid, issues = _validate_scratchpad_format(text)
        assert valid is False
        assert any("Items" in i for i in issues)

    def test_missing_status_section(self):
        text = """# Task
## Items
- [ ] item1"""
        valid, issues = _validate_scratchpad_format(text)
        assert valid is False
        assert any("status" in i.lower() for i in issues)

    def test_valid_minimal(self):
        text = """# Task
## Items
- [ ] item1
## Status
IN_PROGRESS"""
        valid, issues = _validate_scratchpad_format(text)
        assert valid is True
        assert len(issues) == 0

    def test_valid_with_done_marker(self):
        """Scratchpad with DONE but no Items section is invalid (missing Items)."""
        text = """# Task
## Status
DONE"""
        valid, issues = _validate_scratchpad_format(text)
        assert valid is False
        assert any("Items" in i for i in issues)


# ===================================================================
# _parse_scratchpad
# ===================================================================


class TestParseScratchpad:
    def test_completed_and_pending(self):
        text = """# Task
## Items
- [x] done item
- [ ] pending item
## Status
IN_PROGRESS"""
        completed, pending, status = _parse_scratchpad(text)
        assert "done item" in completed
        assert "pending item" in pending
        assert status == "IN_PROGRESS"

    def test_status_done(self):
        text = """# Task
## Items
- [x] item1
## Status
DONE"""
        completed, pending, status = _parse_scratchpad(text)
        assert status == "DONE"
        assert len(pending) == 0

    def test_status_alternative_format(self):
        text = """# Task
## Items
- [ ] item
Status: IN_PROGRESS"""
        completed, pending, status = _parse_scratchpad(text)
        assert status == "IN_PROGRESS"

    def test_ignores_checkboxes_in_fenced_code(self):
        text = """# Task
## Items
- [ ] real item
```
- [x] fake in code block
```
## Status
IN_PROGRESS"""
        completed, pending, status = _parse_scratchpad(text)
        # Fenced block is stripped, so "fake in code block" shouldn't appear
        assert "real item" in pending
        # The fake checkbox is inside the fence - after stripping, it's gone
        # So we should only have "real item" in pending
        assert len(pending) == 1

    def test_uppercase_x_checkbox(self):
        text = """## Items
- [X] completed
- [ ] pending
## Status
IN_PROGRESS"""
        completed, pending, status = _parse_scratchpad(text)
        assert "completed" in completed
        assert "pending" in pending


# ===================================================================
# _find_scratchpad -- default.md fallback
# ===================================================================


class TestFindScratchpadFallback:
    """Test that _find_scratchpad falls back to default.md."""

    def test_returns_session_specific_when_exists(self, tmp_path):
        """Session-specific scratchpad takes priority over default.md."""
        scratch_dir = tmp_path / "scratchpads"
        scratch_dir.mkdir()
        session_file = scratch_dir / "abc123.md"
        session_file.write_text("# Task\n## Items\n- [ ] item\n## Status\nIN_PROGRESS\n")
        default_file = scratch_dir / "default.md"
        default_file.write_text("# Default\n## Items\n- [ ] other\n## Status\nIN_PROGRESS\n")

        with mock.patch.object(_grind_mod, "_SCRATCHPADS_DIR", scratch_dir):
            result = _find_scratchpad("abc123")
        assert result is not None
        assert result.name == "abc123.md"

    def test_falls_back_to_default_when_session_missing(self, tmp_path):
        """Falls back to default.md when session-specific file doesn't exist."""
        scratch_dir = tmp_path / "scratchpads"
        scratch_dir.mkdir()
        default_file = scratch_dir / "default.md"
        default_file.write_text("# Task\n## Items\n- [ ] item\n## Status\nIN_PROGRESS\n")

        with mock.patch.object(_grind_mod, "_SCRATCHPADS_DIR", scratch_dir):
            result = _find_scratchpad("nonexistent-session")
        assert result is not None
        assert result.name == "default.md"

    def test_returns_none_when_neither_exists(self, tmp_path):
        """Returns None when neither session nor default scratchpad exists."""
        scratch_dir = tmp_path / "scratchpads"
        scratch_dir.mkdir()

        with mock.patch.object(_grind_mod, "_SCRATCHPADS_DIR", scratch_dir):
            result = _find_scratchpad("nonexistent-session")
        assert result is None

    def test_returns_none_when_dir_missing(self, tmp_path):
        """Returns None when scratchpads directory does not exist."""
        scratch_dir = tmp_path / "no_such_dir"

        with mock.patch.object(_grind_mod, "_SCRATCHPADS_DIR", scratch_dir):
            result = _find_scratchpad("any-session")
        assert result is None

    def test_session_file_takes_priority_over_default(self, tmp_path):
        """Explicit priority check: session-specific file wins over default."""
        scratch_dir = tmp_path / "scratchpads"
        scratch_dir.mkdir()
        session_file = scratch_dir / "mysession.md"
        session_file.write_text("session content")
        default_file = scratch_dir / "default.md"
        default_file.write_text("default content")

        with mock.patch.object(_grind_mod, "_SCRATCHPADS_DIR", scratch_dir):
            result = _find_scratchpad("mysession")
        assert result is not None
        assert result == session_file


# ===================================================================
# _cleanup_stale -- default.md protection
# ===================================================================


class TestCleanupStaleDefaultProtection:
    """Test that _cleanup_stale does NOT delete default.md."""

    def test_does_not_delete_default_md(self, tmp_path):
        """default.md is preserved even when older than the stale threshold."""
        scratch_dir = tmp_path / "scratchpads"
        scratch_dir.mkdir()
        default_file = scratch_dir / "default.md"
        default_file.write_text("# Persistent default scratchpad\n")
        # Set mtime to 48 hours ago (well past the 24h threshold)
        old_time = time.time() - 48 * 3600
        import os
        os.utime(default_file, (old_time, old_time))

        with mock.patch.object(_grind_mod, "_SCRATCHPADS_DIR", scratch_dir):
            _cleanup_stale()
        assert default_file.exists(), "default.md should not be cleaned up"

    def test_deletes_stale_session_files(self, tmp_path):
        """Stale session-specific files are cleaned up normally."""
        scratch_dir = tmp_path / "scratchpads"
        scratch_dir.mkdir()
        stale_file = scratch_dir / "old-session.md"
        stale_file.write_text("# Stale session\n")
        old_time = time.time() - 48 * 3600
        import os
        os.utime(stale_file, (old_time, old_time))

        with mock.patch.object(_grind_mod, "_SCRATCHPADS_DIR", scratch_dir):
            _cleanup_stale()
        assert not stale_file.exists(), "Stale session file should be removed"

    def test_preserves_fresh_session_files(self, tmp_path):
        """Non-stale session files are preserved."""
        scratch_dir = tmp_path / "scratchpads"
        scratch_dir.mkdir()
        fresh_file = scratch_dir / "recent-session.md"
        fresh_file.write_text("# Fresh session\n")

        with mock.patch.object(_grind_mod, "_SCRATCHPADS_DIR", scratch_dir):
            _cleanup_stale()
        assert fresh_file.exists(), "Fresh session file should not be removed"

    def test_default_and_stale_coexist(self, tmp_path):
        """default.md survives cleanup while stale session files are removed."""
        scratch_dir = tmp_path / "scratchpads"
        scratch_dir.mkdir()
        default_file = scratch_dir / "default.md"
        default_file.write_text("# Default\n")
        stale_file = scratch_dir / "stale-session.md"
        stale_file.write_text("# Stale\n")
        import os
        old_time = time.time() - 48 * 3600
        os.utime(default_file, (old_time, old_time))
        os.utime(stale_file, (old_time, old_time))

        with mock.patch.object(_grind_mod, "_SCRATCHPADS_DIR", scratch_dir):
            _cleanup_stale()
        assert default_file.exists(), "default.md must survive cleanup"
        assert not stale_file.exists(), "Stale session file should be removed"


# ===================================================================
# default.md end-to-end with main()
# ===================================================================


class TestDefaultScratchpadEndToEnd:
    """Test that default.md works end-to-end through main()."""

    def test_main_uses_default_md_fallback(self, tmp_path, capsys):
        """main() picks up default.md when session-specific file is absent."""
        scratch_dir = tmp_path / "scratchpads"
        scratch_dir.mkdir()
        default_file = scratch_dir / "default.md"
        default_file.write_text(
            "# Task: Test default\n\n"
            "## Items\n"
            "- [x] step 1\n"
            "- [ ] step 2\n"
            "- [ ] step 3\n\n"
            "## Status\n"
            "IN_PROGRESS\n"
        )

        with (
            mock.patch.object(_grind_mod, "_SCRATCHPADS_DIR", scratch_dir),
            mock.patch.object(_grind_mod, "_read_hook_input", return_value={}),
            mock.patch("helpers.session_utils.resolve_session_id", return_value="no-such-session"),
        ):
            with pytest.raises(SystemExit) as exc_info:
                _grind_mod.main()
            assert exc_info.value.code == 0

        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "followup_message" in output
        assert "step 2" in output["followup_message"] or "2 item(s) remaining" in output["followup_message"]
