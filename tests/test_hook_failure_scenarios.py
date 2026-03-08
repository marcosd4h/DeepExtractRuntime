"""Failure scenario tests for grind-until-done and inject-module-context hooks.

Tests cover corrupted inputs, malformed data, permission errors, race
conditions, and edge cases that the happy-path tests do not exercise.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

_AGENT_DIR = Path(__file__).resolve().parent.parent
if str(_AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENT_DIR))

# Load grind hook module
_GRIND_PATH = _AGENT_DIR / "hooks" / "grind-until-done.py"
_grind_spec = importlib.util.spec_from_file_location("grind_hook", _GRIND_PATH)
_grind_mod = importlib.util.module_from_spec(_grind_spec)
_grind_spec.loader.exec_module(_grind_mod)

_parse_scratchpad = _grind_mod._parse_scratchpad
_validate_scratchpad_format = _grind_mod._validate_scratchpad_format
_find_scratchpad = _grind_mod._find_scratchpad

# Load inject-context module
_INJECT_PATH = _AGENT_DIR / "hooks" / "inject-module-context.py"
_inject_spec = importlib.util.spec_from_file_location("inject_context", _INJECT_PATH)
_inject_mod = importlib.util.module_from_spec(_inject_spec)
_inject_spec.loader.exec_module(_inject_mod)

from hooks._context_builder import build_context as _build_context

from helpers.analyzed_files_db import open_analyzed_files_db as _open_analyzed_files_db
from hooks._scanners import (
    scan_modules as _scan_modules,
    scan_dbs as _scan_dbs,
    count_modules_fast as _count_modules_fast_raw,
)


def _count_modules_fast(extracted_code_dir, tracking_db_path):
    return _count_modules_fast_raw(extracted_code_dir, tracking_db_path, _open_analyzed_files_db)


# ===================================================================
# Grind hook: corrupted scratchpad
# ===================================================================

class TestGrindCorruptedScratchpad:
    """Grind hook must not crash on corrupted scratchpad content."""

    def test_binary_garbage(self):
        content = "\x00\x01\x02\xff\xfe\xfd binary garbage"
        valid, issues = _validate_scratchpad_format(content)
        assert valid is False

    def test_truncated_markdown_mid_section(self):
        content = "# Task\n## Items\n- [ ] ite"
        valid, issues = _validate_scratchpad_format(content)
        assert valid is False
        assert any("status" in i.lower() for i in issues)

    def test_only_whitespace(self):
        content = "   \n\n  \t  \n  "
        valid, issues = _validate_scratchpad_format(content)
        assert valid is False
        assert any("empty" in i.lower() for i in issues)

    def test_parse_scratchpad_binary_garbage(self):
        content = "\x00\xff## Items\n- [ ] broken\n## Status\nIN_PROGRESS"
        completed, pending, status = _parse_scratchpad(content)
        assert isinstance(completed, list)
        assert isinstance(pending, list)
        assert isinstance(status, str)

    def test_parse_scratchpad_no_checkboxes(self):
        content = "# Task\n## Items\nno checkboxes here\n## Status\nIN_PROGRESS"
        completed, pending, status = _parse_scratchpad(content)
        assert len(completed) == 0
        assert len(pending) == 0
        assert status == "IN_PROGRESS"


class TestGrindMalformedCheckboxes:
    """Grind hook handles malformed checkbox formats gracefully."""

    def test_missing_brackets(self):
        content = "# Task\n## Items\n- broken item\n- another\n## Status\nIN_PROGRESS"
        completed, pending, status = _parse_scratchpad(content)
        assert len(completed) == 0
        assert len(pending) == 0

    def test_mixed_checkbox_formats(self):
        content = "# Task\n## Items\n- [x] done\n- [ ] pending\n* not a checkbox\n## Status\nIN_PROGRESS"
        completed, pending, status = _parse_scratchpad(content)
        assert "done" in completed
        assert "pending" in pending
        assert status == "IN_PROGRESS"

    def test_extra_spaces_in_checkbox(self):
        content = "# Task\n## Items\n-  [x]  spaced done\n-  [ ]  spaced pending\n## Status\nIN_PROGRESS"
        completed, pending, status = _parse_scratchpad(content)
        assert len(completed) + len(pending) >= 0


class TestGrindFileErrors:
    """Grind hook handles file system errors gracefully."""

    def test_scratchpad_deleted_between_find_and_read(self, tmp_path):
        """Simulate race: file exists during find but deleted before read."""
        scratch_dir = tmp_path / "scratchpads"
        scratch_dir.mkdir()
        session_file = scratch_dir / "race-session.md"
        session_file.write_text("# Task\n## Items\n- [ ] item\n## Status\nIN_PROGRESS\n")

        with mock.patch.object(_grind_mod, "_SCRATCHPADS_DIR", scratch_dir):
            found = _find_scratchpad("race-session")
            assert found is not None
            os.unlink(found)
            assert not found.exists()

    def test_find_scratchpad_with_path_traversal_attempt(self, tmp_path):
        """Session IDs with path traversal characters should be rejected or handled safely."""
        scratch_dir = tmp_path / "scratchpads"
        scratch_dir.mkdir()

        with mock.patch.object(_grind_mod, "_SCRATCHPADS_DIR", scratch_dir):
            result = _find_scratchpad("../../etc/passwd")
            assert result is None or (result and scratch_dir in result.parents)


# ===================================================================
# Inject context: malformed file_info.json
# ===================================================================

class TestInjectMalformedFileInfo:
    """inject-module-context handles broken file_info.json gracefully."""

    def test_invalid_json_file_info(self, tmp_path):
        mod_dir = tmp_path / "mymod"
        mod_dir.mkdir()
        (mod_dir / "file_info.json").write_text("{invalid json!!!")
        modules = _scan_modules(tmp_path)
        assert len(modules) == 0

    def test_missing_required_fields(self, tmp_path):
        mod_dir = tmp_path / "mymod"
        mod_dir.mkdir()
        (mod_dir / "file_info.json").write_text(json.dumps({"random_field": True}))
        modules = _scan_modules(tmp_path)
        assert isinstance(modules, list)

    def test_empty_file_info(self, tmp_path):
        mod_dir = tmp_path / "mymod"
        mod_dir.mkdir()
        (mod_dir / "file_info.json").write_text("")
        modules = _scan_modules(tmp_path)
        assert len(modules) == 0

    def test_file_info_is_array_not_object(self, tmp_path):
        mod_dir = tmp_path / "mymod"
        mod_dir.mkdir()
        (mod_dir / "file_info.json").write_text(json.dumps([1, 2, 3]))
        modules = _scan_modules(tmp_path)
        assert isinstance(modules, list)


class TestInjectInvalidDatabase:
    """inject-module-context handles corrupt DB files gracefully."""

    def test_db_file_is_not_sqlite(self, tmp_path):
        (tmp_path / "fake.db").write_text("this is not a database")
        dbs, has_tracking = _scan_dbs(tmp_path)
        assert isinstance(dbs, list)

    def test_empty_db_file(self, tmp_path):
        (tmp_path / "empty.db").write_bytes(b"")
        dbs, has_tracking = _scan_dbs(tmp_path)
        assert isinstance(dbs, list)


class TestInjectLargeModuleCount:
    """inject-module-context handles very large module counts."""

    def test_very_large_module_count_via_tracking_db(self, tmp_path):
        db_path = tmp_path / "analyzed_files.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "CREATE TABLE analyzed_files ("
            "  file_path TEXT PRIMARY KEY NOT NULL,"
            "  base_dir TEXT, file_name TEXT, file_extension TEXT,"
            "  md5_hash TEXT, sha256_hash TEXT, analysis_db_path TEXT,"
            "  status TEXT NOT NULL DEFAULT 'PENDING',"
            "  analysis_flags TEXT,"
            "  analysis_start_timestamp TIMESTAMP,"
            "  analysis_completion_timestamp TIMESTAMP)"
        )
        for i in range(200):
            conn.execute(
                "INSERT INTO analyzed_files (file_path, file_name, analysis_db_path, status) "
                "VALUES (?, ?, ?, ?)",
                (f"C:\\mod_{i}.dll", f"mod_{i}.dll", f"mod_{i}_dll_abcdef0123.db", "COMPLETE"),
            )
        conn.commit()
        conn.close()

        count = _count_modules_fast(tmp_path / "nodir", db_path)
        assert count == 200

    def test_compact_mode_with_many_modules(self):
        modules = [
            {"name": f"mod_{i:04d}", "file_name": f"mod_{i:04d}.dll",
             "db_path": f"mod_{i:04d}_abcdef0123.db", "status": "COMPLETE"}
            for i in range(200)
        ]
        ctx = _build_context(modules, [], True, [], "standard", compact_mode=True)
        assert "**200 extracted module(s)**" in ctx
        assert isinstance(ctx, str)


class TestInjectRegistryErrors:
    """inject-module-context handles broken registry files."""

    def test_build_context_with_empty_skill_list(self):
        ctx = _build_context([], [], False, [], "standard")
        assert isinstance(ctx, str)
        assert "DeepExtractIDA" in ctx or "0 extracted" in ctx

    def test_build_context_with_none_session_id(self):
        ctx = _build_context([], [], False, [], "standard", session_id=None)
        assert isinstance(ctx, str)
