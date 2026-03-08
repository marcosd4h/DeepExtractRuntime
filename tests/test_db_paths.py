"""Tests for helpers.db_paths -- path resolution and Windows long-path safety.

Target: .agent/helpers/db_paths.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from helpers.db_paths import (
    resolve_db_path,
    resolve_tracking_db,
    safe_long_path,
    safe_makedirs,
)


# ---------------------------------------------------------------------------
# resolve_db_path
# ---------------------------------------------------------------------------


class TestResolveDbPath:

    def test_absolute_path_returned_as_is(self, tmp_path):
        db = tmp_path / "test.db"
        db.write_bytes(b"")
        result = resolve_db_path(str(db), tmp_path)
        assert result == str(db)

    def test_relative_path_resolved(self, tmp_path):
        db = tmp_path / "my.db"
        db.write_bytes(b"")
        result = resolve_db_path("my.db", tmp_path)
        assert result == str(db)

    def test_fallback_to_extracted_dbs(self, tmp_path):
        dbs_dir = tmp_path / "extracted_dbs"
        dbs_dir.mkdir()
        db = dbs_dir / "module.db"
        db.write_bytes(b"")
        result = resolve_db_path("module.db", tmp_path)
        assert result == str(db)

    def test_nonexistent_returns_path(self, tmp_path):
        result = resolve_db_path("missing.db", tmp_path)
        assert "missing.db" in result


# ---------------------------------------------------------------------------
# resolve_tracking_db (now checks two locations)
# ---------------------------------------------------------------------------


class TestResolveTrackingDb:

    def test_in_extracted_dbs(self, tmp_path):
        dbs_dir = tmp_path / "extracted_dbs"
        dbs_dir.mkdir()
        tracking = dbs_dir / "analyzed_files.db"
        tracking.write_bytes(b"")
        result = resolve_tracking_db(tmp_path)
        assert result == str(tracking)

    def test_at_root_level(self, tmp_path):
        tracking = tmp_path / "analyzed_files.db"
        tracking.write_bytes(b"")
        result = resolve_tracking_db(tmp_path)
        assert result == str(tracking)

    def test_extracted_dbs_takes_priority(self, tmp_path):
        """When both locations exist, extracted_dbs/ should win."""
        dbs_dir = tmp_path / "extracted_dbs"
        dbs_dir.mkdir()
        tracking_dbs = dbs_dir / "analyzed_files.db"
        tracking_dbs.write_bytes(b"inner")
        tracking_root = tmp_path / "analyzed_files.db"
        tracking_root.write_bytes(b"outer")
        result = resolve_tracking_db(tmp_path)
        assert result == str(tracking_dbs)

    def test_missing_returns_none(self, tmp_path):
        result = resolve_tracking_db(tmp_path)
        assert result is None


# ---------------------------------------------------------------------------
# safe_long_path
# ---------------------------------------------------------------------------


class TestSafeLongPath:

    def test_short_path_unchanged(self, tmp_path):
        p = safe_long_path(tmp_path / "short.txt")
        # Should not have \\?\ prefix for short paths
        assert str(p) == str((tmp_path / "short.txt").resolve())

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")
    def test_long_path_gets_prefix(self, tmp_path):
        long_name = "a" * 200
        another_long = "b" * 100
        long_path = tmp_path / long_name / another_long / "file.txt"
        result = safe_long_path(long_path)
        assert str(result).startswith("\\\\?\\")

    def test_returns_path_object(self, tmp_path):
        result = safe_long_path(tmp_path / "test")
        assert isinstance(result, Path)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")
    def test_exactly_260_chars_gets_prefix(self, tmp_path):
        """Verify the >= 260 boundary (fix for off-by-one)."""
        base = str(tmp_path) + "\\"
        remaining = 260 - len(base)
        if remaining <= 0:
            pytest.skip("tmp_path too long for boundary test")
        long_name = "x" * remaining
        path_str = base + long_name
        assert len(path_str) == 260
        result = safe_long_path(path_str)
        assert str(result).startswith("\\\\?\\")

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")
    def test_259_chars_no_prefix(self, tmp_path):
        """Paths under 260 should NOT get the prefix."""
        base = str(tmp_path) + "\\"
        remaining = 259 - len(base)
        if remaining <= 0:
            pytest.skip("tmp_path too long for boundary test")
        short_name = "y" * remaining
        path_str = base + short_name
        assert len(path_str) == 259
        result = safe_long_path(path_str)
        assert not str(result).startswith("\\\\?\\")

# ---------------------------------------------------------------------------
# safe_makedirs
# ---------------------------------------------------------------------------


class TestSafeMakedirs:

    def test_creates_directory(self, tmp_path):
        target = tmp_path / "deep" / "nested" / "dir"
        result = safe_makedirs(target)
        assert result.exists()
        assert result.is_dir()

    def test_exist_ok(self, tmp_path):
        target = tmp_path / "existing"
        target.mkdir()
        result = safe_makedirs(target, exist_ok=True)
        assert result.exists()

    def test_returns_path(self, tmp_path):
        result = safe_makedirs(tmp_path / "new_dir")
        assert isinstance(result, Path)
