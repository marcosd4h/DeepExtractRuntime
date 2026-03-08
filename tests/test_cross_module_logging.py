"""Tests that cross_module_graph.py exception blocks produce log_warning() calls.

Regression guard for audit fix item 2: bare ``except Exception`` blocks in
ModuleResolver and CrossModuleGraph now emit structured warnings instead of
silently swallowing errors.

Targets:
  helpers/cross_module_graph.py
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

from conftest import _create_sample_db, _seed_sample_db


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_tracking_db(tmp_path: Path, module_dbs: dict[str, Path]) -> Path:
    tracking_path = tmp_path / "analyzed_files.db"
    conn = sqlite3.connect(tracking_path)
    conn.execute("""
        CREATE TABLE analyzed_files (
            file_path TEXT, base_dir TEXT, file_name TEXT,
            file_extension TEXT, md5_hash TEXT, sha256_hash TEXT,
            analysis_db_path TEXT, status TEXT, analysis_flags TEXT,
            analysis_start_timestamp TEXT, analysis_completion_timestamp TEXT
        )
    """)
    for file_name, db_path in module_dbs.items():
        rel = db_path.relative_to(tmp_path)
        conn.execute(
            "INSERT INTO analyzed_files "
            "(file_path, file_name, file_extension, analysis_db_path, status) "
            "VALUES (?, ?, ?, ?, ?)",
            (str(db_path), file_name, ".dll", str(rel), "COMPLETE"),
        )
    conn.commit()
    conn.close()
    return tracking_path


def _create_module_db(tmp_path: Path, name: str, functions: list[tuple[int, str]]) -> Path:
    db_path = tmp_path / f"{name}.db"
    _create_sample_db(db_path)
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO file_info (file_path, file_name, file_extension) VALUES (?, ?, ?)",
        (f"C:\\Windows\\System32\\{name}", name, ".dll"),
    )
    for fid, fname in functions:
        conn.execute(
            "INSERT INTO functions (function_id, function_name, decompiled_code) "
            "VALUES (?, ?, ?)",
            (fid, fname, f"void {fname}() {{}}"),
        )
    conn.commit()
    conn.close()
    return db_path


def _create_corrupt_module_db(tmp_path: Path, name: str) -> Path:
    """Create a DB file that will cause errors when queried."""
    db_path = tmp_path / f"{name}.db"
    _create_sample_db(db_path)
    conn = sqlite3.connect(db_path)
    conn.execute("DROP TABLE functions")
    conn.commit()
    conn.close()
    return db_path


# ---------------------------------------------------------------------------
# Tests: _build_function_name_index logs warnings on corrupt DBs
# ---------------------------------------------------------------------------

class TestBuildFunctionNameIndexLogging:
    def test_logs_warning_on_corrupt_db(self, tmp_path):
        """When a module DB is corrupt, _build_function_name_index logs a warning."""
        from helpers.cross_module_graph import ModuleResolver

        good_db = _create_module_db(tmp_path, "good.dll", [(1, "GoodFunc")])
        bad_db = _create_corrupt_module_db(tmp_path, "bad.dll")
        tracking = _create_tracking_db(tmp_path, {
            "good.dll": good_db,
            "bad.dll": bad_db,
        })

        with patch("helpers.cross_module_graph.log_warning") as mock_warn:
            with ModuleResolver(str(tracking)) as resolver:
                results = resolver.resolve_function("GoodFunc")
                assert len(results) >= 1
                assert mock_warn.called
                warning_msg = mock_warn.call_args_list[0][0][0]
                assert "bad.dll" in warning_msg

    def test_continues_after_corrupt_db(self, tmp_path):
        """Resolver still returns results from healthy modules after encountering corrupt ones."""
        from helpers.cross_module_graph import ModuleResolver

        good_db = _create_module_db(tmp_path, "good.dll", [(1, "GoodFunc")])
        bad_db = _create_corrupt_module_db(tmp_path, "bad.dll")
        tracking = _create_tracking_db(tmp_path, {
            "good.dll": good_db,
            "bad.dll": bad_db,
        })

        with ModuleResolver(str(tracking)) as resolver:
            results = resolver.resolve_function("GoodFunc")
            assert len(results) == 1
            assert results[0]["function_name"] == "GoodFunc"


# ---------------------------------------------------------------------------
# Tests: resolve_function logs warnings on per-module errors
# ---------------------------------------------------------------------------

class TestResolveFunctionLogging:
    def test_resolve_xref_logs_on_error(self, tmp_path):
        """resolve_xref logs a warning when the target module DB is corrupt."""
        from helpers.cross_module_graph import ModuleResolver

        bad_db = _create_corrupt_module_db(tmp_path, "bad.dll")
        tracking = _create_tracking_db(tmp_path, {"bad.dll": bad_db})

        with patch("helpers.cross_module_graph.log_warning") as mock_warn:
            with ModuleResolver(str(tracking)) as resolver:
                result = resolver.resolve_xref("bad.dll", "SomeFunc")
                assert result is not None
                assert result.get("note") is not None
                assert mock_warn.called
                warning_msg = mock_warn.call_args_list[0][0][0]
                assert "bad.dll" in warning_msg or "SomeFunc" in warning_msg


# ---------------------------------------------------------------------------
# Tests: batch_resolve_xrefs logs warnings
# ---------------------------------------------------------------------------

class TestBatchResolveLogging:
    def test_batch_resolve_logs_on_error(self, tmp_path):
        """batch_resolve_xrefs logs warnings for modules with corrupt DBs."""
        from helpers.cross_module_graph import ModuleResolver

        good_db = _create_module_db(tmp_path, "good.dll", [(1, "GoodFunc")])
        bad_db = _create_corrupt_module_db(tmp_path, "bad.dll")
        tracking = _create_tracking_db(tmp_path, {
            "good.dll": good_db,
            "bad.dll": bad_db,
        })

        xrefs = [
            {"function_name": "GoodFunc", "module_name": "good.dll"},
            {"function_name": "BadFunc", "module_name": "bad.dll"},
        ]

        with patch("helpers.cross_module_graph.log_warning") as mock_warn:
            with ModuleResolver(str(tracking)) as resolver:
                results = resolver.batch_resolve_xrefs(xrefs)
                assert results["good.dll!GoodFunc"] is not None
                assert mock_warn.called


class TestTrackingDbLoadLogging:
    def test_missing_tracking_db_logs_warning(self, tmp_path):
        """Resolver emits a structured warning when the tracking DB is missing."""
        from helpers.cross_module_graph import ModuleResolver

        missing_tracking = tmp_path / "missing_analyzed_files.db"

        with patch("helpers.cross_module_graph.log_warning") as mock_warn:
            with ModuleResolver(str(missing_tracking)) as resolver:
                assert resolver.list_modules() == []

        mock_warn.assert_called_once()
        warning_msg, warning_code = mock_warn.call_args[0]
        assert "tracking db" in warning_msg.lower()
        assert warning_code == "NOT_FOUND"


# ---------------------------------------------------------------------------
# Tests: CrossModuleGraph.from_tracking_db logs warnings
# ---------------------------------------------------------------------------

class TestCrossModuleGraphLogging:
    def test_from_tracking_db_logs_on_corrupt_module(self, tmp_path):
        """from_tracking_db logs a warning for modules that fail to load."""
        from helpers.cross_module_graph import CrossModuleGraph

        good_db = _create_module_db(tmp_path, "good.dll", [(1, "GoodFunc")])
        bad_db = _create_corrupt_module_db(tmp_path, "bad.dll")
        tracking = _create_tracking_db(tmp_path, {
            "good.dll": good_db,
            "bad.dll": bad_db,
        })

        with patch("helpers.cross_module_graph.log_warning") as mock_warn:
            with CrossModuleGraph.from_tracking_db(str(tracking)) as graph:
                assert graph.get_module_graph("good.dll") is not None
                assert mock_warn.called
                all_msgs = [call[0][0] for call in mock_warn.call_args_list]
                assert any("bad.dll" in msg for msg in all_msgs)
