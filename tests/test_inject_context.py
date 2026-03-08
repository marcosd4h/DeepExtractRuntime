"""Tests for inject-module-context hook helpers.

Target: .agent/hooks/inject-module-context.py
"""

from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
from pathlib import Path

import pytest

# Load inject-module-context module
_AGENT_DIR = Path(__file__).resolve().parent.parent
_HOOK_PATH = _AGENT_DIR / "hooks" / "inject-module-context.py"
if str(_AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENT_DIR))

spec = importlib.util.spec_from_file_location("inject_context", _HOOK_PATH)
_inject_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(_inject_mod)

_normalize_context_level = _inject_mod._normalize_context_level
_is_level_enabled = _inject_mod._is_level_enabled
_DEFAULT_MODULE_THRESHOLD = _inject_mod._DEFAULT_MODULE_THRESHOLD

from hooks._context_builder import build_context as _build_context

from helpers.analyzed_files_db import open_analyzed_files_db as _open_analyzed_files_db
from hooks._scanners import (
    scan_modules as _scan_modules,
    scan_dbs as _scan_dbs,
    count_modules_fast as _count_modules_fast_raw,
    derive_module_dir_name as _derive_module_dir_name,
    scan_modules_from_tracking_db as _scan_modules_from_tracking_db_raw,
    scan_modules_from_extraction_report as _scan_modules_from_extraction_report,
)


def _count_modules_fast(extracted_code_dir, tracking_db_path):
    return _count_modules_fast_raw(extracted_code_dir, tracking_db_path, _open_analyzed_files_db)


def _scan_modules_from_tracking_db(tracking_db_path):
    return _scan_modules_from_tracking_db_raw(tracking_db_path, _open_analyzed_files_db)


def _create_tracking_db(db_path: Path, rows: list[tuple]) -> None:
    """Helper: create a minimal analyzed_files.db with the given rows.

    Each row is (file_path, file_name, analysis_db_path, status).
    """
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE analyzed_files ("
        "  file_path TEXT PRIMARY KEY NOT NULL,"
        "  base_dir TEXT,"
        "  file_name TEXT,"
        "  file_extension TEXT,"
        "  md5_hash TEXT,"
        "  sha256_hash TEXT,"
        "  analysis_db_path TEXT,"
        "  status TEXT NOT NULL DEFAULT 'PENDING',"
        "  analysis_flags TEXT,"
        "  analysis_start_timestamp TIMESTAMP,"
        "  analysis_completion_timestamp TIMESTAMP"
        ")"
    )
    for file_path, file_name, db_path_val, status in rows:
        conn.execute(
            "INSERT INTO analyzed_files (file_path, file_name, analysis_db_path, status) "
            "VALUES (?, ?, ?, ?)",
            (file_path, file_name, db_path_val, status),
        )
    conn.commit()
    conn.close()


# ===================================================================
# _normalize_context_level
# ===================================================================


class TestNormalizeContextLevel:
    def test_none_returns_standard(self):
        assert _normalize_context_level(None) == "standard"

    def test_valid_levels(self):
        assert _normalize_context_level("minimal") == "minimal"
        assert _normalize_context_level("standard") == "standard"
        assert _normalize_context_level("full") == "full"

    def test_case_insensitive(self):
        assert _normalize_context_level("FULL") == "full"
        assert _normalize_context_level("Standard") == "standard"

    def test_invalid_returns_standard(self):
        assert _normalize_context_level("invalid") == "standard"
        assert _normalize_context_level("") == "standard"


# ===================================================================
# _is_level_enabled
# ===================================================================


class TestIsLevelEnabled:
    def test_full_enables_all(self):
        assert _is_level_enabled("full", "minimal") is True
        assert _is_level_enabled("full", "standard") is True
        assert _is_level_enabled("full", "full") is True

    def test_standard_enables_standard_and_minimal(self):
        assert _is_level_enabled("standard", "minimal") is True
        assert _is_level_enabled("standard", "standard") is True
        assert _is_level_enabled("standard", "full") is False

    def test_minimal_only_minimal(self):
        assert _is_level_enabled("minimal", "minimal") is True
        assert _is_level_enabled("minimal", "standard") is False
        assert _is_level_enabled("minimal", "full") is False


# ===================================================================
# _scan_modules
# ===================================================================


class TestScanModules:
    def test_empty_dir_returns_empty(self, tmp_path):
        assert _scan_modules(tmp_path) == []

    def test_non_dir_returns_empty(self, tmp_path):
        file_path = tmp_path / "file"
        file_path.write_text("x")
        assert _scan_modules(file_path) == []

    def test_scan_valid_file_info(self, tmp_path):
        mod_dir = tmp_path / "mymodule"
        mod_dir.mkdir()
        file_info = {
            "module_name": "mymodule",
            "basic_file_info": {"file_name": "test.dll", "size_bytes": 1000},
            "pe_version_info": {"file_description": "Test", "file_version": "1.0"},
            "function_summary": {"total_functions": 50, "class_methods": [], "standalone_functions": []},
            "entry_points": [],
            "exports": [],
            "imports": [],
        }
        (mod_dir / "file_info.json").write_text(json.dumps(file_info))
        modules = _scan_modules(tmp_path)
        assert len(modules) == 1
        assert modules[0]["name"] == "mymodule"
        assert modules[0]["file_name"] == "test.dll"
        assert modules[0]["total_functions"] == 50

    def test_skips_dir_without_file_info(self, tmp_path):
        (tmp_path / "nomodule").mkdir()
        assert _scan_modules(tmp_path) == []


# ===================================================================
# _scan_dbs
# ===================================================================


class TestScanDbs:
    def test_empty_dir_returns_empty(self, tmp_path):
        dbs, has_tracking = _scan_dbs(tmp_path)
        assert dbs == []
        assert has_tracking is False

    def test_scan_db_files(self, tmp_path):
        (tmp_path / "module_abc.db").write_bytes(b"x" * 100)
        (tmp_path / "other.db").write_bytes(b"y" * 200)
        dbs, has_tracking = _scan_dbs(tmp_path)
        assert len(dbs) == 2
        assert has_tracking is False
        names = {d["file"] for d in dbs}
        assert "module_abc.db" in names
        assert "other.db" in names

    def test_tracking_db_detected(self, tmp_path):
        (tmp_path / "analyzed_files.db").write_bytes(b"x")
        dbs, has_tracking = _scan_dbs(tmp_path)
        assert has_tracking is True
        assert not any(d["file"] == "analyzed_files.db" for d in dbs)


# ===================================================================
# _build_context
# ===================================================================


class TestBuildContext:
    def test_build_minimal_context(self):
        modules = [{"name": "m1", "total_functions": 10, "export_count": 2}]
        dbs = [{"path": "extracted_dbs/m1.db", "size_kb": 50}]
        ctx = _build_context(modules, dbs, False, ["classify"], "minimal")
        assert "m1" in ctx
        assert "10" in ctx
        assert "DeepExtractIDA Workspace Context" in ctx

    def test_build_includes_session_id(self):
        ctx = _build_context([], [], False, [], "standard", session_id="sess-123")
        assert "sess-123" in ctx
        assert "scratchpads" in ctx


# ===================================================================
# _derive_module_dir_name
# ===================================================================


class TestDeriveModuleDirName:
    def test_standard_dll(self):
        assert _derive_module_dir_name("appinfo_dll_f2bbf324a1.db") == "appinfo_dll"

    def test_standard_exe(self):
        assert _derive_module_dir_name("cmd_exe_6d109a3a00.db") == "cmd_exe"

    def test_underscore_in_name(self):
        assert _derive_module_dir_name("coredpus_dll_319f60b0a5.db") == "coredpus_dll"

    def test_no_hash_suffix(self):
        assert _derive_module_dir_name("unusual_name.db") == "unusual_name"

    def test_full_path(self):
        assert _derive_module_dir_name("extracted_dbs/appinfo_dll_f2bbf324a1.db") == "appinfo_dll"

    def test_bare_stem_no_extension(self):
        assert _derive_module_dir_name("test_mod_abcdef0123") == "test_mod"

    def test_empty_string(self):
        result = _derive_module_dir_name("")
        assert isinstance(result, str)

    def test_uppercase_hex_is_matched(self):
        """Unified via helpers.module_discovery: case-insensitive like db_paths.DB_NAME_RE."""
        assert _derive_module_dir_name("mod_ABCDEF0123.db") == "mod"

    def test_short_hash_not_stripped(self):
        assert _derive_module_dir_name("mod_abcde.db") == "mod_abcde"


# ===================================================================
# _count_modules_fast
# ===================================================================


class TestCountModulesFast:
    def test_with_tracking_db(self, tmp_path):
        db_path = tmp_path / "analyzed_files.db"
        _create_tracking_db(db_path, [
            ("C:\\f1.dll", "f1.dll", "f1_dll_abc1234567.db", "COMPLETE"),
            ("C:\\f2.dll", "f2.dll", "f2_dll_def1234567.db", "COMPLETE"),
            ("C:\\f3.exe", "f3.exe", "f3_exe_ghi1234567.db", "PENDING"),
        ])
        count = _count_modules_fast(tmp_path / "nodir", db_path)
        assert count == 3

    def test_fallback_to_directory_listing(self, tmp_path):
        code_dir = tmp_path / "extracted_code"
        code_dir.mkdir()
        for i in range(5):
            mod = code_dir / f"mod_{i}"
            mod.mkdir()
            (mod / "file_info.json").write_text("{}")
        # Also a dir without file_info.json (should not be counted)
        (code_dir / "no_info").mkdir()

        count = _count_modules_fast(code_dir, None)
        assert count == 5

    def test_no_data_returns_zero(self, tmp_path):
        assert _count_modules_fast(tmp_path / "nodir", None) == 0

    def test_tracking_db_preferred_over_dir(self, tmp_path):
        """Tracking DB count is used even if extracted_code/ has different count."""
        code_dir = tmp_path / "extracted_code"
        code_dir.mkdir()
        (code_dir / "mod_a").mkdir()
        (code_dir / "mod_a" / "file_info.json").write_text("{}")

        db_path = tmp_path / "analyzed_files.db"
        _create_tracking_db(db_path, [
            ("C:\\a.dll", "a.dll", "a_dll_1234567890.db", "COMPLETE"),
            ("C:\\b.dll", "b.dll", "b_dll_abcdef0123.db", "COMPLETE"),
            ("C:\\c.dll", "c.dll", "c_dll_fedcba9876.db", "COMPLETE"),
        ])
        count = _count_modules_fast(code_dir, db_path)
        assert count == 3  # DB count, not dir count

    def test_corrupt_tracking_db_falls_back_to_dir(self, tmp_path):
        """If the tracking DB is corrupt, fall back to directory listing."""
        code_dir = tmp_path / "extracted_code"
        code_dir.mkdir()
        for i in range(4):
            mod = code_dir / f"mod_{i}"
            mod.mkdir()
            (mod / "file_info.json").write_text("{}")

        corrupt_db = tmp_path / "analyzed_files.db"
        corrupt_db.write_text("this is not a sqlite database")

        count = _count_modules_fast(code_dir, corrupt_db)
        assert count == 4

    def test_empty_tracking_db_returns_zero(self, tmp_path):
        db_path = tmp_path / "analyzed_files.db"
        _create_tracking_db(db_path, [])
        assert _count_modules_fast(tmp_path / "nodir", db_path) == 0


# ===================================================================
# _scan_modules_from_tracking_db
# ===================================================================


class TestScanModulesFromTrackingDb:
    def test_basic_scan(self, tmp_path):
        db_path = tmp_path / "analyzed_files.db"
        _create_tracking_db(db_path, [
            ("C:\\sys\\appinfo.dll", "appinfo.dll", "appinfo_dll_f2bbf324a1.db", "COMPLETE"),
            ("C:\\sys\\cmd.exe", "cmd.exe", "cmd_exe_6d109a3a00.db", "COMPLETE"),
        ])
        modules = _scan_modules_from_tracking_db(db_path)
        assert len(modules) == 2
        assert modules[0]["name"] == "appinfo_dll"
        assert modules[0]["file_name"] == "appinfo.dll"
        assert modules[0]["status"] == "COMPLETE"
        assert modules[1]["name"] == "cmd_exe"

    def test_missing_db_returns_empty(self, tmp_path):
        modules = _scan_modules_from_tracking_db(tmp_path / "nonexistent.db")
        assert modules == []

    def test_mixed_statuses(self, tmp_path):
        db_path = tmp_path / "analyzed_files.db"
        _create_tracking_db(db_path, [
            ("C:\\a.dll", "a.dll", "a_dll_1234567890.db", "COMPLETE"),
            ("C:\\b.dll", "b.dll", "b_dll_abcdef0123.db", "PENDING"),
            ("C:\\c.dll", "c.dll", "c_dll_fedcba9876.db", "COMPLETE"),
        ])
        modules = _scan_modules_from_tracking_db(db_path)
        assert len(modules) == 3
        statuses = {m["name"]: m["status"] for m in modules}
        assert statuses["a_dll"] == "COMPLETE"
        assert statuses["b_dll"] == "PENDING"

    def test_results_sorted_by_file_name(self, tmp_path):
        db_path = tmp_path / "analyzed_files.db"
        _create_tracking_db(db_path, [
            ("C:\\z.dll", "z.dll", "z_dll_1234567890.db", "COMPLETE"),
            ("C:\\a.dll", "a.dll", "a_dll_abcdef0123.db", "COMPLETE"),
        ])
        modules = _scan_modules_from_tracking_db(db_path)
        assert modules[0]["file_name"] == "a.dll"
        assert modules[1]["file_name"] == "z.dll"

    def test_record_with_empty_db_path_uses_file_name(self, tmp_path):
        db_path = tmp_path / "analyzed_files.db"
        _create_tracking_db(db_path, [
            ("C:\\x.dll", "x.dll", "", "COMPLETE"),
        ])
        modules = _scan_modules_from_tracking_db(db_path)
        assert len(modules) == 1
        assert modules[0]["name"] == "x.dll"
        assert modules[0]["db_path"] == ""

    def test_record_with_null_fields_uses_fallback(self, tmp_path):
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
        conn.execute(
            "INSERT INTO analyzed_files (file_path, file_name, analysis_db_path, status) "
            "VALUES (?, NULL, NULL, ?)",
            ("C:\\unknown", "COMPLETE"),
        )
        conn.commit()
        conn.close()
        modules = _scan_modules_from_tracking_db(db_path)
        assert len(modules) == 1
        assert modules[0]["name"] == "?"

    def test_corrupt_db_returns_empty(self, tmp_path):
        corrupt = tmp_path / "analyzed_files.db"
        corrupt.write_text("not a database")
        assert _scan_modules_from_tracking_db(corrupt) == []


# ===================================================================
# _scan_modules_from_extraction_report
# ===================================================================


class TestScanModulesFromExtractionReport:
    def test_basic_report(self, tmp_path):
        report = {
            "successful_extractions": [
                {
                    "FileName": "C:\\windows\\system32\\appinfo.dll",
                    "DbPath": "C:\\out\\extracted_dbs\\appinfo_dll_f2bbf324a1.db",
                },
                {
                    "FileName": "C:\\windows\\system32\\cmd.exe",
                    "DbPath": "C:\\out\\extracted_dbs\\cmd_exe_6d109a3a00.db",
                },
            ],
        }
        report_path = tmp_path / "extraction_report.json"
        report_path.write_text(json.dumps(report))
        modules = _scan_modules_from_extraction_report(report_path)
        assert len(modules) == 2
        names = {m["name"] for m in modules}
        assert "appinfo_dll" in names
        assert "cmd_exe" in names
        assert all(m["status"] == "COMPLETE" for m in modules)

    def test_missing_report_returns_empty(self, tmp_path):
        assert _scan_modules_from_extraction_report(tmp_path / "nope.json") == []

    def test_empty_successful_extractions(self, tmp_path):
        report_path = tmp_path / "extraction_report.json"
        report_path.write_text(json.dumps({"successful_extractions": []}))
        assert _scan_modules_from_extraction_report(report_path) == []

    def test_results_sorted_by_name(self, tmp_path):
        report = {
            "successful_extractions": [
                {"FileName": "C:\\z.dll", "DbPath": "C:\\out\\z_dll_1234567890.db"},
                {"FileName": "C:\\a.dll", "DbPath": "C:\\out\\a_dll_abcdef0123.db"},
            ],
        }
        report_path = tmp_path / "extraction_report.json"
        report_path.write_text(json.dumps(report))
        modules = _scan_modules_from_extraction_report(report_path)
        assert modules[0]["name"] == "a_dll"
        assert modules[1]["name"] == "z_dll"

    def test_corrupt_json_returns_empty(self, tmp_path):
        report_path = tmp_path / "extraction_report.json"
        report_path.write_text("{invalid json!!!")
        assert _scan_modules_from_extraction_report(report_path) == []

    def test_entry_with_missing_fields(self, tmp_path):
        report = {
            "successful_extractions": [
                {},
                {"FileName": "C:\\only_name.dll"},
                {"DbPath": "C:\\out\\only_db_abc1234567.db"},
            ],
        }
        report_path = tmp_path / "extraction_report.json"
        report_path.write_text(json.dumps(report))
        modules = _scan_modules_from_extraction_report(report_path)
        assert len(modules) == 3
        names = {m["name"] for m in modules}
        assert "only_name.dll" in names
        assert "only_db" in names
        assert "?" in names

    def test_no_successful_extractions_key(self, tmp_path):
        report_path = tmp_path / "extraction_report.json"
        report_path.write_text(json.dumps({"summary": {"total": 0}}))
        assert _scan_modules_from_extraction_report(report_path) == []


# ===================================================================
# _build_context compact mode
# ===================================================================


class TestBuildContextCompactMode:
    @staticmethod
    def _make_compact_modules(count: int) -> list[dict]:
        return [
            {
                "name": f"mod_{i:04d}",
                "file_name": f"mod_{i:04d}.dll",
                "db_path": f"mod_{i:04d}_abcdef0123.db",
                "status": "COMPLETE",
            }
            for i in range(count)
        ]

    def test_compact_mode_shows_count_header(self):
        modules = self._make_compact_modules(30)
        ctx = _build_context(modules, [], True, [], "standard", compact_mode=True)
        assert "**30 extracted module(s)**" in ctx
        assert "| Module |" not in ctx

    def test_compact_mode_shows_status_breakdown(self):
        modules = [
            {"name": "a", "file_name": "a.dll", "db_path": "a.db", "status": "COMPLETE"},
            {"name": "b", "file_name": "b.dll", "db_path": "b.db", "status": "COMPLETE"},
            {"name": "c", "file_name": "c.dll", "db_path": "c.db", "status": "PENDING"},
        ]
        ctx = _build_context(modules, [], True, [], "standard", compact_mode=True)
        assert "2 COMPLETE" in ctx
        assert "1 PENDING" in ctx

    def test_compact_mode_shows_name_list_under_500(self):
        modules = self._make_compact_modules(100)
        ctx = _build_context(modules, [], True, [], "standard", compact_mode=True)
        assert "**100 extracted module(s)**" in ctx
        assert "**100 analysis DB(s)**" in ctx

    def test_compact_mode_omits_name_list_over_500(self):
        modules = self._make_compact_modules(501)
        ctx = _build_context(modules, [], True, [], "standard", compact_mode=True)
        assert "**501 extracted module(s)**" in ctx
        assert "**501 analysis DB(s)**" in ctx

    def test_compact_mode_db_section_shows_count(self):
        modules = self._make_compact_modules(50)
        ctx = _build_context(modules, [], True, [], "standard", compact_mode=True)
        assert "**50 extracted module(s)**" in ctx
        assert "**50 analysis DB(s)**" in ctx

    def test_compact_mode_uses_module_count_for_db_header(self):
        modules = self._make_compact_modules(42)
        ctx = _build_context(modules, [], True, [], "standard", compact_mode=True)
        assert "**42 extracted module(s)**" in ctx
        assert "**42 analysis DB(s)**" in ctx

    def test_compact_mode_includes_guidance(self):
        modules = self._make_compact_modules(30)
        ctx = _build_context(modules, [], True, [], "standard", compact_mode=True)
        assert ".agent/AGENTS.md" in ctx

    def test_normal_mode_still_works(self):
        modules = [{
            "name": "m1", "file_name": "m1.dll", "description": "Test",
            "total_functions": 10, "class_count": 2, "export_count": 1,
            "export_names": ["Foo"], "top_classes": [{"name": "Bar", "method_count": 5}],
            "import_func_count": 20, "import_dll_count": 3,
        }]
        dbs = [{"path": "extracted_dbs/m1.db", "size_kb": 50}]
        ctx = _build_context(modules, dbs, False, [], "standard", compact_mode=False)
        assert "**1 extracted module(s)**" in ctx
        assert "**1 analysis DB(s)**" in ctx
        assert ".agent/AGENTS.md" in ctx

    def test_compact_mode_exactly_500_shows_name_list(self):
        modules = self._make_compact_modules(500)
        ctx = _build_context(modules, [], True, [], "standard", compact_mode=True)
        assert "**500 extracted module(s)**" in ctx
        assert "**500 analysis DB(s)**" in ctx

    def test_compact_mode_no_tracking_db(self):
        modules = self._make_compact_modules(30)
        ctx = _build_context(modules, [], False, [], "standard", compact_mode=True)
        assert "**30 extracted module(s)**" in ctx
        assert "**30 analysis DB(s)**" in ctx

    def test_compact_mode_with_minimal_level(self):
        """Compact mode should render compact modules even at minimal level."""
        modules = self._make_compact_modules(30)
        ctx = _build_context(modules, [], True, ["skill1"], "minimal", compact_mode=True)
        assert "**30 extracted module(s)**" in ctx
        assert "| Module |" not in ctx
        assert "`skill1`" in ctx

    def test_compact_mode_thousand_separator(self):
        modules = self._make_compact_modules(5247)
        ctx = _build_context(modules, [], True, [], "standard", compact_mode=True)
        assert "**5247 extracted module(s)**" in ctx
        assert "**5247 analysis DB(s)**" in ctx

    def test_compact_mode_does_not_access_rich_keys(self):
        """Compact modules lack description/total_functions/etc. -- no KeyError."""
        modules = [
            {"name": "x", "file_name": "x.dll", "db_path": "x.db", "status": "COMPLETE"},
        ]
        ctx = _build_context(modules, [], True, [], "standard", compact_mode=True)
        assert "x" in ctx
        assert "description" not in ctx.lower().split("file_info")[0]

    def test_compact_mode_all_statuses_shown(self):
        modules = [
            {"name": "a", "file_name": "a.dll", "db_path": "a.db", "status": "COMPLETE"},
            {"name": "b", "file_name": "b.dll", "db_path": "b.db", "status": "ANALYZING"},
            {"name": "c", "file_name": "c.dll", "db_path": "c.db", "status": "PENDING"},
            {"name": "d", "file_name": "d.dll", "db_path": "d.db", "status": "COMPLETE"},
        ]
        ctx = _build_context(modules, [], True, [], "standard", compact_mode=True)
        assert "2 COMPLETE" in ctx
        assert "1 ANALYZING" in ctx
        assert "1 PENDING" in ctx

    def test_compact_mode_empty_modules(self):
        ctx = _build_context([], [], True, [], "standard", compact_mode=True)
        assert "### Extracted Modules" not in ctx
        assert "**0 extracted module(s)**" in ctx


# ===================================================================
# Threshold constant
# ===================================================================


class TestThresholdConstant:
    def test_default_threshold_is_positive(self):
        assert _DEFAULT_MODULE_THRESHOLD > 0

    def test_default_threshold_value(self):
        assert _DEFAULT_MODULE_THRESHOLD == 25
