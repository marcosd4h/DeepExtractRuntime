"""Extended tests for helpers.validation -- workspace data validation,
parameter validators, and the new validate_depth/validate_positive_int.

Target: .agent/helpers/validation.py
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from helpers.errors import ScriptError
from helpers.validation import (
    WorkspaceDataStatus,
    validate_analysis_db,
    validate_depth,
    validate_function_id,
    validate_function_index,
    validate_positive_int,
    validate_tracking_db,
    validate_workspace_data,
    quick_validate,
)


def _create_tracking_db(db_path: Path) -> None:
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        """
        CREATE TABLE analyzed_files (
            file_path TEXT PRIMARY KEY NOT NULL,
            base_dir TEXT,
            file_name TEXT,
            file_extension TEXT,
            md5_hash TEXT,
            sha256_hash TEXT,
            analysis_db_path TEXT,
            status TEXT NOT NULL DEFAULT 'PENDING',
            analysis_flags TEXT,
            analysis_start_timestamp TIMESTAMP,
            analysis_completion_timestamp TIMESTAMP
        )
        """
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# validate_workspace_data
# ---------------------------------------------------------------------------


class TestValidateWorkspaceData:
    """Test workspace data pre-flight validation."""

    def test_empty_workspace(self, tmp_path):
        status = validate_workspace_data(tmp_path, sample_limit=0)
        assert not status.ok
        assert not status.has_extracted_code
        assert not status.has_extracted_dbs
        assert len(status.errors) > 0

    def test_code_only_workspace(self, tmp_path):
        code_dir = tmp_path / "extracted_code" / "test_dll"
        code_dir.mkdir(parents=True)
        (code_dir / "function_index.json").write_text("{}", encoding="utf-8")
        (code_dir / "file_info.json").write_text("{}", encoding="utf-8")

        status = validate_workspace_data(tmp_path, sample_limit=0)
        assert status.ok
        assert status.has_extracted_code
        assert not status.has_extracted_dbs
        assert status.json_only
        assert "test_dll" in status.modules_with_code
        assert len(status.warnings) > 0  # warns about missing dbs

    def test_full_workspace(self, tmp_path):
        # Create code
        code_dir = tmp_path / "extracted_code" / "test_dll"
        code_dir.mkdir(parents=True)
        (code_dir / "function_index.json").write_text("{}", encoding="utf-8")

        # Create dbs
        dbs_dir = tmp_path / "extracted_dbs"
        dbs_dir.mkdir()
        db_path = dbs_dir / "test_dll_abc123.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE functions (function_id INTEGER PRIMARY KEY)")
        conn.close()

        tracking = dbs_dir / "analyzed_files.db"
        _create_tracking_db(tracking)

        status = validate_workspace_data(tmp_path, sample_limit=0)
        assert status.ok
        assert status.has_extracted_code
        assert status.has_extracted_dbs
        assert status.has_tracking_db
        assert not status.json_only

    def test_full_workspace_with_workspace_relative_db_path(self, tmp_path):
        code_dir = tmp_path / "extracted_code" / "test_dll"
        code_dir.mkdir(parents=True)
        (code_dir / "function_index.json").write_text("{}", encoding="utf-8")

        dbs_dir = tmp_path / "extracted_dbs"
        dbs_dir.mkdir()
        module_db = dbs_dir / "test_dll_abc123.db"
        conn = sqlite3.connect(str(module_db))
        conn.execute("CREATE TABLE functions (function_id INTEGER PRIMARY KEY)")
        conn.close()

        tracking = dbs_dir / "analyzed_files.db"
        _create_tracking_db(tracking)
        conn = sqlite3.connect(str(tracking))
        conn.execute(
            "INSERT INTO analyzed_files (file_path, file_name, analysis_db_path, status) "
            "VALUES (?, ?, ?, ?)",
            (
                "C:\\test\\test.dll",
                "test.dll",
                "extracted_dbs/test_dll_abc123.db",
                "COMPLETE",
            ),
        )
        conn.commit()
        conn.close()

        status = validate_workspace_data(tmp_path, sample_limit=0)
        assert status.has_tracking_db
        assert "test_dll_abc123" in status.modules_with_dbs
        assert status.json_only_modules == []

    def test_json_only_modules_use_exact_normalized_match(self, tmp_path):
        (tmp_path / "extracted_code" / "combase_dll").mkdir(parents=True)
        (tmp_path / "extracted_code" / "combase_dll" / "function_index.json").write_text(
            "{}",
            encoding="utf-8",
        )
        (tmp_path / "extracted_code" / "combasebroker_dll").mkdir(parents=True)
        (
            tmp_path / "extracted_code" / "combasebroker_dll" / "function_index.json"
        ).write_text("{}", encoding="utf-8")

        dbs_dir = tmp_path / "extracted_dbs"
        dbs_dir.mkdir()
        tracking = dbs_dir / "analyzed_files.db"
        _create_tracking_db(tracking)
        module_db = dbs_dir / "combase_dll_abc123.db"
        conn = sqlite3.connect(str(module_db))
        conn.execute("CREATE TABLE functions (function_id INTEGER PRIMARY KEY)")
        conn.close()

        conn = sqlite3.connect(str(tracking))
        conn.execute(
            "INSERT INTO analyzed_files (file_path, file_name, analysis_db_path, status) "
            "VALUES (?, ?, ?, ?)",
            (
                "C:\\test\\combase.dll",
                "combase.dll",
                "extracted_dbs/combase_dll_abc123.db",
                "COMPLETE",
            ),
        )
        conn.commit()
        conn.close()

        status = validate_workspace_data(tmp_path, sample_limit=0)
        assert "combase_dll" in status.modules_with_code
        assert "combasebroker_dll" in status.modules_with_code
        assert "combasebroker_dll" in status.json_only_modules
        assert "combase_dll" not in status.json_only_modules

    def test_workspace_with_empty_tracking_db_is_not_counted_as_healthy(self, tmp_path):
        code_dir = tmp_path / "extracted_code" / "test_dll"
        code_dir.mkdir(parents=True)
        (code_dir / "function_index.json").write_text("{}", encoding="utf-8")

        dbs_dir = tmp_path / "extracted_dbs"
        dbs_dir.mkdir()
        (dbs_dir / "test_dll_abc123.db").write_bytes(b"sqlite-placeholder")
        (dbs_dir / "analyzed_files.db").write_bytes(b"")

        status = validate_workspace_data(tmp_path, sample_limit=0)
        assert not status.has_tracking_db
        assert any("Tracking DB validation error" in warning for warning in status.warnings)

    def test_summary_method(self, tmp_path):
        status = validate_workspace_data(tmp_path, sample_limit=0)
        summary = status.summary()
        assert isinstance(summary, str)
        assert len(summary) > 0

    def test_db_available_property(self, tmp_path):
        status = validate_workspace_data(tmp_path, sample_limit=0)
        assert not status.db_available


# ---------------------------------------------------------------------------
# validate_depth
# ---------------------------------------------------------------------------


class TestValidateDepth:

    def test_valid_depth(self):
        assert validate_depth(0) == 0
        assert validate_depth(1) == 1
        assert validate_depth(5) == 5

    def test_clamped_depth(self):
        assert validate_depth(100) == 10  # default max_depth=10
        assert validate_depth(20, max_depth=5) == 5

    def test_negative_depth_exits(self):
        with pytest.raises(ScriptError):
            validate_depth(-1)

    def test_custom_max(self):
        assert validate_depth(3, max_depth=3) == 3
        assert validate_depth(4, max_depth=3) == 3


# ---------------------------------------------------------------------------
# validate_positive_int
# ---------------------------------------------------------------------------


class TestValidatePositiveInt:

    def test_valid_int(self):
        assert validate_positive_int(1, "test") == 1
        assert validate_positive_int("42", "test") == 42

    def test_below_min(self):
        with pytest.raises(ScriptError):
            validate_positive_int(0, "test")

    def test_above_max(self):
        with pytest.raises(ScriptError):
            validate_positive_int(100, "test", max_val=50)

    def test_string_int(self):
        assert validate_positive_int("10", "test") == 10

    def test_non_numeric_exits(self):
        with pytest.raises(ScriptError):
            validate_positive_int("abc", "test")

    def test_custom_min(self):
        assert validate_positive_int(0, "test", min_val=0) == 0


# ---------------------------------------------------------------------------
# validate_function_index (additional edge cases)
# ---------------------------------------------------------------------------


class TestValidateFunctionIndexEdgeCases:

    def test_valid_index(self, tmp_path):
        index = {"func1": {"function_id": 1}, "func2": {"function_id": 2}}
        path = tmp_path / "function_index.json"
        path.write_text(json.dumps(index), encoding="utf-8")
        result = validate_function_index(str(path))
        assert result.ok

    def test_missing_function_id_warning(self, tmp_path):
        index = {"func1": {"files": ["test.cpp"]}}
        path = tmp_path / "function_index.json"
        path.write_text(json.dumps(index), encoding="utf-8")
        result = validate_function_index(str(path))
        assert len(result.warnings) > 0

    def test_invalid_json(self, tmp_path):
        path = tmp_path / "function_index.json"
        path.write_text("not json{{{", encoding="utf-8")
        result = validate_function_index(str(path))
        assert not result.ok

    def test_invalid_entry_after_tenth_is_reported(self, tmp_path):
        index = {
            f"func{i}": {"function_id": i}
            for i in range(1, 16)
        }
        index["func12"] = "not-a-dict"
        path = tmp_path / "function_index.json"
        path.write_text(json.dumps(index), encoding="utf-8")

        result = validate_function_index(str(path))

        assert not result.ok
        assert any("func12" in error for error in result.errors)


class TestValidateTrackingDb:
    def test_missing_analyzed_files_table(self, tmp_path):
        db_path = tmp_path / "analyzed_files.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE something_else (id INTEGER)")
        conn.commit()
        conn.close()

        result = validate_tracking_db(str(db_path))
        assert not result.ok
        assert any("analyzed_files" in error for error in result.errors)

    def test_missing_required_columns(self, tmp_path):
        db_path = tmp_path / "analyzed_files.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            """
            CREATE TABLE analyzed_files (
                file_path TEXT PRIMARY KEY NOT NULL,
                file_name TEXT,
                status TEXT NOT NULL DEFAULT 'PENDING'
            )
            """
        )
        conn.commit()
        conn.close()

        result = validate_tracking_db(str(db_path))
        assert not result.ok
        assert any("analysis_db_path" in error for error in result.errors)

    def test_complete_record_missing_analysis_db_path(self, tmp_path):
        db_path = tmp_path / "analyzed_files.db"
        _create_tracking_db(db_path)
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "INSERT INTO analyzed_files (file_path, file_name, analysis_db_path, status) "
            "VALUES (?, ?, ?, ?)",
            ("C:\\test\\appinfo.dll", "appinfo.dll", None, "COMPLETE"),
        )
        conn.commit()
        conn.close()

        result = validate_tracking_db(str(db_path))
        assert result.ok
        assert any("no analysis_db_path" in warning for warning in result.warnings)

    def test_complete_record_with_missing_db(self, tmp_path):
        db_path = tmp_path / "analyzed_files.db"
        _create_tracking_db(db_path)
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "INSERT INTO analyzed_files (file_path, file_name, analysis_db_path, status) "
            "VALUES (?, ?, ?, ?)",
            ("C:\\test\\appinfo.dll", "appinfo.dll", "missing.db", "COMPLETE"),
        )
        conn.commit()
        conn.close()

        result = validate_tracking_db(str(db_path))
        assert not result.ok
        assert any("points to missing DB" in error for error in result.errors)

    def test_valid_tracking_db(self, tmp_path):
        db_path = tmp_path / "analyzed_files.db"
        _create_tracking_db(db_path)
        module_db = tmp_path / "module_abc123.db"
        module_db.write_bytes(b"sqlite-placeholder")
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "INSERT INTO analyzed_files (file_path, file_name, analysis_db_path, status) "
            "VALUES (?, ?, ?, ?)",
            ("C:\\test\\appinfo.dll", "appinfo.dll", module_db.name, "COMPLETE"),
        )
        conn.commit()
        conn.close()

        result = validate_tracking_db(str(db_path))
        assert result.ok
        assert result.errors == []

    def test_valid_tracking_db_with_workspace_relative_db_path(self, tmp_path):
        dbs_dir = tmp_path / "extracted_dbs"
        dbs_dir.mkdir()
        db_path = dbs_dir / "analyzed_files.db"
        _create_tracking_db(db_path)
        module_db = dbs_dir / "module_abc123.db"
        module_db.write_bytes(b"sqlite-placeholder")
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "INSERT INTO analyzed_files (file_path, file_name, analysis_db_path, status) "
            "VALUES (?, ?, ?, ?)",
            (
                "C:\\test\\appinfo.dll",
                "appinfo.dll",
                "extracted_dbs/module_abc123.db",
                "COMPLETE",
            ),
        )
        conn.commit()
        conn.close()

        result = validate_tracking_db(str(db_path))
        assert result.ok
        assert result.errors == []

    def test_array_instead_of_dict(self, tmp_path):
        path = tmp_path / "function_index.json"
        path.write_text("[1, 2, 3]", encoding="utf-8")
        result = validate_function_index(str(path))
        assert not result.ok


# ---------------------------------------------------------------------------
# quick_validate
# ---------------------------------------------------------------------------


class TestQuickValidate:

    def test_nonexistent_file(self, tmp_path):
        assert not quick_validate(str(tmp_path / "missing.db"))

    def test_empty_file(self, tmp_path):
        path = tmp_path / "empty.db"
        path.write_bytes(b"")
        assert not quick_validate(str(path))

    def test_valid_db(self, sample_db):
        assert quick_validate(str(sample_db))
