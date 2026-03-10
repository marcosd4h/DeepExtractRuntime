"""Tests for helpers/command_validation.py.

Validates the command-layer argument validation helper: module existence
checks, function resolution, depth validation, and the composite
validate_command_args() dispatcher.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from helpers.command_validation import (
    CommandValidationResult,
    command_preflight,
    validate_command_args,
    validate_depth_param,
    validate_function_arg,
    validate_module,
)
from helpers.errors import ErrorCode


# ===================================================================
# CommandValidationResult
# ===================================================================


class TestCommandValidationResult:
    def test_default_is_ok(self):
        r = CommandValidationResult()
        assert r.ok is True
        assert r.errors == []
        assert r.error_codes == []
        assert r.warnings == []
        assert r.resolved == {}

    def test_add_error_sets_ok_false(self):
        r = CommandValidationResult()
        r.add_error("something went wrong")
        assert r.ok is False
        assert "something went wrong" in r.errors
        assert r.error_codes == [ErrorCode.INVALID_ARGS.value]

    def test_add_warning_keeps_ok_true(self):
        r = CommandValidationResult()
        r.add_warning("heads up")
        assert r.ok is True
        assert "heads up" in r.warnings

    def test_multiple_errors(self):
        r = CommandValidationResult()
        r.add_error("err1")
        r.add_error("err2")
        assert len(r.errors) == 2
        assert r.ok is False


# ===================================================================
# validate_depth
# ===================================================================


class TestValidateDepth:
    def test_valid_depth(self):
        r = validate_depth_param(5)
        assert r.ok is True
        assert r.resolved["depth"] == 5

    def test_depth_one(self):
        r = validate_depth_param(1)
        assert r.ok is True
        assert r.resolved["depth"] == 1

    def test_depth_clamped_to_max(self):
        r = validate_depth_param(50, max_depth=20)
        assert r.ok is True
        assert r.resolved["depth"] == 20
        assert len(r.warnings) == 1

    def test_depth_zero_invalid(self):
        r = validate_depth_param(0)
        assert r.ok is False

    def test_depth_negative_invalid(self):
        r = validate_depth_param(-1)
        assert r.ok is False

    def test_depth_non_numeric(self):
        r = validate_depth_param("abc")
        assert r.ok is False
        assert any("integer" in e.lower() for e in r.errors)

    def test_depth_none(self):
        r = validate_depth_param(None)
        assert r.ok is False

    def test_depth_string_numeric(self):
        r = validate_depth_param("3")
        assert r.ok is True
        assert r.resolved["depth"] == 3


# ===================================================================
# validate_function_arg
# ===================================================================


class TestValidateFunctionArg:
    def test_valid_function_name(self, sample_db):
        r = validate_function_arg(str(sample_db), "DllMain")
        assert r.ok is True
        assert r.resolved["function_name"] == "DllMain"
        assert r.resolved["function_id"] == 1

    def test_valid_function_id(self, sample_db):
        r = validate_function_arg(str(sample_db), "1")
        assert r.ok is True
        assert r.resolved["function_id"] == 1

    def test_function_not_found(self, sample_db):
        r = validate_function_arg(str(sample_db), "NonexistentFunction")
        assert r.ok is False
        assert len(r.errors) > 0
        assert r.error_codes == [ErrorCode.NOT_FOUND.value]

    def test_empty_function_ref(self, sample_db):
        r = validate_function_arg(str(sample_db), "")
        assert r.ok is False
        assert any("empty" in e.lower() for e in r.errors)

    def test_none_function_ref(self, sample_db):
        r = validate_function_arg(str(sample_db), None)
        assert r.ok is False

    def test_invalid_db_path(self, tmp_path):
        r = validate_function_arg(str(tmp_path / "nonexistent.db"), "FuncName")
        assert r.ok is False
        assert r.error_codes == [ErrorCode.DB_ERROR.value]

    def test_invalid_function_id_negative(self, sample_db):
        r = validate_function_arg(str(sample_db), "-1")
        assert r.ok is False
        assert any("invalid function id" in e.lower() for e in r.errors)
        assert r.error_codes == [ErrorCode.INVALID_ARGS.value]

    def test_whitespace_only_function_ref(self, sample_db):
        r = validate_function_arg(str(sample_db), "   ")
        assert r.ok is False

    def test_ambiguous_function_name_sets_ambiguous_code(self, sample_db):
        r = validate_function_arg(str(sample_db), "sub_14000")
        assert r.ok is False
        assert r.error_codes == [ErrorCode.AMBIGUOUS.value]


# ===================================================================
# validate_module
# ===================================================================


class TestValidateModule:
    def test_empty_module_name(self):
        r = validate_module("")
        assert r.ok is False
        assert any("empty" in e.lower() for e in r.errors)
        assert r.error_codes == [ErrorCode.INVALID_ARGS.value]

    def test_none_module_name(self):
        r = validate_module(None)
        assert r.ok is False

    def test_whitespace_module_name(self):
        r = validate_module("   ")
        assert r.ok is False

    def test_explicit_workspace_root_is_used(self, tmp_path):
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        dbs_dir = workspace / "extracted_dbs"
        dbs_dir.mkdir()

        module_db = dbs_dir / "appinfo_dll_abc123.db"
        module_db.write_bytes(b"placeholder")

        tracking = dbs_dir / "analyzed_files.db"
        conn = sqlite3.connect(tracking)
        conn.execute("""
            CREATE TABLE analyzed_files (
                file_path TEXT PRIMARY KEY,
                base_dir TEXT,
                file_name TEXT,
                file_extension TEXT,
                md5_hash TEXT,
                sha256_hash TEXT,
                analysis_db_path TEXT,
                status TEXT,
                analysis_flags TEXT,
                analysis_start_timestamp TEXT,
                analysis_completion_timestamp TEXT
            )
        """)
        conn.execute(
            """
            INSERT INTO analyzed_files
                (file_path, file_name, file_extension, analysis_db_path, status)
            VALUES (?, ?, ?, ?, ?)
            """,
            ("C:\\Windows\\System32\\appinfo.dll", "appinfo.dll", ".dll", module_db.name, "COMPLETE"),
        )
        conn.commit()
        conn.close()

        r = validate_module("appinfo.dll", workspace_root=workspace)
        assert r.ok is True
        assert Path(r.resolved["db_path"]) == module_db

    def test_code_only_module_requires_db_by_default(self, tmp_path):
        workspace = tmp_path / "workspace"
        code_dir = workspace / "extracted_code" / "appinfo_dll"
        code_dir.mkdir(parents=True)

        r = validate_module("appinfo.dll", workspace_root=workspace)

        assert r.ok is False
        assert "code_dir" in r.resolved
        assert any("requires an analysis db" in e.lower() for e in r.errors)
        assert r.error_codes == [ErrorCode.NO_DATA.value]

    def test_missing_module_sets_not_found_code(self, tmp_path):
        workspace = tmp_path / "workspace"
        workspace.mkdir()

        r = validate_module("missing.dll", workspace_root=workspace)

        assert r.ok is False
        assert r.error_codes == [ErrorCode.NOT_FOUND.value]


# ===================================================================
# validate_command_args
# ===================================================================


class TestValidateCommandArgs:
    def test_unknown_command_warns(self):
        r = validate_command_args("nonexistent-command", {})
        assert r.ok is True
        assert any("unknown" in w.lower() for w in r.warnings)

    def test_triage_missing_module(self):
        r = validate_command_args("triage", {})
        assert r.ok is False
        assert any("module" in e.lower() for e in r.errors)

    def test_triage_code_only_module_fails_fast(self, tmp_path):
        workspace = tmp_path / "workspace"
        (workspace / "extracted_code" / "appinfo_dll").mkdir(parents=True)

        r = validate_command_args(
            "triage",
            {"module": "appinfo.dll"},
            workspace_root=workspace,
        )

        assert r.ok is False
        assert "db_path" not in r.resolved
        assert any("requires an analysis db" in e.lower() for e in r.errors)

    def test_audit_missing_function(self):
        r = validate_command_args("audit", {"module": "nonexistent.dll"})
        assert r.ok is False

    def test_search_missing_term_and_module(self):
        r = validate_command_args("search", {})
        assert r.ok is False
        assert any("module" in e.lower() or "search" in e.lower() for e in r.errors)

    def test_search_missing_term_only(self):
        """When module resolves but term is missing, the term error fires."""
        r = validate_command_args("search", {"module": "nonexistent.dll"})
        assert r.ok is False

    def test_lift_class_missing_class_and_module(self):
        r = validate_command_args("lift-class", {})
        assert r.ok is False
        assert any("module" in e.lower() or "class" in e.lower() for e in r.errors)

    def test_lift_class_missing_class_only(self):
        """When module resolves but class is missing, the class error fires."""
        r = validate_command_args("lift-class", {"module": "nonexistent.dll"})
        assert r.ok is False

    def test_health_no_args_needed(self):
        r = validate_command_args("health", {})
        assert r.ok is True

    def test_cache_manage_no_args_needed(self):
        r = validate_command_args("cache-manage", {})
        assert r.ok is True

    def test_runs_no_args_needed(self):
        r = validate_command_args("runs", {})
        assert r.ok is True

    def test_brainstorm_no_args_needed(self):
        r = validate_command_args("brainstorm", {})
        assert r.ok is True

    def test_quickstart_no_args_needed(self):
        r = validate_command_args("quickstart", {})
        assert r.ok is True

    def test_depth_validation_passes_through(self):
        r = validate_command_args("health", {"depth": 5})
        assert r.ok is True
        assert r.resolved.get("depth") == 5

    def test_invalid_depth_fails(self):
        r = validate_command_args("health", {"depth": -1})
        assert r.ok is False

    def test_search_allows_moduleless_form(self, monkeypatch):
        called = False

        def _validate_module(module_name, workspace_root=None):
            nonlocal called
            called = True
            return CommandValidationResult()

        monkeypatch.setattr("helpers.command_validation.validate_module", _validate_module)

        r = validate_command_args("search", {"term": "CreateFile"})
        assert r.ok is True
        assert called is False

    def test_verify_allows_moduleless_form(self, monkeypatch):
        called = False

        def _validate_module(module_name, workspace_root=None):
            nonlocal called
            called = True
            return CommandValidationResult()

        monkeypatch.setattr("helpers.command_validation.validate_module", _validate_module)

        r = validate_command_args("verify", {"function": "DllMain"})
        assert r.ok is True
        assert called is False

    def test_audit_allows_optional_module(self, monkeypatch):
        called = False

        def _validate_module(module_name, workspace_root=None):
            nonlocal called
            called = True
            return CommandValidationResult()

        monkeypatch.setattr("helpers.command_validation.validate_module", _validate_module)

        r = validate_command_args("audit", {"function": "DllMain"})
        assert r.ok is True
        assert called is False

    def test_runs_allows_moduleless_form(self, monkeypatch):
        called = False

        def _validate_module(module_name, workspace_root=None):
            nonlocal called
            called = True
            return CommandValidationResult()

        monkeypatch.setattr("helpers.command_validation.validate_module", _validate_module)

        r = validate_command_args("runs", {})
        assert r.ok is True
        assert called is False

    def test_runs_validates_optional_module(self, monkeypatch):
        called = False

        def _validate_module(module_name, workspace_root=None):
            nonlocal called
            called = True
            result = CommandValidationResult()
            result.resolved["db_path"] = "fake.db"
            return result

        monkeypatch.setattr("helpers.command_validation.validate_module", _validate_module)

        r = validate_command_args("runs", {"module": "appinfo.dll"})
        assert r.ok is True
        assert called is True

    @pytest.mark.parametrize("command_name, mode", [
        ("rpc", "surface"),
        ("rpc", "clients"),
        ("winrt", "privesc"),
        ("winrt", "surface"),
        ("com", "surface"),
        ("com", "privesc"),
    ])
    def test_moduleless_modes_are_allowed(self, command_name, mode):
        r = validate_command_args(command_name, {"mode": mode})
        assert r.ok is True

    @pytest.mark.parametrize("command_name, mode", [
        ("rpc", "audit"),
        ("rpc", "trace"),
        ("winrt", "audit"),
        ("winrt", "methods"),
        ("com", "audit"),
        ("com", "methods"),
    ])
    def test_module_required_for_non_moduleless_modes(self, command_name, mode):
        r = validate_command_args(command_name, {"mode": mode})
        assert r.ok is False
        assert any("module" in e.lower() for e in r.errors)


class TestCommandPreflight:
    def test_uses_structured_not_found_code(self, monkeypatch):
        captured: dict[str, object] = {}

        def fake_emit_error(message, code=ErrorCode.UNKNOWN):
            captured["message"] = message
            captured["code"] = code
            raise SystemExit(1)

        monkeypatch.setattr("helpers.errors.emit_error", fake_emit_error)

        with pytest.raises(SystemExit):
            command_preflight("triage", module="missing.dll")

        assert "missing.dll" in captured["message"]
        assert captured["code"] == ErrorCode.NOT_FOUND
