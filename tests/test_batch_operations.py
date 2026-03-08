from __future__ import annotations

import sqlite3

import pytest

from helpers.batch_operations import load_function_record
from helpers.errors import ErrorCode, ScriptError
from skills._shared.verify_base import verify_findings


class _DummyDb:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def get_file_info(self):
        return None


def test_load_function_record_returns_none_for_missing_function(sample_db):
    assert load_function_record(str(sample_db), function_name="DefinitelyMissing") is None


def test_load_function_record_raises_script_error_on_open_failure(monkeypatch, tmp_path):
    def _raise_open(_db_path):
        raise RuntimeError("Failed to open DB for testing")

    monkeypatch.setattr(
        "helpers.individual_analysis_db.open_individual_analysis_db",
        _raise_open,
    )

    with pytest.raises(ScriptError) as exc_info:
        load_function_record(str(tmp_path / "missing.db"), function_id=1)

    assert exc_info.value.code == ErrorCode.DB_ERROR


def test_load_function_record_raises_script_error_on_query_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "helpers.individual_analysis_db.open_individual_analysis_db",
        lambda _db_path: _DummyDb(),
    )
    monkeypatch.setattr(
        "helpers.function_resolver.resolve_function",
        lambda *args, **kwargs: (_ for _ in ()).throw(sqlite3.OperationalError("boom")),
    )

    with pytest.raises(ScriptError) as exc_info:
        load_function_record(str(tmp_path / "query_fail.db"), function_id=1)

    assert exc_info.value.code == ErrorCode.DB_ERROR


def test_verify_findings_records_infrastructure_failure():
    findings = [{
        "function_id": 123,
        "function_name": "Problematic",
        "category": "test_category",
        "score": 0.9,
    }]

    def _raise_loader(_db_path, function_id=None):
        raise ScriptError("query failed", ErrorCode.DB_ERROR)

    results = verify_findings(
        findings,
        "fake.db",
        category_verifiers={},
        check_feasibility=lambda finding, func: True,
        load_function_record=_raise_loader,
        status_message=lambda _msg: None,
    )

    assert len(results) == 1
    result = results[0]
    assert result.confidence == "UNCERTAIN"
    assert result.finding["infrastructure_error"]["code"] == ErrorCode.DB_ERROR
    assert "infrastructure error" in result.reasoning.lower()
