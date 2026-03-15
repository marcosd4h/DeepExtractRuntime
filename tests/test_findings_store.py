"""Unit tests for helpers/findings_store.py.

Tests the SQLite-backed findings persistence store.
All tests use pytest tmp_path fixture — no live DBs required.
"""

from __future__ import annotations
import sys
from pathlib import Path

_AGENT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENT_DIR))

import pytest
from helpers.finding_schema import Finding
from helpers.findings_store import (
    FindingsStore,
    upsert_finding,
    load_findings,
    update_verification,
    purge_old_findings,
    get_summary,
)


def _make_finding(function_name="TestFunc", sink="memcpy", source_category="copy",
                  score=0.5, severity="MEDIUM", module="srvsvc.dll", source_type="taint",
                  function_id=42) -> Finding:
    return Finding(
        function_name=function_name,
        function_id=function_id,
        sink=sink,
        source_category=source_category,
        score=score,
        severity=severity,
        module=module,
        source_type=source_type,
    )


class TestFindingsStoreUpsert:

    def test_basic_insert(self, tmp_path):
        db = tmp_path / "findings.db"
        f = _make_finding()
        upsert_finding(f, run_id="run1", db_path=db)
        rows = load_findings(db_path=db)
        assert len(rows) == 1
        assert rows[0].sink == "memcpy"
        assert rows[0].score == pytest.approx(0.5)

    def test_higher_score_replaces_existing(self, tmp_path):
        db = tmp_path / "findings.db"
        f_low = _make_finding(score=0.4, severity="MEDIUM")
        f_high = _make_finding(score=0.9, severity="CRITICAL")  # same dedup_key
        upsert_finding(f_low, run_id="run1", db_path=db)
        upsert_finding(f_high, run_id="run2", db_path=db)
        rows = load_findings(db_path=db)
        assert len(rows) == 1  # deduplicated
        assert rows[0].score == pytest.approx(0.9)
        assert rows[0].severity == "CRITICAL"

    def test_lower_score_no_update(self, tmp_path):
        db = tmp_path / "findings.db"
        f_high = _make_finding(score=0.9, severity="CRITICAL")
        f_low = _make_finding(score=0.3, severity="LOW")
        upsert_finding(f_high, run_id="run1", db_path=db)
        upsert_finding(f_low, run_id="run2", db_path=db)
        rows = load_findings(db_path=db)
        assert rows[0].score == pytest.approx(0.9)  # unchanged

    def test_different_sinks_both_retained(self, tmp_path):
        db = tmp_path / "findings.db"
        f1 = _make_finding(sink="memcpy", source_category="copy")
        f2 = _make_finding(sink="HeapAlloc", source_category="alloc")
        upsert_finding(f1, db_path=db)
        upsert_finding(f2, db_path=db)
        rows = load_findings(db_path=db)
        assert len(rows) == 2

    def test_lower_score_updates_verification_status(self, tmp_path):
        db = tmp_path / "findings.db"
        f = _make_finding(score=0.9)
        f2 = _make_finding(score=0.3)
        f2.verification_status = "FALSE_POSITIVE"
        upsert_finding(f, db_path=db)
        upsert_finding(f2, db_path=db)
        rows = load_findings(db_path=db)
        assert rows[0].score == pytest.approx(0.9)  # score unchanged
        assert rows[0].verification_status == "FALSE_POSITIVE"  # status updated


class TestFindingsStoreLoad:

    def test_load_module_filter(self, tmp_path):
        db = tmp_path / "findings.db"
        upsert_finding(_make_finding(module="srvsvc.dll", sink="s1", source_category="c1"), db_path=db)
        upsert_finding(_make_finding(module="other.dll", sink="s2", source_category="c2"), db_path=db)
        rows = load_findings(module="srvsvc.dll", db_path=db)
        assert len(rows) == 1
        assert rows[0].module == "srvsvc.dll"

    def test_load_severity_filter(self, tmp_path):
        db = tmp_path / "findings.db"
        for sev, sink in [("CRITICAL", "s1"), ("HIGH", "s2"), ("MEDIUM", "s3"), ("LOW", "s4")]:
            upsert_finding(_make_finding(severity=sev, sink=sink, source_category=sink), db_path=db)
        rows = load_findings(severity="HIGH", db_path=db)
        severities = {r.severity for r in rows}
        assert "CRITICAL" in severities
        assert "HIGH" in severities
        assert "MEDIUM" not in severities
        assert "LOW" not in severities

    def test_load_source_type_filter(self, tmp_path):
        db = tmp_path / "findings.db"
        upsert_finding(_make_finding(source_type="taint", sink="s1", source_category="c1"), db_path=db)
        upsert_finding(_make_finding(source_type="memory_corruption", sink="s2", source_category="c2"), db_path=db)
        rows = load_findings(source_type="taint", db_path=db)
        assert len(rows) == 1
        assert rows[0].source_type == "taint"

    def test_load_empty_db(self, tmp_path):
        db = tmp_path / "findings.db"
        assert load_findings(db_path=db) == []

    def test_load_limit_respected(self, tmp_path):
        db = tmp_path / "findings.db"
        for i in range(10):
            upsert_finding(_make_finding(sink=f"sink{i}", source_category=f"cat{i}"), db_path=db)
        rows = load_findings(limit=3, db_path=db)
        assert len(rows) == 3


class TestFindingsStoreUpdateVerification:

    def test_update_sets_status(self, tmp_path):
        db = tmp_path / "findings.db"
        f = _make_finding()
        upsert_finding(f, db_path=db)
        update_verification(f.dedup_key, status="TRUE_POSITIVE", db_path=db)
        rows = load_findings(db_path=db)
        assert rows[0].verification_status == "TRUE_POSITIVE"

    def test_update_nonexistent_key_silent(self, tmp_path):
        db = tmp_path / "findings.db"
        # Should not raise
        update_verification("no::such::key", status="FALSE_POSITIVE", db_path=db)

    def test_update_raises_score(self, tmp_path):
        db = tmp_path / "findings.db"
        f = _make_finding(score=0.5)
        upsert_finding(f, db_path=db)
        update_verification(f.dedup_key, status="TRUE_POSITIVE", score=0.95, db_path=db)
        rows = load_findings(db_path=db)
        assert rows[0].score == pytest.approx(0.95)


class TestFindingsStorePurge:

    def test_purge_removes_entries(self, tmp_path):
        db = tmp_path / "findings.db"
        upsert_finding(_make_finding(), db_path=db)
        # Purge with 0 days = delete everything
        count = purge_old_findings(older_than_days=0, db_path=db)
        assert count >= 1
        assert load_findings(db_path=db) == []

    def test_purge_returns_count(self, tmp_path):
        db = tmp_path / "findings.db"
        upsert_finding(_make_finding(), db_path=db)
        count = purge_old_findings(older_than_days=0, db_path=db)
        assert isinstance(count, int)
        assert count >= 0

    def test_purge_leaves_recent(self, tmp_path):
        db = tmp_path / "findings.db"
        upsert_finding(_make_finding(), db_path=db)
        # Purge very old (1000 days) — should not remove recent finding
        count = purge_old_findings(older_than_days=1000, db_path=db)
        assert count == 0
        assert len(load_findings(db_path=db)) == 1


class TestFindingsStoreSummary:

    def test_summary_structure(self, tmp_path):
        db = tmp_path / "findings.db"
        upsert_finding(_make_finding(severity="CRITICAL", score=0.9, source_type="taint"), db_path=db)
        upsert_finding(_make_finding(severity="HIGH", score=0.7, sink="s2", source_category="c2"), db_path=db)
        s = get_summary(db_path=db)
        assert s["total"] == 2
        assert s["by_severity"].get("CRITICAL") == 1
        assert s["by_severity"].get("HIGH") == 1
        assert s["top_score"] == pytest.approx(0.9)

    def test_summary_empty_db(self, tmp_path):
        db = tmp_path / "findings.db"
        s = get_summary(db_path=db)
        assert s["total"] == 0
        assert s["top_score"] == pytest.approx(0.0)


class TestFindingsStoreIntegration:

    def test_dedup_key_is_primary_key(self, tmp_path):
        db = tmp_path / "findings.db"
        f = _make_finding()
        upsert_finding(f, db_path=db)
        upsert_finding(f, db_path=db)  # same finding twice
        rows = load_findings(db_path=db)
        assert len(rows) == 1  # deduplicated to 1

    def test_round_trip_preserves_fields(self, tmp_path):
        db = tmp_path / "findings.db"
        f = _make_finding(function_name="RoundTripFunc", sink="VirtualAlloc",
                          source_category="alloc", score=0.8, severity="HIGH",
                          module="test.dll", source_type="memory_corruption")
        f.summary = "Test finding for round-trip"
        f.path = ["func1", "func2", "VirtualAlloc"]
        upsert_finding(f, run_id="test-run", db_path=db)
        rows = load_findings(db_path=db)
        assert len(rows) == 1
        r = rows[0]
        assert r.function_name == "RoundTripFunc"
        assert r.sink == "VirtualAlloc"
        assert r.score == pytest.approx(0.8)
        assert r.module == "test.dll"
        assert r.path == ["func1", "func2", "VirtualAlloc"]

    def test_helpers_init_exports_store(self):
        import helpers
        assert hasattr(helpers, "upsert_finding") or "upsert_finding" in dir(helpers)
