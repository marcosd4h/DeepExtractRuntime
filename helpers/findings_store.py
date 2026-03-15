"""Findings persistence store — SQLite-backed cross-session finding accumulation.

Public API:
    upsert_finding(finding, run_id) — insert or update by dedup_key (score monotone-increasing)
    load_findings(module, min_score, severity, source_type, limit) → list[Finding]
    load_findings_for_run(run_id) → list[Finding]
    update_verification(dedup_key, status, score) — update verification status and score
    update_exploitability(dedup_key, score, rating) — update exploitability fields
    purge_old_findings(older_than_days) → int count deleted
    get_summary(module) → dict with counts by severity/module/source_type
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from helpers.finding_schema import Finding
from helpers.config import get_config_value

__all__ = [
    "FindingsStore",
    "upsert_finding",
    "load_findings",
    "load_findings_for_run",
    "update_verification",
    "update_exploitability",
    "purge_old_findings",
    "get_summary",
]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    dedup_key           TEXT    NOT NULL,
    function_name       TEXT    NOT NULL,
    function_id         INTEGER,
    module              TEXT,
    source_type         TEXT,
    source_category     TEXT,
    sink                TEXT,
    sink_category       TEXT,
    severity            TEXT,
    score               REAL    DEFAULT 0.0,
    exploitability_score REAL,
    exploitability_rating TEXT,
    verification_status  TEXT,
    guards_json         TEXT,
    path_json           TEXT,
    evidence_lines_json TEXT,
    summary             TEXT,
    extra_json          TEXT,
    run_id              TEXT,
    created_at          TEXT,
    updated_at          TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS findings_dedup ON findings(dedup_key);
CREATE INDEX IF NOT EXISTS findings_module ON findings(module);
CREATE INDEX IF NOT EXISTS findings_severity ON findings(severity, score DESC);
CREATE INDEX IF NOT EXISTS findings_run ON findings(run_id);
"""


def _get_db_path() -> Path:
    """Resolve findings store path from config."""
    raw = get_config_value("findings_store.db_path", default=".agent/cache/findings.db")
    # Resolve relative to the workspace root (caller's CWD or WORKSPACE_ROOT)
    p = Path(raw)
    if not p.is_absolute():
        # Try to resolve from .agent's parent directory
        agent_dir = Path(__file__).resolve().parent.parent  # helpers/ -> .agent/
        p = agent_dir.parent / raw
    return p


def _open_db(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """Open the findings SQLite database, creating it if necessary."""
    if db_path is None:
        db_path = _get_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


def _finding_to_row(finding: Finding, run_id: str) -> dict:
    """Convert a Finding to a DB row dict."""
    now = datetime.now(timezone.utc).isoformat()
    return {
        "dedup_key": finding.dedup_key,
        "function_name": finding.function_name,
        "function_id": finding.function_id,
        "module": finding.module or "",
        "source_type": finding.source_type or "",
        "source_category": finding.source_category or "",
        "sink": finding.sink or "",
        "sink_category": finding.sink_category or "",
        "severity": finding.severity or "MEDIUM",
        "score": finding.score or 0.0,
        "exploitability_score": finding.exploitability_score,
        "exploitability_rating": finding.exploitability_rating,
        "verification_status": finding.verification_status,
        "guards_json": json.dumps(finding.guards) if finding.guards else None,
        "path_json": json.dumps(finding.path) if finding.path else None,
        "evidence_lines_json": json.dumps(finding.evidence_lines) if finding.evidence_lines else None,
        "summary": finding.summary or "",
        "extra_json": json.dumps(finding.extra) if finding.extra else None,
        "run_id": run_id,
        "created_at": now,
        "updated_at": now,
    }


def _row_to_finding(row: sqlite3.Row) -> Finding:
    """Convert a DB row to a Finding object."""
    return Finding(
        function_name=row["function_name"],
        function_id=row["function_id"],
        module=row["module"] or "",
        source_type=row["source_type"] or "",
        source_category=row["source_category"] or "",
        sink=row["sink"] or "",
        sink_category=row["sink_category"] or "",
        severity=row["severity"] or "MEDIUM",
        score=row["score"] or 0.0,
        exploitability_score=row["exploitability_score"],
        exploitability_rating=row["exploitability_rating"],
        verification_status=row["verification_status"],
        guards=json.loads(row["guards_json"]) if row["guards_json"] else [],
        path=json.loads(row["path_json"]) if row["path_json"] else [],
        evidence_lines=json.loads(row["evidence_lines_json"]) if row["evidence_lines_json"] else [],
        summary=row["summary"] or "",
        extra=json.loads(row["extra_json"]) if row["extra_json"] else {},
    )


def upsert_finding(finding: Finding, run_id: str = "", db_path: Optional[Path] = None) -> None:
    """Insert or update a finding by dedup_key.

    Score is monotone-increasing: if a finding with the same dedup_key exists and
    has a higher score, only metadata (verification_status, updated_at) is updated.
    """
    row = _finding_to_row(finding, run_id)
    with _open_db(db_path) as conn:
        existing = conn.execute(
            "SELECT score FROM findings WHERE dedup_key = ?", (row["dedup_key"],)
        ).fetchone()

        now = datetime.now(timezone.utc).isoformat()
        if existing is None:
            # New finding
            cols = ", ".join(row.keys())
            placeholders = ", ".join(["?"] * len(row))
            conn.execute(f"INSERT INTO findings ({cols}) VALUES ({placeholders})", list(row.values()))
        elif row["score"] > (existing["score"] or 0.0):
            # Better score — update everything
            row["updated_at"] = now
            conn.execute(
                """UPDATE findings SET
                    function_name=?, function_id=?, module=?, source_type=?, source_category=?,
                    sink=?, sink_category=?, severity=?, score=?, exploitability_score=?,
                    exploitability_rating=?, verification_status=?, guards_json=?, path_json=?,
                    evidence_lines_json=?, summary=?, extra_json=?, run_id=?, updated_at=?
                WHERE dedup_key=?""",
                [
                    row["function_name"], row["function_id"], row["module"], row["source_type"],
                    row["source_category"], row["sink"], row["sink_category"], row["severity"],
                    row["score"], row["exploitability_score"], row["exploitability_rating"],
                    row["verification_status"], row["guards_json"], row["path_json"],
                    row["evidence_lines_json"], row["summary"], row["extra_json"],
                    row["run_id"], now, row["dedup_key"],
                ],
            )
        else:
            # Lower or equal score — only update metadata fields
            conn.execute(
                "UPDATE findings SET verification_status=?, updated_at=? WHERE dedup_key=?",
                [row["verification_status"], now, row["dedup_key"]],
            )
        conn.commit()


def load_findings(
    module: Optional[str] = None,
    min_score: float = 0.0,
    severity: Optional[str] = None,
    source_type: Optional[str] = None,
    limit: int = 200,
    db_path: Optional[Path] = None,
) -> list[Finding]:
    """Load findings from the store with optional filters."""
    _SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    min_sev_rank = _SEVERITY_ORDER.get(severity, 0) if severity else 0

    query = "SELECT * FROM findings WHERE score >= ?"
    params: list = [min_score]

    if module:
        query += " AND module = ?"
        params.append(module)

    if source_type:
        query += " AND source_type = ?"
        params.append(source_type)

    if severity:
        # Filter by severity rank
        allowed = [s for s, r in _SEVERITY_ORDER.items() if r >= min_sev_rank]
        placeholders = ",".join(["?"] * len(allowed))
        query += f" AND severity IN ({placeholders})"
        params.extend(allowed)

    query += " ORDER BY score DESC LIMIT ?"
    params.append(limit)

    try:
        with _open_db(db_path) as conn:
            rows = conn.execute(query, params).fetchall()
            return [_row_to_finding(r) for r in rows]
    except sqlite3.OperationalError:
        return []


def load_findings_for_run(run_id: str, db_path: Optional[Path] = None) -> list[Finding]:
    """Load all findings from a specific scan run."""
    try:
        with _open_db(db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE run_id = ? ORDER BY score DESC", (run_id,)
            ).fetchall()
            return [_row_to_finding(r) for r in rows]
    except sqlite3.OperationalError:
        return []


def update_verification(
    dedup_key: str,
    status: str,
    score: Optional[float] = None,
    db_path: Optional[Path] = None,
) -> None:
    """Update verification status (and optionally score) for a finding."""
    now = datetime.now(timezone.utc).isoformat()
    try:
        with _open_db(db_path) as conn:
            if score is not None:
                conn.execute(
                    "UPDATE findings SET verification_status=?, score=MAX(score, ?), updated_at=? WHERE dedup_key=?",
                    [status, score, now, dedup_key],
                )
            else:
                conn.execute(
                    "UPDATE findings SET verification_status=?, updated_at=? WHERE dedup_key=?",
                    [status, now, dedup_key],
                )
            conn.commit()
    except sqlite3.OperationalError:
        pass  # DB doesn't exist yet — no-op


def update_exploitability(
    dedup_key: str,
    score: float,
    rating: str,
    db_path: Optional[Path] = None,
) -> None:
    """Update exploitability score and rating for a finding."""
    now = datetime.now(timezone.utc).isoformat()
    try:
        with _open_db(db_path) as conn:
            conn.execute(
                "UPDATE findings SET exploitability_score=?, exploitability_rating=?, updated_at=? WHERE dedup_key=?",
                [score, rating, now, dedup_key],
            )
            conn.commit()
    except sqlite3.OperationalError:
        pass


def purge_old_findings(older_than_days: int = 30, db_path: Optional[Path] = None) -> int:
    """Delete findings older than the specified number of days. Returns count deleted."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=older_than_days)).isoformat()
    try:
        with _open_db(db_path) as conn:
            cur = conn.execute("DELETE FROM findings WHERE updated_at < ?", (cutoff,))
            conn.commit()
            return cur.rowcount
    except sqlite3.OperationalError:
        return 0


def get_summary(module: Optional[str] = None, db_path: Optional[Path] = None) -> dict:
    """Return aggregate counts for findings in the store."""
    base_query = "FROM findings"
    params: list = []

    if module:
        base_query += " WHERE module = ?"
        params.append(module)

    try:
        with _open_db(db_path) as conn:
            total = conn.execute(f"SELECT COUNT(*) {base_query}", params).fetchone()[0]
            top_row = conn.execute(f"SELECT MAX(score) {base_query}", params).fetchone()
            top_score = top_row[0] or 0.0 if top_row else 0.0

            by_severity = {}
            for row in conn.execute(f"SELECT severity, COUNT(*) {base_query} GROUP BY severity", params):
                by_severity[row[0] or "UNKNOWN"] = row[1]

            by_source = {}
            for row in conn.execute(f"SELECT source_type, COUNT(*) {base_query} GROUP BY source_type", params):
                by_source[row[0] or "unknown"] = row[1]

            verified = conn.execute(
                f"SELECT COUNT(*) {base_query}" + (" AND" if module else " WHERE") + " verification_status IS NOT NULL",
                params,
            ).fetchone()[0]

        return {
            "total": total,
            "top_score": top_score,
            "by_severity": by_severity,
            "by_source_type": by_source,
            "verified_count": verified,
        }
    except sqlite3.OperationalError:
        return {"total": 0, "top_score": 0.0, "by_severity": {}, "by_source_type": {}, "verified_count": 0}


class FindingsStore:
    """Convenience class wrapping the module-level functions with a bound db_path."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = db_path

    def upsert_finding(self, finding: Finding, run_id: str = "") -> None:
        upsert_finding(finding, run_id=run_id, db_path=self.db_path)

    def load_findings(self, **kwargs) -> list[Finding]:
        return load_findings(db_path=self.db_path, **kwargs)

    def update_verification(self, dedup_key: str, status: str, score: Optional[float] = None) -> None:
        update_verification(dedup_key, status, score, db_path=self.db_path)

    def purge_old_findings(self, older_than_days: int = 30) -> int:
        return purge_old_findings(older_than_days, db_path=self.db_path)

    def get_summary(self, module: Optional[str] = None) -> dict:
        return get_summary(module, db_path=self.db_path)
