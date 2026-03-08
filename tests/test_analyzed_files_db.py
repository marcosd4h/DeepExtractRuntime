from __future__ import annotations

import sqlite3
from pathlib import Path

from helpers.analyzed_files_db import open_analyzed_files_db


def _create_tracking_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE analyzed_files (
            file_path TEXT,
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
        """
    )
    conn.commit()
    conn.close()


def test_open_analyzed_files_db_without_path_uses_auto_detected_workspace(monkeypatch, tmp_path):
    tracking_db = tmp_path / "extracted_dbs" / "analyzed_files.db"
    _create_tracking_db(tracking_db)
    monkeypatch.setattr(
        "helpers.db_paths.resolve_tracking_db_auto",
        lambda: str(tracking_db),
    )

    with open_analyzed_files_db() as db:
        assert db.db_path == tracking_db.resolve()


def test_open_analyzed_files_db_without_path_supports_agent_style_workspace(monkeypatch, tmp_path):
    workspace_root = tmp_path / "agent-workspace"
    tracking_db = workspace_root / "extracted_dbs" / "analyzed_files.db"
    _create_tracking_db(tracking_db)
    monkeypatch.setattr(
        "helpers.db_paths.resolve_tracking_db_auto",
        lambda: str(tracking_db),
    )

    with open_analyzed_files_db() as db:
        assert db.db_path == tracking_db.resolve()
