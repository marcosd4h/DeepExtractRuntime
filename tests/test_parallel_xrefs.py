import pytest
import sqlite3
import json
from helpers.analyzed_files_db import open_analyzed_files_db
from conftest import _create_sample_db

@pytest.fixture
def tracking_db_path(tmp_path):
    db_path = tmp_path / "analyzed_files.db"
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE analyzed_files (
            file_path TEXT PRIMARY KEY, base_dir TEXT, file_name TEXT,
            file_extension TEXT, md5_hash TEXT, sha256_hash TEXT,
            analysis_db_path TEXT, status TEXT, analysis_flags TEXT,
            analysis_start_timestamp TEXT, analysis_completion_timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()
    return db_path

def test_parallel_xref_resolution(tracking_db_path, mock_db_path, sample_function_data):
    # 1. Setup a module DB with a function that has an outbound xref
    conn = sqlite3.connect(mock_db_path)
    keys = ", ".join(sample_function_data.keys())
    placeholders = ", ".join(["?"] * len(sample_function_data))
    conn.execute(f"INSERT INTO functions ({keys}) VALUES ({placeholders})", 
                 list(sample_function_data.values()))
    conn.commit()
    conn.close()

    # 2. Setup tracking DB pointing to this module
    conn = sqlite3.connect(tracking_db_path)
    conn.execute("""
        INSERT INTO analyzed_files (file_path, file_name, analysis_db_path, status)
        VALUES (?, ?, ?, ?)
    """, ("test.dll", "test.dll", mock_db_path.name, "COMPLETE"))
    conn.commit()
    conn.close()

    # 3. Run cross-module xref search
    with open_analyzed_files_db(tracking_db_path) as db:
        # We search for "Callee" which is in sample_function_data's simple_outbound_xrefs
        results = db.get_cross_module_xrefs("Callee")

        assert len(results) == 1
        assert results[0]["source_module"] == "test.dll"
        assert results[0]["target_function"] == "Callee"
        assert results.skipped == []


def test_parallel_xref_resolution_with_workspace_relative_db_path(tmp_path, mock_db_path, sample_function_data):
    workspace = tmp_path
    dbs_dir = workspace / "extracted_dbs"
    dbs_dir.mkdir()
    tracking_db_path = dbs_dir / "analyzed_files.db"
    conn = sqlite3.connect(tracking_db_path)
    conn.execute("""
        CREATE TABLE analyzed_files (
            file_path TEXT PRIMARY KEY, base_dir TEXT, file_name TEXT,
            file_extension TEXT, md5_hash TEXT, sha256_hash TEXT,
            analysis_db_path TEXT, status TEXT, analysis_flags TEXT,
            analysis_start_timestamp TEXT, analysis_completion_timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()

    module_db = dbs_dir / mock_db_path.name
    _create_sample_db(module_db)
    conn = sqlite3.connect(module_db)
    keys = ", ".join(sample_function_data.keys())
    placeholders = ", ".join(["?"] * len(sample_function_data))
    conn.execute(
        f"INSERT INTO functions ({keys}) VALUES ({placeholders})",
        list(sample_function_data.values()),
    )
    conn.commit()
    conn.close()

    conn = sqlite3.connect(tracking_db_path)
    conn.execute("""
        INSERT INTO analyzed_files (file_path, file_name, analysis_db_path, status)
        VALUES (?, ?, ?, ?)
    """, ("test.dll", "test.dll", f"extracted_dbs/{module_db.name}", "COMPLETE"))
    conn.commit()
    conn.close()

    with open_analyzed_files_db(tracking_db_path) as db:
        results = db.get_cross_module_xrefs("Callee")

    assert len(results) == 1
    assert results[0]["source_module"] == "test.dll"
    assert results[0]["target_function"] == "Callee"
    assert results.skipped == []


def test_parallel_xref_resolution_reports_skipped_modules(
    tracking_db_path,
    mock_db_path,
    sample_function_data,
):
    conn = sqlite3.connect(mock_db_path)
    keys = ", ".join(sample_function_data.keys())
    placeholders = ", ".join(["?"] * len(sample_function_data))
    conn.execute(
        f"INSERT INTO functions ({keys}) VALUES ({placeholders})",
        list(sample_function_data.values()),
    )
    conn.commit()
    conn.close()

    missing_db_name = "missing_analysis.db"

    conn = sqlite3.connect(tracking_db_path)
    conn.executemany(
        """
        INSERT INTO analyzed_files (file_path, file_name, analysis_db_path, status)
        VALUES (?, ?, ?, ?)
        """,
        [
            ("good.dll", "good.dll", mock_db_path.name, "COMPLETE"),
            ("bad.dll", "bad.dll", missing_db_name, "COMPLETE"),
        ],
    )
    conn.commit()
    conn.close()

    with open_analyzed_files_db(tracking_db_path) as db:
        results = db.get_cross_module_xrefs("Callee")

    assert len(results) == 1
    assert results[0]["source_module"] == "good.dll"
    assert len(results.skipped) == 1
    assert results.skipped[0]["module_name"] == "bad.dll"
    assert missing_db_name in results.skipped[0]["reason"]
