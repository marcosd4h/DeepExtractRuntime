"""Tests for validation helpers: schema, integrity, and extraction–DB consistency."""

import json
import sqlite3
import pytest
from pathlib import Path

from helpers.validation import (
    ValidationResult,
    validate_analysis_db,
    validate_function_index,
    validate_function_id_consistency,
    validate_file_info_consistency,
    validate_extraction_db_consistency,
    quick_validate,
)


_FULL_FUNCTION_COLUMNS = [
    "function_id INTEGER PRIMARY KEY",
    "function_signature TEXT",
    "function_signature_extended TEXT",
    "mangled_name TEXT",
    "function_name TEXT",
    "assembly_code TEXT",
    "decompiled_code TEXT",
    "inbound_xrefs TEXT",
    "outbound_xrefs TEXT",
    "simple_inbound_xrefs TEXT",
    "simple_outbound_xrefs TEXT",
    "vtable_contexts TEXT",
    "global_var_accesses TEXT",
    "dangerous_api_calls TEXT",
    "string_literals TEXT",
    "stack_frame TEXT",
    "loop_analysis TEXT",
    "analysis_errors TEXT",
    "created_at TEXT",
]

_FULL_FILE_INFO_COLUMNS = [
    "file_path TEXT",
    "base_dir TEXT",
    "file_name TEXT",
    "file_extension TEXT",
    "file_size_bytes INTEGER",
    "md5_hash TEXT",
    "sha256_hash TEXT",
    "imports TEXT",
    "exports TEXT",
    "entry_point TEXT",
    "file_version TEXT",
    "product_version TEXT",
    "company_name TEXT",
    "file_description TEXT",
    "internal_name TEXT",
    "original_filename TEXT",
    "legal_copyright TEXT",
    "product_name TEXT",
    "time_date_stamp_str TEXT",
    "file_modified_date_str TEXT",
    "sections TEXT",
    "pdb_path TEXT",
    "rich_header TEXT",
    "tls_callbacks TEXT",
    "is_net_assembly BOOLEAN",
    "clr_metadata TEXT",
    "idb_cache_path TEXT",
    "dll_characteristics TEXT",
    "security_features TEXT",
    "exception_info TEXT",
    "load_config TEXT",
    "analysis_timestamp TEXT",
]


def _create_analysis_db_with_columns(
    db_path: Path,
    *,
    function_columns: list[str] | None = None,
    file_info_columns: list[str] | None = None,
) -> None:
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE schema_version (version INTEGER)")
    conn.execute("INSERT INTO schema_version VALUES (1)")
    conn.execute(f"CREATE TABLE file_info ({', '.join(file_info_columns or _FULL_FILE_INFO_COLUMNS)})")
    conn.execute(f"CREATE TABLE functions ({', '.join(function_columns or _FULL_FUNCTION_COLUMNS)})")
    conn.commit()
    conn.close()


# -----------------------------------------------------------------------
# Schema / integrity tests (existing APIs)
# -----------------------------------------------------------------------

def test_validate_analysis_db_missing_file():
    result = validate_analysis_db("/nonexistent/path.db")
    assert not result.ok
    assert any("does not exist" in e for e in result.errors)


def test_validate_analysis_db_valid(sample_db):
    result = validate_analysis_db(str(sample_db))
    assert result.ok
    assert len(result.errors) == 0


def test_validate_analysis_db_missing_required_function_columns(tmp_path):
    db_path = tmp_path / "missing_function_cols.db"
    function_columns = [
        column for column in _FULL_FUNCTION_COLUMNS
        if not column.startswith("mangled_name ")
        and not column.startswith("created_at ")
    ]
    _create_analysis_db_with_columns(db_path, function_columns=function_columns)

    result = validate_analysis_db(str(db_path))

    assert not result.ok
    assert any("Missing columns in 'functions' table" in e for e in result.errors)
    assert any("mangled_name" in e for e in result.errors)
    assert any("created_at" in e for e in result.errors)


def test_validate_analysis_db_missing_required_file_info_columns(tmp_path):
    db_path = tmp_path / "missing_file_info_cols.db"
    file_info_columns = [
        column for column in _FULL_FILE_INFO_COLUMNS
        if not column.startswith("company_name ")
        and not column.startswith("load_config ")
    ]
    _create_analysis_db_with_columns(db_path, file_info_columns=file_info_columns)

    result = validate_analysis_db(str(db_path))

    assert not result.ok
    assert any("Missing columns in 'file_info' table" in e for e in result.errors)
    assert any("company_name" in e for e in result.errors)
    assert any("load_config" in e for e in result.errors)


def test_validate_function_index_valid(tmp_path):
    index_path = tmp_path / "function_index.json"
    index_path.write_text(json.dumps({
        "Foo": {"function_id": 1, "files": ["foo.cpp"], "has_assembly": True},
        "Bar": {"function_id": 2, "files": ["bar.cpp"], "has_assembly": True},
    }))
    result = validate_function_index(str(index_path))
    assert result.ok


def test_validate_function_index_missing():
    result = validate_function_index("/nonexistent/function_index.json")
    assert not result.ok
    assert any("not found" in e for e in result.errors)


def test_quick_validate(sample_db):
    assert quick_validate(str(sample_db)) is True


def test_quick_validate_missing():
    assert quick_validate("/nonexistent.db") is False


# -----------------------------------------------------------------------
# Function ID consistency: matching scenario
# -----------------------------------------------------------------------

def test_validate_function_id_consistency_matching(
    sample_db, sample_function_index, tmp_path
):
    """When function_index.json and DB agree on function_ids, validation passes."""
    ext_dir = tmp_path / "extracted_code" / "test_dll"
    ext_dir.mkdir(parents=True)

    # Write index that matches sample_db (DllMain=1, WppAutoLogTrace=2, etc.)
    matching_index = {
        k: v for k, v in sample_function_index.items()
        if v["function_id"] in (1, 2, 3, 4)  # Only DB functions
    }
    (ext_dir / "function_index.json").write_text(
        json.dumps(matching_index, indent=2)
    )

    result = validate_function_id_consistency(str(sample_db), ext_dir)
    assert result.ok
    assert len(result.errors) == 0
    assert result.warnings == []


# -----------------------------------------------------------------------
# Function ID consistency: mismatch scenarios
# -----------------------------------------------------------------------

def test_validate_function_id_consistency_id_mismatch(sample_db, tmp_path):
    """When function_index has different function_id than DB, validation fails."""
    ext_dir = tmp_path / "extracted_code" / "test_dll"
    ext_dir.mkdir(parents=True)

    # DllMain has function_id 99 in index but 1 in DB
    index_data = {
        "DllMain": {"function_id": 99, "files": ["test.cpp"], "has_assembly": True},
        "WppAutoLogTrace": {"function_id": 2, "files": ["test.cpp"], "has_assembly": True},
    }
    (ext_dir / "function_index.json").write_text(json.dumps(index_data))

    result = validate_function_id_consistency(str(sample_db), ext_dir)
    assert not result.ok
    assert any("mismatch" in e.lower() for e in result.errors)
    assert any("99" in e and "1" in e for e in result.errors)


def test_validate_function_id_consistency_index_not_found(sample_db, tmp_path):
    """When function_index.json is missing, validation fails."""
    ext_dir = tmp_path / "extracted_code" / "test_dll"
    ext_dir.mkdir(parents=True)
    # No function_index.json

    result = validate_function_id_consistency(str(sample_db), ext_dir)
    assert not result.ok
    assert any("not found" in e for e in result.errors)


def test_validate_function_id_consistency_in_index_not_db(sample_db, tmp_path):
    """Functions in index but not in DB produce warnings (not errors)."""
    ext_dir = tmp_path / "extracted_code" / "test_dll"
    ext_dir.mkdir(parents=True)

    # STLHelper is in index but not in sample_db
    index_data = {
        "DllMain": {"function_id": 1, "files": ["test.cpp"], "has_assembly": True},
        "NonexistentFunc": {"function_id": 999, "files": ["test.cpp"], "has_assembly": True},
    }
    (ext_dir / "function_index.json").write_text(json.dumps(index_data))

    result = validate_function_id_consistency(str(sample_db), ext_dir)
    # No ID mismatch for DllMain; NonexistentFunc triggers warning
    assert result.ok  # No errors
    assert any("not in DB" in w for w in result.warnings)


def test_validate_function_id_consistency_mangled_name_match(sample_db, tmp_path):
    """Matching by mangled_name when function_name differs works."""
    ext_dir = tmp_path / "extracted_code" / "test_dll"
    ext_dir.mkdir(parents=True)

    # DB has function_name="sub_140001000", mangled_name="??0CFoo@@QEAA@XZ"
    # Index uses mangled name as key and includes the remaining DB functions.
    index_data = {
        "DllMain": {"function_id": 1, "files": ["test.cpp"], "has_assembly": True},
        "WppAutoLogTrace": {"function_id": 2, "files": ["test.cpp"], "has_assembly": True},
        "??0CFoo@@QEAA@XZ": {"function_id": 3, "files": ["test.cpp"], "has_assembly": True},
        "sub_140002000": {"function_id": 4, "files": ["test.cpp"], "has_assembly": True},
    }
    (ext_dir / "function_index.json").write_text(json.dumps(index_data))

    result = validate_function_id_consistency(str(sample_db), ext_dir)
    assert result.ok
    assert result.warnings == []


# -----------------------------------------------------------------------
# File info consistency: matching scenario
# -----------------------------------------------------------------------

def test_validate_file_info_consistency_matching(sample_db, tmp_path):
    """When file_info.json and DB agree on identity fields, validation passes."""
    ext_dir = tmp_path / "extracted_code" / "test_dll"
    ext_dir.mkdir(parents=True)

    # Match sample_db file_info (from conftest _seed_sample_db)
    file_info_json = {
        "module_name": "test_dll",
        "basic_file_info": {
            "file_name": "test.dll",
            "md5_hash": "f2bbf324a1176c01101bc75d017633bc",
            "sha256_hash": "60df03e7deba0b62ecafabc123456789abcdef0123456789abcdef0123456789",
        },
        "pe_version_info": {
            "file_version": "10.0.26100.7824",
            "product_version": "10.0.26100.7824",
        },
    }
    (ext_dir / "file_info.json").write_text(json.dumps(file_info_json, indent=2))

    result = validate_file_info_consistency(str(sample_db), ext_dir)
    assert result.ok
    assert len(result.errors) == 0


# -----------------------------------------------------------------------
# File info consistency: mismatch scenarios
# -----------------------------------------------------------------------

def test_validate_file_info_consistency_md5_mismatch(sample_db, tmp_path):
    """When md5_hash differs between JSON and DB, validation fails."""
    ext_dir = tmp_path / "extracted_code" / "test_dll"
    ext_dir.mkdir(parents=True)

    file_info_json = {
        "basic_file_info": {
            "file_name": "test.dll",
            "md5_hash": "wrong_hash_123456789012345678901234",
            "sha256_hash": "60df03e7deba0b62ecafabc123456789abcdef0123456789abcdef0123456789",
        },
        "pe_version_info": {"file_version": "10.0.26100.7824", "product_version": "10.0.26100.7824"},
    }
    (ext_dir / "file_info.json").write_text(json.dumps(file_info_json))

    result = validate_file_info_consistency(str(sample_db), ext_dir)
    assert not result.ok
    assert any("md5" in e.lower() or "hash" in e.lower() for e in result.errors)


def test_validate_file_info_consistency_filename_mismatch(sample_db, tmp_path):
    """When file_name differs between JSON and DB, validation fails."""
    ext_dir = tmp_path / "extracted_code" / "test_dll"
    ext_dir.mkdir(parents=True)

    file_info_json = {
        "basic_file_info": {
            "file_name": "other.dll",
            "md5_hash": "f2bbf324a1176c01101bc75d017633bc",
            "sha256_hash": "60df03e7deba0b62ecafabc123456789abcdef0123456789abcdef0123456789",
        },
        "pe_version_info": {"file_version": "10.0.26100.7824", "product_version": "10.0.26100.7824"},
    }
    (ext_dir / "file_info.json").write_text(json.dumps(file_info_json))

    result = validate_file_info_consistency(str(sample_db), ext_dir)
    assert not result.ok
    assert any("file_name" in e or "filename" in e.lower() for e in result.errors)


def test_validate_file_info_consistency_file_not_found(sample_db, tmp_path):
    """When file_info.json is missing, validation fails."""
    ext_dir = tmp_path / "extracted_code" / "test_dll"
    ext_dir.mkdir(parents=True)
    # No file_info.json

    result = validate_file_info_consistency(str(sample_db), ext_dir)
    assert not result.ok
    assert any("not found" in e for e in result.errors)


# -----------------------------------------------------------------------
# Combined consistency validation
# -----------------------------------------------------------------------

def test_validate_extraction_db_consistency_all_pass(
    sample_db, sample_function_index, tmp_path
):
    """Combined validation passes when both checks pass."""
    ext_dir = tmp_path / "extracted_code" / "test_dll"
    ext_dir.mkdir(parents=True)

    matching_index = {
        k: v for k, v in sample_function_index.items()
        if v["function_id"] in (1, 2, 3, 4)
    }
    (ext_dir / "function_index.json").write_text(json.dumps(matching_index))

    file_info_json = {
        "basic_file_info": {
            "file_name": "test.dll",
            "md5_hash": "f2bbf324a1176c01101bc75d017633bc",
            "sha256_hash": "60df03e7deba0b62ecafabc123456789abcdef0123456789abcdef0123456789",
        },
        "pe_version_info": {"file_version": "10.0.26100.7824", "product_version": "10.0.26100.7824"},
    }
    (ext_dir / "file_info.json").write_text(json.dumps(file_info_json))

    result = validate_extraction_db_consistency(str(sample_db), ext_dir)
    assert result.ok


def test_validate_extraction_db_consistency_function_mismatch_fails(
    sample_db, tmp_path
):
    """Combined validation fails when function_id check fails."""
    ext_dir = tmp_path / "extracted_code" / "test_dll"
    ext_dir.mkdir(parents=True)

    (ext_dir / "function_index.json").write_text(json.dumps({
        "DllMain": {"function_id": 999, "files": ["x.cpp"], "has_assembly": True},
    }))
    file_info_json = {
        "basic_file_info": {"file_name": "test.dll", "md5_hash": "f2bbf324a1176c01101bc75d017633bc",
                           "sha256_hash": "60df03e7deba0b62ecafabc123456789abcdef0123456789abcdef0123456789"},
        "pe_version_info": {"file_version": "10.0.26100.7824", "product_version": "10.0.26100.7824"},
    }
    (ext_dir / "file_info.json").write_text(json.dumps(file_info_json))

    result = validate_extraction_db_consistency(str(sample_db), ext_dir)
    assert not result.ok
    assert any("mismatch" in e.lower() for e in result.errors)
