"""Tests for SQL injection protection and safe query methods.

Targets:
  helpers/individual_analysis_db/db.py
    - _validate_readonly_sql()
    - execute_query() (with validation)
    - execute_safe_select()
    - _execute_query_raw()

Covers:
  - Dangerous keyword detection across all blocked patterns
  - Case-insensitive keyword matching
  - Parameter binding correctness
  - execute_safe_select() strict SELECT enforcement
  - Valid queries pass through successfully
  - Edge cases: empty SQL, whitespace, mixed case
"""

from __future__ import annotations

import json
import sqlite3

import pytest

from helpers.individual_analysis_db.db import (
    IndividualAnalysisDB,
    _validate_readonly_sql,
    open_individual_analysis_db,
)


# ===================================================================
# _validate_readonly_sql (unit tests)
# ===================================================================

class TestValidateReadonlySql:
    """Direct tests for the SQL validation function."""

    # -- Should pass (no error) ----------------------------------------

    def test_select_passes(self):
        _validate_readonly_sql("SELECT * FROM functions")

    def test_select_with_where(self):
        _validate_readonly_sql(
            "SELECT function_name FROM functions WHERE function_id = ?"
        )

    def test_select_with_join(self):
        _validate_readonly_sql(
            "SELECT f.*, fi.file_name FROM functions f, file_info fi"
        )

    def test_select_with_subquery(self):
        _validate_readonly_sql(
            "SELECT * FROM functions WHERE function_id IN "
            "(SELECT function_id FROM functions LIMIT 5)"
        )

    def test_pragma_passes(self):
        _validate_readonly_sql("PRAGMA table_info(functions)")

    def test_select_count(self):
        _validate_readonly_sql("SELECT COUNT(*) FROM functions")

    def test_select_with_like(self):
        _validate_readonly_sql(
            "SELECT * FROM functions WHERE function_name LIKE ? COLLATE NOCASE"
        )

    def test_select_with_order_limit(self):
        _validate_readonly_sql(
            "SELECT * FROM functions ORDER BY function_id DESC LIMIT 10"
        )

    # -- Should fail (ValueError) --------------------------------------

    @pytest.mark.parametrize("keyword", [
        "DROP", "DELETE", "INSERT", "UPDATE", "ALTER",
        "CREATE", "ATTACH", "DETACH", "REPLACE", "REINDEX", "VACUUM",
    ])
    def test_blocked_keywords(self, keyword):
        with pytest.raises(ValueError, match="disallowed keyword"):
            _validate_readonly_sql(f"{keyword} TABLE functions")

    @pytest.mark.parametrize("keyword", [
        "drop", "delete", "insert", "update", "alter",
        "create", "attach", "detach", "replace", "reindex", "vacuum",
    ])
    def test_blocked_keywords_lowercase(self, keyword):
        with pytest.raises(ValueError, match="disallowed keyword"):
            _validate_readonly_sql(f"{keyword} table functions")

    @pytest.mark.parametrize("keyword", [
        "Drop", "Delete", "Insert", "Update", "Alter",
        "Create", "Attach", "Detach", "Replace", "Reindex", "Vacuum",
    ])
    def test_blocked_keywords_mixed_case(self, keyword):
        with pytest.raises(ValueError, match="disallowed keyword"):
            _validate_readonly_sql(f"{keyword} TABLE functions")

    def test_empty_sql(self):
        with pytest.raises(ValueError, match="Empty SQL"):
            _validate_readonly_sql("")

    def test_whitespace_only(self):
        with pytest.raises(ValueError, match="Empty SQL"):
            _validate_readonly_sql("   \t\n  ")

    def test_drop_table(self):
        with pytest.raises(ValueError, match="DROP"):
            _validate_readonly_sql("DROP TABLE functions")

    def test_insert_into(self):
        with pytest.raises(ValueError, match="INSERT"):
            _validate_readonly_sql("INSERT INTO functions (function_id) VALUES (1)")

    def test_update_set(self):
        with pytest.raises(ValueError, match="UPDATE"):
            _validate_readonly_sql("UPDATE functions SET function_name = 'evil'")

    def test_delete_from(self):
        with pytest.raises(ValueError, match="DELETE"):
            _validate_readonly_sql("DELETE FROM functions WHERE 1=1")

    def test_create_table(self):
        with pytest.raises(ValueError, match="CREATE"):
            _validate_readonly_sql("CREATE TABLE evil (id INTEGER)")

    def test_alter_table(self):
        with pytest.raises(ValueError, match="ALTER"):
            _validate_readonly_sql("ALTER TABLE functions ADD COLUMN evil TEXT")

    def test_attach_database(self):
        with pytest.raises(ValueError, match="ATTACH"):
            _validate_readonly_sql("ATTACH DATABASE 'evil.db' AS evil")

    def test_replace_into(self):
        with pytest.raises(ValueError, match="REPLACE"):
            _validate_readonly_sql("REPLACE INTO functions VALUES (1, 'evil')")

    # -- SQL injection payloads ----------------------------------------

    def test_injection_union_drop(self):
        with pytest.raises(ValueError, match="DROP"):
            _validate_readonly_sql(
                "SELECT * FROM functions; DROP TABLE functions--"
            )

    def test_injection_semicolon_insert(self):
        with pytest.raises(ValueError, match="INSERT"):
            _validate_readonly_sql(
                "SELECT 1; INSERT INTO functions VALUES (999, 'pwned')"
            )

    def test_injection_comment_update(self):
        with pytest.raises(ValueError, match="UPDATE"):
            _validate_readonly_sql(
                "SELECT * FROM functions WHERE 1=1 /* */ UPDATE functions SET x=1"
            )

    def test_injection_nested_delete(self):
        with pytest.raises(ValueError, match="DELETE"):
            _validate_readonly_sql(
                "SELECT * FROM functions WHERE function_name = '' "
                "OR 1=1; DELETE FROM functions"
            )


# ===================================================================
# execute_query (with validation)
# ===================================================================

class TestExecuteQueryValidated:
    def test_valid_select(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            rows = db.execute_query("SELECT COUNT(*) AS c FROM functions")
            assert int(rows[0]["c"]) == 4

    def test_valid_select_with_params(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            rows = db.execute_query(
                "SELECT * FROM functions WHERE function_name = ?",
                ("DllMain",),
            )
            assert len(rows) == 1
            assert rows[0]["function_name"] == "DllMain"

    def test_rejects_insert(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            with pytest.raises(ValueError, match="INSERT"):
                db.execute_query(
                    "INSERT INTO functions (function_id) VALUES (999)"
                )

    def test_rejects_drop(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            with pytest.raises(ValueError, match="DROP"):
                db.execute_query("DROP TABLE functions")

    def test_rejects_update(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            with pytest.raises(ValueError, match="UPDATE"):
                db.execute_query(
                    "UPDATE functions SET function_name = 'evil' WHERE 1=1"
                )

    def test_rejects_delete(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            with pytest.raises(ValueError, match="DELETE"):
                db.execute_query("DELETE FROM functions")

    def test_rejects_empty_sql(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            with pytest.raises(ValueError, match="Empty SQL"):
                db.execute_query("")

    def test_pragma_allowed(self, sample_db):
        """PRAGMA queries should pass validation (they are read-safe)."""
        with IndividualAnalysisDB(sample_db) as db:
            rows = db.execute_query("PRAGMA table_info(functions)")
            assert len(rows) > 0


# ===================================================================
# execute_safe_select
# ===================================================================

class TestExecuteSafeSelect:
    def test_valid_select(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            rows = db.execute_safe_select(
                "SELECT function_name FROM functions LIMIT 2"
            )
            assert len(rows) == 2

    def test_valid_select_with_params(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            rows = db.execute_safe_select(
                "SELECT * FROM functions WHERE function_id = ?",
                (1,),
            )
            assert len(rows) == 1
            assert rows[0]["function_name"] == "DllMain"

    def test_rejects_pragma(self, sample_db):
        """execute_safe_select should reject non-SELECT statements."""
        with IndividualAnalysisDB(sample_db) as db:
            with pytest.raises(ValueError, match="Only SELECT"):
                db.execute_safe_select("PRAGMA table_info(functions)")

    def test_rejects_insert(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            with pytest.raises(ValueError, match="Only SELECT"):
                db.execute_safe_select(
                    "INSERT INTO functions (function_id) VALUES (999)"
                )

    def test_rejects_with_leading_whitespace(self, sample_db):
        """Even with leading whitespace, non-SELECT should be rejected."""
        with IndividualAnalysisDB(sample_db) as db:
            with pytest.raises(ValueError, match="Only SELECT"):
                db.execute_safe_select("  DELETE FROM functions")

    def test_case_insensitive_select(self, sample_db):
        """select (lowercase) should be accepted."""
        with IndividualAnalysisDB(sample_db) as db:
            rows = db.execute_safe_select("select count(*) as c from functions")
            assert int(rows[0]["c"]) == 4

    def test_rejects_drop_disguised(self, sample_db):
        """SELECT containing DROP in a semicolon-injection should be caught."""
        with IndividualAnalysisDB(sample_db) as db:
            with pytest.raises(ValueError, match="DROP"):
                db.execute_safe_select(
                    "SELECT 1; DROP TABLE functions"
                )


# ===================================================================
# _execute_query_raw (internal, no validation)
# ===================================================================

class TestExecuteQueryRaw:
    def test_raw_select_works(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            rows = db._execute_query_raw("SELECT COUNT(*) AS c FROM functions")
            assert int(rows[0]["c"]) == 4

    def test_raw_pragma_works(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            rows = db._execute_query_raw("PRAGMA table_info(functions)")
            assert len(rows) > 0

    def test_raw_write_still_blocked_by_sqlite(self, sample_db):
        """Even _execute_query_raw should fail on writes due to PRAGMA query_only."""
        with IndividualAnalysisDB(sample_db) as db:
            with pytest.raises(RuntimeError):
                db._execute_query_raw(
                    "INSERT INTO functions (function_id) VALUES (999)"
                )


# ===================================================================
# Parameter binding correctness
# ===================================================================

class TestParameterBinding:
    def test_parameterized_query_prevents_injection(self, sample_db):
        """SQL injection via parameter values should be harmless."""
        with IndividualAnalysisDB(sample_db) as db:
            # The injection payload is in the parameter, not the SQL
            rows = db.execute_query(
                "SELECT * FROM functions WHERE function_name = ?",
                ("'; DROP TABLE functions;--",),
            )
            # No rows match, but the table is intact
            assert len(rows) == 0
            count = db.execute_query("SELECT COUNT(*) AS c FROM functions")
            assert int(count[0]["c"]) == 4

    def test_like_with_special_chars(self, sample_db):
        """LIKE patterns with SQL-special characters via params."""
        with IndividualAnalysisDB(sample_db) as db:
            rows = db.execute_query(
                "SELECT * FROM functions WHERE function_name LIKE ?",
                ("%Dll%",),
            )
            assert len(rows) >= 1
