"""Tests for database access and record parsing.

Targets:
  helpers/individual_analysis_db/db.py
  helpers/individual_analysis_db/records.py
"""

from __future__ import annotations

import json
import sqlite3

import pytest

from helpers.individual_analysis_db.records import (
    FunctionRecord,
    Page,
    parse_json_safe,
)
from helpers.individual_analysis_db.db import (
    IndividualAnalysisDB,
    open_individual_analysis_db,
)


# ===================================================================
# parse_json_safe
# ===================================================================

class TestParseJsonSafe:
    def test_valid_json(self):
        assert parse_json_safe('{"a": 1}') == {"a": 1}

    def test_valid_json_list(self):
        assert parse_json_safe('[1, 2, 3]') == [1, 2, 3]

    def test_none_input(self):
        assert parse_json_safe(None) is None

    def test_empty_string(self):
        assert parse_json_safe("") is None

    def test_whitespace_only(self):
        assert parse_json_safe("   ") is None

    def test_null_string(self):
        assert parse_json_safe("null") is None
        assert parse_json_safe("NULL") is None
        assert parse_json_safe("  null  ") is None

    def test_malformed_json(self):
        assert parse_json_safe("{not valid json") is None

    def test_non_string_passthrough(self):
        """Already-parsed objects are returned as-is."""
        data = {"key": "value"}
        assert parse_json_safe(data) is data

    def test_non_string_list_passthrough(self):
        data = [1, 2, 3]
        assert parse_json_safe(data) is data

    def test_integer_passthrough(self):
        assert parse_json_safe(42) == 42


# ===================================================================
# FunctionRecord properties
# ===================================================================

class TestFunctionRecordProperties:
    def test_parsed_outbound_xrefs(self):
        xrefs = [{"function_name": "foo", "function_id": 1}]
        rec = FunctionRecord(
            function_id=1, function_signature=None,
            function_signature_extended=None, mangled_name=None,
            function_name="test", assembly_code=None, decompiled_code=None,
            inbound_xrefs=None, outbound_xrefs=None,
            simple_inbound_xrefs=None,
            simple_outbound_xrefs=json.dumps(xrefs),
            vtable_contexts=None, global_var_accesses=None,
            dangerous_api_calls=None, string_literals=None,
            stack_frame=None, loop_analysis=None, analysis_errors=None,
            created_at=None,
        )
        assert rec.parsed_simple_outbound_xrefs == xrefs

    def test_parsed_dangerous_api_calls_none(self):
        rec = FunctionRecord(
            function_id=1, function_signature=None,
            function_signature_extended=None, mangled_name=None,
            function_name="test", assembly_code=None, decompiled_code=None,
            inbound_xrefs=None, outbound_xrefs=None,
            simple_inbound_xrefs=None, simple_outbound_xrefs=None,
            vtable_contexts=None, global_var_accesses=None,
            dangerous_api_calls=None, string_literals=None,
            stack_frame=None, loop_analysis=None, analysis_errors=None,
            created_at=None,
        )
        assert rec.parsed_dangerous_api_calls is None

    def test_parsed_string_literals_malformed(self):
        rec = FunctionRecord(
            function_id=1, function_signature=None,
            function_signature_extended=None, mangled_name=None,
            function_name="test", assembly_code=None, decompiled_code=None,
            inbound_xrefs=None, outbound_xrefs=None,
            simple_inbound_xrefs=None, simple_outbound_xrefs=None,
            vtable_contexts=None, global_var_accesses=None,
            dangerous_api_calls=None, string_literals="BAD JSON {{",
            stack_frame=None, loop_analysis=None, analysis_errors=None,
            created_at=None,
        )
        assert rec.parsed_string_literals is None

    def test_parsed_loop_analysis(self):
        loop_data = {"loop_count": 2, "loops": [{"depth": 1}]}
        rec = FunctionRecord(
            function_id=1, function_signature=None,
            function_signature_extended=None, mangled_name=None,
            function_name="test", assembly_code=None, decompiled_code=None,
            inbound_xrefs=None, outbound_xrefs=None,
            simple_inbound_xrefs=None, simple_outbound_xrefs=None,
            vtable_contexts=None, global_var_accesses=None,
            dangerous_api_calls=None, string_literals=None,
            stack_frame=None, loop_analysis=json.dumps(loop_data),
            analysis_errors=None, created_at=None,
        )
        assert rec.parsed_loop_analysis == loop_data


# ===================================================================
# Page dataclass
# ===================================================================

class TestPage:
    def test_total_pages(self):
        p = Page(items=[], total=25, page=1, page_size=10)
        assert p.total_pages == 3

    def test_total_pages_exact(self):
        p = Page(items=[], total=20, page=1, page_size=10)
        assert p.total_pages == 2

    def test_has_next(self):
        p = Page(items=[], total=25, page=1, page_size=10)
        assert p.has_next is True

    def test_has_next_last_page(self):
        p = Page(items=[], total=25, page=3, page_size=10)
        assert p.has_next is False

    def test_has_prev(self):
        p = Page(items=[], total=25, page=2, page_size=10)
        assert p.has_prev is True

    def test_has_prev_first_page(self):
        p = Page(items=[], total=25, page=1, page_size=10)
        assert p.has_prev is False


# ===================================================================
# IndividualAnalysisDB -- queries against sample_db fixture
# ===================================================================

class TestIndividualAnalysisDB:
    def test_context_manager(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            assert db.db_path.exists()

    def test_get_function_by_id_found(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            rec = db.get_function_by_id(1)
            assert rec is not None
            assert rec.function_id == 1
            assert rec.function_name == "DllMain"

    def test_get_function_by_id_missing(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            rec = db.get_function_by_id(9999)
            assert rec is None

    def test_get_function_by_name(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            recs = db.get_function_by_name("DllMain")
            assert len(recs) == 1
            assert recs[0].function_name == "DllMain"

    def test_get_function_by_name_case_insensitive(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            recs = db.get_function_by_name("dllmain")
            assert len(recs) == 1

    def test_count_functions(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            assert db.count_functions() == 4  # 4 seed functions

    def test_get_all_functions(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            funcs = db.get_all_functions()
            assert len(funcs) == 4

    def test_get_all_functions_limit(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            funcs = db.get_all_functions(limit=2)
            assert len(funcs) == 2

    def test_get_all_functions_offset(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            funcs = db.get_all_functions(limit=2, offset=2)
            assert len(funcs) == 2
            # Should be IDs 3 and 4 (offset past 1 and 2)
            ids = {f.function_id for f in funcs}
            assert 3 in ids

    def test_get_function_names(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            names = db.get_function_names()
            assert "DllMain" in names
            assert "WppAutoLogTrace" in names

    def test_search_functions_by_name(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            results = db.search_functions(name_contains="sub_")
            assert len(results) == 2  # sub_140001000, sub_140002000

    def test_search_functions_limit_offset(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            results = db.search_functions(limit=2, offset=1)
            assert len(results) == 2
            assert [r.function_id for r in results] == [2, 3]

    def test_search_functions_desc_order(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            results = db.search_functions(limit=1, order_by="function_id", ascending=False)
            assert len(results) == 1
            assert results[0].function_id == 4

    def test_search_functions_invalid_order_by(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            with pytest.raises(ValueError, match="Invalid order_by"):
                db.search_functions(order_by="not_a_column")

    def test_iter_functions(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            ids = [rec.function_id for rec in db.iter_functions(batch_size=2)]
            assert ids == [1, 2, 3, 4]

    def test_search_functions_has_decompiled(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            results = db.search_functions(has_decompiled_code=True)
            assert len(results) >= 2  # DllMain, sub_140002000, WppAutoLogTrace

    def test_search_functions_no_decompiled(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            results = db.search_functions(has_decompiled_code=False)
            assert any(r.function_name == "sub_140001000" for r in results)

    def test_search_functions_has_dangerous_apis(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            results = db.search_functions(has_dangerous_apis=True)
            assert any(r.function_name == "DllMain" for r in results)

    def test_compute_stats(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            stats = db.compute_stats()
            assert stats["total_functions"] == 4
            assert "decompiled_count" in stats
            assert "dangerous_api_count" in stats
            assert "has_assembly_count" in stats

    def test_get_file_info(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            info = db.get_file_info()
            assert info is not None
            assert info.file_name == "test.dll"
            assert info.company_name == "Test Corp"

    def test_get_file_info_field(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            name = db.get_file_info_field("file_name")
            assert name == "test.dll"

    def test_get_file_info_field_invalid(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            with pytest.raises(ValueError, match="Invalid"):
                db.get_file_info_field("nonexistent_column")

    def test_get_functions_by_ids(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            funcs = db.get_functions_by_ids([1, 3])
            assert len(funcs) == 2
            ids = {f.function_id for f in funcs}
            assert ids == {1, 3}

    def test_get_functions_by_ids_empty(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            assert db.get_functions_by_ids([]) == []

    def test_get_functions_by_names(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            result = db.get_functions_by_names(["DllMain", "NoSuchFunc"])
            assert len(result["DllMain"]) == 1
            assert len(result["NoSuchFunc"]) == 0

    def test_get_functions_paginated(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            page = db.get_functions_paginated(page=1, page_size=2)
            assert len(page.items) == 2
            assert page.total == 4
            assert page.has_next is True

    def test_read_only_enforcement(self, sample_db):
        """DB should reject write operations at the validation layer."""
        with IndividualAnalysisDB(sample_db) as db:
            with pytest.raises(ValueError, match="disallowed keyword"):
                db.execute_query("INSERT INTO functions (function_id) VALUES (999)")

    def test_read_only_enforcement_update(self, sample_db):
        """DB should reject UPDATE operations at the validation layer."""
        with IndividualAnalysisDB(sample_db) as db:
            with pytest.raises(ValueError, match="disallowed keyword"):
                db.execute_query("UPDATE functions SET function_name = 'x' WHERE function_id = 1")

    def test_read_only_enforcement_delete(self, sample_db):
        """DB should reject DELETE operations at the validation layer."""
        with IndividualAnalysisDB(sample_db) as db:
            with pytest.raises(ValueError, match="disallowed keyword"):
                db.execute_query("DELETE FROM functions WHERE function_id = 1")

    @pytest.mark.parametrize("sql", [
        "DROP TABLE functions",
        "ALTER TABLE functions ADD COLUMN x TEXT",
        "CREATE TABLE evil (id INTEGER)",
        "ATTACH DATABASE ':memory:' AS evil",
        "DETACH DATABASE evil",
        "REPLACE INTO functions (function_id) VALUES (999)",
        "REINDEX functions",
        "VACUUM",
    ])
    def test_read_only_enforcement_ddl_keywords(self, sample_db, sql):
        """All DDL/write keywords blocked by _UNSAFE_SQL_PATTERN must be rejected."""
        with IndividualAnalysisDB(sample_db) as db:
            with pytest.raises(ValueError, match="disallowed keyword"):
                db.execute_query(sql)

    def test_get_function_by_mangled_name(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            recs = db.get_function_by_mangled_name("??0CFoo@@QEAA@XZ")
            assert len(recs) == 1
            assert recs[0].function_id == 3

    def test_dangerous_api_ranking(self, sample_db_with_extras):
        with IndividualAnalysisDB(sample_db_with_extras) as db:
            ranking = db.get_dangerous_api_ranking(limit=5)
            assert len(ranking) > 0
            # Should be sorted descending by count
            counts = [cnt for _, cnt in ranking]
            assert counts == sorted(counts, reverse=True)

    def test_get_functions_with_module_info(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            results = db.get_functions_with_module_info(limit=2)
            assert len(results) == 2
            assert results[0].module_name == "test.dll"
            assert results[0].function is not None

    def test_iter_functions_start_offset(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            ids = [rec.function_id for rec in db.iter_functions(batch_size=2, start_offset=2)]
            assert ids == [3, 4]

    def test_iter_functions_order_by_name(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            names = [rec.function_name for rec in db.iter_functions(batch_size=10, order_by="function_name")]
            assert names == sorted(names)

    def test_iter_functions_descending(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            ids = [rec.function_id for rec in db.iter_functions(batch_size=10, ascending=False)]
            assert ids == [4, 3, 2, 1]

    def test_iter_functions_invalid_batch_size(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            with pytest.raises(ValueError, match="batch_size"):
                list(db.iter_functions(batch_size=0))

    def test_get_functions_by_id_range(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            funcs = db.get_functions_by_id_range(2, 3)
            assert len(funcs) == 2
            ids = {f.function_id for f in funcs}
            assert ids == {2, 3}
            assert funcs[0].function_id <= funcs[1].function_id

    def test_search_by_json_field(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            # DllMain has CreateProcessW in dangerous_api_calls
            results = db.search_by_json_field("dangerous_api_calls", "CreateProcess")
            assert len(results) >= 1
            assert any(r.function_name == "DllMain" for r in results)

    def test_search_by_json_field_invalid_field(self, sample_db):
        with IndividualAnalysisDB(sample_db) as db:
            with pytest.raises(ValueError, match="Invalid JSON field"):
                db.search_by_json_field("nonexistent", "x")


# ===================================================================
# Vtable / class grouping (requires sample_db_with_vtables)
# ===================================================================


@pytest.fixture
def sample_db_with_vtables(tmp_path):
    """DB with vtable_contexts for get_vtable_classes tests."""
    from conftest import _create_sample_db, _seed_sample_db
    db_path = tmp_path / "vtables.db"
    _create_sample_db(db_path)
    _seed_sample_db(db_path)
    conn = sqlite3.connect(db_path)
    # Add vtable_contexts to function 1
    conn.execute(
        "UPDATE functions SET vtable_contexts = ? WHERE function_id = 1",
        (json.dumps([{"class_name": "CSecurityDescriptor", "class": "CSecurityDescriptor"}]),),
    )
    conn.execute(
        "UPDATE functions SET vtable_contexts = ? WHERE function_id = 2",
        (json.dumps([{"class_name": "CSecurityDescriptor"}]),),
    )
    conn.commit()
    conn.close()
    return db_path


class TestVtableClasses:
    def test_get_vtable_classes(self, sample_db_with_vtables):
        with IndividualAnalysisDB(sample_db_with_vtables) as db:
            classes = db.get_vtable_classes()
            assert "CSecurityDescriptor" in classes
            assert 1 in classes["CSecurityDescriptor"]
            assert 2 in classes["CSecurityDescriptor"]

    def test_get_functions_by_vtable_class(self, sample_db_with_vtables):
        with IndividualAnalysisDB(sample_db_with_vtables) as db:
            by_class = db.get_functions_by_vtable_class()
            assert "CSecurityDescriptor" in by_class
            funcs = by_class["CSecurityDescriptor"]
            assert len(funcs) >= 1
            assert all(hasattr(f, "function_name") for f in funcs)


# ===================================================================
# open_individual_analysis_db helper
# ===================================================================

class TestOpenHelper:
    def test_open_and_close(self, sample_db):
        db = open_individual_analysis_db(sample_db)
        with db:
            assert db.count_functions() == 4

    def test_nonexistent_path(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            open_individual_analysis_db(tmp_path / "nonexistent.db")
