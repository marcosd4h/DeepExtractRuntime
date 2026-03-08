"""Tests for the three new deduplication helper modules.

Covers:
  - helpers.function_resolver (resolve_function, search_functions_by_pattern)
  - helpers.db_paths (resolve_module_db)
  - helpers.string_taxonomy (categorize_string, categorize_string_simple,
    categorize_strings, TAXONOMY_TO_CLASSIFICATION, STRING_TAXONOMY)
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# sys.path setup
# ---------------------------------------------------------------------------
_AGENT_DIR = Path(__file__).resolve().parent.parent
if str(_AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENT_DIR))

from helpers.function_resolver import resolve_function, search_functions_by_pattern
from helpers.string_taxonomy import (
    CATEGORIES,
    STRING_TAXONOMY,
    TAXONOMY_TO_CLASSIFICATION,
    categorize_string,
    categorize_string_simple,
    categorize_strings,
)
from helpers.db_paths import resolve_module_db, resolve_db_path, resolve_tracking_db
from helpers import open_individual_analysis_db

# Re-use the conftest fixtures
from conftest import _create_sample_db, _make_function_record


# ===========================================================================
# function_resolver tests
# ===========================================================================

class TestResolveFunction:
    """Tests for resolve_function()."""

    def test_resolve_by_id(self, sample_db):
        with open_individual_analysis_db(str(sample_db)) as db:
            func, err = resolve_function(db, function_id=1)
            assert err is None
            assert func is not None
            assert func.function_name == "DllMain"

    def test_resolve_by_id_not_found(self, sample_db):
        with open_individual_analysis_db(str(sample_db)) as db:
            func, err = resolve_function(db, function_id=99999)
            assert func is None
            assert "No function with ID 99999" in err

    def test_resolve_by_exact_name_with_index(self, sample_db, sample_function_index):
        with open_individual_analysis_db(str(sample_db)) as db:
            func, err = resolve_function(
                db, name="DllMain", function_index=sample_function_index,
            )
            assert err is None
            assert func is not None
            assert func.function_id == 1

    def test_resolve_by_partial_name_with_index(self, sample_db, sample_function_index):
        """Partial match 'Dll' should match 'DllMain' when it's unique."""
        with open_individual_analysis_db(str(sample_db)) as db:
            func, err = resolve_function(
                db, name="DllMai", function_index=sample_function_index,
            )
            assert err is None
            assert func is not None
            assert func.function_name == "DllMain"

    def test_resolve_multiple_partial_matches(self, sample_db, sample_function_index):
        """Partial match 'sub_' matches two index entries -> ambiguous error."""
        with open_individual_analysis_db(str(sample_db)) as db:
            func, err = resolve_function(
                db, name="sub_", function_index=sample_function_index,
            )
            assert func is None
            assert err is not None
            assert "Multiple matches" in err
            assert "sub_140001000" in err
            assert "sub_140002000" in err

    def test_resolve_multi_match_error(self, sample_db):
        """When multiple DB results match, returns error with list."""
        # Add extra functions to DB with similar names
        import sqlite3
        conn = sqlite3.connect(str(sample_db))
        for fid, name in [(50, "TestFuncAlpha"), (51, "TestFuncBeta")]:
            conn.execute(
                "INSERT INTO functions (function_id, function_name) VALUES (?, ?)",
                (fid, name),
            )
        conn.commit()
        conn.close()

        with open_individual_analysis_db(str(sample_db)) as db:
            func, err = resolve_function(db, name="TestFunc")
            assert func is None
            assert "Multiple matches" in err
            assert "TestFuncAlpha" in err
            assert "TestFuncBeta" in err

    def test_resolve_no_args(self, sample_db):
        with open_individual_analysis_db(str(sample_db)) as db:
            func, err = resolve_function(db)
            assert func is None
            assert err is not None

    def test_resolve_by_name_db_fallback_no_index(self, sample_db):
        """Without an index, falls back to DB-based name lookup."""
        with open_individual_analysis_db(str(sample_db)) as db:
            func, err = resolve_function(db, name="DllMain")
            assert err is None
            assert func is not None
            assert func.function_name == "DllMain"

    def test_resolve_by_name_not_found(self, sample_db, sample_function_index):
        with open_individual_analysis_db(str(sample_db)) as db:
            func, err = resolve_function(
                db, name="CompletelyBogusName9999",
                function_index=sample_function_index,
            )
            assert func is None
            assert "No function matching" in err

    def test_allow_partial_false(self, sample_db, sample_function_index):
        """With allow_partial=False, partial matches are rejected."""
        with open_individual_analysis_db(str(sample_db)) as db:
            func, err = resolve_function(
                db, name="DllMai",
                function_index=sample_function_index,
                allow_partial=False,
            )
            assert func is None
            assert err is not None
            assert "No function matching" in err

    def test_allow_partial_false_still_allows_exact_match(
        self,
        sample_db,
        sample_function_index,
    ):
        with open_individual_analysis_db(str(sample_db)) as db:
            func, err = resolve_function(
                db,
                name="DllMain",
                function_index=sample_function_index,
                allow_partial=False,
            )
            assert err is None
            assert func is not None
            assert func.function_name == "DllMain"

    def test_id_takes_priority_over_name(self, sample_db, sample_function_index):
        """function_id is checked first, name is ignored."""
        with open_individual_analysis_db(str(sample_db)) as db:
            func, err = resolve_function(
                db, name="WppAutoLogTrace", function_id=1,
                function_index=sample_function_index,
            )
            assert err is None
            assert func.function_name == "DllMain"  # ID=1, not the name


class TestSearchFunctionsByPattern:
    """Tests for search_functions_by_pattern()."""

    def test_search_with_index(self, sample_db, sample_function_index):
        with open_individual_analysis_db(str(sample_db)) as db:
            results = search_functions_by_pattern(
                db, "Dll", function_index=sample_function_index,
            )
            assert len(results) >= 1
            names = [r.function_name for r in results]
            assert "DllMain" in names

    def test_search_without_index(self, sample_db):
        with open_individual_analysis_db(str(sample_db)) as db:
            results = search_functions_by_pattern(db, "DllMain")
            assert len(results) >= 1

    def test_search_without_index_finds_name_only_match(self, tmp_path):
        db_path = tmp_path / "name_only_match.db"
        _create_sample_db(db_path)

        conn = sqlite3.connect(str(db_path))
        conn.execute(
            """
            INSERT INTO functions (
                function_id, function_signature, function_signature_extended,
                mangled_name, function_name, assembly_code, decompiled_code,
                inbound_xrefs, outbound_xrefs, simple_inbound_xrefs,
                simple_outbound_xrefs, vtable_contexts, global_var_accesses,
                dangerous_api_calls, string_literals, stack_frame, loop_analysis,
                analysis_errors, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                99,
                "void helper_alias(void)",
                "void helper_alias(void)",
                None,
                "OnlyNameMatch",
                None,
                "void helper_alias(void) { return; }",
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ),
        )
        conn.commit()
        conn.close()

        with open_individual_analysis_db(str(db_path)) as db:
            results = search_functions_by_pattern(db, "OnlyNameMatch")

        assert len(results) == 1
        assert results[0].function_name == "OnlyNameMatch"

    def test_search_no_results(self, sample_db, sample_function_index):
        with open_individual_analysis_db(str(sample_db)) as db:
            results = search_functions_by_pattern(
                db, "ZZZZZ_NoMatch_ZZZZZ",
                function_index=sample_function_index,
            )
            assert results == []


# ===========================================================================
# db_paths tests
# ===========================================================================

class TestResolveModuleDb:
    """Tests for the centralized resolve_module_db().

    Uses mock workspace layouts instead of real extraction data so tests
    pass on any machine without requiring actual extracted_dbs/.
    """

    @pytest.fixture
    def mock_workspace(self, tmp_path):
        """Create a workspace with a tracking DB and a fake analysis DB."""
        ws = tmp_path / "workspace"
        ws.mkdir()
        dbs_dir = ws / "extracted_dbs"
        dbs_dir.mkdir()

        # Create a fake analysis DB file
        fake_db = dbs_dir / "appinfo_dll_f2bbf324a1.db"
        fake_db.write_bytes(b"")

        # Create the tracking DB
        import sqlite3
        tracking = dbs_dir / "analyzed_files.db"
        conn = sqlite3.connect(str(tracking))
        conn.execute(
            "CREATE TABLE analyzed_files ("
            "  file_path TEXT PRIMARY KEY NOT NULL,"
            "  base_dir TEXT, file_name TEXT, file_extension TEXT,"
            "  md5_hash TEXT, sha256_hash TEXT, analysis_db_path TEXT,"
            "  status TEXT NOT NULL DEFAULT 'PENDING',"
            "  analysis_flags TEXT,"
            "  analysis_start_timestamp TIMESTAMP,"
            "  analysis_completion_timestamp TIMESTAMP)"
        )
        conn.execute(
            "INSERT INTO analyzed_files "
            "(file_path, file_name, analysis_db_path, status) "
            "VALUES (?, ?, ?, ?)",
            ("C:\\Windows\\appinfo.dll", "appinfo.dll",
             "appinfo_dll_f2bbf324a1.db", "COMPLETE"),
        )
        conn.commit()
        conn.close()
        return ws

    def test_resolve_by_module_name(self, mock_workspace):
        result = resolve_module_db("appinfo.dll", mock_workspace)
        assert result is not None
        assert "appinfo_dll" in result
        assert result.endswith(".db")

    def test_resolve_by_db_path(self, mock_workspace):
        result = resolve_module_db(
            "extracted_dbs/appinfo_dll_f2bbf324a1.db", mock_workspace,
        )
        assert result is not None
        assert Path(result).exists()

    def test_resolve_not_found(self, mock_workspace):
        result = resolve_module_db("nonexistent_module.dll", mock_workspace)
        assert result is None

    def test_resolve_require_complete_true(self, mock_workspace):
        result = resolve_module_db("appinfo.dll", mock_workspace, require_complete=True)
        assert result is not None
        assert "appinfo_dll" in result
        assert result.endswith(".db")

    def test_resolve_require_complete_false(self, mock_workspace):
        result = resolve_module_db("appinfo.dll", mock_workspace, require_complete=False)
        assert result is not None
        assert "appinfo_dll" in result
        assert result.endswith(".db")

    def test_resolve_by_sanitized_module_name(self, mock_workspace):
        result = resolve_module_db("appinfo_dll", mock_workspace)
        assert result is not None
        assert Path(result).name == "appinfo_dll_f2bbf324a1.db"

    def test_resolve_by_module_name_without_tracking_db(self, mock_workspace):
        tracking = mock_workspace / "extracted_dbs" / "analyzed_files.db"
        tracking.unlink()

        result = resolve_module_db("appinfo.dll", mock_workspace)

        assert result is not None
        assert Path(result).name == "appinfo_dll_f2bbf324a1.db"

    def test_resolve_ambiguous_partial_match_returns_none(self, mock_workspace, capsys):
        alt_db = mock_workspace / "extracted_dbs" / "appinfo_tools_dll_a1b2c3.db"
        alt_db.write_bytes(b"")

        import sqlite3

        tracking = mock_workspace / "extracted_dbs" / "analyzed_files.db"
        conn = sqlite3.connect(str(tracking))
        conn.execute(
            "INSERT INTO analyzed_files "
            "(file_path, file_name, analysis_db_path, status) "
            "VALUES (?, ?, ?, ?)",
            (
                "C:\\Windows\\appinfo-tools.dll",
                "appinfo-tools.dll",
                alt_db.name,
                "COMPLETE",
            ),
        )
        conn.commit()
        conn.close()

        result = resolve_module_db("appinfo", mock_workspace)

        assert result is None
        err = capsys.readouterr().err
        assert "Ambiguous module name" in err
        assert "appinfo-tools.dll" in err
        assert "appinfo.dll" in err

    def test_resolve_tracking_db(self, mock_workspace):
        result = resolve_tracking_db(mock_workspace)
        assert result is not None
        assert "analyzed_files.db" in result

    def test_resolve_db_path_relative(self, mock_workspace):
        result = resolve_db_path("extracted_dbs/appinfo_dll_f2bbf324a1.db", mock_workspace)
        assert result is not None
        assert Path(result).name == "appinfo_dll_f2bbf324a1.db"


# ===========================================================================
# string_taxonomy tests
# ===========================================================================

class TestStringTaxonomy:
    """Tests for STRING_TAXONOMY data and categorize_* functions."""

    def test_taxonomy_count(self):
        assert len(STRING_TAXONOMY) >= 15

    def test_taxonomy_structure(self):
        for pat, cat, desc in STRING_TAXONOMY:
            assert hasattr(pat, "search"), f"Pattern for {cat} not compiled"
            assert isinstance(cat, str)
            assert isinstance(desc, str)
            assert len(cat) > 0
            assert len(desc) > 0

    def test_categories_list(self):
        assert len(CATEGORIES) >= 10
        assert "file_path" in CATEGORIES
        assert "registry_key" in CATEGORIES
        assert "url" in CATEGORIES
        assert "debug_trace" in CATEGORIES
        assert "alpc_path" in CATEGORIES
        assert "service_account" in CATEGORIES
        assert "certificate" in CATEGORIES

    def test_all_categories_covered(self):
        """Every category in CATEGORIES appears in at least one taxonomy entry."""
        taxonomy_cats = {cat for _, cat, _ in STRING_TAXONOMY}
        for cat in CATEGORIES:
            assert cat in taxonomy_cats, f"Category {cat} not in taxonomy"


class TestCategorizeString:
    """Tests for categorize_string() -> (category, description) | None."""

    def test_file_path_drive(self):
        result = categorize_string(r"C:\Windows\System32\ntdll.dll")
        assert result is not None
        assert result[0] == "file_path"

    def test_file_path_device(self):
        result = categorize_string(r"\\?\C:\test")
        assert result is not None
        assert result[0] == "file_path"

    def test_file_path_env_var(self):
        result = categorize_string(r"%SystemRoot%\test.dll")
        assert result is not None
        assert result[0] == "file_path"

    def test_file_path_system(self):
        result = categorize_string(r"something\System32\driver")
        assert result is not None
        assert result[0] == "file_path"

    def test_file_path_pe_extension(self):
        # The pattern requires a preceding '.' -> full filename like "path\foo.dll"
        result = categorize_string(r"C:\path\mymodule.dll")
        assert result is not None
        assert result[0] == "file_path"

    def test_registry_key(self):
        result = categorize_string(r"HKEY_LOCAL_MACHINE\SOFTWARE\Test")
        assert result is not None
        assert result[0] == "registry_key"

    def test_registry_path(self):
        result = categorize_string(r"SOFTWARE\Microsoft\Windows")
        assert result is not None
        assert result[0] == "registry_key"

    def test_url(self):
        result = categorize_string("https://example.com/api")
        assert result is not None
        assert result[0] == "url"

    def test_rpc_endpoint(self):
        result = categorize_string("ncalrpc:")
        assert result is not None
        assert result[0] == "rpc_endpoint"

    def test_named_pipe(self):
        # Use the escaped form that appears in decompiled code strings
        result = categorize_string("\\\\.\\pipe\\testpipe")
        assert result is not None
        result2 = categorize_string_simple("\\\\.\\pipe\\mypipe")
        assert result2 == "file_path"

    def test_etw_provider(self):
        result = categorize_string("Microsoft-Windows-Shell-Core")
        assert result is not None
        assert result[0] == "etw_provider"

    def test_guid(self):
        result = categorize_string("{12345678-1234-1234-1234-123456789ABC}")
        assert result is not None
        assert result[0] == "guid"

    def test_error_message(self):
        result = categorize_string("Error: access denied")
        assert result is not None
        assert result[0] == "error_message"

    def test_format_string(self):
        result = categorize_string("%s: %d items processed")
        assert result is not None
        assert result[0] == "format_string"

    def test_debug_trace(self):
        result = categorize_string("TraceLogging provider init")
        assert result is not None
        assert result[0] == "debug_trace"

    def test_no_match(self):
        result = categorize_string("just a normal string")
        assert result is None

    def test_empty_string(self):
        result = categorize_string("")
        assert result is None

    def test_returns_description(self):
        result = categorize_string("https://test.com")
        assert result is not None
        cat, desc = result
        assert cat == "url"
        assert isinstance(desc, str)
        assert len(desc) > 0


class TestCategorizeStringSimple:
    """Tests for categorize_string_simple() -> str."""

    def test_match_returns_category(self):
        assert categorize_string_simple("https://test.com") == "url"

    def test_no_match_returns_other(self):
        assert categorize_string_simple("random text") == "other"

    def test_empty_returns_other(self):
        assert categorize_string_simple("") == "other"


class TestCategorizeStrings:
    """Tests for categorize_strings() -> dict."""

    def test_basic_categorization(self):
        strings = [
            "https://a.com",
            "https://b.com",
            r"HKEY_LOCAL_MACHINE\X",
            "normal text",
        ]
        result = categorize_strings(strings)
        assert "url" in result
        assert len(result["url"]) == 2
        assert "registry_key" in result
        assert "other" in result

    def test_skips_non_strings(self):
        result = categorize_strings(["text", 123, None, "", "more text"])
        # empty string is skipped (strip() is falsy)
        # 123 and None are skipped (not isinstance str)
        total = sum(len(v) for v in result.values())
        assert total == 2  # "text" and "more text"

    def test_empty_list(self):
        result = categorize_strings([])
        assert result == {}


class TestTaxonomyToClassification:
    """Tests for the backward-compatibility mapping."""

    def test_all_expected_keys(self):
        expected = {
            "registry_key": "registry",
            "url": "network",
            "rpc_endpoint": "rpc",
            "named_pipe": "rpc",
            "alpc_path": "rpc",
            "service_account": "security",
            "certificate": "crypto",
            "etw_provider": "telemetry",
            "format_string": "data_parsing",
        }
        assert TAXONOMY_TO_CLASSIFICATION == expected

    def test_string_rules_derivation(self):
        """Reproduce how classify-functions builds STRING_RULES."""
        STRING_RULES = [
            (pat, TAXONOMY_TO_CLASSIFICATION.get(cat, cat), desc)
            for pat, cat, desc in STRING_TAXONOMY
            if cat in TAXONOMY_TO_CLASSIFICATION
        ]
        # Should have entries for all mapped categories
        rule_cats = {cat for _, cat, _ in STRING_RULES}
        assert "registry" in rule_cats
        assert "rpc" in rule_cats
        assert "network" in rule_cats
        assert "telemetry" in rule_cats
        assert "data_parsing" in rule_cats
        assert "security" in rule_cats
        assert "crypto" in rule_cats
        # Should NOT include unmapped categories
        assert "file_path" not in rule_cats
        assert "guid" not in rule_cats


# ===========================================================================
# Integration: consumer wrappers still work
# ===========================================================================

class TestConsumerWrappers:
    """Verify that the thin wrappers in consumer _common.py files still work."""

    def test_classify_functions_string_rules(self):
        """classify-functions STRING_RULES is derived from taxonomy."""
        from conftest import import_skill_module
        mod = import_skill_module("classify-functions")
        assert hasattr(mod, "STRING_RULES")
        assert len(mod.STRING_RULES) > 0
        # Each rule should be (pattern, category, description)
        for pat, cat, desc in mod.STRING_RULES:
            assert hasattr(pat, "search")
            # Categories should be the classify-functions names
            assert cat in ("registry", "rpc", "network", "telemetry", "data_parsing", "security", "crypto")

    def test_generate_re_report_string_categories(self):
        """generate-re-report STRING_CATEGORIES is the full taxonomy."""
        from conftest import import_skill_module
        mod = import_skill_module("generate-re-report")
        assert hasattr(mod, "STRING_CATEGORIES")
        assert hasattr(mod, "categorize_string")
        # Should be the full taxonomy (grows as we add categories)
        assert len(mod.STRING_CATEGORIES) >= 13

    def test_generate_re_report_categorize_string(self):
        from conftest import import_skill_module
        mod = import_skill_module("generate-re-report")
        result = mod.categorize_string("https://test.com")
        assert result is not None
        assert result[0] == "url"

    def test_deep_research_categorize_strings(self):
        """deep-research-prompt categorize_strings works."""
        from conftest import import_skill_module
        mod = import_skill_module("deep-research-prompt")
        assert hasattr(mod, "categorize_string")
        assert hasattr(mod, "categorize_strings")
        result = mod.categorize_strings(["https://a.com", "random"])
        assert "url" in result
