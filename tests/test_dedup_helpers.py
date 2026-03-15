"""Tests for the deduplication helper modules.

Covers:
  - helpers.function_resolver (resolve_function, search_functions_by_pattern)
  - helpers.db_paths (resolve_module_db)
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

