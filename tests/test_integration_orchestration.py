"""Integration tests for orchestration-layer modules.

Covers:
  1. Workspace bootstrap lifecycle (prepare_step, complete_step, manifest)
  2. Batch operations (batch_extract, batch_resolve, batch_xref_targets)
  3. Cross-module resolution (ModuleResolver, resolve_function, resolve_xref)

These tests exercise the public APIs end-to-end against real SQLite DBs
(created via conftest fixtures) to catch integration issues that unit
tests on individual functions miss.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from conftest import _create_sample_db, _seed_sample_db
from helpers.batch_operations import (
    batch_extract_function_data,
    batch_resolve_functions,
    batch_resolve_xref_targets,
)
from helpers.individual_analysis_db import (
    IndividualAnalysisDB,
    open_individual_analysis_db,
)
from helpers.workspace_bootstrap import complete_step, prepare_step
from helpers.workspace_validation import validate_workspace_run
from helpers.workspace import create_run_dir, update_manifest, write_results


# ===================================================================
# Helpers
# ===================================================================


def _read_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _create_module_db(db_path: Path, module_name: str = "test.dll") -> None:
    """Create and seed a minimal module analysis DB at *db_path*."""
    _create_sample_db(db_path)
    _seed_sample_db(db_path)
    # Update the file_info row with the correct module name
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE file_info SET file_name = ?", (module_name,))
    conn.commit()
    conn.close()


def _create_tracking_db(
    tracking_db_path: Path,
    modules: dict[str, Path],
) -> None:
    """Create a minimal tracking DB that maps module names to analysis DB paths.

    *modules* maps ``file_name -> db_path``.
    """
    conn = sqlite3.connect(tracking_db_path)
    conn.execute("""
        CREATE TABLE analyzed_files (
            file_path TEXT PRIMARY KEY,
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
    """)
    for file_name, db_path in modules.items():
        # Store the path relative to the tracking DB's parent directory
        try:
            rel_path = db_path.relative_to(tracking_db_path.parent)
        except ValueError:
            rel_path = db_path
        conn.execute(
            """
            INSERT INTO analyzed_files
                (file_path, base_dir, file_name, file_extension,
                 md5_hash, sha256_hash, analysis_db_path, status,
                 analysis_flags, analysis_start_timestamp,
                 analysis_completion_timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"C:\\Windows\\System32\\{file_name}",
                "C:\\Windows\\System32",
                file_name,
                ".dll",
                "abc123",
                "def456",
                str(rel_path),
                "COMPLETE",
                None,
                "2024-01-01T00:00:00",
                "2024-01-01T00:01:00",
            ),
        )
    conn.commit()
    conn.close()


# ===================================================================
# 1. Workspace Bootstrap Lifecycle Tests
# ===================================================================


class TestPrepareStep:
    """Test prepare_step() creates directory structure."""

    def test_creates_step_directory(self, tmp_path):
        run_dir = tmp_path / "run_001"
        run_dir.mkdir()
        paths = prepare_step(str(run_dir), "classify")

        step_dir = Path(paths["step_path"])
        assert step_dir.exists()
        assert step_dir.is_dir()
        assert paths["step_name"] == "classify"

    def test_returns_correct_paths(self, tmp_path):
        run_dir = tmp_path / "run_002"
        run_dir.mkdir()
        paths = prepare_step(str(run_dir), "my-step")

        assert "results_path" in paths
        assert "summary_path" in paths
        assert paths["results_path"].endswith("results.json")
        assert paths["summary_path"].endswith("summary.json")

    def test_idempotent_on_existing_dir(self, tmp_path):
        run_dir = tmp_path / "run_003"
        run_dir.mkdir()
        paths1 = prepare_step(str(run_dir), "step_a")
        paths2 = prepare_step(str(run_dir), "step_a")
        assert paths1["step_path"] == paths2["step_path"]


class TestCompleteStep:
    """Test complete_step() writes results + summary + updates manifest."""

    def test_writes_results_and_summary(self, tmp_path):
        run_dir = tmp_path / "run_complete"
        run_dir.mkdir()
        (run_dir / "manifest.json").write_text(json.dumps({
            "run_id": "test", "steps": {}, "created_at": "2024-01-01",
        }))

        full_data = {"functions": [1, 2, 3], "count": 3}
        summary = {"count": 3, "status": "ok"}
        paths = complete_step(str(run_dir), "analysis", full_data, summary)

        results = _read_json(Path(paths["results_path"]))
        assert results["functions"] == [1, 2, 3]

        summary_out = _read_json(Path(paths["summary_path"]))
        assert summary_out["count"] == 3

    def test_updates_manifest(self, tmp_path):
        run_dir = tmp_path / "run_manifest"
        run_dir.mkdir()
        (run_dir / "manifest.json").write_text(json.dumps({
            "run_id": "test", "steps": {}, "created_at": "2024-01-01",
        }))

        complete_step(str(run_dir), "step1", {"data": True}, {"ok": True})

        manifest = _read_json(run_dir / "manifest.json")
        assert "step1" in manifest["steps"]
        assert manifest["steps"]["step1"]["status"] in ("ok", "success")
        assert "summary_path" in manifest["steps"]["step1"]

    def test_error_status_records_failure(self, tmp_path):
        run_dir = tmp_path / "run_error"
        run_dir.mkdir()
        (run_dir / "manifest.json").write_text(json.dumps({
            "run_id": "test", "steps": {}, "created_at": "2024-01-01",
        }))

        complete_step(
            str(run_dir), "failing_step",
            {"error": "something broke"},
            {"status": "failed"},
            status="error",
        )

        manifest = _read_json(run_dir / "manifest.json")
        assert manifest["steps"]["failing_step"]["status"] == "error"


class TestWorkspaceLifecycle:
    """Full lifecycle: create_run_dir -> prepare_step -> complete_step -> validate."""

    def test_full_lifecycle(self, tmp_path, monkeypatch):
        # Point create_run_dir at our tmp_path
        monkeypatch.setattr(
            "helpers.workspace._workspace_base_dir",
            lambda: tmp_path,
        )

        run_dir = create_run_dir("test_module", "analysis")
        run_path = Path(run_dir)
        assert run_path.exists()
        assert (run_path / "manifest.json").exists()

        # Step 1: classify
        prepare_step(run_dir, "classify")
        complete_step(
            run_dir, "classify",
            {"classified": ["func_a", "func_b"]},
            {"count": 2},
        )

        # Step 2: topology
        prepare_step(run_dir, "topology")
        complete_step(
            run_dir, "topology",
            {"graph": {"nodes": 10, "edges": 15}},
            {"nodes": 10, "edges": 15},
        )

        # Validate the full run
        result = validate_workspace_run(run_dir)
        assert result.valid, f"Validation failed: {result.issues}"
        assert result.step_count == 2

    def test_manifest_structure_after_multiple_steps(self, tmp_path):
        run_dir = tmp_path / "multi_step_run"
        run_dir.mkdir()
        (run_dir / "manifest.json").write_text(json.dumps({
            "run_id": "multi", "steps": {}, "created_at": "2024-01-01",
        }))

        steps = ["step_a", "step_b", "step_c"]
        for step in steps:
            prepare_step(str(run_dir), step)
            complete_step(
                str(run_dir), step,
                {"step": step, "data": True},
                {"step": step, "ok": True},
            )

        manifest = _read_json(run_dir / "manifest.json")
        assert "steps" in manifest
        assert isinstance(manifest["steps"], dict)
        for step in steps:
            step_name = step.replace("_", "-")  # _safe_name may normalize
            # Check that each step is present (may be normalized)
            found = any(
                s in manifest["steps"]
                for s in [step, step_name, step.replace("-", "_")]
            )
            assert found, f"Step '{step}' not found in manifest: {list(manifest['steps'].keys())}"

        # All steps should have status and summary_path
        for step_name, step_rec in manifest["steps"].items():
            assert "status" in step_rec
            assert "summary_path" in step_rec
            assert step_rec["status"] in ("ok", "success")


# ===================================================================
# 2. Batch Operations Tests
# ===================================================================


class TestBatchExtractFunctionData:
    """Test batch_extract_function_data against a real sample DB."""

    def test_valid_ids(self, sample_db):
        with open_individual_analysis_db(sample_db) as db:
            result = batch_extract_function_data(db, [1, 4])
        assert 1 in result
        assert 4 in result
        assert result[1]["function_name"] == "DllMain"
        assert result[4]["function_name"] == "sub_140002000"
        assert "decompiled_code" in result[1]
        assert "assembly_code" in result[4]

    def test_empty_id_list(self, sample_db):
        with open_individual_analysis_db(sample_db) as db:
            result = batch_extract_function_data(db, [])
        assert result == {}

    def test_nonexistent_ids(self, sample_db):
        with open_individual_analysis_db(sample_db) as db:
            result = batch_extract_function_data(db, [999, 1000, 2000])
        assert result == {}

    def test_mixed_existing_and_missing(self, sample_db):
        with open_individual_analysis_db(sample_db) as db:
            result = batch_extract_function_data(db, [1, 999])
        assert 1 in result
        assert 999 not in result

    def test_result_has_expected_fields(self, sample_db):
        with open_individual_analysis_db(sample_db) as db:
            result = batch_extract_function_data(db, [1])
        entry = result[1]
        expected_keys = {
            "function_id", "function_name", "function_signature",
            "decompiled_code", "assembly_code", "string_literals",
            "outbound_xrefs", "inbound_xrefs", "dangerous_api_calls",
            "stack_frame", "loop_analysis",
        }
        assert expected_keys.issubset(set(entry.keys()))


class TestBatchResolveFunctions:
    """Test batch_resolve_functions with mixed names and IDs."""

    def test_resolve_by_id(self, sample_db):
        with open_individual_analysis_db(sample_db) as db:
            result = batch_resolve_functions(db, [1, 4])
        assert result[1] is not None
        assert result[1].function_name == "DllMain"
        assert result[4] is not None
        assert result[4].function_name == "sub_140002000"

    def test_resolve_by_name(self, sample_db):
        with open_individual_analysis_db(sample_db) as db:
            result = batch_resolve_functions(db, ["DllMain", "WppAutoLogTrace"])
        assert result["DllMain"] is not None
        assert result["DllMain"].function_id == 1
        assert result["WppAutoLogTrace"] is not None
        assert result["WppAutoLogTrace"].function_id == 2

    def test_mixed_names_and_ids(self, sample_db):
        with open_individual_analysis_db(sample_db) as db:
            result = batch_resolve_functions(db, [1, "WppAutoLogTrace", 999, "NoSuchFunc"])
        assert result[1] is not None
        assert result["WppAutoLogTrace"] is not None
        assert result[999] is None
        assert result["NoSuchFunc"] is None

    def test_empty_list(self, sample_db):
        with open_individual_analysis_db(sample_db) as db:
            result = batch_resolve_functions(db, [])
        assert result == {}

    def test_numeric_string_resolved_as_id(self, sample_db):
        with open_individual_analysis_db(sample_db) as db:
            result = batch_resolve_functions(db, ["1"])
        assert result["1"] is not None
        assert result["1"].function_id == 1


class TestBatchResolveXrefTargets:
    """Test batch_resolve_xref_targets resolves outbound xref targets."""

    def test_resolves_internal_xrefs(self, sample_db):
        # Function 1 (DllMain) has an outbound xref to function_id=3
        with open_individual_analysis_db(sample_db) as db:
            result = batch_resolve_xref_targets(db, [1])
        assert 1 in result
        target_ids = [rec.function_id for rec in result[1]]
        assert 3 in target_ids

    def test_empty_id_list(self, sample_db):
        with open_individual_analysis_db(sample_db) as db:
            result = batch_resolve_xref_targets(db, [])
        assert result == {}

    def test_function_without_xrefs(self, sample_db):
        # Function 4 (sub_140002000) has no outbound xrefs
        with open_individual_analysis_db(sample_db) as db:
            result = batch_resolve_xref_targets(db, [4])
        assert 4 in result
        assert result[4] == []

    def test_nonexistent_source_id(self, sample_db):
        with open_individual_analysis_db(sample_db) as db:
            result = batch_resolve_xref_targets(db, [999])
        assert 999 in result
        assert result[999] == []

    def test_multiple_sources(self, sample_db):
        with open_individual_analysis_db(sample_db) as db:
            result = batch_resolve_xref_targets(db, [1, 3, 4])
        assert 1 in result
        assert 3 in result
        assert 4 in result


# ===================================================================
# 3. Cross-Module Integration Tests
# ===================================================================


class TestModuleResolverIntegration:
    """Test ModuleResolver with real module DBs and tracking DB."""

    @pytest.fixture
    def cross_module_env(self, tmp_path):
        """Create a tmp_path with 2 module DBs and a tracking DB."""
        dbs_dir = tmp_path / "extracted_dbs"
        dbs_dir.mkdir()

        # Module A: alpha.dll
        alpha_db = dbs_dir / "alpha_abc123.db"
        _create_module_db(alpha_db, "alpha.dll")

        # Module B: beta.dll -- fresh DB with different functions
        beta_db = dbs_dir / "beta_def456.db"
        _create_sample_db(beta_db)
        conn = sqlite3.connect(beta_db)
        conn.execute("""
            INSERT INTO file_info (file_path, file_name, file_extension,
                file_size_bytes, md5_hash, sha256_hash, analysis_timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            "C:\\Windows\\System32\\beta.dll", "beta.dll", ".dll",
            204800, "bbb111", "bbb222", "2024-06-20T12:00:00",
        ))
        conn.execute("""
            INSERT INTO functions (function_id, function_name, decompiled_code,
                assembly_code)
            VALUES (?, ?, ?, ?)
        """, (10, "BetaExport", "void BetaExport() {}", "ret"))
        conn.execute("""
            INSERT INTO functions (function_id, function_name, decompiled_code,
                assembly_code)
            VALUES (?, ?, ?, ?)
        """, (11, "BetaHelper", "int BetaHelper() { return 1; }", "mov eax, 1\nret"))
        conn.commit()
        conn.close()

        # Tracking DB
        tracking_db = dbs_dir / "analyzed_files.db"
        _create_tracking_db(tracking_db, {
            "alpha.dll": alpha_db,
            "beta.dll": beta_db,
        })

        return {
            "tracking_db": str(tracking_db),
            "alpha_db": str(alpha_db),
            "beta_db": str(beta_db),
            "dbs_dir": dbs_dir,
        }

    def test_loads_all_modules(self, cross_module_env):
        from helpers.cross_module_graph import ModuleResolver

        with ModuleResolver(cross_module_env["tracking_db"]) as resolver:
            modules = resolver.list_modules()
            module_names = {name.lower() for name, _path in modules}
            assert "alpha.dll" in module_names
            assert "beta.dll" in module_names

    def test_get_module_db(self, cross_module_env):
        from helpers.cross_module_graph import ModuleResolver

        with ModuleResolver(cross_module_env["tracking_db"]) as resolver:
            result = resolver.get_module_db("alpha.dll")
            assert result is not None
            db_path, file_name = result
            assert file_name == "alpha.dll"
            assert Path(db_path).exists()

    def test_get_module_db_case_insensitive(self, cross_module_env):
        from helpers.cross_module_graph import ModuleResolver

        with ModuleResolver(cross_module_env["tracking_db"]) as resolver:
            result = resolver.get_module_db("ALPHA.DLL")
            assert result is not None

    def test_get_module_db_missing(self, cross_module_env):
        from helpers.cross_module_graph import ModuleResolver

        with ModuleResolver(cross_module_env["tracking_db"]) as resolver:
            result = resolver.get_module_db("nonexistent.dll")
            assert result is None

    def test_resolve_function_across_modules(self, cross_module_env):
        from helpers.cross_module_graph import ModuleResolver

        with ModuleResolver(cross_module_env["tracking_db"]) as resolver:
            # DllMain exists in alpha.dll
            results = resolver.resolve_function("DllMain")
            assert len(results) >= 1
            modules_found = {r["module"].lower() for r in results}
            assert "alpha.dll" in modules_found

            # BetaExport exists in beta.dll
            results = resolver.resolve_function("BetaExport")
            assert len(results) >= 1
            modules_found = {r["module"].lower() for r in results}
            assert "beta.dll" in modules_found

    def test_resolve_function_not_found(self, cross_module_env):
        from helpers.cross_module_graph import ModuleResolver

        with ModuleResolver(cross_module_env["tracking_db"]) as resolver:
            results = resolver.resolve_function("CompletelyFakeFunction12345")
            assert results == []

    def test_resolve_xref(self, cross_module_env):
        from helpers.cross_module_graph import ModuleResolver

        with ModuleResolver(cross_module_env["tracking_db"]) as resolver:
            result = resolver.resolve_xref("beta.dll", "BetaExport")
            assert result is not None
            assert result["module"] == "beta.dll"
            assert result["function_name"] == "BetaExport"
            assert result["function_id"] == 10
            assert result["has_decompiled"] is True

    def test_resolve_xref_module_not_found(self, cross_module_env):
        from helpers.cross_module_graph import ModuleResolver

        with ModuleResolver(cross_module_env["tracking_db"]) as resolver:
            result = resolver.resolve_xref("nonexistent.dll", "Func")
            assert result is None

    def test_resolve_xref_function_not_in_module(self, cross_module_env):
        from helpers.cross_module_graph import ModuleResolver

        with ModuleResolver(cross_module_env["tracking_db"]) as resolver:
            result = resolver.resolve_xref("alpha.dll", "NoSuchFunction99999")
            assert result is not None
            # Module is analyzed but function not found -- result has a note
            assert result["function_id"] is None
            assert "not found" in result.get("note", "")

    def test_connection_caching(self, cross_module_env):
        from helpers.cross_module_graph import ModuleResolver

        with ModuleResolver(cross_module_env["tracking_db"]) as resolver:
            # First call opens and caches the connection
            resolver.resolve_function("DllMain")
            cache_size_1 = len(resolver._connection_cache)
            assert cache_size_1 > 0

            # Second call should reuse cached connections (no growth)
            resolver.resolve_function("BetaExport")
            cache_size_2 = len(resolver._connection_cache)
            # May grow by 1 if BetaExport is in a different DB, but no more
            assert cache_size_2 <= cache_size_1 + 1

            # Querying same module again does NOT grow the cache
            resolver.resolve_function("BetaHelper")
            cache_size_3 = len(resolver._connection_cache)
            assert cache_size_3 == cache_size_2

    def test_context_manager_cleanup(self, cross_module_env):
        from helpers.cross_module_graph import ModuleResolver

        resolver = ModuleResolver(cross_module_env["tracking_db"])
        resolver.resolve_function("DllMain")
        assert len(resolver._connection_cache) > 0

        resolver.close()
        assert len(resolver._connection_cache) == 0

    def test_context_manager_with_statement(self, cross_module_env):
        from helpers.cross_module_graph import ModuleResolver

        with ModuleResolver(cross_module_env["tracking_db"]) as resolver:
            resolver.resolve_function("DllMain")
            assert len(resolver._connection_cache) > 0
        # After exiting context, cache should be cleared
        assert len(resolver._connection_cache) == 0

    def test_batch_resolve_xrefs(self, cross_module_env):
        from helpers.cross_module_graph import ModuleResolver

        xrefs = [
            {"function_name": "BetaExport", "module_name": "beta.dll"},
            {"function_name": "DllMain", "module_name": "alpha.dll"},
            {"function_name": "Unknown", "module_name": "missing.dll"},
        ]
        with ModuleResolver(cross_module_env["tracking_db"]) as resolver:
            results = resolver.batch_resolve_xrefs(xrefs)
        assert results["beta.dll!BetaExport"] is not None
        assert results["beta.dll!BetaExport"]["function_id"] == 10
        assert results["alpha.dll!DllMain"] is not None
        assert results["alpha.dll!DllMain"]["function_id"] == 1
        assert results["missing.dll!Unknown"] is None

    def test_batch_resolve_xrefs_preserves_duplicate_function_names(self, cross_module_env):
        from helpers.cross_module_graph import ModuleResolver

        conn = sqlite3.connect(cross_module_env["beta_db"])
        conn.execute(
            """
            INSERT INTO functions (function_id, function_name, decompiled_code, assembly_code)
            VALUES (?, ?, ?, ?)
            """,
            (12, "DllMain", "BOOL DllMain() { return 1; }", "mov eax, 1\nret"),
        )
        conn.commit()
        conn.close()

        xrefs = [
            {"function_name": "DllMain", "module_name": "alpha.dll"},
            {"function_name": "DllMain", "module_name": "beta.dll"},
        ]
        with ModuleResolver(cross_module_env["tracking_db"]) as resolver:
            results = resolver.batch_resolve_xrefs(xrefs)

        assert results["alpha.dll!DllMain"] is not None
        assert results["alpha.dll!DllMain"]["module"] == "alpha.dll"
        assert results["alpha.dll!DllMain"]["function_id"] == 1
        assert results["beta.dll!DllMain"] is not None
        assert results["beta.dll!DllMain"]["module"] == "beta.dll"
        assert results["beta.dll!DllMain"]["function_id"] == 12
