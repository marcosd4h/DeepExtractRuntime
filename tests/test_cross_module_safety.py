"""Tests for cross-module thread safety, connection caching, and cleanup.

Targets:
  helpers/cross_module_graph.py  (ModuleResolver)
  helpers/analyzed_files_db/analyzed_files_db.py  (ThreadPoolExecutor usage)

Covers:
  - Thread safety: concurrent resolve_function calls from multiple threads
  - Connection caching: connections are reused across calls
  - Context manager / close(): all cached connections cleaned up
  - Function name index: built once, used for fast exact-match lookups
  - SQL injection protection: tested in test_sql_injection_protection.py
"""

from __future__ import annotations

import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import pytest

from conftest import _create_sample_db, _seed_sample_db


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_tracking_db(tmp_path: Path, module_dbs: dict[str, Path]) -> Path:
    """Create a minimal analyzed_files.db tracking database.

    *module_dbs* maps ``file_name`` -> ``analysis_db_path`` (absolute).
    The tracking DB stores paths relative to its own directory.
    """
    tracking_path = tmp_path / "analyzed_files.db"
    conn = sqlite3.connect(tracking_path)
    conn.execute("""
        CREATE TABLE analyzed_files (
            file_path TEXT, base_dir TEXT, file_name TEXT,
            file_extension TEXT, md5_hash TEXT, sha256_hash TEXT,
            analysis_db_path TEXT, status TEXT, analysis_flags TEXT,
            analysis_start_timestamp TEXT, analysis_completion_timestamp TEXT
        )
    """)
    for file_name, db_path in module_dbs.items():
        rel = db_path.relative_to(tmp_path)
        conn.execute(
            "INSERT INTO analyzed_files "
            "(file_path, file_name, file_extension, analysis_db_path, status) "
            "VALUES (?, ?, ?, ?, ?)",
            (str(db_path), file_name, ".dll", str(rel), "COMPLETE"),
        )
    conn.commit()
    conn.close()
    return tracking_path


def _create_module_db(tmp_path: Path, name: str, functions: list[tuple[int, str]]) -> Path:
    """Create a per-module analysis DB with the given (id, name) functions."""
    db_path = tmp_path / f"{name}.db"
    _create_sample_db(db_path)
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO file_info (file_path, file_name, file_extension) VALUES (?, ?, ?)",
        (f"C:\\Windows\\System32\\{name}", name, ".dll"),
    )
    for fid, fname in functions:
        conn.execute(
            "INSERT INTO functions (function_id, function_name, decompiled_code) "
            "VALUES (?, ?, ?)",
            (fid, fname, f"void {fname}() {{}}"),
        )
    conn.commit()
    conn.close()
    return db_path


@pytest.fixture
def multi_module_env(tmp_path):
    """Create a 3-module environment with tracking DB."""
    mod_a = _create_module_db(tmp_path, "alpha.dll", [
        (1, "AlphaInit"), (2, "AlphaProcess"), (3, "SharedFunc"),
    ])
    mod_b = _create_module_db(tmp_path, "beta.dll", [
        (1, "BetaInit"), (2, "BetaCleanup"), (3, "SharedFunc"),
    ])
    mod_c = _create_module_db(tmp_path, "gamma.dll", [
        (1, "GammaStart"), (2, "GammaStop"),
    ])
    tracking = _create_tracking_db(tmp_path, {
        "alpha.dll": mod_a,
        "beta.dll": mod_b,
        "gamma.dll": mod_c,
    })
    return tracking, tmp_path


# ===================================================================
# ModuleResolver -- context manager and close()
# ===================================================================

class TestModuleResolverLifecycle:
    def test_context_manager_basic(self, multi_module_env):
        tracking, _ = multi_module_env
        from helpers.cross_module_graph import ModuleResolver

        with ModuleResolver(str(tracking)) as resolver:
            modules = resolver.list_modules()
            assert len(modules) == 3

    def test_context_manager_with_workspace_relative_db_paths(self, tmp_path):
        from helpers.cross_module_graph import ModuleResolver

        workspace = tmp_path
        dbs_dir = workspace / "extracted_dbs"
        dbs_dir.mkdir()
        module_db = _create_module_db(dbs_dir, "alpha.dll", [(1, "AlphaInit")])

        tracking = dbs_dir / "analyzed_files.db"
        conn = sqlite3.connect(tracking)
        conn.execute("""
            CREATE TABLE analyzed_files (
                file_path TEXT, base_dir TEXT, file_name TEXT,
                file_extension TEXT, md5_hash TEXT, sha256_hash TEXT,
                analysis_db_path TEXT, status TEXT, analysis_flags TEXT,
                analysis_start_timestamp TEXT, analysis_completion_timestamp TEXT
            )
        """)
        conn.execute(
            "INSERT INTO analyzed_files "
            "(file_path, file_name, file_extension, analysis_db_path, status) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                str(module_db),
                "alpha.dll",
                ".dll",
                f"extracted_dbs/{module_db.name}",
                "COMPLETE",
            ),
        )
        conn.commit()
        conn.close()

        with ModuleResolver(str(tracking)) as resolver:
            modules = resolver.list_modules()
            assert modules == [("alpha.dll", str(module_db))]

    def test_close_clears_connection_cache(self, multi_module_env):
        tracking, _ = multi_module_env
        from helpers.cross_module_graph import ModuleResolver

        resolver = ModuleResolver(str(tracking))
        resolver.resolve_function("AlphaInit")
        assert len(resolver._connection_cache) > 0

        resolver.close()
        assert len(resolver._connection_cache) == 0
        assert resolver._function_name_index is None

    def test_context_manager_closes_on_exit(self, multi_module_env):
        tracking, _ = multi_module_env
        from helpers.cross_module_graph import ModuleResolver

        resolver = ModuleResolver(str(tracking))
        resolver.__enter__()
        resolver.resolve_function("AlphaInit")
        cache_size = len(resolver._connection_cache)
        assert cache_size > 0

        resolver.__exit__(None, None, None)
        assert len(resolver._connection_cache) == 0

    def test_close_idempotent(self, multi_module_env):
        tracking, _ = multi_module_env
        from helpers.cross_module_graph import ModuleResolver

        resolver = ModuleResolver(str(tracking))
        resolver.resolve_function("AlphaInit")
        resolver.close()
        resolver.close()  # second close should be a no-op
        assert len(resolver._connection_cache) == 0


# ===================================================================
# Connection caching
# ===================================================================

class TestConnectionCaching:
    def test_connections_reused_across_calls(self, multi_module_env):
        tracking, _ = multi_module_env
        from helpers.cross_module_graph import ModuleResolver

        with ModuleResolver(str(tracking)) as resolver:
            resolver.resolve_function("AlphaInit")
            cache_snapshot_1 = dict(resolver._connection_cache)

            resolver.resolve_function("AlphaProcess")
            cache_snapshot_2 = dict(resolver._connection_cache)

            # Same DB objects should be reused (identity check)
            for key in cache_snapshot_1:
                assert cache_snapshot_1[key] is cache_snapshot_2[key]

    def test_resolve_xref_uses_cache(self, multi_module_env):
        tracking, _ = multi_module_env
        from helpers.cross_module_graph import ModuleResolver

        with ModuleResolver(str(tracking)) as resolver:
            resolver.resolve_xref("alpha.dll", "AlphaInit")
            cache_before = len(resolver._connection_cache)
            assert cache_before >= 1

            resolver.resolve_xref("alpha.dll", "AlphaProcess")
            cache_after = len(resolver._connection_cache)
            # No new connections for the same module
            assert cache_after == cache_before

    def test_batch_resolve_uses_cache(self, multi_module_env):
        tracking, _ = multi_module_env
        from helpers.cross_module_graph import ModuleResolver

        with ModuleResolver(str(tracking)) as resolver:
            xrefs = [
                {"function_name": "AlphaInit", "module_name": "alpha.dll"},
                {"function_name": "BetaInit", "module_name": "beta.dll"},
            ]
            resolver.batch_resolve_xrefs(xrefs)
            assert len(resolver._connection_cache) >= 2

            # Second call should not grow the cache
            cache_before = len(resolver._connection_cache)
            resolver.batch_resolve_xrefs(xrefs)
            assert len(resolver._connection_cache) == cache_before

    def test_different_modules_get_different_connections(self, multi_module_env):
        tracking, _ = multi_module_env
        from helpers.cross_module_graph import ModuleResolver

        with ModuleResolver(str(tracking)) as resolver:
            resolver.resolve_xref("alpha.dll", "AlphaInit")
            resolver.resolve_xref("beta.dll", "BetaInit")

            db_objects = list(resolver._connection_cache.values())
            assert len(db_objects) >= 2
            assert db_objects[0] is not db_objects[1]


# ===================================================================
# Function name index
# ===================================================================

class TestFunctionNameIndex:
    def test_index_built_on_first_resolve(self, multi_module_env):
        tracking, _ = multi_module_env
        from helpers.cross_module_graph import ModuleResolver

        with ModuleResolver(str(tracking)) as resolver:
            assert resolver._function_name_index is None
            resolver.resolve_function("AlphaInit")
            assert resolver._function_name_index is not None

    def test_index_contains_all_functions(self, multi_module_env):
        tracking, _ = multi_module_env
        from helpers.cross_module_graph import ModuleResolver

        with ModuleResolver(str(tracking)) as resolver:
            resolver.resolve_function("AlphaInit")
            index = resolver._function_name_index
            assert index is not None
            assert "alphainit" in index
            assert "betainit" in index
            assert "gammastart" in index

    def test_shared_function_in_multiple_modules(self, multi_module_env):
        tracking, _ = multi_module_env
        from helpers.cross_module_graph import ModuleResolver

        with ModuleResolver(str(tracking)) as resolver:
            results = resolver.resolve_function("SharedFunc")
            modules = {r["module"] for r in results}
            assert "alpha.dll" in modules
            assert "beta.dll" in modules

    def test_exact_match_fast_path(self, multi_module_env):
        tracking, _ = multi_module_env
        from helpers.cross_module_graph import ModuleResolver

        with ModuleResolver(str(tracking)) as resolver:
            results = resolver.resolve_function("GammaStart")
            assert len(results) == 1
            assert results[0]["module"] == "gamma.dll"
            assert results[0]["function_name"] == "GammaStart"

    def test_substring_match_fallback(self, multi_module_env):
        tracking, _ = multi_module_env
        from helpers.cross_module_graph import ModuleResolver

        with ModuleResolver(str(tracking)) as resolver:
            results = resolver.resolve_function("Init", fuzzy=True)
            names = {r["function_name"] for r in results}
            assert "AlphaInit" in names
            assert "BetaInit" in names

    def test_no_match_returns_empty(self, multi_module_env):
        tracking, _ = multi_module_env
        from helpers.cross_module_graph import ModuleResolver

        with ModuleResolver(str(tracking)) as resolver:
            results = resolver.resolve_function("NonExistentFunction_XYZ")
            assert results == []


# ===================================================================
# Thread safety
# ===================================================================

class TestThreadSafety:
    def test_concurrent_resolve_function(self, multi_module_env):
        """Multiple threads calling resolve_function simultaneously."""
        tracking, _ = multi_module_env
        from helpers.cross_module_graph import ModuleResolver

        resolver = ModuleResolver(str(tracking))
        errors: list[Exception] = []
        results_per_thread: list[list[dict]] = []
        lock = threading.Lock()

        def worker(func_name: str) -> None:
            try:
                r = resolver.resolve_function(func_name)
                with lock:
                    results_per_thread.append(r)
            except Exception as exc:
                with lock:
                    errors.append(exc)

        threads = []
        names = ["AlphaInit", "BetaInit", "SharedFunc", "GammaStart", "GammaStop"]
        for name in names * 3:  # 15 threads total
            t = threading.Thread(target=worker, args=(name,))
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        resolver.close()
        assert errors == [], f"Thread errors: {errors}"
        assert len(results_per_thread) == 15

    def test_concurrent_resolve_xref(self, multi_module_env):
        """Multiple threads calling resolve_xref simultaneously."""
        tracking, _ = multi_module_env
        from helpers.cross_module_graph import ModuleResolver

        results: list[Any] = []
        errors: list[Exception] = []
        lock = threading.Lock()

        with ModuleResolver(str(tracking)) as resolver:
            def worker(mod: str, func: str) -> None:
                try:
                    r = resolver.resolve_xref(mod, func)
                    with lock:
                        results.append(r)
                except Exception as exc:
                    with lock:
                        errors.append(exc)

            xrefs = [
                ("alpha.dll", "AlphaInit"),
                ("beta.dll", "BetaInit"),
                ("gamma.dll", "GammaStart"),
                ("alpha.dll", "SharedFunc"),
                ("beta.dll", "SharedFunc"),
            ]
            threads = [threading.Thread(target=worker, args=x) for x in xrefs * 2]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10)

        assert errors == [], f"Thread errors: {errors}"
        assert len(results) == 10

    def test_concurrent_ensure_loaded(self, multi_module_env):
        """_ensure_loaded called from many threads at once."""
        tracking, _ = multi_module_env
        from helpers.cross_module_graph import ModuleResolver

        resolver = ModuleResolver(str(tracking))
        barrier = threading.Barrier(8)
        errors: list[Exception] = []

        def worker() -> None:
            try:
                barrier.wait(timeout=5)
                resolver._ensure_loaded()
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        resolver.close()
        assert errors == []
        assert resolver._loaded is True
        assert len(resolver._module_cache) == 3

    def test_thread_pool_resolve_function(self, multi_module_env):
        """ThreadPoolExecutor exercising resolve_function."""
        tracking, _ = multi_module_env
        from helpers.cross_module_graph import ModuleResolver

        with ModuleResolver(str(tracking)) as resolver:
            names = ["AlphaInit", "BetaInit", "SharedFunc", "GammaStart"]
            with ThreadPoolExecutor(max_workers=4) as pool:
                futures = {pool.submit(resolver.resolve_function, n): n for n in names}
                for future in as_completed(futures):
                    result = future.result()
                    assert isinstance(result, list)


# ===================================================================
# Edge cases
# ===================================================================

class TestEdgeCases:
    def test_empty_tracking_db(self, tmp_path):
        """ModuleResolver with no analyzed modules."""
        from helpers.cross_module_graph import ModuleResolver

        tracking = _create_tracking_db(tmp_path, {})
        with ModuleResolver(str(tracking)) as resolver:
            assert resolver.list_modules() == []
            assert resolver.resolve_function("anything") == []
            assert resolver.resolve_xref("foo.dll", "bar") is None

    def test_missing_module_db_file(self, tmp_path):
        """Tracking DB references a module whose .db file is missing."""
        from helpers.cross_module_graph import ModuleResolver

        ghost_path = tmp_path / "ghost.db"
        tracking = _create_tracking_db(tmp_path, {"ghost.dll": ghost_path})
        # ghost.db does not exist on disk
        with ModuleResolver(str(tracking)) as resolver:
            modules = resolver.list_modules()
            assert len(modules) == 0

    def test_resolver_without_tracking_db(self):
        """ModuleResolver with no tracking DB found (returns gracefully)."""
        from helpers.cross_module_graph import ModuleResolver

        resolver = ModuleResolver("/nonexistent/path/analyzed_files.db")
        # _ensure_loaded should handle the missing path
        modules = resolver.list_modules()
        assert modules == []
        resolver.close()
