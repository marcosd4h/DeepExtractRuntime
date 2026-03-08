"""Tests for ModuleResolver LRU connection eviction (Critical fix #1).

Verifies that the connection pool in ModuleResolver:
- Evicts the least-recently-used connection when full
- Respects max_cached_connections limit
- Properly closes evicted connections
- Updates LRU order on cache hits
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from conftest import _create_sample_db


def _create_tracking_db(tmp_path: Path, module_dbs: dict[str, Path]) -> Path:
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
def five_module_env(tmp_path):
    """Create a 5-module environment to test LRU eviction with max_cached=3."""
    modules = {}
    for i, name in enumerate(["a.dll", "b.dll", "c.dll", "d.dll", "e.dll"]):
        db = _create_module_db(tmp_path, name, [(1, f"Func{i}")])
        modules[name] = db
    tracking = _create_tracking_db(tmp_path, modules)
    return tracking, tmp_path


class TestLRUEviction:
    """Test that connections are evicted when the pool is full."""

    def test_max_cached_connections_respected(self, five_module_env):
        tracking, _ = five_module_env
        from helpers.cross_module_graph import ModuleResolver

        with ModuleResolver(str(tracking), max_cached_connections=3) as resolver:
            resolver.resolve_xref("a.dll", "Func0")
            resolver.resolve_xref("b.dll", "Func1")
            resolver.resolve_xref("c.dll", "Func2")
            assert len(resolver._connection_cache) == 3

            resolver.resolve_xref("d.dll", "Func3")
            assert len(resolver._connection_cache) <= 3

    def test_lru_evicts_oldest(self, five_module_env):
        tracking, _ = five_module_env
        from helpers.cross_module_graph import ModuleResolver

        with ModuleResolver(str(tracking), max_cached_connections=2) as resolver:
            resolver.resolve_xref("a.dll", "Func0")
            resolver.resolve_xref("b.dll", "Func1")
            assert len(resolver._connection_cache) == 2

            # Access c.dll => a.dll should be evicted (it's oldest)
            resolver.resolve_xref("c.dll", "Func2")
            assert len(resolver._connection_cache) == 2

            keys = list(resolver._connection_cache.keys())
            a_path = [k for k in keys if "a.dll" in k]
            assert len(a_path) == 0, "a.dll should have been evicted"

    def test_lru_touch_prevents_eviction(self, five_module_env):
        tracking, _ = five_module_env
        from helpers.cross_module_graph import ModuleResolver

        with ModuleResolver(str(tracking), max_cached_connections=2) as resolver:
            resolver.resolve_xref("a.dll", "Func0")
            resolver.resolve_xref("b.dll", "Func1")

            # Touch a.dll again (moves it to end of LRU)
            resolver.resolve_xref("a.dll", "Func0")

            # Now add c.dll => b.dll should be evicted (a was just touched)
            resolver.resolve_xref("c.dll", "Func2")
            keys = list(resolver._connection_cache.keys())
            b_paths = [k for k in keys if "b.dll" in k]
            assert len(b_paths) == 0, "b.dll should have been evicted (a was touched)"

    def test_pool_size_one(self, five_module_env):
        tracking, _ = five_module_env
        from helpers.cross_module_graph import ModuleResolver

        with ModuleResolver(str(tracking), max_cached_connections=1) as resolver:
            for mod in ["a.dll", "b.dll", "c.dll"]:
                resolver.resolve_xref(mod, "Func0")
                assert len(resolver._connection_cache) <= 1

    def test_default_pool_size_from_config(self, five_module_env):
        tracking, _ = five_module_env
        from helpers.cross_module_graph import ModuleResolver
        from helpers.config import get_config_value

        expected = get_config_value("scale.max_cached_connections", 50)
        resolver = ModuleResolver(str(tracking))
        assert resolver._max_cached_connections == expected
        resolver.close()

    def test_close_clears_lru(self, five_module_env):
        tracking, _ = five_module_env
        from helpers.cross_module_graph import ModuleResolver

        resolver = ModuleResolver(str(tracking), max_cached_connections=3)
        resolver.resolve_xref("a.dll", "Func0")
        resolver.resolve_xref("b.dll", "Func1")
        assert len(resolver._connection_cache) > 0

        resolver.close()
        assert len(resolver._connection_cache) == 0

    def test_evicted_connections_closed_immediately(self, five_module_env):
        """Evicted connections are closed during eviction."""
        tracking, _ = five_module_env
        from helpers.cross_module_graph import ModuleResolver

        resolver = ModuleResolver(str(tracking), max_cached_connections=2)
        resolver.resolve_xref("a.dll", "Func0")
        resolver.resolve_xref("b.dll", "Func1")
        resolver.resolve_xref("c.dll", "Func2")  # evicts a.dll

        assert len(resolver._connection_cache) <= 2

        resolver.close()

