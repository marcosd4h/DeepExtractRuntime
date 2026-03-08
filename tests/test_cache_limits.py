"""Tests for cache behavior: clearing, multiple entries, and mtime invalidation.

Covers edge cases around cache size, freshness checking, and cleanup.

Targets:
  helpers/cache.py  (get_cached, cache_result, clear_cache, _cache_key)
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from helpers.cache import (
    _cache_key,
    _cache_path,
    _module_from_db_path,
    cache_result,
    clear_cache,
    clear_cache_for_db,
    get_cached,
)
import helpers.cache as cache_mod


# ===================================================================
# Cache key generation edge cases
# ===================================================================

class TestCacheKeyEdgeCases:
    def test_none_params_returns_operation(self):
        assert _cache_key("triage_summary", None) == "triage_summary"

    def test_empty_params_returns_operation(self):
        assert _cache_key("triage_summary", {}) == "triage_summary"

    def test_none_values_skipped(self):
        key = _cache_key("op", {"a": None, "b": 1})
        assert key == _cache_key("op", {"b": 1})

    def test_bool_params(self):
        key = _cache_key("op", {"app_only": True})
        assert key.startswith("op__h_")

    def test_double_underscore_triggers_hash(self):
        key = _cache_key("op", {"path": "a__b"})
        assert "__h_" in key

    def test_different_params_different_keys(self):
        k1 = _cache_key("op", {"a": 1})
        k2 = _cache_key("op", {"a": 2})
        assert k1 != k2

    def test_param_order_irrelevant(self):
        k1 = _cache_key("op", {"a": 1, "b": 2})
        k2 = _cache_key("op", {"b": 2, "a": 1})
        assert k1 == k2

    @pytest.mark.parametrize("value", [
        "Namespace::Method",
        "folder/name",
        r"folder\name",
        "query?<bad>*",
    ])
    def test_windows_unsafe_strings_are_hashed(self, value):
        key = _cache_key("op", {"term": value})
        assert key.startswith("op__h_")
        assert all(char not in key for char in ':\\/<>?*')


# ===================================================================
# Cache round-trip with multiple entries
# ===================================================================

class TestCacheMultipleEntries:
    def test_multiple_operations_same_db(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cache_mod, "_CACHE_ROOT", tmp_path)
        db_path = str(tmp_path / "test_abc123.db")
        Path(db_path).touch()

        cache_result(db_path, "op_a", {"result": "a"})
        cache_result(db_path, "op_b", {"result": "b"})
        cache_result(db_path, "op_c", {"result": "c"})

        assert get_cached(db_path, "op_a")["result"] == "a"
        assert get_cached(db_path, "op_b")["result"] == "b"
        assert get_cached(db_path, "op_c")["result"] == "c"

    def test_different_params_same_operation(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cache_mod, "_CACHE_ROOT", tmp_path)
        db_path = str(tmp_path / "test_abc123.db")
        Path(db_path).touch()

        cache_result(db_path, "triage", {"top": 5}, params={"top": 5})
        cache_result(db_path, "triage", {"top": 10}, params={"top": 10})

        r1 = get_cached(db_path, "triage", params={"top": 5})
        r2 = get_cached(db_path, "triage", params={"top": 10})
        assert r1["top"] == 5
        assert r2["top"] == 10


# ===================================================================
# Cache clear behavior
# ===================================================================

class TestCacheClear:
    def test_clear_module_cache(self, tmp_path, monkeypatch):
        """clear_cache(module_name) removes all cache entries for that module."""
        monkeypatch.setattr(cache_mod, "_CACHE_ROOT", tmp_path)
        db_path = str(tmp_path / "mod_abc12345678.db")
        Path(db_path).touch()

        cache_result(db_path, "op_a", {"a": 1})
        cache_result(db_path, "op_b", {"b": 2})

        module_name = _module_from_db_path(db_path)
        clear_cache(module_name)
        assert get_cached(db_path, "op_a") is None
        assert get_cached(db_path, "op_b") is None

    def test_clear_all_cache(self, tmp_path, monkeypatch):
        """clear_cache(None) removes all cache entries."""
        monkeypatch.setattr(cache_mod, "_CACHE_ROOT", tmp_path)
        db_path = str(tmp_path / "mod_abc12345678.db")
        Path(db_path).touch()

        cache_result(db_path, "op_a", {"a": 1})
        clear_cache()
        assert get_cached(db_path, "op_a") is None

    def test_clear_nonexistent_is_safe(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cache_mod, "_CACHE_ROOT", tmp_path)
        clear_cache("nonexistent_module")
        clear_cache()

    def test_clear_operation_removes_hashed_variants(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cache_mod, "_CACHE_ROOT", tmp_path)
        db_path = str(tmp_path / "mod_abc12345678.db")
        Path(db_path).touch()

        cache_result(db_path, "triage", {"base": True})
        cache_result(db_path, "triage", {"top": 5}, params={"top": 5})
        cache_result(db_path, "triage", {"query": "Namespace::Method"}, params={"query": "Namespace::Method"})
        cache_result(db_path, "search", {"keep": True})

        deleted = clear_cache(_module_from_db_path(db_path), "triage")

        assert deleted == 3
        assert get_cached(db_path, "triage") is None
        assert get_cached(db_path, "triage", params={"top": 5}) is None
        assert get_cached(db_path, "triage", params={"query": "Namespace::Method"}) is None
        assert get_cached(db_path, "search") == {"keep": True}

    def test_clear_cache_for_db_preserves_other_modules(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cache_mod, "_CACHE_ROOT", tmp_path)
        db_path = str(tmp_path / "mod_abc12345678.db")
        other_db = str(tmp_path / "peer_def12345678.db")
        Path(db_path).touch()
        Path(other_db).touch()

        cache_result(db_path, "op", {"mine": True})
        cache_result(other_db, "op", {"theirs": True})

        deleted = clear_cache_for_db(db_path, "op")

        assert deleted == 1
        assert get_cached(db_path, "op") is None
        assert get_cached(other_db, "op") == {"theirs": True}


# ===================================================================
# Cache mtime invalidation
# ===================================================================

class TestCacheMtimeInvalidation:
    def test_stale_after_db_modification(self, tmp_path, monkeypatch):
        """Cache is invalidated when the DB file mtime changes by >1 second."""
        monkeypatch.setattr(cache_mod, "_CACHE_ROOT", tmp_path)
        db_path = tmp_path / "mod_abc12345678.db"
        db_path.touch()

        cache_result(str(db_path), "op", {"data": "original"})
        assert get_cached(str(db_path), "op") is not None

        # The mtime tolerance is 1.0 second, so we shift mtime forward by 5s
        current_mtime = os.path.getmtime(str(db_path))
        os.utime(str(db_path), (current_mtime + 5, current_mtime + 5))

        result = get_cached(str(db_path), "op")
        assert result is None

    def test_fresh_when_db_unchanged(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cache_mod, "_CACHE_ROOT", tmp_path)
        db_path = tmp_path / "mod_abc12345678.db"
        db_path.touch()

        cache_result(str(db_path), "op", {"data": "cached"})
        result = get_cached(str(db_path), "op")
        assert result is not None
        assert result["data"] == "cached"

    def test_miss_when_db_missing(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cache_mod, "_CACHE_ROOT", tmp_path)
        db_path = tmp_path / "mod_abc12345678.db"
        db_path.touch()

        cache_result(str(db_path), "op", {"data": "cached"})
        db_path.unlink()

        assert get_cached(str(db_path), "op") is None


# ===================================================================
# Module name extraction
# ===================================================================

class TestModuleExtraction:
    def test_standard_db_name(self):
        assert _module_from_db_path("appinfo_dll_f2bbf324a1.db") == "appinfo_dll"

    def test_six_char_hash(self):
        assert _module_from_db_path("cmd_exe_6d109a.db") == "cmd_exe"

    def test_no_hash(self):
        result = _module_from_db_path("plain.db")
        assert result == "plain"

    def test_full_path(self):
        result = _module_from_db_path("/path/to/appinfo_dll_abc123.db")
        assert result == "appinfo_dll"

    def test_short_hash_no_match(self):
        """Hashes shorter than 6 chars don't match the pattern."""
        result = _module_from_db_path("mod_ab12.db")
        assert result == "mod_ab12"
