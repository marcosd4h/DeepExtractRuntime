"""Tests for the filesystem cache module.

Target: helpers/cache.py
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from helpers.cache import (
    _cache_key,
    _cache_path,
    _db_mtime,
    _module_from_db_path,
    cache_result,
    clear_cache,
    clear_cache_for_db,
    get_cached,
)
import helpers.cache as cache_mod


# ===================================================================
# _module_from_db_path
# ===================================================================

class TestModuleFromDbPath:
    def test_standard_pattern(self):
        assert _module_from_db_path("appinfo_dll_f2bbf324a1.db") == "appinfo_dll"

    def test_long_hash(self):
        assert _module_from_db_path("cmd_exe_6d109a3a00.db") == "cmd_exe"

    def test_no_hash_fallback(self):
        assert _module_from_db_path("simple.db") == "simple"

    def test_full_path(self):
        assert _module_from_db_path("/some/path/appinfo_dll_abc123.db") == "appinfo_dll"

    def test_windows_path(self):
        assert _module_from_db_path("C:\\dbs\\coredpus_dll_319f60b0a5.db") == "coredpus_dll"


# ===================================================================
# _cache_key
# ===================================================================

class TestCacheKey:
    def test_no_params(self):
        assert _cache_key("triage_summary", None) == "triage_summary"

    def test_empty_params(self):
        assert _cache_key("triage_summary", {}) == "triage_summary"

    def test_bool_param(self):
        key = _cache_key("triage_summary", {"app_only": True})
        assert key.startswith("triage_summary__h_")

    def test_int_param(self):
        key = _cache_key("classify", {"min_interest": 5})
        assert key.startswith("classify__h_")

    def test_multiple_params_sorted(self):
        key = _cache_key("op", {"z_param": 1, "a_param": 2})
        assert key.startswith("op__h_")

    def test_none_values_skipped(self):
        key = _cache_key("op", {"keep": True, "skip": None})
        assert key == _cache_key("op", {"keep": True})

    def test_all_none_values(self):
        key = _cache_key("op", {"a": None, "b": None})
        assert key == "op"

    def test_double_underscore_separator(self):
        """Parameterized entries use a hash suffix."""
        key = _cache_key("triage", {"app_only": True, "min": 5})
        assert key.startswith("triage__h_")

    def test_no_collision_previously_ambiguous(self):
        """{"a": "1_b"} vs {"a": 1, "b": True} must produce different keys."""
        key1 = _cache_key("op", {"a": "1_b"})
        key2 = _cache_key("op", {"a": 1, "b": True})
        assert key1 != key2

    def test_no_collision_underscore_in_value(self):
        """Values with underscores don't collide with separate params."""
        key1 = _cache_key("op", {"x": "a_b"})
        key2 = _cache_key("op", {"x": "a", "b": True})
        assert key1 != key2

    def test_int_vs_string_different_keys(self):
        key1 = _cache_key("op", {"v": 5})
        key2 = _cache_key("op", {"v": "5"})
        assert key1 != key2

    def test_hash_fallback_double_underscore_in_value(self):
        """Values containing __ still produce a stable hash-based key."""
        key = _cache_key("op", {"a": "x__y"})
        assert "__h_" in key
        assert key.startswith("op__h_")

    def test_hash_fallback_is_deterministic(self):
        """Same params always produce the same hash key."""
        key1 = _cache_key("op", {"a": "x__y"})
        key2 = _cache_key("op", {"a": "x__y"})
        assert key1 == key2

    def test_hash_fallback_different_values_differ(self):
        """Different values with __ produce different hash keys."""
        key1 = _cache_key("op", {"a": "x__y"})
        key2 = _cache_key("op", {"a": "x__z"})
        assert key1 != key2

    def test_bool_branch_distinct_from_int(self):
        """Bool and int values should not collide in the canonical hash."""
        key_bool = _cache_key("op", {"flag": True})
        key_int = _cache_key("op", {"flag": 1})
        assert key_bool != key_int

    def test_backward_compat_no_params(self):
        assert _cache_key("triage_summary", None) == "triage_summary"

    @pytest.mark.parametrize("value", [
        "Namespace::Method",
        "id:42",
        "C:/Windows/System32/test.dll",
        r"C:\Windows\System32\test.dll",
        "search?term=<bad>*",
    ])
    def test_windows_unsafe_values_are_hashed(self, value):
        key = _cache_key("op", {"query": value})
        assert key.startswith("op__h_")
        assert ":" not in key
        assert "\\" not in key
        assert "/" not in key
        assert "?" not in key
        assert "<" not in key
        assert ">" not in key
        assert "*" not in key


# ===================================================================
# cache_result + get_cached round trip
# ===================================================================

class TestCacheRoundTrip:
    @pytest.fixture(autouse=True)
    def _patch_cache_root(self, tmp_path, monkeypatch):
        """Redirect cache to tmp_path so tests don't touch real cache."""
        monkeypatch.setattr(cache_mod, "_CACHE_ROOT", tmp_path / "cache")
        self.cache_root = tmp_path / "cache"
        # Create a fake DB file for mtime checks
        self.fake_db = tmp_path / "test_module_abc123.db"
        self.fake_db.write_text("fake")

    def test_store_and_retrieve(self):
        data = {"count": 42, "items": [1, 2, 3]}
        cache_result(str(self.fake_db), "test_op", data)
        result = get_cached(str(self.fake_db), "test_op")
        assert result == data

    def test_store_with_params(self):
        data = {"filtered": True}
        cache_result(str(self.fake_db), "test_op", data, params={"app_only": True})
        result = get_cached(str(self.fake_db), "test_op", params={"app_only": True})
        assert result == data

    def test_different_params_miss(self):
        data = {"ok": True}
        cache_result(str(self.fake_db), "test_op", data, params={"a": 1})
        result = get_cached(str(self.fake_db), "test_op", params={"a": 2})
        assert result is None

    def test_returns_path(self):
        p = cache_result(str(self.fake_db), "test_op", {"x": 1})
        assert isinstance(p, Path)
        assert p.exists()

    def test_creates_parent_directories(self):
        cache_result(str(self.fake_db), "deep_op", {"x": 1})
        assert self.cache_root.exists()


# ===================================================================
# get_cached -- freshness / invalidation
# ===================================================================

class TestGetCachedFreshness:
    @pytest.fixture(autouse=True)
    def _patch(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cache_mod, "_CACHE_ROOT", tmp_path / "cache")
        self.cache_root = tmp_path / "cache"
        self.fake_db = tmp_path / "test_module_abc123.db"
        self.fake_db.write_text("fake")

    def test_missing_file_returns_none(self):
        assert get_cached(str(self.fake_db), "no_such_op") is None

    def test_corrupted_json_returns_none(self):
        module = _module_from_db_path(str(self.fake_db))
        key = _cache_key("corrupt_op", None)
        path = self.cache_root / module / f"{key}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("NOT VALID JSON {{{")
        assert get_cached(str(self.fake_db), "corrupt_op") is None

    def test_ttl_expired(self, monkeypatch):
        cache_result(str(self.fake_db), "ttl_test", {"val": 1})
        # Patch datetime to simulate 48 hours later
        real_now = datetime.now
        monkeypatch.setattr(
            "helpers.cache.datetime",
            type("FakeDT", (), {
                "now": staticmethod(lambda tz=None: datetime.now(tz) + timedelta(hours=48)),
                "fromisoformat": datetime.fromisoformat,
            })
        )
        result = get_cached(str(self.fake_db), "ttl_test", max_age_hours=24)
        assert result is None

    def test_db_mtime_changed(self):
        cache_result(str(self.fake_db), "mtime_test", {"v": 1})
        # Modify the DB file so its mtime changes significantly
        time.sleep(0.1)
        new_mtime = os.path.getmtime(str(self.fake_db)) + 100
        os.utime(str(self.fake_db), (new_mtime, new_mtime))
        result = get_cached(str(self.fake_db), "mtime_test")
        assert result is None

    def test_subsecond_db_mtime_change_invalidates_cache(self):
        cache_result(str(self.fake_db), "mtime_subsecond_test", {"v": 1})
        stat = os.stat(str(self.fake_db))
        new_mtime_ns = stat.st_mtime_ns + 200_000_000  # +0.2s
        os.utime(
            str(self.fake_db),
            ns=(stat.st_atime_ns, new_mtime_ns),
        )
        result = get_cached(str(self.fake_db), "mtime_subsecond_test")
        assert result is None

    def test_db_mtime_unchanged_returns_data(self):
        data = {"stable": True}
        cache_result(str(self.fake_db), "stable_test", data)
        result = get_cached(str(self.fake_db), "stable_test")
        assert result == data

    def test_deleted_db_returns_cache_miss(self):
        cache_result(str(self.fake_db), "missing_db_test", {"v": 1})
        self.fake_db.unlink()
        assert get_cached(str(self.fake_db), "missing_db_test") is None

    def test_renamed_db_returns_cache_miss(self):
        cache_result(str(self.fake_db), "renamed_db_test", {"v": 1})
        renamed = self.fake_db.with_name("renamed_module_abc123.db")
        self.fake_db.rename(renamed)
        assert get_cached(str(self.fake_db), "renamed_db_test") is None

    def test_unreadable_db_metadata_returns_cache_miss(self, monkeypatch):
        cache_result(str(self.fake_db), "unreadable_db_test", {"v": 1})
        monkeypatch.setattr("helpers.cache._db_mtime", lambda _: None)
        monkeypatch.setattr("helpers.cache._db_mtime_ns", lambda _: None)
        assert get_cached(str(self.fake_db), "unreadable_db_test") is None


# ===================================================================
# clear_cache
# ===================================================================

class TestClearCache:
    @pytest.fixture(autouse=True)
    def _patch(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cache_mod, "_CACHE_ROOT", tmp_path / "cache")
        self.cache_root = tmp_path / "cache"
        self.fake_db = tmp_path / "test_module_abc123.db"
        self.fake_db.write_text("fake")

    def test_clear_specific_module(self):
        cache_result(str(self.fake_db), "op1", {"a": 1})
        cache_result(str(self.fake_db), "op2", {"b": 2})
        deleted = clear_cache("test_module")
        assert deleted == 2
        assert get_cached(str(self.fake_db), "op1") is None

    def test_clear_all(self):
        cache_result(str(self.fake_db), "op1", {"a": 1})
        deleted = clear_cache(None)
        assert deleted >= 1

    def test_clear_nonexistent_module(self):
        deleted = clear_cache("no_such_module")
        assert deleted == 0

    def test_clear_empty_cache(self):
        deleted = clear_cache(None)
        assert deleted == 0

    def test_clear_specific_operation_removes_parameterized_variants_only(self):
        cache_result(str(self.fake_db), "triage", {"variant": "base"})
        cache_result(str(self.fake_db), "triage", {"variant": "top5"}, params={"top": 5})
        cache_result(str(self.fake_db), "triage", {"variant": "top10"}, params={"top": 10})
        cache_result(str(self.fake_db), "other", {"variant": "keep"})

        deleted = clear_cache("test_module", "triage")

        assert deleted == 3
        assert get_cached(str(self.fake_db), "triage") is None
        assert get_cached(str(self.fake_db), "triage", params={"top": 5}) is None
        assert get_cached(str(self.fake_db), "triage", params={"top": 10}) is None
        assert get_cached(str(self.fake_db), "other") == {"variant": "keep"}

    def test_clear_cache_for_db_targets_only_matching_operation(self):
        other_db = self.fake_db.with_name("other_module_abc123.db")
        other_db.write_text("fake")

        cache_result(str(self.fake_db), "triage", {"module": "first"})
        cache_result(str(self.fake_db), "triage", {"module": "first-top"}, params={"top": 5})
        cache_result(str(self.fake_db), "search", {"module": "first-keep"})
        cache_result(str(other_db), "triage", {"module": "second-keep"})

        deleted = clear_cache_for_db(str(self.fake_db), "triage")

        assert deleted == 2
        assert get_cached(str(self.fake_db), "triage") is None
        assert get_cached(str(self.fake_db), "triage", params={"top": 5}) is None
        assert get_cached(str(self.fake_db), "search") == {"module": "first-keep"}
        assert get_cached(str(other_db), "triage") == {"module": "second-keep"}


# ===================================================================
# _db_mtime
# ===================================================================

class TestDbMtime:
    def test_existing_file(self, tmp_path):
        f = tmp_path / "test.db"
        f.write_text("data")
        assert _db_mtime(str(f)) is not None

    def test_nonexistent_file(self):
        assert _db_mtime("/nonexistent/path.db") is None
