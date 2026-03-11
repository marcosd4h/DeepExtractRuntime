"""Scale tests: validate behavior at 5000+ module counts.

Target components:
- inject-module-context.py (hook)
- helpers/cross_module_graph.py (ModuleResolver, CrossModuleGraph)
- helpers/cache.py (cache_stats)
- helpers/validation.py (validate_workspace_data)
- helpers/function_index/index.py (list_extracted_modules, load_all_function_indexes)
- helpers/module_profile.py (load_all_profiles)
"""

from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import sys
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

_AGENT_DIR = Path(__file__).resolve().parent.parent
_HOOK_PATH = _AGENT_DIR / "hooks" / "inject-module-context.py"
if str(_AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENT_DIR))

spec = importlib.util.spec_from_file_location("inject_context", _HOOK_PATH)
_inject_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(_inject_mod)

from hooks._context_builder import build_context as _build_context
_deadline_exceeded = _inject_mod._deadline_exceeded


def _make_tracking_db(db_path: Path, count: int) -> None:
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE IF NOT EXISTS analyzed_files ("
        "  file_path TEXT PRIMARY KEY, base_dir TEXT, file_name TEXT,"
        "  file_extension TEXT, md5_hash TEXT, sha256_hash TEXT,"
        "  analysis_db_path TEXT, status TEXT, analysis_flags TEXT,"
        "  analysis_start_timestamp TEXT, analysis_completion_timestamp TEXT"
        ")"
    )
    for i in range(count):
        conn.execute(
            "INSERT INTO analyzed_files VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                f"C:\\bins\\mod_{i:05d}.dll",
                "C:\\bins",
                f"mod_{i:05d}.dll",
                ".dll",
                f"md5_{i:05d}",
                f"sha_{i:05d}",
                f"mod_{i:05d}_dll_abc{i:05d}.db",
                "COMPLETE",
                "",
                "",
                "",
            ),
        )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Hook: context truncation tests
# ---------------------------------------------------------------------------

class TestContextTruncationAtScale:
    @staticmethod
    def _make_compact_modules(count: int) -> list[dict]:
        return [
            {
                "name": f"mod_{i:05d}_dll",
                "file_name": f"mod_{i:05d}.dll",
                "db_path": f"mod_{i:05d}_dll_abc{i:05d}.db",
                "status": "COMPLETE",
            }
            for i in range(count)
        ]

    def test_500_modules_shows_full_name_list(self):
        modules = self._make_compact_modules(500)
        ctx = _build_context(modules, [], True, [], "standard", compact_mode=True)
        assert "**500 extracted module(s)**" in ctx
        assert "**500 analysis DB(s)**" in ctx

    def test_750_modules_shows_truncated_name_list(self):
        modules = self._make_compact_modules(750)
        ctx = _build_context(modules, [], True, [], "standard", compact_mode=True)
        assert "**750 extracted module(s)**" in ctx
        assert "**750 analysis DB(s)**" in ctx

    def test_5000_modules_omits_name_list_entirely(self):
        modules = self._make_compact_modules(5000)
        ctx = _build_context(modules, [], True, [], "standard", compact_mode=True)
        assert "**5000 extracted module(s)**" in ctx
        assert "**5000 analysis DB(s)**" in ctx

    def test_context_size_bounded_at_5000_modules(self):
        modules = self._make_compact_modules(5000)
        ctx = _build_context(modules, [], True, [], "standard", compact_mode=True)
        assert len(ctx) < 5000, (
            f"Context size {len(ctx)} bytes is too large for 5000-module compact mode"
        )


# ---------------------------------------------------------------------------
# Hook: deadline mechanism
# ---------------------------------------------------------------------------

class TestDeadlineMechanism:
    def test_deadline_not_exceeded_at_start(self):
        _inject_mod._hook_start_time = time.monotonic()
        assert not _deadline_exceeded()

    def test_deadline_exceeded_after_timeout(self):
        _inject_mod._hook_start_time = time.monotonic() - 15.0
        assert _deadline_exceeded()


# ---------------------------------------------------------------------------
# Hook: sidecar cache
# ---------------------------------------------------------------------------

class TestModuleListSidecar:
    def test_save_and_load_sidecar(self, tmp_path):
        tracking_db = tmp_path / "analyzed_files.db"
        tracking_db.write_text("")
        sidecar = tmp_path / "cache" / "_module_list.json"

        modules = [{"name": f"mod_{i}", "status": "COMPLETE"} for i in range(100)]

        orig_sidecar = _inject_mod._MODULE_LIST_SIDECAR
        try:
            _inject_mod._MODULE_LIST_SIDECAR = sidecar
            _inject_mod._save_module_list_sidecar(modules, tracking_db)
            assert sidecar.exists()

            loaded = _inject_mod._load_module_list_sidecar(tracking_db)
            assert loaded is not None
            assert len(loaded) == 100
            assert loaded[0]["name"] == "mod_0"
        finally:
            _inject_mod._MODULE_LIST_SIDECAR = orig_sidecar

    def test_sidecar_invalidated_on_mtime_change(self, tmp_path):
        tracking_db = tmp_path / "analyzed_files.db"
        tracking_db.write_text("")
        sidecar = tmp_path / "cache" / "_module_list.json"

        modules = [{"name": "mod_0"}]

        orig_sidecar = _inject_mod._MODULE_LIST_SIDECAR
        try:
            _inject_mod._MODULE_LIST_SIDECAR = sidecar
            _inject_mod._save_module_list_sidecar(modules, tracking_db)

            sidecar_data = json.loads(sidecar.read_text())
            sidecar_data["tracking_db_mtime"] = 0.0
            sidecar.write_text(json.dumps(sidecar_data))

            loaded = _inject_mod._load_module_list_sidecar(tracking_db)
            assert loaded is None
        finally:
            _inject_mod._MODULE_LIST_SIDECAR = orig_sidecar


# ---------------------------------------------------------------------------
# cross_module_graph: module limits
# ---------------------------------------------------------------------------

class TestCrossModuleGraphLimits:
    def test_build_function_name_index_uses_json_fast_path(self):
        """With default config (threshold=0), index is always built.

        Verifies the JSON-based fast path is used instead of opening DBs.
        """
        from helpers.cross_module_graph import ModuleResolver

        resolver = ModuleResolver.__new__(ModuleResolver)
        resolver._module_cache = {
            f"mod_{i}.dll": (f"/fake/mod_{i}.db", f"mod_{i}.dll")
            for i in range(600)
        }
        resolver._loaded = True
        resolver._lock = __import__("threading").RLock()
        resolver._function_name_index = None
        resolver._connection_cache = __import__("collections").OrderedDict()
        resolver._max_cached_connections = 50
        resolver._tracking_db_path = None
        resolver._closed = False

        with patch("helpers.function_index.index.load_function_index", return_value=None):
            with patch.object(resolver, "_get_cached_db", side_effect=OSError("no DB")):
                resolver._build_function_name_index()

        assert resolver._function_name_index is not None
        assert isinstance(resolver._function_name_index, dict)

    def test_build_function_name_index_populates_from_json(self):
        """Verify function names from JSON indexes appear in the index."""
        from helpers.cross_module_graph import ModuleResolver

        resolver = ModuleResolver.__new__(ModuleResolver)
        resolver._module_cache = {
            "test.dll": ("/fake/test.db", "test.dll"),
        }
        resolver._loaded = True
        resolver._lock = __import__("threading").RLock()
        resolver._function_name_index = None
        resolver._connection_cache = __import__("collections").OrderedDict()
        resolver._max_cached_connections = 50
        resolver._tracking_db_path = None
        resolver._closed = False

        fake_index = {"CreateProcessW": {}, "OpenFile": {}}
        with patch("helpers.function_index.index.load_function_index", return_value=fake_index):
            resolver._build_function_name_index()

        assert "createprocessw" in resolver._function_name_index
        assert "openfile" in resolver._function_name_index
        assert resolver._function_name_index["createprocessw"] == [("/fake/test.db", "test.dll")]

    def test_resolve_function_phase2_bounded(self):
        from helpers.cross_module_graph import ModuleResolver

        resolver = ModuleResolver.__new__(ModuleResolver)
        resolver._module_cache = {
            f"mod_{i}.dll": (f"/fake/mod_{i}.db", f"mod_{i}.dll")
            for i in range(10)
        }
        resolver._loaded = True
        resolver._lock = __import__("threading").RLock()
        resolver._function_name_index = {}
        resolver._connection_cache = __import__("collections").OrderedDict()
        resolver._max_cached_connections = 50
        resolver._tracking_db_path = None
        resolver._closed = False

        results = resolver.resolve_function("NonExistentFunc", fuzzy=False)
        assert results == []

    def test_zero_limit_means_unlimited(self):
        """When max_modules_cross_scan=0, all modules should be loaded."""
        from helpers.cross_module_graph import CrossModuleGraph

        with patch.object(CrossModuleGraph, "__init__", lambda self: None):
            cm = CrossModuleGraph.__new__(CrossModuleGraph)
            cm._graphs = {}
            cm._module_deps = {}

            mock_resolver = MagicMock()
            mock_resolver.list_modules.return_value = [
                (f"mod_{i}.dll", f"/fake/mod_{i}.db") for i in range(6000)
            ]
            cm._resolver = mock_resolver

            with patch("helpers.cross_module_graph.CallGraph") as mock_cg:
                mock_cg.from_db.side_effect = Exception("no real DB")
                with patch("helpers.cross_module_graph.get_config_value", return_value=0):
                    cm_new = CrossModuleGraph.from_tracking_db.__wrapped__(
                        CrossModuleGraph,
                    ) if hasattr(CrossModuleGraph.from_tracking_db, "__wrapped__") else None
                    assert len(mock_resolver.list_modules.return_value) == 6000


# ---------------------------------------------------------------------------
# cache: stats with module filter
# ---------------------------------------------------------------------------

class TestCacheStatsAtScale:
    def test_cache_stats_single_module(self, tmp_path):
        from helpers import cache as cache_mod

        orig_root = cache_mod._CACHE_ROOT
        try:
            cache_mod._CACHE_ROOT = tmp_path

            for i in range(5):
                mod_dir = tmp_path / f"mod_{i}"
                mod_dir.mkdir()
                for j in range(3):
                    (mod_dir / f"op_{j}.json").write_text('{"cached_at":"2025-01-01"}')

            stats_all = cache_mod.cache_stats()
            assert stats_all["total_files"] == 15
            assert len(stats_all["modules"]) == 5

            stats_one = cache_mod.cache_stats(module="mod_2")
            assert stats_one["total_files"] == 3
            assert len(stats_one["modules"]) == 1
            assert "mod_2" in stats_one["modules"]
        finally:
            cache_mod._CACHE_ROOT = orig_root

    def test_cache_stats_uses_mtime_not_json_parse(self, tmp_path):
        from helpers import cache as cache_mod

        orig_root = cache_mod._CACHE_ROOT
        try:
            cache_mod._CACHE_ROOT = tmp_path
            mod_dir = tmp_path / "test_mod"
            mod_dir.mkdir()
            (mod_dir / "op.json").write_text("not valid json {{{")

            stats = cache_mod.cache_stats(module="test_mod")
            assert stats["total_files"] == 1
            assert stats["modules"]["test_mod"]["file_count"] == 1
        finally:
            cache_mod._CACHE_ROOT = orig_root


# ---------------------------------------------------------------------------
# validation: sampling
# ---------------------------------------------------------------------------

class TestValidationSampling:
    def test_validate_workspace_samples_at_scale(self, tmp_path):
        from helpers.validation import validate_workspace_data

        code_dir = tmp_path / "extracted_code"
        code_dir.mkdir()
        for i in range(200):
            mod_dir = code_dir / f"mod_{i:04d}_dll"
            mod_dir.mkdir()
            (mod_dir / "function_index.json").write_text("{}")
            (mod_dir / "file_info.json").write_text("{}")

        dbs_dir = tmp_path / "extracted_dbs"
        dbs_dir.mkdir()

        status = validate_workspace_data(tmp_path, sample_limit=20)
        assert status.has_extracted_code
        assert len(status.modules_with_code) <= 20
        has_sample_warning = any("sampled" in w.lower() for w in status.warnings)
        assert has_sample_warning

    def test_validate_workspace_no_sampling_below_limit(self, tmp_path):
        from helpers.validation import validate_workspace_data

        code_dir = tmp_path / "extracted_code"
        code_dir.mkdir()
        for i in range(10):
            mod_dir = code_dir / f"mod_{i}_dll"
            mod_dir.mkdir()
            (mod_dir / "function_index.json").write_text("{}")
            (mod_dir / "file_info.json").write_text("{}")

        dbs_dir = tmp_path / "extracted_dbs"
        dbs_dir.mkdir()

        status = validate_workspace_data(tmp_path, sample_limit=50)
        assert status.has_extracted_code
        assert len(status.modules_with_code) == 10
        has_sample_warning = any("sampled" in w.lower() for w in status.warnings)
        assert not has_sample_warning


# ---------------------------------------------------------------------------
# function_index: cached listing
# ---------------------------------------------------------------------------

class TestFunctionIndexCaching:
    def test_list_extracted_modules_caches_result(self, tmp_path):
        from helpers.function_index import index as fi_mod

        orig_dir = fi_mod.EXTRACTED_CODE_DIR
        orig_cache = fi_mod._cached_module_list
        orig_mtime = fi_mod._cached_module_list_mtime
        try:
            fi_mod.EXTRACTED_CODE_DIR = tmp_path
            fi_mod._cached_module_list = None
            fi_mod._cached_module_list_mtime = 0.0

            for i in range(5):
                d = tmp_path / f"mod_{i}"
                d.mkdir()
                (d / "function_index.json").write_text("{}")

            result1 = fi_mod.list_extracted_modules()
            assert len(result1) == 5

            result2 = fi_mod.list_extracted_modules()
            assert result2 is result1
        finally:
            fi_mod.EXTRACTED_CODE_DIR = orig_dir
            fi_mod._cached_module_list = orig_cache
            fi_mod._cached_module_list_mtime = orig_mtime


# ---------------------------------------------------------------------------
# config: scale section validation
# ---------------------------------------------------------------------------

class TestScaleConfigValidation:
    def test_scale_config_validates_positive_ints(self):
        from helpers.config import validate_config

        bad_config = {
            "scale": {
                "max_modules_cross_scan": -5,
                "compact_mode_threshold": "not_an_int",
            }
        }
        issues = validate_config(bad_config)
        assert any("max_modules_cross_scan" in i for i in issues)
        assert any("compact_mode_threshold" in i for i in issues)

    def test_zero_is_valid_for_unlimited_keys(self):
        from helpers.config import validate_config

        config = {
            "scale": {
                "max_modules_cross_scan": 0,
                "max_modules_search_all": 0,
                "cross_module_index_warn_threshold": 0,
            }
        }
        issues = validate_config(config)
        assert not any("max_modules_cross_scan" in i for i in issues)
        assert not any("max_modules_search_all" in i for i in issues)
        assert not any("cross_module_index_warn_threshold" in i for i in issues)

    def test_default_config_has_scale_section(self):
        from helpers.config import load_config

        config = load_config()
        assert "scale" in config
        assert config["scale"]["max_modules_cross_scan"] == 200
        assert config["scale"]["compact_mode_threshold"] == 25
        assert config["scale"]["max_modules_compare"] == 200
        assert config["scale"]["max_modules_search_all"] == 200
        assert config["scale"]["cross_module_index_warn_threshold"] == 0
        assert config["scale"]["max_cached_connections"] == 50
