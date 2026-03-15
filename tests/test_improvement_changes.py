"""Tests for the 10 improvement changes.

Covers:
  1. inject-module-context scanner deduplication (wrapper functions)
  2. config.py _mutable parameter (no deepcopy on hot path)
  3. classify_function weights loaded from config
  4. read_hook_input consolidated in session_utils
  5. evict_stale mtime-based eviction
  6. skill_common adoption (import sanity)
  7. ModuleResolver no __del__ (context manager works)
  8. _scanners.py / _profile_formatter.py __all__ exports
  9. unified_search.py absolute imports in --all branch
  10. cleanup_workspace dry_run skips cache eviction
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import os
import sys
import time
from io import StringIO
from pathlib import Path
from unittest import mock

import pytest

AGENT_DIR = Path(__file__).resolve().parent.parent
HOOKS_DIR = AGENT_DIR / "hooks"

# Load the inject-module-context hook as a module
_HOOK_PATH = HOOKS_DIR / "inject-module-context.py"
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))

_hook_spec = importlib.util.spec_from_file_location("inject_context_test", _HOOK_PATH)
_inject_mod = importlib.util.module_from_spec(_hook_spec)
_hook_spec.loader.exec_module(_inject_mod)


# ===================================================================
# 1. inject-module-context uses _scanners (wrapper functions work)
# ===================================================================

class TestHookScannerWrappers:
    """Verify thin wrappers that bind workspace arguments exist and delegate."""

    def test_count_modules_fast_wrapper_exists(self):
        assert callable(getattr(_inject_mod, "_count_modules_fast", None))

    def test_scan_modules_from_tracking_db_wrapper_exists(self):
        assert callable(getattr(_inject_mod, "_scan_modules_from_tracking_db", None))

    def test_load_module_list_sidecar_wrapper_exists(self):
        assert callable(getattr(_inject_mod, "_load_module_list_sidecar", None))

    def test_save_module_list_sidecar_wrapper_exists(self):
        assert callable(getattr(_inject_mod, "_save_module_list_sidecar", None))

    def test_no_local_scan_modules_redef(self):
        """The hook should NOT redefine scan_modules locally -- it imports from _scanners."""
        source = _HOOK_PATH.read_text(encoding="utf-8")
        # Local def would be 'def _scan_modules(' or 'def scan_modules(' at function level
        import re
        local_defs = re.findall(r"^def (?:_scan_modules|_scan_dbs|_scan_skills|_format_profile_line)\(", source, re.MULTILINE)
        assert local_defs == [], f"Found local re-definitions that should have been removed: {local_defs}"

    def test_sidecar_round_trip(self, tmp_path):
        """Wrapper functions correctly save and load sidecar data."""
        tracking_db = tmp_path / "analyzed_files.db"
        tracking_db.write_text("")
        sidecar = tmp_path / "cache" / "_module_list.json"
        modules = [{"name": "mod_0", "status": "COMPLETE"}]

        orig = _inject_mod._MODULE_LIST_SIDECAR
        try:
            _inject_mod._MODULE_LIST_SIDECAR = sidecar
            _inject_mod._save_module_list_sidecar(modules, tracking_db)
            assert sidecar.exists()

            loaded = _inject_mod._load_module_list_sidecar(tracking_db)
            assert loaded is not None
            assert loaded[0]["name"] == "mod_0"
        finally:
            _inject_mod._MODULE_LIST_SIDECAR = orig


# ===================================================================
# 2. config.py _mutable parameter
# ===================================================================

class TestConfigMutable:
    def test_default_returns_independent_copy(self):
        """load_config() returns independent copies to prevent cache corruption."""
        from helpers.config import load_config
        c1 = load_config()
        c2 = load_config()
        assert c1 is not c2, "load_config() should return independent copies"
        assert c1 == c2, "copies should have equal content"

    def test_mutable_returns_independent_copy(self):
        """With _mutable=True, returns a deep copy that is safe to mutate."""
        from helpers.config import load_config
        c1 = load_config(_mutable=True)
        c2 = load_config(_mutable=True)
        assert c1 is not c2, "_mutable=True should return independent copies"
        assert c1 == c2, "copies should have equal content"

    def test_mutable_copy_does_not_affect_cache(self):
        """Mutating a _mutable copy must not affect the cached config."""
        from helpers.config import load_config
        mutable = load_config(_mutable=True)
        mutable["classification"]["weights"]["W_API"] = 999.0

        cached = load_config()
        assert cached["classification"]["weights"]["W_API"] != 999.0

    def test_get_config_value_uses_cached(self):
        """get_config_value should not deep-copy (uses the fast path)."""
        from helpers.config import get_config_value, load_config
        cached = load_config()
        val = get_config_value("classification.weights.W_API")
        assert val == cached["classification"]["weights"]["W_API"]


# ===================================================================
# 3. Classification weights loaded from config
# ===================================================================

class TestClassificationWeightsFromConfig:
    def test_weights_match_config_defaults(self):
        """Classification weights should match config/defaults.json values."""
        from helpers.config import get_config_value
        from helpers.script_runner import load_skill_module
        classify_mod = load_skill_module("classify-functions", "_common")

        config_weights = get_config_value("classification.weights", {})
        assert classify_mod.W_API == config_weights.get("W_API", 5.0)

    def test_weights_are_positive(self):
        from helpers.script_runner import load_skill_module
        classify_mod = load_skill_module("classify-functions", "_common")
        for attr in ("W_API", "W_API_CAP", "W_STRUCTURAL", "W_LIBRARY"):
            val = getattr(classify_mod, attr)
            assert isinstance(val, (int, float)) and val > 0, f"{attr} should be positive, got {val}"


# ===================================================================
# 4. read_hook_input consolidated in session_utils
# ===================================================================

class TestReadHookInput:
    def test_valid_json(self):
        from helpers.session_utils import read_hook_input
        with mock.patch("sys.stdin", StringIO('{"session_id": "abc"}')):
            result = read_hook_input()
        assert result == {"session_id": "abc"}

    def test_empty_stdin(self):
        from helpers.session_utils import read_hook_input
        with mock.patch("sys.stdin", StringIO("")):
            result = read_hook_input()
        assert result == {}

    def test_whitespace_only(self):
        from helpers.session_utils import read_hook_input
        with mock.patch("sys.stdin", StringIO("   \n  ")):
            result = read_hook_input()
        assert result == {}

    def test_malformed_json(self):
        from helpers.session_utils import read_hook_input
        with mock.patch("sys.stdin", StringIO("{bad json")):
            result = read_hook_input()
        assert result == {}

    def test_hook_delegates_to_shared(self):
        """Both hooks' _read_hook_input should delegate to session_utils.read_hook_input."""
        grind_path = HOOKS_DIR / "grind-until-done.py"
        grind_source = grind_path.read_text(encoding="utf-8")
        # Verify the delegation pattern exists in source
        assert "return read_hook_input()" in grind_source, (
            "grind-until-done.py _read_hook_input should delegate to read_hook_input()"
        )

        hook_source = _HOOK_PATH.read_text(encoding="utf-8")
        assert "return read_hook_input()" in hook_source, (
            "inject-module-context.py _read_hook_input should delegate to read_hook_input()"
        )


# ===================================================================
# 5. evict_stale mtime-based eviction
# ===================================================================

class TestEvictStaleMtime:
    def test_evicts_old_files_by_mtime(self, tmp_path):
        from helpers.cache import evict_stale, _CACHE_ROOT
        mod_dir = tmp_path / "test_module"
        mod_dir.mkdir()
        old_file = mod_dir / "old_op.json"
        old_file.write_text(json.dumps({"cached_at": "2020-01-01T00:00:00Z", "result": {}}))
        # Set mtime to 48 hours ago
        old_time = time.time() - (48 * 3600)
        os.utime(old_file, (old_time, old_time))

        new_file = mod_dir / "new_op.json"
        new_file.write_text(json.dumps({"cached_at": "2099-01-01T00:00:00Z", "result": {}}))

        orig_root = evict_stale.__module__
        import helpers.cache as cache_mod
        orig = cache_mod._CACHE_ROOT
        try:
            cache_mod._CACHE_ROOT = tmp_path
            result = evict_stale(max_age_hours=24)
            assert result["evicted"] == 1
            assert result["kept"] == 1
            assert not old_file.exists()
            assert new_file.exists()
        finally:
            cache_mod._CACHE_ROOT = orig

    def test_evict_stale_zero_hour_keeps_all(self, tmp_path):
        """max_age_hours=0 means no expiration — all files are kept."""
        import helpers.cache as cache_mod
        mod_dir = tmp_path / "mod"
        mod_dir.mkdir()
        f = mod_dir / "op.json"
        f.write_text("{}")

        orig = cache_mod._CACHE_ROOT
        try:
            cache_mod._CACHE_ROOT = tmp_path
            result = evict_stale(max_age_hours=0)
            assert result["evicted"] == 0
            assert result["kept"] == 1
            assert f.exists()
        finally:
            cache_mod._CACHE_ROOT = orig

    def test_evict_stale_removes_empty_dirs(self, tmp_path):
        import helpers.cache as cache_mod
        mod_dir = tmp_path / "empty_mod"
        mod_dir.mkdir()
        f = mod_dir / "stale.json"
        f.write_text("{}")
        old_time = time.time() - (48 * 3600)
        os.utime(f, (old_time, old_time))

        orig = cache_mod._CACHE_ROOT
        try:
            cache_mod._CACHE_ROOT = tmp_path
            evict_stale(max_age_hours=24)
            assert not mod_dir.exists(), "Empty module dir should be removed"
        finally:
            cache_mod._CACHE_ROOT = orig

    def test_no_cache_dir_returns_zeros(self):
        import helpers.cache as cache_mod
        orig = cache_mod._CACHE_ROOT
        try:
            cache_mod._CACHE_ROOT = Path("/nonexistent/path/cache")
            result = evict_stale(max_age_hours=24)
            assert result == {"evicted": 0, "kept": 0}
        finally:
            cache_mod._CACHE_ROOT = orig


from helpers.cache import evict_stale


# ===================================================================
# 5b. _evict_if_over_limit size-based cache eviction
# ===================================================================

class TestEvictIfOverLimit:
    def test_evicts_oldest_files_when_over_limit(self, tmp_path):
        import helpers.cache as cache_mod
        from helpers.cache import _evict_if_over_limit

        mod_dir = tmp_path / "mod_a"
        mod_dir.mkdir()
        old_file = mod_dir / "old.json"
        old_file.write_text("x" * 600)
        old_time = time.time() - 3600
        os.utime(old_file, (old_time, old_time))

        new_file = mod_dir / "new.json"
        new_file.write_text("y" * 600)

        orig_root = cache_mod._CACHE_ROOT
        orig_est = cache_mod._estimated_cache_size
        orig_counter = cache_mod._eviction_write_counter
        try:
            cache_mod._CACHE_ROOT = tmp_path
            cache_mod._estimated_cache_size = None
            cache_mod._eviction_write_counter = 0

            with mock.patch("helpers.cache.get_config_value", return_value=0.001):
                deleted = _evict_if_over_limit(last_written=new_file)

            assert deleted >= 1
            assert not old_file.exists(), "Oldest file should be evicted first"
        finally:
            cache_mod._CACHE_ROOT = orig_root
            cache_mod._estimated_cache_size = orig_est
            cache_mod._eviction_write_counter = orig_counter

    def test_no_eviction_when_under_limit(self, tmp_path):
        import helpers.cache as cache_mod
        from helpers.cache import _evict_if_over_limit

        mod_dir = tmp_path / "mod_b"
        mod_dir.mkdir()
        small_file = mod_dir / "small.json"
        small_file.write_text("{}")

        orig_root = cache_mod._CACHE_ROOT
        orig_est = cache_mod._estimated_cache_size
        orig_counter = cache_mod._eviction_write_counter
        try:
            cache_mod._CACHE_ROOT = tmp_path
            cache_mod._estimated_cache_size = None
            cache_mod._eviction_write_counter = 0

            deleted = _evict_if_over_limit(last_written=small_file)
            assert deleted == 0
            assert small_file.exists()
        finally:
            cache_mod._CACHE_ROOT = orig_root
            cache_mod._estimated_cache_size = orig_est
            cache_mod._eviction_write_counter = orig_counter

    def test_disabled_when_max_mb_zero(self, tmp_path):
        import helpers.cache as cache_mod
        from helpers.cache import _evict_if_over_limit

        mod_dir = tmp_path / "mod_c"
        mod_dir.mkdir()
        f = mod_dir / "data.json"
        f.write_text("x" * 10000)

        orig_root = cache_mod._CACHE_ROOT
        orig_est = cache_mod._estimated_cache_size
        try:
            cache_mod._CACHE_ROOT = tmp_path
            cache_mod._estimated_cache_size = None

            with mock.patch("helpers.cache.get_config_value", return_value=0):
                deleted = _evict_if_over_limit(last_written=f)
            assert deleted == 0
            assert f.exists()
        finally:
            cache_mod._CACHE_ROOT = orig_root
            cache_mod._estimated_cache_size = orig_est


# ===================================================================
# 6. cleanup_workspace dry_run skips cache eviction
# ===================================================================

class TestDryRunSkipsCacheEviction:
    def test_dry_run_does_not_call_evict_stale(self, tmp_path):
        ws = tmp_path / "workspace"
        ws.mkdir()
        (ws / ".agent" / "workspace").mkdir(parents=True)

        with mock.patch("helpers.cache.evict_stale") as m:
            from helpers.cleanup_workspace import cleanup_workspace
            result = cleanup_workspace(older_than_days=7, dry_run=True, workspace_root=ws)

        m.assert_not_called()
        assert result["cache_evicted"] == 0

    def test_non_dry_run_calls_evict_stale(self, tmp_path):
        ws = tmp_path / "workspace"
        ws.mkdir()
        (ws / ".agent" / "workspace").mkdir(parents=True)

        with mock.patch("helpers.cache.evict_stale", return_value={"evicted": 5, "kept": 10}) as m:
            from helpers.cleanup_workspace import cleanup_workspace
            result = cleanup_workspace(older_than_days=7, dry_run=False, workspace_root=ws)

        m.assert_called_once()
        assert result["cache_evicted"] == 5


# ===================================================================
# 7. ModuleResolver no __del__ (context manager works)
# ===================================================================

class TestModuleResolverNoDel:
    def test_no_del_method(self):
        from helpers.cross_module_graph import ModuleResolver
        assert not hasattr(ModuleResolver, "__del__"), (
            "ModuleResolver should not have __del__; use context manager instead"
        )

    def test_context_manager_closes(self):
        from helpers.cross_module_graph import ModuleResolver
        resolver = ModuleResolver()
        with resolver:
            assert not resolver._closed
        assert resolver._closed

    def test_close_idempotent(self):
        from helpers.cross_module_graph import ModuleResolver
        resolver = ModuleResolver()
        resolver.close()
        resolver.close()  # should not raise
        assert resolver._closed


# ===================================================================
# 8. _scanners __all__ matches public functions
# ===================================================================

class TestScannersExports:
    def test_scanners_all_completeness(self):
        spec = importlib.util.spec_from_file_location(
            "scanners_check", HOOKS_DIR / "_scanners.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        declared = set(mod.__all__)
        actual_callables = {
            name for name in dir(mod)
            if callable(getattr(mod, name))
            and not name.startswith("_")
            and not isinstance(getattr(mod, name), type)  # skip type imports like Path
        }
        # Filter out imported types/modules (not actual public API)
        from types import ModuleType
        actual_callables = {
            name for name in actual_callables
            if not isinstance(getattr(mod, name), ModuleType)
        }
        missing = actual_callables - declared
        assert not missing, f"Public functions missing from __all__: {missing}"

    def test_profile_formatter_all(self):
        spec = importlib.util.spec_from_file_location(
            "formatter_check", HOOKS_DIR / "_profile_formatter.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        assert hasattr(mod, "__all__")
        assert "format_profile_line" in mod.__all__


# ===================================================================
# 9. unified_search.py absolute imports in --all branch
# ===================================================================

class TestUnifiedSearchImports:
    def test_no_relative_imports_in_all_branch(self):
        """The --all code path should use absolute imports, not relative."""
        source = (AGENT_DIR / "helpers" / "unified_search.py").read_text(encoding="utf-8")
        # Check that from .errors and from .config do NOT appear in the file
        import re
        relative_errors = re.findall(r"from \.errors import", source)
        relative_config = re.findall(r"from \.config import", source)
        assert not relative_errors, "Found relative import 'from .errors' -- should be 'from helpers.errors'"
        assert not relative_config, "Found relative import 'from .config' -- should be 'from helpers.config'"

    def test_absolute_imports_present(self):
        source = (AGENT_DIR / "helpers" / "unified_search.py").read_text(encoding="utf-8")
        assert "from helpers.errors import" in source
        assert "from helpers.config import" in source


# ===================================================================
# 10. skill_common adoption (import sanity)
# ===================================================================

class TestSkillCommonAdoption:
    def test_skill_common_provides_standard_exports(self):
        """skill_common.py should export the standard helpers."""
        from skills._shared.skill_common import (
            emit_error,
            emit_json,
            parse_json_safe,
            open_individual_analysis_db,
            resolve_function,
            get_cached,
            cache_result,
            db_error_handler,
            status_message,
        )
        for fn in (emit_error, emit_json, parse_json_safe, open_individual_analysis_db,
                   resolve_function, get_cached, cache_result, db_error_handler, status_message):
            assert callable(fn)

    def test_security_dossier_imports_from_skill_common(self):
        """security-dossier _common.py should use skill_common for standard helpers."""
        source = (AGENT_DIR / "skills" / "security-dossier" / "scripts" / "_common.py").read_text()
        assert "from skills._shared.skill_common import" in source

    def test_exploitability_imports_from_skill_common(self):
        source = (AGENT_DIR / "skills" / "exploitability-assessment" / "scripts" / "_common.py").read_text()
        assert "from skills._shared.skill_common import" in source
