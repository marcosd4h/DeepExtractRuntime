"""Centralized configuration loader for DeepExtractIDA agents."""

from __future__ import annotations

import copy
import json
import logging
import os
from pathlib import Path
from typing import Any, Optional


_CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
_DEFAULTS_PATH = _CONFIG_DIR / "defaults.json"

_log = logging.getLogger(__name__)

# Process-level config cache: avoids re-reading defaults.json on every call.
# Invalidated when the file's mtime changes.
_cached_config: dict[str, Any] | None = None
_cached_mtime: float | None = None


def _defaults_mtime() -> float | None:
    """Return mtime of defaults.json, or None if inaccessible."""
    try:
        return _DEFAULTS_PATH.stat().st_mtime
    except OSError:
        return None


def _apply_env_overrides(config: dict[str, Any]) -> None:
    """Mutate *config* in-place with DEEPEXTRACT_* environment overrides.

    Supports two formats:

    1. **Double-underscore delimiter** (preferred, unambiguous)::

           DEEPEXTRACT_SCRIPT_RUNNER__MAX_RETRIES=3
           -> config["script_runner"]["max_retries"] = 3

    2. **Single-underscore greedy match** (legacy fallback): tries
       progressively longer section prefixes until a matching section
       is found in the base config.  For ``DEEPEXTRACT_SCRIPT_RUNNER_MAX_RETRIES``
       it tries ``script`` then ``script_runner`` and uses the first hit.

    Only overrides keys within sections that already exist in the
    base config.

    **Limitation:** only one level of nesting is supported.  Deeply nested
    keys like ``classification.weights.W_NAME`` cannot be overridden via
    environment variables because the underscore delimiter is ambiguous.
    Use ``defaults.json`` for those values.
    """
    for env_key, env_val in os.environ.items():
        if not env_key.startswith("DEEPEXTRACT_"):
            continue
        suffix = env_key[12:].lower()
        if not suffix:
            continue

        section: str | None = None
        key: str | None = None

        if "__" in suffix:
            idx = suffix.index("__")
            section = suffix[:idx]
            key = suffix[idx + 2:]
        else:
            parts = suffix.split("_")
            if len(parts) < 2:
                continue
            candidates: list[tuple[str, str]] = []
            for i in range(1, len(parts)):
                candidate_section = "_".join(parts[:i])
                candidate_key = "_".join(parts[i:])
                if candidate_section in config:
                    candidates.append((candidate_section, candidate_key))
            if not candidates:
                continue
            if len(candidates) > 1:
                _log.warning(
                    "Ambiguous env override %s: matches sections %s. "
                    "Use double-underscore format (e.g. DEEPEXTRACT_%s__%s) "
                    "for unambiguous override.",
                    env_key,
                    [c[0] for c in candidates],
                    candidates[0][0].upper(),
                    candidates[0][1].upper(),
                )
            section, key = candidates[0]

        if section is None or not key or section not in config:
            continue

        try:
            config[section][key] = json.loads(env_val)
        except json.JSONDecodeError:
            config[section][key] = env_val


def load_config(*, _mutable: bool = False) -> dict[str, Any]:
    """Load configuration from defaults.json and apply environment overrides.

    Results are cached per-process and invalidated when the file's mtime
    changes, so hot-path callers like ``get_config_value()`` avoid
    redundant disk I/O.

    Environment overrides are re-applied on every call so that changes
    to ``DEEPEXTRACT_*`` env vars take effect without restarting.

    The returned dict is always an independent copy -- callers may
    mutate it freely without corrupting the shared cache.
    """
    global _cached_config, _cached_mtime

    current_mtime = _defaults_mtime()
    if _cached_config is None or current_mtime != _cached_mtime:
        config: dict[str, Any] = {}
        if _DEFAULTS_PATH.exists():
            try:
                with open(_DEFAULTS_PATH, "r", encoding="utf-8") as f:
                    config = json.load(f)
            except (json.JSONDecodeError, OSError) as exc:
                _log.warning(
                    "Failed to parse %s: %s -- using empty config", _DEFAULTS_PATH, exc
                )

        _cached_config = config
        _cached_mtime = current_mtime

    result = copy.deepcopy(_cached_config)
    _apply_env_overrides(result)
    return result


def invalidate_config_cache() -> None:
    """Force the next ``load_config()`` call to re-read from disk.

    Useful in tests or after programmatic config changes.
    """
    global _cached_config, _cached_mtime
    _cached_config = None
    _cached_mtime = None


def get_config_value(path: str, default: Any = None) -> Any:
    """Get a configuration value by dot-separated path (e.g. 'triage.max_workers')."""
    config = load_config()
    parts = path.split(".")
    val = config
    for p in parts:
        if isinstance(val, dict) and p in val:
            val = val[p]
        else:
            return default
    return val


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------

def _resolve(config: dict, dotpath: str) -> Any:
    """Resolve a dot-separated path into *config*, returning ``None`` on miss."""
    val: Any = config
    for part in dotpath.split("."):
        if isinstance(val, dict) and part in val:
            val = val[part]
        else:
            return None
    return val


def validate_config(config: dict[str, Any] | None = None) -> list[str]:
    """Validate configuration values and return a list of issue descriptions.

    Returns an empty list when the configuration is valid.  Does not raise
    exceptions so callers can decide how to handle problems.

    If *config* is ``None`` the current live config is loaded automatically.
    """
    if config is None:
        config = load_config(_mutable=True)

    issues: list[str] = []

    # --- classification.weights.* must be positive floats ---
    weights = _resolve(config, "classification.weights")
    if isinstance(weights, dict):
        for wname, wval in weights.items():
            if not isinstance(wval, (int, float)):
                issues.append(
                    f"classification.weights.{wname}: expected positive number, "
                    f"got {type(wval).__name__} ({wval!r})"
                )
            elif wval <= 0:
                issues.append(
                    f"classification.weights.{wname}: must be positive, got {wval}"
                )
    elif weights is not None:
        issues.append(
            f"classification.weights: expected dict, got {type(weights).__name__}"
        )

    # --- triage section ---
    _check_positive_int(config, "triage.com_density_threshold", issues)
    _check_float_range(config, "triage.com_density_ratio", 0.0, 1.0, issues)
    _check_positive_int(config, "triage.rpc_density_threshold", issues)
    _check_positive_int(config, "triage.security_density_threshold", issues)
    _check_positive_int(config, "triage.max_workers", issues, max_val=16)

    # --- triage.step_timeout_seconds (optional, new) ---
    step_timeout = _resolve(config, "triage.step_timeout_seconds")
    if step_timeout is not None:
        if not isinstance(step_timeout, (int, float)) or step_timeout <= 0:
            issues.append(
                f"triage.step_timeout_seconds: must be a positive number, "
                f"got {step_timeout!r}"
            )

    # --- triage.per_function_timeout_seconds (optional, new) ---
    per_func = _resolve(config, "triage.per_function_timeout_seconds")
    if per_func is not None:
        if not isinstance(per_func, (int, float)) or per_func <= 0:
            issues.append(
                f"triage.per_function_timeout_seconds: must be a positive number, "
                f"got {per_func!r}"
            )

    # --- security_auditor ---
    sa_timeout = _resolve(config, "security_auditor.step_timeout_seconds")
    if sa_timeout is not None:
        if not isinstance(sa_timeout, (int, float)) or sa_timeout <= 0:
            issues.append(
                f"security_auditor.step_timeout_seconds: must be a positive number, "
                f"got {sa_timeout!r}"
            )
    sa_per_func = _resolve(config, "security_auditor.per_function_timeout_seconds")
    if sa_per_func is not None:
        if not isinstance(sa_per_func, (int, float)) or sa_per_func <= 0:
            issues.append(
                f"security_auditor.per_function_timeout_seconds: must be a positive number, "
                f"got {sa_per_func!r}"
            )

    # --- pipeline ---
    pipeline_timeout = _resolve(config, "pipeline.default_step_timeout")
    if pipeline_timeout is not None:
        if not isinstance(pipeline_timeout, (int, float)) or isinstance(pipeline_timeout, bool):
            issues.append(
                "pipeline.default_step_timeout: expected positive number, "
                f"got {type(pipeline_timeout).__name__} ({pipeline_timeout!r})"
            )
        elif pipeline_timeout <= 0:
            issues.append(
                f"pipeline.default_step_timeout: must be positive, got {pipeline_timeout}"
            )

    _check_positive_int(config, "pipeline.max_workers", issues, max_val=16)
    _check_positive_int(config, "pipeline.max_module_workers", issues, max_val=16)

    continue_on_error = _resolve(config, "pipeline.continue_on_error")
    if continue_on_error is not None and not isinstance(continue_on_error, bool):
        issues.append(
            "pipeline.continue_on_error: expected bool, "
            f"got {type(continue_on_error).__name__} ({continue_on_error!r})"
        )

    parallel_modules = _resolve(config, "pipeline.parallel_modules")
    if parallel_modules is not None:
        if isinstance(parallel_modules, bool):
            pass
        elif isinstance(parallel_modules, int):
            if parallel_modules <= 0:
                issues.append(
                    "pipeline.parallel_modules: int value must be positive, "
                    f"got {parallel_modules}"
                )
        else:
            issues.append(
                "pipeline.parallel_modules: expected bool or positive int, "
                f"got {type(parallel_modules).__name__} ({parallel_modules!r})"
            )

    no_cache = _resolve(config, "pipeline.no_cache")
    if no_cache is not None and not isinstance(no_cache, bool):
        issues.append(
            "pipeline.no_cache: expected bool, "
            f"got {type(no_cache).__name__} ({no_cache!r})"
        )

    # --- verifier ---
    _check_float_range(config, "verifier.call_count_tolerance", 0.0, 1.0, issues)
    _check_float_range(config, "verifier.branch_count_tolerance", 0.0, 1.0, issues)
    _check_positive_int(config, "verifier.max_alignment", issues, max_val=64)

    # --- script_runner ---
    _check_positive_int(config, "script_runner.default_timeout_seconds", issues)
    _check_positive_int(config, "script_runner.max_retries", issues, max_val=5)

    # --- explain ---
    _check_positive_int(config, "explain.max_callee_depth", issues, max_val=10)
    _check_positive_int(config, "explain.max_callees_per_level", issues, max_val=50)

    # --- cache ---
    _check_non_negative_int(config, "cache.max_age_hours", issues)
    cache_size = _resolve(config, "cache.max_cache_size_mb")
    if cache_size is not None:
        if not isinstance(cache_size, (int, float)) or isinstance(cache_size, bool):
            issues.append(
                f"cache.max_cache_size_mb: expected positive number, "
                f"got {type(cache_size).__name__} ({cache_size!r})"
            )
        elif cache_size <= 0:
            issues.append(f"cache.max_cache_size_mb: must be positive, got {cache_size}")

    # --- ui ---
    show = _resolve(config, "ui.show_progress")
    if show is not None and not isinstance(show, bool):
        issues.append(
            f"ui.show_progress: expected bool, got {type(show).__name__} ({show!r})"
        )

    # --- scale ---
    for scale_key in (
        "compact_mode_threshold",
        "context_truncation_threshold",
        "max_modules_compare",
        "cache_stats_sample_limit",
        "health_sample_count",
        "max_cached_connections",
    ):
        _check_positive_int(config, f"scale.{scale_key}", issues)

    # These keys use 0 to mean "unlimited"
    for scale_key in (
        "max_modules_cross_scan",
        "max_modules_search_all",
        "cross_module_index_warn_threshold",
    ):
        _check_non_negative_int(config, f"scale.{scale_key}", issues)

    # --- dangerous_apis ---
    da_path = _resolve(config, "dangerous_apis.json_path")
    if da_path is not None:
        if not isinstance(da_path, str) or not da_path.strip():
            issues.append(
                f"dangerous_apis.json_path: expected non-empty string, "
                f"got {type(da_path).__name__} ({da_path!r})"
            )
    da_auto = _resolve(config, "dangerous_apis.auto_classify")
    if da_auto is not None and not isinstance(da_auto, bool):
        issues.append(
            f"dangerous_apis.auto_classify: expected bool, "
            f"got {type(da_auto).__name__} ({da_auto!r})"
        )

    return issues


def _check_positive_int(
    config: dict,
    dotpath: str,
    issues: list[str],
    *,
    max_val: int | None = None,
) -> None:
    val = _resolve(config, dotpath)
    if val is None:
        return
    if not isinstance(val, int) or isinstance(val, bool):
        issues.append(f"{dotpath}: expected positive int, got {type(val).__name__} ({val!r})")
        return
    if val <= 0:
        issues.append(f"{dotpath}: must be positive, got {val}")
    elif max_val is not None and val > max_val:
        issues.append(f"{dotpath}: must be <= {max_val}, got {val}")


def _check_non_negative_int(
    config: dict,
    dotpath: str,
    issues: list[str],
) -> None:
    """Like ``_check_positive_int`` but allows 0 (used for 'unlimited' semantics)."""
    val = _resolve(config, dotpath)
    if val is None:
        return
    if not isinstance(val, int) or isinstance(val, bool):
        issues.append(f"{dotpath}: expected non-negative int, got {type(val).__name__} ({val!r})")
        return
    if val < 0:
        issues.append(f"{dotpath}: must be >= 0 (0 means unlimited), got {val}")


def _check_float_range(
    config: dict,
    dotpath: str,
    lo: float,
    hi: float,
    issues: list[str],
) -> None:
    val = _resolve(config, dotpath)
    if val is None:
        return
    if not isinstance(val, (int, float)) or isinstance(val, bool):
        issues.append(f"{dotpath}: expected float in [{lo}, {hi}], got {type(val).__name__} ({val!r})")
        return
    if val < lo or val > hi:
        issues.append(f"{dotpath}: must be in [{lo}, {hi}], got {val}")


def get_config_validated() -> dict[str, Any]:
    """Load config, validate it, log warnings for any issues, and return it.

    Always returns the config dict even when issues exist, so callers
    can still use fallback/default behavior.
    """
    config = load_config(_mutable=True)
    issues = validate_config(config)
    for issue in issues:
        _log.warning("Config issue: %s", issue)
    return config
