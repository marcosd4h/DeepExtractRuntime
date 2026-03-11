"""Lightweight filesystem cache for expensive skill-script results.

Stores JSON results under ``.agent/cache/{module}/{operation}.json``.
Validates freshness via DB file modification time and a configurable
``max_age_hours`` TTL.  All writes are atomic (write-to-temp then rename)
to avoid partial-read races.

Usage from skill scripts::

    from helpers.cache import get_cached, cache_result

    cached = get_cached(db_path, "triage_summary", params={"app_only": True})
    if cached is not None:
        return cached

    result = expensive_computation(...)
    cache_result(db_path, "triage_summary", result, params={"app_only": True})
    return result
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .config import get_config_value
from .db_paths import DB_NAME_RE as _DB_NAME_RE

_log = logging.getLogger(__name__)

_HELPERS_DIR = Path(__file__).resolve().parent
_AGENT_DIR = _HELPERS_DIR.parent
_CACHE_ROOT = _AGENT_DIR / "cache"


def _module_from_db_path(db_path: str) -> str:
    """Derive a human-friendly module name from a DB filename.

    ``appinfo_dll_f2bbf324a1.db`` -> ``appinfo_dll``
    Falls back to the full stem if the pattern doesn't match.
    """
    stem = Path(db_path).stem
    m = _DB_NAME_RE.match(Path(db_path).name)
    if m:
        return m.group(1)
    return stem


def _cache_key(operation: str, params: dict[str, Any] | None) -> str:
    """Build a filesystem-safe cache key from *operation* and *params*.

    Parameterized entries always hash a canonicalized representation of
    the params block so cache filenames stay filesystem-safe on Windows
    and stable across dict ordering.
    """
    if not params:
        return operation

    def _normalize(value: Any) -> Any:
        if isinstance(value, bool):
            return {"type": "bool", "value": value}
        if isinstance(value, int):
            return {"type": "int", "value": value}
        if isinstance(value, float):
            return {"type": "float", "value": value}
        if isinstance(value, str):
            return {"type": "str", "value": value}
        if isinstance(value, Path):
            return {"type": "path", "value": str(value)}
        if isinstance(value, dict):
            return {
                "type": "dict",
                "value": [[str(k), _normalize(v)] for k, v in sorted(value.items())],
            }
        if isinstance(value, (list, tuple)):
            return {
                "type": type(value).__name__,
                "value": [_normalize(v) for v in value],
            }
        if isinstance(value, set):
            return {
                "type": "set",
                "value": sorted((_normalize(v) for v in value), key=lambda item: json.dumps(item, sort_keys=True)),
            }
        return {"type": type(value).__name__, "value": str(value)}

    canonical_pairs: list[list[Any]] = []
    for k in sorted(params):
        v = params[k]
        if v is None:
            continue
        canonical_pairs.append([str(k), _normalize(v)])

    if not canonical_pairs:
        return operation

    canonical = json.dumps(
        canonical_pairs,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
    return f"{operation}__h_{digest}"


def _cache_path(module: str, key: str) -> Path:
    return _CACHE_ROOT / module / f"{key}.json"


def _db_mtime(db_path: str) -> float | None:
    """Return mtime of the DB file, or None if inaccessible."""
    try:
        return os.path.getmtime(db_path)
    except OSError:
        return None


def _db_mtime_ns(db_path: str) -> int | None:
    """Return nanosecond mtime of the DB file, or None if inaccessible."""
    try:
        return os.stat(db_path).st_mtime_ns
    except OSError:
        return None


def cache_result(
    db_path: str,
    operation: str,
    result: dict | list,
    params: dict[str, Any] | None = None,
) -> Path:
    """Persist *result* to the cache and return the written path.

    The cache entry includes metadata so ``get_cached`` can validate
    freshness without re-running the computation.
    """
    db_path = str(Path(db_path).resolve())
    module = _module_from_db_path(db_path)
    key = _cache_key(operation, params)
    path = _cache_path(module, key)
    path.parent.mkdir(parents=True, exist_ok=True)

    envelope = {
        "cached_at": datetime.now(timezone.utc).isoformat(),
        "db_path": db_path,
        "db_mtime": _db_mtime(db_path),
        "db_mtime_ns": _db_mtime_ns(db_path),
        "operation": operation,
        "params": params or {},
        "result": result,
    }

    fd, tmp = tempfile.mkstemp(
        dir=str(path.parent), suffix=".tmp", prefix=f".{key}_"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(envelope, f, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp, str(path))
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

    _evict_if_over_limit(path)
    return path


# In-memory estimate of total cache size (bytes).
# Updated incrementally on writes; full scan only when estimate exceeds limit.
_estimated_cache_size: int | None = None
_EVICTION_CHECK_INTERVAL = 10
_eviction_write_counter = 0
_eviction_lock = threading.Lock()


def _evict_if_over_limit(last_written: Path | None = None) -> int:
    """Remove oldest cache files when total size exceeds ``max_cache_size_mb``.

    Uses an in-memory size estimate to skip the expensive full directory
    scan on most writes.  A full scan is triggered only when the estimate
    suggests the limit may be exceeded, or every N writes as a consistency check.
    """
    global _estimated_cache_size, _eviction_write_counter

    max_mb = get_config_value("cache.max_cache_size_mb", 500)
    if max_mb <= 0:
        return 0
    max_bytes = max_mb * 1024 * 1024

    with _eviction_lock:
        # Incrementally update size estimate from the just-written file
        if last_written is not None and last_written.exists():
            try:
                new_size = last_written.stat().st_size
            except OSError:
                new_size = 0
            if _estimated_cache_size is not None:
                _estimated_cache_size += new_size

        _eviction_write_counter += 1

        # Skip full scan if estimate is well below the limit
        needs_full_scan = (
            _estimated_cache_size is None
            or _estimated_cache_size > max_bytes
            or _eviction_write_counter % _EVICTION_CHECK_INTERVAL == 0
        )
        if not needs_full_scan:
            return 0

    # Full scan runs outside the lock (only filesystem reads)
    if not _CACHE_ROOT.exists():
        with _eviction_lock:
            _estimated_cache_size = 0
        return 0

    entries: list[tuple[float, int, Path]] = []
    total_size = 0
    for mod_dir in _CACHE_ROOT.iterdir():
        if not mod_dir.is_dir():
            continue
        for f in mod_dir.iterdir():
            if f.is_file() and f.suffix == ".json":
                try:
                    st = f.stat()
                    entries.append((st.st_mtime, st.st_size, f))
                    total_size += st.st_size
                except OSError:
                    continue

    with _eviction_lock:
        _estimated_cache_size = total_size

    if total_size <= max_bytes:
        return 0

    entries.sort(key=lambda e: e[0])
    deleted = 0
    for mtime, size, path in entries:
        if total_size <= max_bytes:
            break
        try:
            path.unlink()
            total_size -= size
            deleted += 1
        except OSError:
            continue

    with _eviction_lock:
        _estimated_cache_size = None
    return deleted


def get_cached(
    db_path: str,
    operation: str,
    params: dict[str, Any] | None = None,
    max_age_hours: int | None = None,
) -> dict | list | None:
    """Return cached result if it is fresh enough, else ``None``.

    Freshness checks:
    1. Cache file must exist.
    2. The DB's current mtime must match the stored ``db_mtime``
       (catches re-extractions).
    3. The cache must be younger than *max_age_hours*.
    """
    if max_age_hours is None:
        max_age_hours = get_config_value("cache.max_age_hours", 24)
    db_path = str(Path(db_path).resolve())
    module = _module_from_db_path(db_path)
    key = _cache_key(operation, params)
    path = _cache_path(module, key)

    if not path.is_file():
        _log.debug("Cache miss (no file): %s/%s", module, key)
        return None

    try:
        with open(path, "r", encoding="utf-8") as f:
            envelope = json.load(f)
    except (OSError, json.JSONDecodeError, ValueError):
        return None

    stored_mtime_ns = envelope.get("db_mtime_ns")
    current_mtime_ns = _db_mtime_ns(db_path)
    if stored_mtime_ns is not None and current_mtime_ns is None:
        return None
    if stored_mtime_ns is not None and current_mtime_ns is not None:
        if stored_mtime_ns != current_mtime_ns:
            return None

    stored_mtime = envelope.get("db_mtime")
    current_mtime = _db_mtime(db_path)
    if stored_mtime_ns is None and stored_mtime is not None and current_mtime is None:
        return None
    if stored_mtime_ns is None and stored_mtime is not None and current_mtime is not None:
        if stored_mtime != current_mtime:
            return None

    cached_at = envelope.get("cached_at")
    if cached_at and max_age_hours > 0:
        try:
            ts = datetime.fromisoformat(cached_at)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            age_hours = (datetime.now(timezone.utc) - ts).total_seconds() / 3600
            if age_hours > max_age_hours:
                return None
        except (ValueError, TypeError):
            return None

    _log.debug("Cache hit: %s/%s", module, key)
    return envelope.get("result")


def clear_cache(module: str | None = None, operation: str | None = None) -> int:
    """Remove cached files.  Returns number of files deleted.

    If *module* and *operation* are given, that cache file and any
    parameterized variants (e.g. ``operation__param_value.json``) are
    removed.  If only *module* is given, the entire module's cache
    directory is cleared.  If both are ``None``, the entire cache tree
    is removed.
    """
    global _estimated_cache_size

    if not _CACHE_ROOT.exists():
        return 0

    deleted = 0
    if module and operation:
        mod_dir = _CACHE_ROOT / module
        if mod_dir.is_dir():
            for f in mod_dir.iterdir():
                if not f.is_file() or f.suffix != ".json":
                    continue
                if f.stem == operation or f.stem.startswith(f"{operation}__"):
                    try:
                        f.unlink()
                        deleted += 1
                    except OSError:
                        pass
        if deleted:
            _estimated_cache_size = None
        return deleted

    if module:
        mod_dir = _CACHE_ROOT / module
        if mod_dir.is_dir():
            for f in mod_dir.iterdir():
                if f.is_file():
                    try:
                        f.unlink()
                        deleted += 1
                    except OSError:
                        pass
            try:
                mod_dir.rmdir()
            except OSError:
                pass
    else:
        for mod_dir in _CACHE_ROOT.iterdir():
            if mod_dir.is_dir():
                for f in mod_dir.iterdir():
                    if f.is_file():
                        try:
                            f.unlink()
                            deleted += 1
                        except OSError:
                            pass
                try:
                    mod_dir.rmdir()
                except OSError:
                    pass
    if deleted:
        _estimated_cache_size = None
    return deleted


def clear_cache_for_db(db_path: str, operation: str | None = None) -> int:
    """Clear cache for a specific DB, resolving the module name automatically.

    If *operation* is given, only that operation's cache entry is removed.
    Otherwise the entire module's cache directory is cleared.
    """
    module = _module_from_db_path(db_path)
    return clear_cache(module=module, operation=operation)


def cache_stats(module: str | None = None) -> dict[str, Any]:
    """Return metrics about the current state of the cache.

    Parameters
    ----------
    module:
        If given, return stats for that single module only.
        At scale (5000+ modules) this avoids scanning all cache directories.
    """
    stats: dict[str, Any] = {
        "total_files": 0,
        "total_size_bytes": 0,
        "modules": {},
        "oldest_mtime": None,
        "newest_mtime": None,
    }
    if not _CACHE_ROOT.exists():
        return stats

    if module:
        dirs = [_CACHE_ROOT / module]
    else:
        all_dirs = [d for d in _CACHE_ROOT.iterdir() if d.is_dir()]
        sample_limit = int(get_config_value("scale.cache_stats_sample_limit", 200))
        if sample_limit > 0 and len(all_dirs) > sample_limit:
            import random
            dirs = random.sample(all_dirs, sample_limit)
            stats["sampled"] = True
            stats["sample_size"] = sample_limit
            stats["total_modules"] = len(all_dirs)
        else:
            dirs = all_dirs

    for mod_dir in dirs:
        if not mod_dir.is_dir():
            continue
        mod_name = mod_dir.name
        mod_stats = {"file_count": 0, "size_bytes": 0}
        for f in mod_dir.iterdir():
            if f.is_file() and f.suffix == ".json":
                try:
                    st = f.stat()
                except OSError:
                    continue
                mod_stats["file_count"] += 1
                mod_stats["size_bytes"] += st.st_size
                stats["total_files"] += 1
                stats["total_size_bytes"] += st.st_size

                mtime = st.st_mtime
                if stats["oldest_mtime"] is None or mtime < stats["oldest_mtime"]:
                    stats["oldest_mtime"] = mtime
                if stats["newest_mtime"] is None or mtime > stats["newest_mtime"]:
                    stats["newest_mtime"] = mtime
        stats["modules"][mod_name] = mod_stats
    return stats


def evict_stale(max_age_hours: int | None = None) -> dict[str, int]:
    """Remove expired cache entries from disk.

    Uses file mtime as a proxy for creation time (the atomic-write in
    ``cache_result`` sets mtime at write time) to avoid reading and
    parsing every cache file.

    Returns ``{"evicted": N, "kept": M}``.
    """
    global _estimated_cache_size

    if max_age_hours is None:
        max_age_hours = get_config_value("cache.max_age_hours", 24)

    if not _CACHE_ROOT.exists():
        return {"evicted": 0, "kept": 0}

    evicted = 0
    kept = 0
    max_age_seconds = max_age_hours * 3600
    now = time.time()

    for mod_dir in _CACHE_ROOT.iterdir():
        if not mod_dir.is_dir():
            continue
        for cache_file in list(mod_dir.iterdir()):
            if not cache_file.is_file() or cache_file.suffix != ".json":
                continue
            try:
                age_seconds = now - cache_file.stat().st_mtime
                if max_age_seconds > 0 and age_seconds > max_age_seconds:
                    cache_file.unlink()
                    evicted += 1
                else:
                    kept += 1
            except OSError:
                try:
                    cache_file.unlink(missing_ok=True)
                except OSError:
                    pass
                evicted += 1

        if not any(mod_dir.iterdir()):
            try:
                mod_dir.rmdir()
            except OSError:
                pass

    if evicted:
        _estimated_cache_size = None
    _log.debug("Cache eviction: evicted=%d, kept=%d", evicted, kept)
    return {"evicted": evicted, "kept": kept}
