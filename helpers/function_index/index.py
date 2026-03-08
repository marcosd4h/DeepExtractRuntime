"""Core utilities for querying function_index.json files.

Provides module discovery, function index loading, library-tag filtering,
file grouping, and statistics for DeepExtractIDA extraction outputs.
"""

from __future__ import annotations

import json
import re
import threading
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Optional

from ..config import get_config_value
from ..db_paths import DB_NAME_RE as _DB_NAME_RE
from ..errors import log_warning


_MODULE_DIR = Path(__file__).resolve().parent
_HELPERS_DIR = _MODULE_DIR.parent
_RUNTIME_ROOT = _HELPERS_DIR.parent
WORKSPACE_ROOT = (
    _RUNTIME_ROOT.parent if _RUNTIME_ROOT.name == ".agent" else _RUNTIME_ROOT
)

EXTRACTED_CODE_DIR = WORKSPACE_ROOT / "extracted_code"
FUNCTION_INDEX_FILENAME = "function_index.json"

# Library tags as defined in the function_index format reference
LIBRARY_TAGS = frozenset({"WIL", "STL", "WRL", "CRT", "ETW/TraceLogging"})

_cached_module_list: list[str] | None = None
_cached_module_list_mtime: float = 0.0
_cached_module_list_fingerprint: tuple[tuple[str, int | None], ...] | None = None
_cached_function_indexes: dict[str, tuple[int, dict[str, dict[str, Any]]]] = {}
_cached_function_indexes_lock = threading.Lock()


def _scan_module_discovery_state() -> tuple[list[str], tuple[tuple[str, int | None], ...]]:
    """Return discovered modules and a fingerprint for cache invalidation."""
    from helpers.module_discovery import iter_module_dirs

    discovered = iter_module_dirs(EXTRACTED_CODE_DIR, require_function_index=True)

    modules = [mod.name for mod in discovered]
    fingerprint_entries: list[tuple[str, int | None]] = []
    for mod in discovered:
        index_path = mod.path / FUNCTION_INDEX_FILENAME
        try:
            index_mtime_ns: int | None = index_path.stat().st_mtime_ns
        except OSError:
            index_mtime_ns = -1
        fingerprint_entries.append((mod.name, index_mtime_ns))

    fingerprint_entries.sort()
    return modules, tuple(fingerprint_entries)


# ---------------------------------------------------------------------------
# Module discovery
# ---------------------------------------------------------------------------


def list_extracted_modules() -> list[str]:
    """Return sorted list of module folder names under extracted_code/.

    Only includes directories that contain a function_index.json file.
    Results are cached and invalidated when the discovered module set changes.
    """
    global _cached_module_list, _cached_module_list_fingerprint
    global _cached_module_list_mtime

    if not EXTRACTED_CODE_DIR.is_dir():
        return []

    result, fingerprint = _scan_module_discovery_state()
    if (
        _cached_module_list is not None
        and fingerprint == _cached_module_list_fingerprint
    ):
        return _cached_module_list

    _cached_module_list = result
    _cached_module_list_fingerprint = fingerprint
    try:
        _cached_module_list_mtime = EXTRACTED_CODE_DIR.stat().st_mtime
    except OSError:
        _cached_module_list_mtime = 0.0
    return result


def resolve_module_dir(module_name: str) -> Optional[Path]:
    """Resolve a module name to its extracted_code directory.

    Accepts exact folder names (e.g., 'appinfo_dll') or original filenames
    (e.g., 'appinfo.dll'). Returns None if not found.
    """
    # Try exact match first
    candidate = EXTRACTED_CODE_DIR / module_name
    if candidate.is_dir() and (candidate / FUNCTION_INDEX_FILENAME).is_file():
        return candidate

    # Try sanitized name: stem_extension (e.g., appinfo.dll -> appinfo_dll)
    if "." in module_name:
        stem, ext = module_name.rsplit(".", 1)
        sanitized = f"{stem}_{ext}"
        candidate = EXTRACTED_CODE_DIR / sanitized
        if candidate.is_dir() and (candidate / FUNCTION_INDEX_FILENAME).is_file():
            return candidate

    # Try case-insensitive match
    if EXTRACTED_CODE_DIR.is_dir():
        lower = module_name.lower()
        for d in EXTRACTED_CODE_DIR.iterdir():
            if d.is_dir() and d.name.lower() == lower:
                if (d / FUNCTION_INDEX_FILENAME).is_file():
                    return d

    # Fallback: treat underscores and dots as interchangeable.
    # DB filenames flatten all dots to underscores (e.g. windows.storage.dll
    # becomes windows_storage_dll_<hash>.db), but extracted_code folders
    # preserve dots in the PE stem (windows.storage_dll).  Normalize both
    # sides so they can match despite the ambiguity.
    if EXTRACTED_CODE_DIR.is_dir():
        normalized_input = module_name.lower().replace(".", "_")
        for d in EXTRACTED_CODE_DIR.iterdir():
            if d.is_dir() and d.name.lower().replace(".", "_") == normalized_input:
                if (d / FUNCTION_INDEX_FILENAME).is_file():
                    return d

    return None


def function_index_path(module_name: str) -> Optional[Path]:
    """Return the absolute path to a module's function_index.json, or None."""
    mod_dir = resolve_module_dir(module_name)
    if mod_dir is None:
        return None
    idx = mod_dir / FUNCTION_INDEX_FILENAME
    return idx if idx.is_file() else None


# ---------------------------------------------------------------------------
# Function index loading
# ---------------------------------------------------------------------------


def load_function_index(
    module_name: str,
    *,
    warn_on_missing: bool = True,
) -> Optional[dict[str, dict[str, Any]]]:
    """Load function_index.json for a module.

    Returns the parsed dict mapping function names to:
    {file, library, function_id, has_decompiled, has_assembly},
    or None if the module or index file is not found.

    Set *warn_on_missing* to ``False`` to suppress the warning when the
    index file does not exist (useful for speculative lookups that have
    a fallback path).
    """
    idx_path = function_index_path(module_name)
    if idx_path is None:
        if warn_on_missing:
            log_warning(
                f"Function index not found for module '{module_name}'",
                "NOT_FOUND",
            )
        return None
    try:
        stat = idx_path.stat()
        mtime_ns = stat.st_mtime_ns
    except OSError as exc:
        log_warning(
            f"Cannot stat function index {idx_path}: {exc}",
            "DB_ERROR",
        )
        return None

    cache_key = str(idx_path.resolve())
    with _cached_function_indexes_lock:
        cached = _cached_function_indexes.get(cache_key)
        if cached is not None and cached[0] == mtime_ns:
            return cached[1]

    try:
        with open(idx_path, "r", encoding="utf-8") as f:
            parsed = json.load(f)
    except json.JSONDecodeError as exc:
        with _cached_function_indexes_lock:
            _cached_function_indexes.pop(cache_key, None)
        log_warning(
            f"Invalid JSON in function index {idx_path}: {exc}",
            "PARSE_ERROR",
        )
        return None
    except OSError as exc:
        with _cached_function_indexes_lock:
            _cached_function_indexes.pop(cache_key, None)
        log_warning(
            f"Cannot read function index {idx_path}: {exc}",
            "DB_ERROR",
        )
        return None

    if not isinstance(parsed, dict):
        with _cached_function_indexes_lock:
            _cached_function_indexes.pop(cache_key, None)
        log_warning(
            f"Invalid function index {idx_path}: expected top-level object, "
            f"got {type(parsed).__name__}",
            "PARSE_ERROR",
        )
        return None

    sanitized: dict[str, dict[str, Any]] = {}
    invalid_entries = 0
    for name, entry in parsed.items():
        if isinstance(name, str) and isinstance(entry, dict):
            sanitized[name] = entry
        else:
            invalid_entries += 1

    if invalid_entries:
        log_warning(
            f"Skipped {invalid_entries} malformed entries in function index {idx_path}",
            "PARSE_ERROR",
        )

    with _cached_function_indexes_lock:
        _cached_function_indexes[cache_key] = (mtime_ns, sanitized)
    return sanitized


_CONSOLIDATED_CACHE_DIR = WORKSPACE_ROOT / ".agent" / "cache"
_CONSOLIDATED_CACHE_FILE = _CONSOLIDATED_CACHE_DIR / "_global_function_index.json"
_consolidated_index_lock = threading.Lock()


def _fingerprint_hash() -> str:
    """Build a hex hash from all modules' function_index.json mtimes."""
    import hashlib
    _, fingerprint = _scan_module_discovery_state()
    h = hashlib.sha1(repr(fingerprint).encode(), usedforsecurity=False)
    return h.hexdigest()[:16]


def _load_consolidated_cache() -> dict[str, dict[str, dict[str, Any]]] | None:
    """Try to load the consolidated index from disk if the fingerprint matches."""
    try:
        if not _CONSOLIDATED_CACHE_FILE.is_file():
            return None
        raw = json.loads(_CONSOLIDATED_CACHE_FILE.read_text(encoding="utf-8"))
        if raw.get("fingerprint") != _fingerprint_hash():
            return None
        return raw.get("indexes", {})
    except (OSError, json.JSONDecodeError, KeyError):
        return None


def _save_consolidated_cache(
    indexes: dict[str, dict[str, dict[str, Any]]],
) -> None:
    """Persist the consolidated index to disk."""
    try:
        _CONSOLIDATED_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        payload = {"fingerprint": _fingerprint_hash(), "indexes": indexes}
        _CONSOLIDATED_CACHE_FILE.write_text(
            json.dumps(payload, separators=(",", ":")),
            encoding="utf-8",
        )
    except OSError:
        pass


def load_all_function_indexes(
    *, max_modules: int | None = None,
) -> dict[str, dict[str, dict[str, Any]]]:
    """Load function_index.json for extracted modules.

    Parameters
    ----------
    max_modules:
        Maximum number of modules to load.  Defaults to
        ``scale.max_modules_cross_scan`` from config.  Pass 0 or a
        negative value to load all (use with caution at scale).

    Returns dict: module_name ->
    {function_name -> {file, library, function_id, has_decompiled, has_assembly}}.

    Uses a disk-cached consolidated index (keyed on a fingerprint of all
    module mtimes) to avoid re-reading 195+ individual JSON files on every
    invocation.
    """
    if max_modules is None:
        max_modules = get_config_value("scale.max_modules_cross_scan", 0)

    use_all = not (max_modules and max_modules > 0)

    if use_all:
        with _consolidated_index_lock:
            cached = _load_consolidated_cache()
            if cached is not None:
                return cached

    modules = list_extracted_modules()
    if not use_all and len(modules) > max_modules:
        log_warning(
            f"load_all_function_indexes: {len(modules)} modules available, "
            f"loading first {max_modules}. Pass max_modules=0 to override.",
            "NO_DATA",
        )
        modules = modules[:max_modules]

    import sys
    total = len(modules)
    result: dict[str, dict[str, dict[str, Any]]] = {}
    for i, module_name in enumerate(modules, 1):
        if total >= 500 and i % 500 == 0:
            print(
                f"  load_all_function_indexes: {i}/{total} modules...",
                file=sys.stderr,
            )
        index = load_function_index(module_name)
        if index:
            result[module_name] = index

    if use_all:
        with _consolidated_index_lock:
            _save_consolidated_cache(result)

    return result


# ---------------------------------------------------------------------------
# Library tag helpers
# ---------------------------------------------------------------------------


def is_library_function(entry: dict[str, Any]) -> bool:
    """Check if a function_index entry represents library/boilerplate code."""
    return entry.get("library") is not None


def is_application_function(entry: dict[str, Any]) -> bool:
    """Check if a function_index entry represents application (non-library) code."""
    return entry.get("library") is None


def get_library_tag(entry: dict[str, Any]) -> Optional[str]:
    """Return the library tag or None for application code."""
    return entry.get("library")


def has_decompiled(entry: dict[str, Any]) -> bool:
    """Check if a function_index entry has valid decompiled output."""
    return bool(entry.get("has_decompiled", entry.get("file") is not None))


def has_assembly(entry: dict[str, Any]) -> bool:
    """Check if a function_index entry has assembly code available."""
    return bool(entry.get("has_assembly", False))


def get_function_id(entry: dict[str, Any]) -> int | None:
    """Return function_id from a function_index entry, or None."""
    value = entry.get("function_id")
    return value if isinstance(value, int) else None


def filter_decompiled(
    index: dict[str, dict[str, Any]],
    decompiled: bool = True,
) -> dict[str, dict[str, Any]]:
    """Filter function index entries by decompilation availability."""
    return {k: v for k, v in index.items() if has_decompiled(v) is decompiled}


def build_id_map(
    index: dict[str, dict[str, Any]],
) -> dict[int, tuple[str, dict[str, Any]]]:
    """Build reverse map: function_id -> (function_name, entry)."""
    return {
        function_id: (func_name, entry)
        for func_name, entry in index.items()
        for function_id in [get_function_id(entry)]
        if function_id is not None
    }


def search_index(
    index: dict[str, dict[str, Any]],
    pattern: str,
    case_sensitive: bool = False,
    mode: str = "substring",
    fuzzy_threshold: float = 0.6,
) -> dict[str, dict[str, Any]]:
    """Search function names in an already-loaded function index.

    Args:
        index: The function_index dict (name -> entry).
        pattern: Search term -- literal substring, regex, or fuzzy target.
        case_sensitive: Whether matching is case-sensitive (substring/fuzzy).
        mode: ``"substring"`` (default), ``"regex"``, or ``"fuzzy"``.
        fuzzy_threshold: Minimum ``SequenceMatcher.ratio()`` for fuzzy mode.

    Returns:
        Dict of matching ``{function_name: entry}`` pairs.
    """
    if mode == "regex":
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            compiled = re.compile(pattern, flags)
        except re.error as exc:
            log_warning(
                f"Invalid regex pattern '{pattern}': {exc}",
                "PARSE_ERROR",
            )
            return {}
        return {k: v for k, v in index.items() if compiled.search(k)}

    if mode == "fuzzy":
        pat = pattern if case_sensitive else pattern.lower()
        results: dict[str, dict[str, Any]] = {}
        for k, v in index.items():
            k_cmp = k if case_sensitive else k.lower()
            if pat in k_cmp:
                results[k] = v
            elif SequenceMatcher(None, pat, k_cmp).ratio() >= fuzzy_threshold:
                results[k] = v
        return results

    # Default: substring
    if case_sensitive:
        return {k: v for k, v in index.items() if pattern in k}
    pat = pattern.lower()
    return {k: v for k, v in index.items() if pat in k.lower()}


def filter_by_library(
    index: dict[str, dict[str, Any]],
    library: Optional[str] = None,
    app_only: bool = False,
    lib_only: bool = False,
) -> dict[str, dict[str, Any]]:
    """Filter function index entries by library tag.

    Args:
        index: The function_index dict.
        library: Filter to specific library tag (e.g., 'WIL', 'STL').
        app_only: If True, return only application code (library=null).
        lib_only: If True, return only library/boilerplate code.

    Returns:
        Filtered dict with matching entries.
    """
    if library:
        return {k: v for k, v in index.items() if v.get("library") == library}
    if app_only:
        return {k: v for k, v in index.items() if v.get("library") is None}
    if lib_only:
        return {k: v for k, v in index.items() if v.get("library") is not None}
    return index


# ---------------------------------------------------------------------------
# Grouping and statistics
# ---------------------------------------------------------------------------


def group_by_file(index: dict[str, dict[str, Any]]) -> dict[Optional[str], list[str]]:
    """Group function names by the .cpp file they belong to.

    Returns dict: filename-or-None -> [function_name, ...].
    """
    groups: dict[Optional[str], list[str]] = {}
    for func_name, entry in index.items():
        fname = entry.get("file")
        groups.setdefault(fname, []).append(func_name)
    return groups


def group_by_library(index: dict[str, dict[str, Any]]) -> dict[Optional[str], list[str]]:
    """Group function names by their library tag.

    Returns dict: library_tag (or None for app code) -> [function_name, ...].
    """
    groups: dict[Optional[str], list[str]] = {}
    for func_name, entry in index.items():
        tag = entry.get("library")
        groups.setdefault(tag, []).append(func_name)
    return groups


def compute_stats(index: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Compute summary statistics for a function index.

    Returns dict with total_functions, app_functions, library_functions,
    library_breakdown, file_count, files, decompiled_count, assembly_count,
    and no_decompiled_count.
    """
    lib_groups = group_by_library(index)
    file_groups = group_by_file(index)

    app_count = len(lib_groups.get(None, []))
    lib_count = sum(len(v) for k, v in lib_groups.items() if k is not None)

    breakdown = {}
    for tag, funcs in lib_groups.items():
        if tag is not None:
            breakdown[tag] = len(funcs)

    decompiled_count = sum(1 for entry in index.values() if has_decompiled(entry))
    assembly_count = sum(1 for entry in index.values() if has_assembly(entry))
    no_decompiled_count = len(index) - decompiled_count
    files = sorted(fname for fname in file_groups.keys() if isinstance(fname, str))

    return {
        "total_functions": len(index),
        "app_functions": app_count,
        "library_functions": lib_count,
        "library_breakdown": breakdown,
        "file_count": len(files),
        "files": files,
        "decompiled_count": decompiled_count,
        "assembly_count": assembly_count,
        "no_decompiled_count": no_decompiled_count,
    }


# ---------------------------------------------------------------------------
# Cross-module lookup
# ---------------------------------------------------------------------------


def lookup_function(
    function_name: str,
    module_name: Optional[str] = None,
    *,
    max_modules: int | None = None,
) -> list[dict[str, Any]]:
    """Find exact function name matches across one or all modules.

    Parameters
    ----------
    max_modules:
        When *module_name* is ``None``, limit the number of modules searched.
        Defaults to ``scale.max_modules_search_all`` from config.

    Returns list of dicts with: function_name, module, file, file_path, library,
    function_id, has_decompiled, has_assembly.
    """
    results: list[dict[str, Any]] = []
    if module_name:
        modules = [module_name]
    else:
        modules = list_extracted_modules()
        if max_modules is None:
            max_modules = get_config_value("scale.max_modules_search_all", 0)
        if max_modules and max_modules > 0 and len(modules) > max_modules:
            modules = modules[:max_modules]

    for mod in modules:
        index = load_function_index(mod)
        if index is None:
            continue
        if function_name in index:
            entry = index[function_name]
            mod_dir = resolve_module_dir(mod)
            file_name = entry.get("file")
            if file_name is None:
                file_path = None
            else:
                file_path = str(mod_dir / file_name) if mod_dir else file_name
            results.append({
                "function_name": function_name,
                "module": mod,
                "file": file_name,
                "file_path": file_path,
                "library": entry.get("library"),
                "function_id": get_function_id(entry),
                "has_decompiled": has_decompiled(entry),
                "has_assembly": has_assembly(entry),
            })
    return results


def resolve_function_file(
    function_name: str,
    module_name: Optional[str] = None,
) -> Optional[Path]:
    """Resolve a function name to its absolute .cpp file path.

    Returns the Path to the .cpp file, or None if not found.
    When module_name is omitted, searches all modules (returns first match).
    """
    matches = lookup_function(function_name, module_name=module_name)
    if not matches:
        return None
    file_path = matches[0].get("file_path")
    if not file_path:
        return None
    return Path(file_path)


# ---------------------------------------------------------------------------
# DB-path bridge (resolve module name from a DB, then load its index)
# ---------------------------------------------------------------------------


def load_function_index_for_db(db_path: str | Path) -> Optional[dict[str, dict[str, Any]]]:
    """Load the function_index for the module whose analysis DB is at *db_path*.

    First attempts to infer the module name from the DB filename (avoiding a
    full DB connection).  Falls back to opening the DB and reading
    ``file_info.file_name`` when the filename heuristic fails.  Returns
    ``None`` when no matching function_index.json exists.
    """
    # Fast path: infer module name from DB filename without opening the DB.
    # DB files follow the pattern ``<module_name>_<hex_hash>.db``
    # (e.g. ``appinfo_dll_f2bbf324a1.db`` -> folder ``appinfo_dll``).
    m = _DB_NAME_RE.match(Path(db_path).name)
    if m:
        inferred = m.group(1)
        result = load_function_index(inferred, warn_on_missing=False)
        if result is not None:
            return result

    # Slow path: open the DB to read the authoritative file_name.
    from ..individual_analysis_db import open_individual_analysis_db

    try:
        with open_individual_analysis_db(db_path) as db:
            info = db.get_file_info()
            if info and info.file_name:
                return load_function_index(info.file_name)
    except (json.JSONDecodeError, OSError) as exc:
        log_warning(
            f"Failed to load function index for DB {db_path}: {exc}",
            "DB_ERROR",
        )
    except (RuntimeError, ValueError, KeyError) as exc:
        log_warning(
            f"Unexpected error loading function index for DB {db_path}: {exc}",
            "UNKNOWN",
        )
    return None


def get_library_tag_for_function(
    function_name: str,
    function_index: Optional[dict[str, dict[str, Any]]],
) -> Optional[str]:
    """Return the library tag for *function_name*, or ``None`` (app code).

    Convenience wrapper used by classification and filtering scripts.
    """
    if function_index is None:
        return None
    entry = function_index.get(function_name)
    if entry is None:
        return None
    return entry.get("library")


# ---------------------------------------------------------------------------
# Argparse helper for --app-only
# ---------------------------------------------------------------------------


def add_app_only_argument(parser) -> None:
    """Add the standard ``--app-only`` flag to an argparse parser.

    Scripts that iterate over all functions in a module should call this
    during argument setup and check ``args.app_only`` to filter library
    boilerplate (WIL, STL, WRL, CRT, ETW) from results.

    Usage::

        add_app_only_argument(parser)
        args = parser.parse_args()
        # ... load function_index ...
        if args.app_only:
            function_index = filter_application_functions(function_index)
    """
    parser.add_argument(
        "--app-only",
        action="store_true",
        default=False,
        dest="app_only",
        help="Exclude library boilerplate (WIL, STL, WRL, CRT, ETW) from results",
    )


def filter_application_functions(
    function_index: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Return a copy of *function_index* with library entries removed.

    Keeps only entries where ``library`` is ``None`` (application code).
    Equivalent to ``filter_by_library(index, None)`` but with a clearer name
    for the common ``--app-only`` use case.
    """
    return {
        name: entry
        for name, entry in function_index.items()
        if entry.get("library") is None
    }
