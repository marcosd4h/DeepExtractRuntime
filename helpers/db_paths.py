"""Centralized DB path resolution utilities.

Consolidates ``resolve_db_path()``, ``resolve_tracking_db()``, and
``resolve_module_db()`` which were previously duplicated across 18+
``_common.py`` files with inconsistent variants.  The canonical
implementations live here; skill/agent ``_common.py`` files provide thin
wrappers that bind the ``workspace_root`` parameter.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Optional

DB_NAME_RE = re.compile(r"^(.+?)_[0-9a-f]{6,}\.db$", re.IGNORECASE)
"""Match DB filenames like ``appinfo_dll_f2bbf324a1.db`` and extract the module stem."""


def module_name_from_path(raw_path: str) -> str:
    """Extract the filename from a full Windows path."""
    return Path(raw_path).name


def _normalize_module_lookup_name(name: str) -> str:
    """Normalize a user/module name for tolerant matching."""
    return re.sub(r"[^a-z0-9]+", "_", name.strip().lower()).strip("_")


def _module_stem_from_db_filename(filename: str) -> str:
    """Extract the logical module stem from a DB filename."""
    from .module_discovery import db_stem_from_filename
    return db_stem_from_filename(filename)


def safe_long_path(path: str | Path) -> Path:
    """Return a Path safe for Windows long-path operations (>=260 chars).

    On Windows, paths of 260 characters or more cause ``FileNotFoundError``
    or ``OSError`` unless the ``\\\\?\\`` prefix is applied.  This function
    adds the prefix when needed and is a no-op on non-Windows platforms.

    The prefix is applied *before* ``resolve()`` to handle paths that are
    already too long for Win32 API calls without the extended-length prefix.

    Use this when creating directories or opening files on potentially
    deep workspace paths (e.g. ``.agent/workspace/...`` run dirs, hook
    scratchpads, or nested extraction outputs).
    """
    if sys.platform == "win32":
        raw = str(Path(path))
        if not raw.startswith("\\\\?\\") and len(raw) >= 260:
            prefixed = Path("\\\\?\\" + raw)
            try:
                return prefixed.resolve()
            except OSError:
                return prefixed
    return Path(path).resolve()


def safe_makedirs(path: str | Path, exist_ok: bool = True) -> Path:
    """Create directories with Windows long-path safety.

    Equivalent to ``Path.mkdir(parents=True, exist_ok=True)`` but applies
    ``safe_long_path`` first to handle paths exceeding 260 characters.
    """
    p = safe_long_path(path)
    os.makedirs(str(p), exist_ok=exist_ok)
    return p


def resolve_db_path(db_path: str, workspace_root: Path) -> str:
    """Resolve a DB path relative to *workspace_root* if not absolute.

    Falls back to the ``extracted_dbs/`` subdirectory when the direct path
    does not exist on disk.
    """
    p = Path(db_path)
    if not p.is_absolute():
        p = workspace_root / db_path
    if not p.exists():
        candidate = workspace_root / "extracted_dbs" / Path(db_path).name
        if candidate.exists():
            return str(candidate)
    return str(p)


def resolve_tracking_db(workspace_root: Path) -> Optional[str]:
    """Find the ``analyzed_files.db`` tracking database.

    Checks two locations:
    1. ``extracted_dbs/analyzed_files.db`` (agent convention)
    2. ``analyzed_files.db`` (batch extractor root-level output)
    """
    candidate = workspace_root / "extracted_dbs" / "analyzed_files.db"
    if candidate.exists():
        return str(candidate)
    candidate_root = workspace_root / "analyzed_files.db"
    if candidate_root.exists():
        return str(candidate_root)
    return None


def workspace_root_from_tracking_db(tracking_db_path: str | Path) -> Path:
    """Infer the workspace root from an ``analyzed_files.db`` path.

    Tracking DBs are normally stored at either ``extracted_dbs/analyzed_files.db``
    or ``analyzed_files.db`` in the workspace root.
    """
    tracking_path = Path(tracking_db_path).resolve()
    tracking_dir = tracking_path.parent
    if tracking_dir.name == "extracted_dbs":
        return tracking_dir.parent
    return tracking_dir


def resolve_module_db(
    module_name_or_path: str,
    workspace_root: Path,
    *,
    require_complete: bool = True,
) -> Optional[str]:
    """Resolve a module name or DB path to an absolute DB path.

    Resolution strategy:

    1. If *module_name_or_path* ends with ``.db``, treat as a direct path
       and resolve relative to *workspace_root* or ``extracted_dbs/``.
    2. Otherwise, search ``analyzed_files.db`` by exact filename, then by
       partial name match.

    Args:
        module_name_or_path: Module name (e.g. ``"appinfo.dll"``) or a
            ``.db`` file path (absolute or relative).
        workspace_root: Workspace root directory.
        require_complete: If ``True`` (default), only return DBs whose
            tracking record has ``status == "COMPLETE"``.  Set to ``False``
            to accept any status.

    Returns:
        Absolute path string to the analysis DB, or ``None`` if not found.
    """
    extracted_dbs_dir = workspace_root / "extracted_dbs"
    normalized_lookup = _normalize_module_lookup_name(module_name_or_path)

    # --- Direct .db path -----------------------------------------------------
    if module_name_or_path.endswith(".db"):
        p = Path(module_name_or_path)
        if not p.is_absolute():
            p = workspace_root / module_name_or_path
        if p.exists():
            return str(p)
        candidate = extracted_dbs_dir / Path(module_name_or_path).name
        if candidate.exists():
            return str(candidate)
        return None

    # --- Search tracking DB by module name -----------------------------------
    tracking = resolve_tracking_db(workspace_root)
    from .errors import log_warning

    def _warn_ambiguous(candidates: list[str]) -> None:
        log_warning(
            f"Ambiguous module name '{module_name_or_path}'. Matching modules: "
            f"{', '.join(sorted(candidates))}. Use the exact module name or DB path.",
            "AMBIGUOUS",
        )

    def _resolve_from_filesystem_scan() -> Optional[str]:
        from .module_discovery import iter_module_dbs

        entries: list[tuple[str, str, str]] = [
            (db.file_name, db.module_stem, str(db.path))
            for db in iter_module_dbs(extracted_dbs_dir, include_empty=True)
        ]
        if not entries:
            return None

        exact_matches = [
            (display_name, path)
            for display_name, module_stem, path in entries
            if _normalize_module_lookup_name(module_stem) == normalized_lookup
        ]
        if len(exact_matches) == 1:
            return exact_matches[0][1]
        if len(exact_matches) > 1:
            _warn_ambiguous([name for name, _path in exact_matches])
            return None

        partial_matches = [
            (display_name, path)
            for display_name, module_stem, path in entries
            if normalized_lookup and normalized_lookup in _normalize_module_lookup_name(module_stem)
        ]
        if len(partial_matches) == 1:
            return partial_matches[0][1]
        if len(partial_matches) > 1:
            _warn_ambiguous([name for name, _path in partial_matches])
            return None

        return None

    if not tracking:
        return _resolve_from_filesystem_scan()

    # Lazy import to avoid circular dependencies at module level
    from .analyzed_files_db import open_analyzed_files_db

    with open_analyzed_files_db(tracking) as db:
        def _resolve_existing_paths(records: list) -> list[tuple[str, str]]:
            matches: list[tuple[str, str]] = []
            seen_paths: set[str] = set()
            for rec in records:
                if require_complete and getattr(rec, "status", None) != "COMPLETE":
                    continue
                if not rec.analysis_db_path:
                    continue
                candidates = [
                    workspace_root / rec.analysis_db_path,
                    extracted_dbs_dir / rec.analysis_db_path,
                    extracted_dbs_dir / Path(rec.analysis_db_path).name,
                ]
                for candidate in candidates:
                    if candidate.exists():
                        resolved = str(candidate)
                        if resolved not in seen_paths:
                            display_name = rec.file_name or Path(rec.analysis_db_path).name
                            matches.append((display_name, resolved))
                            seen_paths.add(resolved)
                        break
            return matches

        exact_matches = _resolve_existing_paths(db.get_by_file_name(module_name_or_path))
        if len(exact_matches) == 1:
            return exact_matches[0][1]
        if len(exact_matches) > 1:
            _warn_ambiguous([name for name, _path in exact_matches])
            return None

        all_records = db.get_all()
        alias_exact_matches = _resolve_existing_paths([
            rec for rec in all_records
            if normalized_lookup in {
                _normalize_module_lookup_name(rec.file_name or ""),
                _normalize_module_lookup_name(
                    _module_stem_from_db_filename(rec.analysis_db_path or "")
                ),
            }
        ])
        if len(alias_exact_matches) == 1:
            return alias_exact_matches[0][1]
        if len(alias_exact_matches) > 1:
            _warn_ambiguous([name for name, _path in alias_exact_matches])
            return None

        partial_matches = _resolve_existing_paths(db.search(name_contains=module_name_or_path))
        if len(partial_matches) > 1:
            _warn_ambiguous([name for name, _path in partial_matches])
            return None
        if partial_matches:
            return partial_matches[0][1]

        alias_partial_matches = _resolve_existing_paths([
            rec for rec in all_records
            if normalized_lookup and any(
                normalized_lookup in key for key in {
                    _normalize_module_lookup_name(rec.file_name or ""),
                    _normalize_module_lookup_name(
                        _module_stem_from_db_filename(rec.analysis_db_path or "")
                    ),
                }
            )
        ])
        if len(alias_partial_matches) == 1:
            return alias_partial_matches[0][1]
        if len(alias_partial_matches) > 1:
            _warn_ambiguous([name for name, _path in alias_partial_matches])
            return None

    return None


# ---------------------------------------------------------------------------
# Auto-resolving convenience wrappers
# ---------------------------------------------------------------------------
# These use the workspace root derived from the helpers/ directory layout
# (``<workspace>/.agent/helpers/``).  They exist so that agent and skill
# ``_common.py`` files no longer need to import from ``skills._shared``
# and rebind the workspace root themselves.

def _auto_workspace_root() -> Path:
    """Return the workspace root inferred from helpers/ location.

    In the ``.agent/`` deployment layout the path is
    ``<workspace>/.agent/helpers/db_paths.py`` (3 levels up).
    In standalone layout it is ``<root>/helpers/db_paths.py`` (2 levels up).
    """
    _helpers_dir = Path(__file__).resolve().parent
    _runtime_root = _helpers_dir.parent
    if _runtime_root.name == ".agent":
        return _runtime_root.parent
    return _runtime_root


def resolve_db_path_auto(db_path: str) -> str:
    """Resolve a DB path using the auto-detected workspace root.

    Equivalent to ``resolve_db_path(db_path, <workspace_root>)``.
    """
    return resolve_db_path(db_path, _auto_workspace_root())


def resolve_tracking_db_auto() -> Optional[str]:
    """Find the tracking DB using the auto-detected workspace root.

    Equivalent to ``resolve_tracking_db(<workspace_root>)``.
    """
    return resolve_tracking_db(_auto_workspace_root())


def resolve_module_db_auto(
    module_name_or_path: str,
    *,
    require_complete: bool = True,
) -> Optional[str]:
    """Resolve a module DB using the auto-detected workspace root.

    Equivalent to ``resolve_module_db(name, <workspace_root>, ...)``.
    """
    return resolve_module_db(
        module_name_or_path,
        _auto_workspace_root(),
        require_complete=require_complete,
    )
