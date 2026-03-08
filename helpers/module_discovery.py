"""Canonical module and DB discovery for DeepExtractIDA workspaces.

Provides the single source of truth for enumerating modules in
``extracted_code/`` and analysis DBs in ``extracted_dbs/``.  All scanners
in the runtime should delegate to these functions for directory iteration
and marker-file detection, layering their own processing on top.

Typical usage::

    from helpers.module_discovery import iter_module_dirs, iter_module_dbs

    for mod in iter_module_dirs(workspace / "extracted_code"):
        print(mod.name, mod.has_file_info, mod.has_function_index)

    for db in iter_module_dbs(workspace / "extracted_dbs"):
        print(db.module_stem, db.path)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


TRACKING_DB_NAME = "analyzed_files.db"
FILE_INFO_JSON = "file_info.json"
FUNCTION_INDEX_JSON = "function_index.json"

_DB_HASH_SUFFIX_RE = re.compile(r"_[0-9a-f]{6,}$", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ModuleDir:
    """A discovered module directory under ``extracted_code/``."""

    name: str
    """Directory name (e.g. ``"appinfo_dll"``)."""

    path: Path
    """Full path to the directory."""

    has_file_info: bool
    """Whether ``file_info.json`` exists in this directory."""

    has_function_index: bool
    """Whether ``function_index.json`` exists in this directory."""


@dataclass(frozen=True)
class ModuleDb:
    """A discovered per-module analysis DB under ``extracted_dbs/``."""

    path: Path
    """Full path to the ``.db`` file."""

    file_name: str
    """Basename (e.g. ``"appinfo_dll_f2bbf324a1.db"``)."""

    module_stem: str
    """Logical module stem with hash suffix stripped (e.g. ``"appinfo_dll"``)."""

    size_bytes: int
    """File size in bytes."""


# ---------------------------------------------------------------------------
# Core scanning functions
# ---------------------------------------------------------------------------

def iter_module_dirs(
    extracted_code_dir: Path,
    *,
    require_file_info: bool = False,
    require_function_index: bool = False,
) -> list[ModuleDir]:
    """List module directories in ``extracted_code/``.

    By default returns all directories that have **at least one** marker
    (``file_info.json`` or ``function_index.json``).  Use the ``require_*``
    flags to restrict to directories containing a specific marker.

    Results are sorted by directory name.
    """
    if not extracted_code_dir.is_dir():
        return []

    results: list[ModuleDir] = []
    for entry in sorted(extracted_code_dir.iterdir()):
        if not entry.is_dir():
            continue
        has_fi = (entry / FILE_INFO_JSON).is_file()
        has_fx = (entry / FUNCTION_INDEX_JSON).is_file()

        if require_file_info and not has_fi:
            continue
        if require_function_index and not has_fx:
            continue
        if not has_fi and not has_fx:
            continue

        results.append(ModuleDir(
            name=entry.name,
            path=entry,
            has_file_info=has_fi,
            has_function_index=has_fx,
        ))
    return results


def iter_module_dbs(
    extracted_dbs_dir: Path,
    *,
    include_empty: bool = False,
) -> list[ModuleDb]:
    """List per-module analysis DBs in ``extracted_dbs/``.

    Skips the tracking DB (``analyzed_files.db``).  By default also skips
    empty (0-byte) files.  Results are sorted by filename.
    """
    if not extracted_dbs_dir.is_dir():
        return []

    results: list[ModuleDb] = []
    for entry in sorted(extracted_dbs_dir.glob("*.db")):
        if not entry.is_file():
            continue
        if entry.name.lower() == TRACKING_DB_NAME:
            continue
        try:
            size = entry.stat().st_size
        except OSError:
            continue
        if not include_empty and size == 0:
            continue

        results.append(ModuleDb(
            path=entry,
            file_name=entry.name,
            module_stem=db_stem_from_filename(entry.name),
            size_bytes=size,
        ))
    return results


# ---------------------------------------------------------------------------
# Name-mapping helpers
# ---------------------------------------------------------------------------

def db_stem_from_filename(filename: str) -> str:
    """Extract the logical module stem by stripping the hash suffix.

    ``"appinfo_dll_f2bbf324a1.db"``  ->  ``"appinfo_dll"``
    ``"kernel32_dll.db"``            ->  ``"kernel32_dll"``
    """
    stem = Path(filename).stem
    m = _DB_HASH_SUFFIX_RE.search(stem)
    if m:
        return stem[:m.start()]
    return stem


def dir_name_to_file_name(dir_name: str) -> str:
    """Convert a module directory name to a likely original filename.

    Reverses the ``{stem}_{ext}`` convention back to ``{stem}.{ext}``.
    E.g. ``"kernel32_dll"`` -> ``"kernel32.dll"``
    """
    last_underscore = dir_name.rfind("_")
    if last_underscore > 0:
        stem = dir_name[:last_underscore]
        ext = dir_name[last_underscore + 1:]
        return f"{stem}.{ext}"
    return dir_name


def normalize_module_name(name: str) -> str:
    """Normalize a module name for tolerant matching.

    Lowercases and replaces non-alphanumeric runs with underscores.
    """
    return re.sub(r"[^a-z0-9]+", "_", name.strip().lower()).strip("_")


def get_tracking_db_path(extracted_dbs_dir: Path) -> Optional[Path]:
    """Return the tracking DB path if it exists, else ``None``."""
    path = extracted_dbs_dir / TRACKING_DB_NAME
    return path if path.is_file() else None
