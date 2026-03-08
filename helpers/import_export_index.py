"""Cross-module PE import/export table index.

Builds an in-memory index of all PE import and export table entries
across every analyzed module in the workspace.  Unlike
:class:`ModuleResolver` (which searches function *names* in the
``functions`` table) and :class:`CrossModuleGraph` (which follows
code-level xrefs), this module works from the authoritative PE
import/export data stored in ``file_info.imports`` and
``file_info.exports``.

For performance on large workspaces (5 000+ modules), the build phase
tries ``extracted_code/<module>/file_info.json`` first (a plain file
read, ~0.5 ms per module) and falls back to opening the per-module
SQLite DB only when the JSON file is absent.

Typical questions this answers:

- "Which module exports ``CreateProcessW``?"
- "Which modules import ``CreateProcessW``?"
- "What modules depend on ``ntdll.dll`` at the loader level?"
- "Follow the forwarded export chain for ``kernel32!HeapAlloc``."

Usage::

    from helpers.import_export_index import ImportExportIndex

    with ImportExportIndex() as idx:
        for exp in idx.who_exports("CreateProcessW"):
            print(exp.module, exp.name)
        for imp in idx.who_imports("CreateProcessW"):
            print(imp.importing_module, "imports from", imp.source_module)
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import sys
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional

from .analyzed_files_db import open_analyzed_files_db
from .cache import get_cached, cache_result
from .config import get_config_value
from .db_paths import (
    _auto_workspace_root,
    resolve_db_path,
    resolve_tracking_db,
    workspace_root_from_tracking_db,
)
from .errors import log_warning

_log = logging.getLogger(__name__)

_FILE_INFO_JSON = "file_info.json"


# -------------------------------------------------------------------
# Data classes
# -------------------------------------------------------------------

@dataclass(frozen=True)
class ExportEntry:
    """A single PE export table entry from one module."""

    module: str
    db_path: str
    name: str
    ordinal: int
    is_forwarded: bool
    forwarded_to: Optional[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ImportEntry:
    """A single PE import table entry recording that *importing_module*
    imports *function_name* from *source_module*."""

    importing_module: str
    source_module: str
    function_name: str
    is_delay_loaded: bool
    ordinal: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# -------------------------------------------------------------------
# Parsing helpers (shared by JSON and DB paths)
# -------------------------------------------------------------------

def _parse_exports_list(
    raw: Any, file_name: str, db_path: str,
) -> list[ExportEntry]:
    """Turn a parsed exports JSON list into :class:`ExportEntry` objects."""
    if not isinstance(raw, list):
        return []
    entries: list[ExportEntry] = []
    for exp in raw:
        if not isinstance(exp, dict):
            continue
        name = exp.get("function_name", exp.get("name", ""))
        if not name:
            continue
        entries.append(ExportEntry(
            module=file_name, db_path=db_path, name=name,
            ordinal=exp.get("ordinal", 0),
            is_forwarded=exp.get("is_forwarded", False),
            forwarded_to=exp.get("forwarded_to"),
        ))
    return entries


def _parse_imports_list(
    raw: Any, file_name: str,
) -> list[ImportEntry]:
    """Turn a parsed imports JSON list into :class:`ImportEntry` objects."""
    if not isinstance(raw, list):
        return []
    entries: list[ImportEntry] = []
    for mod_entry in raw:
        if not isinstance(mod_entry, dict):
            continue
        src_module = mod_entry.get("module_name", mod_entry.get("name", ""))
        functions = mod_entry.get("functions", [])
        if not isinstance(functions, list) or not src_module:
            continue
        for func in functions:
            if not isinstance(func, dict):
                continue
            fn = func.get("function_name", func.get("name", ""))
            if not fn:
                continue
            entries.append(ImportEntry(
                importing_module=file_name, source_module=src_module,
                function_name=fn,
                is_delay_loaded=func.get("is_delay_loaded", False),
                ordinal=func.get("ordinal", 0),
            ))
    return entries


# -------------------------------------------------------------------
# ImportExportIndex
# -------------------------------------------------------------------

class ImportExportIndex:
    """Cross-module index of PE import and export tables.

    Lazily scans every module in the tracking database on first query,
    then caches the result for fast repeated lookups.

    The build phase uses a hybrid strategy for performance:

    1. Scan ``extracted_code/`` for ``file_info.json`` files (fast plain
       file reads, ~0.5 ms each).
    2. For modules without a ``file_info.json``, fall back to opening the
       per-module SQLite DB and reading ``file_info.imports``/``exports``.

    Thread Safety
    -------------
    All lazy-initialization paths are guarded by an internal
    ``threading.RLock``, making the index safe to share across threads.

    Resource Management
    -------------------
    DB connections are opened transiently (one at a time during the
    build phase) and closed immediately after reading ``file_info``.
    Use context-manager syntax for deterministic cleanup of internal
    state::

        with ImportExportIndex() as idx:
            ...
    """

    def __init__(
        self,
        tracking_db: Optional[str] = None,
        *,
        max_modules: Optional[int] = None,
        no_cache: bool = False,
    ) -> None:
        self._tracking_db_path = tracking_db
        self._max_modules = max_modules
        self._no_cache = no_cache
        self._lock = threading.RLock()
        self._loaded = False
        self._closed = False
        self._source_fingerprint: str | None = None

        self._export_index: dict[str, list[ExportEntry]] = defaultdict(list)
        self._import_index: dict[str, list[ImportEntry]] = defaultdict(list)
        self._module_exports: dict[str, list[ExportEntry]] = defaultdict(list)
        self._module_imports: dict[str, dict[str, list[str]]] = defaultdict(
            lambda: defaultdict(list)
        )

    # -- Context manager --------------------------------------------

    def __enter__(self) -> "ImportExportIndex":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def close(self) -> None:
        """Release internal state."""
        with self._lock:
            self._closed = True

    # -- Lazy loading -----------------------------------------------

    def _ensure_loaded(self) -> None:
        if self._closed:
            raise RuntimeError("ImportExportIndex has been closed")
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            self._build_index()
            self._loaded = True

    # -- JSON path helpers ------------------------------------------

    @staticmethod
    def _build_json_map(workspace_root: Path) -> dict[str, Path]:
        """Scan ``extracted_code/`` for ``file_info.json`` files.

        Returns ``{lower(file_name): path_to_file_info_json}``.  The
        key is derived from the folder name by reversing the
        ``{stem}_{ext}`` convention back to ``{stem}.{ext}``.
        """
        from helpers.module_discovery import dir_name_to_file_name, iter_module_dirs

        extracted_dir = workspace_root / "extracted_code"
        result: dict[str, Path] = {}
        try:
            for mod in iter_module_dirs(extracted_dir, require_file_info=True):
                fi_path = mod.path / _FILE_INFO_JSON
                file_name = dir_name_to_file_name(mod.name)
                result[file_name.lower()] = fi_path
                result[mod.name.lower()] = fi_path
        except OSError as exc:
            _log.debug("Cannot scan extracted_code/: %s", exc)
        return result

    @staticmethod
    def _scan_module_from_json(
        json_path: Path, file_name: str, db_path: str,
    ) -> tuple[list[ExportEntry], list[ImportEntry]]:
        """Read imports/exports from a ``file_info.json`` file."""
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        exports = _parse_exports_list(data.get("exports"), file_name, db_path)
        imports = _parse_imports_list(data.get("imports"), file_name)
        return exports, imports

    # -- DB path helper ---------------------------------------------

    @staticmethod
    def _scan_module_from_db(
        db_path: str, file_name: str,
    ) -> tuple[list[ExportEntry], list[ImportEntry]]:
        """Read imports/exports from a per-module SQLite analysis DB."""
        from .individual_analysis_db import open_individual_analysis_db

        with open_individual_analysis_db(db_path) as db:
            fi = db.get_file_info()
            if not fi:
                return [], []
            exports = _parse_exports_list(
                fi.parsed_exports, file_name, db_path,
            )
            imports = _parse_imports_list(fi.parsed_imports, file_name)
        return exports, imports

    @staticmethod
    def _build_work_items(
        records: list[Any],
        workspace_root: Path,
        json_map: dict[str, Path],
    ) -> list[tuple[str, str, Optional[Path]]]:
        work_items: list[tuple[str, str, Optional[Path]]] = []
        for rec in records:
            if not rec.file_name or not rec.analysis_db_path:
                continue
            abs_path = Path(resolve_db_path(rec.analysis_db_path, workspace_root))
            if not abs_path.exists():
                continue
            json_path = json_map.get(rec.file_name.lower())
            work_items.append((str(abs_path), rec.file_name, json_path))
        return work_items

    @staticmethod
    def _compute_source_fingerprint(
        work_items: list[tuple[str, str, Optional[Path]]],
    ) -> str:
        fingerprint_inputs: list[dict[str, Any]] = []
        for abs_path, file_name, json_path in work_items:
            source_path = Path(abs_path)
            source_kind = "db"
            if json_path is not None and json_path.is_file():
                source_path = json_path.resolve()
                source_kind = "json"
            try:
                source_mtime = source_path.stat().st_mtime
            except OSError:
                source_mtime = None
            fingerprint_inputs.append({
                "file_name": file_name,
                "source_kind": source_kind,
                "source_path": str(source_path),
                "source_mtime": source_mtime,
            })
        canonical = json.dumps(
            sorted(
                fingerprint_inputs,
                key=lambda item: (
                    item["file_name"].lower(),
                    item["source_kind"],
                    item["source_path"],
                ),
            ),
            ensure_ascii=False,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    # -- Serialization / deserialization ----------------------------

    _CACHE_VERSION = 1
    _CACHE_OPERATION = "import_export_index_full"

    def _serialize_index(self) -> dict[str, Any]:
        """Flatten internal indexes into a JSON-serializable dict."""
        exports: list[dict[str, Any]] = []
        for entries in self._module_exports.values():
            for e in entries:
                exports.append(e.to_dict())
        imports: list[dict[str, Any]] = []
        seen: set[int] = set()
        for entries in self._import_index.values():
            for imp in entries:
                oid = id(imp)
                if oid in seen:
                    continue
                seen.add(oid)
                imports.append(imp.to_dict())
        return {
            "version": self._CACHE_VERSION,
            "source_fingerprint": getattr(self, "_source_fingerprint", None),
            "exports": exports,
            "imports": imports,
        }

    def _deserialize_index(
        self,
        data: dict[str, Any],
        *,
        source_fingerprint: str | None = None,
    ) -> bool:
        """Reconstruct internal indexes from a serialized dict.

        Returns ``True`` on success, ``False`` if the data is invalid
        or uses an incompatible version.
        """
        if not isinstance(data, dict):
            return False
        if data.get("version") != self._CACHE_VERSION:
            return False
        if source_fingerprint is not None and data.get("source_fingerprint") != source_fingerprint:
            return False
        raw_exports = data.get("exports")
        raw_imports = data.get("imports")
        if not isinstance(raw_exports, list) or not isinstance(raw_imports, list):
            return False

        for d in raw_exports:
            if not isinstance(d, dict):
                continue
            entry = ExportEntry(
                module=d.get("module", ""),
                db_path=d.get("db_path", ""),
                name=d.get("name", ""),
                ordinal=d.get("ordinal", 0),
                is_forwarded=d.get("is_forwarded", False),
                forwarded_to=d.get("forwarded_to"),
            )
            if not entry.name:
                continue
            self._export_index[entry.name.lower()].append(entry)
            self._module_exports[entry.module.lower()].append(entry)

        for d in raw_imports:
            if not isinstance(d, dict):
                continue
            imp = ImportEntry(
                importing_module=d.get("importing_module", ""),
                source_module=d.get("source_module", ""),
                function_name=d.get("function_name", ""),
                is_delay_loaded=d.get("is_delay_loaded", False),
                ordinal=d.get("ordinal", 0),
            )
            if not imp.function_name:
                continue
            self._import_index[imp.function_name.lower()].append(imp)
            self._module_imports[imp.importing_module.lower()][
                imp.source_module.lower()
            ].append(imp.function_name)

        return True

    # -- Index build ------------------------------------------------

    def _build_index(self) -> None:
        """Scan all modules and populate internal indexes.

        On first run, scans every module and persists the full index to
        ``cache/`` via :func:`helpers.cache.cache_result`.  Subsequent
        runs load from the cache file (validated against the tracking
        DB's mtime) for near-instant startup.

        When ``no_cache`` is set, the cache is neither read nor written.
        """
        db_path = self._tracking_db_path or resolve_tracking_db(
            _auto_workspace_root()
        )
        if db_path is None:
            _log.debug("No tracking DB found; index will be empty")
            return

        max_modules = self._max_modules or get_config_value(
            "scale.max_modules_cross_scan", 0
        )

        try:
            with open_analyzed_files_db(db_path) as tracking:
                workspace_root = workspace_root_from_tracking_db(tracking.db_path)
                records = tracking.get_complete()
        except (FileNotFoundError, RuntimeError) as exc:
            log_warning(f"Cannot open tracking DB: {exc}", "DB_ERROR")
            return

        if max_modules and max_modules > 0 and len(records) > max_modules:
            log_warning(
                f"ImportExportIndex: {len(records)} modules exceed limit "
                f"({max_modules}). Loading first {max_modules} only.",
                "NO_DATA",
            )
            records = records[:max_modules]

        json_map = self._build_json_map(workspace_root)
        work_items = self._build_work_items(records, workspace_root, json_map)
        self._source_fingerprint = self._compute_source_fingerprint(work_items)

        if not self._no_cache:
            cached = get_cached(str(db_path), self._CACHE_OPERATION)
            if cached is not None and self._deserialize_index(
                cached,
                source_fingerprint=self._source_fingerprint,
            ):
                _log.debug("ImportExportIndex loaded from persistent cache")
                return

        total = len(work_items)
        max_workers: int = get_config_value("triage.max_workers", 4)

        def _scan_one(
            item: tuple[str, str, Optional[Path]],
        ) -> tuple[list[ExportEntry], list[ImportEntry], str]:
            abs_p, fname, jp = item
            try:
                if jp is not None and jp.is_file():
                    return (*self._scan_module_from_json(jp, fname, abs_p), fname)
                return (*self._scan_module_from_db(abs_p, fname), fname)
            except (OSError, RuntimeError, sqlite3.Error,
                    json.JSONDecodeError, KeyError, TypeError) as exc:
                log_warning(
                    f"Skipping {fname} during index build: {exc}", "DB_ERROR",
                )
                return [], [], fname

        completed = 0
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_scan_one, item): item for item in work_items}
            for future in as_completed(futures):
                completed += 1
                if total >= 500 and completed % 500 == 0:
                    print(
                        f"  ImportExportIndex: {completed}/{total} modules scanned...",
                        file=sys.stderr,
                    )
                exports, imports, fname = future.result()
                mod_lower = fname.lower()
                for entry in exports:
                    self._export_index[entry.name.lower()].append(entry)
                    self._module_exports[mod_lower].append(entry)
                for imp in imports:
                    self._import_index[imp.function_name.lower()].append(imp)
                    self._module_imports[mod_lower][imp.source_module.lower()].append(
                        imp.function_name
                    )

        if not self._no_cache:
            try:
                cache_result(
                    str(db_path), self._CACHE_OPERATION, self._serialize_index(),
                )
            except OSError as exc:
                _log.debug("Failed to write index cache: %s", exc)

    # -- Public query API -------------------------------------------

    def who_exports(self, function_name: str) -> list[ExportEntry]:
        """Find all modules whose PE export table contains *function_name*."""
        self._ensure_loaded()
        return list(self._export_index.get(function_name.lower(), []))

    def who_imports(
        self,
        function_name: str,
        *,
        from_module: Optional[str] = None,
    ) -> list[ImportEntry]:
        """Find all modules whose PE import table lists *function_name*.

        If *from_module* is given, only return entries where the import
        comes from that specific source module.
        """
        self._ensure_loaded()
        entries = self._import_index.get(function_name.lower(), [])
        if from_module is not None:
            from_lower = from_module.lower()
            entries = [
                e for e in entries if e.source_module.lower() == from_lower
            ]
        return list(entries)

    def module_consumers(
        self, module_name: str
    ) -> dict[str, list[str]]:
        """Return modules that import from *module_name*.

        Returns ``{importing_module: [function_names]}`` for every
        module whose PE import table references *module_name*.
        """
        self._ensure_loaded()
        target_lower = module_name.lower()
        result: dict[str, list[str]] = {}
        for entries in self._import_index.values():
            for imp in entries:
                if imp.source_module.lower() == target_lower:
                    result.setdefault(imp.importing_module, []).append(
                        imp.function_name
                    )
        return result

    def module_suppliers(
        self, module_name: str
    ) -> dict[str, list[str]]:
        """Return modules that *module_name* imports from.

        Returns ``{source_module: [function_names]}``.
        """
        self._ensure_loaded()
        mod_lower = module_name.lower()
        raw = self._module_imports.get(mod_lower, {})
        return {src: list(funcs) for src, funcs in raw.items()}

    def resolve_forwarder_chain(
        self,
        module: str,
        function: str,
        *,
        max_depth: int = 5,
    ) -> list[tuple[str, str]]:
        """Follow a forwarded export chain starting at *module*!*function*.

        Returns a list of ``(module, function)`` tuples representing each
        hop.  The first element is always the starting point.  The chain
        stops when a non-forwarded export is found, the target module is
        not in the analyzed set, or *max_depth* is reached.
        """
        self._ensure_loaded()
        chain: list[tuple[str, str]] = [(module, function)]
        visited: set[tuple[str, str]] = {(module.lower(), function.lower())}

        current_mod, current_func = module, function
        for _ in range(max_depth):
            exports = self.who_exports(current_func)
            target_exp: Optional[ExportEntry] = None
            for exp in exports:
                if exp.module.lower() == current_mod.lower() and exp.is_forwarded:
                    target_exp = exp
                    break

            if target_exp is None or not target_exp.forwarded_to:
                break

            fwd = target_exp.forwarded_to
            if "." in fwd:
                next_mod, next_func = fwd.split(".", 1)
                if not next_mod.lower().endswith(".dll"):
                    next_mod += ".dll"
            else:
                break

            key = (next_mod.lower(), next_func.lower())
            if key in visited:
                break
            visited.add(key)
            chain.append((next_mod, next_func))
            current_mod, current_func = next_mod, next_func

        return chain

    def dependency_graph(self) -> dict[str, set[str]]:
        """Module-to-module dependency edges from PE import tables.

        Returns ``{importing_module: {source_module, ...}}``.
        Keys and values use the original case from ``file_info``.
        """
        self._ensure_loaded()
        graph: dict[str, set[str]] = defaultdict(set)
        for entries in self._import_index.values():
            for imp in entries:
                graph[imp.importing_module].add(imp.source_module)
        return dict(graph)

    def module_export_list(self, module_name: str) -> list[ExportEntry]:
        """Return all exports for *module_name*."""
        self._ensure_loaded()
        return list(self._module_exports.get(module_name.lower(), []))

    def summary(self) -> dict[str, Any]:
        """Return aggregate statistics for the loaded index."""
        self._ensure_loaded()
        total_exports = sum(
            len(v) for v in self._module_exports.values()
        )
        total_imports = sum(
            len(v) for v in self._import_index.values()
        )
        forwarded_count = sum(
            1
            for entries in self._export_index.values()
            for e in entries
            if e.is_forwarded
        )
        return {
            "module_count": len(self._module_exports),
            "total_exports": total_exports,
            "total_imports": total_imports,
            "forwarded_count": forwarded_count,
            "unique_export_names": len(self._export_index),
            "unique_import_names": len(self._import_index),
        }
