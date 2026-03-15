"""Cross-module call graph resolution and traversal.

Provides :class:`ModuleResolver` (promoted from the callgraph-tracer skill)
to resolve external xrefs to their implementing module DBs, and
:class:`CrossModuleGraph` to build and traverse call graphs spanning
multiple modules.

Previously the module-resolution logic was duplicated across 7+ scripts:

- ``callgraph-tracer/scripts/cross_module_resolve.py`` (most complete)
- ``re-analyst/scripts/explain_function.py``
- ``resolve_module_db()`` in 4+ ``_common.py`` files

Usage::

    from helpers.cross_module_graph import ModuleResolver, CrossModuleGraph

    resolver = ModuleResolver()
    info = resolver.resolve_xref("kernel32.dll", "CreateProcessW")

    graph = CrossModuleGraph.from_tracking_db()
    reachable = graph.reachable_from("appinfo.dll", "DllMain", max_depth=5)
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import threading
from collections import OrderedDict, defaultdict, deque
from pathlib import Path
from typing import Any, Optional

from .analyzed_files_db import AnalyzedFilesDB, open_analyzed_files_db
from .callgraph import CallGraph
from .config import get_config_value
from .db_paths import (
    _auto_workspace_root,
    resolve_db_path,
    resolve_tracking_db,
    workspace_root_from_tracking_db,
)
from .errors import log_warning

_log = logging.getLogger(__name__)

_GUID_RE = re.compile(
    r'\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?'
)


def _xref_result_key(module_name: str, function_name: str) -> str:
    """Build a collision-free key for a cross-module xref lookup."""
    return f"{module_name}!{function_name}"


def resolve_forwarded_export(
    module_name: str, function_name: str
) -> Optional[tuple[str, str]]:
    """Check ``file_info.json`` for a forwarded export and resolve it.

    PE forwarded exports have the form ``target_dll.FunctionName`` in
    their definition.  This function scans the module's ``file_info.json``
    exports list for entries containing ``->`` (the forwarding marker
    added by IDA / DeepExtractIDA) and returns the resolved
    ``(target_module, target_function)`` tuple or ``None``.
    """
    workspace = _auto_workspace_root()
    if workspace is None:
        return None

    code_dir = Path(workspace) / "extracted_code"
    module_stem = module_name.rsplit(".", 1)[0] if "." in module_name else module_name
    module_dir_candidates = [
        code_dir / module_stem.replace(".", "_"),
        code_dir / module_name.replace(".", "_"),
    ]

    for module_dir in module_dir_candidates:
        fi_path = module_dir / "file_info.json"
        if not fi_path.exists():
            continue
        try:
            fi = json.loads(fi_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue

        exports = fi.get("exports")
        if not isinstance(exports, list):
            continue

        for exp in exports:
            if not isinstance(exp, dict):
                continue
            exp_name = exp.get("name", "")
            if exp_name.lower() != function_name.lower():
                continue
            definition = exp.get("definition", "") or exp.get("forward", "")
            if "->" in definition:
                target = definition.split("->", 1)[1].strip()
            elif "." in definition:
                target = definition.strip()
            else:
                continue

            if "." in target:
                target_module, target_func = target.rsplit(".", 1)
                if not target_module.lower().endswith(".dll"):
                    target_module += ".dll"
                return (target_module, target_func)
        break

    return None


# ===================================================================
# ModuleResolver
# ===================================================================

class ModuleResolver:
    """Resolve module names and function names across all analyzed modules.

    Lazily loads the tracking DB index on first use, then caches
    module-name -> (db_path, file_name) mappings for fast repeated
    lookups.

    Supports context-manager usage for deterministic cleanup of cached
    DB connections::

        with ModuleResolver() as resolver:
            info = resolver.resolve_function("CreateProcessW")

    Thread Safety
    -------------
    All lazy-initialization paths (module index, connection cache,
    function-name index) are protected by an internal lock, making
    ``ModuleResolver`` safe to share across threads.

    Resource Management
    -------------------
    DB connections are cached with LRU eviction to prevent file-handle
    exhaustion.  Pool size defaults to ``scale.max_cached_connections``
    from config (default 50).  When the pool is full the
    least-recently-used connection is closed before a new one is opened.
    """

    def __init__(
        self,
        tracking_db: Optional[str] = None,
        max_cached_connections: int | None = None,
    ) -> None:
        if max_cached_connections is None:
            max_cached_connections = get_config_value("scale.max_cached_connections", 50)
        self._tracking_db_path = tracking_db
        self._module_cache: dict[str, tuple[str, str]] = {}
        self._loaded = False
        self._lock = threading.RLock()
        self._connection_cache: OrderedDict[str, Any] = OrderedDict()
        self._max_cached_connections = max(1, max_cached_connections)
        self._function_name_index: Optional[dict[str, list[tuple[str, str]]]] = None
        self._closed = False

    def __enter__(self) -> "ModuleResolver":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def close(self) -> None:
        """Close all cached DB connections and release resources."""
        with self._lock:
            for db in self._connection_cache.values():
                try:
                    db.close()
                except (OSError, sqlite3.Error):
                    pass
            self._connection_cache.clear()
            self._function_name_index = None
            self._closed = True

    # -- Internal bookkeeping ------------------------------------------

    def _ensure_loaded(self) -> None:
        if getattr(self, "_closed", False):
            raise RuntimeError("ModuleResolver has been closed")
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            db_path = self._tracking_db_path or resolve_tracking_db(
                _auto_workspace_root()
            )
            if db_path is None:
                log_warning(
                    "No tracking DB found for cross-module resolution. "
                    "Cross-module queries will return no results until "
                    "an analyzed_files.db workspace is available.",
                    "NOT_FOUND",
                )
                self._loaded = True
                return
            try:
                with open_analyzed_files_db(db_path) as db:
                    workspace_root = workspace_root_from_tracking_db(db.db_path)
                    for rec in db.get_complete():
                        if rec.file_name and rec.analysis_db_path:
                            abs_path = Path(
                                resolve_db_path(rec.analysis_db_path, workspace_root)
                            )
                            if abs_path.exists():
                                key = rec.file_name.lower()
                                self._module_cache[key] = (
                                    str(abs_path),
                                    rec.file_name,
                                )
            except FileNotFoundError as exc:
                log_warning(
                    f"Tracking DB not found for cross-module resolution: {exc}",
                    "NOT_FOUND",
                )
            except RuntimeError as exc:
                log_warning(
                    f"Failed to load tracking DB for cross-module resolution: {exc}",
                    "DB_ERROR",
                )
            self._loaded = True

    def _get_cached_db(self, db_path: str) -> Any:
        """Return a cached :class:`IndividualAnalysisDB` for *db_path*.

        Opens (and caches) a new connection on the first call for each
        *db_path*.  Subsequent calls return the same handle.  Access to
        the cache is protected by ``_lock`` so this method is safe to
        call from multiple threads.

        When the cache exceeds *max_cached_connections*, the
        least-recently-used connection is evicted and closed.
        """
        if getattr(self, "_closed", False):
            raise RuntimeError("ModuleResolver has been closed")
        with self._lock:
            if db_path in self._connection_cache:
                self._connection_cache.move_to_end(db_path)
                return self._connection_cache[db_path]

            self._evict_if_full()

            from .individual_analysis_db import open_individual_analysis_db

            db = open_individual_analysis_db(db_path)
            try:
                db._ensure_open()
            except Exception:
                db.close()
                raise
            self._connection_cache[db_path] = db
            _log.debug("Opened DB connection: %s (pool: %d/%d)",
                        db_path, len(self._connection_cache),
                        self._max_cached_connections)
            return db

    def _evict_if_full(self) -> None:
        """Evict and close the least-recently-used connection if the pool is full."""
        while len(self._connection_cache) >= self._max_cached_connections:
            _, evicted = self._connection_cache.popitem(last=False)
            try:
                evicted.close()
            except (OSError, sqlite3.Error):
                pass

    def _build_function_name_index(self) -> None:
        """Build a cross-module function-name index (once).

        Maps ``lower(function_name) -> [(db_path, file_name), ...]``
        across every analyzed module so that :meth:`resolve_function`
        can skip modules that definitely lack a given name.

        Reads ``function_index.json`` files from ``extracted_code/``
        instead of opening SQLite DBs, which is ~10-100x faster at
        scale (6000+ modules).  Falls back to DB-based indexing for
        modules without a JSON index.
        """
        if self._function_name_index is not None:
            return
        with self._lock:
            if self._function_name_index is not None:
                return

            from .function_index.index import load_function_index

            module_count = len(self._module_cache)
            index: dict[str, list[tuple[str, str]]] = {}
            indexed = 0
            for db_path, file_name in self._module_cache.values():
                indexed += 1
                if module_count >= 500 and indexed % 500 == 0:
                    import sys
                    print(
                        f"  Building function name index: {indexed}/{module_count} modules...",
                        file=sys.stderr,
                    )

                func_names: list[str] | None = None

                # Fast path: read function_index.json (no DB connection)
                try:
                    fi = load_function_index(file_name, warn_on_missing=False)
                    if fi is not None:
                        func_names = list(fi.keys())
                except (OSError, ValueError) as exc:
                    _log.debug("JSON index failed for %s: %s", file_name, exc)

                # Slow fallback: open the DB
                if func_names is None:
                    try:
                        db = self._get_cached_db(db_path)
                        func_names = list(db.get_function_names())
                    except (OSError, RuntimeError, sqlite3.Error) as exc:
                        log_warning(f"Failed to index {file_name}: {exc}", "DB_ERROR")
                        continue

                for name in func_names:
                    if name:
                        index.setdefault(name.lower(), []).append(
                            (db_path, file_name)
                        )
            self._function_name_index = index

    # -- Public API ----------------------------------------------------

    def get_module_db(self, module_name: str) -> Optional[tuple[str, str]]:
        """Return ``(db_path, file_name)`` for *module_name*, or ``None``.

        Matching is case-insensitive on the file name stored in the
        tracking DB.
        """
        self._ensure_loaded()
        return self._module_cache.get(module_name.lower())

    def list_modules(self) -> list[tuple[str, str]]:
        """Return ``[(file_name, db_path), ...]`` for all analyzed modules."""
        self._ensure_loaded()
        return [(fname, dbpath) for dbpath, fname in self._module_cache.values()]

    def resolve_function(
        self,
        function_name: str,
        *,
        fuzzy: bool = False,
        max_results: int = 50,
    ) -> list[dict[str, Any]]:
        """Search analyzed modules for a function by name.

        Returns a list of dicts with keys ``module``, ``db_path``,
        ``function_name``, ``function_id``.  Empty list if not found.

        Uses an internal cross-module function-name index (built lazily
        on first call) to skip modules that lack an exact match.

        Parameters
        ----------
        fuzzy:
            If True, also perform substring search across modules not
            matched by exact lookup.  Disabled by default to avoid
            scanning thousands of DBs at scale.
        max_results:
            Stop collecting after this many matches.
        """
        self._ensure_loaded()
        self._build_function_name_index()

        results: list[dict[str, Any]] = []
        exact_key = function_name.lower()
        seen_db_paths: set[str] = set()

        assert self._function_name_index is not None

        # Phase 1: exact match via cross-module index (fast path)
        for db_path, file_name in self._function_name_index.get(exact_key, []):
            if len(results) >= max_results:
                break
            seen_db_paths.add(db_path)
            try:
                db = self._get_cached_db(db_path)
                matches = db.get_function_by_name(function_name)
                for func in matches:
                    results.append({
                        "module": file_name,
                        "db_path": db_path,
                        "function_name": func.function_name,
                        "function_id": func.function_id,
                        "has_decompiled": bool(func.decompiled_code),
                    })
                    if len(results) >= max_results:
                        break
            except (OSError, RuntimeError, sqlite3.Error) as exc:
                log_warning(f"Skipping {file_name} during resolve: {exc}", "DB_ERROR")
                continue

        # Phase 1b: forwarded export fallback
        if not results:
            for db_path_entry, file_name_entry in self._module_cache.values():
                fwd = resolve_forwarded_export(file_name_entry, function_name)
                if fwd:
                    target_mod, target_func = fwd
                    fwd_results = self.resolve_function(
                        target_func, fuzzy=False, max_results=max_results,
                    )
                    if fwd_results:
                        results.extend(fwd_results)
                    break

        # Phase 2: substring search -- opt-in and bounded
        if fuzzy and len(results) < max_results:
            max_cross_scan: int = get_config_value(
                "scale.max_modules_cross_scan", 0
            )
            scanned = 0
            for db_path, file_name in self._module_cache.values():
                if db_path in seen_db_paths:
                    continue
                if (max_cross_scan > 0 and scanned >= max_cross_scan) or len(results) >= max_results:
                    break
                scanned += 1
                try:
                    db = self._get_cached_db(db_path)
                    matches = db.search_functions(name_contains=function_name)
                    for func in matches:
                        results.append({
                            "module": file_name,
                            "db_path": db_path,
                            "function_name": func.function_name,
                            "function_id": func.function_id,
                            "has_decompiled": bool(func.decompiled_code),
                        })
                        if len(results) >= max_results:
                            break
                except (OSError, RuntimeError, sqlite3.Error) as exc:
                    log_warning(f"Skipping {file_name} during search: {exc}", "DB_ERROR")
                    continue

        return results

    def resolve_xref(
        self, module_name: str, function_name: str
    ) -> Optional[dict[str, Any]]:
        """Resolve a single external xref to its target module.

        Returns a dict with ``module``, ``db_path``, ``function_name``,
        ``function_id``, ``has_decompiled``, or ``None`` if the target
        module is not analyzed.
        """
        entry = self.get_module_db(module_name)
        if entry is None:
            return None
        db_path, file_name = entry

        try:
            db = self._get_cached_db(db_path)
            matches = db.get_function_by_name(function_name)
            if matches:
                func = matches[0]
                return {
                    "module": file_name,
                    "db_path": db_path,
                    "function_name": func.function_name,
                    "function_id": func.function_id,
                    "function_signature": func.function_signature or "",
                    "has_decompiled": bool(func.decompiled_code),
                    "has_assembly": bool(func.assembly_code),
                }
        except (OSError, RuntimeError, sqlite3.Error) as exc:
            log_warning(f"Failed to resolve xref {module_name}!{function_name}: {exc}", "DB_ERROR")
        return {
            "module": file_name,
            "db_path": db_path,
            "function_name": function_name,
            "function_id": None,
            "function_signature": "",
            "has_decompiled": False,
            "has_assembly": False,
            "note": "module analyzed but function not found in DB",
        }

    def batch_resolve_xrefs(
        self, xrefs: list[dict[str, Any]]
    ) -> dict[str, Optional[dict[str, Any]]]:
        """Resolve multiple external xrefs in one pass.

        *xrefs* is a list of dicts with at least ``function_name`` and
        ``module_name`` keys (as found in ``simple_outbound_xrefs``).

        Returns ``{"<module>!<function>": resolved_dict | None}``.
        Keying by both module and function preserves duplicate symbol
        names across modules instead of overwriting earlier results.
        Uses the internal module cache to avoid repeated DB opens.
        """
        results: dict[str, Optional[dict[str, Any]]] = {}
        grouped: dict[str, list[tuple[str, str]]] = defaultdict(list)

        for xref in xrefs:
            fname = xref.get("function_name", "")
            mod = xref.get("module_name", "")
            if fname and mod:
                grouped[mod.lower()].append((mod, fname))
                results[_xref_result_key(mod, fname)] = None

        for mod_lower, xref_entries in grouped.items():
            entry = self.get_module_db(mod_lower)
            if entry is None:
                continue
            db_path, file_name = entry
            try:
                db = self._get_cached_db(db_path)
                by_name = db.get_functions_by_names(
                    [name for _module_name, name in xref_entries]
                )
                for input_module, name in xref_entries:
                    matches = by_name.get(name, [])
                    if matches:
                        func = matches[0]
                        results[_xref_result_key(input_module, name)] = {
                            "module": file_name,
                            "db_path": db_path,
                            "function_name": func.function_name,
                            "function_id": func.function_id,
                            "has_decompiled": bool(func.decompiled_code),
                        }
            except (OSError, RuntimeError, sqlite3.Error) as exc:
                log_warning(f"Skipping {file_name} during batch resolve: {exc}", "DB_ERROR")
                continue

        return results


# ===================================================================
# CrossModuleGraph
# ===================================================================

class CrossModuleGraph:
    """Call graph spanning multiple modules.

    Wraps per-module :class:`CallGraph` instances and stitches them
    together using :class:`ModuleResolver` to follow external calls
    across module boundaries.

    Supports context-manager usage for deterministic cleanup of the
    internal resolver's cached DB connections::

        with CrossModuleGraph.from_tracking_db() as graph:
            reachable = graph.reachable_from("appinfo.dll", "DllMain")
    """

    def __init__(self) -> None:
        self._graphs: dict[str, CallGraph] = {}
        self._resolver = ModuleResolver()
        self._module_deps: dict[str, set[str]] = defaultdict(set)

    def close(self) -> None:
        """Close all cached DB connections held by the internal resolver."""
        self._resolver.close()

    def __enter__(self) -> "CrossModuleGraph":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    @classmethod
    def from_tracking_db(
        cls,
        tracking_db: Optional[str] = None,
        modules: Optional[list[str]] = None,
    ) -> "CrossModuleGraph":
        """Build a cross-module graph from the tracking DB.

        Parameters
        ----------
        tracking_db:
            Path to ``analyzed_files.db``.  Auto-detected if ``None``.
        modules:
            Optional list of module file names (e.g. ``["appinfo.dll"]``)
            to include.  ``None`` means all analyzed modules (subject
            to ``scale.max_modules_cross_scan``; 0 = unlimited).
        """
        cm = cls()
        cm._resolver = ModuleResolver(tracking_db)

        available = cm._resolver.list_modules()
        targets = available
        if modules:
            want = {m.lower() for m in modules}
            targets = [(fn, dp) for fn, dp in available if fn.lower() in want]
        else:
            max_scan: int = get_config_value("scale.max_modules_cross_scan", 0)
            if max_scan > 0 and len(targets) > max_scan:
                log_warning(
                    f"CrossModuleGraph: {len(targets)} modules available but "
                    f"limit is {max_scan}. Pass an explicit module list or "
                    f"increase scale.max_modules_cross_scan. Loading first "
                    f"{max_scan} modules only.",
                    "NO_DATA",
                )
                targets = targets[:max_scan]

        import sys
        total = len(targets)
        for i, (file_name, db_path) in enumerate(targets, 1):
            if total >= 500 and i % 500 == 0:
                print(
                    f"  CrossModuleGraph: loaded {i}/{total} modules...",
                    file=sys.stderr,
                )
            try:
                graph = CallGraph.from_db(db_path)
                key = file_name.lower()
                cm._graphs[key] = graph
            except (OSError, RuntimeError, sqlite3.Error) as exc:
                log_warning(f"Failed to load call graph for {file_name}: {exc}", "DB_ERROR")
                continue

        cm._build_module_deps()
        return cm

    def _build_module_deps(self) -> None:
        """Scan external_calls in each module graph to build dependency map."""
        for mod_key, graph in self._graphs.items():
            for _caller, ext_calls in graph.external_calls.items():
                for _callee_name, target_module in ext_calls:
                    target_lower = target_module.lower()
                    if target_lower != mod_key and target_lower in self._graphs:
                        self._module_deps[mod_key].add(target_lower)

    def module_dependency_map(self) -> dict[str, set[str]]:
        """Return ``{module_name: set_of_modules_it_calls}`` (lowercase keys)."""
        return dict(self._module_deps)

    def get_module_graph(self, module_name: str) -> Optional[CallGraph]:
        """Return the per-module CallGraph for *module_name*."""
        return self._graphs.get(module_name.lower())

    def reachable_from(
        self,
        module: str,
        function: str,
        max_depth: int = 10,
    ) -> dict[str, dict[str, int]]:
        """Cross-module BFS from *function* in *module*.

        Returns ``{module_name: {function_name: depth}}`` where depth is
        the hop count from the starting function.  Traversal follows
        external calls into other loaded modules, and any injected IPC
        edges (RPC, COM, WinRT).
        """
        mod_key = module.lower()
        start_graph = self._graphs.get(mod_key)
        if start_graph is None:
            return {}

        resolved = start_graph.find_function(function)
        if resolved is None:
            return {}

        result: dict[str, dict[str, int]] = defaultdict(dict)
        result[mod_key][resolved] = 0

        # Queue entries: (module_key, function_name, depth)
        queue: deque[tuple[str, str, int]] = deque([(mod_key, resolved, 0)])
        visited: set[tuple[str, str]] = {(mod_key, resolved)}

        while queue:
            cur_mod, cur_func, depth = queue.popleft()
            if 0 < max_depth <= depth:
                continue

            cur_graph = self._graphs.get(cur_mod)
            if cur_graph is None:
                continue

            # Follow internal edges
            for callee in cur_graph.outbound.get(cur_func, set()):
                key = (cur_mod, callee)
                if key not in visited:
                    visited.add(key)
                    result[cur_mod][callee] = depth + 1
                    if cur_graph.is_internal(callee):
                        queue.append((cur_mod, callee, depth + 1))

            # Follow external edges into other loaded modules
            for callee_name, target_module in cur_graph.external_calls.get(cur_func, set()):
                target_key = target_module.lower()
                target_graph = self._graphs.get(target_key)
                if target_graph is None:
                    continue
                target_func = target_graph.find_function(callee_name)
                if target_func is None:
                    continue
                key = (target_key, target_func)
                if key not in visited:
                    visited.add(key)
                    result[target_key][target_func] = depth + 1
                    queue.append((target_key, target_func, depth + 1))

            # Follow injected IPC edges (RPC, COM, WinRT)
            ipc_edges = getattr(cur_graph, "ipc_edges", {})
            for proc_name, server_mod, _ipc_id in ipc_edges.get(cur_mod, set()):
                target_graph = self._graphs.get(server_mod)
                if target_graph is None:
                    continue
                target_func = target_graph.find_function(proc_name)
                if target_func is None:
                    continue
                key = (server_mod, target_func)
                if key not in visited:
                    visited.add(key)
                    result[server_mod][target_func] = depth + 1
                    queue.append((server_mod, target_func, depth + 1))

        return dict(result)

    # NdrClientCall* API names used to identify RPC client modules
    _NDR_CLIENT_APIS = frozenset({
        "ndrclientcall", "ndrclientcall2", "ndrclientcall3",
        "ndrasyncclientcall",
    })

    def _add_ipc_edge(
        self,
        client_graph: CallGraph,
        client_key: str,
        server_key: str,
        proc_name: str,
        ipc_id: str,
    ) -> None:
        """Register a single IPC edge on the client graph."""
        if not hasattr(client_graph, "ipc_edges"):
            client_graph.ipc_edges = {}
        client_graph.ipc_edges.setdefault(client_key, set()).add(
            (proc_name, server_key, ipc_id)
        )
        self._module_deps[client_key].add(server_key)

    def inject_rpc_edges(self) -> int:
        """Add cross-process RPC edges from the RPC index.

        For each RPC interface in the index, creates edges from client
        modules (containing NdrClientCall stubs) to server modules
        (implementing the handler procedures).  These edges represent
        cross-process RPC invocations that the normal import/export
        analysis cannot see.

        When the index contains explicit client entries (``is_client=True``),
        those are used directly.  When no client entries exist (common with
        NtApiDotNet extraction data), a fallback heuristic kicks in: any
        loaded module that imports ``NdrClientCall*`` runtime APIs is
        treated as a potential RPC client and paired with known servers.

        Returns the number of RPC edges added.
        """
        try:
            from .rpc_index import get_rpc_index
        except ImportError:
            return 0

        idx = get_rpc_index()
        if not idx.loaded:
            return 0

        added = 0

        # Phase 1: explicit client entries from the index
        for uuid_key, ifaces in idx._by_uuid.items():
            servers = [i for i in ifaces if not i.is_client]
            clients = [i for i in ifaces if i.is_client]

            if not servers or not clients:
                continue

            for client_iface in clients:
                client_key = client_iface.binary_name.lower()
                client_graph = self._graphs.get(client_key)
                if client_graph is None:
                    continue

                for server_iface in servers:
                    server_key = server_iface.binary_name.lower()
                    if server_key not in self._graphs:
                        continue

                    for proc_name in server_iface.procedure_names:
                        if not hasattr(client_graph, 'rpc_edges'):
                            client_graph.rpc_edges = {}
                        client_graph.rpc_edges.setdefault(client_key, set()).add(
                            (proc_name, server_key, uuid_key)
                        )
                        self._add_ipc_edge(client_graph, client_key, server_key, proc_name, f"rpc:{uuid_key}")
                        added += 1

        # Phase 2: fallback -- infer clients from NdrClientCall* imports
        if added == 0 and idx.loaded:
            stub_added = self._inject_rpc_edges_from_ndr_heuristic(idx)
            added += stub_added

        if added:
            _log.info("Injected %d RPC cross-process edges", added)
        return added

    def _inject_rpc_edges_from_ndr_heuristic(self, idx) -> int:
        """Fallback: infer client-server RPC edges via NdrClientCall* imports.

        Scans every loaded module graph for external calls to NdrClientCall,
        NdrClientCall2, NdrClientCall3, or NdrAsyncClientCall.  Modules that
        import these APIs are potential RPC clients.  For each interface UUID
        with server implementations, edges are created from every such
        potential-client module (excluding the server module itself) to the
        server's procedures.
        """
        ndr_caller_modules: set[str] = set()
        for mod_key, graph in self._graphs.items():
            for _caller, ext_calls in graph.external_calls.items():
                for callee_name, _target_mod in ext_calls:
                    bare = callee_name.lstrip("_")
                    if bare.startswith("imp_"):
                        bare = bare[4:]
                    if bare.lower() in self._NDR_CLIENT_APIS:
                        ndr_caller_modules.add(mod_key)
                        break
                if mod_key in ndr_caller_modules:
                    break

        if not ndr_caller_modules:
            _log.debug("No modules import NdrClientCall* APIs; "
                       "skipping stub-based RPC edge inference")
            return 0

        added = 0
        for uuid_key, ifaces in idx._by_uuid.items():
            servers = [i for i in ifaces if not i.is_client]
            if not servers:
                continue

            server_keys = {s.binary_name.lower() for s in servers}
            loaded_server_keys = server_keys & set(self._graphs.keys())
            if not loaded_server_keys:
                continue

            potential_clients = ndr_caller_modules - server_keys

            for client_key in potential_clients:
                client_graph = self._graphs.get(client_key)
                if client_graph is None:
                    continue

                for server_key in loaded_server_keys:
                    server_ifaces = [
                        s for s in servers
                        if s.binary_name.lower() == server_key
                    ]
                    for server_iface in server_ifaces:
                        for proc_name in server_iface.procedure_names:
                            if not hasattr(client_graph, 'rpc_edges'):
                                client_graph.rpc_edges = {}
                            client_graph.rpc_edges.setdefault(
                                client_key, set()
                            ).add((proc_name, server_key, uuid_key))
                            self._add_ipc_edge(client_graph, client_key, server_key, proc_name, f"rpc:{uuid_key}")
                            added += 1

        _log.info(
            "Stub-based heuristic: added %d RPC edges from %d "
            "NdrClientCall* caller modules",
            added, len(ndr_caller_modules),
        )
        return added

    def get_rpc_edges(self) -> list[dict[str, str]]:
        """Return all RPC cross-process edges as a flat list of dicts."""
        edges: list[dict[str, str]] = []
        for _mod_key, graph in self._graphs.items():
            rpc_edges = getattr(graph, 'rpc_edges', {})
            for client_mod, targets in rpc_edges.items():
                for proc_name, server_mod, uuid in targets:
                    edges.append({
                        "client_module": client_mod,
                        "server_module": server_mod,
                        "procedure": proc_name,
                        "interface_uuid": uuid,
                    })
        return edges

    # COM activation APIs whose callers are treated as COM clients
    _COM_ACTIVATION_APIS = frozenset({
        "cocreateinstance", "cocreateinstanceex",
        "cogetclassobject", "cogetobject",
        "clsidfromprogid", "clsidfromprogidex",
    })

    @staticmethod
    def _is_com_activation_api(name: str) -> bool:
        """Check if a function name is a COM activation API after stripping IDA prefixes."""
        bare = name.lstrip("_")
        if bare.startswith("imp_"):
            bare = bare[4:]
        return bare.lower() in CrossModuleGraph._COM_ACTIVATION_APIS

    def _find_com_caller_functions(self, graph: "CallGraph") -> dict[str, set[str]]:
        """Return ``{caller_function: {com_api_names_called}}`` for COM-calling functions."""
        callers: dict[str, set[str]] = {}
        for caller, ext_calls in graph.external_calls.items():
            for callee_name, _target_mod in ext_calls:
                if self._is_com_activation_api(callee_name):
                    callers.setdefault(caller, set()).add(callee_name)
        return callers

    def _has_com_activation_apis(self, graph: "CallGraph") -> bool:
        """Check if any function in the graph calls COM activation APIs."""
        for _caller, ext_calls in graph.external_calls.items():
            for callee_name, _target_mod in ext_calls:
                if self._is_com_activation_api(callee_name):
                    return True
        return False

    def _module_display_name(self, mod_key: str) -> str:
        """Get the original-case file_name for a lowercase module key."""
        for fn, _dp in self._resolver.list_modules():
            if fn.lower() == mod_key:
                return fn
        return mod_key

    def _resolve_clsids_at_callsites(
        self,
        mod_key: str,
        graph: "CallGraph",
        com_callers: dict[str, set[str]],
    ) -> dict[int, set[str]]:
        """Resolve CLSIDs referenced at COM activation call sites.

        For each function that calls a COM activation API, extracts CLSID
        references from the structured ``string_literals`` field in the DB
        (IDA-extracted string data).  Uses _GUID_RE only to validate and
        parse GUID patterns within those strings.  No regex on decompiled
        code.

        Returns ``{function_id: set_of_clsid_identifiers}`` where each
        identifier is a lowercase GUID string (without braces).
        """
        entry = self._resolver.get_module_db(mod_key)
        if entry is None:
            return {}
        db_path, _file_name = entry

        try:
            db = self._resolver._get_cached_db(db_path)
        except (OSError, RuntimeError, sqlite3.Error):
            return {}

        result: dict[int, set[str]] = {}

        for func_name in com_callers:
            func_id = graph.name_to_id.get(func_name)
            if func_id is None:
                continue

            try:
                record = db.get_function_by_id(func_id)
            except (OSError, sqlite3.Error):
                continue
            if record is None:
                continue

            clsids: set[str] = set()

            # GUID literals from structured string_literals (no regex on code)
            try:
                strings_raw = (
                    json.loads(record.string_literals)
                    if record.string_literals
                    else []
                )
            except (json.JSONDecodeError, TypeError):
                strings_raw = []

            for s in strings_raw:
                text = (
                    s
                    if isinstance(s, str)
                    else (s.get("value", "") if isinstance(s, dict) else str(s))
                )
                for gm in _GUID_RE.finditer(text):
                    clsids.add(gm.group().strip("{}").lower())

            if clsids:
                result[func_id] = clsids

        return result

    def _resolve_clsid_to_servers(self, clsid_ref: str, idx: Any) -> list:
        """Resolve a CLSID identifier to :class:`ComServer` objects.

        Handles both raw GUID strings and symbolic ``CLSID_Xxx`` names.
        """
        normalized = clsid_ref.strip()

        if _GUID_RE.fullmatch(normalized):
            if not normalized.startswith("{"):
                normalized = "{" + normalized + "}"
            server = idx.get_server_by_clsid(normalized)
            return [server] if server else []

        lower = normalized.lower()
        return [
            srv for srv in idx._servers
            if lower in srv.name.lower().replace(" ", "")
        ]

    def _get_unresolved_com_callers(
        self,
        graph: "CallGraph",
        com_callers: dict[str, set[str]],
        resolved: dict[int, set[str]],
    ) -> set[str]:
        """Find functions that call COM APIs but have no resolved CLSIDs."""
        resolved_ids = set(resolved.keys())
        unresolved: set[str] = set()
        for func_name in com_callers:
            func_id = graph.name_to_id.get(func_name)
            if func_id is None or func_id not in resolved_ids:
                unresolved.add(func_name)
        return unresolved

    def _clsid_matches(self, server: Any, clsids: set[str], idx: Any) -> bool:
        """Check if a COM server matches any of the resolved CLSIDs."""
        server_guid = server.clsid.strip("{}").lower()
        if server_guid in clsids:
            return True
        if server.clsid.lower() in clsids:
            return True
        for ref in clsids:
            if not _GUID_RE.fullmatch(ref):
                if ref.lower() in server.name.lower().replace(" ", ""):
                    return True
        return False

    def inject_com_edges(self) -> int:
        """Add cross-process COM activation edges from the COM index.

        Resolves CLSIDs at call sites when possible so that edges are
        targeted to the specific COM servers referenced by each client
        module.  Falls back to broad connectivity (tagged with
        ``:unresolved``) when CLSID resolution fails or the analysis DB
        is unavailable.

        Returns the number of COM edges added.
        """
        try:
            from .com_index import get_com_index
        except ImportError:
            return 0

        idx = get_com_index()
        if not idx.loaded:
            return 0

        # Phase 1: find functions calling COM activation APIs per module
        com_caller_modules: dict[str, dict[str, set[str]]] = {}
        for mod_key, graph in self._graphs.items():
            callers = self._find_com_caller_functions(graph)
            if callers:
                com_caller_modules[mod_key] = callers

        if not com_caller_modules:
            return 0

        # Phase 2: resolve CLSIDs at call sites
        module_resolved: dict[str, dict[int, set[str]]] = {}
        module_all_clsids: dict[str, set[str]] = {}
        for mod_key, callers in com_caller_modules.items():
            graph = self._graphs[mod_key]
            resolved = self._resolve_clsids_at_callsites(mod_key, graph, callers)
            if resolved:
                module_resolved[mod_key] = resolved
                merged: set[str] = set()
                for s in resolved.values():
                    merged.update(s)
                module_all_clsids[mod_key] = merged

        # Phase 3: inject edges
        added = 0
        for client_key, callers in com_caller_modules.items():
            client_graph = self._graphs.get(client_key)
            if client_graph is None:
                continue

            resolved_clsids = module_all_clsids.get(client_key, set())
            graph = self._graphs[client_key]

            if resolved_clsids:
                # Targeted edges: only connect to servers matching resolved CLSIDs
                seen: set[tuple[str, str]] = set()
                for clsid_ref in resolved_clsids:
                    for server in self._resolve_clsid_to_servers(clsid_ref, idx):
                        server_key = server.hosting_binary.lower()
                        if server_key not in self._graphs or server_key == client_key:
                            continue
                        for method in server.methods_flat:
                            edge = (server_key, method.name)
                            if edge not in seen:
                                seen.add(edge)
                                self._add_ipc_edge(
                                    client_graph, client_key, server_key,
                                    method.name, f"com:{server_key}",
                                )
                                added += 1

                # Broad fallback for functions whose CLSIDs could not be resolved
                unresolved = self._get_unresolved_com_callers(
                    graph, callers, module_resolved.get(client_key, {}),
                )
                if unresolved:
                    for server_mod_key in self._graphs:
                        if server_mod_key == client_key:
                            continue
                        procs = idx.get_procedures_for_module(
                            self._module_display_name(server_mod_key)
                        )
                        for proc_name in procs:
                            edge = (server_mod_key, proc_name)
                            if edge not in seen:
                                seen.add(edge)
                                self._add_ipc_edge(
                                    client_graph, client_key, server_mod_key,
                                    proc_name, f"com:{server_mod_key}:unresolved",
                                )
                                added += 1
            else:
                # No CLSIDs resolved at all -- full broad fallback
                for server_mod_key in self._graphs:
                    if server_mod_key == client_key:
                        continue
                    procs = idx.get_procedures_for_module(
                        self._module_display_name(server_mod_key)
                    )
                    for proc_name in procs:
                        self._add_ipc_edge(
                            client_graph, client_key, server_mod_key,
                            proc_name, f"com:{server_mod_key}:unresolved",
                        )
                        added += 1

        if added:
            _log.info("Injected %d COM cross-process edges", added)
        return added

    # WinRT activation APIs
    _WINRT_ACTIVATION_APIS = frozenset({
        "roactivateinstance", "rogetactivationfactory",
    })

    def inject_winrt_edges(self) -> int:
        """Add cross-process WinRT activation edges from the WinRT index.

        Scans loaded module graphs for calls to RoActivateInstance-family
        APIs.  Modules making these calls are treated as WinRT clients.
        For each WinRT server known from the index, edges are created from
        every client module to the server's method implementations.

        Returns the number of WinRT edges added.
        """
        try:
            from .winrt_index import get_winrt_index
        except ImportError:
            return 0

        idx = get_winrt_index()
        if not idx.loaded:
            return 0

        winrt_caller_modules: set[str] = set()
        for mod_key, graph in self._graphs.items():
            for _caller, ext_calls in graph.external_calls.items():
                for callee_name, _target_mod in ext_calls:
                    bare = callee_name.lstrip("_")
                    if bare.startswith("imp_"):
                        bare = bare[4:]
                    if bare.lower() in self._WINRT_ACTIVATION_APIS:
                        winrt_caller_modules.add(mod_key)
                        break
                if mod_key in winrt_caller_modules:
                    break

        if not winrt_caller_modules:
            return 0

        added = 0
        for server_mod_key, graph in self._graphs.items():
            procs = idx.get_procedures_for_module(
                next((fn for fn, dp in self._resolver.list_modules()
                      if dp == server_mod_key or fn.lower() == server_mod_key), server_mod_key)
            )
            if not procs:
                continue

            for client_key in winrt_caller_modules:
                if client_key == server_mod_key:
                    continue
                client_graph = self._graphs.get(client_key)
                if client_graph is None:
                    continue
                for proc_name in procs:
                    self._add_ipc_edge(client_graph, client_key, server_mod_key, proc_name, f"winrt:{server_mod_key}")
                    added += 1

        if added:
            _log.info("Injected %d WinRT cross-process edges", added)
        return added

    def build_unified_adjacency(self) -> dict[tuple[str, str], set[tuple[str, str]]]:
        """Return a single adjacency dict keyed by ``(module, function)`` tuples.

        Merges all per-module internal edges, cross-module external
        edges, and injected IPC edges into one unified graph.  Useful
        for whole-workspace reachability queries.
        """
        adj: dict[tuple[str, str], set[tuple[str, str]]] = defaultdict(set)

        for mod_key, graph in self._graphs.items():
            for caller, callees in graph.outbound.items():
                caller_key = (mod_key, caller)
                for callee in callees:
                    if graph.is_internal(callee):
                        adj[caller_key].add((mod_key, callee))

            for caller, ext_calls in graph.external_calls.items():
                caller_key = (mod_key, caller)
                for callee_name, target_module in ext_calls:
                    target_key = target_module.lower()
                    target_graph = self._graphs.get(target_key)
                    if target_graph is not None:
                        resolved = target_graph.find_function(callee_name)
                        if resolved:
                            adj[caller_key].add((target_key, resolved))

            ipc_edges = getattr(graph, "ipc_edges", {})
            for _client_mod, targets in ipc_edges.items():
                for proc_name, server_mod, _ipc_id in targets:
                    target_graph = self._graphs.get(server_mod)
                    if target_graph is not None:
                        resolved = target_graph.find_function(proc_name)
                        if resolved:
                            for caller in graph.all_nodes:
                                if graph.is_internal(caller):
                                    adj[(mod_key, caller)].add((server_mod, resolved))

        return dict(adj)

    def inject_all_ipc_edges(self) -> dict[str, int]:
        """Inject RPC, COM, and WinRT edges in one call.

        Returns ``{"rpc": N, "com": N, "winrt": N}`` with edge counts.
        """
        return {
            "rpc": self.inject_rpc_edges(),
            "com": self.inject_com_edges(),
            "winrt": self.inject_winrt_edges(),
        }
