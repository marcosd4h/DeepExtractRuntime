"""Unified directed call graph built from DeepExtractIDA analysis databases.

Consolidates graph construction, BFS/DFS traversal, reachability analysis,
Tarjan's SCC, and path-finding into a single shared module.  Previously
duplicated across:

  - callgraph-tracer/scripts/build_call_graph.py  (full ``CallGraph`` class)
  - security-dossier/scripts/_common.py            (``MiniCallGraph``)
  - map-attack-surface/scripts/_common.py          (``build_adjacency`` / ``compute_reachability``)
  - generate-re-report/scripts/analyze_topology.py (inline ``_build_call_graph``)

Usage::

    from helpers.callgraph import CallGraph

    # From a database path (with caching):
    graph = CallGraph.from_db(db_path)

    # From pre-loaded FunctionRecord objects (no caching):
    graph = CallGraph.from_functions(functions)

    # Query:
    reachable = graph.reachable_from("DllMain", max_depth=10)
    callers   = graph.callers_of("VulnFunc", max_depth=5)
    path      = graph.bfs_path("DllMain", "CreateProcessW")
    sccs      = graph.strongly_connected_components()
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Callable, Optional

from .errors import log_warning


# ===================================================================
# Xref filter constants
# ===================================================================
# Sentinel module_name values that represent non-call references
SKIP_MODULES = frozenset({"data"})
SKIP_FTYPES = frozenset({4})  # FT_MEM (data references only)

# vtable dispatch xrefs -- tracked separately but included in
# reachability queries by default since COM vtable calls are a
# primary attack surface on Windows.
VTABLE_MODULES = frozenset({"vtable"})
VTABLE_FTYPES = frozenset({8})  # FT_VTB


def _is_followable_xref(xref: dict, *, include_vtable: bool = True) -> bool:
    """Check if an outbound xref represents a followable function call.

    When *include_vtable* is True (the default), vtable dispatch
    references are treated as followable edges.  Pass False to
    restrict to direct calls only.
    """
    mod = (xref.get("module_name") or "").lower()
    ftype = xref.get("function_type", 0)
    if mod in SKIP_MODULES or ftype in SKIP_FTYPES:
        return False
    if not include_vtable and (mod in VTABLE_MODULES or ftype in VTABLE_FTYPES):
        return False
    return True


# ===================================================================
# CallGraph
# ===================================================================

class CallGraph:
    """Directed call graph built from simple_outbound_xrefs / simple_inbound_xrefs.

    Filters out non-call xrefs: data/global variable references
    (module_name="data", function_type=4) and vtable dispatch refs
    (module_name="vtable", function_type=8) are excluded from graph
    edges since they are not function calls.
    """

    def __init__(self) -> None:
        # function_name -> set of callee names (outbound edges)
        self.outbound: dict[str, set[str]] = defaultdict(set)
        # function_name -> set of caller names (inbound edges)
        self.inbound: dict[str, set[str]] = defaultdict(set)
        # function_name -> function_id (only for internal functions)
        self.name_to_id: dict[str, int] = {}
        # function_id -> function_name
        self.id_to_name: dict[int, str] = {}
        # External calls: function_name -> set of (callee_name, module_name)
        self.external_calls: dict[str, set[tuple[str, str]]] = defaultdict(set)
        # All known function names
        self.all_nodes: set[str] = set()
        # Module name for this graph
        self.module_name: str = ""
        # Lowercase name -> canonical name for O(1) exact lookup
        self._name_lower_index: dict[str, str] = {}
        # Edges originating from vtable xrefs (uncertain resolution)
        self.vtable_edges: set[tuple[str, str]] = set()

    # ------------------------------------------------------------------
    # Serialisation (for caching)
    # ------------------------------------------------------------------
    def _to_cacheable(self) -> dict:
        """Serialize graph to a JSON-safe dict (sets -> sorted lists)."""
        return {
            "module_name": self.module_name,
            "outbound": {k: sorted(v) for k, v in self.outbound.items()},
            "inbound": {k: sorted(v) for k, v in self.inbound.items()},
            "name_to_id": self.name_to_id,
            "id_to_name": {str(k): v for k, v in self.id_to_name.items()},
            "external_calls": {
                k: sorted([list(t) for t in v])
                for k, v in self.external_calls.items()
            },
            "all_nodes": sorted(self.all_nodes),
            "vtable_edges": sorted([list(t) for t in self.vtable_edges]),
        }

    @classmethod
    def _from_cached(cls, data: dict) -> "CallGraph":
        """Reconstruct a CallGraph from a cached dict.

        Validates the cached structure before reconstruction.  Raises on
        corrupt data so that :meth:`from_db` can fall back to rebuilding
        from the database.
        """
        required_keys = {
            "module_name", "outbound", "inbound", "name_to_id",
            "id_to_name", "external_calls", "all_nodes",
        }
        missing = required_keys - set(data.keys())
        if missing:
            log_warning(
                f"Cached call graph missing keys: {missing}", "PARSE_ERROR",
            )
            raise ValueError(f"Cached call graph missing keys: {missing}")

        try:
            graph = cls()
            graph.module_name = data.get("module_name", "")
            graph.outbound = defaultdict(set, {
                k: set(v) for k, v in data.get("outbound", {}).items()
            })
            graph.inbound = defaultdict(set, {
                k: set(v) for k, v in data.get("inbound", {}).items()
            })
            graph.name_to_id = data.get("name_to_id", {})
            graph.id_to_name = {
                int(k): v for k, v in data.get("id_to_name", {}).items()
            }
            graph.external_calls = defaultdict(set, {
                k: {tuple(t) for t in v}
                for k, v in data.get("external_calls", {}).items()
            })
            graph.all_nodes = set(data.get("all_nodes", []))
            graph._rebuild_name_index()
            return graph
        except (TypeError, ValueError, KeyError) as exc:
            log_warning(
                f"Cached call graph corrupt, rebuilding: {exc}",
                "PARSE_ERROR",
            )
            raise

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------
    @classmethod
    def from_db(cls, db_path: str, *, no_cache: bool = False) -> "CallGraph":
        """Build graph from an individual analysis database.

        Uses the helpers cache layer to avoid rebuilding on repeated calls.
        Requires ``helpers.cache`` and ``helpers.individual_analysis_db``.
        """
        from helpers.cache import cache_result, get_cached
        from helpers.individual_analysis_db import open_individual_analysis_db, parse_json_safe

        if not no_cache:
            cached = get_cached(db_path, "call_graph")
            if cached is not None:
                try:
                    return cls._from_cached(cached)
                except (TypeError, ValueError, KeyError):
                    pass  # warning already logged; fall through to rebuild

        graph = cls()

        with open_individual_analysis_db(db_path) as db:
            file_info = db.get_file_info()
            if file_info:
                graph.module_name = file_info.file_name or ""
            functions = db.get_all_functions()

        graph._ingest_functions(functions, parse_json_safe)

        cache_result(db_path, "call_graph", graph._to_cacheable())
        return graph

    @classmethod
    def from_functions(cls, functions, parse_json_safe=None) -> "CallGraph":
        """Build graph from a list of FunctionRecord objects (no caching).

        Useful when function records have already been loaded (e.g. by the
        security dossier builder which needs all records for other work too).

        *parse_json_safe* is optional -- if not supplied the one from helpers
        is imported automatically.
        """
        _parser = parse_json_safe
        if _parser is None:
            from helpers.individual_analysis_db import parse_json_safe as _default_parser
            _parser = _default_parser
        graph = cls()
        graph._ingest_functions(functions, _parser)
        return graph

    def _ingest_functions(self, functions, parse_json_safe) -> None:
        """Populate graph from a sequence of FunctionRecord-like objects or dicts.

        Accepts both FunctionRecord objects (attribute access) and plain dicts
        (key access, as returned by ``load_all_functions_slim``).  When xref
        data is already a parsed list the ``parse_json_safe`` step is skipped.
        """
        for func in functions:
            if isinstance(func, dict):
                fname = func.get("function_name")
                fid = func.get("function_id")
                raw_outbound = func.get("simple_outbound_xrefs") or func.get("outbound_xrefs")
                raw_inbound = func.get("simple_inbound_xrefs") or func.get("inbound_xrefs")
            else:
                fname = func.function_name
                fid = func.function_id
                raw_outbound = func.simple_outbound_xrefs
                raw_inbound = func.simple_inbound_xrefs

            if not fname:
                continue
            self.all_nodes.add(fname)
            self.name_to_id[fname] = fid
            self.id_to_name[fid] = fname

            # Process outbound xrefs (callees)
            outbound = raw_outbound if isinstance(raw_outbound, list) else parse_json_safe(raw_outbound)
            if outbound:
                for xref in outbound:
                    if not isinstance(xref, dict):
                        continue
                    callee = xref.get("function_name")
                    if not callee:
                        continue
                    if not _is_followable_xref(xref):
                        continue

                    callee_id = xref.get("function_id")
                    module = xref.get("module_name", "")

                    is_vtable = (
                        (module.lower() in VTABLE_MODULES)
                        or (xref.get("function_type", 0) in VTABLE_FTYPES)
                    )

                    self.outbound[fname].add(callee)
                    self.inbound[callee].add(fname)
                    self.all_nodes.add(callee)

                    if is_vtable:
                        self.vtable_edges.add((fname, callee))

                    if callee_id is None and module:
                        self.external_calls[fname].add((callee, module))

            # Process inbound xrefs (callers)
            inbound = raw_inbound if isinstance(raw_inbound, list) else parse_json_safe(raw_inbound)
            if inbound:
                for xref in inbound:
                    if not isinstance(xref, dict):
                        continue
                    caller = xref.get("function_name")
                    if not caller:
                        continue
                    if not _is_followable_xref(xref):
                        continue
                    self.inbound[fname].add(caller)
                    self.outbound[caller].add(fname)
                    self.all_nodes.add(caller)

        self._rebuild_name_index()

    def _rebuild_name_index(self) -> None:
        """Build the lowercase-name lookup index from all_nodes."""
        self._name_lower_index = {n.lower(): n for n in self.all_nodes}

    # ------------------------------------------------------------------
    # Node lookup
    # ------------------------------------------------------------------
    def find_function(self, name: str) -> Optional[str]:
        """Find a function by exact or partial name match (case-insensitive).

        Uses a pre-built lowercase index for O(1) exact matches.
        Falls back to substring scan only when exact match fails.
        """
        lower = name.lower()
        exact = self._name_lower_index.get(lower)
        if exact is not None:
            return exact
        matches = [n for n in self.all_nodes if lower in n.lower()]
        if len(matches) == 1:
            return matches[0]
        return None

    def find_function_by_id(self, function_id: int) -> Optional[str]:
        """Find a function by its numeric ID. Returns the canonical name or ``None``."""
        return self.id_to_name.get(function_id)

    def is_internal(self, name: str) -> bool:
        """Return True if *name* is an internal (defined) function."""
        return name in self.name_to_id

    # ------------------------------------------------------------------
    # Traversal: BFS forward (callees)
    # ------------------------------------------------------------------
    def reachable_from(self, start: str, max_depth: int = 0) -> dict[str, int]:
        """BFS forward to find all functions reachable from *start*.

        Returns ``{name: depth}`` where depth 0 is *start* itself.
        *max_depth* of 0 means unlimited.
        """
        if start not in self.all_nodes:
            return {}
        visited: dict[str, int] = {start: 0}
        queue: deque[tuple[str, int]] = deque([(start, 0)])
        while queue:
            current, depth = queue.popleft()
            if 0 < max_depth <= depth:
                continue
            for neighbor in self.outbound.get(current, set()):
                if neighbor not in visited:
                    visited[neighbor] = depth + 1
                    queue.append((neighbor, depth + 1))
        return visited

    def reachable_from_internal_only(
        self, start: str, max_depth: int = 10,
    ) -> dict[str, int]:
        """BFS forward following only internal (defined) functions.

        Useful for attack-surface reachability where you only want to
        traverse functions that exist in the module.
        """
        if start not in self.all_nodes:
            return {}
        visited: dict[str, int] = {start: 0}
        queue: deque[tuple[str, int]] = deque([(start, 0)])
        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for neighbor in self.outbound.get(current, set()):
                if neighbor not in visited and neighbor in self.name_to_id:
                    visited[neighbor] = depth + 1
                    queue.append((neighbor, depth + 1))
        return visited

    # ------------------------------------------------------------------
    # Traversal: BFS reverse (callers)
    # ------------------------------------------------------------------
    def callers_of(self, target: str, max_depth: int = 0) -> dict[str, int]:
        """BFS reverse to find all transitive callers of *target*.

        Returns ``{name: depth}``.  *max_depth* of 0 means unlimited.
        """
        if target not in self.all_nodes:
            return {}
        visited: dict[str, int] = {target: 0}
        queue: deque[tuple[str, int]] = deque([(target, 0)])
        while queue:
            current, depth = queue.popleft()
            if 0 < max_depth <= depth:
                continue
            for caller in self.inbound.get(current, set()):
                if caller not in visited:
                    visited[caller] = depth + 1
                    queue.append((caller, depth + 1))
        return visited

    # ------------------------------------------------------------------
    # ID-based traversal helpers
    # ------------------------------------------------------------------
    def ancestors(self, function_id: int, max_depth: int = 0) -> set[int]:
        """Return set of function IDs that can reach *function_id* (transitive callers).

        Delegates to :meth:`callers_of` and maps names back to IDs.
        *max_depth* of 0 means unlimited.
        """
        name = self.id_to_name.get(function_id)
        if name is None:
            return set()
        callers = self.callers_of(name, max_depth)
        return {self.name_to_id[n] for n in callers if n in self.name_to_id}

    def descendants(self, function_id: int, max_depth: int = 0) -> set[int]:
        """Return set of function IDs reachable from *function_id* (transitive callees).

        Delegates to :meth:`reachable_from` and maps names back to IDs.
        *max_depth* of 0 means unlimited.
        """
        name = self.id_to_name.get(function_id)
        if name is None:
            return set()
        reachable = self.reachable_from(name, max_depth)
        return {self.name_to_id[n] for n in reachable if n in self.name_to_id}

    def shortest_path(self, source_id: int, target_id: int) -> Optional[list[str]]:
        """Shortest path from *source_id* to *target_id*, returned as function names.

        Thin wrapper over :meth:`bfs_path` that accepts function IDs.
        Returns ``None`` if either ID is unknown or no path exists.
        """
        source = self.id_to_name.get(source_id)
        target = self.id_to_name.get(target_id)
        if source is None or target is None:
            return None
        return self.bfs_path(source, target)

    # ------------------------------------------------------------------
    # Path finding
    # ------------------------------------------------------------------
    def bfs_path(self, source: str, target: str) -> Optional[list[str]]:
        """Find shortest path from *source* to *target* using BFS.

        Uses a parent-pointer map for memory-efficient path reconstruction
        instead of carrying full path copies in the queue.
        """
        if source not in self.all_nodes or target not in self.all_nodes:
            return None
        if source == target:
            return [source]

        visited = {source}
        parent: dict[str, str] = {}
        queue: deque[str] = deque([source])

        while queue:
            current = queue.popleft()
            for neighbor in self.outbound.get(current, set()):
                if neighbor not in visited:
                    parent[neighbor] = current
                    if neighbor == target:
                        path = [target]
                        node = target
                        while node != source:
                            node = parent[node]
                            path.append(node)
                        path.reverse()
                        return path
                    visited.add(neighbor)
                    queue.append(neighbor)
        return None

    def all_paths(
        self, source: str, target: str, max_depth: int = 10, max_paths: int = 100,
    ) -> list[list[str]]:
        """Find all paths from *source* to *target* up to *max_depth*.

        *max_paths* caps the number of paths returned to prevent
        exponential blowup on graphs with high fan-out or diamond patterns.
        """
        paths: list[list[str]] = []
        if source not in self.all_nodes or target not in self.all_nodes:
            return paths

        def _dfs(current: str, path: list[str], visited: set[str]) -> None:
            if len(paths) >= max_paths:
                return
            if len(path) > max_depth:
                return
            if current == target:
                paths.append(list(path))
                return
            for neighbor in self.outbound.get(current, set()):
                if neighbor not in visited and len(paths) < max_paths:
                    visited.add(neighbor)
                    path.append(neighbor)
                    _dfs(neighbor, path, visited)
                    path.pop()
                    visited.discard(neighbor)

        _dfs(source, [source], {source})
        return paths

    def shortest_path_reverse(
        self, target: str, sources: set[str], max_depth: int = 10,
    ) -> Optional[list[str]]:
        """BFS upward from *target* to any node in *sources*.

        Returns the path in forward order (source -> ... -> target).
        Uses a parent-pointer map for memory-efficient reconstruction.
        """
        if target in sources:
            return [target]
        visited = {target}
        # parent[node] = the node we discovered it from (in reverse direction)
        parent: dict[str, str] = {}
        queue: deque[tuple[str, int]] = deque([(target, 0)])
        while queue:
            cur, depth = queue.popleft()
            if depth > max_depth:
                continue
            for caller in self.inbound.get(cur, set()):
                if caller not in visited:
                    parent[caller] = cur
                    if caller in sources:
                        # Reconstruct path: caller -> ... -> target
                        path = [caller]
                        node = caller
                        while node != target:
                            node = parent[node]
                            path.append(node)
                        return path
                    visited.add(caller)
                    queue.append((caller, depth + 1))
        return None

    # ------------------------------------------------------------------
    # Structural queries
    # ------------------------------------------------------------------
    def strongly_connected_components(self) -> list[list[str]]:
        """Tarjan's SCC algorithm (iterative).  Returns components with > 1 node.

        Uses an explicit call stack to avoid Python's recursion limit on
        graphs with 2000+ nodes and deep call chains.
        """
        index_counter = 0
        scc_stack: list[str] = []
        lowlinks: dict[str, int] = {}
        index: dict[str, int] = {}
        on_stack: set[str] = set()
        result: list[list[str]] = []

        for start in sorted(self.all_nodes):
            if start in index:
                continue

            # Explicit DFS stack: (node, iterator_over_successors, is_root_call)
            call_stack: list[tuple[str, list[str], int]] = []
            index[start] = index_counter
            lowlinks[start] = index_counter
            index_counter += 1
            scc_stack.append(start)
            on_stack.add(start)
            successors = sorted(self.outbound.get(start, set()))
            call_stack.append((start, successors, 0))

            while call_stack:
                v, succs, si = call_stack[-1]
                if si < len(succs):
                    call_stack[-1] = (v, succs, si + 1)
                    w = succs[si]
                    if w not in index:
                        index[w] = index_counter
                        lowlinks[w] = index_counter
                        index_counter += 1
                        scc_stack.append(w)
                        on_stack.add(w)
                        w_succs = sorted(self.outbound.get(w, set()))
                        call_stack.append((w, w_succs, 0))
                    elif w in on_stack:
                        lowlinks[v] = min(lowlinks[v], index[w])
                else:
                    if lowlinks[v] == index[v]:
                        component: list[str] = []
                        while True:
                            w = scc_stack.pop()
                            on_stack.discard(w)
                            component.append(w)
                            if w == v:
                                break
                        if len(component) > 1:
                            result.append(sorted(component))
                    call_stack.pop()
                    if call_stack:
                        parent = call_stack[-1][0]
                        lowlinks[parent] = min(lowlinks[parent], lowlinks[v])

        return result

    def leaf_functions(self) -> list[str]:
        """Functions that are called but don't call anything."""
        return sorted(
            n for n in self.all_nodes
            if not self.outbound.get(n) and self.inbound.get(n)
        )

    def root_functions(self) -> list[str]:
        """Functions that call others but are not called."""
        return sorted(
            n for n in self.all_nodes
            if self.outbound.get(n) and not self.inbound.get(n)
        )

    def entry_points_and_exports(self) -> tuple[list[str], list[str]]:
        """Functions that are roots or have no internal callers."""
        roots = self.root_functions()
        external_entry = sorted(
            n for n in self.all_nodes
            if n in self.name_to_id
            and all(c not in self.name_to_id for c in self.inbound.get(n, set()))
            and n not in roots
        )
        return roots, external_entry

    def neighbors(self, name: str) -> tuple[set[str], set[str]]:
        """Return (callees, callers) for a function."""
        return self.outbound.get(name, set()), self.inbound.get(name, set())

    def max_depth_from(self, start: str, max_depth: int = 50) -> int:
        """Compute max call depth from a starting node (BFS-based)."""
        if start not in self.all_nodes:
            return 0
        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(start, 0)])
        max_d = 0
        while queue:
            node, depth = queue.popleft()
            if node in visited or depth > max_depth:
                continue
            visited.add(node)
            max_d = max(max_d, depth)
            for neighbor in self.outbound.get(node, set()):
                if neighbor not in visited:
                    queue.append((neighbor, depth + 1))
        return max_d

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------
    def stats(self) -> dict:
        """Return summary statistics dict."""
        internal_nodes = len(self.name_to_id)
        total_edges = sum(len(v) for v in self.outbound.values())
        external_edges = sum(len(v) for v in self.external_calls.values())
        return {
            "module": self.module_name,
            "internal_functions": internal_nodes,
            "total_nodes": len(self.all_nodes),
            "external_targets": len(self.all_nodes) - internal_nodes,
            "total_edges": total_edges,
            "external_edges": external_edges,
            "internal_edges": total_edges - external_edges,
        }

    # ------------------------------------------------------------------
    # ID-based helpers (for topology analysis, attack-surface ranking)
    # ------------------------------------------------------------------
    def id_forward_edges(self) -> dict[int, set[int]]:
        """Return caller_id -> {callee_ids} for internal functions only."""
        forward: dict[int, set[int]] = defaultdict(set)
        for fname, callees in self.outbound.items():
            caller_id = self.name_to_id.get(fname)
            if caller_id is None:
                continue
            for callee_name in callees:
                callee_id = self.name_to_id.get(callee_name)
                if callee_id is not None:
                    forward[caller_id].add(callee_id)
        return forward

    def id_reverse_edges(self) -> dict[int, set[int]]:
        """Return callee_id -> {caller_ids} for internal functions only."""
        reverse: dict[int, set[int]] = defaultdict(set)
        for fname, callers in self.inbound.items():
            callee_id = self.name_to_id.get(fname)
            if callee_id is None:
                continue
            for caller_name in callers:
                caller_id = self.name_to_id.get(caller_name)
                if caller_id is not None:
                    reverse[callee_id].add(caller_id)
        return reverse

    def id_external_calls(self) -> dict[int, list[str]]:
        """Return function_id -> [external callee names]."""
        result: dict[int, list[str]] = defaultdict(list)
        for fname, externals in self.external_calls.items():
            fid = self.name_to_id.get(fname)
            if fid is not None:
                result[fid] = sorted(callee for callee, _mod in externals)
        return result
