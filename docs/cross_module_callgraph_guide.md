# Cross-Module Callgraph Extraction Guide

Definitive reference for building, traversing, and querying callgraphs that
span multiple Windows PE modules in the DeepExtractIDA workspace. Covers
forward and backward traversal, IPC edge injection (RPC/COM/WinRT), depth
control, and all available helpers and scripts.

## Table of Contents

1. [Overview](#1-overview)
2. [Data Foundation](#2-data-foundation)
3. [Helper Classes](#3-helper-classes)
4. [Forward Traversal (Callees)](#4-forward-traversal-callees)
5. [Backward Traversal (Callers)](#5-backward-traversal-callers)
6. [Cross-Module Resolution](#6-cross-module-resolution)
7. [IPC Edge Injection](#7-ipc-edge-injection)
8. [Depth Control](#8-depth-control)
9. [Path Finding and Structure Queries](#9-path-finding-and-structure-queries)
10. [Available Scripts](#10-available-scripts)
11. [Choosing the Right Tool](#11-choosing-the-right-tool)
12. [Internals: How It Works](#12-internals-how-it-works)
13. [Performance and Caching](#13-performance-and-caching)
14. [Common Patterns](#14-common-patterns)

---

## 1. Overview

A callgraph maps which functions call which other functions. In a multi-module
Windows binary analysis workspace, callgraphs cross DLL boundaries -- an RPC
handler in `srvsvc.dll` calls `HeapAlloc` in `kernel32.dll`, which forwards
to `RtlAllocateHeap` in `ntdll.dll`.

Three levels of callgraph are available:

| Level | Scope | Helper | Code Included |
|-------|-------|--------|---------------|
| **Single-module** | One DLL/EXE | `CallGraph` | No |
| **Cross-module** | All analyzed modules | `CrossModuleGraph` | No |
| **Chain with code** | Rooted subtree | `ChainAnalyzer` | Yes (decompiled) |

For AI-driven scanning, use `CrossModuleGraph` for structure and
`extract_function_data.py` for on-demand code retrieval (the pattern
documented in the [AI Scanner Authoring Guide](ai_scanner_authoring_guide.md)).

---

## 2. Data Foundation

### Source: IDA xrefs in analysis DBs

Every function record in the per-module analysis DB contains:

- **`simple_outbound_xrefs`** -- JSON list of callees. Each entry:
  ```json
  {
    "function_name": "HeapAlloc",
    "module_name": "kernel32.dll",
    "function_id": null,
    "function_type": 1
  }
  ```
  - `function_id` is set for same-module calls, `null` for cross-module
  - `module_name` is the target module (`null` or same module for internal)
  - `function_type`: 1=normal call, 4=data ref, 8=vtable dispatch

- **`simple_inbound_xrefs`** -- JSON list of callers (same format, reversed direction)

### Xref filtering

Not all xrefs are call edges. The callgraph helpers filter:

- **Followed:** Normal calls (`function_type` != 4), vtable dispatches (type 8, optional)
- **Skipped:** Data references (`module_name == "data"` or `function_type == 4`)
- **Configurable:** Vtable edges can be included or excluded

### Tracking DB (`analyzed_files.db`)

The tracking DB maps module names to their analysis DB paths. It is the
bridge that enables cross-module resolution:

```python
from helpers.analyzed_files_db import open_analyzed_files_db
with open_analyzed_files_db() as db:
    for record in db.get_complete():
        print(record.file_name, record.analysis_db_path)
```

---

## 3. Helper Classes

### `CallGraph` (`helpers/callgraph.py`)

Single-module callgraph built from one analysis DB's xrefs.

```python
from helpers.callgraph import CallGraph

graph = CallGraph.from_db("extracted_dbs/srvsvc_dll_abc123.db")
```

**Key attributes:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `outbound` | `dict[str, set[str]]` | caller -> set of callee names |
| `inbound` | `dict[str, set[str]]` | callee -> set of caller names |
| `external_calls` | `dict[str, set[tuple[str, str]]]` | caller -> set of (callee, target_module) |
| `name_to_id` | `dict[str, int]` | function name -> function_id (internal only) |
| `all_nodes` | `set[str]` | all function names (internal + external targets) |
| `vtable_edges` | `set[tuple[str, str]]` | edges from vtable dispatches |
| `module_name` | `str` | module file name |

**Key methods:**

| Method | Direction | Cross-module | Returns |
|--------|-----------|-------------|---------|
| `reachable_from(start, max_depth)` | Forward | No (single module) | `{name: depth}` |
| `callers_of(target, max_depth)` | Backward | No | `{name: depth}` |
| `reachable_from_internal_only(start, max_depth)` | Forward | No (internal only) | `{name: depth}` |
| `bfs_path(source, target)` | Forward | No | `[name, ...]` or None |
| `all_paths(source, target, max_depth, max_paths)` | Forward | No | `[[name, ...], ...]` |
| `strongly_connected_components()` | Both | No | `[[name, ...], ...]` |

### `CrossModuleGraph` (`helpers/cross_module_graph.py`)

Multi-module callgraph that stitches per-module `CallGraph` objects together
via external call resolution and IPC edge injection.

```python
from helpers.cross_module_graph import CrossModuleGraph

with CrossModuleGraph.from_tracking_db() as graph:
    graph.inject_all_ipc_edges()
    reachable = graph.reachable_from("srvsvc.dll", "NetrShareGetInfo", max_depth=5)
```

**Key methods:**

| Method | Direction | Returns |
|--------|-----------|---------|
| `reachable_from(module, function, max_depth)` | Forward | `{module: {function: depth}}` |
| `build_unified_adjacency()` | Both | `{(mod, func): set of (mod, func)}` |
| `inject_all_ipc_edges()` | N/A | `{rpc: N, com: N, winrt: N}` |
| `get_module_graph(module_name)` | N/A | `CallGraph` or None |
| `module_dependency_map()` | Forward | `{module: set of modules}` |

### `ModuleResolver` (`helpers/cross_module_graph.py`)

Resolves function names and xrefs to their implementing module DBs.

```python
from helpers.cross_module_graph import ModuleResolver

resolver = ModuleResolver()
result = resolver.resolve_xref("kernel32.dll", "HeapAlloc")
# {"module": "kernel32.dll", "db_path": "...", "function_id": 42, "has_decompiled": True, ...}
```

### `ChainAnalyzer` (`callgraph-tracer/scripts/chain_analysis.py`)

Produces a nested tree from a root function, following xrefs across modules,
with decompiled code at each node. This is the only helper that returns code.

```python
from helpers.script_runner import load_skill_module
chain = load_skill_module("callgraph-tracer", "chain_analysis")
analyzer = chain.ChainAnalyzer()
data = analyzer.collect_chain_data(db_path, function_name="NetrShareGetInfo", max_depth=3)
```

Returns nested dicts with: `function_name`, `module_name`, `decompiled_code`,
`xrefs` (classified), `children` (recursive).

---

## 4. Forward Traversal (Callees)

### Single-module forward BFS

```python
graph = CallGraph.from_db(db_path)
callees = graph.reachable_from("MyFunction", max_depth=5)
# {"MyFunction": 0, "HelperA": 1, "HelperB": 2, "HeapAlloc": 3, ...}
```

Returns `{function_name: depth}`. Depth 0 is the start. `max_depth=0` means
unlimited. Includes both internal and external (imported) functions.

For internal functions only (no cross-module targets):

```python
internal_callees = graph.reachable_from_internal_only("MyFunction", max_depth=5)
```

### Cross-module forward BFS

```python
with CrossModuleGraph.from_tracking_db() as graph:
    graph.inject_all_ipc_edges()
    reachable = graph.reachable_from("srvsvc.dll", "NetrShareGetInfo", max_depth=5)
    # {
    #   "srvsvc.dll": {"NetrShareGetInfo": 0, "SsShareInfoGet": 1, ...},
    #   "kernel32.dll": {"HeapAlloc": 3, "HeapFree": 4},
    #   "ntdll.dll": {"RtlAllocateHeap": 4, ...},
    # }
```

**Algorithm:** BFS starting from `(module, function)`. At each node:

1. Follow **internal edges** via `graph.outbound[func]`
2. Follow **external edges** via `graph.external_calls[func]` -- resolves
   the target function in the target module's loaded `CallGraph`
3. Follow **IPC edges** via `graph.ipc_edges` -- crosses RPC/COM/WinRT
   boundaries to server module procedures

All three edge types are traversed uniformly. The result maps every reachable
function to its module and hop depth.

### Forward chain with code

```python
analyzer = ChainAnalyzer()
tree = analyzer.collect_chain_data(db_path, function_name="NetrShareGetInfo", max_depth=3)
# Nested dict with decompiled_code at each node
```

Returns a tree structure. Each node includes `decompiled_code` (but NOT
`assembly_code`). Cross-module callees are followed when their module has an
analysis DB in the tracking DB.

---

## 5. Backward Traversal (Callers)

### Single-module backward BFS

```python
graph = CallGraph.from_db(db_path)
callers = graph.callers_of("HeapAlloc", max_depth=3)
# {"HeapAlloc": 0, "AllocWrapper": 1, "ProcessRequest": 2, "NetrShareEnum": 3}
```

Follows `graph.inbound` edges (who calls this function). Same depth semantics
as forward BFS.

### ID-based backward traversal

```python
ancestor_ids = graph.ancestors(function_id=42, max_depth=5)
# {1, 7, 15, ...}  -- set of function IDs
```

Returns only internal function IDs (not external imports).

### Cross-module backward traversal

`CrossModuleGraph` does not have a dedicated `callers_of` method. To find
cross-module callers:

1. Use `build_unified_adjacency()` to get the full edge map
2. Invert it to get `{(mod, func): set of (mod, func)}` for callers
3. BFS backward from your target

```python
with CrossModuleGraph.from_tracking_db() as graph:
    graph.inject_all_ipc_edges()
    adj = graph.build_unified_adjacency()

    # Invert: build caller map
    callers_map = defaultdict(set)
    for src, targets in adj.items():
        for tgt in targets:
            callers_map[tgt].add(src)

    # BFS backward from target
    target = ("srvsvc.dll", "HeapAlloc")
    visited = {target: 0}
    queue = deque([(target, 0)])
    while queue:
        current, depth = queue.popleft()
        if max_depth > 0 and depth >= max_depth:
            continue
        for caller in callers_map.get(current, set()):
            if caller not in visited:
                visited[caller] = depth + 1
                queue.append((caller, depth + 1))
```

### Reverse path finding

```python
graph = CallGraph.from_db(db_path)
path = graph.shortest_path_reverse("HeapAlloc", sources=["NetrShareEnum", "ServiceMain"], max_depth=10)
# ["NetrShareEnum", "SsShareEnumSticky", "SsAllocBuffer", "HeapAlloc"]
```

Finds the shortest path from any source to the target, traversing backward.

---

## 6. Cross-Module Resolution

When a function in module A calls a function in module B, the callgraph needs
to resolve which analyzed module implements that function.

### How resolution works

1. **Module lookup:** `ModuleResolver.get_module_db("kernel32.dll")` returns
   `(db_path, file_name)` from the tracking DB.

2. **Function lookup:** Open the target module's DB and search for the function
   by name. `ModuleResolver.resolve_xref("kernel32.dll", "HeapAlloc")` returns
   the function record with `function_id`, `has_decompiled`, `has_assembly`.

3. **Forwarded exports:** If a function is not found directly, PE forwarded
   exports are checked. `resolve_forwarded_export("kernel32.dll", "HeapAlloc")`
   checks `file_info.json` exports for forwarding markers (`->` or `.`
   notation) and resolves to the actual implementing module.

4. **Module name normalization:** All module names are lowercased for lookup.
   Extensions are preserved (`kernel32.dll`, not `kernel32`).

### Batch resolution

For resolving many xrefs at once (more efficient):

```python
resolver = ModuleResolver()
xrefs = [
    {"function_name": "HeapAlloc", "module_name": "kernel32.dll"},
    {"function_name": "memcpy", "module_name": "ntdll.dll"},
]
results = resolver.batch_resolve_xrefs(xrefs)
# {"kernel32.dll!HeapAlloc": {...}, "ntdll.dll!memcpy": {...}}
```

### Global function search

When you don't know which module contains a function:

```python
resolver = ModuleResolver()
matches = resolver.resolve_function("CreateProcessW", fuzzy=True)
# [{"module": "kernel32.dll", "db_path": "...", "function_id": 123, "has_decompiled": True}, ...]
```

---

## 7. IPC Edge Injection

Standard callgraph edges come from direct function calls (import/export
relationships). IPC edges represent inter-process communication paths that
are invisible at the call level -- an RPC client calls `NdrClientCall2` which
at runtime dispatches to a server procedure in a different process/module.

### Injecting all IPC edges

```python
with CrossModuleGraph.from_tracking_db() as graph:
    counts = graph.inject_all_ipc_edges()
    # {"rpc": 3062, "com": 10730, "winrt": 0}
```

### RPC edges

**Source:** RPC index (`helpers.rpc_index.get_rpc_index()`)

**Logic:**
1. For each RPC interface UUID, find server modules and client modules
2. Explicit clients: modules that implement the client-side stubs
3. Heuristic clients: modules that import `NdrClientCall*` functions
4. For each (client, server) pair, add edges from client to each server procedure

**Edge format:** `(procedure_name, server_module, "rpc:<uuid>")`

### COM edges

**Source:** COM index (`helpers.com_index.get_com_index()`)

**Logic:**
1. Find COM server modules (those that register CLSIDs)
2. Find COM client modules (those that call `CoCreateInstance`, `CoGetClassObject`, etc.)
3. **CLSID-based filtering:** Edges are only injected between a client and
   server when the client references a CLSID that the server registers.
   This prevents the O(N*M) explosion of connecting every COM client to
   every COM server. The CLSID filter uses string literal analysis on
   client functions to identify referenced CLSIDs and matches them against
   the COM index's CLSID-to-module mapping.
4. Add edges from matched client functions to the corresponding server procedures

**Edge format:** `(procedure_name, server_module, "com:<clsid>")`

### WinRT edges

**Source:** WinRT index (`helpers.winrt_index.get_winrt_index()`)

**Logic:** Same pattern as COM but with `RoActivateInstance`/`RoGetActivationFactory`
as client indicators.

**Edge format:** `(procedure_name, server_module, "winrt:<server_module>")`

### How IPC edges are traversed

IPC edges are stored as `graph.ipc_edges` on the client's `CallGraph`. During
BFS in `CrossModuleGraph.reachable_from()`, after processing internal and
external edges, IPC edges are checked. If the server module is loaded and the
procedure name resolves, the edge is followed.

This means: if you inject IPC edges, a forward BFS from an RPC client function
will cross the RPC boundary and continue into the server module's procedure
implementations.

---

## 8. Depth Control

All traversal methods use `max_depth` to limit expansion:

| Method | `max_depth=0` | `max_depth=N` | Depth 0 |
|--------|---------------|---------------|---------|
| `CallGraph.reachable_from()` | Unlimited | Stop at depth N | Start function |
| `CallGraph.callers_of()` | Unlimited | Stop at depth N | Target function |
| `CrossModuleGraph.reachable_from()` | Unlimited (dangerous) | Stop at depth N | Start function |
| `ChainAnalyzer.collect_chain_data()` | Start only | Follow to depth N | Start function |

**Depth semantics:**
- Depth 0 = the start/target function itself
- Depth 1 = direct callees/callers
- Depth N = N hops from the start

**Practical guidance:**
- Depth 3: covers most direct call chains (good for focused analysis)
- Depth 5: covers typical RPC handler -> internal logic -> API call chains
- Depth 10+: very large graphs, may include thousands of nodes
- `max_depth=0` on `CrossModuleGraph`: use with caution, can traverse the
  entire workspace

---

## 9. Path Finding and Structure Queries

### Shortest path between functions

```python
graph = CallGraph.from_db(db_path)
path = graph.bfs_path("NetrShareEnum", "HeapAlloc")
# ["NetrShareEnum", "SsShareEnumSticky", "SsAllocBuffer", "HeapAlloc"]
```

### All paths (bounded)

```python
paths = graph.all_paths("NetrShareEnum", "HeapAlloc", max_depth=6, max_paths=50)
# [["NetrShareEnum", "SsShareEnumSticky", ...], ["NetrShareEnum", "SsShareEnumTransient", ...], ...]
```

### Strongly connected components (recursive clusters)

```python
sccs = graph.strongly_connected_components()
# [["FuncA", "FuncB", "FuncC"], ...]  -- only components with 2+ nodes
```

### Root and leaf functions

```python
roots = graph.root_functions()    # Functions that call others but aren't called
leaves = graph.leaf_functions()   # Functions that are called but call nothing
```

### Module-to-module dependencies

```python
with CrossModuleGraph.from_tracking_db() as graph:
    deps = graph.module_dependency_map()
    # {"srvsvc.dll": {"kernel32.dll", "ntdll.dll", "rpcrt4.dll"}, ...}
```

---

## 10. Available Scripts

### From the callgraph-tracer skill

| Script | Purpose | Uses |
|--------|---------|------|
| `chain_analysis.py` | Follow call chains with code, cross-module | Own module cache |
| `build_call_graph.py` | Build and query single-module graph | `CallGraph` |
| `generate_diagram.py` | Mermaid/DOT diagrams of subgraphs | `CallGraph` (path mode) |
| `analyze_detailed_xrefs.py` | Classify xrefs (direct/indirect/vtable) | DB xrefs directly |
| `module_dependencies.py` | Module-to-module import/export mapping | Own dependency scan |
| `cross_module_resolve.py` | Resolve which module implements a function | `ModuleResolver` |

### Usage examples

```bash
# Single-module callgraph stats
python .agent/skills/callgraph-tracer/scripts/build_call_graph.py <db_path> --stats --json

# Forward reachability
python .agent/skills/callgraph-tracer/scripts/build_call_graph.py <db_path> --reachable "FuncName" --depth 5 --json

# Backward (callers)
python .agent/skills/callgraph-tracer/scripts/build_call_graph.py <db_path> --callers "FuncName" --depth 5 --json

# Shortest path
python .agent/skills/callgraph-tracer/scripts/build_call_graph.py <db_path> --path "Source" "Target" --json

# Call chain with code (cross-module)
python .agent/skills/callgraph-tracer/scripts/chain_analysis.py <db_path> --function "FuncName" --depth 3 --json

# Mermaid diagram
python .agent/skills/callgraph-tracer/scripts/generate_diagram.py <db_path> --function "FuncName" --depth 3 --format mermaid

# Cross-module resolution
python .agent/skills/callgraph-tracer/scripts/cross_module_resolve.py "HeapAlloc" --json

# Module dependencies
python .agent/skills/callgraph-tracer/scripts/module_dependencies.py --overview --json
```

### From the AI memory corruption scanner

```bash
# Cross-module callgraph with IPC edges (JSON, no code)
python .agent/skills/ai-memory-corruption-scanner/scripts/prepare_context.py <db_path> \
    --function "NetrShareGetInfo" --depth 5 --json
```

---

## 11. Choosing the Right Tool

| I need to... | Use | Why |
|---|---|---|
| See what a function calls (single module) | `CallGraph.reachable_from()` | Fast, cached, single-module |
| See who calls a function (single module) | `CallGraph.callers_of()` | Backward BFS |
| Traverse across DLL boundaries | `CrossModuleGraph.reachable_from()` | Crosses module boundaries |
| Include RPC/COM/WinRT edges | `CrossModuleGraph` + `inject_all_ipc_edges()` | IPC edges invisible to normal xrefs |
| Get function code along a chain | `ChainAnalyzer.collect_chain_data()` | Only tool that returns decompiled code |
| Get callgraph structure for AI agent | `prepare_context.py` (ai-memory-corruption-scanner) | JSON callgraph + IPC edges, no code |
| Find shortest path A -> B | `CallGraph.bfs_path()` | Single-module only |
| Find all paths A -> B | `CallGraph.all_paths()` | Bounded enumeration |
| Find recursive function clusters | `CallGraph.strongly_connected_components()` | Tarjan SCC |
| Resolve which module has a function | `ModuleResolver.resolve_function()` | Fuzzy search across all modules |
| Generate a diagram | `generate_diagram.py` | Mermaid or DOT output |
| See module-to-module dependencies | `module_dependencies.py` or `CrossModuleGraph.module_dependency_map()` | Import/export or xref-based |

---

## 12. Internals: How It Works

### CallGraph construction from DB

1. Open analysis DB via `open_individual_analysis_db(db_path)`
2. Load all function records via `db.get_all_functions()`
3. For each function, parse `simple_outbound_xrefs` and `simple_inbound_xrefs`
4. For each outbound xref:
   - Skip if `_is_followable_xref()` returns False (data refs)
   - If `function_id` is set: internal call -> add to `outbound` and `inbound`
   - If `function_id` is null and `module_name` is set: external call -> add to `external_calls`
   - If vtable type (function_type=8): also add to `vtable_edges`
5. Build `name_to_id`, `id_to_name` mappings for internal functions
6. Build `_name_lower_index` for case-insensitive lookup

### CrossModuleGraph construction

1. Open tracking DB via `open_analyzed_files_db()`
2. For each analyzed module, build a `CallGraph` via `CallGraph.from_db()`
3. Store in `_graphs: {module_name.lower(): CallGraph}`
4. Build `_module_deps` from `external_calls` across all graphs
5. Optionally inject IPC edges (RPC/COM/WinRT)

### Cross-module BFS algorithm (`reachable_from`)

```
queue = [(start_module, start_function, depth=0)]
visited = {(start_module, start_function)}

while queue not empty:
    (mod, func, depth) = queue.pop()
    if max_depth > 0 and depth >= max_depth: skip

    graph = _graphs[mod]

    # 1. Internal edges (same module)
    for callee in graph.outbound[func]:
        if (mod, callee) not visited:
            add to result and queue at depth+1

    # 2. External edges (cross-module imports)
    for (callee_name, target_module) in graph.external_calls[func]:
        target_graph = _graphs[target_module.lower()]
        resolved = target_graph.find_function(callee_name)
        if resolved and (target_module, resolved) not visited:
            add to result and queue at depth+1

    # 3. IPC edges (RPC/COM/WinRT)
    for (proc_name, server_mod, ipc_id) in graph.ipc_edges.get(mod, set()):
        server_graph = _graphs[server_mod]
        resolved = server_graph.find_function(proc_name)
        if resolved and (server_mod, resolved) not visited:
            add to result and queue at depth+1
```

### ChainAnalyzer cross-module resolution

ChainAnalyzer has its own module cache (independent of `ModuleResolver`) built
from the tracking DB. For each function's outbound xrefs, it classifies them:

- **Internal:** `function_id` set -> same module
- **Resolvable:** target module in cache -> follow into target DB
- **Unresolvable:** target module not analyzed -> report but don't follow
- **Data refs:** `module_name == "data"` -> skip
- **Vtable refs:** `function_type == 8` -> skip

It does NOT follow IPC edges. Only explicit import/export cross-module calls
are followed. For IPC-aware traversal, use `CrossModuleGraph`.

---

## 13. Performance and Caching

### CallGraph caching

`CallGraph.from_db()` caches its result using `helpers.cache` with key
`(db_path, "call_graph")`. Subsequent calls return the cached graph without
reopening the DB. Use `no_cache=True` to force a fresh build.

Cache is validated by DB modification time with a 24-hour TTL.

### CrossModuleGraph performance

Building a `CrossModuleGraph` for all 43 modules in a typical workspace takes
~2-5 seconds (each module's `CallGraph` is cached). IPC edge injection adds
~1-3 seconds (reading RPC/COM/WinRT indices).

A `reachable_from()` BFS at depth 5 typically completes in <1 second for
callgraphs with <1000 nodes.

### ModuleResolver connection pooling

`ModuleResolver` maintains a connection pool (`_connection_cache`) with LRU
eviction. Default pool size is 50 connections. This avoids repeatedly opening
and closing SQLite connections during batch resolution.

### Practical guidance

| Operation | Typical time | Notes |
|-----------|-------------|-------|
| `CallGraph.from_db()` (cached) | <100ms | Cache hit |
| `CallGraph.from_db()` (cold) | 1-3s | Depends on function count |
| `CrossModuleGraph.from_tracking_db()` | 2-5s | All modules loaded |
| `inject_all_ipc_edges()` | 1-3s | Reads RPC/COM/WinRT indices |
| `reachable_from()` depth 5 | <1s | ~500-2000 nodes typical |
| `ChainAnalyzer.collect_chain_data()` depth 3 | 5-15s | Loads code per node |
| `ChainAnalyzer.collect_chain_data()` depth 5 | 30-90s | Large trees |

---

## 14. Common Patterns

### Pattern 1: "What does this entry point reach?"

```python
with CrossModuleGraph.from_tracking_db() as graph:
    graph.inject_all_ipc_edges()
    reachable = graph.reachable_from("srvsvc.dll", "NetrShareEnum", max_depth=5)
    for mod, funcs in reachable.items():
        for func, depth in sorted(funcs.items(), key=lambda x: x[1]):
            print(f"  [{depth}] {mod}::{func}")
```

### Pattern 2: "Who calls this dangerous API?"

```python
graph = CallGraph.from_db(db_path)
callers = graph.callers_of("HeapAlloc", max_depth=5)
for func, depth in sorted(callers.items(), key=lambda x: x[1]):
    if depth > 0:  # exclude HeapAlloc itself
        print(f"  [{depth} hops] {func}")
```

### Pattern 3: "Is there a path from entry point to dangerous operation?"

```python
graph = CallGraph.from_db(db_path)
path = graph.bfs_path("NetrShareEnum", "HeapAlloc")
if path:
    print(" -> ".join(path))
```

### Pattern 4: "Build callgraph JSON for AI scanner"

```bash
python .agent/skills/ai-memory-corruption-scanner/scripts/prepare_context.py \
    extracted_dbs/srvsvc_dll_abc123.db --function "NetrShareEnum" --depth 5 --json
```

This uses `CrossModuleGraph` internally and produces the JSON structure
documented in the [AI Scanner Authoring Guide](ai_scanner_authoring_guide.md#5-callgraph-json-schema).

### Pattern 5: "Cross-module backward search (who across all modules calls X?)"

```python
from collections import defaultdict, deque

with CrossModuleGraph.from_tracking_db() as graph:
    graph.inject_all_ipc_edges()
    adj = graph.build_unified_adjacency()

    reverse = defaultdict(set)
    for src, targets in adj.items():
        for tgt in targets:
            reverse[tgt].add(src)

    target = ("kernel32.dll", "CreateProcessW")
    visited = {target: 0}
    queue = deque([(target, 0)])
    while queue:
        current, depth = queue.popleft()
        if depth >= 5:
            continue
        for caller in reverse.get(current, set()):
            if caller not in visited:
                visited[caller] = depth + 1
                queue.append((caller, depth + 1))

    for (mod, func), depth in sorted(visited.items(), key=lambda x: x[1]):
        if depth > 0:
            print(f"  [{depth}] {mod}::{func}")
```

### Pattern 6: "Visualize a function's call subtree"

```bash
python .agent/skills/callgraph-tracer/scripts/generate_diagram.py \
    extracted_dbs/srvsvc_dll_abc123.db --function "NetrShareEnum" --depth 3 --format mermaid
```
