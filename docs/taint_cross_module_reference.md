# Taint Cross-Module Analysis Reference

This document describes how cross-module taint tracing works in the DeepExtractIDA workspace, including depth limits, module resolution, termination at unresolved boundaries, and extraction coverage.

---

## 1. trace_taint_cross_module.py — How It Works

### Overview

`trace_taint_cross_module.py` is the **cross-module taint orchestrator**. It traces tainted parameters from a function across DLL boundaries into other analyzed modules.

**Location:** `.agent/skills/taint-analysis/scripts/trace_taint_cross_module.py`

### Architecture

The script delegates to `trace_taint_forward.trace_forward()` with `cross_module=True`. The actual cross-module logic lives in `trace_taint_forward._trace_cross_module_callees()`.

```
trace_taint_cross_module.trace_cross_module()
    └── trace_taint_forward.trace_forward(cross_module=True, cross_depth=N)
            └── _trace_cross_module_callees()  [recursive]
                    └── ModuleResolver.batch_resolve_xrefs()
                    └── trace_forward() for each resolved callee (recursive)
```

### Features

- **Full parameter mapping** across each boundary crossing
- **Guard/bypass accumulation** through the entire chain
- **Trust boundary analysis** (privilege escalation detection)
- **COM vtable call resolution** for indirect COM dispatch (`--no-com-resolve` disables)
- **RPC boundary detection** for cross-process taint chains
- **Return-value back-propagation** when tainted data flows back

### Depth Limits

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--depth` | 2 | Max **intra-module** recursion depth (calls within the same module) |
| `--cross-depth` | 2 | Max **cross-module hops** (DLL boundary crossings) |

- **Intra-module depth** is passed to `forward_trace.py` and limits how deep the data-flow tracer recurses within a single module.
- **Cross-depth** is decremented at each boundary: when `cross_depth <= 0`, `_trace_cross_module_callees` returns without recursing into external callees.

### Module Resolution

Cross-module resolution uses `helpers.cross_module_graph.ModuleResolver`:

1. **Tracking DB:** `ModuleResolver` loads the module index from `analyzed_files.db` (see [Section 3](#3-which-modules-are-extracted)).
2. **Xref resolution:** For each external call in `outbound_xrefs` (and COM vtable callees when enabled), it calls `batch_resolve_xrefs()`.
3. **Lookup:** `get_module_db(module_name)` returns `(db_path, file_name)` if the module is in the tracking DB; otherwise `None`.
4. **Function lookup:** For resolved modules, the resolver opens the analysis DB and looks up the callee by name.

### Modes

- **Single function:** `trace_taint_cross_module.py <db_path> <function_name> [--params 1,3] [--cross-depth 2]`
- **From entry points:** `--from-entrypoints` discovers ranked entry points via `rank_entrypoints.py`, then runs cross-module taint on the top N (`--top 5`).

---

## 2. How Taint Chain Terminates at Unresolved External Boundaries

### Termination Conditions

The taint chain **silently stops** (no findings, no error) when an external callee cannot be followed. This happens in `_trace_cross_module_callees` in `trace_taint_forward.py`:

```python
for info in resolved.values():
    if info is None:
        continue   # ← Unresolved: module not in tracking DB
    ...
    if not callee_name or not target_db or not info.get("has_decompiled"):
        continue   # ← Module analyzed but function missing or no decompiled code
    if target_module.lower() in visited_modules:
        continue   # ← Cycle prevention
```

### When `info` Is `None`

`batch_resolve_xrefs()` returns `{"<module>!<function>": resolved_dict | None}`. `info` is `None` when:

1. **Module not in tracking DB** — `get_module_db(module_name)` returns `None` because the module is not listed in `analyzed_files.db` with status `COMPLETE`.
2. **Module not in `_module_cache`** — The tracking DB was missing at load time, or the module record has no `analysis_db_path`.

### When `info` Exists but Is Skipped

- **`has_decompiled` is False** — The function exists in the analysis DB but has no decompiled code. Taint cannot trace through it.
- **`target_module` in `visited_modules`** — Prevents infinite recursion when modules call each other.

### No Explicit Reporting

**The taint scripts do not report unresolved boundaries.** Unresolved external calls are skipped with `continue`; there is no `unresolved_callees` or `suggest_extract` field in the output.

To discover which external calls are unresolved, use the **callgraph-tracer** skill:

```bash
python .agent/skills/callgraph-tracer/scripts/cross_module_resolve.py --from-function <db_path> <function_name> --json
```

This returns `external_calls` with `resolved: true/false` and `note: "module 'X' not analyzed"` for unresolved callees.

---

## 3. Which Modules Are "Extracted"

### Source of Truth: analyzed_files.db

**Extracted** modules are those listed in the **tracking database** with status `COMPLETE` and a valid `analysis_db_path`.

| Path | Purpose |
|------|---------|
| `extracted_dbs/analyzed_files.db` | Primary location (agent convention) |
| `analyzed_files.db` (workspace root) | Fallback (batch extractor output) |

`resolve_tracking_db(workspace_root)` checks both locations.

### Tracking DB Schema

The `analyzed_files` table includes:

- `file_name` — Module filename (e.g. `appinfo.dll`)
- `analysis_db_path` — Path to the per-module SQLite DB (e.g. `extracted_dbs/appinfo_dll_f2bbf324a1.db`)
- `status` — Must be `COMPLETE` for cross-module resolution

`ModuleResolver.get_complete()` uses `get_by_status("COMPLETE")`; only those records are loaded into `_module_cache`.

### extracted_dbs/

- **Individual analysis DBs:** `extracted_dbs/<module>_<hash>.db` — One per extracted binary. Contains functions, xrefs, assembly, decompiled code.
- **Tracking DB:** `extracted_dbs/analyzed_files.db` — Index of all analyzed modules and their DB paths.

### extracted_code/

- Decompiled `.cpp` files, `file_info.json`, `function_index.json`, `module_profile.json` per module.
- Used for function-index lookups and JSON-based resolution; the taint tracer primarily uses the analysis DBs.

---

## 4. Mechanism to Suggest "Extract Module X to Complete Taint Chain"

### Current State: **None**

There is **no built-in mechanism** in the taint analysis scripts to suggest extracting additional modules to complete a taint chain.

- `trace_taint_cross_module.py` and `trace_taint_forward.py` do not collect or emit unresolved callees.
- Output does not include fields like `unresolved_boundaries`, `suggest_extract`, or `missing_modules`.

### Related Capabilities

1. **cross_module_resolve.py** — Reports `resolved: false` and `note: "module 'X' not analyzed"` for external calls whose target module is not in the tracking DB. This can be used **manually** to identify modules to extract.

2. **deep-research-prompt / gather_cross_module()** — In `gather_function_context.py`, `gather_cross_module()` returns `resolvable: true/false` and `target_db` for each external callee. This feeds into research prompts but is **not** integrated into taint output.

3. **audit command** — Uses `cross_module_resolve.py` (Step 4c) to resolve cross-module callees and report "resolvable cross-module callees, and unresolvable external calls" for manual follow-up.

### Possible Enhancement

To add "suggest extract module X" support, the taint scripts would need to:

1. In `_trace_cross_module_callees`, collect xrefs where `resolved[key] is None` or `has_decompiled` is False.
2. Emit an `unresolved_boundaries` list in the output, e.g.:
   ```json
   "unresolved_boundaries": [
     {"module": "kernel32.dll", "function": "CreateProcessW", "reason": "module not analyzed"},
     {"module": "appinfo.dll", "function": "Foo", "reason": "no decompiled code"}
   ]
   ```
3. Optionally derive `suggest_extract: ["kernel32.dll"]` from modules that appear in `unresolved_boundaries` with reason "module not analyzed".

---

## Quick Reference

| Question | Answer |
|----------|--------|
| Where is cross-module taint logic? | `trace_taint_forward._trace_cross_module_callees()` |
| Default cross-depth? | 2 |
| Default intra-module depth? | 2 |
| How are modules resolved? | `ModuleResolver` + `analyzed_files.db` |
| What happens at unresolved boundaries? | Silently skipped; no output |
| Which modules are extracted? | Those in `analyzed_files.db` with status `COMPLETE` |
| Suggest extract module X? | No; use `cross_module_resolve.py` manually |
