---
name: taint-analysis
description: Trace attacker-controlled inputs forward to dangerous sinks and backward to discover origins, including deep cross-module taint propagation with parameter mapping, trust boundary analysis, COM vtable resolution, and RPC boundary detection.  Reports what sensitive functions are reached, what guards must be bypassed, how tainted data affects internal logic, and identifies multi-module attack chains.  Use when the user asks to taint-trace, find where a parameter goes, check if attacker data reaches a sensitive API, identify what needs to be bypassed, trace across DLL boundaries, find privilege escalation vectors, or asks about exploitation potential of a function's inputs.
---

# Taint Analysis

## Purpose

Vulnerability-research-focused parameter taint tracing.  Given a function and (optionally) a set of parameters, answer:

- **Sink reachability** -- Does attacker-controlled data reach a sensitive function (CreateProcess, memcpy, LoadLibrary, etc.)?
- **Guards to bypass** -- What conditional checks sit between the taint source and the sink?  Are they attacker-controllable?
- **Logic effects** -- Does tainted data steer branches, index arrays, bound loops, control allocation sizes, or get stored to globals?
- **Origin context** (backward) -- Where does the tainted data come from?  Is it from an export parameter, a file read, a registry value?

## When to Use

- Tracing where attacker-controlled parameters flow to (forward taint)
- Checking if user input reaches dangerous sinks (memcpy, CreateProcess, LoadLibrary)
- Identifying what guards sit between a taint source and a sink
- Understanding how tainted data affects control flow (branch steering, array indexing)
- Tracing data origins backward through the caller chain
- Cross-module taint propagation across DLL boundaries

## When NOT to Use

- For general call graph exploration without taint focus -- use **callgraph-tracer**
- For building comprehensive security context on a function -- use **security-dossier**
- For detailed data flow without security classification -- use **data-flow-tracer**
- For mapping all entry points and attack surface -- use **map-attack-surface**
- For assessing exploitability of already-identified findings -- use **exploitability-assessment**

## Data Sources

- **Individual analysis DBs** (`extracted_dbs/{module}_{hash}.db`): Functions, decompiled code, xrefs, global accesses
- **Tracking DB** (`extracted_dbs/analyzed_files.db`): Module-to-DB resolution for cross-module callee tracing
- **API taxonomy** (`helpers/api_taxonomy.py`): `classify_api_security()` for sink detection
- **Guard classifier** (`helpers/guard_classifier.py`): `find_guards_between()` for bypass analysis

### Finding a Module DB

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py --list
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll
```

## Utility Scripts

All scripts live in `scripts/`.  Run from the workspace root.

### taint_function.py -- Full Taint Analysis (Start Here)

```bash
# Trace all parameters forward (default)
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> <function_name>

# Trace specific parameters
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> <function_name> --params 1,3

# Both directions with deeper recursion
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> <function_name> --params 1 --depth 3 --direction both

# JSON output
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> --id <fid> --json
```

**Direction options:**
- `forward` (default) -- trace where tainted params flow to
- `backward` -- trace where tainted params come from (caller chain)
- `both` -- run forward and backward

### trace_taint_forward.py -- Forward Only

```bash
python .agent/skills/taint-analysis/scripts/trace_taint_forward.py <db_path> <function_name> --params 1,3 --depth 2
python .agent/skills/taint-analysis/scripts/trace_taint_forward.py <db_path> --id <fid> --json

# Cross-module: resolve external callees to other analyzed modules
python .agent/skills/taint-analysis/scripts/trace_taint_forward.py <db_path> <function_name> --cross-module
python .agent/skills/taint-analysis/scripts/trace_taint_forward.py <db_path> <function_name> --cross-module --cross-depth 2
```

**Cross-module tracing** (`--cross-module`): When enabled, external callees
(imports from other DLLs) are resolved via the tracking DB to other analyzed
modules. If a callee is found in another extracted module, a forward taint
trace is run in that module's DB. Use `--cross-depth N` (default 1) to
control how many cross-module hops are allowed.

### trace_taint_backward.py -- Backward Only

```bash
python .agent/skills/taint-analysis/scripts/trace_taint_backward.py <db_path> <function_name> --params 1
python .agent/skills/taint-analysis/scripts/trace_taint_backward.py <db_path> --id <fid> --depth 2 --json
```

### trace_taint_cross_module.py -- Cross-Module Taint Orchestrator

Traces tainted parameters across DLL boundaries with full context preservation:

- **Parameter mapping**: Tracks which specific parameters carry tainted data at each boundary crossing (not all params)
- **Guard accumulation**: Collects all guard conditions from every module in the chain
- **Trust boundary analysis**: Classifies modules by trust level (`user_process`, `system_service`, `com_server`, `rpc_server`, `kernel_adjacent`) and flags privilege escalation crossings
- **COM vtable resolution**: Follows taint through COM virtual method dispatch calls using `is_vtable_call` xref data
- **RPC boundary detection**: Identifies NdrClientCall-family calls as cross-process taint boundaries
- **Return-value propagation**: When a cross-module callee returns tainted data, propagates it back to the caller's assignment targets

```bash
# Cross-module trace with full context (default 2 hops)
python .agent/skills/taint-analysis/scripts/trace_taint_cross_module.py <db_path> <function_name>

# Specific params, deeper cross-module recursion
python .agent/skills/taint-analysis/scripts/trace_taint_cross_module.py <db_path> <function_name> --params 1,3 --cross-depth 3

# Disable trust analysis or COM resolution
python .agent/skills/taint-analysis/scripts/trace_taint_cross_module.py <db_path> <function_name> --no-trust-analysis
python .agent/skills/taint-analysis/scripts/trace_taint_cross_module.py <db_path> <function_name> --no-com-resolve

# JSON output
python .agent/skills/taint-analysis/scripts/trace_taint_cross_module.py <db_path> --id <fid> --json

# Auto-discover top entry points and taint-trace each across modules
python .agent/skills/taint-analysis/scripts/trace_taint_cross_module.py <db_path> --from-entrypoints
python .agent/skills/taint-analysis/scripts/trace_taint_cross_module.py <db_path> --from-entrypoints --top 10 --json
python .agent/skills/taint-analysis/scripts/trace_taint_cross_module.py <db_path> --from-entrypoints --top 3 --min-score 0.4 --cross-depth 3
```

**Batch from entry points** (`--from-entrypoints`): Discovers and ranks the
module's entry points via `rank_entrypoints.py`, then runs cross-module taint
analysis on the top N (default 5). Use `--top N` to control how many entry
points are analyzed and `--min-score` to filter by minimum attack score. Each
entry point's `tainted_args` from ranking are used to select which parameters
to trace; when none are inferred, all parameters are traced. Results are
aggregated across all entry points.

Requires the tracking DB (`extracted_dbs/analyzed_files.db`) for cross-module
resolution. If the tracking DB is missing, only local findings are reported.

### generate_taint_report.py -- Report Generator

Merges forward and backward results into a unified JSON or markdown report. Typically called by `taint_function.py`, but can be invoked standalone:

```bash
python .agent/skills/taint-analysis/scripts/generate_taint_report.py --forward <json_path> --json
python .agent/skills/taint-analysis/scripts/generate_taint_report.py --forward <fwd.json> --backward <bwd.json> --direction both
```

## Workflows

```
Taint Analysis Progress:
- [ ] Step 1: Locate the module DB and resolve the function
- [ ] Step 2: Run forward taint to find dangerous sinks
- [ ] Step 3: Review guards/bypass requirements on each path
- [ ] Step 4: Check logic effects (branch steering, OOB, state pollution)
- [ ] Step 5: Optionally run backward to understand caller origins
- [ ] Step 6: Optionally run cross-module to trace across DLL boundaries
```

**Step 1**: Find module and function

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll
python .agent/skills/function-index/scripts/lookup_function.py AiLaunchProcess --json
```

**Step 2**: Run forward taint

```bash
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> AiLaunchProcess --params 1 --depth 3
```

**Step 3**: Review the output

Focus on:

| Indicator | Meaning |
|-----------|---------|
| **CRITICAL/HIGH findings** | Tainted data reaches dangerous sinks with few/weak guards |
| **attacker_controllable: YES** | The guard depends on tainted data -- attacker controls the check |
| **bypass_difficulty: easy** | Attacker directly controls inputs to the guard condition |
| **bypass_difficulty: hard** | Guard is independent of tainted data -- must already be satisfied |
| **branch_steering** | Tainted data affects control flow decisions |
| **array_index** | Potential out-of-bounds access |
| **size_argument** | Tainted data controls buffer/allocation size |

**Step 4**: Backward origin analysis (optional)

```bash
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> AiLaunchProcess --params 1 --direction backward
```

## Output Reference

### Forward Finding Structure

Each finding in `forward_findings` contains:

- `param` / `param_name` -- which tainted parameter reaches this sink
- `sink` -- name of the dangerous API reached
- `sink_category` -- from `classify_api_security()` (e.g., `command_execution`, `memory_unsafe`)
- `severity` / `score` -- composite rating (CRITICAL/HIGH/MEDIUM/LOW)
- `path` -- the call chain from source to sink
- `guards` -- list of conditional guards on the path, each with:
  - `guard_type` (auth_check, bounds_check, null_check, validation, error_check)
  - `attacker_controllable` (bool)
  - `bypass_difficulty` (easy/medium/hard)
  - `api_in_condition` (if a security API is called in the condition)
- `logic_effects` -- how tainted data affects internal logic

### Severity Scoring

Score = sink_weight * (1/sqrt(path_hops)) * guard_penalty

Sink weights (20 categories): command_execution (1.0) > code_injection (0.95) > memory_unsafe (0.9) > privilege (0.85) > code_loading (0.8) > named_pipe/device_io/alpc_ipc (0.75) > file_write/registry_write/service_control (0.7) > com_marshaling/dde (0.65) > network (0.6) > debug_control (0.55) > memory_alloc (0.5) > process_enum (0.4) > wow64 (0.35)

Covers ~250 dangerous API prefixes including Nt* syscalls, COM/OLE/DDE, named pipes, ALPC, DeviceIoControl, and more (sourced from `deep_extract/data/dangerous_apis.json`).

Each non-attacker-controllable guard reduces score by 0.15.

Bands: CRITICAL >= 0.8, HIGH >= 0.6, MEDIUM >= 0.3, LOW < 0.3

### Cross-Module Finding Structure

Cross-module findings include additional fields:

- `cross_module_source` -- boundary crossing details:
  - `from_module` / `to_module` -- source and target module names
  - `from_function` / `to_function` -- source and target function names
  - `boundary_type` -- `dll_import`, `com_vtable`, or `rpc`
  - `param_mapping` -- maps source param numbers to callee param numbers
- `taint_context` -- accumulated context across the chain:
  - `call_stack` -- full call chain with trust levels at each hop
  - `accumulated_guards` -- all guards from every module traversed
  - `trust_transitions` -- each boundary crossing with trust classification
  - `param_map` -- original-to-current parameter number mapping
  - `return_taint` -- whether the callee returned tainted data
- `trust_escalated` (bool) -- true when taint crossed into a higher-trust module (score boosted by 1.25x)
- `return_taint_origin` (bool) -- true when finding was discovered via return-value back-propagation

### Trust Levels

Modules are classified by their role:

| Trust Level | Detection Signal | Example |
|-------------|-----------------|---------|
| `user_process` | Default | cmd.exe |
| `com_server` | `DllGetClassObject` / `DllRegisterServer` in exports | appinfo.dll |
| `rpc_server` | `RpcServerRegisterIf*` in imports | lsass.exe |
| `system_service` | `ServiceMain` export or `StartServiceCtrlDispatcher` import | svchost.exe |
| `kernel_adjacent` | Heavy `NtDeviceIoControlFile` usage | drivers |

When taint crosses from a lower-trust to a higher-trust module, the finding
score is multiplied by 1.25x and annotated with `trust_escalated: true`.

**Step 6**: Cross-module taint (optional)

When a function's tainted data flows to external callees in other DLLs,
use the cross-module orchestrator to follow the taint chain across module
boundaries:

```bash
python .agent/skills/taint-analysis/scripts/trace_taint_cross_module.py <db_path> AiLaunchProcess --cross-depth 2
```

Or use the `--cross-module` flag on the main entry point:

```bash
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> AiLaunchProcess --cross-module --cross-depth 2
```

## Rationalizations to Reject

| Rationalization | Why It's Wrong |
|-----------------|----------------|
| "A guard exists on this path, so it's safe" | Guards may be attacker-controllable or bypassable. Always check `attacker_controllable` and `bypass_difficulty` -- a guard the attacker controls is no guard at all. |
| "The call path is too deep to exploit" | Depth doesn't determine exploitability. A 5-hop chain with no guards is worse than a 1-hop with strong validation. Report the finding with path length as context. |
| "This function is internal, so unreachable" | Internal functions may be reachable via exported callers. Check reachability data before dismissing. Run backward trace if uncertain. |
| "Only informational sinks, not dangerous" | Sinks like `OutputDebugString` or `EventWrite` can leak sensitive data. Report them with appropriate severity, not as safe. |
| "Cross-module trace didn't find anything, so it's clean" | Missing tracking DB or unextracted modules cause silent gaps. Check whether the cross-module resolution actually covered all external callees. |

## Integration with Other Skills

| Task | Recommended Skill |
|------|-------------------|
| Build full security dossier before taint analysis | security-dossier |
| Trace detailed call chains from flagged callees | callgraph-tracer |
| Get detailed forward/backward data flow | data-flow-tracer |
| Lift flagged functions to clean code for review | code-lifting / batch-lift |
| Map all entry points to find attack surface | map-attack-surface |
| Verify decompiler accuracy of flagged functions | verify-decompiled |

## Performance

| Operation | Typical Time | Notes |
|-----------|-------------|-------|
| Forward trace, 1 param, depth 2 | ~5-10s | Depends on callee count |
| Forward trace, all params, depth 3 | ~15-40s | More params = more subprocess calls |
| Backward trace, depth 1 | ~3-8s | Per caller count |
| Full both-direction analysis | ~20-60s | Combined forward + backward |
| Cross-module trace, 2 hops | ~30-90s | Depends on module count and external callees |
| Cross-module with COM resolve | ~40-120s | Adds vtable resolution overhead |
