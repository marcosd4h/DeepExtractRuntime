# DeepExtract Configuration Reference

`defaults.json` is the central configuration file for all DeepExtract Agent
Analysis Runtime components. It is loaded by `helpers/config.py` and consumed
by skill scripts, agents, hooks, and pipeline orchestrators.

## How Configuration Is Loaded

1. `defaults.json` is read from `.agent/config/defaults.json`.
2. The result is cached per-process (invalidated when file mtime changes).
3. Environment variable overrides are applied on every load (see below).
4. Callers receive a deep copy, so mutations never corrupt the cache.

Access a value programmatically:

```python
from helpers.config import get_config_value

timeout = get_config_value("triage.step_timeout_seconds", default=180)
```

## Environment Variable Overrides

Any top-level section key can be overridden at runtime via environment
variables prefixed with `DEEPEXTRACT_`. Two delimiter formats are supported:

| Format | Example | Resolves to |
|---|---|---|
| **Double-underscore** (preferred) | `DEEPEXTRACT_SCRIPT_RUNNER__MAX_RETRIES=3` | `script_runner.max_retries = 3` |
| **Single-underscore** (legacy) | `DEEPEXTRACT_SCRIPT_RUNNER_MAX_RETRIES=3` | `script_runner.max_retries = 3` (greedy section match) |

Values are parsed as JSON first; if that fails they are stored as plain
strings. The double-underscore format is unambiguous and should be preferred.

**Limitation:** only one level of nesting is supported. Deeply nested keys
like `classification.weights.W_NAME` cannot be overridden via environment
variables. Edit `defaults.json` directly for those values.

## Important Notes

- **`hooks.grind_loop_limit`** must be kept in sync with `loop_limit` in
  `.agent/hooks.json` (and `.cursor/hooks.json`). The JSON hooks file is
  consumed by the host runtime; `defaults.json` is consumed by Python code.
  If you change one, change both.
- All extraction databases are read-only. Configuration values control
  analysis behavior, never database writes.
- Validation rules are enforced by `helpers/config.py:validate_config()`.
  Invalid values produce warnings but do not crash -- scripts fall back to
  coded defaults.

---

## `classification` -- Function Classification

Controls the weighted scoring system that assigns category labels and
interest scores to decompiled functions.

### `classification.weights`

| Setting | Type | Default | Description | Constraints |
|---|---|---|---|---|
| `W_NAME` | float | `10.0` | Weight for function name pattern matching | > 0 |
| `W_API` | float | `5.0` | Weight per matched API call | > 0 |
| `W_API_CAP` | float | `25.0` | Maximum total score contribution from API matches | > 0 |
| `W_STRING` | float | `2.0` | Weight per matched string literal | > 0 |
| `W_STRING_CAP` | float | `10.0` | Maximum total score contribution from string matches | > 0 |
| `W_STRUCTURAL` | float | `4.0` | Weight for structural pattern matching (dispatch tables, loops) | > 0 |
| `W_LIBRARY` | float | `12.0` | Weight for library/boilerplate detection | > 0 |

### `classification` (top-level penalties)

| Setting | Type | Default | Description | Constraints |
|---|---|---|---|---|
| `library_interest_penalty` | int | `5` | Interest score penalty for library/boilerplate functions | — |
| `library_interest_penalty_with_dangerous_apis` | int | `2` | Reduced penalty when a library function calls dangerous APIs | — |
| `noise_interest_penalty` | int | `3` | Interest score penalty for noise functions | — |
| `noise_interest_penalty_with_dangerous_apis` | int | `1` | Reduced penalty when a noise function calls dangerous APIs | — |

### `classification.structural_thresholds`

| Setting | Type | Default | Description | Constraints |
|---|---|---|---|---|
| `dispatch_min_branches` | int | `15` | Minimum branch count to flag as dispatch/switch table | — |
| `dispatch_min_calls` | int | `5` | Minimum outbound call count for dispatch classification | — |
| `dispatch_max_loops` | int | `1` | Maximum loop count to still qualify as dispatch (not parser) | — |
| `parsing_min_loops` | int | `3` | Minimum loop count for parsing/iteration classification | — |
| `parsing_min_complexity` | int | `5` | Minimum cyclomatic complexity for parsing classification | — |
| `utility_max_asm_instructions` | int | `10` | Functions with <= this many instructions are utility/trivial | — |
| `utility_max_calls` | int | `2` | Functions with <= this many calls are utility/trivial | — |
| `leaf_max_instructions` | int | `20` | Max instruction count to classify as a leaf function | — |

---

## `scoring` -- Finding and Severity Scoring

Controls confidence thresholds and severity weights used by vulnerability
scanners, taint analysis, and exploitability assessment.

| Setting | Type | Default | Description | Constraints |
|---|---|---|---|---|
| `min_confidence_for_report` | float | `0.7` | Minimum confidence to include a finding in reports | [0.0, 1.0] |
| `uncategorized_dangerous_severity` | float | `0.65` | Default severity for dangerous API calls that don't match a known category | [0.0, 1.0] |
| `sync_severity` | float | `0.5` | Severity weight for synchronization-related findings | [0.0, 1.0] |
| `source_severity_call_result` | float | `0.5` | Severity when taint source is a call return value | [0.0, 1.0] |
| `source_severity_global` | float | `0.7` | Severity when taint source is a global variable | [0.0, 1.0] |
| `guard_unknown_weight` | float | `0.18` | Weight penalty for unknown/unresolved guard functions | [0.0, 1.0] |
| `infeasibility_penalty_factor` | float | `0.1` | Multiplier to reduce score when a path seems infeasible | [0.0, 1.0] |
| `scanner_default_top_n` | int | `100` | Default number of top results returned by scanner scripts | > 0 |

---

## `callgraph` -- Call Graph Traversal

Controls call graph construction and depth limits for reachability,
taint, and chain analysis.

| Setting | Type | Default | Description | Constraints |
|---|---|---|---|---|
| `include_vtable_edges` | bool | `true` | Include vtable/virtual call edges in the call graph | — |
| `default_max_depth` | int | `10` | Default maximum traversal depth for chain analysis | > 0 |
| `max_depth_for_reachability` | int | `15` | Maximum depth for reachability queries (entry point -> function) | > 0 |
| `max_depth_for_taint` | int | `8` | Maximum depth for taint propagation traversal | > 0 |

---

## `triage` -- Module Triage

Controls the triage coordinator agent that classifies and prioritizes
functions across a module.

| Setting | Type | Default | Description | Constraints |
|---|---|---|---|---|
| `com_density_threshold` | int | `5` | Min COM-related functions to flag module as COM-heavy | > 0 |
| `com_density_ratio` | float | `0.1` | Min ratio of COM functions to total to flag as COM-heavy | [0.0, 1.0] |
| `rpc_density_threshold` | int | `3` | Min RPC-related functions to flag module as RPC-heavy | > 0 |
| `security_density_threshold` | int | `3` | Min security-related functions to flag as security-relevant | > 0 |
| `max_workers` | int | `4` | Parallel worker threads for triage steps | [1, 16] |
| `step_timeout_seconds` | float | `180` | Timeout per triage step in seconds | > 0 |
| `per_function_timeout_seconds` | float | `0.2` | Timeout per individual function classification in seconds | > 0 |

---

## `security_auditor` -- Security Auditor Agent

Controls the security auditor agent's function selection and timeout
behavior.

| Setting | Type | Default | Description | Constraints |
|---|---|---|---|---|
| `step_timeout_seconds` | float | `180` | Timeout per audit step in seconds | > 0 |
| `per_function_timeout_seconds` | float | `0.2` | Timeout per individual function analysis in seconds | > 0 |
| `top_n_base` | int | `5` | Base number of functions to audit | > 0 |
| `top_n_per_100_functions` | int | `1` | Additional functions to audit per 100 functions in the module | > 0 |
| `top_n_max` | int | `25` | Maximum number of functions to audit regardless of module size | > 0 |
| `top_n_min` | int | `3` | Minimum number of functions to audit regardless of module size | > 0 |

---

## `pipeline` -- Pipeline Orchestration

Controls the YAML-driven pipeline runner for multi-step and multi-module
analysis workflows.

| Setting | Type | Default | Description | Constraints |
|---|---|---|---|---|
| `default_step_timeout` | float | `300` | Default timeout per pipeline step in seconds | > 0 |
| `max_workers` | int | `4` | Max parallel workers for pipeline steps | [1, 16] |
| `continue_on_error` | bool | `true` | Continue executing subsequent steps when a step fails | — |
| `parallel_modules` | bool\|int | `false` | Run modules in parallel (`false` = serial, `true` = auto, int = explicit worker count) | bool or > 0 |
| `max_module_workers` | int | `2` | Max parallel module workers when `parallel_modules` is `true` | [1, 16] |
| `no_cache` | bool | `false` | Bypass the result cache for all pipeline steps | — |

---

## `verifier` -- Code Lifting Verifier

Controls the verifier agent that compares lifted code against assembly
ground truth.

| Setting | Type | Default | Description | Constraints |
|---|---|---|---|---|
| `call_count_tolerance` | float | `0.2` | Allowed fractional deviation in call site count between lifted and original | [0.0, 1.0] |
| `branch_count_tolerance` | float | `0.3` | Allowed fractional deviation in branch count between lifted and original | [0.0, 1.0] |
| `max_alignment` | int | `8` | Maximum struct member alignment to consider during verification | [1, 64] |

---

## `script_runner` -- Script Execution

Controls timeout and retry behavior for skill script invocations.

| Setting | Type | Default | Description | Constraints |
|---|---|---|---|---|
| `default_timeout_seconds` | int | `180` | Default timeout for script execution in seconds | > 0 |
| `max_retries` | int | `2` | Maximum retry attempts for a failed script invocation | [0, 5] |

---

## `explain` -- Function Explanation

Controls depth limits for the `/explain` command's callee expansion.

| Setting | Type | Default | Description | Constraints |
|---|---|---|---|---|
| `max_callee_depth` | int | `5` | Maximum depth to recurse into callees when explaining a function | [1, 10] |
| `max_callees_per_level` | int | `15` | Maximum callees to include at each depth level | [1, 50] |

---

## `cache` -- Result Cache

Controls the `.agent/cache/` result caching system. Cached results are
validated by database mtime and age. Use `--no-cache` on any script to
bypass.

| Setting | Type | Default | Description | Constraints |
|---|---|---|---|---|
| `max_age_hours` | int | `24` | Maximum age of a cached result in hours before it is stale | >= 0 (0 disables caching) |
| `max_cache_size_mb` | float | `500` | Maximum total cache directory size in MB | > 0 |

---

## `ui` -- User Interface

| Setting | Type | Default | Description | Constraints |
|---|---|---|---|---|
| `show_progress` | bool | `true` | Show progress bars and status messages during long operations | — |

---

## `dangerous_apis` -- Dangerous API Database

Controls loading and use of the dangerous API classification database.

| Setting | Type | Default | Description | Constraints |
|---|---|---|---|---|
| `json_path` | string | `"config/assets/misc_data/dangerous_apis.json"` | Path (relative to `.agent/`) to the dangerous API definitions file | Non-empty string |
| `auto_classify` | bool | `true` | Automatically incorporate dangerous API data during classification | — |

---

## `hooks` -- Lifecycle Hooks

Controls the session-start hook, grind loop, and workspace cleanup.

| Setting | Type | Default | Description | Constraints |
|---|---|---|---|---|
| `session_start_timeout_seconds` | int | `15` | Timeout for the session-start context injector hook | > 0 |
| `grind_scratchpad_stale_hours` | int | `24` | Hours after which an untouched grind scratchpad is considered stale | > 0 |
| `grind_loop_limit` | int | `10` | Maximum grind loop re-invocations. **Must match `loop_limit` in `hooks.json`.** | > 0 |
| `workspace_cleanup_age_hours` | int | `48` | Hours after which old workspace run directories are eligible for cleanup | > 0 |

---

## `rpc` -- RPC Interface Analysis

Controls loading of RPC server metadata and client stubs for the
`rpc-interface-analysis` skill.

| Setting | Type | Default | Description | Constraints |
|---|---|---|---|---|
| `servers_path` | string | `"config/assets/rpc_data/rpc_servers.json"` | Path (relative to `.agent/`) to RPC server definitions | Non-empty string |
| `client_stubs_path` | string | `"config/assets/rpc_data/rpc_clients_26200_7840"` | Path (relative to `.agent/`) to RPC client stub directory | Non-empty string |
| `enabled` | bool | `true` | Enable RPC interface analysis features | — |
| `cache_loaded_index` | bool | `true` | Cache the parsed RPC index in memory after first load | — |
| `load_stubs` | bool | `true` | Load C# client stub signatures for procedure enrichment | — |

---

## `winrt` -- WinRT Interface Analysis

Controls loading of WinRT activation server metadata for the
`winrt-interface-analysis` skill.

| Setting | Type | Default | Description | Constraints |
|---|---|---|---|---|
| `data_root` | string | `"config/assets/winrt_data"` | Path (relative to `.agent/`) to WinRT data directory | Non-empty string |
| `enabled` | bool | `true` | Enable WinRT interface analysis features | — |
| `cache_loaded_index` | bool | `true` | Cache the parsed WinRT index in memory after first load | — |
| `exclude_staterepo` | bool | `false` | Exclude StateRepository-related WinRT classes from results | — |

---

## `com` -- COM Interface Analysis

Controls loading of COM server metadata for the `com-interface-analysis`
skill.

| Setting | Type | Default | Description | Constraints |
|---|---|---|---|---|
| `data_root` | string | `"config/assets/com_data"` | Path (relative to `.agent/`) to COM data directory | Non-empty string |
| `enabled` | bool | `true` | Enable COM interface analysis features | — |
| `cache_loaded_index` | bool | `true` | Cache the parsed COM index in memory after first load | — |

---

## `scale` -- Large Workspace Scaling

Controls thresholds and limits that prevent runaway resource usage when
operating on workspaces with many modules or large databases.

| Setting | Type | Default | Description | Constraints |
|---|---|---|---|---|
| `compact_mode_threshold` | int | `25` | Number of modules above which compact output mode is activated | > 0 |
| `context_truncation_threshold` | int | `1000` | Character count above which context strings are truncated | > 0 |
| `max_modules_cross_scan` | int | `200` | Max modules to include in cross-module scans | >= 0 (0 = unlimited) |
| `max_modules_compare` | int | `200` | Max modules to include in comparison operations | > 0 |
| `max_modules_search_all` | int | `200` | Max modules to include in unified search-all queries | >= 0 (0 = unlimited) |
| `cross_module_index_warn_threshold` | int | `0` | Warn when cross-module index exceeds this count (0 = no warning) | >= 0 (0 = disabled) |
| `max_cached_connections` | int | `50` | Max SQLite database connections to keep in the connection pool | > 0 |
| `cache_stats_sample_limit` | int | `200` | Max entries to sample when computing cache statistics | > 0 |
| `health_sample_count` | int | `100` | Number of database entries to sample for health checks | > 0 |
