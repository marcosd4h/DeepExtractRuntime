# Performance Guide: Large-Scale Analysis

This guide provides strategies for analyzing large modules (1000+ functions)
and large workspaces (many extracted modules) efficiently without overwhelming
context windows or hitting timeouts.

## Key Metrics

| Module Size | Functions | Typical Analysis Time | Strategy                                |
| ----------- | --------- | --------------------- | --------------------------------------- |
| Small       | < 100     | < 30 seconds          | No special handling needed              |
| Medium      | 100-500   | 30-120 seconds        | Use caching, `--app-only`               |
| Large       | 500-2000  | 2-5 minutes           | Filter aggressively, use `--top N`      |
| Very Large  | 2000+     | 5+ minutes            | Target specific areas, avoid full scans |

## Strategy 1: Filter Library Noise with `--app-only`

Most large modules contain 40-70% library code (WIL, STL, WRL, CRT, ETW).
The `--app-only` flag excludes these from classification and ranking:

```
# Without --app-only: classifies ALL 1500 functions
/triage large_module.dll

# With --app-only: classifies only ~500 application functions
python .agent/skills/classify-functions/scripts/triage_summary.py <db_path> --app-only --top 15
```

The `module_profile.json` in `extracted_code/<module>/` contains pre-computed
noise ratio and library breakdown -- check this first before deciding on
filtering strategy.

## Strategy 2: Bound Output with `--top N`

Many skill scripts accept `--top N` to limit output to the N most interesting
items. Use this to prevent large result sets from overwhelming context:

```
# Show only top 10 functions (default)
triage_summary.py <db_path> --top 10

# Show only top 5 attack surface entries
rank_entrypoints.py <db_path> --top 5

# Limit call graph stats to top 10 hubs
build_call_graph.py <db_path> --stats --top 10
```

## Strategy 3: Leverage Caching

First analysis runs are always slower because they compute and cache results.
Subsequent runs use cached data (validated by DB mtime + 24h TTL).

```
# Check cache status
/cache-manage stats

# Force refresh if needed
/cache-manage refresh <module>

# Bypass cache for a specific run
python <script>.py <db_path> --no-cache
```

## Strategy 4: Target Specific Areas

Instead of running full triage on a large module, target specific subsystems:

```
# Search for specific functions/patterns first
/search large_module.dll CreateProcess

# Explain a specific function
/explain large_module.dll <function>

# Audit a specific export with diagram (bounded by call chain depth)
/audit large_module.dll <export> --diagram

# Reconstruct types for a specific class
/reconstruct-types large_module.dll CSpecificClass
```

## Strategy 5: Use Summary Mode

The `/full-report` command supports `--brief` mode that skips expensive
topology and decompilation quality analyses:

```
/full-report large_module.dll --brief
```

## Strategy 6: Limit Call Graph Depth

Cross-module call chain tracing can explode on large modules. Always use
`--depth` to bound traversal:

```
# Audit a single export (bounded call chain depth 4)
/audit large_module.dll <export> --diagram

# Limit data flow tracing depth
/data-flow forward large_module.dll <function> --param 1 --depth 2
```

## Performance Characteristics by Skill

| Skill                   | Scales With         | Bottleneck              | Cached |
| ----------------------- | ------------------- | ----------------------- | ------ |
| classify-functions      | Function count      | DB iteration            | Yes    |
| callgraph-tracer        | Edge count          | Graph construction      | Yes    |
| map-attack-surface      | Export/vtable count | Reachability BFS        | Yes    |
| generate-re-report      | Function count      | Import/string analysis  | Yes    |
| reconstruct-types       | Memory access count | Pattern scanning        | Yes    |
| data-flow-tracer        | Xref depth          | Cross-module resolution | No     |
| verify-decompiled       | Assembly size       | Heuristic matching      | No     |
| state-machine-extractor | Switch case count   | Pattern detection       | No     |

## Workspace Cleanup

Large analyses generate workspace run directories. Clean them periodically:

```
# Show what would be deleted
python .agent/helpers/cleanup_workspace.py --dry-run

# Delete runs older than 7 days (default)
python .agent/helpers/cleanup_workspace.py

# Delete runs older than 1 day
python .agent/helpers/cleanup_workspace.py --older-than 1
```

Or use `/cache-manage purge-runs` to clean stale workspace runs.

---

## Module Count Scalability

The runtime automatically adapts to the number of extracted modules. The
strategies above address **per-module function count**; this section addresses
**total module count** across the workspace.

### Scale Tiers

| Workspace Size | Modules | Context Injection | Cross-Module Ops | Recommended Workflow |
|----------------|---------|-------------------|------------------|----------------------|
| Small          | < 50    | Full tables       | All work normally | No special handling |
| Medium         | 50-500  | Compact mode auto | All work normally | Use explicit module names |
| Large          | 500-5000| Compact + truncated | All work; progress logged to stderr | Target specific modules when possible |
| Very Large     | 5000+   | Minimal fallback  | All work; parallel scanning, progress logged | Use `/search` to discover modules; target specific modules for expensive ops |

### Session Context at Scale

The session start hook automatically switches to compact mode when the module
count exceeds `scale.compact_mode_threshold` (default: 25). Above
`scale.context_truncation_threshold` (default: 1000), module name lists are
omitted entirely and only a count + status summary is injected.

A sidecar cache (`.agent/cache/_module_list.json`) stores the module list
between sessions, invalidated by tracking DB mtime. This avoids re-scanning
the tracking database on every session start.

### Cross-Module Operations at Scale

All cross-module operations work at any module count by default (limits set
to 0 = unlimited). For workspaces with 6000+ modules, the runtime uses
several optimizations:

- **JSON-first indexing**: The cross-module function name index reads
  `function_index.json` files instead of opening SQLite DBs, which is
  ~10-100x faster at scale.
- **Parallel scanning**: `ImportExportIndex` uses a thread pool
  (configurable via `triage.max_workers`, default 4) to scan module
  databases in parallel.
- **Scaled connection pools**: LRU connection pools default to 50
  cached connections (configurable via `scale.max_cached_connections`)
  instead of the previous 8, reducing connection churn.
- **Progress reporting**: Operations that iterate many modules log
  progress to stderr every 500 modules.

| Operation | Config Key | Default | Behavior |
|-----------|-----------|---------|----------|
| Cross-module function index | `scale.cross_module_index_warn_threshold` | 0 (unlimited) | Index always built; uses JSON fast path |
| Cross-module graph build | `scale.max_modules_cross_scan` | 0 (unlimited) | All modules loaded; progress logged |
| `/search --all` | `scale.max_modules_search_all` | 0 (unlimited) | All modules searched |
| `/compare-modules --all` | `scale.max_modules_compare` | 200 | Only first N modules compared |
| `/health` DB validation | `scale.health_sample_count` | 100 | Random sample validated |
| `cache_stats()` | `scale.cache_stats_sample_limit` | 200 | (stats scan all; use `--module` for single) |
| LRU connection pool | `scale.max_cached_connections` | 50 | Max cached SQLite connections |

All limits are configurable in `.agent/config/defaults.json` under the `scale` section
and overridable via environment variables (e.g., `DEEPEXTRACT_SCALE__MAX_MODULES_CROSS_SCAN=500`).
A value of `0` means unlimited for `max_modules_cross_scan`, `max_modules_search_all`,
and `cross_module_index_warn_threshold`.

### Safe Commands at Any Scale

These commands operate on a single module and are always safe:

- `/triage <module>`, `/explain <module> <function>`, `/audit <module> <function>`
- `/verify <module> <function>`, `/lift-class <module> <class>`
- `/audit <module> <export> --diagram`, `/data-flow <module> <function>`
- `/reconstruct-types <module>`, `/state-machines <module>`
- `/search <module> <term>` (single-module search)

### Commands That May Be Slow at Very Large Scale (6000+ modules)

- `/compare-modules --all` -- O(N^2) pairwise; use explicit module lists
- `/health --full` -- validates every DB; use `/health` (sampled) or `--quick`
- Any script with `--overview` that enumerates all modules (e.g., `module_dependencies.py`)

### Overriding Limits

To restrict limits for a specific session (e.g., for faster iteration):

```bash
# Restrict cross-module graph to only 500 modules
export DEEPEXTRACT_SCALE__MAX_MODULES_CROSS_SCAN=500

# Restrict search to first 100 modules
export DEEPEXTRACT_SCALE__MAX_MODULES_SEARCH_ALL=100

# Reduce connection pool size (lower memory usage)
export DEEPEXTRACT_SCALE__MAX_CACHED_CONNECTIONS=10
```

To permanently change defaults, edit `.agent/config/defaults.json`.
Set a value to `0` to mean unlimited (the default for most module-count keys).
