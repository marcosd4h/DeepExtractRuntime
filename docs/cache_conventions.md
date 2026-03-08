# Cache Conventions

How skill scripts use the filesystem cache in `.agent/cache/`.

## Infrastructure

The cache is implemented in `.agent/helpers/cache.py` (216 lines) and provides:

- **Storage**: `.agent/cache/{module}/{operation}.json`
- **Freshness**: DB file mtime matching (catches re-extractions) + configurable TTL (default 24h)
- **Atomicity**: Write-to-temp then `os.replace()` -- no partial-read races
- **API**: `get_cached()`, `cache_result()`, `clear_cache()`

## Cache Key Naming

Cache keys use `snake_case` matching the script's main function or purpose:

| Script | Cache Key | Params | Path Pattern | Payload Size |
|--------|-----------|--------|--------------|--------------|
| `triage_summary.py` | `triage_summary` | `app_only` | `.agent/cache/{mod}/triage_summary.json` | ~50KB |
| `classify_module.py` | `classify_module` | -- | `.agent/cache/{mod}/classify_module.json` | ~500KB |
| `build_call_graph.py` | `call_graph` | -- | `.agent/cache/{mod}/call_graph.json` | ~2MB |
| `analyze_topology.py` | `analyze_topology` | `app_only` | `.agent/cache/{mod}/analyze_topology.json` | ~10KB |
| `analyze_imports.py` | `analyze_imports` | -- | `.agent/cache/{mod}/analyze_imports.json` | ~20KB |
| `analyze_strings.py` | `analyze_strings` | -- | `.agent/cache/{mod}/analyze_strings.json` | ~100KB |
| `analyze_complexity.py` | `analyze_complexity` | `app_only` | `.agent/cache/{mod}/analyze_complexity.json` | ~30KB |
| `discover_entrypoints.py` | `discover_entrypoints` | -- | `.agent/cache/{mod}/discover_entrypoints.json` | ~150KB |
| `scan_com_interfaces.py` | `scan_com_interfaces` | `vtable_only` | `.agent/cache/{mod}/scan_com_interfaces.json` | ~80KB |
| `scan_struct_fields.py` | `scan_struct_fields` | `all_classes`, `no_asm`, `app_only` | `.agent/cache/{mod}/scan_struct_fields.json` | ~1MB |
| `build_dossier.py` | `security_dossier` | `function`, `callee_depth` | `.agent/cache/{mod}/security_dossier__*.json` | ~200KB |

### Filesystem Examples

```
.agent/cache/appinfo_dll/
├── call_graph.json
├── classify_module.json
├── triage_summary.json
├── triage_summary__app_only_True.json
├── analyze_topology.json
├── analyze_imports.json
├── analyze_strings.json
├── analyze_complexity.json
├── discover_entrypoints.json
├── scan_com_interfaces.json
├── scan_struct_fields__all_classes_True_app_only_False_no_asm_False.json
└── security_dossier__callee_depth_1_function_BatLoop.json
```

## Parameter Encoding Rules

Parameters are encoded into the cache key filename by `_cache_key()` in `cache.py`:

1. Only include params that **change the output** (not display params like `--top`, `--category`).
2. Params are sorted alphabetically and joined with `__`.
3. Boolean `True` produces `param_True`, boolean `False` produces `param_False`.
4. Falsy-only params (default case) produce the bare operation name with no suffix.

```python
_cache_key("triage_summary", {"app_only": True})   # -> "triage_summary__app_only_True"
_cache_key("triage_summary", {"app_only": False})   # -> "triage_summary__app_only_False"
_cache_key("triage_summary", None)                   # -> "triage_summary"
```

## Per-Function Caching

When caching results that are per-function (not per-module), include the function
name as a param:

```python
params = {"function": func.function_name, "callee_depth": callee_depth}
cached = get_cached(db_path, "security_dossier", params=params)
```

This generates distinct cache files per function, e.g.:
`security_dossier__callee_depth_1_function_AiLaunchProcess.json`

## Conditional Caching

Some scripts only cache their expensive modes. For example, `scan_struct_fields.py`
only caches when `--all-classes` is used (full-module scan). Per-function and
per-class modes are cheap subsets not worth caching.

```python
# Only cache the expensive --all-classes scan
if all_classes and not no_cache:
    cached = get_cached(db_path, "scan_struct_fields", params=params)
    ...
```

## When NOT to Cache

- **Single-function lookups**: `extract_function_data.py`, `classify_function.py`
- **Display-only filters**: `--top N`, `--category`, `--type` (filter after computation)
- **Low-cost operations**: Anything that reads a single DB record or does O(1) work
- **Search/interactive modes**: `--search` patterns, multi-match disambiguation

## The `--no-cache` Flag

Every cacheable script must accept `--no-cache` as an argparse flag:

```python
parser.add_argument("--no-cache", action="store_true", help="Bypass result cache")
```

And forward it as a keyword-only argument to the computation function:

```python
def analyze_foo(db_path: str, *, no_cache: bool = False) -> dict:
    if not no_cache:
        cached = get_cached(db_path, "analyze_foo")
        if cached is not None:
            return cached
    ...
    cache_result(db_path, "analyze_foo", result)
    return result
```

Orchestrator scripts (like `generate_report.py`) add their own `--no-cache` flag
and forward it to all sub-analyzer calls.

## TTL Behavior

The cache system enforces two conditions for a cache hit:

- **DB Freshness**: The `db_mtime` stored in the cache envelope must match the current filesystem `mtime` of the analysis database within a 1-second tolerance. This ensures the cache is invalidated if the database is re-extracted.
- **TTL Expiry**: The default Time-To-Live (TTL) is 24 hours. This can be overridden using the `max_age_hours` parameter in `get_cached()`.

Cache writes are atomic. Data is first written to a temporary file and then moved to the final destination using `os.replace()`, preventing partial-read race conditions.

## Cache Inspection & Debugging

- **Listing Cache Contents**: Use `ls .agent/cache/<module_name>/` to view cached operations for a specific module.
- **Reading Cache Metadata**: Each cache file is a JSON object with an envelope:
  ```json
  {
    "db_mtime": 1700000000.0,
    "created_at": 1700000000.0,
    "params": {"app_only": true},
    "data": { ... }
  }
  ```
- **Force-Refresh**: Pass the `--no-cache` flag to any cacheable skill script to bypass the cache and recompute the result.
- **Manual Clearing**: Call `clear_cache("module_name")` to remove all cache files for a specific module, or `clear_cache()` to remove the entire runtime cache.

For more information on resolving cache-related failures, see the [Troubleshooting Guide](troubleshooting.md).

## Custom Serialization

When a function returns custom objects (not plain dicts), add
`_to_cacheable()` / `_from_cached()` helpers:

- `callgraph.py`: `CallGraph._to_cacheable()` / `CallGraph._from_cached()`
- `classify_module.py`: `_result_to_cacheable()` / `_result_from_cached()`
- `discover_entrypoints.py`: `_entrypoints_to_cacheable()` / `_entrypoints_from_cached()`

## Adding Caching to a New Script -- Checklist

1. **Import**: `from helpers.cache import get_cached, cache_result`
2. **Add `no_cache` kwarg**: `def compute(db_path, *, no_cache=False)`
3. **Cache check** at top of function:
   ```python
   params = {"key": value}  # only if output varies by param
   if not no_cache:
       cached = get_cached(db_path, "operation_name", params=params)
       if cached is not None:
           return cached
   ```
4. **Cache store** before return:
   ```python
   cache_result(db_path, "operation_name", result, params=params)
   return result
   ```
5. **Argparse**: `parser.add_argument("--no-cache", action="store_true", help="Bypass result cache")`
6. **Forward**: `result = compute(args.db_path, no_cache=args.no_cache)`
7. **Declare cacheability**: Document in the skill's `SKILL.md` that the script supports caching, and ensure the `--no-cache` flag is listed in the script's argparse definition. The cache is self-registering via `get_cached()`/`cache_result()` calls -- no separate registry file is needed.
