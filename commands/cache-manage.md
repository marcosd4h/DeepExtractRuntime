# Cache Manage

## Overview

View statistics, clear, or refresh cached analysis results stored in `.agent/cache/`. Caching significantly speeds up commands like `/triage`, `/full-report`, and `/audit` by avoiding redundant expensive computations.

Usage:

- `/cache-manage stats` -- show cache size, hit rates, and oldest entries
- `/cache-manage clear` -- clear all cached results
- `/cache-manage clear appinfo.dll` -- clear cache for a specific module
- `/cache-manage refresh appinfo.dll` -- clear and re-run common analysis for a module
- `/cache-manage purge-runs` -- delete old workspace run directories
- `/cache-manage purge-runs --older-than 1` -- delete workspace runs older than 1 day

## Steps

1. **View Statistics** (`/cache-manage stats`)
   - Use the **cache** helper (`cache_stats()`) to gather metrics.
   - Present a summary:
     - **Total Size**: total disk space used by cache
     - **File Count**: number of cached JSON results
     - **Module Breakdown**: size and count per module
     - **Oldest Entry**: timestamp of the oldest cached result

2. **Clear Cache** (`/cache-manage clear`)
   - Use the **cache** helper (`clear_cache()`) to remove files.
   - If a module is specified, only clear that module's subdirectory.
   - Report the number of files deleted.

3. **Refresh Cache** (`/cache-manage refresh`)
   - Clear the cache for the specified module.
   - Re-run common analysis scripts to populate the cache:
     - `classify_module.py` (classify-functions skill)
     - `build_call_graph.py` (callgraph-tracer skill)
     - `analyze_topology.py` (generate-re-report skill)
   - This ensures the cache is fresh and ready for subsequent commands.

4. **Purge Workspace Runs** (`/cache-manage purge-runs`)
   - Run `python .agent/helpers/cleanup_workspace.py` to delete stale workspace run directories.
   - Default: deletes runs older than 7 days.
   - Use `--older-than N` to specify a custom age threshold (in days).
   - Use `--dry-run` to preview what would be deleted without actually removing anything.
   - Also cleans up stale code-lifter state files from `.agent/agents/code-lifter/state/`.

## Output

Present the cache management results in chat.

**Follow-up suggestions**:

- `/triage <module>` -- run a fresh triage after refreshing the cache.
- `/audit <module> <function>` -- audit a function with fresh analysis data.

## Error Handling

- **Cache directory not found**: Report that no cache exists yet; nothing to manage
- **Permission error**: Report the file path and suggest checking filesystem permissions
- **Invalid subcommand**: List available subcommands: `stats`, `clear`, `refresh`, `purge-runs`
