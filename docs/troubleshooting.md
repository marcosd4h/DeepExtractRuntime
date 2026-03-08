# Troubleshooting Guide -- DeepExtractIDA Agent Analysis Runtime

This guide provides procedures for diagnosing and resolving common failures within the Agent Analysis Runtime.

## 4.1 Structured Error Code Reference

The runtime uses structured JSON error output to stderr via `helpers.errors.emit_error()`.

| Code           | Definition                                        | Common Trigger Conditions                                                | Resolution Steps                                                     |
| -------------- | ------------------------------------------------- | ------------------------------------------------------------------------ | -------------------------------------------------------------------- |
| `NOT_FOUND`    | Requested resource does not exist.                | Module name mismatch, function ID out of range, missing DB file.         | Verify module name in tracking DB, check function ID in analysis DB. |
| `INVALID_ARGS` | Provided arguments are malformed or incompatible. | Missing required flags, invalid regex pattern, type mismatch.            | Validate CLI arguments against script `README.md` or `--help`.       |
| `DB_ERROR`     | Database access failure.                          | SQLite file corruption, locked database, schema mismatch.                | Run `quick_validate()`, check for concurrent write processes.        |
| `PARSE_ERROR`  | Data parsing failure.                             | Malformed JSON in DB column, corrupted cache file, invalid C++ mangling. | Bypass cache with `--no-cache`, inspect raw DB records.              |
| `NO_DATA`      | Query returned no results.                        | Empty analysis DB, search pattern matched zero functions.                | Broaden search criteria, verify extraction status of the module.     |
| `UNKNOWN`      | Unclassified internal error.                      | Unhandled exception, environment failure.                                | Inspect stderr for full traceback and system logs.                   |

**stderr JSON format:** `{"error": "<message>", "code": "<code>"}`

## 4.2 Common Failure Scenarios

### Module DB Resolution Failure

- **Symptom**: `resolve_module_db()` returns `None`.
- **Cause**: The tracking database at `extracted_dbs/analyzed_files.db` is missing, the module name does not match any `file_name` entry, or the module status is not `complete`.
- **Resolution**: Verify the module name using `python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py --list`. Ensure the extraction process finished successfully.

### Function Lookup Failure

- **Symptom**: `resolve_function()` returns `(None, error_msg)`.
- **Cause**: Exact name match failed and partial match returned multiple hits, the function is filtered by a library tag, or the function ID is invalid.
- **Resolution**: Use the function ID instead of the name. If searching by name, provide a more specific pattern or use `--all` to include library functions.

### Stale Cache Results

- **Symptom**: A skill script returns outdated data after a module re-extraction.
- **Cause**: The database `mtime` is within the 1-second tolerance of the cached `db_mtime`, or the TTL has not expired.
- **Resolution**: Execute the script with the `--no-cache` flag, or call `clear_cache("module_name")` to force a recomputation.

### Grind-Loop Stall

- **Symptom**: The agent re-invokes automatically but makes no progress on the task list.
- **Cause**: The scratchpad status is not set to `DONE`, there is a session ID mismatch between the hook and the agent, or the scratchpad file path is incorrect.
- **Resolution**: Inspect `.agent/hooks/scratchpads/` for the active scratchpad. Manually set the status to `DONE` to stop the loop, or delete the file to reset the task.

### Script Runner Subprocess Failure

- **Symptom**: `run_skill_script()` returns a non-zero exit code.
- **Cause**: Python import errors, missing database files, or malformed arguments.
- **Resolution**: Inspect the stderr output for the specific error JSON. The script runner automatically retries up to 2 times if the error message contains "database is locked."

### Read-Only DB Enforcement Error

- **Symptom**: SQLite returns an error indicating the database is read-only.
- **Cause**: Code attempted an `INSERT` or `UPDATE` operation on an analysis database opened through the helper layer.
- **Resolution**: All helper-mediated database connections enforce `PRAGMA query_only = ON`. Modifications to analysis databases must be performed through the extraction pipeline, not the runtime.

### Workspace Handoff Failure

- **Symptom**: A coordinator script cannot read results from a previous step.
- **Cause**: The child step failed to write `results.json` to its designated workspace directory, the `manifest.json` was not updated, or the step exited with an error.
- **Resolution**: Inspect `.agent/workspace/<run_dir>/manifest.json` to identify the failed step. Check the corresponding step directory for error logs.

## 4.3 Debugging Procedures

- **Parse stderr JSON**: Always check stderr for structured error codes and messages when a script fails.
- **Bypass Cache**: Use the `--no-cache` flag to eliminate stale or corrupted cache files as a source of error.
- **Inspect Cache Directory**: List `.agent/cache/<module>/` to verify which operations have been cached and inspect their JSON envelopes.
- **Validate Database**: Use `helpers.validation.quick_validate(db_path)` to check for SQLite schema integrity and required tables.
- **Direct Execution**: Run skill scripts directly from the terminal with the `--json` flag to isolate subprocess behavior from agent logic.
- **Inspect Workspace**: Read `.agent/workspace/<run_dir>/manifest.json` to trace the execution status of multi-step pipelines.

## 4.4 Script Runner Retry Behavior

The `script_runner.py` module implements a 2-retry loop for transient database errors. If a subprocess exits with a non-zero code and the stderr contains the string "database is locked," the runner waits for a short interval and re-executes the command. If the error persists after two retries, the final error is propagated to the caller.

## 4.5 Workspace Run Cleanup

Workspace run directories accumulate under `.agent/workspace/` during multi-step workflows (`/triage`, `/full-report`, `/lift-class`). Each run creates a timestamped directory with `manifest.json`, `results.json`, and `summary.json` files.

To clean up stale workspace runs:

```bash
# Preview what would be deleted (default: older than 7 days)
python .agent/helpers/cleanup_workspace.py --dry-run

# Delete workspace runs older than 7 days
python .agent/helpers/cleanup_workspace.py

# Delete runs older than 1 day
python .agent/helpers/cleanup_workspace.py --older-than 1
```

Or use the `/cache-manage purge-runs` command from chat.

The cleanup script also removes stale code-lifter state files from `.agent/agents/code-lifter/state/`.
