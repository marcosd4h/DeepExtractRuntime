# Runs

## Overview

Browse prior workspace runs created by multi-step workflows such as `/triage`,
`/full-report`, `/scan`, and `/batch-audit`. Use this command to list the most
recent runs, reopen the latest run for a module, or inspect the step summaries
from a specific run without re-running the workflow.

Usage:

- `/runs` -- list the 10 most recent runs
- `/runs list` -- list the 10 most recent runs
- `/runs list appinfo.dll` -- list recent runs for a module
- `/runs show appinfo.dll_triage_20260306_031523` -- reopen one run by ID
- `/runs latest appinfo.dll` -- reopen the newest run for a module

## IMPORTANT: Execution Model

Execute immediately. Do NOT ask for confirmation. Read the existing workspace
artifacts and present the results directly.

## Execution Context

> **IMPORTANT**: Any inline Python that imports `helpers.*` must run with
> `cd <workspace>/.agent` so the `.agent/` directory is on `sys.path`.

This command should use the helpers library rather than manually traversing
JSON:

- `helpers.workspace.list_runs()` for run discovery and sorting
- `helpers.workspace.read_summary()` for per-step summaries
- `helpers.workspace_validation.validate_workspace_run()` to validate a run

## Steps

### Step 0: Preflight Validation

Parse the subcommand and optional module filter:

- No subcommand -> `list`
- `list [module]`
- `show <run_id>`
- `latest [module]`

If a module filter is present for `list` or `latest`, validate it with:

```python
from helpers.command_validation import validate_command_args
result = validate_command_args("runs", {"module": "<module>"})
```

If validation fails, report the errors and stop.

### Step 1: `/runs` or `/runs list [module]` -- List Recent Runs

Use inline Python from `.agent/`:

```python
from helpers.workspace import list_runs
runs = list_runs(module="<module_or_None>", limit=10)
```

Present a compact table:

| Run ID | Module | Goal | Status | Updated | Steps |
|--------|--------|------|--------|---------|-------|

For each row, use:

- `run_id`
- `module_name`
- `goal`
- `status`
- `updated_at`
- `step_count`

If no runs match, say so clearly. For module-filtered queries, suggest removing
the module filter to view all runs.

### Step 2: `/runs show <run_id>` -- Reopen a Specific Run

1. Use `list_runs(limit=None)` to load all known runs.
2. Match the requested `run_id` exactly. If there is no exact match, allow a
   unique prefix match.
3. Validate the selected run with:

```python
from helpers.workspace_validation import validate_workspace_run
result = validate_workspace_run("<run_dir>")
```

4. Load per-step summaries using:

```python
from helpers.workspace import read_summary
summary = read_summary("<run_dir>", "<step_name>")
```

5. Read full `results.json` only when a step summary is missing and you need a
   minimal fallback description.

Present:

- Run metadata: run ID, module, goal, created/updated timestamps
- Validation state: valid/invalid plus any issues from `validate_workspace_run`
- Step overview table: step name, status, summary path
- Per-step summaries pulled from `summary.json`
- Artifact locations: run directory and manifest path

### Step 3: `/runs latest [module]` -- Reopen the Newest Matching Run

Use inline Python:

```python
from helpers.workspace import list_runs
runs = list_runs(module="<module_or_None>", limit=1)
```

If a run exists, render it using the same flow as `show`. If none exist, report
that no matching runs were found.

## Output

For `list`, return a compact recent-runs table ordered by most recent update.

For `show` and `latest`, return a structured run summary with:

- Metadata
- Validation status
- Step table
- Step summaries
- Artifact paths

Keep the response concise. Use `results.json` only for targeted fallback detail;
prefer `summary.json` to avoid dumping large payloads into chat.

**Follow-up suggestions:**

- `/runs show <run_id>` -- inspect a specific run from the list
- `/triage <module>` -- refresh stale orientation data
- `/scan <module>` -- re-run a security workflow if the saved run is outdated

## Error Handling

- **No workspace runs found**: report that `.agent/workspace/` has no runs yet
- **Unknown run ID**: show the 5 most recent run IDs to help the user choose
- **Ambiguous prefix match**: list the matching run IDs and ask the user to pick one
- **Invalid run structure**: show available metadata and validation issues rather than failing completely
- **Missing step summary**: report the step status and note that `summary.json` is missing
