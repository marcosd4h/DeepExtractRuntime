---
description: Enforce Sub-Agent Workspace Pattern for multi-skill pipelines to prevent context-window bloat.
alwaysApply: true
---

# Sub-Agent Workspace Pattern

Use filesystem handoff for any multi-step or multi-skill workflow to keep coordinator context compact.

## When It Is Required

Apply this pattern when:

- A coordinator runs 2+ skill scripts or sub-agents.
- A command performs phased analysis (`triage`, `security`, `full`, batch lifting, multi-function verification, etc.).
- Intermediate outputs are large JSON payloads.

## Run Directory

Create (or reuse) a run directory under `.agent/workspace/`, for example:

- `.agent/workspace/<module>_<goal>_<timestamp>/`

The run directory must contain `manifest.json` with per-step status records.

## Invocation Contract

Every step in the pipeline must be invoked with:

- `--workspace-dir <run_dir>`
- `--workspace-step <step_name>`

`<step_name>` should be stable, unique in the run, and safe for paths.

## Step Output Contract

When workspace args are present, each step must:

1. Write full payload to `<run_dir>/<step_name>/results.json`
2. Write compact summary to `<run_dir>/<step_name>/summary.json`
3. Update `<run_dir>/manifest.json` with step status and summary path
4. Print only the compact summary JSON to stdout (not the full payload)

## Context Policy

- Keep only compact summaries and file references in coordinator context/output.
- Never inline full multi-step JSON into coordinator responses.
- Load `results.json` only on demand for synthesis, ranking, or targeted follow-up.

## Coordinator Requirements

Coordinator scripts should:

- Create `workspace_run_dir` when not provided.
- Pass workspace args to all child steps.
- Store returned summary metadata (status, key counts, top items, file paths).
- Include `workspace_run_dir` and `workspace_manifest` in final structured output.

## Failure Handling

- Failed steps still write summary/error info and update manifest status.
- Coordinators should continue where possible and use manifest state as source of truth.

## Error Output Contract

All skill scripts use `emit_error()` from `helpers.errors` for structured error output:

- On failure, scripts write a single JSON line to **stderr**: `{"error": "<message>", "code": "<code>"}`
- Exit code is always **1** on error.
- Error codes: `NOT_FOUND`, `INVALID_ARGS`, `DB_ERROR`, `PARSE_ERROR`, `NO_DATA`, `AMBIGUOUS`, `UNKNOWN`.
- Coordinators should parse stderr for this JSON format when a child step exits non-zero.

## JSON Output Contract

All data-producing skill scripts support `--json` for machine-readable output:

- When `--json` is passed, scripts write only valid JSON to **stdout**.
- Human-readable text output (tables, headers) is the default when `--json` is omitted.
- Progress/status messages always go to **stderr**, never stdout.
