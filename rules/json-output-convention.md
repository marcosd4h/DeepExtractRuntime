---
description: Conventions for JSON vs human-readable output in skill scripts
globs:
  - ".agent/skills/*/scripts/*.py"
  - ".agent/agents/*/scripts/*.py"
alwaysApply: true
---

# JSON Output Convention

## When to Produce JSON

- When `--json` flag is passed on the command line.
- When `--workspace-dir` is active (workspace bootstrap handles this automatically).
- When stdout is being piped to another process (detected by workspace handoff).

## Stdout vs Stderr Separation

- **stdout**: Data output only. Either structured JSON (`--json`) or human-readable tables/text (default).
- **stderr**: Progress messages, warnings, and structured errors. Never data.

## JSON Output Rules

1. When `--json` is active, emit **exactly one** JSON document to stdout.
2. The document must be a dict (not a bare list or string).
3. Include a `"status"` key (`"ok"` or `"error"`) at the top level.
4. The `"status"` key MUST be exactly `"ok"` or `"error"`. Other values
   like `"partial"`, `"dry_run"`, `"success"`, or `"planned"` are
   FORBIDDEN at the top level. Use additional fields (e.g. `"dry_run": true`,
   `"pipeline_complete": false`) to convey sub-states.
5. Progress/status messages go to stderr via `helpers.progress.status_message()`.
6. Errors go to stderr via `helpers.errors.emit_error()` or `log_error()`.

## Script Implementation Rules (for script authors)

0. **Always use `status_message()` for progress output.** When emitting
   progress or status messages to stderr, use `status_message()` from
   `helpers.progress` -- never bare `print(..., file=sys.stderr)`. This
   ensures consistent `[status]` prefixing that downstream consumers and
   the QA runner can distinguish from actual errors. For structured
   progress events, use `ProgressReporter` from the same module.
1. **Every code path** that writes to stdout must respect `--json`. This
   includes `--search` result listings, multi-match disambiguation tables,
   empty-result messages, and any other "interactive" paths. No code path
   is exempt from `--json`.
2. When `--json` is active, **never call `print()` to stdout**. Use
   `emit_json()` or `emit_json_list()` from `helpers.json_output`
   exclusively. For error/ambiguous conditions, use `emit_error()` which
   writes structured JSON to stderr and exits.
3. When `main()` dispatches to a helper function (e.g. `search_functions()`),
   **always pass the `as_json` / `--json` flag through**. Do not assume
   helper functions are "interactive-only".
4. Search/listing results under `--json` must return a structured dict with
   the match list (e.g. `{"match_count": N, "matches": [...]}`), not a
   hint message like "Use --id <ID>".
5. Multi-match disambiguation under `--json` should use `emit_error()` with
   `ErrorCode.AMBIGUOUS`, not `print()` the match table to stdout.
6. **Agent scripts follow the same conventions as skill scripts.** Every agent
   entry-point script (in `.agent/agents/*/scripts/`) must use `emit_json()`
   or `emit_json_list()` from `helpers.json_output` -- never raw
   `print(json.dumps(...))`. This ensures the `"status"` key is always
   present and the output contract is consistent for callers.
7. **Status values must be standard.** The top-level `"status"` key in JSON
   output must be `"ok"` or `"error"` -- no other values (e.g. `"not_found"`,
   `"target_not_found"`, `"no_code"`). For error conditions, use
   `emit_error()` with the appropriate `ErrorCode`. Internal recursive
   structures may use non-standard status values in nested dicts, but the
   top-level result emitted to stdout must be normalized before emission.

## Human-Readable Output Rules

1. Use formatted tables for multi-row data.
2. Use section headers (`=== Section ===`) for visual grouping.
3. Keep line widths under 120 characters when practical.
4. Always print to stdout (not stderr) for data output.

## Script Invocation Rules (for the agent calling scripts)

1. **Never use `2>/dev/null`** on skill script invocations. Stderr carries
   structured error JSON and progress messages -- suppressing it hides the
   cause of failures and prevents self-correction.
2. **Never write inline `python -c` commands** to query databases or perform
   operations that an existing skill script already handles. Use the provided
   scripts (e.g. `list_functions.py <db_path> --search "<pattern>"`,
   `extract_function_data.py <db_path> <function_name>`).
   Inline Python with shell variable interpolation is fragile, especially on
   Windows.
3. When a script exits non-zero, **read stderr** to diagnose the error before
   retrying or moving on. The error will be structured JSON with `"error"` and
   `"code"` fields.
4. **Never use `2>&1` when piping `--json` output.** Stderr carries structured
   warnings and errors as separate JSON lines (e.g. `{"warning": "...", "code": "..."}`).
   Merging stderr into stdout with `2>&1` produces multiple JSON documents on
   the same stream, which breaks any downstream `json.load()` / `json.loads()`
   parser with an "Extra data" error. If you need both streams, capture them
   separately.
5. **Never pipe `--json` output through `python -c` or other inline
   post-processing filters.** The `--json` flag already produces a complete,
   well-structured JSON document with every field the script supports. If you
   need a subset of fields, read the Shell output directly. For large JSON
   files (agent-tools output, workspace results), use
   `python .agent/helpers/json_extract.py <file> <key>` to extract specific
   keys without inline Python.

## Common Invocation Mistakes

**BAD** -- merging stderr into stdout before a JSON parser:

```bash
python script.py <db_path> --id 42 --json 2>&1 | python -c "import sys,json; d=json.load(sys.stdin); ..."
```

This fails because stderr warnings (valid JSON lines) get prepended to the
stdout JSON document, producing two concatenated JSON objects that
`json.load()` cannot parse.

**GOOD** -- use `--json` output directly, no pipe:

```bash
python script.py <db_path> --id 42 --json
```

The output is already the complete JSON document. Read it directly from the
command's stdout. Stderr warnings remain visible for diagnostics without
corrupting the data stream.
