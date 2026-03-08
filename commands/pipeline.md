# Pipeline

## Overview

Run, validate, or inspect headless batch analysis pipelines from YAML
definitions. Wraps the `pipeline_cli.py` CLI for interactive use within a
Cursor session.

Usage:

- `/pipeline run config/pipelines/security-sweep.yaml` -- execute a pipeline
- `/pipeline run config/pipelines/quick-triage.yaml --dry-run` -- preview without executing
- `/pipeline run config/pipelines/full-analysis.yaml --modules appinfo.dll,consent.exe` -- override modules
- `/pipeline validate config/pipelines/security-sweep.yaml` -- validate without executing
- `/pipeline list-steps` -- show available pipeline steps

For YAML schema details and example pipeline files, see
[docs/pipeline_guide.md](../docs/pipeline_guide.md) and
`config/pipelines/`.

## Execution Context

> **IMPORTANT**: Invoke `pipeline_cli.py` from the workspace root:
> `python .agent/helpers/pipeline_cli.py <subcommand> <args> --json`

Always pass `--json` when parsing output programmatically.

## Steps

### Step 0: Preflight Validation

For `run` and `validate` subcommands, verify the pipeline YAML file path
exists and is readable before invoking the CLI. For `list-steps`, skip
validation.

### 1. Invoke pipeline CLI

Run the appropriate subcommand:

```bash
# List available steps
python .agent/helpers/pipeline_cli.py list-steps --json

# Validate a pipeline definition
python .agent/helpers/pipeline_cli.py validate <pipeline_file> --json

# Execute a pipeline (with optional flags)
python .agent/helpers/pipeline_cli.py run <pipeline_file> [--dry-run] [--modules M] [--output DIR] --json
```

Parse JSON stdout for the result payload.

### 2. Present results

**For `list-steps`**: present available steps as a table with columns: name,
kind, description, and supported options.

**For `validate`**: present pipeline name, resolved modules, rendered output
path, step summary, and any warnings.

**For `run --dry-run`**: present the planned execution (modules x steps) without
running any analysis.

**For `run`**: present a summary table:

| Column   | Source                                   |
| -------- | ---------------------------------------- |
| Module   | `modules.<name>.module_name`             |
| Status   | `modules.<name>.status`                  |
| Elapsed  | `modules.<name>.elapsed_seconds`         |
| Steps    | count of `modules.<name>.step_results`   |
| Errors   | `modules.<name>.errors`                  |

Include the overall pipeline status (`ok`, `partial`, or `error`), total
elapsed time, and output directory path. For each failed step, include the
step name and error message.

## Output

Present a structured summary in chat. For `run`, the summary includes:

- Pipeline name and YAML source path
- Overall status (ok / partial / error)
- Per-module results table (module, status, elapsed, step count, errors)
- Per-step breakdown within each module when steps failed
- Output directory path for on-disk artifacts

For `validate` and `list-steps`, present a compact informational summary.

## Error Handling

| Failure                                | Recovery                                                                |
| -------------------------------------- | ----------------------------------------------------------------------- |
| YAML file not found                    | Report the path and suggest checking `config/pipelines/`                |
| YAML parse error                       | Report the parse error returned by the CLI                              |
| Unknown step name in YAML              | Report which step is unknown and list available steps                   |
| No modules resolved                    | Report which modules were requested and that none matched available DBs |
| Step failure with `continue_on_error`  | Report partial results -- show what completed and what failed           |
| Step failure without `continue_on_error` | Report what completed, what failed, and that execution stopped early  |
| CLI script not found                   | Suggest running `/health` to verify workspace integrity                 |
