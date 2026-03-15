# Headless Pipeline Guide

This guide documents the headless batch pipeline mode implemented by
`helpers/pipeline_cli.py`. It lets you run analysis pipelines across one or
more modules without an interactive Cursor session.

For interactive use within a Cursor session, the `/pipeline` slash command
wraps the same CLI.

Use batch pipelines when you want to:

- Run the same analysis sequence across multiple modules
- Schedule repeatable sweeps (triage, security, scan, type reconstruction)
- Capture results in a predictable workspace directory
- Validate a plan before executing it

Use interactive slash commands when you want iterative exploration, ad-hoc
follow-up questions, or agent-driven synthesis in chat.

---

## Quick Start

1. Write a pipeline YAML file, or start from one of the examples in
   `config/pipelines/`.
2. Validate it:

   ```bash
   python .agent/helpers/pipeline_cli.py validate config/pipelines/security-sweep.yaml
   ```

3. Execute it:

   ```bash
   python .agent/helpers/pipeline_cli.py run config/pipelines/security-sweep.yaml
   ```

For a no-side-effects preview, use:

```bash
python .agent/helpers/pipeline_cli.py run config/pipelines/security-sweep.yaml --dry-run
```

---

## CLI Reference

### `run`

Execute a pipeline definition.

```bash
python .agent/helpers/pipeline_cli.py run <pipeline.yaml> [--dry-run] [--modules m1,m2] [--output DIR] [--json]
```

Options:

| Flag | Meaning |
|------|---------|
| `--dry-run` | Resolve modules and steps without running analysis |
| `--modules` | Override the YAML `modules` field with a comma-separated list or `all` |
| `--output` | Override the YAML output directory template |
| `--json` | Emit machine-readable JSON to stdout |

### `validate`

Parse and validate a pipeline definition without running any analysis.

```bash
python .agent/helpers/pipeline_cli.py validate <pipeline.yaml> [--modules m1,m2] [--output DIR] [--json]
```

Validation checks:

- YAML structure is valid
- All step names are known
- Step options have valid types
- All modules resolve to analysis DBs
- Each resolved DB passes `validate_analysis_db()`

### `list-steps`

List every supported top-level pipeline step.

```bash
python .agent/helpers/pipeline_cli.py list-steps
python .agent/helpers/pipeline_cli.py list-steps --json
```

---

## YAML Schema

Minimal example:

```yaml
name: security-sweep

modules:
  - appinfo.dll
  - consent.exe

steps:
  - triage: {}
  - security:
      top: 10
  - scan:
      top: 10

settings:
  continue_on_error: true
  max_workers: 4
  step_timeout: 420
  parallel_modules: true
  max_module_workers: 2
  no_cache: false

output: workspace/batch_{name}_{timestamp}/
```

### Top-Level Keys

| Key | Required | Type | Description |
|-----|----------|------|-------------|
| `name` | No | string | Pipeline name. Defaults to the YAML filename stem. |
| `modules` | Yes | string or list | Either `all` or a non-empty list of module names. |
| `steps` | Yes | list | Non-empty list of step definitions. |
| `settings` | No | mapping | Execution settings overriding config defaults. |
| `output` | No | string | Output directory template. |

Unknown top-level keys are rejected.

### `modules`

Accepted forms:

```yaml
modules: all
```

```yaml
modules:
  - appinfo.dll
  - consent.exe
```

Rules:

- `all` resolves every module with a complete analysis DB
- A list entry must be a non-empty string
- Duplicate modules are deduplicated after resolution

### `steps`

Each step is either:

- A bare string for steps with no options
- A single-key mapping for steps with options

Examples:

```yaml
steps:
  - triage
  - types: {}
  - scan:
      top: 10
```

This is invalid:

```yaml
steps:
  - triage:
      quick: true
    scan:
      top: 10
```

Each list item must contain exactly one step name.

### `settings`

Supported settings:

| Setting | Type | Default source | Description |
|---------|------|----------------|-------------|
| `continue_on_error` | bool | `config.defaults.json` | Continue to later steps/modules after a failure |
| `max_workers` | int | `config.defaults.json` | Max worker threads within grouped steps |
| `step_timeout` | int | `config.defaults.json` | Per-step timeout in seconds |
| `parallel_modules` | bool or int | `config.defaults.json` | `false` = sequential, `true` = use `max_module_workers`, integer = explicit module worker count |
| `max_module_workers` | int | `config.defaults.json` | Module worker count when `parallel_modules: true` |
| `no_cache` | bool | `config.defaults.json` | Pass `--no-cache` to supported skill scripts |

Unknown settings are rejected.

### `output`

`output` is a directory template. The runner expands:

- `{name}` -> sanitized pipeline name
- `{timestamp}` -> UTC timestamp in `YYYYMMDD_HHMMSS`

Examples:

```yaml
output: workspace/batch_{name}_{timestamp}/
output: .agent/workspace/nightly_{timestamp}/
output: reports/pipeline_runs/{name}_{timestamp}/
```

Path semantics:

- Absolute paths are used as-is
- Relative paths are resolved from the workspace root
- `workspace/...` is a shorthand for `.agent/workspace/...`

---

## Step Reference

### Goal-backed steps

These steps delegate to existing agent orchestrators instead of reimplementing
the analysis logic.

| Step | Backing entry point | Description | Options |
|------|---------------------|-------------|---------|
| `triage` | `agents/triage-coordinator/scripts/analyze_module.py --goal triage` | Classification + attack surface discovery | `quick` (bool, compatibility flag) |
| `security` | `agents/triage-coordinator/scripts/analyze_module.py --goal security` | Triage + ranked entrypoints + dossiers + taint | `top` (int) |
| `full-analysis` | `agents/triage-coordinator/scripts/analyze_module.py --goal full` | Full module analysis | `top` (int) |
| `types` | `agents/triage-coordinator/scripts/analyze_module.py --goal types` | Type reconstruction + COM scanning | none |
| `scan` | `agents/security-auditor/scripts/run_security_scan.py --goal scan` | Full multi-phase security scan | `top` (int), `memory_only` (bool), `logic_only` (bool), `taint_only` (bool) |

Notes:

- `scan` accepts at most one of `memory_only`, `logic_only`, or `taint_only`
- The full `scan` step reuses the security-auditor pipeline
- The `*_only` forms dispatch directly to the relevant grouped skill steps

### Direct skill-group steps

These steps orchestrate one or more skill scripts directly.

| Step | Scripts | Description | Options |
|------|---------|-------------|---------|
| `memory-scan` | `build_threat_model.py`, `prepare_context.py` + LLM-driven analysis | AI-driven memory corruption detection via callgraph navigation | `top` (int) |
| `ai-logic-scan` | `build_threat_model.py`, `prepare_context.py` + LLM-driven analysis | AI-driven logic vulnerability detection via callgraph navigation | `top` (int) |
| `entrypoints` | `discover_entrypoints.py`, `rank_entrypoints.py` | Attack surface discovery + ranking | `top` (int) |
| `classify` | `triage_summary.py` | Triage-oriented function classification summary | `top` (int) |
| `callgraph` | `build_call_graph.py --stats` | Call graph statistics | `stats` (bool) |
| `taint` | `rank_entrypoints.py` + `taint_function.py` | Taint analysis on top-ranked entry points | `top` (int), `depth` (int) |
| `dossiers` | `rank_entrypoints.py` + `build_dossier.py` | Security dossiers for top-ranked entry points | `top` (int) |

---

## Workspace Layout

Batch pipelines write into a top-level batch directory with per-module and
per-step subdirectories.

Example:

```text
.agent/workspace/batch_security-sweep_20260306_010203/
  batch_manifest.json
  batch_summary.json
  appinfo.dll/
    triage/
      manifest.json
      classify_triage/results.json
      classify_triage/summary.json
      classify_full/results.json
      classify_full/summary.json
      discover_entrypoints/results.json
      discover_entrypoints/summary.json
    scan/
      manifest.json
      build_threat_model/results.json
      build_threat_model/summary.json
      ...
  consent.exe/
    triage/
      ...
```

### `batch_manifest.json`

Tracks overall pipeline progress while the run is in flight.

Key fields:

- `pipeline_name`
- `pipeline_file`
- `started_at`
- `updated_at`
- `modules`
- `steps`
- `settings`
- `progress`

Each module/step record includes:

- `status`
- `elapsed_seconds`
- `workspace_path`
- `error`

### `batch_summary.json`

Final consolidated output after the run completes.

Key fields:

- Top-level run status (`ok`, `partial`, or `error`)
- Output directory
- Module counts
- Total step count
- Elapsed time
- Per-module execution details

### Per-step `manifest.json`

Each top-level step directory is itself a workspace run directory and reuses the
existing workspace handoff contract:

- `manifest.json`
- per-substep `results.json`
- per-substep `summary.json`

This keeps the batch mode aligned with the interactive runtime.

---

## Validation and Failure Semantics

### Validation phase

`pipeline_cli.py validate` and `pipeline_cli.py run` both validate before execution:

- YAML is parsed with `yaml.safe_load`
- Step names are checked against `STEP_REGISTRY`
- Step option types are validated
- Modules are resolved through existing helpers
- Each DB is validated with `validate_analysis_db()`

### Failure handling

If `continue_on_error: true`:

- A failed step marks the module as `partial` or `failed`
- Later steps still run
- Later modules still run

If `continue_on_error: false`:

- A failed step stops further steps for that module
- Other modules still run unless the failure occurs during global setup

### Cache behavior

If `no_cache: true`, the runner passes `--no-cache` to supported skill scripts.
Scripts that do not support `--no-cache` keep their normal behavior.

---

## Environment Overrides

Pipeline defaults live in `config/defaults.json` under the `pipeline` section.

They can be overridden with `DEEPEXTRACT_*` environment variables, for example:

```bash
set DEEPEXTRACT_PIPELINE__DEFAULT_STEP_TIMEOUT=600
set DEEPEXTRACT_PIPELINE__MAX_WORKERS=8
set DEEPEXTRACT_PIPELINE__CONTINUE_ON_ERROR=false
```

The batch runner also reuses existing config-driven behavior from other runtime
components, such as `triage.max_workers`.

---

## Examples

Reference YAML files live in `config/pipelines/`:

- `quick-triage.yaml`
- `security-sweep.yaml`
- `full-analysis.yaml`
- `function-deep-dive.yaml`

Useful commands:

```bash
python .agent/helpers/pipeline_cli.py list-steps
python .agent/helpers/pipeline_cli.py validate config/pipelines/quick-triage.yaml
python .agent/helpers/pipeline_cli.py run config/pipelines/quick-triage.yaml --dry-run
python .agent/helpers/pipeline_cli.py run config/pipelines/security-sweep.yaml --json
python .agent/helpers/pipeline_cli.py run config/pipelines/security-sweep.yaml --modules appinfo.dll,consent.exe
python .agent/helpers/pipeline_cli.py run config/pipelines/full-analysis.yaml --output workspace/custom_{timestamp}/
```

---

## Extending the Step Vocabulary

To add a new top-level pipeline step:

1. Add a `StepConfig` entry to `helpers/pipeline_schema.py` in `STEP_REGISTRY`
2. Define its option schema with `OptionSpec`
3. Implement dispatch logic in `helpers/pipeline_executor.py`
4. Document the new step here
5. Add or update example YAML files if the step is user-facing
6. Add tests covering parsing, validation, and execution behavior

Prefer delegating to existing skills or agent entry points. Do not duplicate
analysis logic that already exists elsewhere in the runtime.
