# FR-004: Remove YAML, Use JSON for Pipeline Definitions

**Status:** Proposed
**Priority:** Low
**Category:** Infrastructure / Simplification
**Author:** Runtime Assessment Review
**Date:** 2026-03-16

---

## Problem Statement

YAML is used only for pipeline definitions (4 files in
`.claude/config/pipelines/`).  It adds a `pyyaml>=6.0` dependency and
a separate parsing path for no meaningful benefit over JSON, which is
already the standard format for every other config and data file in
the workspace:

- `defaults.json` -- runtime configuration
- `registry.json` -- skills, agents, commands registries
- `module_profile.json` -- per-module fingerprints
- `file_info.json` -- PE metadata
- `function_index.json` -- function-to-file resolution
- All workspace handoff files (`results.json`, `summary.json`, `manifest.json`)

The 4 pipeline YAML files use zero YAML-specific features (no anchors,
no aliases, no multi-document, no complex keys).  Their content is
structurally identical to JSON.  Removing YAML simplifies the
dependency tree and makes the pipeline format consistent with
everything else.

---

## Current State

### YAML Consumers (exactly 1)

| File | Usage |
|------|-------|
| `helpers/pipeline_schema.py` | `yaml.safe_load()` in `load_pipeline()` |

No other file in the runtime imports `yaml`.

### Pipeline Definition Files (4)

| File | Purpose |
|------|---------|
| `config/pipelines/quick-triage.yaml` | Lightweight triage across listed modules |
| `config/pipelines/security-sweep.yaml` | Security-focused scan pipeline |
| `config/pipelines/full-analysis.yaml` | End-to-end multi-phase analysis |
| `config/pipelines/function-deep-dive.yaml` | Single-function deep analysis |

Example current YAML:

```yaml
name: quick-triage
modules:
  - appinfo.dll
  - shell32.dll
steps:
  - triage:
      quick: true
settings:
  continue_on_error: true
  max_workers: 4
  step_timeout: 300
  parallel_modules: false
  no_cache: false
output: workspace/batch_{name}_{timestamp}/
```

Equivalent JSON (no information loss):

```json
{
  "name": "quick-triage",
  "modules": ["appinfo.dll", "shell32.dll"],
  "steps": [
    {"triage": {"quick": true}}
  ],
  "settings": {
    "continue_on_error": true,
    "max_workers": 4,
    "step_timeout": 300,
    "parallel_modules": false,
    "no_cache": false
  },
  "output": "workspace/batch_{name}_{timestamp}/"
}
```

### PyYAML Dependency

`pyproject.toml` includes `"pyyaml>=6.0"`.  This is the only
YAML-related dependency.

### Documentation and Tests That Reference YAML

| File | Reference |
|------|-----------|
| `docs/pipeline_guide.md` | Schema docs with YAML examples |
| `commands/pipeline.md` | `/pipeline` command usage with YAML paths |
| `commands/README.md` | `/pipeline` description |
| `tests/test_pipeline_schema.py` | `_write_pipeline()` writes YAML fixtures |
| `tests/test_pipeline_executor.py` | References `.yaml` source paths |
| `tests/test_ai_logic_scanner.py` | Minor YAML reference |

---

## Proposed Solution

### 1. Convert Pipeline Files from YAML to JSON

Convert the 4 YAML files to JSON.  The structure maps 1:1 with no
information loss.  Delete the `.yaml` files after conversion.

### 2. Update `pipeline_schema.py`

Replace `yaml.safe_load()` with `json.load()` in `load_pipeline()`.
Remove the `import yaml` block.  The dataclass structures
(`PipelineDef`, `StepDef`, `PipelineSettings`) stay unchanged -- they
consume dicts from either parser.

### 3. Remove `pyyaml` from `pyproject.toml`

Delete the `"pyyaml>=6.0"` dependency line.

### 4. Update `pipeline_cli.py`

Accept `.json` files.  Update help text, error messages, and
file-extension checks.

### 5. Update Documentation

Replace YAML examples with JSON in:
- `docs/pipeline_guide.md`
- `commands/pipeline.md`
- `commands/README.md`

### 6. Update Tests

Change `_write_pipeline()` in `test_pipeline_schema.py` to write JSON.
Update `source_path` references from `.yaml` to `.json`.

---

## Integration Points

| File | Change |
|------|--------|
| `helpers/pipeline_schema.py` | Replace `yaml.safe_load()` with `json.load()`, remove yaml import |
| `helpers/pipeline_cli.py` | Accept `.json`, update help text |
| `pyproject.toml` | Remove `pyyaml>=6.0` |
| `config/pipelines/quick-triage.yaml` | Convert to `.json`, delete `.yaml` |
| `config/pipelines/security-sweep.yaml` | Convert to `.json`, delete `.yaml` |
| `config/pipelines/full-analysis.yaml` | Convert to `.json`, delete `.yaml` |
| `config/pipelines/function-deep-dive.yaml` | Convert to `.json`, delete `.yaml` |
| `docs/pipeline_guide.md` | Replace YAML examples with JSON |
| `commands/pipeline.md` | Update examples and file references |
| `commands/README.md` | Update `/pipeline` description |
| `tests/test_pipeline_schema.py` | Write JSON in `_write_pipeline()` |
| `tests/test_pipeline_executor.py` | Update `.yaml` -> `.json` reference |
| `tests/test_ai_logic_scanner.py` | Update minor YAML reference if present |

---

## What NOT to Build

- **No dual-format support.** Do not add "accept both YAML and JSON"
  logic.  That doubles the parsing paths and defeats the purpose of
  simplification.  JSON only.
- **No migration script.** 4 files is a manual conversion.  The JSON
  equivalents are shown above.

---

## Acceptance Criteria

1. All 4 pipeline files are `.json` and load correctly via
   `pipeline_cli.py`
2. `pipeline_schema.py` uses `json.load()` -- no `yaml` import
3. `pyyaml` is removed from `pyproject.toml`
4. `pipeline_cli.py validate <file>.json` works
5. `pipeline_cli.py run <file>.json` works
6. All pipeline tests pass with JSON fixtures
7. Documentation references JSON, not YAML
8. No `yaml` import anywhere in the codebase

---

## References

- [Pipeline Guide](../pipeline_guide.md) -- current YAML schema docs
- [Pipeline Command](../../commands/pipeline.md) -- `/pipeline` usage
- `helpers/pipeline_schema.py` -- the sole YAML consumer
