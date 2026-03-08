# Health Check

## Overview

Pre-flight validation of the DeepExtractIDA workspace. Checks that extraction data, analysis databases, skill/agent/command registries, and configuration are present and consistent.

Usage:
- `/health` -- standard health check (samples DBs and function indexes at scale)
- `/health --quick` -- fast check (skip DB validation and function indexes)
- `/health --full` -- exhaustive check (validate every DB, every index, run tests)

## Execution

Run `.agent/helpers/health_check.py` directly from the workspace root. This is the canonical implementation -- do **not** write inline Python to read or iterate the registries.

```
python .agent/helpers/health_check.py [--quick|--full] [--json] [--workspace <path>]
```

The script handles all registry loading and validation internally. Present its stdout output to the user.

### Invocation by mode

| Mode | Command |
|------|---------|
| Standard | `python .agent/helpers/health_check.py` |
| Quick (skip DBs + indexes) | `python .agent/helpers/health_check.py --quick` |
| Full (all DBs + tests) | `python .agent/helpers/health_check.py --full` |
| JSON output | `python .agent/helpers/health_check.py [--quick\|--full] --json` |

### Working directory

The script auto-resolves the workspace root from its own location (`..` relative to `.agent/helpers/`). If running from a non-standard layout, pass `--workspace <path>` explicitly.

## What the script checks

1. **Extraction Data** -- `extracted_code/` and `extracted_dbs/` are present with usable modules.
2. **Analysis DBs** -- individual `.db` files pass schema validation (sampled at scale; all if `--full`).
3. **Tracking DB** -- `analyzed_files.db` exists and is valid.
4. **Skills** -- every non-methodology skill in `skills/registry.json` has a matching `scripts/` directory, `_common.py`, and all `entry_scripts` on disk.
5. **Agents** -- every agent in `agents/registry.json` has `scripts/`, `_common.py`, and all `entry_scripts` on disk.
6. **Commands** -- every command in `commands/registry.json` has its `.md` file and cross-references valid skills/agents.
7. **Configuration** -- `helpers.config.validate_config()` reports no issues.
8. **Function Indexes** -- `function_index.json` files are valid JSON (sampled at scale; all if `--full`).
9. **Test Suite** -- `--full` only: runs `pytest tests/ -x -q --tb=short` and reports pass/fail counts.

## Registry structure reference

All three registry files use a **named-dict** shape, not a list:

```json
{ "skills":   { "skill-name":   { "entry_scripts": [...], ... } } }
{ "agents":   { "agent-name":   { "entry_scripts": [...], ... } } }
{ "commands": { "command-name": { "file": "foo.md", ... } } }
```

The script iterates with `for name, meta in registry.items()`. Never treat these as lists.

## Output format

```
Workspace Health Check
========================================================
Extraction Data:   OK  (195 modules with DBs, 0 JSON-only)
Analysis DBs:      OK  (50/195 sampled, 0 failed)
Tracking DB:       OK  (analyzed_files.db found)
Skills:            OK  (29/29 present)
Agents:            OK  (6/6 present)
Commands:          OK  (36/36 registered)
Configuration:     OK
Function Indexes:  OK  (50/195 sampled, 0 failed)
Test Suite:        OK  (87 passed, 2 skipped)  [--full only]
========================================================
Overall: OK
```

Any failures are listed below the table with `ERROR [label]: <detail>`.

Exit code is 0 on clean, 1 on any failure.

## Follow-up suggestions

- `/triage <module>` -- triage a healthy module.
- `/explain <module> <function>` -- start analyzing functions.

## Error handling

- **No extraction data found**: neither `extracted_code/` nor `extracted_dbs/` exists. Run DeepExtractIDA first.
- **Tracking DB missing**: `analyzed_files.db` absent; cross-module features unavailable (warning, not fatal).
- **Individual DB corrupt**: script reports which DBs failed validation with specific error messages.
- **Registry missing or empty**: script reports which registry file could not be loaded.
- **Test failures** (`--full`): failure output is captured; run `cd .agent && python -m pytest tests/ -v` for full details.
