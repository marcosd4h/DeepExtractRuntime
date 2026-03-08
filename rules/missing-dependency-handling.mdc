---
description: Handling missing databases, skills, or extraction data gracefully
globs:
  - ".agent/skills/*/scripts/*.py"
  - ".agent/agents/*/scripts/*.py"
  - ".agent/hooks/*.py"
alwaysApply: true
---

# Missing Dependency Handling

## Pre-Flight Validation

Before running analysis, check data availability using:

```python
from helpers.validation import validate_workspace_data

status = validate_workspace_data(workspace_root)
if not status.ok:
    emit_error("No extraction data found", "NO_DATA")
if status.json_only:
    log_warning("No analysis DBs; some features unavailable", "NO_DATA")
```

## Missing Database Graceful Degradation

When a DB is expected but not found:

1. **Required DB**: Call `emit_error()` with `NOT_FOUND` code.
2. **Optional DB** (e.g., cross-module resolution): Log a warning and continue
   with reduced functionality.
3. **Tracking DB**: If `resolve_tracking_db()` returns `None`, cross-module
   features are unavailable. Report this but don't abort single-module analysis.

## Missing Skill Scripts

When a skill script is needed but may not exist:

```python
script = find_skill_script("optional-skill", "some_script.py")
if script is None:
    log_warning("optional-skill not available; skipping", "NOT_FOUND")
```

## JSON-Only Mode

When `extracted_dbs/` is absent but `extracted_code/` exists, scripts should:

1. Fall back to `function_index.json` for function listing and lookup.
2. Fall back to `file_info.json` for module identity and metadata.
3. Report clearly which DB-dependent features are unavailable.
4. Never crash with an opaque error -- always explain what's missing.
