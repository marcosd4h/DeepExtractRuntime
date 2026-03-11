# Diff -- Compare Binary Versions

## Overview

Compare two versions of the same module to identify changed functions, new attack surface, and fixed vulnerabilities. Use when a binary has been updated (patched, new version) and you want to understand what changed from a security perspective.

Usage:
- `/diff <module_old> <module_new>`
- `/diff appinfo_v1.dll appinfo_v2.dll`

## IMPORTANT: Execution Model

**This is an execute-immediately command. Do NOT present anything for user confirmation.** Run all analysis steps and present the completed diff report straight to the chat as your response.

## Execution Context

> **IMPORTANT**: Any inline Python that imports `helpers.*` must run with `cd <workspace>/.agent`
> (so the `.agent/` directory is on `sys.path`), **not** from the workspace root.
> Script invocations like `python .agent/skills/.../script.py` can be run from the workspace root
> because those scripts manage their own path setup.

> **Tip:** All skill scripts support `--json` for machine-readable output. Use `--json` when parsing script output programmatically.

## Steps

### Step 0: Preflight Validation

Validate arguments using `helpers.command_validation.validate_command_args("diff", {"module": "<module_old>"})` and again for `<module_new>`. If either validation fails, report the errors to the user and stop. On success, use `result.resolved["db_path"]` for both modules in all subsequent skill script calls.

### Step 1: Resolve Both Module DBs

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py <module_old>
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py <module_new>
```

**Entry:** Two module names provided by the user
**Exit:** Both DB paths resolve to existing files

### Step 2: Extract Function Inventories

```bash
python .agent/skills/decompiled-code-extractor/scripts/list_functions.py <db_old> --has-decompiled --json
python .agent/skills/decompiled-code-extractor/scripts/list_functions.py <db_new> --has-decompiled --json
```

Compare function name sets to identify:
- **Added functions** -- present in new, absent in old
- **Removed functions** -- present in old, absent in new
- **Common functions** -- present in both (candidates for code diff)

**Entry:** Step 1 exit criteria met
**Exit:** Three function lists (added, removed, common) with counts

### Step 3: Classify Changes

Run classification on both modules:

```bash
python .agent/skills/classify-functions/scripts/classify_module.py <db_old> --json
python .agent/skills/classify-functions/scripts/classify_module.py <db_new> --json
```

Compare classification distributions. Highlight:
- New functions in security-relevant categories
- Category shifts (e.g., function moved from utility to security)
- Interest score changes for common functions

**Entry:** Step 2 exit criteria met
**Exit:** Classification comparison with delta summary

### Step 4: Attack Surface Delta

```bash
python .agent/skills/map-attack-surface/scripts/discover_entrypoints.py <db_old> --json
python .agent/skills/map-attack-surface/scripts/discover_entrypoints.py <db_new> --json
```

Compare entry point sets:
- **New entry points** -- added attack surface
- **Removed entry points** -- reduced attack surface
- **Score changes** -- entry points with different attack rankings

**Entry:** Step 2 exit criteria met (can run in parallel with Step 3)
**Exit:** Entry point delta with new/removed/changed lists

### Step 5: Code-Level Diff for Key Functions

For the top 5-10 most interesting changed functions (by interest score or security relevance):

```bash
python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py <db_old> --id <id> --json
python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py <db_new> --id <id> --json
```

Compare decompiled code to identify:
- Added/removed API calls (especially dangerous APIs)
- Changed control flow (new branches, removed checks)
- Modified string references
- Changed parameter handling

**Entry:** Steps 3-4 exit criteria met
**Exit:** Per-function semantic diff summaries for top changed functions

### Step 6: Synthesis

Assemble the diff report:

1. **Executive Summary**: Module identity comparison, total function count delta, key security-relevant changes
2. **Function Inventory Delta**: Added/removed/modified function tables
3. **Classification Delta**: Category distribution comparison with notable shifts
4. **Attack Surface Delta**: New/removed entry points, score changes
5. **Code-Level Changes**: Semantic diff summaries for top changed functions
6. **Security Impact Assessment**: What the changes mean for the module's security-relevant behavior
7. **Recommended Next Steps**: Specific `/audit` or `/taint` commands for new or changed security-relevant functions

**Entry:** Steps 3-5 exit criteria met
**Exit:** Complete diff report written to `extracted_code/<module>/diff_report_<timestamp>.md`

### Step 7: Verification

Spot-check the top 3 reported code changes by comparing the actual decompiled code excerpts to verify the diff summary accurately reflects the changes. If any diff summary is inaccurate, correct it before finalizing.

## Step Dependencies

- **Step 1 --> Steps 2**: Sequential (need DB paths)
- **Step 2 --> Steps 3 + 4**: Classification and attack surface are independent -- run in parallel
- **Steps 3 + 4 --> Step 5**: Both inform which functions to deep-diff
- **Step 5 --> Step 6**: Sequential (synthesis needs all data)
- **Step 6 --> Step 7**: Sequential (verify the synthesis)

## Degradation Paths

1. **Only one version has a DB**: Report what's available for the existing module, note that the other version could not be analyzed
2. **Function counts differ dramatically** (>50% change): Focus on the security-relevant subset rather than attempting full comparison
3. **No common functions found**: Report as a complete rewrite, focus on attack surface comparison only
4. **Classification fails for one module**: Continue with function inventory and attack surface delta, note classification was unavailable

## Output

Structured diff report in chat with:
- Module identity comparison table
- Function delta summary (added/removed/modified counts)
- Classification shift highlights
- Attack surface changes with new entry points flagged
- Code-level semantic diffs for top changed functions
- Concrete follow-up commands for new security-relevant functions
