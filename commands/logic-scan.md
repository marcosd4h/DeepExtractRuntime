# Logic Vulnerability Scan

## Overview

Scan a module (or a specific function) for logic vulnerabilities that bypass hardware memory mitigations: authentication/authorization bypasses, state machine errors, TOCTOU/double-fetch, missing security return checks, impersonation leaks, confused deputy, and error-path privilege leaks.  Includes independent verification that re-reads code with fresh eyes before presenting results.

The text after `/logic-scan` specifies the **module** and optional **function** or flags:

- `/logic-scan appinfo.dll` -- full module logic scan (all 4 detectors + verify)
- `/logic-scan appinfo.dll --top 10` -- limit to top 10 findings
- `/logic-scan appinfo.dll AiLaunchProcess` -- scan a specific function
- `/logic-scan appinfo.dll --id 42` -- scan a specific function by ID

If no module is specified, list available modules and ask the user.

## IMPORTANT: Execution Model

**This is an execute-immediately command. Do NOT present anything for user confirmation.** Run all scanners, verify findings, and present the final report as your response.

## Execution Context

> **IMPORTANT**: Any inline Python that imports `helpers.*` must run with `cd <workspace>/.agent`
> (so the `.agent/` directory is on `sys.path`), **not** from the workspace root.
> Script invocations like `python .agent/skills/.../script.py` can be run from the workspace root
> because those scripts manage their own path setup.

## Steps

### Step 0: Preflight Validation

Validate arguments using `helpers.command_validation.validate_command_args("logic-scan", {"module": "<module>"})`.
If validation fails, report the errors and stop. On success, use `result.resolved["db_path"]` for subsequent script calls.

### 1. Locate the module

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py <module_name>
```

### 2. Run auth bypass scanner

```bash
python .agent/skills/logic-vulnerability-detector/scripts/scan_auth_bypass.py <db_path> --top 20 --json
```

### 3. Run state machine scanner

```bash
python .agent/skills/logic-vulnerability-detector/scripts/scan_state_errors.py <db_path> --json
```

### 4. Run general logic flaw scanner

```bash
python .agent/skills/logic-vulnerability-detector/scripts/scan_logic_flaws.py <db_path> --top 20 --json
```

### 5. Run API misuse scanner

```bash
python .agent/skills/logic-vulnerability-detector/scripts/scan_api_misuse.py <db_path> --top 20 --json
```

### 6. Merge findings

Combine the `findings` arrays from all four scanner outputs into a single JSON file.

### 7. Run independent verification

```bash
python .agent/skills/logic-vulnerability-detector/scripts/verify_findings.py \
    --findings merged_findings.json --db-path <db_path> --json
```

### 8. Generate report

```bash
python .agent/skills/logic-vulnerability-detector/scripts/generate_logic_report.py \
    --findings verified.json --json
```

### 9. Present results

Parse the report and present:

**Executive Summary:**
- Total findings, actionable count, false positives removed
- Severity distribution (CRITICAL/HIGH/MEDIUM/LOW)
- Category distribution
- Mitigation note: logic bugs bypass ASLR/DEP/CFG/CET

**For each top finding (sorted by verified score):**
- Severity, confidence, and verified score
- Function name and category
- Summary of the vulnerability
- Dangerous operation and entry point (if applicable)
- Verification reasoning
- Assembly evidence (if available)
- Mitigating factors (if any)

**Verification Summary:**
- Confirmed, Likely, Uncertain, False Positive counts

### Single-function mode

If the user specifies a function name or `--id`, run only the relevant scanners on that function:

```bash
python .agent/skills/logic-vulnerability-detector/scripts/scan_auth_bypass.py <db_path> --id <fid> --json
python .agent/skills/logic-vulnerability-detector/scripts/scan_logic_flaws.py <db_path> --id <fid> --json
python .agent/skills/logic-vulnerability-detector/scripts/scan_api_misuse.py <db_path> --id <fid> --json
```

Then verify and report as in steps 7-9.

## Output

Present the logic vulnerability report in chat.  When the user asks to save, write to `extracted_code/<module_folder>/reports/logic_scan_<timestamp>.json`.

**Follow-up suggestions:**

- `/audit <module> <function>` -- deep security audit on flagged functions
- `/taint <module> <function>` -- trace tainted params on flagged functions
- `/explain <module> <function>` -- understand what a flagged function does
- `/hunt <module>` -- hypothesis-driven VR campaign using findings as seeds

## Error Handling

- **Module not found**: List available modules via `find_module_db.py --list` and ask user
- **Function not found**: Run fuzzy search and suggest close matches
- **No decompiled code**: Report the gap
- **Scanner subprocess failure**: Report partial results from completed scanners
- **No findings**: Report explicitly -- "no logic vulnerabilities detected" is a valid result
