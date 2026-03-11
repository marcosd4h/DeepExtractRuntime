# Vulnerability Scan

## Overview

Unified vulnerability scan that orchestrates all three detection pipelines (memory corruption, logic vulnerabilities, and taint analysis), deduplicates overlapping findings, verifies them against assembly, and scores exploitability. Produces a consolidated, severity-ranked findings report.

This command is the comprehensive alternative to running `/memory-scan`, `/logic-scan`, and `/taint` separately.

Usage:

- `/scan appinfo.dll` -- full scan (all detectors + taint on top entries + verification + exploitability)
- `/scan appinfo.dll --top 15` -- limit to top 15 findings per category
- `/scan appinfo.dll --memory-only` -- only memory corruption detection
- `/scan appinfo.dll --logic-only` -- only logic vulnerability detection
- `/scan appinfo.dll --taint-only` -- only taint analysis on entry points
- `/scan appinfo.dll <function>` -- all detectors on a specific function
- `/scan appinfo.dll --auto-audit` -- after scanning, automatically audit the top 3 CRITICAL/HIGH findings
- `/scan appinfo.dll --no-cache` -- bypass cached results for all scanners

## IMPORTANT: Execution Model

**This is an execute-immediately command.** Run the full pipeline and deliver the completed report. Use the grind loop for large modules where all phases cannot complete in one pass.

## Workspace Protocol

This command orchestrates many analysis steps:

1. Create `.agent/workspace/<module>_scan_<timestamp>/`.
2. Store per-phase results in `<run_dir>/<phase>/results.json`.
3. Use `<run_dir>/manifest.json` to track completed/failed phases.
4. Keep only summaries in context; read full findings from results.json on demand.

## Execution Context

> **IMPORTANT**: Any inline Python that imports `helpers.*` must run with `cd <workspace>/.agent`
> (so the `.agent/` directory is on `sys.path`), **not** from the workspace root.
> Script invocations like `python .agent/skills/.../script.py` can be run from the workspace root
> because those scripts manage their own path setup.

## Steps

### Step 0: Preflight Validation

Validate arguments using `helpers.command_validation.validate_command_args("scan", {"module": "<module>"})`.
If validation fails, report the errors and stop. On success, use `result.resolved["db_path"]` for subsequent script calls.

### Setup

1. **Find the module DB**

> **Tip:** All skill scripts support `--json` for machine-readable output. Use `--json` when parsing script output programmatically.

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py <module_name> --json
```

### Run scan via security-auditor

2. **Execute the full scan pipeline**
   Use the **security-auditor** agent's `run_security_scan.py` to run the complete 6-phase pipeline in one call:

   ```bash
   # Full module scan
   python .agent/agents/security-auditor/scripts/run_security_scan.py <db_path> --goal scan --json

   # Function-specific scan
   python .agent/agents/security-auditor/scripts/run_security_scan.py <db_path> --goal audit --function <name> --json

   # Limit top findings
   python .agent/agents/security-auditor/scripts/run_security_scan.py <db_path> --goal scan --top 15 --json
   ```

   The script handles all phases internally with parallel execution and deduplication:
   - **Phase 1 (Recon)**: Classify functions, discover entry points, rank by attack value, gather IPC context (RPC/COM/WinRT)
   - **Phase 2 (Vulnerability Scanning)**: Memory corruption (4 scanners) + logic vulnerability (4 scanners) in parallel
   - **Phase 3 (Taint Analysis)**: Taint analysis on top ranked entry points
   - **Phase 4 (Verification)**: `verify_findings.py` for both memory and logic findings
   - **Phase 5 (Exploitability)**: `assess_finding.py` / `batch_assess.py` with guard bypass and primitive quality scoring
   - **Phase 6 (Synthesis)**: Merged, deduplicated, severity-ranked findings report

   **Cache bypass:** When the user specifies `--no-cache`, pass `--no-cache` to `run_security_scan.py`.

   **Mode mapping:** `--memory-only`, `--logic-only`, and `--taint-only` modes are not directly supported by `run_security_scan.py`. For these, fall back to running the individual skill scripts directly (as documented in the memory-corruption-detector, logic-vulnerability-detector, and taint-analysis skills respectively).

### Synthesize Report

**Executive Summary:**
- Module identity
- Total findings by pipeline (memory, logic, taint)
- After verification: confirmed, likely, removed (false positive) counts
- Severity distribution (CRITICAL/HIGH/MEDIUM/LOW)

**Top Findings** (sorted by exploitability score, then severity):

| # | Severity | Exploitability | Function | Category | Pipeline | Score |
|---|----------|---------------|----------|----------|----------|-------|

**For each top finding:**
- Category and subcategory
- Evidence: code lines, taint path, dangerous API
- Guards on path and bypass feasibility
- Verification status and reasoning
- Exploitability assessment (primitive quality, guard bypass feasibility)
- Cross-pipeline correlation (if the same function flagged by multiple pipelines)

**Pipeline Breakdown:**
- Memory corruption: buffer overflows, integer issues, UAF, format strings
- Logic vulnerabilities: auth bypass, state errors, TOCTOU, missing checks
- Taint analysis: attacker-reachable sinks with guard/bypass analysis

**Recommended Next Steps:**
- `/audit <module> <function>` -- deep audit on CRITICAL/HIGH findings
- `/taint <module> <function> --cross-module` -- cross-module impact assessment
- `/hunt-plan hypothesis <type> <module>` -- hypothesis-driven investigation on patterns
- `/explain <module> <function>` -- understand what a flagged function does

Check off Phase 5.

### Phase 6: Auto-Audit (conditional -- only when `--auto-audit` is specified)

If `--auto-audit` was passed, automatically run `/audit` on the top 3 CRITICAL or HIGH exploitability findings:

1. Select up to 3 findings with exploitability rating CRITICAL or HIGH (skip duplicates from the same function).
2. For each finding, execute the `/audit` pipeline:
   - Security dossier + decompiled code extraction
   - Backward taint trace to confirm attacker control
   - Decompiler verification
   - Deep-context analysis
3. Store per-function audit results in `<run_dir>/auto_audit/<function_name>/results.json`.
4. Append an **Auto-Audit Findings** section to the report with each audited function's detailed assessment.

This phase uses the grind loop -- add auto-audit items to the scratchpad and process them iteratively.

Set Status to DONE after Phase 5 (or Phase 6 if auto-audit is active).

## Output

Present the consolidated report in chat. Save to `extracted_code/<module_folder>/reports/scan_<module>_<timestamp>.md`.

All saved files must include a provenance header: generation date, module name, DB path, workspace run directory, pipelines executed, and finding counts.

## Error Handling

- **Module not found**: List available modules via `find_module_db.py --list` and ask user
- **Function not found**: Run fuzzy search and suggest close matches
- **Scanner failure**: Log error, continue with results from successful scanners
- **Verification failure**: Present unverified findings with a note
- **Exploitability assessment failure**: Present findings without exploitability scores
- **No findings**: Report "no vulnerabilities detected across all pipelines" as a valid result
- **Partial completion**: Always report what completed successfully, even if some phases failed
