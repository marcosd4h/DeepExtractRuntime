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

2. **Create grind-loop scratchpad**

```markdown
# Task: Vulnerability Scan -- <module>

## Items
- [ ] Phase 1: Detection (memory + logic + taint)
- [ ] Phase 2: Merge and deduplicate
- [ ] Phase 3: Verify findings
- [ ] Phase 4: Score exploitability
- [ ] Phase 5: Synthesize report

## Status
IN_PROGRESS
```

### Phase 1: Detection (Parallel)

Run all three detection pipelines concurrently. For `--memory-only`, `--logic-only`, or `--taint-only` modes, run only the specified pipeline.

**a. Memory corruption detection** (4 scanners in parallel):

```bash
python .agent/skills/memory-corruption-detector/scripts/scan_buffer_overflows.py <db_path> --json
python .agent/skills/memory-corruption-detector/scripts/scan_integer_issues.py <db_path> --json
python .agent/skills/memory-corruption-detector/scripts/scan_use_after_free.py <db_path> --json
python .agent/skills/memory-corruption-detector/scripts/scan_format_strings.py <db_path> --json
```

**b. Logic vulnerability detection** (4 scanners in parallel):

```bash
python .agent/skills/logic-vulnerability-detector/scripts/scan_auth_bypass.py <db_path> --top 20 --json
python .agent/skills/logic-vulnerability-detector/scripts/scan_state_errors.py <db_path> --json
python .agent/skills/logic-vulnerability-detector/scripts/scan_logic_flaws.py <db_path> --top 20 --json
python .agent/skills/logic-vulnerability-detector/scripts/scan_api_misuse.py <db_path> --top 20 --json
```

**c. Taint analysis on top entry points:**

First discover entry points:

```bash
python .agent/skills/map-attack-surface/scripts/discover_entrypoints.py <db_path> --json
python .agent/skills/map-attack-surface/scripts/rank_entrypoints.py <db_path> --json --top 5
```

Then run taint analysis on the top 5 ranked entry points:

```bash
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> --id <fid> --depth 2 --json
```

**Single-function mode:** If a function is specified, run all scanners with `--id <fid>` and taint analysis on that specific function. Skip entry point discovery.

Check off Phase 1.

### Phase 2: Merge and Deduplicate

Combine findings from all three pipelines into a unified findings list:

1. Normalize each finding to a common schema: `{function_name, function_id, category, subcategory, severity, score, evidence, source_pipeline}`
2. Deduplicate by `(function_id, category)` -- keep the higher-scoring finding when duplicates exist
3. Cross-reference: if a taint analysis finding and a memory corruption finding target the same function, boost the combined score (intersection of attacker-reachable + vulnerable = higher risk)
4. Sort by score descending

Write merged findings to `<run_dir>/merged/results.json`.

Check off Phase 2.

### Phase 3: Verify Findings

Run independent verification for each pipeline's findings:

```bash
python .agent/skills/memory-corruption-detector/scripts/verify_findings.py \
    --findings <memory_findings.json> --db-path <db_path> --json

python .agent/skills/logic-vulnerability-detector/scripts/verify_findings.py \
    --findings <logic_findings.json> --db-path <db_path> --json
```

Apply verification adjustments:
- FALSE_POSITIVE findings are removed
- UNCERTAIN findings get a 50% score reduction
- CONFIRMED findings retain full score

Write verified findings to `<run_dir>/verified/results.json`.

Check off Phase 3.

### Phase 4: Score Exploitability

For all CRITICAL and HIGH severity verified findings, run exploitability assessment.
The assessor now accepts findings from **all scanner types** (taint, memory-corruption, and logic-vulnerability):

```bash
# Combined assessment of all finding types
python .agent/skills/exploitability-assessment/scripts/assess_finding.py \
    --taint-report <taint_results.json> \
    --memory-findings <memory_results.json> \
    --logic-findings <logic_results.json> \
    --module-db <db_path> --json
```

For batch processing of entry points:

```bash
python .agent/skills/exploitability-assessment/scripts/batch_assess.py <db_path> --json
```

The assessment considers:
- Mitigations (ASLR/DEP/CFG/CET) and their effectiveness against the finding category
- Guard bypass difficulty (including constraint feasibility analysis)
- Primitive quality (arbitrary read/write, code execution, DoS)
- Reachability from entry points

Write scored findings to `<run_dir>/exploitability/results.json`.

Check off Phase 4.

### Phase 5: Synthesize Report

**Executive Summary:**
- Module identity and security posture
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
- Exploitability assessment (primitive quality, mitigation effectiveness)
- Cross-pipeline correlation (if the same function flagged by multiple pipelines)

**Pipeline Breakdown:**
- Memory corruption: buffer overflows, integer issues, UAF, format strings
- Logic vulnerabilities: auth bypass, state errors, TOCTOU, missing checks
- Taint analysis: attacker-reachable sinks with guard/bypass analysis

**Mitigation Analysis:**
- Which mitigations (ASLR/DEP/CFG/CET/canary) protect against which findings
- Logic bugs that bypass all hardware mitigations (flagged prominently)

**Recommended Next Steps:**
- `/audit <module> <function>` -- deep audit on CRITICAL/HIGH findings
- `/taint <module> <function> --cross-module` -- cross-module impact assessment
- `/hunt hypothesis <type> <module>` -- hypothesis-driven investigation on patterns
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
