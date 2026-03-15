# Vulnerability Scan

## Overview

Unified vulnerability scan that orchestrates recon, AI scanner context preparation, taint analysis, assembly verification, exploitability scoring, and deduplication into a single pipeline. Produces a consolidated, severity-ranked findings report.

The pipeline prepares workspace context for the AI-driven memory-corruption, logic, and taint scanners, launches LLM scanner subagents, scores exploitability across all finding types, and merges everything into a deduplicated report.

Usage:

- `/scan appinfo.dll` -- full scan (recon + AI context + taint + verify + exploit + report)
- `/scan appinfo.dll --top 15` -- analyze top 15 entry points
- `/scan appinfo.dll --taint-only` -- delegate to `/taint` (AI-driven taint scanner)
- `/scan appinfo.dll --memory-only` -- delegate to `/memory-scan` (AI-driven scanner)
- `/scan appinfo.dll --logic-only` -- delegate to `/ai-logical-bug-scan` (AI-driven scanner)
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
   - **Phase 2 (Scanner Context Preparation)**: Build threat models and callgraph context for all three AI scanners (memory-corruption, logic, taint). Runs `build_threat_model.py` and `prepare_context.py` for each scanner skill. These workspace artifacts are consumed by the coordinator-launched scanner subagents.
   - **Phase 3 (Taint Context)**: Per-function taint-enriched callgraph context for top entry points (consumed by taint-scanner subagent)
   - **Phase 4 (Exploitability)**: `assess_finding.py` with `--taint-report`, `--memory-findings`, and `--logic-findings` for unified scoring with guard bypass and primitive quality analysis
   - **Phase 5 (Synthesis)**: Merged, deduplicated, severity-ranked findings report

3. **Launch AI scanner subagents** (coordinator responsibility)
   After Phase 2 completes, the coordinator launches scanner subagents that consume the prepared workspace:
   - **memory-corruption-scanner**: Reads `mem_threat_model` and `mem_context` from workspace, performs LLM-driven memory corruption analysis, writes results to `mem_findings/results.json`
   - **logic-scanner**: Reads `logic_threat_model` and `logic_context` from workspace, performs LLM-driven logic vulnerability analysis, writes results to `logic_findings/results.json`
   - **taint-scanner**: Reads `taint_threat_model`, `taint_context`, and per-function taint contexts from workspace, performs LLM-driven taint analysis, writes results to `taint_findings/results.json`

   These subagents run after Phase 2 (or in parallel with Phase 3 context prep). Their output is picked up by Phase 4 for exploitability scoring.

   **Cache bypass:** When the user specifies `--no-cache`, pass `--no-cache` to `run_security_scan.py`.

   **Mode mapping:** `--logic-only`, `--taint-only`, and `--memory-only` modes delegate to their respective commands: `/ai-logical-bug-scan`, `/taint`, and `/memory-scan`.

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
- Memory corruption: threat model + callgraph context prepared in Phase 2, scanned by memory-corruption-scanner subagent
- Logic vulnerabilities: threat model + callgraph context prepared in Phase 2, scanned by logic-scanner subagent
- Taint analysis: threat model + taint-enriched callgraph context prepared in Phases 2-3, scanned by taint-scanner subagent

**Recommended Next Steps:**
- `/audit <module> <function>` -- deep audit on CRITICAL/HIGH findings
- `/taint <module> <function> --cross-module` -- cross-module impact assessment
- `/hunt-plan hypothesis <type> <module>` -- hypothesis-driven investigation on patterns
- `/explain <module> <function>` -- understand what a flagged function does

Check off Phase 4.

### Phase 5: Auto-Audit (conditional -- only when `--auto-audit` is specified)

If `--auto-audit` was passed, automatically run `/audit` on the top 3 CRITICAL or HIGH exploitability findings:

1. Select up to 3 findings with exploitability rating CRITICAL or HIGH (skip duplicates from the same function).
2. For each finding, execute the `/audit` pipeline:
   - Security dossier + decompiled code extraction
   - Skeptic verification against assembly ground truth
   - Deep-context analysis
3. Store per-function audit results in `<run_dir>/auto_audit/<function_name>/results.json`.
4. Append an **Auto-Audit Findings** section to the report with each audited function's detailed assessment.

This phase uses the grind loop -- add auto-audit items to the scratchpad and process them iteratively.

Set Status to DONE after Phase 4 (or Phase 5 if auto-audit is active).

## Output

Present the consolidated report in chat. Save to `extracted_code/<module_folder>/reports/scan_<module>_<timestamp>.md`.

All saved files must include a provenance header: generation date, module name, DB path, workspace run directory, pipelines executed, and finding counts.

## Error Handling

- **Module not found**: List available modules via `find_module_db.py --list` and ask user
- **Function not found**: Run fuzzy search and suggest close matches
- **Scanner context failure**: Log warning, continue with available scanners (graceful degradation)
- **Scanner subagent failure**: Log error, continue with results from successful scanners
- **Verification failure**: Present unverified findings with a note
- **Exploitability assessment failure**: Present findings without exploitability scores
- **No findings**: Report "no vulnerabilities detected across all pipelines" as a valid result
- **Partial completion**: Always report what completed successfully, even if some phases failed
