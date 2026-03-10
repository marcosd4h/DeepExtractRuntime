# Prioritize Findings

## Overview

Cross-module finding prioritization. Loads cached scan and audit results from multiple modules, normalizes them via the unified finding schema, ranks by exploitability × reachability × impact, and produces a single priority-ordered list spanning all specified modules.

Usage:

- `/prioritize --modules appinfo.dll lsasrv.dll` -- prioritize findings across two modules
- `/prioritize --all` -- prioritize findings across all available modules
- `/prioritize --modules appinfo.dll --top 20` -- limit to top 20 findings
- `/prioritize --all --min-score 0.5` -- only show findings with composite score ≥ 0.5

## IMPORTANT: Execution Model

**This is an execute-immediately command.** Discover modules, load cached results, merge and rank findings, then deliver the completed report.

## Workspace Protocol

This command aggregates results from prior scan/audit runs:

1. Create `.agent/workspace/prioritize_<timestamp>/`.
2. Store per-module loaded findings in `<run_dir>/<module>/results.json`.
3. Store merged and ranked output in `<run_dir>/ranked/results.json`.
4. Use `<run_dir>/manifest.json` to track completed/failed phases.

## Execution Context

> **IMPORTANT**: Any inline Python that imports `helpers.*` must run with `cd <workspace>/.agent`
> (so the `.agent/` directory is on `sys.path`), **not** from the workspace root.
> Script invocations like `python .agent/skills/.../script.py` can be run from the workspace root
> because those scripts manage their own path setup.

## Steps

### Step 0: Preflight Validation

Validate arguments using `helpers.command_validation.validate_command_args("prioritize", {"modules": "<modules>"})`.
If validation fails, report the errors and stop.

### Step 1: Discover Available Modules

**If `--all`:** List all modules via the decompiled-code-extractor:

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py --list --json
```

**If `--modules A B C`:** Resolve each named module to its DB path:

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py <module_name> --json
```

Fail gracefully if a module cannot be resolved -- log a warning and continue with the remaining modules.

### Step 2: Load Cached Scan Results Per Module

For each resolved module, load existing scan/audit results from the cache directory `.agent/cache/<module>/`. Look for:

- `scan_*.json` -- output from `/scan` (memory + logic + taint findings)
- `audit_*.json` -- output from `/audit` (function-level security assessments)
- `hunt_execute_*.json` -- output from `/hunt-execute` (hypothesis investigation findings)
- `batch_audit_*.json` -- output from `/batch-audit` (batch security assessments)

If no cached results exist for a module, log a warning suggesting the user run `/scan <module>` first, and skip that module.

### Step 3: Normalize Findings

Convert all loaded findings to the unified schema using `helpers.finding_schema`:

```python
from helpers.finding_schema import normalize_scanner_output, Finding
from helpers.finding_merge import merge_findings, deduplicate, rank

all_findings = []
for module_name, scanner_outputs in per_module_results.items():
    for data, source_type in scanner_outputs:
        findings = normalize_scanner_output(data, source_type)
        for f in findings:
            f.module = module_name
        all_findings.extend(findings)
```

Ensure every `Finding` has its `.module` field set so cross-module attribution is preserved.

### Step 4: Score and Rank Across Modules

Compute a composite priority score for each finding:

```
composite_score = exploitability_score × reachability_weight × impact_multiplier
```

Where:
- `exploitability_score` comes from the finding's exploitability assessment (fall back to raw `.score` if unavailable)
- `reachability_weight` is `1.0` for exported/entry-point functions, `0.7` for internally reachable, `0.4` for deep internal
- `impact_multiplier` is derived from severity: CRITICAL=1.0, HIGH=0.8, MEDIUM=0.5, LOW=0.2

Deduplicate using `helpers.finding_merge.deduplicate()`, then sort by composite score descending.

Apply `--top N` and `--min-score` filters if specified.

### Step 5: Synthesize Cross-Module Priority Report

**Executive Summary:**
- Number of modules analyzed
- Total findings before and after deduplication
- Severity distribution across all modules

**Priority Table** (sorted by composite score):

| # | Score | Severity | Module | Function | Category | Source Pipeline | Exploitability |
|---|-------|----------|--------|----------|----------|----------------|----------------|

**Per-Module Breakdown:**
For each module, show:
- Finding count and severity distribution
- Top finding from that module
- Whether cached results were fresh or stale

**Cross-Module Patterns:**
- Categories that appear across multiple modules (systemic issues)
- Functions that appear as both caller and callee across module boundaries
- Shared dangerous API patterns

**Recommended Next Steps:**
- `/audit <module> <function>` -- deep audit on the top CRITICAL/HIGH findings
- `/scan <module>` -- run scans on modules with no cached results
- `/hunt-plan <module>` -- hypothesis-driven investigation on high-priority patterns

## Output

Present the prioritized report in chat. Save to `.agent/workspace/prioritize_<timestamp>/ranked/results.json` and a human-readable report to `.agent/workspace/prioritize_<timestamp>/report.md`.

All saved files must include a provenance header: generation date, modules analyzed, finding counts, and workspace run directory path.

## Error Handling

- **No modules found**: List available modules and suggest running `/triage <module>` first
- **No cached results for any module**: Report which modules lack results and suggest running `/scan` on them
- **Partial results**: Always report findings from modules that have cached data, note which modules were skipped
- **Schema mismatch**: If cached data cannot be normalized, log a warning and skip that result file
- **Empty result set**: Report "no findings across all modules" as a valid result
