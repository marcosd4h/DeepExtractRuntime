# Scan, Audit, Taint Workflow and Drill-Down

This document describes the `/scan` command, how researchers drill down on findings today, how `/audit` and `/taint` are invoked for individual functions, and the gap for interactive "tell me more about finding #N" mode.

---

## 1. `/scan` Command

### What It Runs

The `/scan` command is a **unified vulnerability scan** that orchestrates multiple detection pipelines, verification, and exploitability scoring. It is the comprehensive alternative to running `/memory-scan`, `/logic-scan`, and `/taint` separately.

**Primary mechanism:** The **security-auditor** agent's `run_security_scan.py` script handles the full 6-phase pipeline (recon, scanning, taint, verification, exploitability, synthesis) with parallel execution and deduplication. The individual skill scripts listed below are called internally by `run_security_scan.py`.

| Pipeline | Scripts / Components |
|----------|----------------------|
| **Memory corruption** | `scan_buffer_overflows.py`, `scan_integer_issues.py`, `scan_use_after_free.py`, `scan_format_strings.py` |
| **Logic vulnerabilities** | `scan_auth_bypass.py`, `scan_state_errors.py`, `scan_logic_flaws.py`, `scan_api_misuse.py` |
| **Taint analysis** | Entry point discovery → `rank_entrypoints.py` → `taint_function.py` on top 5 ranked entry points |
| **Verification** | `verify_findings.py` (memory + logic pipelines only; taint has no separate verifier) |
| **Exploitability** | `assess_finding.py` or `batch_assess.py` for CRITICAL/HIGH findings |

### Modes

| Flag | Effect |
|------|--------|
| (none) | Full scan: all detectors + taint on top entries + verification + exploitability |
| `--memory-only` | Only memory corruption detection |
| `--logic-only` | Only logic vulnerability detection |
| `--taint-only` | Only taint analysis on entry points |
| `--top N` | Limit to top N findings per category |
| `--auto-audit` | After scanning, automatically run `/audit` on top 3 CRITICAL/HIGH findings |

### Single-Function Mode

`/scan <module> <function>` runs all scanners with `--id <fid>` on that specific function and skips entry point discovery.

### Output Format

The scan produces a consolidated report with:

1. **Executive Summary**
   - Module identity and security posture
   - Total findings by pipeline (memory, logic, taint)
   - After verification: confirmed, likely, removed (false positive) counts
   - Severity distribution (CRITICAL/HIGH/MEDIUM/LOW)

2. **Top Findings Table** (sorted by exploitability score, then severity)

   | # | Severity | Exploitability | Function | Category | Pipeline | Score |
   |---|----------|----------------|----------|----------|----------|-------|

3. **Per-Finding Details**
   - Category and subcategory
   - Evidence: code lines, taint path, dangerous API
   - Guards on path and bypass feasibility
   - Verification status and reasoning
   - Exploitability assessment
   - Cross-pipeline correlation (if same function flagged by multiple pipelines)

4. **Pipeline Breakdown**
   - Memory: buffer overflows, integer issues, UAF, format strings
   - Logic: auth bypass, state errors, TOCTOU, missing checks
   - Taint: attacker-reachable sinks with guard/bypass analysis

5. **Recommended Next Steps**
   - `/audit <module> <function>` — deep audit on CRITICAL/HIGH findings
   - `/taint <module> <function> --cross-module` — cross-module impact
   - `/hunt-plan hypothesis <type> <module>` — hypothesis-driven investigation
   - `/explain <module> <function>` — understand what a flagged function does

### Workspace Protocol

- Run directory: `.agent/workspace/<module>_scan_<timestamp>/`
- Per-phase results: `<run_dir>/<phase>/results.json` (merged, verified, exploitability)
- Manifest: `<run_dir>/manifest.json` tracks completed/failed phases

---

## 2. How a Researcher Drills Down Today

There is **no dedicated "drill down on finding #N" command**. The workflow is manual:

1. **Read the scan report** — findings are presented in a numbered table (e.g., #1, #2, #3).
2. **Extract the function name** — each finding row includes a `Function` column.
3. **Run a follow-up command** using the function name:
   - `/audit <module> <function>` — full security audit
   - `/taint <module> <function>` — taint trace on that function
   - `/explain <module> <function>` — quick explanation

### Example Flow

```
/scan appinfo.dll
→ Report shows: #1 CRITICAL AiLaunchProcess (logic), #2 HIGH AiCheckSecureApplicationDirectory (memory), ...

Researcher: "I want to understand finding #2"
→ Must manually: /audit appinfo.dll AiCheckSecureApplicationDirectory
   (or /taint appinfo.dll AiCheckSecureApplicationDirectory)
```

### What Exists to Help

- **Recommended Next Steps** in the report list concrete `/audit` and `/taint` commands for top findings.
- **`/prioritize`** loads cached scan/audit results and ranks findings across modules, but still outputs function names — no index-based lookup.
- **`/runs`** can list and show prior workspace runs; the agent can read `<run_dir>/verified/results.json` or `exploitability/results.json` to get finding details, but the user must still invoke `/audit` or `/taint` with the function name.

---

## 3. `/audit` and `/taint` — Invocation for Individual Functions

### `/audit`

**Purpose:** Full security audit of a specific function — dossier, attack reachability, data flow, risk assessment, concern checklist.

**Invocation:**

| Form | Example |
|------|---------|
| `/audit <function>` | `/audit AiCheckSecureApplicationDirectory` — searches all modules |
| `/audit <module> <function>` | `/audit appinfo.dll AiCheckSecureApplicationDirectory` |
| `/audit <module> --search <pattern>` | `/audit appinfo.dll --search CheckSecurity` |

**Resolution:** Uses `lookup_function.py` or `unified_search.py` to resolve function name → `function_id` and `db_path`. All subsequent steps use `--id <function_id>`.

**Key scripts:**

- `build_dossier.py <db_path> --id <fid> --json`
- `extract_function_data.py <db_path> --id <fid> --json`
- `rank_entrypoints.py <db_path> --function <name> --json`
- `backward_trace.py <db_path> --id <fid> --target <api> --json`
- `taint_function.py <db_path> --id <fid> --depth 4 --json`
- `chain_analysis.py <db_path> --id <fid> --depth 4 --summary --json`
- `classify_function.py <db_path> --id <fid> --json`

**Output:** Structured audit report saved to `extracted_code/<module>/reports/audit_<function>_<timestamp>.md`.

---

### `/taint`

**Purpose:** Trace attacker-controlled inputs forward to dangerous sinks and backward to caller origins, with guard/bypass analysis.

**Invocation:**

| Form | Example |
|------|---------|
| `/taint <module> <function>` | `/taint appinfo.dll AiLaunchProcess` — forward trace all params |
| `/taint <module> <function> --params 1,3` | Trace specific parameters |
| `/taint <module> <function> --depth 3` | Deeper recursion |
| `/taint <module> <function> --direction both` | Forward + backward |
| `/taint <module> <function> --direction backward` | Caller origins only |
| `/taint <module> <function> --cross-module` | Trace across DLL boundaries |
| `/taint <module> --from-entrypoints` | Auto-discover top entry points and taint-trace each |

**Resolution:** Uses `lookup_function.py` or `find_module_db.py` to get `function_id` and `db_path`.

**Key scripts:**

- `taint_function.py <db_path> --id <fid> [--params N] [--depth N] [--direction forward|backward|both] [--cross-module] [--cross-depth N] --json`
- `trace_taint_cross_module.py <db_path> --id <fid> [--from-entrypoints] [--top N] [--min-score S] --json`

**Output:** Taint report in chat; optionally saved to `extracted_code/<module>/reports/taint_<function>_<timestamp>.md`.

---

## 4. The Gap: No Interactive "Tell Me More About Finding #3" Mode

### Current State

- Scan reports present findings in a **numbered table** (#1, #2, #3, …).
- There is **no command or mode** that accepts a finding index (e.g., "finding 3", "find 3", "tell me more about #3").
- The user must:
  1. Read the table
  2. Identify the function name for the row of interest
  3. Manually type `/audit <module> <function>` or `/taint <module> <function>`

### What Would Be Needed

To support "tell me more about finding #3":

1. **Stable finding index** — Scan output would need to persist a numbered list (e.g., in workspace `manifest.json` or `ranked/results.json`) so that "finding 3" maps to a specific `{function_name, function_id, module, category, pipeline}`.
2. **Command or mode** — e.g. `/scan-detail <module> 3` or a natural-language handler that parses "find 3" / "explain finding #3" and:
   - Loads the last scan run for the module
   - Looks up finding index 3
   - Invokes `/audit` or `/taint` (or a lighter `/explain`) with the resolved function
3. **Session context** — The agent would need to know which scan run is "current" (e.g., from the last `/scan` output or a `--run-id` parameter).

### Existing Infrastructure That Could Support This

- **`helpers.finding_schema`** — `normalize_scanner_output()`, `Finding` dataclass for unified schema
- **`helpers.finding_merge`** — `merge_findings`, `deduplicate`, `rank` for cross-module prioritization
- **Workspace manifest** — `<run_dir>/manifest.json` and phase `results.json` already store findings; adding an indexed `findings_by_rank` or similar would enable lookup by #N
- **`/prioritize`** — Already loads cached scan results and produces a ranked list; could be extended to support "show detail for rank N" or to emit a machine-readable index for downstream commands

---

## Quick Reference

| Task | Command |
|------|---------|
| Full vulnerability scan | `/scan <module>` |
| Memory-only scan | `/scan <module> --memory-only` |
| Logic-only scan | `/scan <module> --logic-only` |
| Taint-only scan | `/scan <module> --taint-only` |
| Scan + auto-audit top 3 | `/scan <module> --auto-audit` |
| Deep audit on a function | `/audit [module] <function>` |
| Taint trace on a function | `/taint <module> <function>` |
| Cross-module taint | `/taint <module> <function> --cross-module` |
| Quick explanation | `/explain [module] <function>` |
| Cross-module prioritization | `/prioritize --modules A B \| --all` |

---

*Generated from `.agent/commands/scan.md`, `audit.md`, `taint.md`, `memory-scan.md`, `logic-scan.md`, and related skill/helper references.*
