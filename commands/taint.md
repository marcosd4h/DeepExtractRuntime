# Taint Analysis

## Overview

AI-driven taint analysis: trace attacker-controlled data from entry points
to dangerous sinks across module boundaries.  Uses LLM agents that navigate
taint-enriched callgraphs with trust boundary metadata, read decompiled code
on demand, and verify findings against assembly ground truth.

Usage:
- `/taint <module>` -- scan top entry points for taint paths
- `/taint <module> <function>` -- scan from a specific function
- `/taint <module> <function> --depth 5` -- control callgraph depth
- `/taint <module> --from-entrypoints --top 10` -- batch-scan top 10 entry points

## IMPORTANT: Execution Model

This command executes immediately. Run the full pipeline and deliver the
completed report without pausing for confirmation. Use the workspace handoff
pattern for all phases.

## Status Messaging (MANDATORY)

Keep the user informed at every phase boundary. Output a plain-text status
message **before** each phase starts and **after** it completes. Messages
are 1-2 lines summarizing what is happening and what the phase produced.
Do NOT suppress status messages to "save time."

## Execution Context

> **IMPORTANT**: Script invocations like `python .agent/skills/.../script.py`
> run from the workspace root. The scripts manage their own path setup.

## Step 0: Preflight Validation

```python
from helpers.command_validation import validate_command_args
result = validate_command_args("taint", {
    "module": "<user_module>",
    "function": "<user_function_or_None>",
})
if not result.ok:
    # report errors and stop
db_path = result.resolved["db_path"]
```

## Workspace Protocol

Create `.agent/workspace/<module>_taint_<function_or_all>_<timestamp>/` and
pass `--workspace-dir` and `--workspace-step` to all skill scripts.

**Shell setup rules (required before any redirect):**

- Always assign `WORKDIR` as an **absolute path** from the workspace root.
- Always `mkdir -p "$WORKDIR/<step_name>"` **before** any `>` redirect.
- Never use `2>&1` when capturing `--json` output.

## Steps

## Subagent Compliance Checklist (MANDATORY)

Before proceeding past each phase, verify the following. Violations
invalidate the scan.

- [ ] Phase 2 (Triage): Launched a `security-auditor` subagent via the
      Task tool. Did NOT write triage/results.json from coordinator context.
- [ ] Phase 3 (Deep Analysis): Launched the `taint-scanner` subagent via
      the Task tool. Did NOT perform taint analysis inline.
- [ ] Every finding includes `verification_subgraph` with propagation_chain
      nodes, edges, must_read, and db_path.

**Protocol violations:**
- Writing triage/results.json without a Stage 2 Task call
- Performing taint analysis inline instead of via taint-scanner subagent
- Finding missing verification_subgraph field
- Launching a second scanner instance for deeper depths (scanner is self-driving)
- Pre-analyzing function code in the orchestrator prompt (bias injection)
- Batch-fetching code for the scanner instead of letting it read via Shell

### Phase 0 -- Threat Model

**Status (before):** Tell the user: `Building taint threat model for <module>...`

```bash
python .agent/skills/ai-taint-scanner/scripts/build_threat_model.py <db_path> --json \
    --workspace-dir <run_dir> --workspace-step threat_model
```

Read the summary from stdout. This tells you: service type, trust boundary
classification, attacker model, top entry points with sink density and
taint parameter hints, trust transition opportunities, and IPC reachability.

**Status (after):** Tell the user the key facts: service type, attacker model, trust boundary, entry point count, sink density.

### Phase 1 -- Callgraph Preparation

**Status (before):** Tell the user: `Preparing taint-enriched callgraph from <function/entry-points> (depth <N>)...`

For module-wide scan:
```bash
python .agent/skills/ai-taint-scanner/scripts/prepare_context.py <db_path> \
    --entry-points --depth 5 --with-code --json \
    --workspace-dir <run_dir> --workspace-step context
```

For single-function scan:
```bash
python .agent/skills/ai-taint-scanner/scripts/prepare_context.py <db_path> \
    --function "<function_name>" --depth 5 --with-code --json \
    --workspace-dir <run_dir> --workspace-step context
```

Read the summary from stdout. This gives you callgraph stats, per-node
taint enrichments (sink APIs, sink categories, parameter counts, trust
levels), trust boundary metadata, and sink density aggregates.

**Status (after):** Tell the user the callgraph size and taint enrichment summary (e.g., `Callgraph: 1,597 nodes, 67 MUST_READ functions, 12 dangerous sinks reachable, trust boundary: rpc_server -> system_service`).

### Phase 2 -- Quick Triage (MANDATORY)

**Status (before):** Tell the user: `Running taint triage assessment...`

> **This phase MUST NOT be skipped.** A scan that proceeds directly from
> Phase 1 to Phase 3 without a recorded triage decision is a protocol
> violation.  Write the triage result to `<run_dir>/triage/results.json`
> before starting Phase 3.

Read the full callgraph JSON from `<run_dir>/context/results.json` and the
threat model from `<run_dir>/threat_model/results.json`.

**For module-wide scans:** Launch a **cheap** `security-auditor` subagent
with this prompt:

> Read the callgraph JSON and threat model.  For each entry point in the
> callgraph, produce a one-line assessment: is there a **likely** or
> **unlikely** taint path to a dangerous sink based on the callgraph
> structure, the number and severity of reachable sink APIs, trust boundary
> transitions, parameter counts, and IPC reachability?  Be conservative --
> if unsure, say likely.  Return a JSON object with `status: "ok"`,
> `triage` array of `{entry_point, assessment, reasoning}` objects, and
> `counts: {likely, unlikely, total}`.

The triage operates on callgraph structure and taint enrichment metadata
only -- no decompiled code or assembly is read during this phase.

**For single-function scans:** The triage has exactly one entry with
`assessment: "likely"`.  The reasoning MUST still describe the callgraph
characteristics (MUST_READ count, sink APIs reachable, trust transitions,
parameter count, depth) -- do NOT just say "user-directed."

Keep only the **likely** entry points for Phase 3.

**Status (after):** Tell the user the triage result (e.g., `Triage: 1 likely, 0 unlikely -- proceeding with NetrShareAdd`).

### Phase 3 -- Deep Analysis (Self-Driving Scanner)

**Status (before):** Tell the user: `Launching taint scanner (self-driving, max depth <N>)...`

Launch a **SINGLE** `taint-scanner` subagent. The scanner drives its own
depth expansion internally -- it reads deeper functions itself via Shell.
Do NOT batch-fetch code for the scanner. Do NOT launch a second scanner
instance for deeper depths. Do NOT pre-analyze any functions in the prompt.

**Provide to the scanner subagent:**

1. Threat model content (from Phase 0 -- read `<run_dir>/threat_model/results.json`)
2. Callgraph structure + traversal_plan + taint enrichment (from Phase 1 -- read `<run_dir>/context/results.json`)
3. Preloaded code for depth 0+1 MUST_READ functions (from `preloaded_code` in context results)
4. `db_path` for on-demand code retrieval via Shell
5. Reference material paths:
   - `.agent/skills/ai-taint-scanner/reference/taint_patterns.md`
   - `.agent/skills/ai-taint-scanner/reference/decompiler_pitfalls.md`
6. `max_depth` parameter

The scanner returns complete findings with `verification_subgraph`,
`taint_map`, `propagation_chain`, and a `coverage_report` showing all
functions read and classified across all depths.

**Escalation handling:** If the scanner returns `status: "needs_escalation"`,
resolve the request (find cross-module DB, extract function, run a different
skill) and **resume the SAME scanner instance** via `Task(resume=<agent_id>)`.
Provide ONLY the requested data -- no analysis, no summaries.

Write scanner output to `<run_dir>/findings/results.json`.

**Status (after):** Tell the user what the scanner found (e.g., `Taint scanner complete: 3 taint paths found, 2 trust boundary crossings, depth reached 4, 12 functions analyzed`).

### Phase 4 -- Skeptic Verification

**Status (before):** If findings exist, tell the user: `Verifying <N> taint findings with independent skeptic...`. If 0 findings, tell the user: `No findings to verify -- skipping skeptic phase.`

For each finding from Stage 3:

**Step 1 -- Ensure `verification_subgraph` exists.**
If a finding lacks `verification_subgraph`, the coordinator MUST construct one
before launching the skeptic:
- `call_chain`: `[entry_point, ..., sink_function]` (the taint propagation path)
- `must_read`: at minimum the entry point, the sink function, and intermediate
  functions where taint is transformed or checked
- `db_path`: from the scan context
- `nodes`/`edges`: extracted from `<run_dir>/context/results.json`

**Step 2 -- Extract the MUST_READ sub-callgraph.**
From `<run_dir>/context/results.json`, extract and include directly in the
skeptic prompt:
- **MUST_READ functions by depth** from `traversal_plan.by_depth` -- the full
  list of application functions at each depth level
- **Edges between MUST_READ functions** from `callgraph.edges` -- filtered to
  only edges where both source and target are MUST_READ nodes

This gives the skeptic a navigable map of the callgraph neighborhood rather
than just the functions on the finding's taint propagation chain.

**Step 3 -- Launch a SEPARATE `security-auditor` subagent via the Task tool.**
The skeptic MUST have fresh context -- do NOT reuse the scanner subagent.

Use this prompt template (fill in all `[bracketed]` values):

> You are an independent skeptic verifier. Your job is to determine whether
> the following taint analysis finding is TRUE_POSITIVE or FALSE_POSITIVE by
> independently reading and analyzing the code.
>
> ## Finding
> [Paste the complete finding JSON here, including verification_subgraph
> with call_chain/propagation_chain, nodes, edges, must_read, and db_path]
>
> ## Callgraph Neighborhood (MUST_READ sub-callgraph)
> These are all application-logic functions in the scan callgraph, organized
> by depth from the entry point. Use this to understand what exists around
> the finding's taint propagation chain.
>
> **MUST_READ by depth:**
> [Paste traversal_plan.by_depth content -- function names grouped by depth]
>
> **Edges between MUST_READ functions:**
> [Paste filtered edges -- only edges where both source and target are
> MUST_READ nodes, in format: source -> target]
>
> The full callgraph (including library/API nodes) is at:
>   `[run_dir]/context/results.json`
> Read it with the Read tool if you need detail beyond the MUST_READ
> neighborhood.
>
> ## How to Read Function Code
> To read any function's decompiled code and assembly, run:
> ```
> python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py "[db_path]" --function "FunctionName" --json
> ```
> Read the `decompiled_code` and `assembly_code` fields from the Shell output.
>
> You MUST independently read ALL functions in `verification_subgraph.must_read`.
> You MAY read ANY other function in the database if needed for verification --
> the MUST_READ list by depth shows what application functions exist at each
> level. You are not restricted to the finding's propagation chain.
>
> ## Reference Materials
> - `.agent/skills/ai-taint-scanner/reference/taint_patterns.md`
> - `.agent/skills/ai-taint-scanner/reference/decompiler_pitfalls.md`
>
> ## Verification Protocol
> CONSIDER YOU MAY BE WRONG. If you are wrong in your reasoning, where would
> it be? FULLY TEST ALL OTHER POSSIBILITIES. Use at least 2 independent
> methods to verify: (1) trace through decompiled code, (2) verify against
> assembly.
>
> Apply these 4 criteria:
> 1. TAINT PROPAGATION: Re-read each function in the propagation chain. Does
>    attacker-controlled data actually reach the dangerous sink through
>    concrete assignments and function arguments? Check each hop.
> 2. GUARD EFFECTIVENESS: Are sanitizers, validators, or bounds checks on the
>    path sufficient to neutralize the taint? Verify in assembly that guards
>    are not bypassable or applied to copies rather than the original data.
> 3. REACHABILITY: Is the taint path actually reachable from the entry point?
>    Check for dead code, impossible branch conditions, or missing prerequisites.
> 4. EXPLOITABILITY: Construct the exact input that reaches the sink with
>    attacker-controlled content. If you cannot, explain which specific
>    constraint prevents exploitation.
>
> ## Output
> Return your verdict as `TRUE_POSITIVE` or `FALSE_POSITIVE` with per-criterion
> reasoning. Write results to `[run_dir]/skeptic/results.json`.

**Step 4 -- Collect verdict.**
`TRUE_POSITIVE` or `FALSE_POSITIVE` with per-criterion reasoning.

**Step 5 -- Write results** to `<run_dir>/skeptic/results.json`.

**Status (after):** Tell the user the verification result (e.g., `Skeptic: 2 TRUE_POSITIVE, 1 FALSE_POSITIVE`).

### Phase 5 -- Report

**Status (before):** Tell the user: `Writing final taint report...`

1. Collect all findings from Phase 3
2. Correlate related findings into attack narratives:
   - **Fan-out**: same parameter reaching multiple sinks
   - **Convergence**: multiple parameters reaching the same sink
   - **Trust escalation chains**: taint crossing privilege boundaries
   - **Complementary primitives**: branch steering + size control = overflow
3. Write the report to `extracted_code/<module>/reports/ai_taint_scan_<YYYYMMDD_HHMM>.md`
4. Present the report with:
   - Module threat model and trust boundary summary
   - Taint findings ranked by severity
   - For each finding: sink API, sink category, call path from entry to
     sink, guards on path and bypass feasibility, trust transitions,
     logic effects, assembly confirmation
   - Attack narratives grouping related findings
   - Rejected findings with reasons (for transparency)

### Phase 5 Companion JSON

After writing the markdown report, also write a structured `.findings.json`
companion file alongside it. The companion path replaces `.md` with
`.findings.json` (e.g. `ai_logic_scan_20260315_2345.findings.json`).

The companion JSON must contain the **same or more information** than the
`.md` report. It is the authoritative structured record of the scan. Include:

- All report header metadata: `scan_type`, `module`, `entry_point`,
  `entry_point_opnum`, `entry_point_interface`, `depth`, `timestamp`,
  `db_path`, `workspace_run_dir`, `report_path`, `callgraph_stats`,
  `functions_analyzed`
- Full `threat_model` object (all table fields + narrative)
- `true_positives` array: each finding with `id`, `vulnerability_type`,
  `vulnerability_class`, `severity`, `title`, `description`, `call_chain`,
  `primary_function`, `evidence`, `assembly_confirmation`,
  `impact_assessment`, `practical_exploitability`, `structural_mitigation`,
  `remediation`, `verification_subgraph`, `skeptic_verdict`,
  `skeptic_summary`, `skeptic_criteria`, `dedup_key`
- `false_positives` array: same fields plus `hypothesis`, `why_dismissed`
- `false_leads` array from the scanner
- `attack_chain_analysis` narrative
- `overall_severity` and `overall_severity_justification`
- `coverage_summary` (per-phase) and `coverage` (functions read/skipped)
- `provenance` (workspace artifact paths)

### Phase 6 -- Cross-Report Comparison

**Status (before):** Tell the user: `Checking for previous scan reports...`

1. Use `helpers.report_comparison.discover_reports()` to find previous
   `.findings.json` files of the same scan type in
   `extracted_code/<module>/reports/`
2. If no previous report exists, tell the user "First scan of this type
   for this module" and skip
3. Load the most recent previous `.findings.json` with
   `helpers.report_comparison.load_findings_json()`
4. Run `helpers.report_comparison.compare_findings(current, previous)`
   using the just-written `.findings.json`
5. Generate comparison markdown with
   `helpers.report_comparison.format_comparison_section()`
6. Append the `## Previous Findings Comparison` section to the markdown
   report file
7. Present the comparison summary to the user

**Status (after):** Tell the user the comparison result (e.g., `Cross-report:
2 recurring, 1 new, 3 missed from previous scan`). If this was the first
scan, say so.

## Output

Save the report as:
```
extracted_code/<module>/reports/ai_taint_scan_<YYYYMMDD_HHMM>.md
```

Include provenance: db_path, workspace run directory, entry points analyzed,
callgraph depth, timestamp.

Save a JSON report to:
```
extracted_code/<module>/reports/taint_<function_or_entrypoints>_<YYYYMMDD_HHMM>.json
```

```json
{
  "scan_type": "ai_taint_analysis",
  "entry_point": "<function_name or 'entrypoints'>",
  "module": "<module_name>",
  "timestamp": "<ISO timestamp>",
  "findings": [],
  "rejected_findings": [],
  "attack_narratives": [],
  "workspace_dir": "<path>"
}
```

Mention the saved paths at the end of the chat report.

## Follow-Up Suggestions

- `/audit <module> <function>` -- full security audit on flagged functions
- `/memory-scan <module> <function>` -- deep memory corruption scan on callees
- `/ai-logical-bug-scan <module> <function>` -- logic scan on flagged callees
- `/explain <module> <callee>` -- understand what a flagged callee does

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Module not found | Report error, suggest `find_module_db.py --list` |
| Function not found | Report error, suggest `list_functions.py --search` |
| No entry points discovered | Report "no attack surface found", stop |
| Callgraph preparation fails | Report error with stderr details |
| Quick triage: all unlikely | Report "no likely taint targets", stop |
| Deep analysis: no findings | Report "no taint paths found" (valid result) |
| Subagent timeout | Note timeout, continue with remaining findings |
