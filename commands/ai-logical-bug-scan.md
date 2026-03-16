# AI Logical Bug Scan

## Overview

AI-driven scan for logic vulnerabilities: authentication/authorization bypass,
state machine errors, confused deputy, privilege escalation,
missing impersonation revert, and sensitive API parameter injection.

Uses LLM agents that navigate cross-module callgraphs, read decompiled code
on demand, and verify findings against assembly ground truth. All
vulnerability detection decisions are made by LLM agents, not pattern matching.

Usage:

- `/ai-logical-bug-scan <module>` -- scan top entry points for the module
- `/ai-logical-bug-scan <module> <function>` -- scan from a specific function
- `/ai-logical-bug-scan <module> <function> --depth 3` -- limit callgraph depth

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
result = validate_command_args("ai-logical-bug-scan", {
    "module": "<user_module>",
    "function": "<user_function_or_None>",
})
if not result.ok:
    # report errors and stop
db_path = result.resolved["db_path"]
```

## Workspace Protocol

Create `.agent/workspace/<module>_logicscan_<function_or_all>_<timestamp>/` and
pass `--workspace-dir` and `--workspace-step` to all skill scripts.

## Subagent Compliance Checklist (MANDATORY)

Before proceeding past each phase, verify the following. Violations
invalidate the scan.

- [ ] Phase 2 (Triage): Launched a `security-auditor` subagent via the
      Task tool. Did NOT write triage/results.json from coordinator context.
- [ ] Phase 3 (Deep Analysis): Launched the `logic-scanner` subagent via
      the Task tool. Did NOT perform adversarial analysis inline.
- [ ] Phase 4 (Skeptic): For EACH finding, launched a SEPARATE subagent
      via the Task tool with fresh context. Did NOT verify findings in the
      same context that discovered them.
- [ ] Every finding includes `verification_subgraph` with nodes, edges,
      must_read, and db_path.

**Protocol violations:**

- Writing triage/results.json without a Stage 2 Task call
- Writing skeptic/results.json without per-finding Task calls
- Skeptic running in the same context as the scanner (confirmation bias)
- Finding missing verification_subgraph field
- Launching a second scanner instance for deeper depths (scanner is self-driving)
- Pre-analyzing function code in the orchestrator prompt (bias injection)
- Batch-fetching code for the scanner instead of letting it read via Shell

## Steps

### Phase 0 -- Threat Model

**Status (before):** Tell the user: `Building threat model for <module>...`

```bash
python .agent/skills/ai-logic-scanner/scripts/build_threat_model.py <db_path> --json \
    --workspace-dir <run_dir> --workspace-step threat_model
```

Read the summary from stdout. This tells you: service type, privilege level,
attacker model, top entry points with RPC/COM context.

**Status (after):** Tell the user the key facts: service type, attacker model, entry point count.

### Phase 1 -- Callgraph Preparation

**Status (before):** Tell the user: `Preparing callgraph from <function/entry-points> (depth <N>)...`

For module-wide scan:

```bash
python .agent/skills/ai-logic-scanner/scripts/prepare_context.py <db_path> \
    --entry-points --depth 5 --with-code --json \
    --workspace-dir <run_dir> --workspace-step context
```

For single-function scan:

```bash
python .agent/skills/ai-logic-scanner/scripts/prepare_context.py <db_path> \
    --function "<function_name>" --depth 5 --with-code --json \
    --workspace-dir <run_dir> --workspace-step context
```

Read the summary from stdout. This gives you the callgraph stats (node count,
edge count, modules involved).

**Status (after):** Tell the user the callgraph size (e.g., `Callgraph: 1,597 nodes, 4,098 edges, 67 MUST_READ functions across 11 modules`).

### Phase 2 -- Quick Triage (MANDATORY)

**Status (before):** Tell the user: `Running triage assessment...`

> **This phase MUST NOT be skipped.** A scan that proceeds directly from
> Phase 1 to Phase 3 without a recorded triage decision is a protocol
> violation. Write the triage result to `<run_dir>/triage/results.json`
> before starting Phase 3.

Read the full callgraph JSON from `<run_dir>/context/results.json` and the
threat model from `<run_dir>/threat_model/results.json`.

**For module-wide scans:** Launch a **cheap** `security-auditor` subagent
with this prompt:

> Read the callgraph JSON and threat model. For each entry point in the
> callgraph, produce a one-line assessment: is a logic vulnerability
> **likely** or **unlikely** based on the callgraph structure, the types
> of privileged operations reachable, the presence of auth-check APIs, and
> the impersonation patterns? Be conservative -- if unsure, say likely.
> Return a JSON object with `status: "ok"`, `triage` array of
> `{entry_point, assessment, reasoning}` objects, and
> `counts: {likely, unlikely, total}`.

The triage operates on callgraph structure only -- no decompiled code or
assembly is read during this phase. This is what makes it cheap (~5-10
seconds per entry point).

**For single-function scans:** The triage has exactly one entry with
`assessment: "likely"`. The reasoning MUST still describe the callgraph
characteristics (privileged ops reachable, auth-check API count,
impersonation pattern, dispatch shape) -- do NOT just say "user-directed."
Write the triage result to `<run_dir>/triage/results.json` for workspace
completeness.

Keep only the **likely** entry points for Phase 3.

**Status (after):** Tell the user the triage result (e.g., `Triage: 3 likely, 2 unlikely -- proceeding with NetrShareAdd, NetrShareSetInfo, NetrShareGetInfo`).

### Phase 3 -- Deep Analysis (Self-Driving Scanner)

**Status (before):** Tell the user: `Launching logic scanner (self-driving, max depth <N>)...`

Launch a **SINGLE** `logic-scanner` subagent. The scanner drives its own
depth expansion internally -- it reads deeper functions itself via Shell.
Do NOT batch-fetch code for the scanner. Do NOT launch a second scanner
instance for deeper depths. Do NOT pre-analyze any functions in the prompt.

**Provide to the scanner subagent:**

1. Threat model content (from Phase 0 -- read `<run_dir>/threat_model/results.json`)
2. Callgraph structure + traversal_plan (from Phase 1 -- read `<run_dir>/context/results.json`)
3. Preloaded code for depth 0+1 MUST_READ functions (from `preloaded_code` in context results)
4. `db_path` for on-demand code retrieval via Shell
5. Reference material paths:
   - `.agent/skills/ai-logic-scanner/reference/vulnerability_patterns.md`
   - `.agent/skills/ai-logic-scanner/reference/decompiler_pitfalls.md`
6. `max_depth` parameter

The scanner returns complete findings with `verification_subgraph`, false
leads, and a `coverage_report` showing all functions read across all depths.

**Escalation handling:** If the scanner returns `status: "needs_escalation"`,
resolve the request (find cross-module DB, extract function, run a different
skill) and **resume the SAME scanner instance** via `Task(resume=<agent_id>)`.
Provide ONLY the requested data -- no analysis, no summaries.

Write scanner output to `<run_dir>/findings/results.json`.

**Status (after):** Tell the user what the scanner found (e.g., `Scanner complete: 2 findings, 5 false leads, depth reached 4, 15 functions analyzed`).

### Phase 4 -- Skeptic Verification

**Status (before):** If findings exist, tell the user: `Verifying <N> findings with independent skeptic...`. If 0 findings, tell the user: `No findings to verify -- skipping skeptic phase.`

For each finding from Stage 3:

**Step 1 -- Ensure `verification_subgraph` exists.**
If a finding lacks `verification_subgraph` (e.g. secondary findings outside the
primary vulnerability class), the coordinator MUST construct one before launching
the skeptic:

- `call_chain`: `[entry_point, ..., finding_function]`
- `must_read`: at minimum the finding function and its immediate caller
- `db_path`: from the scan context
- `nodes`/`edges`: extracted from `<run_dir>/context/results.json`

**Step 2 -- Extract the MUST_READ sub-callgraph.**
From `<run_dir>/context/results.json`, extract and include directly in the
skeptic prompt:

- **MUST_READ functions by depth** from `traversal_plan.by_depth` -- the full
  list of application functions at each depth level
- **Edges between MUST_READ functions** from `callgraph.edges` -- filtered to
  only edges where both source and target are MUST_READ nodes

This gives the skeptic a navigable map of the callgraph neighborhood (typically
~50-100 application functions and their call relationships) rather than just the
3-4 functions on the finding's own chain.

**Step 3 -- Launch a SEPARATE `security-auditor` subagent via the Task tool.**
The skeptic MUST have fresh context -- do NOT reuse the scanner subagent.

Use this prompt template (fill in all `[bracketed]` values):

> You are an independent skeptic verifier. Your job is to determine whether
> the following vulnerability finding is TRUE_POSITIVE or FALSE_POSITIVE by
> independently reading and analyzing the code.
>
> ## Finding
>
> [Paste the complete finding JSON here, including verification_subgraph
> > with call_chain, nodes, edges, must_read, and db_path]
>
> ## Callgraph Neighborhood (MUST_READ sub-callgraph)
>
> These are all application-logic functions in the scan callgraph, organized
> by depth from the entry point. Use this to understand what exists around
> the finding's call chain.
>
> **MUST_READ by depth:**
> [Paste traversal_plan.by_depth content -- function names grouped by depth]
>
> **Edges between MUST_READ functions:**
> [Paste filtered edges -- only edges where both source and target are
> > MUST_READ nodes, in format: source -> target]
>
> The full callgraph (including library/API nodes) is at:
> `[run_dir]/context/results.json`
> Read it with the Read tool if you need detail beyond the MUST_READ
> neighborhood.
>
> ## How to Read Function Code
>
> To read any function's decompiled code and assembly, run:
>
> ```
> python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py "[db_path]" --function "FunctionName" --json
> ```
>
> Read the `decompiled_code` and `assembly_code` fields from the Shell output.
>
> You MUST independently read ALL functions in `verification_subgraph.must_read`.
> You MAY read ANY other function in the database if needed for verification --
> the MUST_READ list by depth shows what application functions exist at each
> level. You are not restricted to the finding's call chain.
>
> ## Reference Materials
>
> - `.agent/skills/ai-logic-scanner/reference/vulnerability_patterns.md`
> - `.agent/skills/ai-logic-scanner/reference/decompiler_pitfalls.md`
>
> ## Verification Protocol
>
> CONSIDER YOU MAY BE WRONG. If you are wrong in your reasoning, where would
> it be? FULLY TEST ALL OTHER POSSIBILITIES. Use at least 2 independent
> methods to verify: (1) trace through decompiled code, (2) verify against
> assembly.
>
> Apply these 4 criteria:
>
> 1. DATA FLOW: Re-read each function in the call chain. Does data actually
>    flow through the path as claimed? Check each hop through concrete
>    assignments and function arguments.
> 2. VALIDATION CHECKS: Are the guards and access checks on the path
>    sufficient? Verify in assembly that checks are not optimized away or
>    bypassable. Check both the happy path and error/fallback paths.
> 3. REACHABILITY: Is the path actually reachable from the entry point?
>    Check for dead code, impossible branch conditions, or missing prerequisites.
> 4. EXPLOITABILITY: Write the exact RPC/COM call sequence and parameter
>    values that trigger this logic vulnerability. If you cannot, explain
>    which specific constraint prevents exploitation.
>
> ## Output
>
> Return your verdict as `TRUE_POSITIVE` or `FALSE_POSITIVE` with per-criterion
> reasoning. Write results to `[run_dir]/skeptic/results.json`.

**Step 4 -- Collect verdict.**
`TRUE_POSITIVE` or `FALSE_POSITIVE` with per-criterion reasoning.

**Step 5 -- Write results** to `<run_dir>/skeptic/results.json`.

**Status (after):** Tell the user the verification result (e.g., `Skeptic: 1 TRUE_POSITIVE, 1 FALSE_POSITIVE`).

### Phase 5 -- Report

**Status (before):** Tell the user: `Writing final report...`

1. Collect all `TRUE_POSITIVE` findings
2. Correlate related findings into attack chains (e.g. auth bypass enables
   file write enables privilege escalation)
3. Write the report to `extracted_code/<module>/reports/ai_logic_scan_<YYYYMMDD_HHMM>.md`
4. Present the report with:
   - Module threat model summary
   - Verified findings ranked by severity
   - For each finding: vulnerability type, call chain, evidence, exploitation
     assessment, assembly confirmation
   - FALSE_POSITIVE findings with reasons (for transparency)

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
extracted_code/<module>/reports/ai_logic_scan_<YYYYMMDD_HHMM>.md
```

Include provenance: db_path, workspace run directory, entry points analyzed,
callgraph depth, timestamp.

## Error Handling

| Scenario                    | Behavior                                                    |
| --------------------------- | ----------------------------------------------------------- |
| Module not found            | Report error, suggest `find_module_db.py --list`            |
| Function not found          | Report error, suggest `list_functions.py --search`          |
| No entry points discovered  | Report "no attack surface found", stop                      |
| Callgraph preparation fails | Report error with stderr details                            |
| Quick triage: all unlikely  | Report "no likely logic vulnerability targets", stop        |
| Deep analysis: no findings  | Report "no logic vulnerabilities found" (valid result)      |
| Skeptic: all FALSE_POSITIVE | Report "findings did not survive verification" with reasons |
| Subagent timeout            | Note timeout, continue with remaining findings              |

## Degradation Paths

| Condition                                     | Behavior                                                              |
| --------------------------------------------- | --------------------------------------------------------------------- |
| Analysis DB missing but extracted_code exists | Report error -- AI scanner requires DB for function data              |
| Tracking DB missing                           | Single-module callgraph only, no cross-module edges. Note limitation. |
| No IPC context (no RPC/COM/WinRT)             | Entry points from exports only. Note limitation.                      |
| Assembly code missing for a function          | Skip assembly verification for that function. Note in findings.       |
