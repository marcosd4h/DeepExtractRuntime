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

### Phase 0 -- Threat Model

```bash
python .agent/skills/ai-taint-scanner/scripts/build_threat_model.py <db_path> --json \
    --workspace-dir <run_dir> --workspace-step threat_model
```

Read the summary from stdout. This tells you: service type, trust boundary
classification, attacker model, top entry points with sink density and
taint parameter hints, trust transition opportunities, and IPC reachability.

### Phase 1 -- Callgraph Preparation

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

### Phase 2 -- Quick Triage (MANDATORY)

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

### Phase 3 -- Iterative Depth Analysis

The deep analysis uses an iterative depth-expansion loop.  The coordinator
(you) drives the loop; the scanner subagent receives code one depth level
at a time and returns taint-guided requests for the next level.

**Preparation:** Read the callgraph context from `<run_dir>/context/results.json`.
It contains `traversal_plan` (functions classified by depth and category) and
`preloaded_code` (decompiled code for depth 0+1 MUST_READ functions).

**Loop:**

```
current_depth = 1
code_batch = preloaded_code from Phase 1 output

LOOP:
  Launch (or resume) a `taint-scanner` subagent with:
    1. Threat model content (from Phase 0)
    2. Callgraph structure + traversal_plan + taint_enrichment (from Phase 1)
    3. code_batch (MUST_READ functions for current depth level)
    4. db_path for on-demand KNOWN_API retrieval if needed
    5. Reference material paths:
       - .agent/skills/ai-taint-scanner/reference/taint_patterns.md
       - .agent/skills/ai-taint-scanner/reference/decompiler_pitfalls.md

  Read subagent output:
    - findings: [...] (taint paths found so far)
    - next_depth_requests: [{function, reason}, ...] (depth N+1 functions)
    - coverage_report: {functions_read, functions_skipped}

  Accumulate findings and coverage across iterations.

  IF next_depth_requests is empty OR current_depth >= max_depth:
    BREAK

  Batch-fetch requested functions:
    python .agent/agents/code-lifter/scripts/batch_extract.py <db_path> \
      --functions <requested_func_names...> --json

  code_batch = batch_extract output
  current_depth += 1
  CONTINUE
```

This loop runs at most `max_depth - 1` iterations (depth 0+1 is pre-loaded).

**Taint-specific analysis focus for the subagent:**

The taint-scanner subagent traces data flow from attacker-controlled
parameters to dangerous sinks.  For each function it reads, it must:

1. Identify which parameters carry attacker-controlled data (from the
   enrichment metadata or from the entry point signature)
2. Track how those parameters propagate through local variables, function
   calls, and return values
3. Check whether tainted data reaches any sink API (from the sink_apis
   enrichment list)
4. Record any guards/validation on the path (NULL checks, size bounds,
   format validation, ACL checks)
5. Note trust boundary transitions (tainted data crossing from lower-trust
   to higher-trust modules)
6. Flag logic effects: branch steering, array indexing, size arguments,
   loop bounds controlled by tainted data

### Phase 4 -- Report

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
