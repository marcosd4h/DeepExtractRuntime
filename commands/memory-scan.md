# Memory Scan

## Overview

AI-driven scan for memory corruption vulnerabilities: buffer overflows,
integer overflow/truncation, use-after-free, double-free, and type confusion.
Uses LLM agents that navigate cross-module callgraphs, read decompiled code
on demand, and verify findings against assembly ground truth.

Usage:
- `/memory-scan <module>` -- scan top entry points for the module
- `/memory-scan <module> <function>` -- scan from a specific function
- `/memory-scan <module> <function> --depth 3` -- limit callgraph depth

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
result = validate_command_args("memory-scan", {
    "module": "<user_module>",
    "function": "<user_function_or_None>",
})
if not result.ok:
    # report errors and stop
db_path = result.resolved["db_path"]
```

## Workspace Protocol

Create `.agent/workspace/<module>_memscan_<function_or_all>_<timestamp>/` and
pass `--workspace-dir` and `--workspace-step` to all skill scripts.

## Steps

## Subagent Compliance Checklist (MANDATORY)

Before proceeding past each phase, verify the following. Violations
invalidate the scan.

- [ ] Phase 2 (Triage): Launched a `security-auditor` subagent via the
      Task tool. Did NOT write triage/results.json from coordinator context.
- [ ] Phase 3 (Deep Analysis): Launched the `memory-corruption-scanner`
      subagent via the Task tool. Did NOT perform adversarial analysis inline.
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

### Phase 0 -- Threat Model

```bash
python .agent/skills/ai-memory-corruption-scanner/scripts/build_threat_model.py <db_path> --json \
    --workspace-dir <run_dir> --workspace-step threat_model
```

Read the summary from stdout. This tells you: service type, privilege level,
attacker model, top entry points with RPC/COM context.

### Phase 1 -- Callgraph Preparation

For module-wide scan:
```bash
python .agent/skills/ai-memory-corruption-scanner/scripts/prepare_context.py <db_path> \
    --entry-points --depth 5 --with-code --json \
    --workspace-dir <run_dir> --workspace-step context
```

For single-function scan:
```bash
python .agent/skills/ai-memory-corruption-scanner/scripts/prepare_context.py <db_path> \
    --function "<function_name>" --depth 5 --with-code --json \
    --workspace-dir <run_dir> --workspace-step context
```

Read the summary from stdout. This gives you the callgraph stats (node count,
edge count, modules involved).

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
> callgraph, produce a one-line assessment: is memory corruption **likely**
> or **unlikely** based on the callgraph structure, the number of allocation
> and copy operations reachable, and the parameter types?  Be conservative
> -- if unsure, say likely.  Return a JSON object with `status: "ok"`,
> `triage` array of `{entry_point, assessment, reasoning}` objects, and
> `counts: {likely, unlikely, total}`.

The triage operates on callgraph structure only -- no decompiled code or
assembly is read during this phase.  This is what makes it cheap (~5-10
seconds per entry point).

**For single-function scans:** The triage has exactly one entry with
`assessment: "likely"`.  The reasoning MUST still describe the callgraph
characteristics (MUST_READ count, allocation/copy APIs reachable, parameter
types, depth) -- do NOT just say "user-directed."  Write the triage result
to `<run_dir>/triage/results.json` for workspace completeness.

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
  Launch (or resume) a `memory-corruption-scanner` subagent with:
    1. Threat model content (from Phase 0)
    2. Callgraph structure + traversal_plan (from Phase 1)
    3. code_batch (MUST_READ functions for current depth level)
    4. db_path for on-demand KNOWN_API retrieval if needed
    5. Reference material paths:
       - .agent/skills/ai-memory-corruption-scanner/reference/vulnerability_patterns.md
       - .agent/skills/ai-memory-corruption-scanner/reference/decompiler_pitfalls.md

  Read subagent output:
    - findings: [...] (vulnerabilities found so far)
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

### Phase 4 -- Skeptic verification

For each finding from Stage 3:

1. Extract `finding.verification_subgraph` -- this is the focused subgraph
   the skeptic must independently verify.

2. Launch a **SEPARATE** `security-auditor` subagent via the Task tool.
   The skeptic MUST have fresh context -- do NOT reuse the scanner subagent.

   Pass to the skeptic subagent:
   - The finding JSON (including `verification_subgraph`)
   - Full callgraph path: `<run_dir>/context/results.json`
   - `db_path` for on-demand code retrieval
   - Reference material paths (vulnerability_patterns.md, decompiler_pitfalls.md)

   Skeptic prompt must include:
   - "CONSIDER YOU MAY BE WRONG. FULLY TEST ALL OTHER POSSIBILITIES."
   - Instruction to read ALL functions in `verification_subgraph.must_read`
     independently using `extract_function_data.py`
   - The 4 verification criteria:
     1. TAINT FLOW: Re-read each function in the subgraph. Does attacker data
        actually reach the dangerous operation through the call_chain as claimed?
     2. ACCESS SIZE: Are buffer sizes and integer arithmetic correct in assembly?
     3. REACHABILITY: Is the path reachable from entry point? No dead code?
     4. EXPLOITABILITY: Construct the exact input bytes / parameter values that
        trigger this memory corruption.

3. The skeptic MUST read code independently -- not rely on the scanner's
   `evidence.code_lines` excerpts.

4. Collect verdict: `TRUE_POSITIVE` or `FALSE_POSITIVE` with per-criterion reasoning.

5. Write results to `<run_dir>/skeptic/results.json`.

### Phase 5 -- Report

1. Collect all `TRUE_POSITIVE` findings
2. Correlate related findings into attack chains (e.g. integer overflow leads
   to heap overflow leads to RCE)
3. Write the report to `extracted_code/<module>/reports/ai_memory_scan_<YYYYMMDD_HHMM>.md`
4. Present the report with:
   - Module threat model summary
   - Verified findings ranked by severity
   - For each finding: vulnerability type, call chain, evidence, exploitation
     assessment, assembly confirmation
   - FALSE_POSITIVE findings with reasons (for transparency)

## Output

Save the report as:
```
extracted_code/<module>/reports/ai_memory_scan_<YYYYMMDD_HHMM>.md
```

Include provenance: db_path, workspace run directory, entry points analyzed,
callgraph depth, timestamp.

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Module not found | Report error, suggest `find_module_db.py --list` |
| Function not found | Report error, suggest `list_functions.py --search` |
| No entry points discovered | Report "no attack surface found", stop |
| Callgraph preparation fails | Report error with stderr details |
| Quick triage: all unlikely | Report "no likely memory corruption targets", stop |
| Deep analysis: no findings | Report "no memory corruption found" (valid result) |
| Skeptic: all FALSE_POSITIVE | Report "findings did not survive verification" with reasons |
| Subagent timeout | Note timeout, continue with remaining findings |
