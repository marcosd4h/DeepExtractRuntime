# Hunt Execute

## Overview

Automatically execute a vulnerability research plan produced by `/hunt`. Runs the investigation commands for each hypothesis, collects evidence, scores confidence, and produces a consolidated findings report.

Usage:

- `/hunt-execute appinfo.dll` -- execute the most recent hunt plan for this module
- `/hunt-execute` -- execute the plan from the most recent `/hunt` session
- `/hunt-execute --plan-file .agent/workspace/appinfo_hunt_plan_20260304.json` -- execute a specific plan file

This command is the "action" counterpart to `/hunt`'s "planning" phase. While `/hunt` produces hypotheses and maps them to commands, `/hunt-execute` runs those commands and interprets results.

## IMPORTANT: Execution Model

**This is an execute-immediately command.** Run the full investigation pipeline and deliver the completed findings report. Use the grind loop for multi-hypothesis workflows.

## Workspace Protocol

This command orchestrates multiple analysis steps per hypothesis:

1. Create `.agent/workspace/<module>_hunt_execute_<timestamp>/`.
2. Store per-hypothesis results in `<run_dir>/hypothesis_<N>/results.json`.
3. Keep only summary output and confidence scores in context.
4. Use `<run_dir>/manifest.json` to track which hypotheses have been investigated.

## Execution Context

> **IMPORTANT**: Any inline Python that imports `helpers.*` must run with `cd <workspace>/.agent`
> (so the `.agent/` directory is on `sys.path`), **not** from the workspace root.
> Script invocations like `python .agent/skills/.../script.py` can be run from the workspace root
> because those scripts manage their own path setup.

## Steps

### 1. Locate the hunt plan

Check for an existing `/hunt` plan using this priority order:

1. **Explicit plan file** (highest priority): If `--plan-file <path>` is provided, load that file directly. Fail with a clear error if the file does not exist or is not valid JSON.
2. **Workspace files** (preferred): Scan `.agent/workspace/` for `*_hunt_plan_*.json` files. If a module name is provided, filter to plans matching that module. Use the most recent file by timestamp.
3. **Conversation history** (fallback): If no workspace file is found, look in the conversation history for the most recent `/hunt` output.
4. If no plan is found by any method, suggest running `/hunt <module>` first.

Extract from the plan:
- **Hypotheses**: Each hypothesis statement with its priority score
- **Per-hypothesis commands**: The specific commands mapped to each hypothesis
- **Validation criteria**: What confirms vs refutes each hypothesis

### 2. Create grind-loop scratchpad

Create a session-scoped scratchpad at `.agent/hooks/scratchpads/{session_id}.md` with one checkbox per hypothesis:

```markdown
# Task: Hunt Execute -- <module>

## Items
- [ ] Hypothesis 1: <statement> (priority: N)
- [ ] Hypothesis 2: <statement> (priority: N)
...

## Status
IN_PROGRESS
```

### 3. Investigate each hypothesis

For each hypothesis in priority order:

**a. Run the mapped commands:**

> **Tip:** All skill scripts support `--json` for machine-readable output. Use `--json` when parsing script output programmatically.

Execute the commands specified in the hunt plan. Common patterns:

| Hypothesis Type | Commands to Run |
|----------------|----------------|
| Missing access check | `/audit <module> <func>` -> `/taint <module> <func>` |
| TOCTOU / file race | `/data-flow forward <module> <func>` -> `/audit <module> <func>` |
| Integer overflow | `/verify <module> <func>` -> `/taint <module> <func>` |
| COM privilege escalation | `/reconstruct-types <module> <class>` -> `/trace-export <module> <export>` |
| Variant of known CVE | `/search <module> <pattern>` -> `/taint <module> <candidate>` |

**b. Collect evidence:**

For each command result, extract:
- Relevant findings (taint sinks, dangerous ops, verification issues)
- Guard/bypass information
- Data flow paths
- Cross-module transitions

**c. Score confidence:**

Rate the hypothesis using the evidence:

| Confidence | Criteria |
|-----------|---------|
| CONFIRMED | Direct evidence: taint reaches sink with weak/no guards, decompiler-verified |
| LIKELY | Strong evidence: taint reaches sink but guards present, or decompiler unverified |
| POSSIBLE | Indirect evidence: dangerous APIs reachable but taint path unclear |
| UNLIKELY | Counter-evidence: strong guards, mitigations block exploitation |
| REFUTED | Clear counter-evidence: path doesn't exist, types don't match |

**d. Update scratchpad:** Check off the hypothesis.

### 4. Score exploitability of confirmed findings

For each hypothesis scored CONFIRMED or LIKELY, run **exploitability-assessment** to get a structured exploitability score:

```bash
python .agent/skills/exploitability-assessment/scripts/assess_finding.py \
    --taint-report <run_dir>/hypothesis_<N>/taint_results.json \
    --dossier <run_dir>/hypothesis_<N>/dossier.json \
    --module-db <db_path> --json
```

If multiple confirmed findings exist, use the batch assessor:

```bash
python .agent/skills/exploitability-assessment/scripts/batch_assess.py <db_path> --json
```

The assessment considers: mitigations (ASLR/DEP/CFG), guard bypass difficulty, primitive quality (read/write/exec), and reachability from entry points.

### 5. Synthesize findings report

After all hypotheses are investigated and scored:

**Confirmed/Likely findings (with exploitability):**
- Hypothesis statement, confidence level, and exploitability score
- Evidence summary (taint paths, missing checks, dangerous operations)
- Exploitation primitive (what the attacker gets) with quality rating
- Mitigation coverage and bypass feasibility
- Suggested next steps (PoC development, deeper analysis)

**Refuted hypotheses:**
- Brief explanation of why the hypothesis was refuted
- What compensating controls were found

**Overall assessment:**
- Module risk level based on confirmed findings and exploitability scores
- Priority-ordered list of findings for follow-up, ranked by exploitability

## Output

Present the investigation report in chat. Always save to `extracted_code/<module_folder>/reports/hunt_execute_<timestamp>.md` (using `YYYYMMDD_HHMM` for timestamp). Create the `reports/` directory if needed.

All saved files must include a provenance header: generation date, module name, hypotheses investigated, and workspace run directory path.

**Follow-up suggestions:**

- `/audit <module> <function>` -- deeper audit on confirmed findings
- `/taint <module> <function> --cross-module` -- trace cross-module impact
- `/hunt validate <module> <function>` -- plan PoC development for confirmed findings

## Error Handling

- **No hunt plan found**: Suggest running `/hunt <module>` first
- **Module not found**: List available modules and ask user to choose
- **Command failure**: Log the error, mark hypothesis as "investigation incomplete", continue with next
- **Partial results**: Always report what was successfully investigated, even if some hypotheses couldn't be tested
