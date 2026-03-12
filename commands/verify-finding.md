# Verify Finding

## Overview

Verify suspected vulnerability findings against assembly ground truth to produce TRUE POSITIVE or FALSE POSITIVE verdicts with documented evidence. Bridges the gap between "the scanner flagged this" and "this is a real vulnerability."

This command wraps the **finding-verification** skill, exposing its structured verification workflow as a first-class slash command.

Usage:

- `/verify-finding srvsvc.dll ClientCertificatesAccessCheck` -- verify findings for a specific function
- `/verify-finding srvsvc.dll --findings <path>` -- verify findings from a saved scan/taint report
- `/verify-finding srvsvc.dll --batch` -- verify all findings from the most recent scan workspace

The text after `/verify-finding` specifies the **module** and either a **function name** or a `--findings` path pointing to prior scan output.

## IMPORTANT: Execution Model

**This is an execute-immediately command. Do NOT present anything for user confirmation.** Run and write the final verification verdicts straight to the chat as your response. The user expects to see the completed output.

## When to Use

- After `/scan`, `/memory-scan`, `/logic-scan`, or `/taint` produces findings that need confirmation
- When a researcher says "is this bug real?" or "verify this finding"
- When a hunt plan (`/hunt-execute`) collects evidence that needs confidence scoring
- When triaging batch audit results to separate true positives from false positives

## When NOT to Use

- **Checking decompiler accuracy** -- use `/verify-decompiler` instead
- **Discovering new vulnerabilities** -- use `/scan`, `/memory-scan`, `/logic-scan`, or `/taint` first
- **Scoring exploitability of confirmed findings** -- use exploitability-assessment after verification
- **Understanding what a function does** -- use `/explain`

## Workspace Protocol

This command orchestrates multi-step verification:

1. Create `.agent/workspace/<module>_verify_finding_<timestamp>/`.
2. Store per-finding verification results in `<run_dir>/finding_<N>/results.json`.
3. Keep only verdicts and evidence summaries in context; read full trace data on demand.
4. Use `<run_dir>/manifest.json` to track verification progress.

## Execution Context

> **IMPORTANT**: Any inline Python that imports `helpers.*` must run with `cd <workspace>/.agent`
> (so the `.agent/` directory is on `sys.path`), **not** from the workspace root.
> Script invocations like `python .agent/skills/.../script.py` can be run from the workspace root
> because those scripts manage their own path setup.

## Steps

### Step 0: Preflight Validation

Validate arguments using `helpers.command_validation.validate_command_args("verify-finding", {"module": "<module>"})`.
If validation fails, report the errors and stop. On success, use `result.resolved["db_path"]` for subsequent script calls.

1. **Resolve the module DB**

   ```bash
   python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py <module> --json
   ```

2. **Gather findings to verify**

   **If `--findings <path>` is provided**: Load the JSON findings from the specified file (output from `/scan`, `/memory-scan`, `/logic-scan`, or `/taint`).

   **If `--batch` is provided**: Scan `.agent/workspace/` for the most recent scan/taint workspace for the target module. Load findings from `results.json` files within that workspace.

   **If a function name is provided (no `--findings`)**: Run taint analysis and memory/logic scans on the function to generate findings to verify:

   ```bash
   python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> --function <name> --json
   python .agent/skills/memory-corruption-detector/scripts/scan_buffer_overflows.py <db_path> --function <name> --json
   python .agent/skills/logic-vulnerability-detector/scripts/scan_auth_bypass.py <db_path> --function <name> --json
   ```

   Collect all non-empty findings into a unified list.

> **Tip:** All skill scripts support `--json` for machine-readable output. Use `--json` when parsing script output programmatically.

### Step 1: Restate Each Claim (Gate 0)

For each finding, restate the vulnerability claim in precise terms. Half of false positives collapse at this step.

Document per finding:
- **Function**: By ID and module DB path
- **Claim**: The exact vulnerability allegation
- **Root cause**: The alleged defect in the decompiled code
- **Trigger**: How an attacker would reach this code path
- **Impact**: What happens if the bug is real
- **Bug class**: Memory corruption, logic bug, race condition, etc.

Discard findings where the claim cannot be coherently restated.

### Step 2: Route Each Finding

**Standard verification** -- use when ALL hold:
- Clear, specific vulnerability claim
- Single function (no cross-module interaction in bug path)
- Well-understood bug class (buffer overflow, integer overflow, missing check)

**Deep verification** -- use when ANY hold:
- Cross-module bug path (data flows through 2+ DLLs)
- Race conditions or TOCTOU in the trigger
- Logic bugs without a clear specification to verify against
- Standard verification was inconclusive

Default to Standard. Process all Standard-routed findings first, then Deep.

### Step 3: Standard Verification (per finding)

**Gate 1 -- Verify data flow**:

```bash
python .agent/skills/data-flow-tracer/scripts/forward_trace.py <db_path> --id <func_id> --json
```

Trace from attacker-controlled source to the dangerous sink. Every hop in the chain must exist in the actual code.

**Gate 2 -- Verify attacker control**:

```bash
python .agent/skills/callgraph-tracer/scripts/chain_analysis.py <db_path> --id <func_id> --depth 3 --json
```

Trace back to module entry points. Can the attacker actually reach this code path and control the relevant input?

**Gate 3 -- Devil's advocate**: Argue against the finding.
- What compensating controls exist along the path?
- What guards were identified by taint analysis? Are they bypassable?
- Could the "dangerous" operation be safe in this specific context?

**Gate 4 -- Render verdict**: TRUE POSITIVE or FALSE POSITIVE with evidence from Gates 1-3.

### Step 4: Deep Verification (per finding)

For cross-module or complex findings, delegate to the **verifier** subagent for fresh-eyes assembly comparison. The verifier operates with no prior context, preventing confirmation bias.

### Step 5: Check for Exploit Chains

After all individual findings are verified, check whether findings that individually failed may combine into an exploit chain.

## Mandatory Language

Use "does / is / will" in all verdicts. NEVER use "might / could / possibly / may / theoretically" in a verdict. Uncertainty belongs in evidence notes, not in the verdict itself.

## Output

Present the verification report in chat with:

**Per-finding verdicts:**
- Verdict: TRUE POSITIVE or FALSE POSITIVE
- Evidence summary: data flow confirmation, attacker control assessment, devil's advocate result
- Confidence: HIGH / MEDIUM / LOW with explanation

**Summary:**
- Total findings verified: N
- TRUE POSITIVES: X (with severity)
- FALSE POSITIVES: Y (with rejection reason)
- Exploit chains identified (if any)

**Recommended next steps:**
- `/audit <module> <function>` -- deep audit on confirmed TRUE POSITIVE findings
- `/verify-decompiler <module> <function>` -- check decompiler accuracy for functions with uncertain verdicts

Always save to `extracted_code/<module_folder>/reports/verify_finding_<function_or_batch>_<timestamp>.md` (using `YYYYMMDD_HHMM` for timestamp). Create the `reports/` directory if needed.

All saved files must include a provenance header: generation date, module name, DB path, findings source, and workspace run directory path.

## Error Handling

- **Module not found**: List available modules via `find_module_db.py --list` and ask the user to choose
- **Function not found**: Run a fuzzy search and suggest close matches
- **No findings to verify**: If no scanner output exists and no findings were generated, suggest running `/scan <module>` or `/taint <module> <function>` first
- **DB access failure**: Report the error with the DB path and suggest running `/health`
- **Missing assembly code**: Cannot compare finding against assembly ground truth; note the gap and continue at reduced confidence
- **Cross-module tracking DB unavailable**: Scope verification to single module and note the limitation
- **Partial verification failure**: Report successful verdicts and list which findings could not be verified and why
