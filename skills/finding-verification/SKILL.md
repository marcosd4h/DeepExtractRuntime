---
name: finding-verification
description: >-
  Systematically verify suspected vulnerabilities in IDA Pro decompiled
  binaries to eliminate false positives, producing TRUE POSITIVE or FALSE
  POSITIVE verdicts with evidence grounded in assembly truth. Use when
  the user asks to verify a finding, check if a bug is real, confirm a
  taint result, validate a suspected vulnerability, determine if a
  finding is a false positive, or needs to triage findings from
  memory-corruption-detector, logic-vulnerability-detector, or
  taint-analysis before reporting.
depends_on: ["taint-analysis", "verify-decompiled", "data-flow-tracer", "security-dossier", "exploitability-assessment", "import-export-resolver"]
---

# Finding Verification

## Purpose

Bridge the gap between "the scanner flagged this" and "this is a real
vulnerability." Taint analysis, memory corruption detection, and logic
scanners all produce findings against Hex-Rays decompiled output -- an
approximation of the actual binary. This skill provides a structured
verification workflow that forces the agent to prove each finding against
assembly ground truth before accepting or rejecting it.

The skill does not discover vulnerabilities. It verifies findings already
produced by other skills and produces a verdict (TRUE POSITIVE or FALSE
POSITIVE) with documented evidence for each.

## When to Use

- After `taint-analysis` produces findings that need confirmation
- After `memory-corruption-detector` or `logic-vulnerability-detector` flags issues
- When a researcher says "is this bug real?" or "verify this finding"
- When batch-auditing (`/batch-audit`) produces many findings that need triage
- When `/hunt-execute` collects evidence and needs to score confidence

## When NOT to Use

- Discovering where tainted data flows -- use **taint-analysis** first
- Scoring exploitability of confirmed findings -- use **exploitability-assessment**
- Planning a vulnerability research campaign -- use **adversarial-reasoning**
- Understanding what a function does -- use **re-analyst** or `/explain`
- Building general security context -- use **security-dossier**

## Rationalizations to Reject

| Rationalization | Why It's Wrong | Required Action |
|-----------------|----------------|-----------------|
| "The decompiled code looks dangerous" | Hex-Rays output is an approximation; phantom bugs arise from type recovery errors, optimized-away branches, and decompiler artifacts | Verify against assembly via `verify-decompiled` before concluding |
| "The taint path reaches a dangerous sink" | Taint analysis has false positives from unresolved indirect calls and missing cross-module context | Verify the path exists in assembly; check every hop |
| "Similar code was vulnerable elsewhere" | Each binary context has different callers, mitigations, and guard functions | Verify this specific instance independently |
| "Skipping verification for efficiency" | Every finding gets full verification through all gates | Return to the gate checklist and complete every step |
| "Pattern recognition confirms it" | Matching a known-bad pattern is a hypothesis, not a proof | Complete data flow tracing via `data-flow-tracer` before any conclusion |
| "This is clearly critical" | LLMs are biased toward seeing bugs and overrating severity | Complete devil's advocate review; prove it with evidence |

## Data Sources

Findings to verify come from other skills' JSON output:
- `taint-analysis`: `taint_function.py --json` output (findings, guards, scores)
- `memory-corruption-detector`: `scan_*.py --json` output
- `logic-vulnerability-detector`: `scan_*.py --json` output
- `exploitability-assessment`: `assess_finding.py --json` output (for context)
- `security-dossier`: `build_dossier.py --json` output (for reachability)

### Finding a Module DB

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py --list
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py <module>
```

## Mandatory Language

Use "does / is / will" in all verdicts.
NEVER use "might / could / possibly / may / theoretically" in a verdict.
Uncertainty belongs in evidence notes, not in the verdict itself.

## Workflow

### Step 0: Restate the Claim

Before any analysis, restate the finding in precise terms. Half of false
positives collapse at this step.

Document:
- **Function**: By ID and module DB path (use `--id` in subsequent calls)
- **Claim**: The exact vulnerability allegation
- **Root cause**: The alleged defect in the decompiled code
- **Trigger**: How an attacker would reach this code path
- **Impact**: What happens if the bug is real
- **Bug class**: Memory corruption, logic bug, race condition, etc.

If you cannot restate the claim clearly, ask the user for clarification.

### Route: Standard vs Deep

**Standard verification** -- use when ALL hold:
- Clear, specific vulnerability claim
- Single function (no cross-module interaction in bug path)
- Well-understood bug class (buffer overflow, integer overflow, missing check)

**Deep verification** -- use when ANY hold:
- Cross-module bug path (data flows through 2+ DLLs)
- Race conditions or TOCTOU in the trigger
- Logic bugs without a clear specification to verify against
- Standard verification was inconclusive

Default to Standard. It has built-in escalation to Deep when complexity
exceeds the linear checklist.

### Standard Verification

Verification Progress:
- [ ] Step 1: Check decompiler accuracy
- [ ] Step 2: Verify data flow
- [ ] Step 3: Verify attacker control
- [ ] Step 4: Devil's advocate review
- [ ] Step 5: Render verdict

**Step 1**: Check decompiler accuracy for the target function.

```bash
python .agent/skills/verify-decompiled/scripts/verify_function.py <db_path> --id <func_id> --json
```

If the verification reveals decompiler artifacts affecting the finding
(sign extension errors, missing branches, wrong types), the finding may
be a phantom. Check assembly at the specific location.

**Step 2**: Verify the data flow path exists.

```bash
python .agent/skills/data-flow-tracer/scripts/forward_trace.py <db_path> --id <func_id> --json
```

Trace from attacker-controlled source to the dangerous sink. Every hop
in the chain must exist in the actual code.

**Step 3**: Verify attacker control of the relevant parameter.

```bash
python .agent/skills/callgraph-tracer/scripts/chain_analysis.py <db_path> --id <func_id> --depth 3 --json
```

Trace back to module entry points. Can the attacker actually reach this
code path and control the relevant input?

**Step 4**: Devil's advocate -- argue against the finding.
- What compensating controls exist along the path?
- What guards were identified by taint analysis? Are they bypassable?
- Could the "dangerous" operation be safe in this specific context?

**Step 5**: Render verdict as TRUE POSITIVE or FALSE POSITIVE with
evidence from Steps 1-4.

### Deep Verification

For cross-module or complex findings, delegate to the `verifier` subagent
for fresh-eyes assembly comparison. The verifier operates with no prior
context (per the agent authoring guide Section 7.3), preventing
confirmation bias.

### Batch Triage

When verifying multiple findings at once:

1. Run Step 0 for all findings first -- restating each claim collapses obvious FPs
2. Route each finding independently (some Standard, some Deep)
3. Process all Standard-routed findings first, then Deep
4. After all verified, check for **exploit chains** -- findings that individually failed may combine

## Scope Exclusions

- Does not discover new vulnerabilities (use taint-analysis, memory-corruption-detector, logic-vulnerability-detector)
- Does not assess exploitability of confirmed findings (use exploitability-assessment)
- Does not analyze library boilerplate (WIL, STL, WRL, CRT) unless a finding specifically targets it

## Degradation Paths

1. **Assembly data missing for the function**: Cannot complete Step 1. Report "decompiler accuracy unverifiable" and note the gap. Continue with Steps 2-4 at reduced confidence.
2. **Cross-module tracking DB unavailable**: Cannot verify cross-DLL paths. Scope verification to single module and note the limitation.
3. **Upstream skill output missing**: If taint/scanner JSON is unavailable, ask the user to run the relevant skill first.

## Prompt Patterns

### Pattern A: Verify a single finding

> "Is this taint finding real?" / "Verify this buffer overflow"

1. Get the finding details (function, claim, evidence)
2. Follow Standard Verification (Steps 0-5)
3. Present verdict with evidence

### Pattern B: Triage batch findings

> "Verify all findings from the memory scan"

1. Collect all findings from the scan output
2. Run Step 0 for each, collapse obvious FPs
3. Route and verify remaining findings
4. Present summary: X TRUE POSITIVES, Y FALSE POSITIVES

## Integration with Other Skills

| Task | Skill |
|------|-------|
| Generate findings to verify | taint-analysis, memory-corruption-detector, logic-vulnerability-detector |
| Check decompiler accuracy | verify-decompiled |
| Trace data flow paths | data-flow-tracer |
| Trace back to entry points | callgraph-tracer |
| Check cross-module boundaries | import-export-resolver |
| Score confirmed findings | exploitability-assessment |
| Build security context | security-dossier |

## Performance

| Operation | Typical Time | Notes |
|-----------|-------------|-------|
| Step 0 restatement | ~5s | Agent reasoning, no scripts |
| Standard verification (single finding) | ~30-60s | 3-4 script calls + reasoning |
| Deep verification (single finding) | ~2-3 min | Includes verifier subagent |
| Batch triage (10 findings) | ~5-10 min | Step 0 collapses ~30% as FPs |

## Additional Resources

- [reference.md](reference.md) -- Gate review details, false positive patterns, bug-class requirements, evidence templates
- [verify-decompiled SKILL.md](../verify-decompiled/SKILL.md) -- Assembly ground truth verification
- [taint-analysis SKILL.md](../taint-analysis/SKILL.md) -- Taint finding format
- [exploitability-assessment SKILL.md](../exploitability-assessment/SKILL.md) -- Post-verification scoring
