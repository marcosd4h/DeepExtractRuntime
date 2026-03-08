# finding-verification

Structured false-positive elimination for security findings in IDA Pro
decompiled binaries. Verifies findings from taint-analysis,
memory-corruption-detector, and logic-vulnerability-detector against
assembly ground truth.

## When to Use

- After automated scanners produce findings that need confirmation
- When a researcher asks "is this bug real?"
- When triaging batch audit results before reporting

## How It Works

The skill provides a gate-based verification workflow:

1. **Restate** the finding in precise terms (collapses ~30% of FPs)
2. **Route** to Standard (single function, clear bug class) or Deep
   (cross-module, race conditions, inconclusive)
3. **Verify** through 5 mandatory gates: assembly truth, data flow,
   attacker control, cross-module boundary, devil's advocate
4. **Verdict**: TRUE POSITIVE or FALSE POSITIVE with evidence

## Integration

This is a methodology skill with no scripts. It directs the agent to
use existing skills:

| Gate | Primary Skill |
|------|---------------|
| Assembly ground truth | verify-decompiled |
| Data flow | data-flow-tracer |
| Attacker control | callgraph-tracer |
| Cross-module boundary | import-export-resolver |
| Devil's advocate | (agent reasoning) |

## Usage in Commands

Wired into `/audit` and `/hunt-execute` for finding verification during
security assessment workflows.

## Files

| File | Purpose |
|------|---------|
| `SKILL.md` | Full verification methodology and workflow |
| `reference.md` | Gate details, FP patterns, bug-class requirements, evidence templates |
| `README.md` | This file |

## Related Skills

- [taint-analysis](../taint-analysis/) -- produces findings to verify
- [verify-decompiled](../verify-decompiled/) -- assembly ground truth
- [exploitability-assessment](../exploitability-assessment/) -- scores confirmed findings
- [adversarial-reasoning](../adversarial-reasoning/) -- hypothesis-driven research planning
