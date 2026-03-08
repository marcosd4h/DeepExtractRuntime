# Testing Guide -- Agent Prompts

Copy-paste prompts for agent-driven test execution and remediation.
Each prompt is self-contained: paste it into a new agent session as-is.

See `.agent/docs/testing_guide.md` for the full QA plan, test architecture,
runner docs, and test case definitions.

---

## Phase 1: Run and Capture

**Goal**: Execute the full test suite (unit + integration) and capture all
failures, warnings, and misbehavior. Do not fix anything.

```text
Run all test cases from the testing guide at @.agent/docs/testing_guide.md.
Read the entire plan before proceeding.

Run BOTH test tiers and capture output into @work/testcase_output:

1. Unit tests (Tier 1):
   python -m pytest .agent/tests/ -v --tb=short
   Save the full output to pytest_output.log in the output directory.

2. Integration tests (Tier 2):
   python .agent/helpers/qa_runner.py --output-dir work/testcase_output
   This generates SUMMARY.json, SUMMARY.md, and per-test failure dirs.

Your goal is to run the test cases and capture every failing tool execution.
Do NOT attempt to fix anything -- just capture the output. Capture warnings
too when applicable. Capture empty or misbehaving steps too. Write a
FINDINGS.md in the output directory summarizing all failures, warnings,
timeouts, and behavioral deviations. These findings will be fixed by a
different agent in Phase 2.
```

---

## Phase 2: Investigate and Fix

**Goal**: Analyze every failure from Phase 1, determine root causes, plan
and apply fixes, then re-run to verify.

```text
Investigate in detail every failure and behavioral deviation captured in
@work/testcase_output. Read FINDINGS.md, SUMMARY.json, pytest_output.log,
and all per-test failure directories.

For each finding:
- Understand the root cause by reading the relevant source code.
- Determine whether the same issue could affect other commands, skills,
  or sub-agents beyond the failing test.
- Plan a fix that prevents recurrence across all affected components.
- Apply the fix.

Update code, docs, and workspace rules where needed. After all fixes are
applied, re-run Phase 1 (both unit and integration tests) to verify the
suite is clean. Repeat until 0 failures and 0 warnings.
```

---

## Quick Reference: Manual Execution

Run both tiers without an agent:

```bash
# Tier 1: Unit tests
python -m pytest .agent/tests/ -v --tb=short 2>&1 | tee work/testcase_output/pytest_output.log

# Tier 2: Integration tests
python .agent/helpers/qa_runner.py --output-dir work/testcase_output
```

## Old prompts

### Execution

```text
I want you to run all the testcases from the QA plan here @.agent/docs/qa_test_plan.md and run the testcases. Read the entire plan before proceeding.

Your  goal is to run the testcases, and capture tool execution that is failing here @work/testcase_output . Don't attempt to fix anything, just capture the failing tool execution output. Capture warnings too when applicable. Capture empty or misbehaving steps too. These findings will be fixed by a different agent

```

### Fix findings

```text
I want you to investigate in detail and understand how to fix the all the failures. Get all the failures and behavioral deviations, understand them in detail, plan how to fix them. This should cover all faling testscaes. Also check if failures is something that might affect other commands, skills, subagents and make sure to add a fix so same issue does not happen on them. Update docs where needed. Update rules if needed to ensure fixes are applied.
```
