# Command Authoring Guide

This guide describes how to define new slash commands for the DeepExtractIDA
Agent Analysis Runtime. In an installed workspace, commands live under
`.agent/commands/` inside a `DeepExtractIDA_output_root`, while extraction data
remains at workspace root in `extracted_code/` and `extracted_dbs/`.

It covers the structural requirements for command files (sections 1-3) and the
engineering practices for building reliable, consistent command behavior (sections 4-18).

## Directory Structure

Commands are defined as Markdown files in `.agent/commands/`:

```
<DeepExtractIDA_output_root>/
├── extracted_code/
├── extracted_dbs/
├── .agent/
│   ├── commands/
│   │   ├── registry.json   # Machine-readable command contracts
│   │   ├── README.md       # Command catalog
│   │   └── my-command.md   # Command definition and workflow
│   ├── helpers/
│   └── tests/
└── hooks.json
```

In this source repository, those installed files live at repository-root
`commands/`, `helpers/`, and `tests/`. The guidance below uses the installed
workspace paths because that is how the runtime is consumed inside a real
DeepExtractIDA output root.

## 1. Command Definition (`.md`)

A command file should follow a standard structure to ensure consistency and clarity.

### Header
Use a clear, descriptive title.

### Overview
Explain what the command does and provide usage examples.

```markdown
# My Command

## Overview
Brief description of the command's purpose.

Usage:
- `/my-command <module> <target>`
```

### Steps
Provide a step-by-step guide for the agent to execute the command.

1. **Resolution**: How to find the target module or function.
2. **Execution**: Which skills or scripts to run, including specific CLI flags.
3. **Synthesis**: How to combine results from multiple steps into a final report.

### Output
Describe what the final response to the user should look like.

## 2. Registry Registration

Add an entry to `.agent/commands/registry.json` with:

- `purpose`: Brief description of the command
- `file`: The `.md` filename (e.g., `my-command.md`)
- `skills_used`: Array of skill names this command orchestrates
- `agents_used`: Array of agent names this command delegates to (empty array if none)
- `parameters`: Human-readable parameter pattern (e.g., `<module> <function>`)
- `grind_loop`: Boolean -- `true` if the command creates a session-scoped scratchpad
- `workspace_protocol`: Boolean -- `true` if the command creates a workspace run directory

The infrastructure test suite validates that every command `.md` file is
registered and every registered file exists on disk. `skills_used` and
`agents_used` are cross-checked against their respective registries.

## 3. Integration with Framework

### Workspace Pattern
If the command involves multiple steps or large data payloads, it **must**
follow the Workspace Pattern:
- Create a run directory under `.agent/workspace/`.
- Pass `--workspace-dir` and `--workspace-step` to all skill scripts.
- Use the run manifest to track progress.

Command definitions live under `.agent/commands/`, but their inputs and outputs
usually live outside `.agent/`:

- Inputs: `extracted_dbs/`, `extracted_code/`, `extraction_report.json`
- Runtime artifacts: `.agent/workspace/`, `.agent/cache/`, `.agent/hooks/`
- Saved reports: typically `extracted_code/<module>/reports/`

### Grind Loop Protocol
For commands that process multiple discrete items (e.g., a list of functions), use the **Grind Loop Protocol**:
- Create a session-scoped scratchpad at `.agent/hooks/scratchpads/{session_id}.md`.
- List items to be processed.
- The framework will automatically re-invoke the agent until all items are checked.

### Preflight Validation

Every command should validate its arguments before invoking skill scripts. Use
the `command_validation` helper to catch bad input early with clear error
messages:

```python
from helpers.command_validation import validate_command_args

result = validate_command_args("triage", {"module": "appinfo.dll"})
if not result.ok:
    for err in result.errors:
        print(err)
    # Stop -- do not proceed to skill scripts
```

For commands that accept a module and/or function argument, this resolves the
DB path and function ID upfront, making them available in `result.resolved`.
The `_COMMAND_REQUIREMENTS` dict in `helpers/command_validation.py` defines
what each command requires; new commands should add their entry there.

In the command `.md` file, add this as the first step:

```markdown
### Step 0: Preflight Validation

Validate arguments using `helpers.command_validation.validate_command_args("<command_name>", {...})`.
If validation fails, report the errors to the user and stop. On success, use
`result.resolved["db_path"]` (and `result.resolved["function_id"]` if applicable)
for all subsequent skill script calls.
```

### Skills-First Execution

Both the main agent and any subagents it spawns should **always prefer existing
skill scripts over ad-hoc inline logic**. Skills encode tested workflows,
use the helpers library correctly, and produce consistent output formats.

- **Use skill scripts for any operation a skill covers.** Don't write inline
  Python to classify functions when `classify_function.py` exists. Don't
  hand-roll call graph traversal when `chain_analysis.py` does it.
- **Subagents must follow skills too.** When delegating to a subagent, instruct
  it to read the relevant SKILL.md and use the skill's scripts. Don't re-explain
  the workflow in the subagent prompt when a skill already documents it.
- **Read the SKILL.md before invoking scripts.** Skills define argument
  conventions, output formats, and edge-case handling. Skipping the skill and
  calling scripts directly risks missing flags, misinterpreting output, or
  hitting undocumented preconditions.
- **Fall back to helpers only when no skill covers the operation.** For one-off
  operations not covered by any skill, use the helpers library directly
  (see section 3.3). Never write raw SQL, manual path resolution, or ad-hoc
  API classification.

For how skills work and how to author new ones, see
[skill_authoring_guide.md](skill_authoring_guide.md).

---

## 3.1 Testing Requirements

Every new or modified command must be validated by the automated test suite.

**Mandatory checks after any command change:**

1. **Run the full infrastructure suite**:
   `cd <DeepExtractIDA_output_root>/.agent && python -m pytest tests/test_infrastructure_consistency.py -v`.
   This validates that `registry.json` entries match `.md` files on disk, that
   `skills_used` and `agents_used` reference registered entities, and that the
   command README listings are consistent.

2. **Add integration tests** when a command wires in new skills or agents.
   Create or update a test file in `.agent/tests/` that verifies:
   - The command's `skills_used` in `registry.json` lists the expected skills
   - The command's `.md` file references the skill scripts by name
   - Negative checks: unrelated commands do not gain the new dependency

3. **Run the full test suite** before considering the change complete:
   `cd <DeepExtractIDA_output_root>/.agent && python -m pytest tests/ -v`.
   A green suite across all test files is the minimum bar.

**Test file convention**: Integration tests that validate how a skill is wired across multiple commands/agents belong in `test_<skill>_integration.py`. Command-specific functional tests belong in `test_<command_name>.py`.

---

## Best Practices

The following sections (4-18) are generic engineering practices for building
reliable, consistent, and maintainable slash commands. They apply to any
multi-step command in the runtime.

## 4. Python Execution Context

### 4.1 Always run `helpers.*` imports from `.agent/`

The `helpers` package lives at `.agent/helpers/` and is **not** installed as a system package.
Any Python code that does `from helpers.X import Y` must be run with `.agent/` as the working
directory (or on `sys.path`).

**Correct pattern for inline Python snippets:**

```bash
cd <DeepExtractIDA_output_root>/.agent && python -c "
from helpers.validation import validate_workspace_data
status = validate_workspace_data('..')
...
"
```

**Correct pattern for skill scripts** (they manage their own path setup, so run from workspace root):

```bash
python .agent/skills/<skill>/scripts/<script>.py --db extracted_dbs/foo.db
```

Running inline `helpers.*` imports from the workspace root will always produce
`ModuleNotFoundError: No module named 'helpers'`.

### 4.2 Pass `..` as workspace root in inline snippets

When running from `.agent/`, the DeepExtractIDA output root is one level up:
`..`.
Pass `..` to any helper that accepts a workspace root parameter (e.g., `validate_workspace_data('..')`).

### 4.3 Use helpers, don't reimplement

When commands need inline logic, always use the `.agent/helpers/` library. Never
write raw SQLite queries, hand-parse function names, roll custom path resolution,
or build ad-hoc API classification. Common violations:

- Raw `SELECT * FROM functions` instead of `open_individual_analysis_db()` + `resolve_function()`
- Manual string splitting on function names instead of `parse_class_from_mangled()`
- Custom path joining instead of `resolve_db_path()` / `resolve_tracking_db()`

Using helpers ensures consistency across commands, prevents subtle bugs from
divergent implementations, and lets every command benefit when a helper improves.

## 5. Workspace & Context Management

### 5.1 Use filesystem handoff, not inline payloads

Create a run directory under `.agent/workspace/` for any command that invokes two
or more skill scripts. Write full payloads to disk; pass only compact summaries
through coordinator context.

```
.agent/workspace/<module>_<goal>_<timestamp>/
├── manifest.json
├── step_a/
│   ├── results.json    # full payload
│   └── summary.json    # compact summary
└── step_b/
    ├── results.json
    └── summary.json
```

**Why**: Large JSON payloads in context degrade agent reasoning quality and
hit token limits. Filesystem handoff keeps context lean while preserving
full data for on-demand access.

### 5.2 Treat the manifest as source of truth

Use `manifest.json` to track which steps have completed, which failed, and
where their outputs live. Never rely on implicit state or agent memory to
determine pipeline progress.

### 5.3 Pass workspace args to every step

Always invoke skill scripts with `--workspace-dir <run_dir>` and
`--workspace-step <step_name>` so each step knows where to write and how
to label itself in the manifest.

### 5.4 Load full results only on demand

Read `results.json` only when you need the data for synthesis, ranking, or
a targeted follow-up. Default to reading `summary.json` for decision-making.

## 6. Entity Resolution

### 6.1 Prefer IDs over names after initial resolution

Once a function, module, or entity is resolved, use its unique identifier
(e.g., `--id <function_id>`) in all subsequent invocations. IDs are unambiguous
and avoid re-resolution edge cases like overloaded names or partial matches.

### 6.2 Use a layered resolution strategy

1. **Quick lookup** first (cheapest, most common case)
2. **Cross-dimensional search** second (when the term might match strings, APIs, or classes)
3. **Skill-based fallback** third (when the above miss)

Don't jump to expensive search when a simple index lookup suffices.

### 6.3 Flag library vs. application code

Check whether a resolved entity is library boilerplate (WIL, CRT, STL, WRL, ETW).
Surface this to the user or adjust priority accordingly -- library code is almost
always lower-priority than application code for analysis.

### 6.4 Prompt for missing required arguments

If a command requires a target (function, module, class) and the user didn't
provide one, ask explicitly. Don't guess or pick a default silently.

### 6.5 Validate arguments before passing to scripts

Don't just check that arguments exist -- validate their format and consistency
before invoking skill scripts. Catch bad input at the command level rather than
letting it propagate into cryptic script errors downstream.

- Verify IDs are numeric with `validate_function_id()`
- Verify paths resolve with `resolve_db_path()`
- Check mutually exclusive options aren't both set
- Reject out-of-range values (e.g., negative depth) early

## 7. Machine-Readable Output

### 7.1 Always pass `--json` when parsing programmatically

All skill scripts support `--json`. When the coordinator or a subagent will
parse the output, always use it. Never parse human-formatted tables in automation.

### 7.2 Separate stdout and stderr

- **stdout**: Data only (JSON when `--json`, tables/text otherwise)
- **stderr**: Progress messages, warnings, structured errors

This enables reliable piping and programmatic consumption.

## 8. Parallelism

### 8.1 Run independent steps concurrently

If steps have no data dependencies between them, launch them in parallel.
Explicitly document which steps are independent in the command definition
so future maintainers preserve the parallelism.

### 8.2 Gate conditional steps on prior results

Don't run a step whose preconditions aren't met. Check the output of earlier
steps and skip gracefully when there's nothing to do. For example, a backward
trace is pointless if no dangerous APIs were found.

### 8.3 Document the dependency graph

State which steps depend on which. A simple grouping like "Run A + B + C in
parallel; D depends on A; E + F + G run in parallel after the first batch"
makes execution order unambiguous.

### 8.4 Know when to bypass caching

Skill scripts cache expensive results (TTL 24h, keyed by DB mtime). This means
first runs are slower than subsequent ones. Be aware of caching behavior when
designing commands:

- Pass `--no-cache` to force fresh analysis when the user suspects stale results
  or after the underlying DB has been regenerated
- If a command pipeline has long cold-start times, mention it in the command
  documentation so the user knows to expect it
- Don't cache results that depend on parameters beyond the DB path -- the cache
  key may not capture the full input space

## 9. Subagent Discipline

### 9.1 Use descriptive subagent names

Name subagents after the analysis step and target entity:

- Good: `"Build security dossier for AiCheckLockdown"`
- Good: `"Trace call chain from AiCheckLockdown"`
- Bad: `"Raw JSON content retrieval"`
- Bad: `"File read"`

Descriptive names make logs readable and debugging straightforward.

### 9.2 Match subagent type to the task

Use the most appropriate `subagent_type` for the work:

- `re-analyst` for explanation tasks and classification enrichment
- `security-auditor` for security finding verification and severity validation
- `verifier` for lifted-code verification against assembly
- `code-lifter` for batch lifting with shared context
- `triage-coordinator` scripts for triage and multi-skill orchestration
- `type-reconstructor` scripts for struct/class reconstruction

Don't route everything through `generalPurpose` when a specialized agent
exists. In particular, use `security-auditor` (not `re-analyst`) for
skeptical verification of security findings -- it has adversarial reasoning
guidance, severity criteria, and a "rationalizations to reject" table.

### 9.3 Use readonly mode for validation subagents

When a subagent's job is to verify, review, or validate work done by an earlier
step, launch it with `readonly: true`. Validation tasks should never modify
outputs -- they only read data and return a judgment.

## 10. Data Interpretation

### 10.1 Document scales and units for every numeric field

Different fields use different scales. Misinterpreting a 0-100 percentage as
a 0-1 fraction (or vice versa) produces wrong conclusions. Always state the
scale alongside any metric you define or consume.

Examples of common pitfalls:

| Field                | Scale    | Trap                              |
|----------------------|----------|-----------------------------------|
| `canary_coverage_pct`| 0-100    | `0.2` = 0.2%, not 20%            |
| `param_risk_score`   | 0.0-1.0  | `0.7` = 70th percentile risk     |
| `noise_ratio`        | 0.0-1.0  | `0.48` = 48% library boilerplate |
| `attack_score`       | 0.0-1.0  | Higher = more attractive target  |

### 10.2 Show human-readable interpretation alongside raw values

When citing any metric in output, include both the raw number and its
interpretation. Never present a bare `0.2` without clarifying whether it
means 0.2% or 20%.

### 10.3 Treat empty results as data points

An empty or negative result from a tool is still information. If a function
is not detected as an entry point, that itself is a data point (internal-only
function). If a search returns no matches, record that explicitly rather than
silently omitting the section. Empty results prevent false conclusions later.

## 11. Report Structure & Consistency

### 11.1 Define a fixed template

Every command that produces a report should define an exact section structure
with heading levels, table schemas, and formatting rules. Don't leave layout
to improvisation -- consistency across runs makes reports comparable.

### 11.2 Use the right visualization for the data shape

| Data Shape                | Format                        |
|---------------------------|-------------------------------|
| Key-value metadata        | Two-column table              |
| Hierarchical relationships| ASCII tree                    |
| Multi-attribute rankings  | Multi-column table            |
| Ordered findings          | Numbered list with prefixes   |
| Code flow                 | Fenced code block             |

### 11.3 Preserve original data fidelity

Use raw signatures, names, and values from the database. Don't reconstruct,
rename, or "improve" data in a reporting context -- that belongs in a
separate transformation step (like lifting).

## 12. Scoring & Assessment Rigor

*Applies to commands that produce scored assessments or rankings (e.g., `/audit`,
`/triage`, `/full-report`). Commands that only retrieve or display data can skip
this section.*

### 12.1 Make scoring data-driven, not improvised

Every score or rating must trace back to explicit data sources, named fields,
and concrete thresholds. If a human can't reproduce the same score from the
same data, the rubric is too vague.

### 12.2 Define explicit thresholds per level

For each scoring dimension, list:
- **Data sources**: Which fields feed into this dimension
- **Inputs**: The specific values extracted from those sources
- **Thresholds**: Concrete cutoffs for each level (e.g., `>= 500` instructions = HIGH)

### 12.3 Handle tool false negatives with documented overrides

Automated tools can underreport. When heuristics or manual evidence contradict
a tool's output, apply an explicit override:
1. For categorical fields (e.g., entity type), set to the heuristic-confirmed value
2. For numeric fields (e.g., risk scores), treat the tool's value as unknown --
   don't use a wrong zero in scoring formulas as though it were a real measurement
3. Document the override and evidence in the confidence section

Never silently accept a tool's zero when independent evidence says otherwise.

### 12.4 Use deterministic aggregation formulas

When combining dimension scores into an overall assessment:
1. Start with the highest individual dimension score as baseline
2. Apply escalation rules (e.g., 3+ dimensions above a threshold)
3. Apply confidence adjustments
4. Cap at the maximum level

Write the formula out so it's reproducible.

## 13. Severity & Finding Assignment

*Applies to commands that report findings with severity levels (e.g., `/audit`,
`/verify`). Each command should define severity criteria appropriate to its domain.*

### 13.1 Define strict severity criteria

Each severity level needs a concrete, falsifiable definition tied to the
command's domain. Define what each level means in terms of observable evidence,
not subjective judgment. Example for security-focused commands:

| Level    | Definition                                                                  |
|----------|-----------------------------------------------------------------------------|
| CRITICAL | Confirmed data flow from untrusted source to dangerous sink, directly achievable |
| HIGH     | One additional precondition needed, or confirmed missing check in active path |
| MEDIUM   | Multiple preconditions, or defense-in-depth gap without confirmed exploit path |
| LOW      | Code quality concern without direct impact                                  |

Other domains will have different criteria (e.g., decompiler verification uses
accuracy confidence levels, not security severity).

### 13.2 Cite the source for every finding

Every concern, finding, or recommendation must reference the specific data
field it came from (e.g., `Source: dossier.dangerous_operations.security_relevant_callees`).
Unsourced claims erode trust in the report.

### 13.3 Use a mandatory checklist for baseline coverage

Define a fixed set of concern categories that every run must evaluate. For each,
explicitly state APPLIES (with severity and evidence) or DOES NOT APPLY (with
brief reason). This prevents inconsistent coverage across runs.

### 13.4 Don't speculate beyond the evidence

Severity should reflect what the data confirms, not what might theoretically
be possible. If compensating controls are unaudited, say "unknown" rather than
assuming they're absent.

## 14. Independent Verification

*Applies to commands that synthesize findings or assessments from multiple data
sources. Optional for commands that only retrieve or display raw data.*

### 14.1 Verify findings with fresh eyes

After synthesizing a report, launch a separate subagent to independently
validate findings and their assigned levels. The verifier should receive:
- The level/severity criteria (the rubric)
- The raw data (summaries, not the synthesis reasoning)
- The draft findings with assigned levels

The verifier has never seen the synthesis logic, which eliminates confirmation bias.

### 14.2 Handle corrections transparently

If the verifier adjusts a finding's level:
- Update the final report
- Note the adjustment in the confidence section (e.g., "Finding #3 adjusted
  from CRITICAL to HIGH by independent verification")
- Recompute any aggregated scores that depend on the adjusted value

### 14.3 Don't include verifier output verbatim

Apply corrections; don't dump the verifier's raw response into the report.

## 15. Recommended Next Steps

### 15.1 Use a deterministic ranking formula

Don't rely on ad-hoc judgment for "what to look at next." Define a ranking:
1. Collect candidate entities from the analysis results
2. Assign tiers based on category (highest-risk categories first)
3. Sort within tiers by a quantitative signal (e.g., reachable dangerous ops)
4. Output the top N

### 15.2 Bound the output

Cap recommendations at a fixed number (e.g., 5-7). An unbounded list is
not actionable.

### 15.3 Suggest concrete follow-up commands

End with a specific command the user can run next, not a vague instruction.
`/callgraph appinfo.dll AiLaunchProcess --depth 3` is better than
"consider tracing the call graph."

## 16. Output & Persistence

### 16.1 Save reports to disk

Always write a copy of the report to a predictable location:
`extracted_code/<module>/reports/<command>_<target>_<timestamp>.md`

Use `YYYYMMDD_HHMM` for timestamps. Create the `reports/` directory if needed.

### 16.2 Include provenance metadata in outputs

Reports and saved artifacts should include traceability information: generation
date, workspace run directory path, target entity identifiers, and which tool
versions produced the data. This enables reproducibility and lets users know
exactly what they're looking at.

### 16.3 Execute immediately when the command says so

If the command is marked execute-immediately, run the full pipeline and deliver
the completed report. Don't pause for confirmation mid-pipeline.

## 17. Error Handling

### 17.1 Define recovery actions per failure type

Every command should specify what to do for each common failure:

| Failure              | Recovery                                               |
|----------------------|--------------------------------------------------------|
| Module not found     | List available modules, ask user to choose             |
| Entity not found     | Fuzzy search, suggest close matches                    |
| DB access failure    | Report error with path, suggest `/health`              |
| Missing data         | Report what's missing, offer reduced-fidelity fallback |
| Skill script failure | Log error, continue with partial results               |

### 17.2 Prefer partial results over total failure

If one step in a multi-step pipeline fails, report what completed successfully
and clearly state what's missing. A partial report is almost always more useful
than an error message.

### 17.3 Never crash silently

Every error path should produce a visible, structured message explaining
what went wrong and what the user can do about it.

### 17.4 Build explicit degradation decision trees

Don't just say "degrade gracefully" -- document the specific fallback paths
for each data source that might be absent. Build a decision tree into the
command definition:

1. Analysis DB missing but `extracted_code/` exists? Fall back to
   `function_index.json` for function listing and `file_info.json` for
   module identity. Note which DB-dependent features are unavailable.
2. Tracking DB missing? Scope to single-module analysis. Report that
   cross-module resolution is unavailable.
3. Assembly data absent for a function? Skip assembly-dependent steps
   (verification, structural metrics) and note the gap.
4. Decompiled code absent? Offer assembly-only analysis where supported.

Each branch should produce a clear message about what's reduced and why.

## 18. Manual Observations

*Applies to commands where the agent reads code or data beyond what automated
scripts produce -- security audits, code reviews, explanations with deep dives.*

### 18.1 Cap and curate

Set a hard limit (e.g., max 3). Don't pad with low-value filler.

### 18.2 Require specific references

Every observation must reference a concrete line, variable, or code pattern.
Vague statements like "the error handling could be improved" are not useful.

### 18.3 Label the source

Mark observations as manual findings to distinguish them from automated tool
output. Use a consistent label like `"Manual review -- not from automated analysis"`.
This lets readers know which findings are reproducible by re-running scripts
and which depend on agent judgment.

### 18.4 Keep them isolated from scoring

Manual observations inform the reader but should not alter automated
dimension scores or aggregate risk levels.

### 18.5 Omit rather than pad

If nothing noteworthy exists beyond the automated findings, omit the section
entirely. An empty section with a "no observations" note adds noise.
