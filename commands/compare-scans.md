# Compare Scans

## Overview

Compare findings across AI vulnerability scan reports for the same module.
Identifies recurring findings, new findings, missed regressions, severity
changes, and verdict conflicts between scans.

Usage:

- `/compare-scans <module>` -- compare two most recent scan reports (any type)
- `/compare-scans <module> --type logic|memory|taint` -- filter by scan type
- `/compare-scans <module> --reports <path1> <path2>` -- compare specific reports

## IMPORTANT: Execution Model

This command executes immediately. Run the full comparison and deliver
results without pausing for confirmation.

## Status Messaging (MANDATORY)

Output a plain-text status message before each step starts and after it
completes. Messages are 1-2 lines summarizing what is happening.

## Step 0: Preflight Validation

```python
from helpers.command_validation import validate_command_args
result = validate_command_args("compare-scans", {
    "module": "<user_module>",
})
if not result.ok:
    # report errors and stop
```

Resolve the module reports directory at `extracted_code/<module>/reports/`.

## Step 1: Report Discovery

**Status (before):** Tell the user: `Discovering scan reports for <module>...`

Use `helpers.report_comparison.discover_reports(reports_dir, scan_type)` to find
`.findings.json` companion files. If `--type` is specified, filter by scan type.
If `--reports` is given, use those paths directly.

Require at least 2 reports. If only 1 exists, show its summary and stop.
If 0 exist, report "no structured scan reports found" and suggest running
`/ai-logical-bug-scan`, `/memory-scan`, or `/taint` first.

**Status (after):** Tell the user how many reports were found and which two will be compared.

## Step 2: Load Reports

**Status (before):** Tell the user: `Loading report data...`

Use `helpers.report_comparison.load_findings_json()` for both reports.
Present brief identity: timestamp, entry point, scan type, finding counts
(TP count, FP count).

**Status (after):** Tell the user the identity of both reports.

## Step 3: Compare

**Status (before):** Tell the user: `Comparing findings...`

Use `helpers.report_comparison.compare_findings(current, previous)`.

**Status (after):** Summarize: N recurring, N new, N missed, N severity changes, N verdict conflicts.

## Step 4: Present Results

**Status (before):** Tell the user: `Writing comparison report...`

1. Use `helpers.report_comparison.format_comparison_section()` to generate markdown
2. Save comparison report to `extracted_code/<module>/reports/scan_comparison_<YYYYMMDD_HHMM>.md`
3. Present the comparison to the user with:
   - Report header with both report identities
   - Recurring findings with any changes (severity, verdict, remediation)
   - New findings with full details (title, severity, description excerpt)
   - Missed findings with full details from previous report
   - Verdict conflicts with both skeptic reasoning summaries
   - Coverage delta (functions analyzed in one but not the other)

## Output

Save the comparison report as:

```
extracted_code/<module>/reports/scan_comparison_<YYYYMMDD_HHMM>.md
```

Include provenance: both report paths, timestamps, module, scan type filter.

## Error Handling

| Scenario | Behavior |
|---|---|
| Module not found | Report error, suggest available modules |
| No `.findings.json` files found | Report "no structured scan reports found", suggest running a scanner first |
| Only 1 report found | Show its summary, report "nothing to compare" |
| `--reports` path does not exist | Report error with the bad path |
| Malformed `.findings.json` | Report parse error, skip that file, try next most recent |

## Degradation Paths

| Condition | Behavior |
|---|---|
| Previous report has `.md` but no `.findings.json` companion | Report "legacy report without structured companion; cannot compare programmatically" |
| Mixed scan types in reports dir | Default compares most recent pair regardless of type; `--type` filters |
| Entry points differ between scans | Proceed with comparison, note differing entry points in output header |
