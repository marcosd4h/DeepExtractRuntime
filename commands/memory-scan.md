# Memory Scan

## Overview

Scan a module for memory corruption vulnerabilities: buffer overflows,
integer overflow/truncation, use-after-free, double-free, and format
string bugs. Runs four parallel scanners, merges and verifies findings,
then presents a prioritized report.

Usage:
- `/memory-scan <module>`
- `/memory-scan <module> <function>`
- `/memory-scan <module> --top 20`

## IMPORTANT: Execution Model

This command executes immediately. Run the full pipeline and deliver
the completed report without pausing for confirmation.

## Steps

### Step 0: Preflight Validation

Validate arguments using `helpers.command_validation.validate_command_args("memory-scan", {"module": "<module>"})`.
If validation fails, report the errors and stop. On success, use `result.resolved["db_path"]` for subsequent script calls.

1. **Resolve module DB**
   Use `find_module_db.py` to resolve the module name to a database path.
   If not found, list available modules and ask user.

2. **Single-function mode** (if function specified)
   Run all four scanners with `--id <fid>`, merge results, verify, present.
   Skip to step 5.

3. **Run scanners** (module-wide, parallel)
   Run these four scripts in parallel, all with `--json`:

   ```bash
   python .agent/skills/memory-corruption-detector/scripts/scan_buffer_overflows.py <db_path> --json
   python .agent/skills/memory-corruption-detector/scripts/scan_integer_issues.py <db_path> --json
   python .agent/skills/memory-corruption-detector/scripts/scan_use_after_free.py <db_path> --json
   python .agent/skills/memory-corruption-detector/scripts/scan_format_strings.py <db_path> --json
   ```

4. **Merge and deduplicate**
   Combine findings from all scanners. Deduplicate by (function_name, category).
   Keep the higher-scoring finding when duplicates exist.

5. **Verify findings**
   Write merged findings to a workspace file, then verify:

   ```bash
   python .agent/skills/memory-corruption-detector/scripts/verify_findings.py \
       --findings <merged.json> --db-path <db_path> --json
   ```

   Apply verification adjustments: FALSE_POSITIVE findings are removed,
   UNCERTAIN findings get a 50% score reduction.

6. **Present results**
   Format as a report with:
   - Module identity and security features
   - Summary: total findings by category and severity
   - Top findings table: rank, severity, function, category, API, score, confidence
   - For each top finding: evidence lines, path, guards, verification notes
   - Recommended next steps: `/audit` for CRITICAL/HIGH findings, `/taint` for deeper flow analysis

## Error Handling

| Failure | Recovery |
|---------|----------|
| Module not found | List available modules, ask user |
| Function not found | Fuzzy search, suggest matches |
| Scanner script fails | Report error, continue with results from other scanners |
| No findings | Report "no memory corruption patterns detected" as a valid result |
| Verification fails | Present unverified findings with note |

## Output

Present a structured report with these sections:

### Header
Module name, binary name, function count, security features (ASLR, DEP, CFG, canary).

### Summary Table
Category counts and severity distribution.

### Findings (top N, default 10)
For each finding:
- Severity and confidence
- Function name and ID
- Category and dangerous API
- Evidence: relevant code lines
- Guards on path (if any)
- Verification notes

### Recommended Next Steps
Suggest 3-5 concrete follow-up commands for the most interesting findings.
