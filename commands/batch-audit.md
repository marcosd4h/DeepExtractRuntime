# Batch Audit

## Overview

Security audit multiple functions in parallel, targeting the top-ranked attack
surface entry points, module-scoped privilege-boundary handlers (RPC/COM/WinRT),
or a user-specified list. Produces a consolidated security report with
per-function audit summaries and cross-function patterns.

Usage:

- `/batch-audit appinfo.dll` -- audit top 5 entry points (default)
- `/batch-audit appinfo.dll --top 10` -- audit top 10 entry points
- `/batch-audit appinfo.dll --top 10 --min-score 0.4` -- only entry points with attack score >= 0.4
- `/batch-audit appinfo.dll --privilege-boundary` -- audit auto-discovered RPC/COM/WinRT handlers in the module
- `/batch-audit appinfo.dll --privilege-boundary --top 8` -- cap privilege-boundary auditing to the top 8 resolved handlers
- `/batch-audit appinfo.dll AiLaunchProcess AiCheckSecureApplicationDirectory AiCreateElevatedProcess` -- audit specific functions
- `/batch-audit appinfo.dll --class CSecurityDescriptor` -- audit all methods of a class

## IMPORTANT: Execution Model

**This is an execute-immediately command. Do NOT present anything for user confirmation.** Run and write the final batch audit report straight to the chat as your response. The user expects to see the completed report.

## Workspace Protocol

This command orchestrates N parallel audit workflows:

1. Create `.agent/workspace/<module>_batch_audit_<timestamp>/`.
2. Store per-function audit results in `<run_dir>/<function_name>/results.json`.
3. Keep only severity summaries and top findings in context.
4. Use `<run_dir>/manifest.json` to track which functions have been audited.

## Execution Context

> **IMPORTANT**: Any inline Python that imports `helpers.*` must run with `cd <workspace>/.agent`
> (so the `.agent/` directory is on `sys.path`), **not** from the workspace root.
> Script invocations like `python .agent/skills/.../script.py` can be run from the workspace root
> because those scripts manage their own path setup.

## Steps

### Step 0: Preflight Validation

Validate arguments using `helpers.command_validation.validate_command_args("batch-audit", {"module": "<module>"})`.
If validation fails, report the errors and stop. On success, use `result.resolved["db_path"]` for subsequent script calls.

If `--privilege-boundary` is present, treat it as mutually exclusive with:

- explicit function names
- `--class`

If the user combines them, report the invalid option mix and stop.

### 1. Resolve audit targets

> **Tip:** All skill scripts support `--json` for machine-readable output. Use `--json` when parsing script output programmatically.

**If specific functions are listed:**
- Resolve the module DB using `python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py <module>`.
- Resolve each function using `python .agent/skills/function-index/scripts/lookup_function.py <name> --json`.
- After resolving, use the returned `function_id` for all subsequent operations.

**If `--class` is specified:**
- Use `python .agent/skills/batch-lift/scripts/collect_functions.py <db_path> --class <name> --json` to collect all methods.

**If `--privilege-boundary` is specified:**
- This is a module-scoped discovery mode that composes the interface-analysis skills with the existing batch audit pipeline.
- Run the discovery steps below in parallel, then merge and deduplicate the candidate handler names.
- Ignore `--min-score` in this mode; it only applies to the default attack-surface ranking path.

**a. RPC privilege-boundary candidates**

```bash
python .agent/skills/rpc-interface-analysis/scripts/map_rpc_surface.py <module> --servers-only --json
```

- Keep server-side interfaces in `critical` or `high` risk tiers.
- Also keep interfaces that are remote-reachable or named-pipe reachable even if they fall below `high`.
- Harvest `procedure_names` from each retained interface as candidate handler names.

**b. COM privilege-boundary candidates**

```bash
python .agent/skills/com-interface-analysis/scripts/find_com_privesc.py --json
```

- Filter `targets` to servers whose `hosting_binary` matches the requested module (case-insensitive).
- Prefer `high_value_methods` as candidate handler names.
- If a retained server has no `high_value_methods`, fall back to the first 3 methods across its exposed interfaces.
- Carry forward the server `clsid`, `privesc_score`, and `risk_tier` for reporting context.

**c. WinRT privilege-boundary candidates**

```bash
python .agent/skills/winrt-interface-analysis/scripts/find_winrt_privesc.py --json
```

- Filter `targets` to servers whose `hosting_binary` matches the requested module (case-insensitive).
- Prefer `high_value_methods` as candidate handler names.
- If a retained server has no `high_value_methods`, fall back to the first 3 methods across its exposed interfaces.
- Carry forward the class name, `privesc_score`, and `risk_tier` for reporting context.

**d. Resolve candidate names to function IDs**
- Resolve each harvested candidate with `lookup_function.py` or `validate_function_arg`.
- For COM/WinRT methods, try the fully-qualified method name first, then retry with `short_name` if the full name does not resolve.
- Skip unresolved names and library-tagged methods (WIL/CRT/STL/WRL/ETW).
- Deduplicate by resolved `function_id`.

**e. Rank final privilege-boundary targets**
- Rank RPC candidates by interface risk tier first, then procedure count.
- Rank COM and WinRT candidates by `privesc_score`.
- Annotate each target with its discovery source: `RPC_HANDLER`, `COM_METHOD`, or `WINRT_METHOD`.
- If `--top` is specified, cap the final merged list to `N`.
- If `--top` is omitted in this mode, default to auditing the top 10 resolved privilege-boundary handlers.

**If `--top N` (default mode):**
- Run `python .agent/skills/map-attack-surface/scripts/rank_entrypoints.py <db_path> --top <N> --json` to get ranked entry points.
- Filter by `--min-score` if specified (default: 0.2).
- Skip library-tagged functions (WIL/CRT/STL/WRL/ETW).

### 2. Create grind-loop scratchpad

Create a session-scoped scratchpad at `.agent/hooks/scratchpads/{session_id}.md`:

```markdown
# Task: Batch Audit -- <module> (<N> functions)

## Items
- [ ] Function 1: <name> [<source>] (score: N)
- [ ] Function 2: <name> [<source>] (score: N)
...

## Status
IN_PROGRESS
```

### 3. Audit each function

For each target function, run a condensed audit pipeline:

**a. Build security dossier** (parallel across functions where possible):

```bash
python .agent/skills/security-dossier/scripts/build_dossier.py <db_path> --id <fid> --json
```

**b. Run taint analysis:**

```bash
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> --id <fid> --depth 2 --json
```

**c. Run exploitability assessment** (if taint found sinks):

```bash
python .agent/skills/exploitability-assessment/scripts/assess_finding.py \
    --taint-report <taint.json> --module-db <db_path> --json
```

**d. Classify function purpose:**

```bash
python .agent/skills/classify-functions/scripts/classify_function.py <db_path> --id <fid> --json
```

**e. Synthesize per-function audit summary:**
- Risk rating (CRITICAL/HIGH/MEDIUM/LOW) based on highest exploitability score
- Top 3 findings with taint paths and guard bypass difficulty
- Key dangerous operations and reachability status

**f. Update scratchpad:** Check off the function.

### Step Dependencies

- Step 1 is sequential (resolve targets).
- In `--privilege-boundary` mode, the RPC, COM, and WinRT discovery sub-steps are independent and should run in parallel before candidate resolution.
- Step 3a-3d: For each function, dossier and taint can run in parallel. Classification is independent.
- Step 3e depends on 3a-3d completion.
- Functions are independent -- audit up to 3-4 functions concurrently (subject to agent limits).

### 4. Synthesize batch report

After all functions are audited:

**Executive Summary:**
- Total functions audited, risk distribution (N CRITICAL, N HIGH, etc.)
- Module security posture (ASLR/DEP/CFG status)
- Top 3 most exploitable findings across all functions

**Per-Function Results** (table format):

| Function | Risk | Top Finding | Exploitability | Entry Type |
|----------|------|-------------|---------------|------------|
| ... | ... | ... | ... | ... |

**Cross-Function Patterns:**
- Common dangerous API sinks reached by multiple entry points
- Shared guard weaknesses across functions
- Missing security checks that affect multiple paths
- Repeated privilege-boundary weaknesses across RPC, COM, and WinRT entry handlers

**Prioritized Recommendations:**
- Top 5 functions requiring immediate deeper investigation
- Specific follow-up commands for each

## Output

Present the batch audit report in chat. Always save to `extracted_code/<module_folder>/reports/batch_audit_<target>_<timestamp>.md` (using `YYYYMMDD_HHMM` for timestamp, `<target>` is `top10`, a class name, `custom`, or `priv_boundary`). Create the `reports/` directory if needed.

All saved files must include a provenance header: generation date, module name, DB path, functions audited, and workspace run directory path.

**Follow-up suggestions:**

- `/audit <module> <function>` -- full deep audit on critical findings
- `/taint <module> <function> --cross-module` -- trace critical findings across DLL boundaries
- `/hunt validate <module> <function>` -- plan PoC for confirmed findings
- `/lift-class <module> <class>` -- lift flagged class for manual code review
- `/rpc audit <module>` -- inspect interface-level RPC security findings
- `/com audit <module_or_clsid>` -- inspect COM permission and activation details
- `/winrt audit <module>` -- inspect WinRT security metadata for flagged handlers

## Error Handling

- **Module not found**: List available modules via `find_module_db.py --list` and ask user to choose
- **No entry points found**: Report that the module has no discovered entry points; suggest running `/triage` first
- **No privilege-boundary handlers found**: Report that no RPC, COM, or WinRT handlers in the module resolved to auditable functions
- **Invalid option mix**: Reject `--privilege-boundary` combined with explicit functions or `--class`
- **Function not found**: Report which functions were not found; audit the ones that exist
- **Class not found**: List available classes and suggest close matches
- **Partial audit failure**: If some functions audit successfully but others fail, report the successful audits and list which functions could not be audited and why
- **DB access failure**: Report the error with the DB path and suggest running `/health`
