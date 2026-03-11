# Module Triage

## Overview

Perform a complete triage of a DeepExtractIDA module -- identifying the binary, classifying all functions, mapping the attack surface, and producing a prioritized list of functions worth deeper analysis.

The text after `/triage` is the **module name** (e.g., `/triage appinfo.dll`). If omitted, list available modules and ask.

Optional flags:

- `--with-security` -- after standard triage, run a lightweight taint scan on the top 3-5 ranked entry points and include a "Quick Security Findings" section in the report.

## IMPORTANT: Execution Model

**This is an execute-immediately command. Do NOT present anything for user confirmation.** Run and write the final triage report straight to the chat as your response. The user expects to see the completed report.

## Execution Context

> **IMPORTANT**: Any inline Python that imports `helpers.*` must run with `cd <workspace>/.agent`
> (so the `.agent/` directory is on `sys.path`), **not** from the workspace root.
> Script invocations like `python .agent/skills/.../script.py` can be run from the workspace root
> because those scripts manage their own path setup.

## Workspace Protocol

Before running triage:

1. Create `.agent/workspace/<module>_triage_<timestamp>/`.
2. Pass `--workspace-dir <run_dir>` and `--workspace-step <step_name>` to each skill invocation.
3. Treat stdout as summary-only; do not inline full JSON in chat.
4. Read full payloads only when needed from `<run_dir>/<step_name>/results.json`.
5. Use `<run_dir>/manifest.json` to track progress and available outputs.

## Steps

### Step 0: Preflight Validation

Validate arguments using `helpers.command_validation.validate_command_args("triage", {"module": "<module>"})`.
If validation fails, report the errors and stop. On success, use `result.resolved["db_path"]` for subsequent script calls.

1. **Find the module DB**
   Use the **decompiled-code-extractor** skill (`find_module_db.py`) to resolve the module name to its analysis database path. If the module is not found, run with `--list` to show all available modules.
   Alternatively, use `list_extracted_modules()` from helpers or `python .agent/skills/function-index/scripts/index_functions.py --all --stats` for instant module enumeration.

> **Tip:** All skill scripts support `--json` for machine-readable output. Use `--json` when parsing script output programmatically.

2. **Run triage via triage-coordinator**
   Use the **triage-coordinator** agent's `analyze_module.py` to run the full triage pipeline in one call:

   ```bash
   python .agent/agents/triage-coordinator/scripts/analyze_module.py <db_path> --goal triage --json
   ```

   This returns structured JSON covering: binary identity, security posture, function classification (category distribution, noise ratio, top interesting functions), call graph topology (node/edge counts, hubs, connectivity), attack surface discovery (entry point types, ranked by attack value), and module fingerprinting (COM-heavy, RPC-heavy, dispatch-heavy trait detection). The coordinator handles adaptive routing based on detected module characteristics.

   The session context "Module Profiles" section already contains pre-computed library noise ratio, dangerous API categories, technology surface flags, and complexity metrics from `module_profile.json`. Use these for additional orientation alongside the coordinator output.

3. **Quick security scan** (conditional -- only when `--with-security` is specified)
   Run `taint_function.py` from the **taint-analysis** skill on the top 3-5 ranked entry points from Step 2:
   ```bash
   python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> --id <fid> --depth 2 --json
   ```
   Collect any CRITICAL or HIGH severity findings. This is intentionally lightweight -- a quick signal of exploitable issues, not a comprehensive scan. For full vulnerability scanning, use `/scan`.

4. **Synthesize triage report**
   Combine all findings into a structured report:

   - **Binary Identity**: name, size, hashes, compiler, PDB
   - **Capability Profile**: import categories, export count, primary purpose
   - **Scale & Complexity**: total functions, named vs `sub_*`, category breakdown, noise ratio. `module_profile.json` provides pre-computed noise ratio, library breakdown (WIL/STL/WRL/CRT/ETW), and complexity stats (loop counts, assembly sizes). `compute_stats()` from function_index provides additional decompiled/assembly availability counts (including entries with `file: null` when decompilation failed).
   - **Most Interesting Functions (Top 10)**: table with name, category, interest score, dangerous APIs, reason
   - **Attack Surface Summary**: entry point types/counts, top 5 ranked by attack score, hidden entry points
   - **Quick Security Findings** (when `--with-security` was used): top taint findings from entry points, severity distribution, recommended `/audit` targets
   - **Recommended Next Steps**: suggest `/explain` or `/verify` for quick follow-ups, `/audit`, `/lift-class`, or `/full-report` for deep analysis, `/scan` for comprehensive vulnerability scanning, and `/search` for targeted exploration

## Step Dependencies

- Steps 1 -> 2 are sequential (resolve DB then run coordinator).
- Step 3 (when `--with-security`) depends on Step 2 (needs ranked entry points from coordinator output).
- Step 4 depends on all previous steps.

## Output

Present the triage report in chat. Always save to `extracted_code/<module_folder>/reports/triage_<module>_<timestamp>.md` (using `YYYYMMDD_HHMM` for timestamp).

All saved files must include a provenance header: generation date, workspace run directory path, module name, DB path, and function/entry point counts.

## Error Handling

- **Module not found**: List available modules via `find_module_db.py --list` and ask the user to choose
- **DB access failure**: Report the error with the DB path and suggest running `/health`
- **Tracking DB missing**: Fall back to direct DB resolution; warn that cross-module features are unavailable
- **Skill step failure**: Log the error, continue with remaining triage steps, report partial results
