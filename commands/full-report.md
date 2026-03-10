# Full Analysis Report

## Overview

End-to-end analysis of a DeepExtractIDA module combining multiple analysis passes: binary identity, function classification, attack surface mapping, call graph topology, and specialized analysis (COM, dispatch tables, global state). This is the most thorough single-command analysis.

The text after `/full-report` is the **module name** (e.g., `/full-report appinfo.dll`). Add `--brief` for an abbreviated version. If omitted, list available modules and ask.

## IMPORTANT: Execution Model

**This is an execute-immediately command. Do NOT present anything for user confirmation.** Run and write the final report straight to the chat as your response. The user expects to see the completed report.

## Execution Context

> **IMPORTANT**: Any inline Python that imports `helpers.*` must run with `cd <workspace>/.agent`
> (so the `.agent/` directory is on `sys.path`), **not** from the workspace root.
> Script invocations like `python .agent/skills/.../script.py` can be run from the workspace root
> because those scripts manage their own path setup.

## Workspace Protocol

This command orchestrates many skills; always use filesystem handoff:

1. At setup time, create `.agent/workspace/<module>_full_report_<timestamp>/`.
2. For every skill execution in all phases, pass:
   - `--workspace-dir <run_dir>`
   - `--workspace-step <phase_or_step_name>`
3. Treat script stdout as summary-only.
4. Read full intermediate results only from `<run_dir>/<step_name>/results.json` when synthesizing the final report.
5. Use `<run_dir>/manifest.json` to confirm completed/failed steps and avoid context blowup from large JSON payloads.

## Steps

### Step 0: Preflight Validation

Validate arguments using `helpers.command_validation.validate_command_args("full-report", {"module": "<module>"})`.
If validation fails, report the errors and stop. On success, use `result.resolved["db_path"]` for subsequent script calls.

### Setup

1. **Find the module DB**
   Use the **decompiled-code-extractor** skill (`find_module_db.py`) to resolve the module.

> **Tip:** All skill scripts support `--json` for machine-readable output. Use `--json` when parsing script output programmatically.

1b. **Generate adaptive analysis plan** (triage-coordinator)
   Use the **triage-coordinator** agent (`generate_analysis_plan.py`) to fingerprint the module and produce a phased analysis plan. The coordinator detects module characteristics (COM-heavy, RPC-heavy, security-relevant, dispatch-heavy, class-heavy) and tailors Phase 5 steps accordingly.

   ```bash
   python .agent/agents/triage-coordinator/scripts/generate_analysis_plan.py <db_path> --goal full --json
   ```

   The plan output includes `traits` (detected module characteristics) and `phases` (ordered skill tasks). Use the `traits` to decide which Phase 5 specialized analyses to run -- this replaces manual signal detection with the coordinator's adaptive routing logic.

2. **Create the task scratchpad** (grind loop)
   This command runs 6 phases. Write `.agent/hooks/scratchpads/{session_id}.md` (use the Session ID from your injected context) so the stop hook keeps you going until the full report is complete:

   ```
   # Task: Full report for <module_name>

   ## Items
   - [ ] Phase 1: Module discovery and identity
   - [ ] Phase 2: Function classification
   - [ ] Phase 3: Attack surface mapping
   - [ ] Phase 4: Topology analysis
   - [ ] Phase 5: Specialized analysis
   - [ ] Phase 6: Synthesize report

   ## Status
   IN_PROGRESS
   ```

   Check off each phase as you complete it. Set Status to `DONE` after Phase 6.

### Phase 1: Module Identity

3. **Generate base RE report**
   Use the **generate-re-report** skill (`generate_report.py --top 15`) for the comprehensive 10-section report covering: executive summary, provenance, security posture, imports/exports, architecture, complexity hotspots, string intelligence, topology, anomalies, and recommendations.
   For `--brief` mode, use `generate_report.py --summary` (sections 1, 3, 4, 10 only).
   Check off Phase 1 in the scratchpad.

### Phase 2: Function Classification

4. **Triage summary**
   The library noise ratio and breakdown are already available from `module_profile.json` in session context ("Module Profiles" section). Only run `python .agent/skills/function-index/scripts/index_functions.py <module> --stats` if the profile is missing. Use `--app-only` on `triage_summary.py` and `classify_module.py` to focus on application code.
   The enriched index includes `function_id`, `has_decompiled`, `has_assembly`, and may include `file: null`; use these fields directly instead of DB round-trips for metadata checks.
   Use the **classify-functions** skill (`triage_summary.py --top 20`) for category distribution and top interesting functions.

5. **Full classification (filtered)**
   Use the **classify-functions** skill (`classify_module.py --min-interest 3 --no-telemetry --no-compiler --json`) to identify all interesting functions with infrastructure noise filtered out.
   Check off Phase 2 in the scratchpad.

### Phase 3: Attack Surface

6. **Discover all entry points**
   Use the **map-attack-surface** skill (`discover_entrypoints.py`) to find exports, COM methods, RPC handlers, callbacks, TLS callbacks, and more.

7. **Rank by attack value**
   Use the **map-attack-surface** skill (`rank_entrypoints.py --top 15`) to score entry points by dangerous operation reachability, parameter risk, and proximity to danger.

8. **Generate entrypoints.json**
   Use the **map-attack-surface** skill (`generate_entrypoints_json.py -o extracted_code/<module_folder>/entrypoints.json --top 20`) for downstream tooling.

9. **Security dossiers for top entry points**
   Use the **security-dossier** skill (`build_dossier.py`) on the top 3-5 ranked entry points from Step 7 to gather per-function security context (attack reachability, data flow exposure, dangerous operations, resource patterns):
   ```bash
   python .agent/skills/security-dossier/scripts/build_dossier.py <db_path> <entry_point_name> --json
   ```
   Feed results into the Attack Surface section of the final report.

9b. **Taint analysis for top entry points**
   Use the **taint-analysis** skill (`taint_function.py`) on the top 3 ranked entry points from Step 7 to trace tainted parameters forward to dangerous sinks:
   ```bash
   python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> <entry_point_name> --depth 2 --json \
       --workspace-dir <run_dir> --workspace-step taint_<entry_point_name>
   ```
   For each entry point, report: sinks reached, severity breakdown (CRITICAL/HIGH/MEDIUM/LOW), guards on the path with bypass difficulty, and notable logic effects. Feed results into the Attack Surface section alongside the dossier findings.

   Check off Phase 3 in the scratchpad.

### Phase 4: Topology

10. **Call graph statistics**
    Use the **callgraph-tracer** skill (`build_call_graph.py --stats`) for graph metrics.

11. **Cross-module dependencies**
    Use the **callgraph-tracer** skill (`module_dependencies.py --module <name>`) to map inter-module relationships.

12. **Diagrams for top entry points**
    Use the **callgraph-tracer** skill (`generate_diagram.py --function <entry> --depth 2`) for the top 3 highest-ranked entry points from Phase 3.
    Check off Phase 4 in the scratchpad.

### Phase 5: Specialized Analysis (Adaptive)

The triage-coordinator's plan from Setup Step 1b determines which specialized analyses to run based on module fingerprinting. Run the steps whose traits were detected:

13. **COM interfaces** (trait: `com_heavy` -- >5 COM functions or >10% COM density)
    Use the **com-interface-reconstruction** skill (`scan_com_interfaces.py`).

14. **Dispatch tables** (trait: `dispatch_heavy` -- >5 dispatch/handler functions)
    Use the **state-machine-extractor** skill (`detect_dispatchers.py`).

15. **Global state hotspots** (if heavy global variable usage detected in Phase 2 classification)
    Use the **data-flow-tracer** skill (`global_state_map.py --summary`).

16. **Decompilation quality** (if module has >20% unnamed functions or index entries with `has_decompiled=false`)
    Use the **generate-re-report** skill (`analyze_decompilation_quality.py`) for quality metrics, or the **verify-decompiled** skill (`scan_module.py --min-severity HIGH --top 10`) for the worst decompiler issues. Feed results into the Anomalies section.

17. **Type reconstruction** (trait: `class_heavy` -- >3 C++ classes)
    Use the **reconstruct-types** skill (`scan_struct_fields.py --all-classes --app-only`) to collect struct layouts for classes found in Phase 2.

If the triage-coordinator plan is unavailable (e.g., script failure), fall back to manual signal detection from earlier phases.

Check off Phase 5 in the scratchpad (even if no specialized analysis was needed).

### Phase 6: Synthesize

17. **Assemble full report**
    Combine ALL findings into a comprehensive markdown report:
    - **Executive Summary**: one paragraph with identity, purpose, scale, key findings
    - **Binary Identity & Provenance**: hashes, compiler, PDB, timestamps
    - **Security Posture**: ASLR/DEP/CFG, canary coverage, DLL characteristics. `module_profile.json` provides canary coverage percentage and security flags directly.
    - **Capability Profile**: imports by category, exports by type, delay-loaded deps. `module_profile.json` has technology surface flags (COM/RPC/WinRT/pipes) and dangerous API categories.
    - **Function Classification**: distribution table, noise ratio, top 20 interesting functions. `module_profile.json` provides noise ratio and library tag breakdown (WIL/STL/WRL/CRT/ETW counts). Use function_index `compute_stats()` for additional decompiled/assembly availability counts from index metadata.
    - **Attack Surface**: entry point types/counts, top 15 ranked, hidden entry points, taint analysis findings for top entries (sinks reached, severity, guard bypass difficulty)
    - **Call Graph Topology**: statistics, hub functions, SCCs, Mermaid diagrams
    - **Complexity Hotspots**: by loop complexity, by size, by xref density
    - **String Intelligence**: categorized strings, notable clusters
    - **Specialized Findings**: COM interfaces, dispatch tables, global state (if detected)
    - **Anomalies**: decompiler failures, oversized functions, missing canaries. Include index entries where `has_decompiled=false` (these may have `file=null` but still valid `function_id` / `has_assembly` metadata).
    - **Prioritized Analysis Roadmap**: ranked next steps with `/explain` and `/verify` for quick follow-ups, `/audit`, `/lift-class` for deep dives, and `/search` for targeted exploration

    Check off Phase 6 and set Status to `DONE` in the scratchpad.

## Step Dependencies

- **Phase 1**: Sequential (Step 3 depends on Setup Steps 1-2).
- **Phase 2**: Steps 4 + 5 are independent and can run concurrently.
- **Phase 3**: Steps 6 -> 7 -> 8 are sequential (ranking depends on discovery, JSON export depends on ranking). Steps 9 and 9b depend on Step 7 (need ranked entry points) but are independent of each other -- run concurrently.
- **Phase 4**: Steps 10 + 11 are independent and can run concurrently. Step 12 depends on Phase 3 results (needs top-ranked entry points).
- **Phase 5**: Steps 13 + 14 + 15 + 16 are all conditional but independent of each other -- run whichever apply concurrently.
- **Phase 6**: Depends on all previous phases.

## Output

Save the full report to `extracted_code/<module_folder>/reports/full_report_<module>_<timestamp>.md` (using `YYYYMMDD_HHMM` for timestamp) and entrypoints.json (done in Step 8).

All saved files must include a provenance header: generation date, workspace run directory path, module name and DB path, and which skill script versions produced the data.

Present in chat: executive summary (2-3 sentences), key statistics table, top 5 analysis targets, and saved file locations.

## Error Handling

- **Module not found**: List available modules via `find_module_db.py --list` and ask the user to choose
- **DB access failure**: Report the error with the DB path and suggest running `/health`
- **Skill step failure**: Log the error, update workspace manifest with `"error"` status, continue with remaining phases
- **All phases failed**: Report aggregated errors and suggest running `/health` to diagnose
- **Workspace creation failure**: Fall back to inline output; warn that step tracking is unavailable
