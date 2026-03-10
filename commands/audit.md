# Security Audit

## Overview

Perform a focused security audit of a specific function -- building a comprehensive security dossier, tracing attack reachability, and reporting findings with risk assessment and recommendations.

The text after `/audit` specifies the **function name** and optionally the **module**:

- `/audit AiCheckSecureApplicationDirectory` -- searches all modules
- `/audit appinfo.dll AiCheckSecureApplicationDirectory` -- targets specific module
- `/audit appinfo.dll --search CheckSecurity` -- pattern search
- `/audit appinfo.dll AiLaunchProcess --diagram` -- include Mermaid call graph diagram

If no function is specified, ask the user.

## IMPORTANT: Execution Model

**This is an execute-immediately command. Do NOT present anything for user confirmation** Run and write the final audit report straight to the chat as your response. The user expects to see the completed report.

## Workspace Protocol

Before running the multi-skill audit pipeline:

1. Create a run directory under `.agent/workspace/` (for example, `.agent/workspace/<module>_audit_<function>_<timestamp>/`).
2. Run every skill script with:
   - `--workspace-dir <run_dir>`
   - `--workspace-step <step_name>`
3. Keep only compact summaries in context/chat output.
4. Read full details only on demand from:
   - `<run_dir>/<step_name>/results.json`
   - `<run_dir>/<step_name>/summary.json`
5. Use `<run_dir>/manifest.json` as the source of truth for completed steps.
6. **Staleness check (when reusing an existing workspace):** If a workspace directory already exists and `manifest.json` shows all steps with `status: success`, check freshness before reusing results:
   - Read `manifest.json` `created_at` timestamp.
   - Compare against the analysis DB file modification time (`mtime` of the `.db` file resolved in Step 0).
   - If the DB `mtime` is **newer** than `manifest.created_at`, warn the user: *"Workspace was created before the current DB was last modified. Results may be outdated. Re-run with `--no-cache` to regenerate all steps."* Then proceed with the stale results unless the user explicitly requests regeneration.
   - If the workspace is **older than 24 hours** (regardless of DB age), emit an informational note at the start of the report: *"Note: Workspace is N hours old. Results may be stale if the extraction has been re-run since creation."*
   - These are warnings only — do not block execution. The user decides whether to re-run.

## Conventions

- **Function ID over name**: Step 1 returns a `function_id`. Use `--id <function_id>` in all subsequent script invocations -- it is unambiguous and avoids name-resolution edge cases.
- **JSON mode**: All skill scripts support `--json` for machine-readable output. Always pass `--json` when parsing script output programmatically.
- **Parallelism**: See the inline `>` note after Step 3h+3i for execution batches. Steps 2, 3, 3b, 3d, 3e, 4, and 4b (if `--diagram`) all run in the first parallel batch. Step 4c runs in Batch B (needs callchain results). Step 7 runs after Step 6.
- **Subagent descriptions**: When delegating to subagents, use descriptions that name the audit step and target function -- e.g. "Build security dossier for RAiLaunchAdminProcess", "Trace call chain from RAiLaunchAdminProcess". Never use generic descriptions like "Raw JSON content retrieval" or "File read".

## Steps

### Step 0: Preflight Validation

Validate arguments using `helpers.command_validation.validate_command_args("audit", {"module": "<module>", "function": "<function>"})`.
If validation fails, report the errors and stop. On success, use `result.resolved["db_path"]` for subsequent script calls.

### 1. Locate the function

**Quick lookup** (preferred):

```
python .agent/skills/function-index/scripts/lookup_function.py <function_name> --json
```

Returns module, library tag, `function_id`, and decompiled/assembly availability.

**Cross-dimensional search** (when the term might match a string, API call, or class name):

```
python .agent/helpers/unified_search.py <db_path> --query <term> --json
```

The JSON output contains `results_flat` (deduplicated flat list, easiest to iterate) and `results` (dimension-grouped dict).

**Fallback**: Use the **decompiled-code-extractor** skill (`find_module_db.py` then `list_functions.py --search`) to find the module DB and the exact function name.

Check `is_library_function()` from the function_index -- auditing a library/boilerplate function (WIL/CRT/STL) is typically lower priority than application code.

Once located, note the **`function_id`** and **`db_path`** -- all subsequent steps use them.

### 2. Build security dossier

```
python .agent/skills/security-dossier/scripts/build_dossier.py <db_path> --id <function_id> \
    --callee-depth 4 --json \
    --workspace-dir <run_dir> --workspace-step dossier
```

Produces: IPC context (RPC/COM/WinRT classification), parameter risk scoring, identity, function classification (primary/secondary categories, interest score, signals), attack reachability from exports, untrusted data exposure, dangerous operations (direct + transitive), resource patterns, complexity metrics, neighboring context, and module security posture.

### 3. Extract full function data

```
python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py <db_path> --id <function_id> \
    --json \
    --workspace-dir <run_dir> --workspace-step extract
```

Returns the complete function record: decompiled code, assembly, signatures, strings, xrefs, globals, stack frame, loops.

### 3b. Query attack surface ranking

```
python .agent/skills/map-attack-surface/scripts/rank_entrypoints.py <db_path> \
    --function <function_name> --json \
    --workspace-dir <run_dir> --workspace-step attack_surface
```

Returns entry point classification and risk scoring: `entry_type` (COM_METHOD, RPC_HANDLER, NAMED_PIPE_HANDLER, IPC_DISPATCHER, WINRT_METHOD, EXPORT_DLL, etc.), `attack_score`, `param_risk_score`, `param_risk_reasons`, `dangerous_ops_reachable`, `depth_to_first_danger`, `tainted_args`. If the function is not detected as an entry point, the empty result itself is a data point (internal-only function).

### 3c. Backward trace to dangerous APIs (conditional)

Run the backward trace selector to determine which traces to execute:

```
python .agent/helpers/select_backward_traces.py \
    --dossier <run_dir>/dossier/results.json \
    --extract-callee <run_dir>/extract_callee/results.json \
    --json
```

The script implements the Case A / Case B / Skip decision:
- **Case A**: Target function has direct dangerous calls → traces from the target function
- **Case B**: Thin wrapper (target has no direct dangerous calls but Step 3f callee does) → traces from the callee
- **Skip**: Neither applies → no traces needed

The output contains a `traces` array with `function_id`, `target_api`, `category`, and `step_name` for each trace to run. Execute all returned traces in parallel:

```
python .agent/skills/data-flow-tracer/scripts/backward_trace.py <db_path> --id <function_id> \
    --target <target_api> --json \
    --workspace-dir <run_dir> --workspace-step <step_name>
```

Each trace produces concrete parameter-to-sink argument paths for that danger category. Use results to populate the Data Flow Concerns section with confirmed call-site evidence.

### 3d. Read module profile (no script needed)

Read `extracted_code/<module_folder>/module_profile.json` for module-level context:
- `api_profile.import_surface`: `com_present`, `rpc_present`, `winrt_present`, `named_pipes_present`

### 3e. Forward taint analysis

```
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> --id <function_id> \
    --depth 4 --json \
    --workspace-dir <run_dir> --workspace-step taint_forward
```

Traces tainted parameters forward to dangerous sinks. For each finding, reports the sink name, category, severity score, the call path from source to sink, guards on the path (with attacker-controllability and bypass difficulty), and logic effects (branch steering, array indexing, size arguments). Use these results to strengthen concern C1 evidence and enrich the Data Flow Concerns section.

### 3f. Thin-wrapper callee extraction (conditional, depth up to 4)

If the target function's `complexity.instruction_count < 200` AND it has exactly 1-2 internal callees that account for the bulk of the dangerous operations (check `dangerous_operations.callee_dangerous_apis`), it is likely a thin wrapper. Extract the primary callee's decompiled code to enable deeper manual review:

```
python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py <db_path> \
    --id <primary_callee_id> --json \
    --workspace-dir <run_dir> --workspace-step extract_callee
```

**Recursive extraction for deep wrapper chains (up to depth 4):** After extracting the primary callee, check whether it is *also* a thin wrapper:
- Its `loop_analysis.loop_count == 0` AND `instruction_count < 200` (from the extract result)
- AND its `outbound_xrefs` has 1-2 internal callees that appear in `dangerous_operations.callee_dangerous_apis`

If both conditions hold, extract that callee as depth-2:

```
python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py <db_path> \
    --id <depth_2_callee_id> --json \
    --workspace-dir <run_dir> --workspace-step extract_callee_d2
```

Repeat for depth-3 and depth-4 using step names `extract_callee_d3` and `extract_callee_d4`. **Stop as soon as** the extracted function is no longer thin (has loops, > 200 instructions, or > 2 internal dangerous callees), OR depth 4 is reached. Cap at depth 4 to prevent explosion on long delegation chains.

During Step 6 synthesis, use ALL extracted callee levels to evaluate concerns C2 (impersonation pairing), C4 (flag validation), and C7 (alternate paths). Note each finding with its source depth: e.g., *"(Source: depth-2 callee AiFoo)"*.

### 3g. RPC interface security lookup (conditional)

Only run if dossier `reachability.ipc_context.is_rpc_handler = true`:

```
python .agent/skills/rpc-interface-analysis/scripts/resolve_rpc_interface.py <module_name> --json \
    --workspace-dir <run_dir> --workspace-step rpc_interface
```

Returns interface-level security context for all RPC interfaces in the module. Filter to the interface matching `reachability.ipc_context.rpc_interface_id`. Key fields to extract for the Attack Reachability section:

| Field | Use |
|---|---|
| `risk_tier` | critical/high/medium/low -- pre-computed interface risk classification |
| `is_remote_reachable` | Whether the interface is accessible over TCP/HTTP (vs. LRPC-only) |
| `protocols` | `ncalrpc` = local-only; `ncacn_np` = named pipe; `ncacn_ip_tcp` = remote |
| `service_name` / `service_display_name` | Which service hosts this RPC server |
| `is_client` | If true, this module is an RPC *client*, not a server -- adjust reachability assessment |

**Note:** RPC authentication level (`RPC_C_AUTHN_LEVEL_*`), security callbacks, and endpoint ACLs are set at runtime during server registration and are not present in static extraction data. Note this as a caveat in the Confidence and Caveats section: *"RPC auth level and security callback are runtime-registered and not statically detectable; assume worst-case (unauthenticated) unless a dynamic analysis confirms otherwise."*

### 3h+3i. Deep callee extraction (conditional, scripted)

Run the callee selection helper to determine which callees to extract for Steps 3h (deep security callees) and 3i (taint-path intermediates). This script implements both selection algorithms and handles DB existence checks, tier assignment, deduplication, and capping.

**Trigger conditions** (evaluated by the script):
- Step 3h triggers when `dangerous_ops_reachable >= 10` (from step 3b) OR `is_rpc_handler: true` (from step 2 dossier)
- Step 3i triggers when taint forward (step 3e) has findings with `path_hops > 1` AND empty `guards`

```
python .agent/helpers/select_audit_callees.py <db_path> \
    --dossier <run_dir>/dossier/results.json \
    --attack-surface <run_dir>/attack_surface/results.json \
    --taint-forward <run_dir>/taint_forward/results.json \
    --exclude <callee_names_from_step_3f> \
    --json
```

The script outputs `all_extractions` -- a combined list of deep callees (up to 4, tier-ranked) and taint-path callees (up to 3, score-ranked). Each entry includes `callee_name`, `function_id`, `step_name`, `tier`, `api_count`, `source` ("3h" or "3i"), and `rationale`.

Extract all returned callees in parallel:

```
python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py <db_path> \
    --function <callee_name> --json \
    --workspace-dir <run_dir> --workspace-step <step_name>
```

**Completeness rule:** ALL callees returned by the script must be extracted. After all extractions complete, verify that every step name appears in the workspace `manifest.json` with `status: success`. If any extraction failed, retry it once with `--function` instead of `--id`; if it fails again, note the specific gap in the Confidence and Caveats section.

**What each extraction resolves during synthesis:**

| Callee type | Concern addressed |
|---|---|
| Tier 1 `command_execution` callee (e.g. `AiLaunchProcess`) | C1/C5: confirm size args, path checks, and input validation before `CreateProcessAsUserW` |
| Tier 2 `privilege` callee that does impersonation (e.g. `AiGetClientInformation`) | C2: verify `RpcImpersonateClient` / `RpcRevertToSelf` are paired on all error paths |
| Tier 2 callee that modifies tokens (e.g. `AipBuildConsentToken`) | C4: confirm flag validation before `NtSetInformationToken` |
| Tier 3 `file_write` callee (e.g. `AiCheckSecureApplicationDirectory`) | C3: confirm `CreateFileW` share flags and handle-based path resolution |
| Taint-path intermediate (e.g. `AiBuildAxISParams`) | C1/C5: verify allocation arithmetic, implicit bounds checks, and taint severity |

During Step 6 synthesis, read all `extract_deep_*` and `extract_taint_*` payloads and reference them by callee name. Prefix findings: *"(Source: deep callee `AiLaunchProcess`, manual review)"* or *"(Source: taint-path callee `AiBuildAxISParams`, manual review of allocation arithmetic)"*. If manual review changes a taint severity, state the adjustment and evidence in the concern entry.

> **Batch A: Run steps 2 + 3 + 3b + 3d + 3e + 4 + 4b (if `--diagram`) in parallel** -- they all depend only on Step 1 (`db_path` + `function_id`). **Batch B (after Batch A):** Run `select_audit_callees.py` (needs dossier + attack_surface + taint_forward results), then extract all returned callees in parallel alongside 3f, 3g, 3c, and 4c (needs callchain results). Step 3f depends on steps 2 + 3; each deeper level depends on the previous level's extract result. Step 3g depends on step 2 (needs `is_rpc_handler`). Step 3c depends on steps 2 + 3f (see Step 3c rules).

### 4. Trace call chain

```
python .agent/skills/callgraph-tracer/scripts/chain_analysis.py <db_path> --id <function_id> \
    --depth 4 --summary --json \
    --workspace-dir <run_dir> --workspace-step callchain
```

Shows the compact call tree (depth 4). For specific paths of interest, extract full code output from the callchain results.

### 4b. Generate Mermaid diagram (conditional -- only when `--diagram` is specified)

```
python .agent/skills/callgraph-tracer/scripts/generate_diagram.py <db_path> \
    --id <function_id> --depth 4 --format mermaid --json \
    --workspace-dir <run_dir> --workspace-step diagram
```

Produces a Mermaid call graph diagram rooted at the target function. Runs in Batch A (depends only on Step 1). Include the diagram in a `## Call Graph Diagram` section in the report between "Call Chain Analysis" and "Risk Assessment".

### 4c. Cross-module resolution

Resolve external callees discovered in the call chain:

1. First try the **import-export-resolver** skill (`query_function.py --function <callee> --direction export`) to resolve external callees via PE import/export tables (handles API-set forwarders like `api-ms-win-*` -> `kernelbase.dll`).
2. Fall back to the **callgraph-tracer** skill (`cross_module_resolve.py --from-function`) for callees not resolvable via import tables.
3. For each resolvable cross-module callee, optionally run `chain_analysis.py` starting from that callee's module DB.

Runs in Batch B (needs callchain results to know which callees are external). Include a `## Cross-Module Transitions` section in the report showing a table:

| Source Function | External Callee | Target Module | Resolved? |
|---|---|---|---|

### 6. Synthesize audit report

Read the workspace results from all steps (2, 3, 3b, 3c, 3d, 3e, 3f + depth-2/3/4 extractions if run, 3g, `extract_deep_*` and `extract_taint_*` if run, 4, 4b if `--diagram`, 4c) and combine all findings into a structured report.

**IMPORTANT -- workspace results.json envelope structure**: Every `results.json` file written by the workspace bootstrap has this shape:
```json
{ "output_type": "json", "captured_at": "...", "stdout_char_count": N, "stdout": { ...actual skill output... } }
```
The actual skill payload is always under the `"stdout"` key. Never access fields directly at the top level of `results.json` -- they will silently return empty. Always use one of:
- Python: `data = json.load(f); payload = data["stdout"]` then `payload.get("decompiled_code", "")`
- Helper: `from helpers.workspace import read_step_payload; payload = read_step_payload(run_dir, "extract")`

Read the full decompiled code from the extract step (`<run_dir>/extract/results.json` at `stdout.decompiled_code`) for manual code review -- the Code-Level Observations section requires referencing specific lines, variables, and code patterns.

#### Data Interpretation Rules

Several numeric fields use different scales. Always apply these rules when citing values:

- `param_risk_score`: **0.0-1.0 scale** (fraction). `0.7` = 70th percentile risk.
- `noise_ratio`: **0.0-1.0 scale** (fraction). `0.48` = 48% of functions are library boilerplate.
- `attack_score`: **0.0-1.0 scale** (fraction). Higher = more attractive attack target.

When citing any of these values in the report, always include the human-readable interpretation alongside the raw number.

#### Report Template

Use this exact section structure and formatting. Do not rearrange sections or change heading levels.

**Formatting rules:**
- Use the **raw IDA signature** from the database. Do not reconstruct parameter names (that is lifting, not auditing).
- **Function Overview** uses a key-value table.
- **Call Chain Analysis** uses an ASCII tree (not a table).
- **Dimension Table** uses a table with columns: Dimension | Score | Key Data Points.
- **Specific Concerns** uses a numbered list with `[SEVERITY -- checklist_id]` prefix.
- **Recommended Next Steps** uses a table with columns: Priority | Function | Danger Category | dangerous_ops_reachable.

```markdown
# Security Audit: `<function_name>` -- <module>

> Generated: <date>
> Workspace: `<run_dir>`

## Function Overview

| Field | Value |
|---|---|
| **Function** | `<function_name>` |
| **Module** | `<module>` (<description>) |
| **Function ID** | <id> |
| **Signature** | `<raw IDA signature from DB -- do not reconstruct param names>` |
| **Classification** | Primary: `<category>` / Secondary: `<categories>` |
| **Interest Score** | <N>/10 |
| **Metrics** | <instruction_count> instructions, <branch_count> branches, <loop_count> loops, complexity <cyclomatic>, <local_vars_size>-byte stack frame |

<1-2 paragraph description of the function's purpose, based on dossier identity, classification, and decompiled code.>

## Attack Reachability

<Explain whether the function is exported, externally reachable, or an IPC entry point. Cite the specific dossier fields and step 3b results. If static analysis underreports (e.g., RPC dispatch), explain the gap and the evidence used to override it.>

| Attribute | Value |
|---|---|
| Exported | <yes/no> |
| Externally reachable | <yes/no -- via what mechanism> |
| Entry type | <from step 3b or fallback heuristic> |
| Shortest path from entry | <hop count or "IS the entry"> |
| Receives external data | <yes/no -- which parameters> |
| RPC protocol (if handler) | <ncalrpc / ncacn_np / ncacn_ip_tcp -- from step 3g, or omit if not RPC> |
| RPC remote reachable | <yes/no -- ncalrpc = local sessions only; omit if not RPC> |
| RPC risk tier | <critical/high/medium/low -- from step 3g; omit if not RPC> |
| Hosting service | <service name + privilege level, if available from step 3g; omit if not RPC> |

## Security-Relevant Operations

### Direct (within <function_name>)

| API | Category | Context |
|---|---|---|
| <api_name> | <category> | <brief context from decompiled code> |

### Transitive (via callees)

| Callee | Dangerous APIs | Risk |
|---|---|---|
| <callee_name> | <api_list> | <brief risk note> |

**Reachable dangerous operations (BFS):** <dangerous_ops_reachable>
**Depth to first danger:** <depth_to_first_danger>

### Resource Patterns
- File operations: ...
- Global reads/writes: <global_reads> reads, <global_writes> writes
- Sync operations: <present or none>
- Module security: ASLR <check> DEP <check> CFG <check> SEH <check>

## Data Flow Concerns

<Trace untrusted parameters from entry to dangerous sinks. Use the dossier data_exposure, backward_trace, taint_forward (step 3e), and decompiled code. When taint analysis results are available, cite specific taint findings: which parameters reach which sinks, the severity score, guard bypass difficulty, and logic effects (branch steering, array indexing, size arguments). Describe the security gates in the path.>

## Call Chain Analysis

```
<function_name>
├── <callee_1>       [<annotation>]
│   ├── <sub_callee>  [<annotation>]
│   └── ...
├── <callee_2>       [<annotation>]
└── ...
```

<Brief notes on cross-module calls.>

## Call Graph Diagram (when --diagram)

<Mermaid diagram from Step 4b>

## Cross-Module Transitions

| Source Function | External Callee | Target Module | Resolved? |
|---|---|---|---|
| <source> | <callee> | <module> | <yes/no> |

<Brief notes on cross-module dependencies and API-set forwarder resolution.>

## Risk Assessment

### Dimension Table

| Dimension | Score | Key Data Points |
|---|---|---|
| **Attack Surface Exposure** | <SCORE> | <cite specific field values that drove this score> |
| **Dangerous Operation Density** | <SCORE> | <cite specific field values> |
| **Complexity and Error Surface** | <SCORE> | <cite specific field values> |

### Overall Risk: <LEVEL>

<One-line rationale citing which dimensions drove it and any escalation applied.>

### Specific Concerns

1. **[SEVERITY -- C<id>]** <Title> -- <description>. *(Source: <dossier_field>)*
2. **[SEVERITY -- C<id>]** <Title> -- <description>. *(Source: <dossier_field>)*
...

### Confidence and Caveats

- <Any data gaps, static analysis limitations, tool false negatives>

### Code-Level Observations (optional)

<See rules below for this section.>

## Recommended Next Steps

| Priority | Function | Danger Category | dangerous_ops_reachable | Reason |
|---|---|---|---|---|
| 1 | `<function>` | <category> | <count> | <brief reason> |
| 2 | ... | ... | ... | ... |
```

#### Risk Assessment Rubric

The Risk Assessment section must be data-driven, not improvised. Score each dimension below using the specified data sources and thresholds, then compute the overall risk.

**Dimension 1 -- Attack Surface Exposure**

Data sources: dossier `reachability` + `data_exposure` + step 3b `attack_surface` + step 3d `module_profile`.

Inputs:
- `reachability.is_exported`, `reachability.externally_reachable`
- `reachability.shortest_path_from_entry` (path length = hop count)
- `data_exposure.receives_external_data`
- From step 3b: `entry_type` (COM_METHOD / RPC_HANDLER / NAMED_PIPE_HANDLER / IPC_DISPATCHER / WINRT_METHOD / EXPORT_DLL / etc.), `param_risk_score` (0.0-1.0), `tainted_args`
- From dossier: `reachability.ipc_context` fields (`is_rpc_handler`, `is_com_method`, `is_winrt_method`, `reachable_from_rpc/com/winrt`). This field may be absent in cached results -- use `--no-cache` if missing, or fall back to name-pattern heuristics.
- From step 3d: `module_profile.api_profile.import_surface` flags (`rpc_present`, `com_present`, `winrt_present`, `named_pipes_present`)
- Fallback if step 3b returns no entry point: name-pattern heuristics (`RA` = RPC Async, `s_` = RPC stub, `::Invoke` = COM vtable)

Scoring:
- CRITICAL: `entry_type` is RPC_HANDLER/COM_METHOD/NAMED_PIPE_HANDLER/IPC_DISPATCHER AND `param_risk_score >= 0.7`
- HIGH: `entry_type` is EXPORT_DLL AND `param_risk_score >= 0.5` AND `receives_external_data`; OR `externally_reachable` AND path <= 2 hops AND `receives_external_data`
- MEDIUM: `externally_reachable` but path > 2 hops, or reachable without confirmed external data; OR module has `rpc_present`/`com_present` but function not identified as entry point
- LOW: Not externally reachable AND not an IPC entry point AND no IPC import surface in module

**Override for tool false negatives:** When step 3b returns `param_risk_score: 0.0` or does not detect the function as an entry point, BUT fallback heuristics (name-pattern + signature + RPC/COM API calls in body) confirm the function IS an RPC_HANDLER/COM_METHOD/IPC_DISPATCHER, apply this override:
- Set `entry_type` to the heuristic-confirmed type.
- Treat `param_risk_score` as **unknown** (not 0.0). Do NOT use the tool's 0.0 value in the scoring formula.
- Score D1 as **CRITICAL** — the function is a confirmed IPC handler with attacker-controlled parameters; the tool simply failed to detect it. The `param_risk_score >= 0.7` threshold is waived because the tool's score is a known artifact, not a real measurement.
- State the override and evidence in the Confidence and Caveats section.

**Dimension 2 -- Dangerous Operation Density**

Data sources: dossier `dangerous_operations` + dossier `classification.signals` + step 3b `attack_surface` + step 3c `backward_trace` + step 3e `taint_forward`.

Inputs:
- `dangerous_operations.dangerous_api_count`, `dangerous_operations.security_relevant_callees` (category keys: `memory_unsafe`, `command_execution`, `code_injection`, `privilege`, `file_write`, `registry_write`, `network`, `crypto`, `service`, `handle`, `sync`), `dangerous_operations.callee_dangerous_apis`
- dossier `classification.signals` for categories like `security`, `process_thread`
- From step 3b: `dangerous_ops_reachable` (total dangerous sinks reachable via callgraph BFS), `depth_to_first_danger` (hop count to nearest dangerous operation)
- From step 3c: concrete parameter-to-sink paths showing which function parameters feed into which dangerous APIs
- From step 3e: taint analysis forward findings with severity scores, guard bypass difficulty, and logic effects. Use CRITICAL/HIGH taint findings as direct evidence for scoring.

Scoring:
- CRITICAL: `dangerous_ops_reachable >= 10` OR both `command_execution` + `privilege` present in `security_relevant_callees` OR `depth_to_first_danger == 0` (function directly calls dangerous API with tainted arg confirmed by backward_trace) OR taint_forward has CRITICAL-severity findings (score >= 0.8)
- HIGH: `dangerous_ops_reachable` 5-9 OR `depth_to_first_danger <= 1` OR `dangerous_api_count` 2-4 OR `file_write`/`registry_write` present OR `command_execution` alone
- MEDIUM: `dangerous_api_count == 1` OR only transitive dangerous APIs via `callee_dangerous_apis` OR `dangerous_ops_reachable` 1-4
- LOW: No dangerous APIs direct or transitive AND `dangerous_ops_reachable == 0`

**Dimension 3 -- Complexity and Error Surface**

Data sources: dossier `complexity` + `resource_patterns` + `module_security`.

Inputs:
- `complexity.instruction_count`, `complexity.branch_count`, `complexity.loop_count`
- `complexity.max_cyclomatic_complexity`
- `resource_patterns.has_global_writes`, `resource_patterns.sync_operations`
- `module_security.cfg`
- Note: if `complexity.has_syscall` is true (direct syscall / `int 2Eh`), flag as HIGH risk signal (potential evasion of security hooks)

Scoring:
- HIGH: `instruction_count >= 500` OR (`loop_count >= 5` AND `max_cyclomatic_complexity >= 5`) OR (sync ops present AND global writes) OR `has_syscall == true`
- MEDIUM: `instruction_count` 100-499 OR `loop_count` 2-4 OR `branch_count >= 20`
- LOW: `instruction_count < 100` AND `loop_count <= 1`

#### Mandatory Concern Checklist

Every audit must evaluate these eight concern categories against the function's data. For each, state APPLIES (with severity and evidence) or DOES NOT APPLY (with brief reason). This ensures consistent baseline coverage across runs. Additional findings beyond this list are encouraged but must follow the same severity rules.

| ID | Concern | What to Check |
|----|---------|---------------|
| C1 | **Untrusted input to dangerous sinks** | Does any client/external parameter flow to `CreateProcessAsUser*`, `CreateFile*`, memory-unsafe APIs, or other dangerous sinks? Cite the dossier `data_exposure` + `dangerous_operations` fields, backward_trace results, and taint_forward findings (step 3e). When taint analysis results are available, use the taint severity score, guard bypass difficulty, and concrete parameter-to-sink paths as primary evidence. |
| C2 | **Impersonation/revert pairing** | Are all `RpcImpersonateClient`/`ImpersonateLoggedOnUser` calls paired with reverts on every exit path (including error/goto paths)? Check decompiled code branch targets. |
| C3 | **TOCTOU / file handle races** | Is there a time gap between file validation and file use? Are `CreateFileW` share flags permissive (`FILE_SHARE_WRITE`)? Could the file be swapped between check and use? |
| C4 | **Flag/bitmask validation** | Are client-controlled flag/bitmask parameters validated for legal combinations before gating security-sensitive branches? |
| C5 | **String/buffer bounds** | Are all string parameters length-validated before use? Are fixed-size stack buffers (WCHAR arrays) bounded correctly at all call sites? |
| C6 | **Handle/resource cleanup** | Are all handles (token, file, process) closed on every exit path including error paths? Check for leaked handles across `goto` labels. |
| C7 | **Alternate code paths** | Do fallback/alias/error paths apply the same security checks as the primary path? List which gates are present on the primary path and which are **confirmed skipped** on the alternate path. Severity guide: **HIGH** if one or more security gates are confirmed skipped on an active alternate path that reaches a dangerous sink (this is a "confirmed missing security check" per the severity rubric). Upgrade to **CRITICAL** only if the skipped gate is the **sole** barrier to the dangerous sink AND the alternate path's trigger condition requires no preconditions beyond attacker-controlled input. Rate **MEDIUM** if the alternate callee's internal checks are unaudited (unknown compensating controls). Do NOT speculate about self-stageability or exploitability beyond what the decompiled code and dossier data confirm. |

In the Specific Concerns section of the report, prefix each concern with its checklist ID: e.g., `[CRITICAL -- C1]`, `[HIGH -- C3]`. Concerns that don't map to a checklist item use `[SEVERITY -- Cx]` where x = "extra".

**Merging overlapping checklist items:** When two checklist items (e.g. C1 and C5) identify the same underlying sink, root cause, and remediation — meaning C5 evidence is entirely subsumed by C1's taint path evidence — merge them into a single finding and cite both IDs: `[HIGH — C1, C5]`. Do NOT create two separate findings that inflate the apparent finding count for one underlying vulnerability. Merging is appropriate only when the code pattern, the attacker-controlled input, the dangerous sink, and the required fix are all identical.

**Overall Risk Calculation**

1. Start with the highest individual dimension score as baseline
2. Escalate by one level if 3+ dimensions score HIGH or above
3. Cap at CRITICAL

**Required Output Format for Risk Assessment**

The Risk Assessment section of the report must contain these parts in order:

1. **Dimension table**: one row per dimension with its score and the key data points that drove it
2. **Overall Risk**: the computed level with a one-line rationale citing which dimensions drove it
3. **Specific concerns**: ranked list where each concern cites its checklist ID and the dossier field it comes from. Assign severity using these rules:
   - **CRITICAL**: Directly achieves code execution, privilege escalation, or authentication bypass with attacker-controlled input. Must have a confirmed data flow from untrusted source to dangerous sink (cite the backward_trace or dossier field).
   - **HIGH**: Could achieve the above with one additional precondition (bypass of an intermediate check, TOCTOU race win, etc.), OR a confirmed missing security check in an active code path.
   - **MEDIUM**: Theoretical weakness requiring multiple preconditions, OR a defense-in-depth gap (e.g., missing CFG coverage, missing SEH on a function that handles user data). A concern about untested flag combinations without a confirmed path to dangerous behavior is MEDIUM at most.
   - **LOW**: Code quality concern, untested path, or cosmetic issue that does not directly affect security posture.

   Every concern must cite its source field (e.g., `Source: dossier.dangerous_operations.security_relevant_callees`) and its checklist ID (e.g., `C1`).
4. **Confidence and caveats**: any data gaps (e.g., "static reachability does not capture RPC dispatch")
5. **Code-level observations** (optional, max 3): Observations from reading the decompiled code that are NOT already covered by the checklist concerns above. Rules:
   - Maximum **3** observations. Do not pad with low-value items.
   - Each must reference a **specific line, variable, or code pattern** in the decompiled output.
   - Each must be labeled: `"Manual review -- not from automated dossier data"`.
   - These do **not** contribute to or alter the risk dimension scores.
   - **Use final assessed severity only.** If analysis reveals an observation is not a live issue, omit it entirely rather than labeling it HIGH and then walking it back within the same entry. A self-refuting finding that starts with a high severity label misleads readers who skim labels. The label must reflect the conclusion, not the initial hypothesis.
   - If no noteworthy observations beyond the checklist items exist, omit this section entirely.
6. **Recommended Next Steps**: ranked table of functions to audit next (see ranking formula below)

#### Recommended Next Steps Ranking Formula

The Recommended Next Steps table must be populated using this deterministic ranking, not ad-hoc judgment:

1. Collect all functions from `dangerous_operations.callee_dangerous_apis` (the dossier's callee-to-dangerous-API map).
2. Assign each callee a **danger tier** based on its highest-priority API category:
   - Tier 1: `command_execution` (e.g., `CreateProcessAsUserW`)
   - Tier 2: `privilege` (e.g., `ImpersonateLoggedOnUser`, `NtSetInformationToken`)
   - Tier 3: `file_write` or `registry_write`
   - Tier 4: all other categories (`memory_unsafe`, `network`, `crypto`, `handle`, `sync`, etc.)
3. Within the same tier, sort by `dangerous_ops_reachable` count (descending). Use `len(callee_dangerous_apis[callee_name])` from the dossier — the number of dangerous API names listed for that callee. Example: `AiBuildAxISParams` has `["wcscpy_s"]` → write `1`. `AiGetClientInformation` has `["NtOpenProcess", "NtDuplicateToken"]` → write `2`. The column must never be blank; if zero, write `0`.
4. Output the top 5-7 functions in the table. Include the danger tier, reachability count, and a brief reason.
5. After the table, optionally add one line suggesting a `/callgraph`, `/data-flow`, or `/taint` command for deeper investigation.

### 7. Verify concerns with fresh eyes

After Step 6 produces the draft report, launch a **separate subagent** to independently validate the specific concerns and their severity assignments. This step eliminates confirmation bias by ensuring the verifier has never seen the synthesis reasoning -- only the raw data and the claims.

**Subagent call:**

Use `subagent_type="re-analyst"` (or `"verifier"`) with `readonly: true`. Pass it a self-contained prompt containing:

1. The **severity criteria** (the CRITICAL/HIGH/MEDIUM/LOW rules from the Required Output Format above)
2. The **raw dossier summary JSON** (from `<run_dir>/dossier/summary.json`)
3. The **raw attack surface summary** (from `<run_dir>/attack_surface/summary.json`, if available)
4. The **raw backward trace summary** (from `<run_dir>/backward_trace/summary.json`, if available)
5. The **raw taint_forward summary** (from `<run_dir>/taint_forward/summary.json`, if available)
6. The **function's decompiled code** (from `<run_dir>/extract/results.json` `stdout.decompiled_code` field)
7. The **function's assembly code** (from `<run_dir>/extract/results.json` `stdout.assembly_code` field) -- required for ground-truth checks such as confirming hardcoded argument values, bit-test instructions, and calling conventions
8. The **primary callee's decompiled code** (from `<run_dir>/extract_callee/results.json` `stdout.decompiled_code`, if Step 3f ran) -- required for verifying concerns about callee-level alternate paths and flag gating
9. The **taint-path callee decompiled code** (from `<run_dir>/extract_taint_*/results.json` `stdout.decompiled_code`, if Step 3i ran) -- required for verifying severity adjustments where the synthesizer upgraded or downgraded a taint finding's severity based on reading the intermediate callee's allocation, copy, or validation logic
10. The **module profile `security_posture` section** (ASLR/DEP/CFG/SEH flags only)
11. The **Data Interpretation Rules** (param_risk_score is 0-1, noise_ratio is 0-1, attack_score is 0-1)
12. The **draft specific concerns list** with their assigned severities, checklist IDs, and cited source fields
13. The **draft dimension scores** with their key data points

**Subagent prompt template:**

```
You are an independent reviewer of a security audit report. You have NOT
participated in writing this report. Your job is to verify that each
specific concern's severity is correctly assigned according to the rubric,
and that each dimension score (D1-D3 only) follows the scoring thresholds.

SEVERITY CRITERIA:
- CRITICAL: Directly achieves code execution, privilege escalation, or
  authentication bypass with attacker-controlled input. Must have confirmed
  data flow from untrusted source to dangerous sink.
- HIGH: Could achieve the above with one additional precondition, OR
  confirmed missing security check in an active code path.
- MEDIUM: Theoretical weakness requiring multiple preconditions, OR
  defense-in-depth gap. Untested flag combinations without confirmed path
  to dangerous behavior are MEDIUM at most.
- LOW: Code quality concern, untested path, or cosmetic issue.

DATA INTERPRETATION:
- param_risk_score: 0.0-1.0 scale
- noise_ratio: 0.0-1.0 scale (0.48 = 48%)

RAW DATA:
<paste dossier summary JSON>
<paste attack surface summary JSON>
<paste backward trace summary JSON>
<paste taint_forward summary JSON, if available>
<paste module profile security_posture>

DECOMPILED CODE (target function):
<paste decompiled code for the target function>

DECOMPILED CODE (primary callee, if available from extract_callee step):
<paste decompiled code for the primary callee>

DECOMPILED CODE (taint-path callee(s), if available from extract_taint_* steps):
<paste decompiled code for each taint-path callee, labeled by function name>

ASSEMBLY CODE (target function, if needed for ground-truth checks):
<paste assembly code for the target function>

DRAFT DIMENSION SCORES (D1-D3):
<paste dimension table rows for Attack Surface Exposure, Dangerous Operation Density, Complexity and Error Surface>

DRAFT SPECIFIC CONCERNS:
<paste numbered concern list with severities>

For each concern, return a JSON object:
{
  "concern_number": N,
  "checklist_id": "C1"-"C7",
  "original_severity": "LEVEL",
  "verified_severity": "LEVEL",
  "change": "none" | "upgraded" | "downgraded",
  "reason": "brief explanation citing the rubric rule and data field"
}

Also verify each of the three dimension scores (D1, D2, D3) against the
thresholds. If a score is wrong, return the correction with the specific
threshold rule that was violated.

Return the complete list as a JSON array, followed by dimension corrections
(if any).
```

**Handling the verifier response:**

- If the verifier returns `"change": "none"` for all concerns, proceed with the draft as-is.
- If any concern is downgraded or upgraded, update the severity in the final report and add a note in the Confidence and Caveats section: `"Severity for concern #N was adjusted from X to Y by independent verification."`
- If a dimension score is corrected, update it and recompute the Overall Risk using the calculation rules.
- The verifier's response is NOT included verbatim in the report -- only the corrections are applied.

**Subagent description:** Use a description like `"Verify audit concerns for <function_name>"`.

> **Execution note**: Step 7 runs after Step 6 completes. It adds one subagent round-trip but catches severity inflation/deflation and data misinterpretation before the user sees the report.

## Output

Present the audit report in chat. Always save a copy to `extracted_code/<module_folder>/reports/audit_<function_name>_<short_timestamp>.md` (e.g. `audit_RAiLaunchAdminProcess_20260221_1343.md`). The `<short_timestamp>` format is `YYYYMMDD_HHMM`. Create the `reports/` directory if it does not exist.

## Error Handling

- **Module not found**: List available modules via `find_module_db.py --list` and ask the user to choose
- **Function not found**: Run a fuzzy search via `search_functions_by_pattern()` and suggest close matches
- **DB access failure**: Report the error with the DB path and suggest running `/health`
- **Missing decompiled code**: Report which functions lack decompiled output; offer to verify via assembly only
- **Security dossier build failure**: Log the error, report partial results from completed skill steps
