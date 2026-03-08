# Security Audit

## Overview

Perform a focused security audit of a specific function -- building a comprehensive security dossier, verifying decompiler accuracy, tracing attack reachability, and reporting findings with risk assessment and recommendations.

The text after `/audit` specifies the **function name** and optionally the **module**:

- `/audit AiCheckSecureApplicationDirectory` -- searches all modules
- `/audit appinfo.dll AiCheckSecureApplicationDirectory` -- targets specific module
- `/audit appinfo.dll --search CheckSecurity` -- pattern search

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

## Conventions

- **Function ID over name**: Step 1 returns a `function_id`. Use `--id <function_id>` in all subsequent script invocations -- it is unambiguous and avoids name-resolution edge cases.
- **JSON mode**: All skill scripts support `--json` for machine-readable output. Always pass `--json` when parsing script output programmatically.
- **Parallelism**: Steps 2 + 3 + 3b are independent and should run in parallel. Step 3c is conditional on step 2 results. Steps 4 + 5 + 6 are independent and can run in parallel after the first batch completes. Step 8 (verify concerns) runs after Step 7 (synthesis) completes.
- **Subagent descriptions**: When delegating to subagents, use descriptions that name the audit step and target function -- e.g. "Build security dossier for RAiLaunchAdminProcess", "Verify decompiler accuracy for RAiLaunchAdminProcess", "Trace call chain from RAiLaunchAdminProcess". Never use generic descriptions like "Raw JSON content retrieval" or "File read".

## Steps

### Step 0: Preflight Validation

Validate arguments using `helpers.command_validation.validate_command_args("audit", {"module": "<module>", "function": "<function>"})`.
If validation fails, report the errors and stop. On success, use `result.resolved["db_path"]` for subsequent script calls.

### 0b. Optional: Verify decompiler accuracy first

If the target function has complex control flow (large switch statements, extensive inlining, or unusual calling conventions), consider running `/verify <module> <function>` before proceeding. Decompiler artifacts can cause false positive security findings. If verification reveals significant decompiler issues, note them in the final audit report as caveats.

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
    --callee-depth 2 --json \
    --workspace-dir <run_dir> --workspace-step dossier
```

Produces: identity, attack reachability from exports, untrusted data exposure, dangerous operations (direct + transitive), resource patterns, complexity metrics, neighboring context, and module security posture.

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

Only run if dossier `dangerous_operations.dangerous_api_count > 0`:

```
python .agent/skills/data-flow-tracer/scripts/backward_trace.py <db_path> --id <function_id> \
    --target <first_dangerous_api> --json \
    --workspace-dir <run_dir> --workspace-step backward_trace
```

Traces which function parameters feed into dangerous API arguments. Produces concrete parameter-to-sink paths.

### 3d. Read module profile (no script needed)

Read `extracted_code/<module_folder>/module_profile.json` for module-level context:
- `api_profile.import_surface`: `com_present`, `rpc_present`, `winrt_present`, `named_pipes_present`
- `security_posture.canary_coverage_pct`

### 3e. Forward taint analysis (conditional)

Only run if dossier `data_exposure.receives_external_data == true` OR `dangerous_operations.dangerous_api_count > 0`:

```
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> --id <function_id> \
    --depth 2 --json \
    --workspace-dir <run_dir> --workspace-step taint_forward
```

Traces tainted parameters forward to dangerous sinks. For each finding, reports the sink name, category, severity score, the call path from source to sink, guards on the path (with attacker-controllability and bypass difficulty), and logic effects (branch steering, array indexing, size arguments). Use these results to strengthen concern C1 evidence and enrich the Data Flow Concerns section.

> **Run steps 2 + 3 + 3b in parallel** -- they are independent. Step 3c depends on step 2 results (needs dangerous_api_count). Step 3d is a file read with no dependencies. Step 3e depends on step 2 results (needs data_exposure and dangerous_api_count).

### 4. Verify decompiler accuracy

```
python .agent/skills/verify-decompiled/scripts/verify_function.py <db_path> --id <function_id> \
    --json \
    --workspace-dir <run_dir> --workspace-step verify
```

Compares decompiled output against assembly ground truth. Note any inaccuracies -- wrong access sizes, missing NULL guards, collapsed operations, or return type errors could mask real bugs.

### 5. Trace call chain

```
python .agent/skills/callgraph-tracer/scripts/chain_analysis.py <db_path> --id <function_id> \
    --depth 2 --summary --json \
    --workspace-dir <run_dir> --workspace-step callchain
```

Shows the compact call tree. For functions with dangerous API callees, follow those paths with `--depth 3` and full code output.

### 6. Classify function purpose

```
python .agent/skills/classify-functions/scripts/classify_function.py <db_path> --id <function_id> \
    --json \
    --workspace-dir <run_dir> --workspace-step classify
```

Returns the function's role, category, interest score, and classification signals.

> **Run steps 4 + 5 + 6 + 3e in parallel** -- they are independent of each other. Steps 4-6 only depend on steps 2 + 3 for context during synthesis. Step 3e depends on step 2 (dossier) for its trigger condition.

### 7. Synthesize audit report

Read the workspace results from all steps (2, 3, 3b, 3c, 3d, 3e, 4, 5, 6) and combine all findings into a structured report.

#### Data Interpretation Rules

Several numeric fields use different scales. Always apply these rules when citing values:

- `canary_coverage_pct`: **0-100 scale** (percentage). `0.2` = 0.2%, `78.5` = 78.5%. Do NOT interpret as a 0-1 fraction.
- `param_risk_score`: **0.0-1.0 scale** (fraction). `0.7` = 70th percentile risk.
- `noise_ratio`: **0.0-1.0 scale** (fraction). `0.48` = 48% of functions are library boilerplate.
- `attack_score`: **0.0-1.0 scale** (fraction). Higher = more attractive attack target.

When citing any of these values in the report, always include the percentage or human-readable interpretation alongside the raw number.

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
| **Metrics** | <instruction_count> instructions, <branch_count> branches, <loop_count> loops, complexity <cyclomatic>, <local_vars_size>-byte stack frame, canary: <yes/no> |

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

## Security-Relevant Operations

### Direct (within <function_name>)

| API | Category | Context |
|---|---|---|
| <api_name> | <category> | <brief context from decompiled code> |

### Transitive (via callees, depth 1-2)

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
- Module canary coverage: <canary_coverage_pct>% (<interpretation>)

## Decompiler Accuracy

<State the verification verdict: HIGH/MEDIUM/LOW confidence with issue counts. Explain impact on audit confidence.>

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

## Risk Assessment

### Dimension Table

| Dimension | Score | Key Data Points |
|---|---|---|
| **Attack Surface Exposure** | <SCORE> | <cite specific field values that drove this score> |
| **Dangerous Operation Density** | <SCORE> | <cite specific field values> |
| **Complexity and Error Surface** | <SCORE> | <cite specific field values> |
| **Decompiler Confidence** | <SCORE> | <cite issue counts> |

### Overall Risk: <LEVEL>

<One-line rationale citing which dimensions drove it and any escalation applied.>

### Specific Concerns

1. **[SEVERITY -- C<id>]** <Title> -- <description>. *(Source: <dossier_field>)*
2. **[SEVERITY -- C<id>]** <Title> -- <description>. *(Source: <dossier_field>)*
...

### Confidence and Caveats

- Decompiler confidence: <level> (<issue summary>)
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

Data sources: dossier `dangerous_operations` + classify `signals` + step 3b `attack_surface` + step 3c `backward_trace` + step 3e `taint_forward`.

Inputs:
- `dangerous_operations.dangerous_api_count`, `dangerous_operations.security_relevant_callees` (category keys: `memory_unsafe`, `command_execution`, `code_injection`, `privilege`, `file_write`, `registry_write`, `network`, `crypto`, `service`, `handle`, `sync`), `dangerous_operations.callee_dangerous_apis`
- classify `signals` for categories like `security`, `process_thread`
- From step 3b: `dangerous_ops_reachable` (total dangerous sinks reachable via callgraph BFS), `depth_to_first_danger` (hop count to nearest dangerous operation)
- From step 3c: concrete parameter-to-sink paths showing which function parameters feed into which dangerous APIs
- From step 3e: taint analysis forward findings with severity scores, guard bypass difficulty, and logic effects. Use CRITICAL/HIGH taint findings as direct evidence for scoring.

Scoring:
- CRITICAL: `dangerous_ops_reachable >= 10` OR both `command_execution` + `privilege` present in `security_relevant_callees` OR `depth_to_first_danger == 0` (function directly calls dangerous API with tainted arg confirmed by backward_trace) OR taint_forward has CRITICAL-severity findings (score >= 0.8)
- HIGH: `dangerous_ops_reachable` 5-9 OR `depth_to_first_danger <= 1` OR `dangerous_api_count` 2-4 OR `file_write`/`registry_write` present OR `command_execution` alone
- MEDIUM: `dangerous_api_count == 1` OR only transitive dangerous APIs via `callee_dangerous_apis` OR `dangerous_ops_reachable` 1-4
- LOW: No dangerous APIs direct or transitive AND `dangerous_ops_reachable == 0`

**Dimension 3 -- Complexity and Error Surface**

Data sources: dossier `complexity` + `resource_patterns` + `module_security` + step 3d `module_profile`.

Inputs:
- `complexity.instruction_count`, `complexity.branch_count`, `complexity.loop_count`
- `complexity.max_cyclomatic_complexity`, `complexity.has_canary`
- `resource_patterns.has_global_writes`, `resource_patterns.sync_operations`
- `module_security.cfg`
- From step 3d: `module_profile.security_posture.canary_coverage_pct` -- **0-100 percentage scale** (a value of `0.2` means 0.2% of functions have canaries, NOT 20%; a value of `78.5` means 78.5%). If low, the module has weak stack protection overall.
- Note: if `asm_metrics.has_syscall` is true (direct syscall / `int 2Eh`), flag as HIGH risk signal (potential evasion of security hooks)

Scoring:
- HIGH: `instruction_count >= 500` OR (`loop_count >= 5` AND `max_cyclomatic_complexity >= 5`) OR (`has_canary == false` AND `instruction_count >= 100`) OR (sync ops present AND global writes) OR `has_syscall == true` OR (`canary_coverage_pct < 30` AND `has_canary == false`)
- MEDIUM: `instruction_count` 100-499 OR `loop_count` 2-4 OR `branch_count >= 20`
- LOW: `instruction_count < 100` AND `loop_count <= 1` AND `has_canary == true`

**Dimension 4 -- Decompiler Confidence**

Data sources: verify results.

Inputs:
- `verify.total_issues`, `verify.critical`, `verify.high`, `verify.moderate`, `verify.low`
- `verify.max_severity`
- `verify.issues[].category` and `verify.issues[].summary`

Scoring:
- LOW confidence: `critical > 0` OR `high >= 2` -- decompiler bugs may hide real vulnerabilities
- MEDIUM confidence: `high == 1` OR `moderate >= 2`
- HIGH confidence: only `low` severity issues or none

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
| C8 | **Module-wide stack protection** | What is `canary_coverage_pct` (see Data Interpretation Rules)? Does this function have a canary? Do its critical callees? |

In the Specific Concerns section of the report, prefix each concern with its checklist ID: e.g., `[CRITICAL -- C1]`, `[HIGH -- C3]`. Concerns that don't map to a checklist item use `[SEVERITY -- Cx]` where x = "extra".

**Overall Risk Calculation**

1. Start with the highest individual dimension score as baseline
2. Escalate by one level if 3+ dimensions score HIGH or above
3. Escalate by one level if Decompiler Confidence is LOW
4. Cap at CRITICAL

**Required Output Format for Risk Assessment**

The Risk Assessment section of the report must contain these parts in order:

1. **Dimension table**: one row per dimension with its score and the key data points that drove it
2. **Overall Risk**: the computed level with a one-line rationale citing which dimensions drove it
3. **Specific concerns**: ranked list where each concern cites its checklist ID and the dossier/verify/classify field it comes from. Assign severity using these rules:
   - **CRITICAL**: Directly achieves code execution, privilege escalation, or authentication bypass with attacker-controlled input. Must have a confirmed data flow from untrusted source to dangerous sink (cite the backward_trace or dossier field).
   - **HIGH**: Could achieve the above with one additional precondition (bypass of an intermediate check, TOCTOU race win, etc.), OR a confirmed missing security check in an active code path.
   - **MEDIUM**: Theoretical weakness requiring multiple preconditions, OR a defense-in-depth gap (e.g., missing canary on callees when the function itself has one). A concern about untested flag combinations without a confirmed path to dangerous behavior is MEDIUM at most.
   - **LOW**: Code quality concern, untested path, or cosmetic issue that does not directly affect security posture.

   Every concern must cite its source field (e.g., `Source: dossier.dangerous_operations.security_relevant_callees`) and its checklist ID (e.g., `C1`).
4. **Confidence and caveats**: decompiler confidence level + any data gaps (e.g., "static reachability does not capture RPC dispatch")
5. **Code-level observations** (optional, max 3): Observations from reading the decompiled code that are NOT already covered by the checklist concerns above. Rules:
   - Maximum **3** observations. Do not pad with low-value items.
   - Each must reference a **specific line, variable, or code pattern** in the decompiled output.
   - Each must be labeled: `"Manual review -- not from automated dossier data"`.
   - These do **not** contribute to or alter the risk dimension scores.
   - Severity follows the same CRITICAL/HIGH/MEDIUM/LOW criteria as other specific concerns.
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
3. Within the same tier, sort by `dangerous_ops_reachable` count from the callchain step (descending). If callchain data is unavailable for a callee, use the count of dangerous APIs listed in `callee_dangerous_apis` as a proxy.
4. Output the top 5-7 functions in the table. Include the danger tier, `dangerous_ops_reachable` count, and a brief reason.
5. After the table, optionally add one line suggesting a `/callgraph`, `/data-flow`, or `/taint` command for deeper investigation.

### 8. Verify concerns with fresh eyes

After Step 7 produces the draft report, launch a **separate subagent** to independently validate the specific concerns and their severity assignments. This step eliminates confirmation bias by ensuring the verifier has never seen the synthesis reasoning -- only the raw data and the claims.

**Subagent call:**

Use `subagent_type="re-analyst"` (or `"verifier"`) with `readonly: true`. Pass it a self-contained prompt containing:

1. The **severity criteria** (the CRITICAL/HIGH/MEDIUM/LOW rules from the Required Output Format above)
2. The **raw dossier summary JSON** (from `<run_dir>/dossier/summary.json`)
3. The **raw attack surface summary** (from `<run_dir>/attack_surface/summary.json`, if available)
4. The **raw backward trace summary** (from `<run_dir>/backward_trace/summary.json`, if available)
5. The **module profile `security_posture` section** (canary_coverage_pct, ASLR/DEP/CFG/SEH)
6. The **Data Interpretation Rules** (canary_coverage_pct is 0-100 scale, param_risk_score is 0-1, etc.)
7. The **draft specific concerns list** with their assigned severities, checklist IDs, and cited source fields
8. The **draft dimension scores** with their key data points

**Subagent prompt template:**

```
You are an independent reviewer of a security audit report. You have NOT
participated in writing this report. Your job is to verify that each
specific concern's severity is correctly assigned according to the rubric,
and that each dimension score follows the scoring thresholds.

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
- canary_coverage_pct: 0-100 scale (0.2 = 0.2%, NOT 20%)
- param_risk_score: 0.0-1.0 scale
- noise_ratio: 0.0-1.0 scale (0.48 = 48%)

RAW DATA:
<paste dossier summary JSON>
<paste attack surface summary JSON>
<paste backward trace summary JSON>
<paste module profile security_posture>

DRAFT DIMENSION SCORES:
<paste dimension table rows>

DRAFT SPECIFIC CONCERNS:
<paste numbered concern list with severities>

For each concern, return a JSON object:
{
  "concern_number": N,
  "original_severity": "LEVEL",
  "verified_severity": "LEVEL",
  "change": "none" | "upgraded" | "downgraded",
  "reason": "brief explanation citing the rubric rule and data field"
}

Also verify each dimension score against the thresholds. If a dimension
score is wrong, return the correction.

Return the complete list as a JSON array.
```

**Handling the verifier response:**

- If the verifier returns `"change": "none"` for all concerns, proceed with the draft as-is.
- If any concern is downgraded or upgraded, update the severity in the final report and add a note in the Confidence and Caveats section: `"Severity for concern #N was adjusted from X to Y by independent verification."`
- If a dimension score is corrected, update it and recompute the Overall Risk using the calculation rules.
- The verifier's response is NOT included verbatim in the report -- only the corrections are applied.

**Subagent description:** Use a description like `"Verify audit concerns for <function_name>"`.

> **Execution note**: Step 8 runs after Step 7 completes. It adds one subagent round-trip but catches severity inflation/deflation and data misinterpretation before the user sees the report.

## Output

Present the audit report in chat. Always save a copy to `extracted_code/<module_folder>/reports/audit_<function_name>_<short_timestamp>.md` (e.g. `audit_RAiLaunchAdminProcess_20260221_1343.md`). The `<short_timestamp>` format is `YYYYMMDD_HHMM`. Create the `reports/` directory if it does not exist.

## Error Handling

- **Module not found**: List available modules via `find_module_db.py --list` and ask the user to choose
- **Function not found**: Run a fuzzy search via `search_functions_by_pattern()` and suggest close matches
- **DB access failure**: Report the error with the DB path and suggest running `/health`
- **Missing decompiled code**: Report which functions lack decompiled output; offer to verify via assembly only
- **Security dossier build failure**: Log the error, report partial results from completed skill steps
