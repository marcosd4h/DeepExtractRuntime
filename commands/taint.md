# Taint Analysis

## Overview

Trace attacker-controlled function inputs forward to dangerous sinks and backward to caller origins, highlighting what sensitive functions are reached, what guards must be bypassed, and how tainted data affects internal logic. Designed for vulnerability research.

The text after `/taint` specifies the **module**, **function**, and optional flags:

- `/taint appinfo.dll AiLaunchProcess` -- trace all params forward (default)
- `/taint appinfo.dll AiLaunchProcess --params 1,3` -- trace specific params
- `/taint appinfo.dll AiLaunchProcess --params 1 --depth 3` -- deeper recursion
- `/taint appinfo.dll AiLaunchProcess --direction both` -- forward + backward
- `/taint appinfo.dll AiLaunchProcess --direction backward` -- caller origins only
- `/taint appinfo.dll AiLaunchProcess --cross-module` -- trace across DLL boundaries
- `/taint appinfo.dll AiLaunchProcess --cross-module --cross-depth 3` -- deeper cross-module
- `/taint appinfo.dll AiLaunchProcess --cross-module --cross-depth 2` -- full context with trust analysis
- `/taint appinfo.dll --from-entrypoints` -- auto-discover top entry points and taint-trace each across modules
- `/taint appinfo.dll --from-entrypoints --top 10 --min-score 0.4` -- top 10 above 0.4 attack score

If no function is specified (and `--from-entrypoints` is not used), ask the user.

## IMPORTANT: Execution Model

**This is an execute-immediately command. Do NOT present anything for user confirmation.** Run and write the final taint report straight to the chat as your response. The user expects to see the completed analysis.

## Execution Context

> **IMPORTANT**: Any inline Python that imports `helpers.*` must run with `cd <workspace>/.agent`
> (so the `.agent/` directory is on `sys.path`), **not** from the workspace root.
> Script invocations like `python .agent/skills/.../script.py` can be run from the workspace root
> because those scripts manage their own path setup.

## Workspace Protocol

When running single-function taint analysis or `--from-entrypoints` batch
mode, use the `.agent/workspace/` handoff pattern to manage large payloads
across phases:

1. Create `.agent/workspace/<module>_taint_<function>_<timestamp>/`
2. Store per-phase results in the run directory using the step mapping below
3. Use `manifest.json` as the source of truth for completed phases
4. Keep only compact summaries and step status in coordinator context
5. Read full `results.json` files only when needed for synthesis

**Shell setup rules (required before any redirect):**

- Always assign `WORKDIR` as an **absolute path** from the workspace root.
  Relative paths break shell redirects when the current directory differs
  from where the path was composed.
- Always `mkdir -p "$WORKDIR/<step_name>"` **before** any `>` redirect into
  that directory. The shell opens the output file before Python runs; if the
  directory does not exist the command fails silently with "No such file or
  directory" and the script never executes.
- Never use `2>&1` when capturing `--json` output. Stderr carries structured
  warning JSON; merging it into stdout corrupts the JSON document and causes
  parse errors downstream. Always redirect stderr separately:
  `> "$WORKDIR/<step>/results.json" 2>"$WORKDIR/<step>/stderr.txt"`.

```bash
# Correct workspace bootstrap pattern
WORKDIR="$(pwd)/.agent/workspace/<module>_taint_<function>_<timestamp>"
mkdir -p "$WORKDIR/taint"
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> \
    --id <fid> --params <N> --depth <D> --json \
    > "$WORKDIR/taint/results.json" \
    2> "$WORKDIR/taint/stderr.txt"
```

**Step mapping (single-function mode):**

| Phase | Step name | Contents |
|-------|-----------|----------|
| Taint | `taint` | `taint_function.py` output |
| B2 | `extractions/<function_id>` | `extract_function_data.py` for sink-path functions |
| D2 | `skeptical_verify` | Subagent verification results |
| Report | `report` | Final structured JSON report |

**Step mapping (`--from-entrypoints` mode):**

| Phase | Step name | Contents |
|-------|-----------|----------|
| Per-EP | `entrypoints/<function_id>` | Per-entry-point taint results |
| B2 | `extractions/<function_id>` | `extract_function_data.py` for sink-path functions |
| D2 | `skeptical_verify` | Verification across all entry points |
| Report | `report` | Aggregated report |

**Step mapping (`--cross-module` mode):**

| Phase | Step name | Contents |
|-------|-----------|----------|
| Taint | `taint` | `trace_taint_cross_module.py` output |
| B2 | `extractions/<module>/<function_id>` | Sink-path extractions (may span modules) |
| D2 | `skeptical_verify` | Subagent verification results |
| Report | `report` | Final structured JSON report |

All script calls that support `--workspace-dir` and `--workspace-step`
should use them. For scripts that don't, write the output manually to the
step directory.

## Steps

### Step 0: Preflight Validation

Validate arguments using `helpers.command_validation.validate_command_args("taint", {"module": "<module>", "function": "<function>"})`.
If validation fails, report the errors and stop. On success, use `result.resolved["db_path"]` for subsequent script calls.

### Step 1: Locate the function

Use the **function-index** skill for fast lookup:

```bash
python .agent/skills/function-index/scripts/lookup_function.py <function_name> --json
```

Or find the module DB first:

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py <module_name>
```

Once located, note `function_id` and `db_path`.

### Step 2: Run taint analysis

```bash
# Forward (default) -- where does tainted data go?
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> --id <fid> --json

# Forward with specific params and depth
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> --id <fid> --params 1,3 --depth 3 --json

# Both directions
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> --id <fid> --direction both --json

# Backward only -- where does tainted data come from?
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> --id <fid> --direction backward --json

# Cross-module -- trace tainted data across DLL boundaries
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> --id <fid> --cross-module --json

# Cross-module with deeper recursion (2 DLL hops)
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> --id <fid> --cross-module --cross-depth 2 --json

# Dedicated cross-module orchestrator (groups findings by boundary, trust analysis, COM/RPC)
python .agent/skills/taint-analysis/scripts/trace_taint_cross_module.py <db_path> --id <fid> --cross-depth 2 --json

# Disable trust analysis or COM vtable resolution
python .agent/skills/taint-analysis/scripts/trace_taint_cross_module.py <db_path> --id <fid> --no-trust-analysis --json
python .agent/skills/taint-analysis/scripts/trace_taint_cross_module.py <db_path> --id <fid> --no-com-resolve --json

# Batch: auto-discover top entry points and taint-trace each across modules
python .agent/skills/taint-analysis/scripts/trace_taint_cross_module.py <db_path> --from-entrypoints --json
python .agent/skills/taint-analysis/scripts/trace_taint_cross_module.py <db_path> --from-entrypoints --top 10 --min-score 0.4 --json
```

### Step 3: Extract and read code for taint-path functions

After Step 2 completes, extract and read the decompiled code of every
function that appears in any forward taint path. This enables semantic
confirmation that automated taint tracing cannot perform, regardless of
the path's assigned severity.

**Step 3a -- Identify functions to extract.**
From the taint output, collect all functions that appear on any forward
taint path, at any severity level. Include the entry point function
itself, all intermediate callees on each path, and the sink functions.
Skip functions whose names match known utility patterns:

- `memset*`, `memcpy*`, `memmove*`
- `atexit`, `_onexit*`, `__dllonexit*`
- `_lock*`, `_unlock*`
- `_guard_*`
- `String*Worker*`, `String*Validate*`
- `WIN32_FROM_*`
- `wil_details_*`
- `Feature_*__private_*`
- `TraceLogging*`, `_tlg*`
- `ApiSetQuery*`
- `_lambda_*`

**Step 3b -- Extract decompiled code.**
For each function in the taint chain:

```bash
python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py <db_path> --id <fid> --json
```

Batch 4 extractions in parallel. For large taint trees (>15 path functions),
prioritize functions closest to sinks first, then work backward toward the
entry point.

**Step 3c -- Read and analyze.**
The agent MUST read the `decompiled_code` field from each extraction result
and perform semantic analysis. This is not optional -- the code must be
read, not just extracted. Look for:

- Whether the dangerous sink is genuinely reachable with the tainted data
  (the taint tracer uses xref-based call discovery, which may include
  conditional paths that are not actually taken with the tainted value)
- Whether guards identified by the taint tracer are real -- check the
  condition text against the actual code; some "guards" may be unrelated
  conditionals that the tracer conservatively includes
- Additional mitigations the tracer may have missed (e.g., a callee that
  sanitizes input before forwarding it to the sink)
- Logic effects the tracer identified (branch steering, array indexing,
  size arguments) -- confirm these are genuine attacker levers

**Step 3d -- Assembly fallback.**
When the decompiled code for a finding is ambiguous (e.g., unclear whether
a guard truly protects the path, or the decompiler may have elided a
condition), read the `assembly_code` field from the same extraction to
verify ground truth.

**Step 3e -- Path-context annotation.**
While reading each function's code, record security-relevant operations
that protect the taint path. Build a `path_guards` map:

```
path_guards = {
  "AipBuildAxISParams": ["StringCchCatW used (bounded) at line 450",
                          "buffer size validated at line 440"],
  "LUASetUIAToken": ["GetTokenInformation(TokenElevationType) checked at line 285",
                      "token handle validated non-null at line 280"]
}
```

In Step 4, the skeptical verifier receives this annotation alongside each
finding. If a finding's sink has compensating controls that the tracer
missed, annotate: `path_mitigated: true, path_guard: "<description>"`.

### Step 4: Skeptical subagent verification

After Step 3, launch a subagent for independent, skeptical verification
of the top confirmed taint findings.

**When to trigger:**
- Only for forward findings with score >= 0.7 (CRITICAL or strong HIGH)
- Cap at **top 5 findings** by score
- If zero findings qualify, skip Step 4

**Subagent invocation:**
Use `subagent_type="security-auditor"` with `readonly: true`. For each finding,
pass:

1. The finding itself (sink name, sink category, severity, score, call
   path, guards on path, logic effects, path_guards annotation from Step 3e)
2. Decompiled code for **every function in the call chain** from entry
   point to sink, listed in call order (all extracted in Step 3b)
3. The sink function's assembly code (from Step 3b extraction)
4. Assembly code for any intermediate function whose decompiled code was
   flagged ambiguous during Step 3d analysis
5. Cross-module context (if `--cross-module` was used): boundary type,
   trust transition, parameter mapping

**Subagent prompt template:**

```
You are a skeptical security auditor. You have NOT participated in taint-
tracing this function. Your job is to independently evaluate whether each
taint finding below is a TRUE POSITIVE or FALSE POSITIVE by reading the
decompiled code and assembly with fresh eyes. Apply the security-auditor's
severity criteria and reject common rationalizations (see your
"Rationalizations to Reject" table).

RULES:
- Use "does / is / will" in verdicts. NEVER use "might / could / possibly".
- For each finding, argue AGAINST it first (devil's advocate), then argue
  FOR it. Only after both sides are evaluated, render a verdict.
- Read every function in the call chain in order. Confirm at each hop
  whether tainted data is genuinely forwarded to the next function or
  whether it is consumed, sanitized, or dropped before leaving.
- Check whether the tainted data actually reaches the dangerous sink on
  all execution paths, or only on a subset that requires additional
  preconditions.
- Check whether the guards identified by the tracer are genuine protective
  checks, or unrelated conditionals that happen to appear on the path.
- Check whether the decompiled code accurately represents the assembly
  (Hex-Rays can elide conditions, merge branches, or mistype values).
- If the finding claims a guard is attacker-controllable, verify in
  assembly that the guard condition truly depends on the tainted parameter.

BUG CLASSES (taint analysis):
- unguarded_sink: tainted data reaches dangerous API with no intervening
  checks -- verify the path has zero guards, not just weak ones
- weak_guard: guard exists but is attacker-controllable or easily bypassed
  -- verify the guard condition references tainted data
- trust_escalation: taint crosses from lower-trust to higher-trust module
  -- verify the trust boundary classification is correct
- logic_effect: tainted data steers branches / controls sizes / indexes
  arrays -- verify the effect is genuine and attacker-exploitable

SAFE API ALTERNATIVES (finding may be FP if these are used):
- StringCchCatW / StringCchCopyW (bounded) vs wcscat / wcscpy (unbounded)
- UIntAdd / UIntMult / SizeTAdd (safe arithmetic) vs raw + / * on sizes
- wcscat_s / wcscpy_s (bounded) vs wcscat / wcscpy (unbounded)

FINDINGS TO VERIFY:
<for each finding: sink, sink_category, severity, score, call_path,
 guards_on_path, logic_effects, path_guards, cross_module_context>

CALL CHAIN DECOMPILED CODE (entry point -> sink, in order):

[1] <entry_function_name> (entry point):
<paste decompiled code>

[2] <intermediate_function_name>:
<paste decompiled code>

...

[N] <sink_function_name> (sink):
<paste decompiled code>

ASSEMBLY CODE (<sink_function_name>):
<paste assembly code>

ASSEMBLY FALLBACK (functions flagged ambiguous in Step 3d):
[function_name]: <paste assembly code>

For each finding, return:
{
  "sink": "...",
  "sink_category": "...",
  "original_severity": "...",
  "verdict": "TRUE_POSITIVE" | "FALSE_POSITIVE",
  "verified_severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "devil_advocate": "argument against the finding",
  "supporting_evidence": "argument for the finding",
  "assembly_confirmation": "what the assembly shows",
  "reasoning": "final reasoning for the verdict"
}
```

**Handling the verifier response:**
- FALSE_POSITIVE: remove from the final report. Note in verification summary.
- Severity change: update severity. Note the adjustment and reasoning.
- TRUE_POSITIVE with same severity: keep as-is.

**Batching:** If 3-5 findings target different functions, batch into a
single subagent call. If >5 functions, use 2 parallel subagent calls.

### Step 5: Attack narrative synthesis

After Step 4, connect related confirmed taint findings into coherent
attack narratives.

**When to trigger:**
- Only when 2+ confirmed findings remain after verification
- Skip if all findings target the same single sink

**How it works:**
Group confirmed findings by:
1. **Fan-out** -- same entry parameter reaching multiple dangerous sinks
   (e.g., param 1 reaches both CreateProcessW and memcpy)
2. **Convergence** -- multiple parameters converging at the same sink
   function (e.g., params 1 and 3 both flow to a single LoadLibraryW call
   via different paths)
3. **Trust escalation chains** -- cross-module findings where taint crosses
   from a lower-trust to a higher-trust module (e.g., user_process ->
   system_service boundary)
4. **Complementary primitives** -- findings whose combination enables a
   stronger attack than either alone (e.g., branch steering via param 1 +
   size control via param 2 = controlled overflow)

For each group of 2+ related findings, generate a 1-2 paragraph attack
narrative that describes the attack story end-to-end. Each narrative cites
its constituent finding numbers.

Example:

> **Attack Narrative 1: Controlled heap overflow via converging taint
> paths**
>
> Attacker-controlled parameter 1 flows from AiLaunchProcess through
> AipBuildBuffer (finding #2) where it controls the allocation size
> argument to LocalAlloc. Parameter 3 flows through AipCopyData (finding
> #4) where it determines the copy length passed to memcpy. Because the
> allocation uses the truncated size from param 1 while the copy uses the
> original length from param 3, an attacker who controls both parameters
> can trigger a heap buffer overflow with controlled content.

Findings that don't belong to any narrative group are listed individually.

### Step 6: Present results

Parse the taint output, code review notes, verification results, and
attack narratives and present a structured report.

**Module identity header:**

- Module name, binary name, function count

**Taint path tree (single-function mode):**
Show the taint propagation tree from the entry point. Mark functions with
confirmed findings using `*`. Mark functions whose code was read and
confirmed clean using `+`. Show sink categories at leaf nodes.

```
Entry point: AiLaunchProcess (tainted params: 1, 3)
  param 1 -->
    |-- AipBuildBuffer* (size_argument -> LocalAlloc [memory_alloc])
    |-- AipValidatePath+ (guard: path validation at line 380)
    |-- AipBuildAxISParams+ (bounded: StringCchCatW)
  param 3 -->
    |-- AipCopyData* (copy_length -> memcpy [memory_unsafe])
    +-- AipLogEntry (branch_steering only)
  * = confirmed findings  + = code reviewed (no findings)
```

**For cross-module findings, extend the tree across DLL boundaries:**

```
Entry point: AiLaunchProcess (tainted params: 1)
  param 1 -->
    |-- [dll_import] appinfo.dll -> shlwapi.dll::PathCchCombine
    |     +-- trust: user_process -> user_process (no escalation)
    |-- [com_vtable] appinfo.dll -> combase.dll::CoCreateInstance*
    |     +-- trust: user_process -> system_service (ESCALATION)
    +-- AipBuildBuffer* (size_argument -> LocalAlloc [memory_alloc])
```

**For each forward finding (sorted by verified score):**

- Sink name and category (command_execution, memory_unsafe, etc.)
- Severity score and label (CRITICAL/HIGH/MEDIUM/LOW)
- Call path from tainted parameter to the sink
- Guards on the path: type, condition text, whether attacker-controllable, bypass difficulty
- Logic effects: branch steering, array indexing, loop bounds, size arguments
- Verification verdict and reasoning (if verified in Step 4)
- Path-context annotation (if path_guards were identified in Step 3e)
- Source: `taint tracer` or `taint tracer + code review`

**For backward callers:**

- Each caller and what they pass for the tainted parameters
- Origin classification (parameter, call_result, global, constant, etc.)
- Risk level (HIGH if origin is an export parameter, MEDIUM if call_result/global, NONE if constant)

**For cross-module findings (when --cross-module is used):**

- Boundary type (dll_import, com_vtable, rpc) and parameter mapping across each crossing
- Trust boundary transitions: source trust level -> target trust level, privilege escalation flags
- Accumulated guard chain across all modules in the path
- Return-value back-propagation: variables tainted via callee return values
- Trust-escalated findings (score boosted 1.25x when taint crosses to a higher-trust module)

**Attack narratives** (if 2+ related findings were grouped in Step 5)

**Verification summary:**
- N findings submitted for independent verification
- M confirmed (TRUE_POSITIVE), K rejected (FALSE_POSITIVE), J severity-adjusted

**Summary line:**

- Total sinks reached, severity breakdown, number of callers, high-risk origins
- Cross-module: boundary counts, trust escalations, return-tainted variables

**Follow-up suggestions:**

- `/audit <module> <function>` -- full security audit on flagged functions
- `/memory-scan <module> <function>` -- deep chain memory scan on flagged callees
- `/logic-scan <module> <function>` -- deep chain logic scan on flagged callees
- `/data-flow forward <module> <function> --param N` -- deeper data flow trace
- `/explain <module> <callee>` -- understand what a flagged callee does
- `/lift-class <module> <function>` -- lift flagged function to clean code for review

### Step 7: Zero-findings enrichment

When taint analysis produces 0 forward findings (no dangerous sinks
reached) and the direction includes forward, run enrichment in parallel:

```bash
python .agent/skills/security-dossier/scripts/build_dossier.py <db_path> --function <name> --json
python .agent/skills/classify-functions/scripts/classify_function.py <db_path> --function <name> --json
```

Use these plus the taint logic effects (branch steering, array indexing,
size arguments, loop bounds) to produce an informed report:

- **Defensive patterns**: from dossier dangerous-ops (absence of unsafe
  APIs, presence of bounded alternatives like StringCchCatW)
- **Security-relevant API surface**: from dossier dangerous operations and
  outbound call categories
- **Complexity snapshot**: from dossier complexity assessment (instruction
  count, cyclomatic complexity, loop count)
- **Logic effects summary**: from the taint output -- even without sinks,
  the logic effects show what attacker levers exist (which branches are
  steered by tainted data, which array indices are controlled, which size
  arguments are influenced). Present these prominently as they indicate
  attack surface quality.
- **Targeted next steps**: derived from classification category AND
  taint/logic effects:
  - `privilege` / `process_launch` -> suggest `/logic-scan` and `/audit` on
    specific callees from taint paths
  - `file_io` / `registry` -> suggest `/taint` with `--cross-module` for
    path traversal or registry injection across DLL boundaries
  - Logic effects on size arguments -> suggest `/memory-scan <module>
    <function>` to check for memory corruption at the influenced sites
  - Callees with high dangerous-op density -> suggest
    `/taint <module> <callee>` to trace them as their own entry point

---

## Auto-Save

**Single-function mode:** Always save a structured JSON report to
`extracted_code/<module_folder>/reports/taint_<function>_<YYYYMMDD_HHMM>.json`
at the end of every taint analysis. Create the `reports/` directory if it
does not exist. The JSON contains:

```json
{
  "scan_type": "taint_analysis",
  "entry_point": "<function_name>",
  "module": "<module_name>",
  "timestamp": "<ISO timestamp>",
  "direction": "forward|backward|both",
  "cross_module": false,
  "forward_findings": [],
  "backward_callers": [],
  "cross_module_findings": [],
  "logic_effects": [],
  "rejected_findings": [],
  "attack_narratives": [],
  "verification_summary": {
    "skeptical_pass": {
      "submitted": 0,
      "true_positive": 0,
      "false_positive": 0,
      "severity_adjusted": 0
    }
  },
  "enrichment": null,
  "workspace_dir": "<path>"
}
```

Mention the saved path at the end of the chat report.

**`--from-entrypoints` mode:** Always save. Use filename
`taint_entrypoints_<YYYYMMDD_HHMM>.json`. Include a top-level
`entry_points` array with per-EP summaries.

**`--cross-module` mode:** Always save. Use filename
`taint_<function>_crossmod_<YYYYMMDD_HHMM>.json`.

**Simple backward-only mode:** Save when the user asks.

---

## Error Handling

| Failure | Recovery |
|---------|----------|
| Module not found | List available modules via `find_module_db.py --list` and ask user |
| Function not found | Run fuzzy search and suggest close matches |
| No decompiled code | Report the gap; suggest `--assembly` traces if available |
| Subprocess timeout | Report partial results from completed parameter traces |
| No sinks found | Run zero-findings enrichment (Step 7); report logic effects |
| Code extraction fails for sink function | Present taint findings without code-level confirmation; note the gap |
| Subagent verification fails | Present findings with taint-only scoring; note subagent failure |
| Cross-module resolution fails | Report local findings only; note missing tracking DB |
| Taint tree too large (>30 path functions) | Extract all chain functions but batch in groups of 4; prioritize closest-to-sink first |
| From-entrypoints: no entry points discovered | Report that no attack-surface entry points were found; suggest manual function specification |
