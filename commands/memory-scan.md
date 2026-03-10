# Memory Scan

## Overview

Scan a module for memory corruption vulnerabilities: buffer overflows,
integer overflow/truncation, use-after-free, double-free, and format
string bugs. Runs four parallel scanners, merges and verifies findings,
then presents a prioritized report.

In **single-function mode**, the target is typically an external entry point
(RPC handler, COM vtable method, export). The command collects the callee
chain from that entry point (default depth 4, configurable via `--depth N`)
and scans every callee, then cross-references with taint analysis to
identify which findings are reachable from attacker-controlled inputs.

Usage:
- `/memory-scan <module>`
- `/memory-scan <module> <function>`
- `/memory-scan <module> <function> --depth 6`
- `/memory-scan <module> <function> --depth 0`
- `/memory-scan <module> --top 20`

## IMPORTANT: Execution Model

This command executes immediately. Run the full pipeline and deliver
the completed report without pausing for confirmation.

## Execution Context

> **IMPORTANT**: Any inline Python that imports `helpers.*` must run with `cd <workspace>/.agent`
> (so the `.agent/` directory is on `sys.path`), **not** from the workspace root.
> Script invocations like `python .agent/skills/.../script.py` can be run from the workspace root
> because those scripts manage their own path setup.

## Workspace Protocol (Single-Function Chain Mode)

When running a single-function deep chain scan, use the `.agent/workspace/`
handoff pattern to manage large payloads across phases:

1. Create `.agent/workspace/<module>_memscan_<function>_<timestamp>/`
2. Store per-phase results in the run directory using the step mapping below
3. Use `manifest.json` as the source of truth for completed phases
4. Keep only compact summaries and step status in coordinator context
5. Read full `results.json` files only when needed for synthesis

**Step mapping:**

| Phase | Step name | Contents |
|-------|-----------|----------|
| A | `chain` | `collect_functions.py` output (chain, depth map, external calls) |
| B | `scanners/<function_id>` | Per-function scanner results |
| B2 | `extractions/<function_id>` | `extract_function_data.py` output (decompiled + assembly) |
| C | `taint` | `taint_function.py` output |
| D | `merged` | Merged + deduplicated findings |
| D (verify) | `verified` | `verify_findings.py` heuristic pass output |
| D2 | `skeptical_verify` | Subagent verification results |
| Report | `report` | Final structured JSON report |

All script calls that support `--workspace-dir` and `--workspace-step`
should use them. For scripts that don't, write the output manually to the
step directory.

## Steps

### Step 0: Preflight Validation

Validate arguments using `helpers.command_validation.validate_command_args("memory-scan", {"module": "<module>"})`.
If validation fails, report the errors and stop. On success, use `result.resolved["db_path"]` for subsequent script calls.

1. **Resolve module DB**
   Use `find_module_db.py` to resolve the module name to a database path.
   If not found, list available modules and ask user.

2. **Single-function mode** (if function specified)
   Follow the deep chain scan workflow below. Skip steps 3-5.

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
   - Module identity and security features (ASLR, DEP, CFG, canary)
   - Summary: total findings by category and severity
   - Top findings table: rank, severity, function, category, API, score, confidence
   - For each top finding: evidence lines, path, guards, verification notes
   - Recommended next steps: `/audit` for CRITICAL/HIGH findings, `/taint` for deeper flow analysis

---

## Single-Function Deep Chain Scan

When a function name or `--id` is specified, the scanners examine not just
the target function but its entire callee chain. The chain depth defaults
to 4 but is configurable via `--depth N` (parsed from the user's command
text). `--depth 0` disables chain scanning and scans only the target
function.

### Phase A: Collect callee chain

```bash
python .agent/skills/batch-lift/scripts/collect_functions.py <db_path> \
    --chain <function_name> --depth <N> --skip-library --json
```

`<N>` is the user-specified depth (default 4). This returns all internal
callees reachable from the entry point via BFS, with function IDs and
depths. `--skip-library` excludes WIL/STL/WRL/CRT boilerplate. Store the
`functions` array, the depth map, and the `external_calls_summary` dict
for later attribution and the chain summary.

If `--depth 0` is specified, skip this phase entirely and scan only the
target function (run all 4 scanners with `--function <name>` and skip to
Phase D merge).

If chain collection fails, fall back to scanning the single function only.

### Phase B: Scan every callee in the chain (parallel)

For each function in the chain (including the entry point itself), run all
4 scanners using `--id <fid>`:

```bash
python .agent/skills/memory-corruption-detector/scripts/scan_buffer_overflows.py <db_path> --id <fid> --json
python .agent/skills/memory-corruption-detector/scripts/scan_integer_issues.py <db_path> --id <fid> --json
python .agent/skills/memory-corruption-detector/scripts/scan_use_after_free.py <db_path> --id <fid> --json
python .agent/skills/memory-corruption-detector/scripts/scan_format_strings.py <db_path> --id <fid> --json
```

Parallelize across functions -- batch 4 functions at a time (16 parallel
scanner calls). For large chains (>20 callees), scan depth 1-2 fully first,
then depth 3-4.

### Phase B2: Extract and read decompiled code

After Phase B completes, extract and read the decompiled code of every
security-relevant function in the chain. This enables semantic analysis
that automated scanners cannot perform.

**Step 1 -- Filter chain to security-relevant functions.**
The chain from Phase A already has `--skip-library` applied. Additionally
skip functions whose names match known utility patterns:

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

Also skip functions at depth >= 4 that produced zero findings from the
Phase B automated scanners.

Record which functions were skipped and which were kept for the chain summary.

**Step 2 -- Extract decompiled code.**
For each security-relevant function, extract decompiled code and assembly:

```bash
python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py <db_path> --id <fid> --json
```

Batch 4 extractions in parallel. For large chains (>15 security-relevant
functions), prioritize depth 0-2 first, then depth 3+.

**Step 3 -- Read and analyze.**
The agent MUST read the `decompiled_code` field from each extraction result
and perform semantic analysis. This is not optional -- the code must be
read, not just extracted. Look for:

- Buffer size calculations that could overflow or truncate
- Allocation-to-copy mismatches where the copy size exceeds the allocated size
- Use-after-free patterns where handles or pointers are used after cleanup
- Stack buffer overflows from unbounded string operations
- Format string injection from attacker-controlled format arguments
- Integer truncation in size parameters passed to allocation or copy APIs

Code-review findings are added to the merge pool in Phase D alongside
automated scanner findings. Prefix them with `(Source: manual code review)`
in the evidence section.

**Step 4 -- Assembly fallback.**
When the decompiled code for a finding is ambiguous (e.g., unclear whether
a size is checked, or the decompiler may have elided a bounds check), read
the `assembly_code` field from the same extraction to verify ground truth.

**Step 5 -- Caller-context propagation.**
When reading the entry point's decompiled code (depth 0), identify the
security-relevant operations (size validations, bounds checks, safe API
usage, null checks) that occur **before each callee invocation**. Record
these as a `caller_guards` map:

```
caller_guards = {
  "AipBuildAxISParams": ["StringCchCatW used (bounded) at line 450",
                         "buffer size validated at line 440"],
  "AiOpenWOWStubs": ["path validated via GetFullPathNameW at line 380"]
}
```

This map is built by semantic analysis while reading the code -- no script
required. In Phase D, attach `caller_guards` to each callee finding. If a
finding's category is `buffer_overflow` or `integer_overflow` and the
caller already bounds-checks the relevant parameter before the call,
annotate: `caller_mitigated: true, caller_guard: "<description>"`. The
skeptical verifier in Phase D2 receives this annotation.

### Phase C: Taint analysis (mandatory, parallel with Phase B2)

```bash
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> \
    --function <name> --depth <N> --json
```

Use the same `<N>` depth as Phase A.

Taint analysis is **mandatory** in single-function chain mode. It traces
attacker-controlled parameters forward through the call chain to dangerous
sinks, with guard/bypass analysis. The output identifies which callees
receive tainted data and what guards protect the paths.

The taint results MUST be summarized in the final report even when no sinks
are reached -- the logic effects (branch steering, array indexing, size
arguments) and parameter flow are valuable context for understanding
attacker levers.

If taint analysis fails, continue with Phase B/B2 findings without taint
cross-referencing, but note the failure in the report.

### Phase D: Merge and verify with depth attribution

Collect all findings from Phase B and Phase B2 (code review) and merge:

1. Deduplicate by `(function_id, category)`, keep the highest score
2. Annotate each finding with its **depth from the entry point** (from the
   Phase A chain data)
3. Attach `caller_guards` from Phase B2 Step 5 to each callee finding
4. Cross-reference with taint (Phase C): if a finding's function appears on a
   tainted path from the entry point, boost its score and mark it
   `taint_reachable: true`
5. Sort by: taint-reachable first, then by score descending

If findings exist, run the heuristic verification pass:

```bash
python .agent/skills/memory-corruption-detector/scripts/verify_findings.py \
    --findings <merged.json> --db-path <db_path> --json
```

Apply verification adjustments: FALSE_POSITIVE removed, UNCERTAIN at 50%
score reduction.

### Phase D2: Skeptical subagent verification

After the heuristic `verify_findings.py` pass, launch a subagent for
deeper, skeptical verification of the top confirmed findings.

**When to trigger:**
- Only for findings that survived the heuristic pass with confidence >=
  LIKELY (score >= 0.7)
- Cap at **top 5 findings** by verified score
- If zero findings survive the heuristic pass, skip Phase D2

**Subagent invocation:**
Use `subagent_type="security-auditor"` with `readonly: true`. For each finding,
pass:

1. The finding itself (category, function name, summary, severity, score,
   evidence lines, dangerous op, guards on path, caller_guards annotation)
2. The function's decompiled code (from Phase B2 extraction)
3. The function's assembly code (from Phase B2 extraction)
4. Taint analysis results for this function (from Phase C, if on a tainted path)
5. The entry point context (which entry point, at what depth)

**Subagent prompt template:**

```
You are a skeptical security auditor. You have NOT participated in scanning
this function. Your job is to independently evaluate whether each finding
below is a TRUE POSITIVE or FALSE POSITIVE by reading the decompiled code
and assembly with fresh eyes. Apply the security-auditor's severity criteria
and reject common rationalizations (see your "Rationalizations to Reject" table).

RULES:
- Use "does / is / will" in verdicts. NEVER use "might / could / possibly".
- For each finding, argue AGAINST it first (devil's advocate), then argue
  FOR it. Only after both sides are evaluated, render a verdict.
- Check whether the dangerous operation has compensating controls in the
  caller chain that the scanner could not see.
- Check whether the decompiled code accurately represents the assembly
  (Hex-Rays can elide conditions, merge branches, or mistype values).
- If the finding is about a missing bounds check, verify in assembly that
  the check is truly absent (not just optimized differently by the decompiler).

BUG CLASSES (memory scan):
- buffer_overflow: copy/write operation exceeds allocated buffer size (heap or stack)
- integer_overflow: arithmetic overflow in size calculation before allocation or copy
- integer_truncation: wide-to-narrow cast on size value before allocation or copy
- use_after_free: pointer/handle used after being freed/closed
- double_free: same allocation freed twice without intervening realloc
- format_string: attacker-controlled format argument to printf-family API

SAFE API ALTERNATIVES (finding may be FP if these are used):
- StringCchCatW / StringCchCopyW (bounded) vs wcscat / wcscpy (unbounded)
- UIntAdd / UIntMult / SizeTAdd (safe arithmetic) vs raw + / * on sizes
- wcscat_s / wcscpy_s (bounded) vs wcscat / wcscpy (unbounded)

FINDINGS TO VERIFY:
<for each finding: category, summary, severity, evidence lines,
 dangerous_op, guards_on_path, caller_guards, depth, taint_reachable>

DECOMPILED CODE (<function_name>):
<paste decompiled code>

ASSEMBLY CODE (<function_name>):
<paste assembly code>

TAINT CONTEXT (if available):
<paste taint findings for this function>

CALLER CONTEXT (if available):
<paste caller_guards for this function>

For each finding, return:
{
  "function_name": "...",
  "category": "...",
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

**Batching:** If 3-5 findings across different functions, batch into a
single subagent call. If >5 functions, use 2 parallel subagent calls.

### Phase D3: Attack narrative synthesis

After Phase D2, connect related confirmed findings into coherent attack
narratives.

**When to trigger:**
- Only when 2+ confirmed findings remain after verification
- Skip if all findings are in the same function at depth 0

**How it works:**
Group confirmed findings by:
1. Shared data flow (findings on the same taint path from entry point)
2. Shared depth band (same or adjacent depths, related APIs)
3. Complementary primitives (e.g., "integer overflow" in size calc +
   "buffer overflow" in subsequent copy = overflow-to-overwrite chain)

For each group of 2+ related findings, generate a 1-2 paragraph attack
narrative that describes the attack story end-to-end. Each narrative cites
its constituent finding numbers.

Example:

> **Attack Narrative 1: Heap overflow via integer truncation in allocation
> chain**
>
> An attacker-controlled size parameter flows from the entry point to
> AipBuildBuffer (finding #2, depth 2) where it is truncated from UINT64
> to UINT32 before passing to LocalAlloc. The subsequent memcpy at depth 3
> uses the original un-truncated size (finding #4, depth 3 in AipCopyData),
> writing past the allocated heap buffer. Together these findings describe
> a controlled heap overflow primitive.

Findings that don't belong to any narrative group are listed individually.

**Report structure:**

- Module identity and security features (ASLR, DEP, CFG, canary) -- read
  from `extracted_code/<module>/module_profile.json` field `security_posture`
- **Chain summary**: ASCII tree grouped by depth with function names. Mark
  functions with confirmed findings using `*`. Mark functions whose code
  was read (no findings) using `+`. Truncate long lists with `...` but
  always show functions that had findings.

```
Entry point: <function_name> (depth 0)
  |-- depth 1 (<N> callees): FuncA*, FuncB, FuncC+, FuncD*, ...
  |-- depth 2 (<N> callees): FuncE*, FuncF+, ...
  |-- depth 3 (<N> callees): FuncG, ...
  |-- depth 4 (<N> callees): FuncH, ...
  |-- depth 5 (<N> callees): FuncI, ...
  +-- depth 6 (<N> callees): FuncJ, ...
  * = confirmed findings  + = code reviewed (no findings)
```

- **External call surface** (mandatory): Below the tree, list the most
  security-relevant external APIs called anywhere in the chain. Data source:
  `external_calls_summary` from Phase A `collect_functions.py --json`
  output. Filter to memory-relevant APIs (allocation: `LocalAlloc`,
  `HeapAlloc`, `RtlAllocateHeap`; copy: `memcpy`, `memmove`, `wcscpy_s`,
  `wcscat_s`; process/thread APIs; file APIs; handle APIs). End with a
  brief characterization (e.g., "allocation + copy chain",
  "string manipulation chain", "file I/O + buffer chain").

```
External call surface: LocalAlloc, RtlAllocateHeap, memcpy, wcscpy_s,
  CreateFileW, GetFullPathNameW -- allocation + file I/O chain.
```

- **Findings table** with depth column: rank, severity, function, depth,
  category, API, score, taint-reachable
- For each finding: evidence lines, call path from entry point, taint flow
  (if reachable), guards on path, caller context (if caller_mitigated),
  verification notes, source (scanner or manual code review)
- **Attack narratives** (if 2+ related findings were grouped)
- **Taint flow summary**: which parameters have logic effects (branch
  steering, size arguments, array indexing), which sinks were reached with
  what guards. If no sinks were reached, state that explicitly and list
  the logic effects as attacker levers.
- **Verification summary**: N findings submitted for independent
  verification. M confirmed, K rejected, J severity-adjusted.
- If findings exist at depth > 0 but not at depth 0: highlight that the
  entry point itself is clean but its callees are not
- Recommended next steps: `/audit` on specific flagged callees,
  `/memory-scan <module> <callee>` to deep-scan a callee as its own entry
  point

### Phase E: Zero-findings enrichment

When the full chain scan (entry point + all callees) and taint analysis
produce 0 memory corruption findings, run enrichment in parallel:

```bash
python .agent/skills/security-dossier/scripts/build_dossier.py <db_path> --function <name> --json
python .agent/skills/classify-functions/scripts/classify_function.py <db_path> --function <name> --json
```

Use these plus the Phase C taint results to produce an informed report:

- **Defensive patterns**: from dossier dangerous-ops (absence of unsafe
  APIs, presence of bounded alternatives like StringCchCatW)
- **Security-relevant API surface**: from dossier dangerous operations and
  outbound call categories
- **Complexity snapshot**: from dossier complexity assessment (instruction
  count, cyclomatic complexity, loop count)
- **Taint flow summary**: from Phase C -- which parameters reach which
  sinks, what guards protect them, whether any paths are unguarded (even
  without memory bugs, this gives actionable context)
- **Targeted next steps**: derived from classification category AND
  taint/chain results:
  - `privilege` / `process_launch` -> suggest `/logic-scan` and `/audit` on
    specific callees from chain analysis
  - `file_io` / `registry` -> suggest `/taint` for path traversal
  - Unguarded taint paths -> suggest `/audit <module> <callee>` on the
    specific unguarded callee
  - Callees with high dangerous-op density -> suggest
    `/memory-scan <module> <callee>` to scan them as their own entry point

---

## Error Handling

| Failure | Recovery |
|---------|----------|
| Module not found | List available modules, ask user |
| Function not found | Fuzzy search, suggest matches |
| Scanner script fails | Report error, continue with results from other scanners |
| No findings | Report "no memory corruption patterns detected" as a valid result |
| Verification fails | Present unverified findings with note |
| Chain collection fails | Fall back to scanning the single function only (current behavior) |
| Taint analysis fails | Present chain scan findings without taint cross-reference; note the failure |
| Chain too large (>50 callees) | Scan depth 1-2 fully, sample top-complexity functions at depth 3-4 |
| Subagent verification fails | Present findings with heuristic verification only; note subagent failure |

## Output

Present a structured report with these sections:

### Header
Module name, binary name, function count, security features (ASLR, DEP, CFG, canary).
Read from `extracted_code/<module>/module_profile.json` field `security_posture`.

### Summary Table
Category counts and severity distribution.

### Findings (top N, default 10)
For each finding:
- Severity and confidence
- Function name and ID
- Depth from entry point (single-function mode)
- Category and dangerous API
- Evidence: relevant code lines
- Call path from entry point (single-function mode)
- Taint reachability (single-function mode)
- Guards on path (if any)
- Caller context (if caller_mitigated)
- Verification notes
- Source (scanner or manual code review)

### Recommended Next Steps
Suggest 3-5 concrete follow-up commands for the most interesting findings.

### Auto-Save (Single-Function Chain Mode)

Always save a structured JSON report to
`extracted_code/<module_folder>/reports/memory_scan_<function>_<YYYYMMDD_HHMM>.json`
at the end of every chain scan. Create the `reports/` directory if it does
not exist. The JSON contains:

```json
{
  "scan_type": "memory_scan",
  "entry_point": "<function_name>",
  "module": "<module_name>",
  "timestamp": "<ISO timestamp>",
  "chain": {
    "total_functions": 0,
    "depth_distribution": {},
    "external_call_surface": []
  },
  "findings": [],
  "rejected_findings": [],
  "taint_summary": {},
  "attack_narratives": [],
  "verification_summary": {
    "heuristic_pass": {"confirmed": 0, "false_positive": 0},
    "skeptical_pass": {"true_positive": 0, "false_positive": 0, "severity_adjusted": 0}
  },
  "workspace_dir": "<path>"
}
```

Mention the saved path at the end of the chat report.

**Module-wide mode:** Save when the user asks.
