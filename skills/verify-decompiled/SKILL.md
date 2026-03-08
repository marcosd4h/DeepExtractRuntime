---
name: verify-decompiled
description: Verify decompiler accuracy by comparing IDA Hex-Rays decompiled output against assembly ground truth, detecting and surgically fixing specific inaccuracies such as wrong access sizes, missing NULL guards, collapsed operations, return type errors, and signedness mismatches. Use when the user asks to verify decompiled code, check decompiler accuracy, find decompiler errors, compare assembly vs decompiled output, validate Hex-Rays output, correct decompilation bugs, or mentions decompiler verification or accuracy checking.
cacheable: true
---

# Verify Decompiled Code

## Purpose

Find and fix **specific places where Hex-Rays got something wrong** compared to the assembly. The output is the original decompiler output with minimal, targeted fixes -- not a rewrite.

This is **not** lifting and **not** annotation. Variables stay as `a1`/`v5`, struct access stays as `*((_QWORD *)a1 + 14)`, gotos stay as gotos. It fixes only what the decompiler got wrong.

### How It Differs from Lifting

|                    | verify-decompiled (this)                 | code-lifting         |
| ------------------ | ---------------------------------------- | ---------------------------- |
| **Goal**           | Fix decompiler errors only               | Full rewrite for readability |
| **Scope**          | Surgical patches to specific lines       | Entire function rewritten    |
| **Variable names** | Keeps `a1`, `v5` as-is                   | Renames everything           |
| **Control flow**   | Keeps gotos/labels as-is                 | Simplifies and restructures  |
| **Speed**          | Fast -- automated scan + targeted fixes  | Deep analysis per function   |
| **When to use**    | Before reading/analyzing decompiled code | When you need clean source   |

**verify-decompiled makes decompiler output trustworthy.** Lifting makes it readable. They're sequential -- verify first, then lift if needed.

## Data Sources

### SQLite Databases (required)

Individual analysis DBs in `extracted_dbs/` contain both `assembly_code` (ground truth) and `decompiled_code` (to verify) for each function. The assembly is essential -- verification cannot work without it.

### Finding a Module DB

Reuse the decompiled-code-extractor skill's `find_module_db.py`:

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py --list
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll
```

### Quick Cross-Dimensional Search

To search across function names, signatures, strings, APIs, classes, and exports in one call:

```bash
python .agent/helpers/unified_search.py <db_path> --query "SearchTerm"
python .agent/helpers/unified_search.py <db_path> --query "SearchTerm" --json
```

## Utility Scripts

Pre-built scripts in `scripts/` handle data extraction and automated heuristic scanning. Run from the workspace root.

### scan_module.py -- Triage All Functions (Start Here)

Scan every function in a module for decompiler accuracy issues. Produces a ranked list by severity.

```bash
# Full scan -- all functions, all severities
python .agent/skills/verify-decompiled/scripts/scan_module.py <db_path>

# Only CRITICAL and HIGH severity issues
python .agent/skills/verify-decompiled/scripts/scan_module.py <db_path> --min-severity HIGH

# Top 20 most problematic functions
python .agent/skills/verify-decompiled/scripts/scan_module.py <db_path> --top 20

# JSON output for programmatic use
python .agent/skills/verify-decompiled/scripts/scan_module.py <db_path> --json
```

Output: ranked function list with issue counts by severity, category distribution, and detailed findings for the top functions.

### verify_function.py -- Deep Verification (Per Function)

Extract assembly and decompiled code with automated heuristic analysis for a single function.

```bash
# By function name
python .agent/skills/verify-decompiled/scripts/verify_function.py <db_path> AiCheckSecureApplicationDirectory

# By function ID (from scan_module.py output)
python .agent/skills/verify-decompiled/scripts/verify_function.py <db_path> --id 124

# Search for functions
python .agent/skills/verify-decompiled/scripts/verify_function.py <db_path> --search "BatLoop"

# JSON output
python .agent/skills/verify-decompiled/scripts/verify_function.py <db_path> AiCheckSecureApplicationDirectory --json
```

Output: assembly stats, decompiled stats, automated findings with severity, full assembly code, and full decompiled code for agent-driven deep comparison.

## Workflows

> **Grind loop**: When verifying **multiple functions** (e.g., "verify all
> CRITICAL issues" or "fix decompiler issues across this module"), create
> `.agent/hooks/scratchpads/{session_id}.md` (use the Session ID from your
> injected context) after Step 1 with one checkbox per function to verify.
> The stop hook re-invokes automatically until all are done.
> See the grind-loop-protocol rule for the format.

```
Verification Progress:
- [ ] Step 1: Triage -- scan_module.py to identify functions with issues
- [ ] Step 2: Extract -- verify_function.py on the target function
- [ ] Step 3: Review automated findings from the script output
- [ ] Step 4: Deep comparison -- assembly vs decompiled (agent-driven)
- [ ] Step 5: Produce issue list with severity, evidence, and fixes
- [ ] Step 6: Generate corrected decompiled code with fix annotations
```

When targeting multiple functions, repeat Steps 2-6 for each function
and check them off in the scratchpad. Set Status to `DONE` when finished.

**Step 1**: Triage the Module

Run `scan_module.py` to get a ranked list of functions with decompiler issues:

```bash
python .agent/skills/verify-decompiled/scripts/scan_module.py <db_path>
```

Start with the highest-severity functions. Functions with score 0 are likely trustworthy as-is.

**Step 2**: Extract Function Data

For each target function, run `verify_function.py`:

```bash
python .agent/skills/verify-decompiled/scripts/verify_function.py <db_path> --id <function_id>
```

This provides assembly stats, decompiled stats, automated findings, and both code blocks.

**Step 3**: Review Automated Findings

The script runs these heuristic checks:

| Check                 | Detects                                                       | Reliability |
| --------------------- | ------------------------------------------------------------- | ----------- |
| Return type mismatch  | Mangled name vs decompiled return type                        | High        |
| Call count mismatch   | Missing or extra function calls                               | Medium      |
| Branch count mismatch | Missing branches/conditionals                                 | High        |
| NULL check detection  | test+jz/jnz pairs without corresponding if-statements         | High        |
| Signedness mismatch   | Unsigned assembly branches with signed decompiled comparisons | Medium      |
| Access size mismatch  | DWORD in assembly shown as QWORD in decompiled                | Medium      |
| Decompiler artifacts  | do/while(0), LOBYTE, HI/LODWORD wrappers                      | High        |

**These are heuristic -- they flag potential issues.** The agent must confirm each finding by examining the specific assembly and decompiled lines.

**Step 4**: Deep Comparison (Agent-Driven)

Using the assembly code (ground truth) and decompiled code from the script output, perform manual comparison. The automated heuristics **cannot** reliably detect these critical issue types -- the agent must find them:

**1. Collapsed Multi-Step Operations (CRITICAL)**

Assembly pattern:

```
mov rcx, [rbx+18h]      ; load pointer
test rcx, rcx            ; NULL check
jz  skip_call            ; skip if NULL
call SomeFunc            ; only called if non-NULL
```

Decompiled (wrong): `v10 = SomeFunc(*((_QWORD *)a1 + 3));` -- NULL guard invisible.

**2. Wrong Offset Calculations (HIGH)**

Assembly: `mov eax, [rcx+1CBh]` (byte offset 0x1CB)
Decompiled: `*((_DWORD *)a1 + 459)` (offset = 459 _ 4 = 0x72C -- wrong!)
Fix: `_(\_DWORD _)((char _)a1 + 0x1CB)`

**3. Lost Volatile Reads (MODERATE)**

Assembly has two consecutive identical reads (volatile/polling):

```
mov eax, [rbx+30h]
mov eax, [rbx+30h]    ; second read is intentional
```

Decompiled shows only one read.

**4. Missing Error Checks (CRITICAL)**

Assembly has `test eax, eax / jz error_path` between two operations.
Decompiled shows the operations back-to-back with no error check.

**Step 5**: Produce Issue List

For each issue found (automated + agent-discovered), document:

```
DECOMPILER ACCURACY REPORT: FunctionName
Total issues found: N  (X critical, Y high, Z moderate, W low)

[SEVERITY] #N: Category (line NN) -- brief description
  Decompiled:  <the wrong decompiled line>
  Assembly:    <the correct assembly evidence>
  Impact:      <why this matters>
  Fix:         <the corrected line>
```

**Step 6**: Generate Corrected Code

Produce the original decompiled code with **only** the detected issues patched. Mark each fix with a comment:

```cpp
unsigned int __fastcall FunctionName(  // [FIX #3: return type]
    const unsigned __int16 *a1, unsigned int *a2)
{
  // ... original decompiler code untouched ...

  v5 = *(_DWORD *)((char *)a1 + 0x70);  // [FIX #2: DWORD at byte offset 0x70]

  v9 = *((_QWORD *)a1 + 3);             // [FIX #1: separated from call]
  if ( v9 )                               // [FIX #1: NULL guard restored]
      v10 = SomeFunc(v9);

  // ... rest of original code untouched ...
}
```

## Issue Categories and Severity

| Severity     | Meaning                                         | Examples                                                |
| ------------ | ----------------------------------------------- | ------------------------------------------------------- |
| **CRITICAL** | Missing operations that change behavior         | Missing NULL guard, missing error check, missing branch |
| **HIGH**     | Wrong types/sizes affecting data interpretation | DWORD shown as QWORD, signed vs unsigned mismatch       |
| **MODERATE** | Wrong return/parameter types                    | `__int64` vs `int`, mistyped pointer                    |
| **LOW**      | Decompiler artifacts, cosmetic                  | `do/while(0)`, redundant casts, LOBYTE wrappers         |

## Direct Helper Module Access

For programmatic use without skill scripts:

- `helpers.resolve_function(db, name_or_id)` -- Resolve function by name or ID
- `helpers.extract_function_calls(source)` -- Extract function calls from decompiled source
- `helpers.scan_assembly_struct_accesses(asm)` -- Scan assembly for struct access patterns
- `helpers.classify_api(api_name)` -- Classify Win32/NT API calls by category

## Integration with Other Skills

This skill fixes the *input* to lifting; the verifier agent validates the *output*. The full pipeline is: verify-decompiled -> code-lifting -> verifier agent.

| Task | Recommended Skill |
|------|-------------------|
| Triage which functions to distrust before reading code | analyze-ida-decompiled |
| Lift corrected decompiled code to clean, readable C++ | code-lifting / batch-lift |
| Independently confirm lifted code matches assembly | verifier subagent (`subagent_type="verifier"`) |
| Hunt for bugs where binary behavior differs from decompiled output | security-dossier |
| Trace call chains through verified functions | callgraph-tracer |

## Performance

| Operation | Typical Time | Notes |
|-----------|-------------|-------|
| Verify single function | ~2-3s | Assembly vs decompiled comparison |
| Scan full module | ~30-60s | Checks all decompiled functions |

## Additional Resources

- For detailed verification methodology and assembly patterns, see [reference.md](reference.md)
- For DB schema and JSON field formats, see [data_format_reference.md](../../docs/data_format_reference.md)
- For lifting verified code, see [code-lifting](../code-lifting/SKILL.md)
- For code analysis, see [analyze-ida-decompiled](../analyze-ida-decompiled/SKILL.md)
