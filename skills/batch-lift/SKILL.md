---
name: batch-lift
description: Lift related groups of decompiled functions together with shared context -- C++ class methods, call chains, or entire subtrees from exports. Builds shared struct definitions, determines dependency order, and generates coordinated output. Use when the user asks to lift multiple related functions, an entire class, a call chain, all methods of a type, everything reachable from an export, or mentions batch lifting or contextual lifting.
cacheable: false
depends_on: ["decompiled-code-extractor", "callgraph-tracer", "reconstruct-types"]
---

# Batch / Contextual Code Lifting

## Purpose

Lift related function groups together instead of one-at-a-time. Individual function lifting loses context -- struct definitions are incomplete, constants are defined in isolation, and cross-references between related functions are missed.

This skill orchestrates **batch lifting** by:

1. Collecting the right set of functions (class methods, call chains, export subtrees)
2. Building **shared struct definitions** accumulated across ALL functions in the set
3. Determining **dependency order** (lift callees before callers)
4. Generating a single cohesive `.cpp` output with constants, structs, and functions

**Builds on**: [decompiled-code-extractor](../decompiled-code-extractor/SKILL.md) (function data extraction), [code-lifting](../code-lifting/SKILL.md) (per-function lifting workflow), [callgraph-tracer](../callgraph-tracer/SKILL.md) (call chain discovery), [reconstruct-types](../reconstruct-types/SKILL.md) (struct scanning).

**This is NOT security analysis.** The goal is faithful, readable code reconstruction.

## When NOT to Use

- Lifting a single function in isolation -- use **code-lifting** or the **code-lifter** agent
- Vulnerability scanning or security analysis of functions -- use **memory-corruption-detector** or **logic-vulnerability-detector**
- Understanding what a function does without rewriting it -- use **re-analyst** or `/explain`
- Reconstructing types without lifting code -- use **reconstruct-types**
- Tracing call chains without lifting the functions -- use **callgraph-tracer**

## Batch Lifting Modes

| Mode          | Trigger                              | What Gets Collected                                |
| ------------- | ------------------------------------ | -------------------------------------------------- |
| Class methods | "Lift all methods of ClassName"      | All methods by mangled name + signature references |
| Call chain    | "Lift FuncX and everything it calls" | BFS from FuncX, N levels of internal calls         |
| Export-down   | "Lift from export X down 3 levels"   | From named export, N levels of internal calls      |

## Data Sources

- **Analysis DBs** (`extracted_dbs/{module}_{hash}.db`): decompiled code, assembly, xrefs, vtables
- **Tracking DB** (`extracted_dbs/analyzed_files.db`): module name to DB path mapping
- **Generated code** (`extracted_code/{module}/file_info.json`): function summaries, class groupings

### Finding the Module DB

Reuse the decompiled-code-extractor skill's script:

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py --list
```

### Quick Cross-Dimensional Search

To search across function names, signatures, strings, APIs, classes, and exports in one call:

```bash
python .agent/helpers/unified_search.py <db_path> --query "SearchTerm"
python .agent/helpers/unified_search.py <db_path> --query "SearchTerm" --json
```

## Utility Scripts

All scripts are in `scripts/`. Run from the workspace root. Auto-resolve workspace root and `.agent/helpers/` imports.

### collect_functions.py -- Identify the Function Set (Start Here)

Multi-mode function collection with dependency ordering.

```bash
# All methods of a C++ class
python .agent/skills/batch-lift/scripts/collect_functions.py <db_path> --class CSecurityDescriptor

# Call chain from a function, 3 levels deep
python .agent/skills/batch-lift/scripts/collect_functions.py <db_path> --chain BatLoop --depth 3

# Call chain by function ID
python .agent/skills/batch-lift/scripts/collect_functions.py <db_path> --chain _ --id <function_id> --depth 3

# From a named export down 2 levels
python .agent/skills/batch-lift/scripts/collect_functions.py <db_path> --export AiLaunchProcess --depth 2

# From an export by function ID
python .agent/skills/batch-lift/scripts/collect_functions.py <db_path> --export _ --id <function_id> --depth 2

# JSON output for piping
python .agent/skills/batch-lift/scripts/collect_functions.py <db_path> --class CSecurityDescriptor --json
```

Output: function list with IDs, signatures, dependency order (callees first), role classification (constructor/destructor/method), and external call summary.

### prepare_batch_lift.py -- Generate the Lift Plan

Extracts all data for the function set, scans shared struct patterns, and produces the full lift plan.

```bash
# From collect_functions.py JSON output (recommended pipeline)
python .agent/skills/batch-lift/scripts/collect_functions.py <db_path> --class CSecurityDescriptor --json > funcs.json
python .agent/skills/batch-lift/scripts/prepare_batch_lift.py --from-json funcs.json

# Direct function IDs
python .agent/skills/batch-lift/scripts/prepare_batch_lift.py <db_path> --ids 42,43,44,45

# Summary only (no code -- good for initial overview)
python .agent/skills/batch-lift/scripts/prepare_batch_lift.py --from-json funcs.json --summary

# Structs only (for progressive accumulation)
python .agent/skills/batch-lift/scripts/prepare_batch_lift.py --from-json funcs.json --structs-only
```

Output includes:

- Shared struct definitions (accumulated across ALL functions)
- Ordered lift plan (callees first)
- Per-function: signatures, decompiled code, assembly, xrefs, strings, vtable contexts

### Scripts from Other Skills (Reused)

| Script                     | Skill                | Purpose                                      |
| -------------------------- | -------------------- | -------------------------------------------- |
| `find_module_db.py`        | decompiled-code-extractor | Map module name to DB path                   |
| `list_functions.py`        | decompiled-code-extractor | Search/list functions in a DB                |
| `extract_function_data.py` | decompiled-code-extractor | Extract single function data (for deep-dive) |
| `unified_search.py`        | helpers              | Cross-dimensional search (names, strings, APIs, classes, exports) |
| `chain_analysis.py`        | callgraph-tracer     | Cross-module chain analysis                  |
| `scan_struct_fields.py`    | reconstruct-types    | Deep struct field scanning (assembly-backed) |
| `generate_header.py`       | reconstruct-types    | Generate compilable header files             |

## Workflows

### Workflow 1: "Lift All Methods of a C++ Class"

The primary use case. Lifts all methods of a class with a shared struct definition.

> **Grind loop**: After Step 2, create `.agent/hooks/scratchpads/{session_id}.md`
> (use the Session ID from your injected context) with one checkbox per method
> to lift plus setup/assembly steps. The stop hook will re-invoke you
> automatically if you run out of context before finishing.
> See the grind-loop-protocol rule for the format.

```
Batch Lift Progress:
- [ ] Step 1: Find the module DB
- [ ] Step 2: Collect all class methods
- [ ] Step 3: Generate the lift plan with shared structs
- [ ] Step 4: Review struct definitions and lift order
- [ ] Step 5: Lift each function in dependency order
- [ ] Step 6: Assemble final .cpp output
- [ ] Step 7: Independent verification -- verifier agent confirms equivalence
```

**Step 1**: Find the module DB

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll
```

**Step 2**: Collect all class methods

```bash
python .agent/skills/batch-lift/scripts/collect_functions.py <db_path> --class CSecurityDescriptor --json > funcs.json
```

Review the output to confirm the function set. The script finds methods by:

- Mangled name prefix (`??0ClassName@@`, `?Method@ClassName@@`)
- Signature references (functions that take `ClassName*` parameters)

**Step 3**: Generate the lift plan

```bash
python .agent/skills/batch-lift/scripts/prepare_batch_lift.py --from-json funcs.json
```

For deeper struct analysis (assembly-backed, more accurate), also run:

```bash
python .agent/skills/reconstruct-types/scripts/scan_struct_fields.py <db_path> --class CSecurityDescriptor
```

**Step 4**: Review before lifting:

- Check the struct definition -- are field offsets and types reasonable?
- Check the lift order -- constructors/destructors should come first
- Identify functions without decompiled code (mark as skip)

**Step 5**: Lift each function following the [code-lifting](../code-lifting/SKILL.md) workflow (Steps 2-10), but with these batch-specific additions:

- **Use the shared struct definition** for all pointer arithmetic conversion
- **Update the struct** as new fields are discovered during each function's lift
- **Reference already-lifted callees** by their clean signatures (not IDA names)
- **Accumulate constants** -- when a constant is identified in one function, apply it to all
- **Check off each function** in the scratchpad as you complete it

**Step 6**: Assemble the final output file (see Output Format below).

**Step 7**: Run independent verification (see [Independent Verification](#independent-verification-verifier-agent) below). Verify the most critical functions first -- constructors, destructors, and any methods with complex control flow. Set scratchpad Status to `DONE` after verification passes or issues are resolved.

### Workflow 2: "Lift a Call Chain"

Lift a function and everything it calls within the module, with shared context.

> **Grind loop**: After Step 3, create `.agent/hooks/scratchpads/{session_id}.md`
> (use the Session ID from your injected context) with one checkbox per function
> to lift. The stop hook re-invokes automatically.

```
Batch Lift Progress:
- [ ] Step 1: Find the module DB
- [ ] Step 2: Collect the call chain
- [ ] Step 3: Review and optionally prune the function set
- [ ] Step 4: Generate the lift plan
- [ ] Step 5: Lift in dependency order (callees first)
- [ ] Step 6: Assemble final output
- [ ] Step 7: Independent verification -- verifier agent confirms equivalence
```

**Step 1**: Find the module DB

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py cmd.exe
```

**Step 2**: Collect the call chain (start with summary to see scope)

```bash
python .agent/skills/batch-lift/scripts/collect_functions.py <db_path> --chain BatLoop --depth 3
```

**Step 3**: Review the function count. If too many, reduce depth or use the callgraph-tracer to identify the most interesting subtree:

```bash
python .agent/skills/callgraph-tracer/scripts/chain_analysis.py <db_path> BatLoop --depth 3 --summary
```

Then create the JSON manifest:

```bash
python .agent/skills/batch-lift/scripts/collect_functions.py <db_path> --chain BatLoop --depth 2 --json > funcs.json
```

**Step 4**: Generate the lift plan

```bash
python .agent/skills/batch-lift/scripts/prepare_batch_lift.py --from-json funcs.json
```

**Step 5**: Lift in dependency order. The plan puts callees first, so each function's callees are already lifted when you reach it. Apply the same batch principles as Workflow 1 Step 5.

**Step 6**: Assemble (see Output Format).

**Step 7**: Run independent verification (see [Independent Verification](#independent-verification-verifier-agent) below). Focus on the root function and any complex callees.

### Workflow 3: "Lift from Export Down N Levels"

Starts from a module's exported function and lifts its implementation subtree.

```bash
# Collect from export
python .agent/skills/batch-lift/scripts/collect_functions.py <db_path> --export AiLaunchProcess --depth 3 --json > funcs.json

# Generate lift plan
python .agent/skills/batch-lift/scripts/prepare_batch_lift.py --from-json funcs.json
```

Follows the same Steps 4-7 as Workflow 2, including independent verification. The script confirms whether the starting function is actually in the module's export table.

## Independent Verification (Verifier Agent)

After assembling the final output (Step 6 in all workflows), run independent verification using the **verifier subagent**. The verifier operates with fresh context -- it has no knowledge of your lifting process, preventing confirmation bias.

### Why verify after batch lifting?

Batch lifting compounds error risk: a wrong struct offset propagated to all functions, a constant misidentified early that infects later lifts, or cross-reference naming inconsistencies. The verifier catches these systematically.

### How to verify

**1. Save the assembled output** to a file (e.g., `<module>_<class>_lifted.cpp`).

**2. Launch the verifier** for the most critical functions using the `Task` tool with `subagent_type="verifier"`. For a batch of N functions, prioritize:

- **Always verify**: constructors, destructors, exported functions, functions with complex control flow (high branch count)
- **Verify if time allows**: simple getters/setters, small helper functions

For each function to verify, provide the verifier with:

- The **DB path**
- The **function name** (or function ID)
- The **path to the saved lifted code file**

Example prompt for the verifier subagent:

> Verify that the lifted code at `<lifted_file_path>` faithfully represents the original binary behavior for function `<function_name>` in `<db_path>`.
>
> Run `compare_lifted.py` with `--json`, then perform block-by-block manual verification using `extract_basic_blocks.py`. Report your verdict (PASS/WARN/FAIL) with evidence for any discrepancies.

The verifier runs automated checks (call count, branch count, string literals, API names, globals, memory offsets) and then performs manual block-by-block comparison against assembly.

**3. Act on the verdict:**

| Verdict | Action |
| ------- | ------ |
| **PASS** | Deliver the lifted code as-is |
| **WARN** | Review the specific warnings; fix if genuine, then re-verify or deliver with noted caveats |
| **FAIL** | Fix the identified discrepancies, update the shared struct if needed (changes propagate to all functions), then re-run the verifier on affected functions |

**4. For large batches (10+ functions)**, verify in stages:

- Verify the constructor first (it defines the struct)
- Verify 2-3 complex methods
- If those pass, spot-check 1-2 simpler methods
- If any fail due to shared struct issues, fix the struct and re-verify all functions that use the affected fields

## Progressive Struct Accumulation

During batch lifting, struct definitions improve as each function reveals new field accesses:

1. **Start** with the auto-detected struct from `prepare_batch_lift.py`
2. **Lift function 1** (typically the constructor) -- discover initial fields and types
3. **Update the struct** with field names and refined types from the constructor
4. **Lift function 2** -- may reveal additional fields not touched by the constructor
5. **Update the struct** again -- add new fields, adjust padding
6. **Continue** through all functions, updating the struct each time
7. **Final struct** has all fields discovered across the entire class

To get the accumulated struct at any point:

```bash
python .agent/skills/batch-lift/scripts/prepare_batch_lift.py --from-json funcs.json --structs-only
```

For the most accurate results, use the reconstruct-types skill's assembly-backed scanner:

```bash
python .agent/skills/reconstruct-types/scripts/scan_struct_fields.py <db_path> --class ClassName
```

## Output Format

The final output is a single `.cpp` file with everything in dependency order:

```cpp
// =============================================================================
// Batch-lifted code: CSecurityDescriptor (appinfo.dll)
// Functions: 12, lifted from analysis DB
// =============================================================================

#pragma once
#include <windows.h>
#include <stdint.h>

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
#define SD_REVISION     1
#define DACL_PRESENT    0x04

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------
struct CSecurityDescriptor;

// ---------------------------------------------------------------------------
// Reconstructed types
// ---------------------------------------------------------------------------

/**
 * CSecurityDescriptor -- Reconstructed from 12 function(s)
 */
struct CSecurityDescriptor {
    SECURITY_DESCRIPTOR sd;      // +0x00
    PACL pDacl;                  // +0x28
    PSID pOwner;                 // +0x30
    uint32_t flags;              // +0x38
};

// ---------------------------------------------------------------------------
// Functions (dependency order: callees first)
// ---------------------------------------------------------------------------

// 1/12: Constructor
CSecurityDescriptor::CSecurityDescriptor() { ... }

// 2/12: Destructor
CSecurityDescriptor::~CSecurityDescriptor() { ... }

// 3/12: SetDacl (called by Initialize, SetSecurityDescriptor)
HRESULT CSecurityDescriptor::SetDacl(PACL pDacl, BOOL bDefaulted) { ... }

// ... remaining functions ...
```

## Batch-Specific Lifting Rules

In addition to the [code-lifting](../code-lifting/SKILL.md) rules:

1. **Shared struct definition**: All functions in the batch use the SAME struct. Update it as fields are discovered but keep all functions consistent.

2. **Consistent naming**: If `a1->field_30` is renamed to `pDacl` in one function, use `pDacl` in ALL functions that access the same field.

3. **Cross-reference comments**: When a lifted function calls another function in the batch, reference it by its lifted name, not the IDA name.

4. **Constants propagate**: `#define` constants discovered in one function apply to the entire batch.

5. **Constructor first**: If the set includes a constructor, lift it first -- constructors initialize all fields and reveal the struct layout most clearly.

## Direct Helper Module Access

For programmatic use without skill scripts:

- `helpers.batch_resolve_functions(db, names_or_ids)` -- Resolve multiple functions at once
- `helpers.batch_extract_function_data(db, func_ids)` -- Extract data for multiple functions
- `helpers.parse_class_from_mangled(name)` -- Extract class name from mangled function names
- `helpers.CallGraph.from_functions(functions)` -- Build call graph for dependency ordering
- `helpers.scan_decompiled_struct_accesses(src)` -- Scan struct access patterns in decompiled code
- `helpers.scan_assembly_struct_accesses(asm)` -- Scan struct access patterns in assembly

## Integration with Other Skills

| Task | Recommended Skill |
|------|-------------------|
| Extract function data before lifting | decompiled-code-extractor |
| Reconstruct struct types for field access | reconstruct-types |
| Verify lifted code against assembly | verify-decompiled |
| Trace call chains to find related functions | callgraph-tracer |
| Classify functions to prioritize lifting targets | classify-functions |

## Performance

| Operation | Typical Time | Notes |
|-----------|-------------|-------|
| Collect related functions | ~2-5s | Scales with class method count |
| Prepare batch context | ~3-8s | Includes dependency ordering |
| Full class lift (5-10 methods) | ~30-60s | Includes struct accumulation |
| Large batch (20+ functions) | ~2-5min | Use grind loop for batches >10 |

## Additional Resources

- For individual function lifting workflow, see [code-lifting](../code-lifting/SKILL.md)
- For call graph analysis and chain tracing, see [callgraph-tracer](../callgraph-tracer/SKILL.md)
- For deep struct/class reconstruction, see [reconstruct-types](../reconstruct-types/SKILL.md)
- For code analysis, see [analyze-ida-decompiled](../analyze-ida-decompiled/SKILL.md)
- For detailed technical reference, see [reference.md](reference.md)
- For DB schema and JSON field formats, see [data_format_reference.md](../../docs/data_format_reference.md)
