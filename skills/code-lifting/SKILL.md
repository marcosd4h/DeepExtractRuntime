---
name: code-lifting
description: Lift and rewrite IDA Pro decompiled C/C++ functions into clean, readable, 100% functionally equivalent code using both decompiled output and assembly as ground truth. Defines the 11-step lifting workflow that the code-lifter agent follows. Use when the user asks to lift, rewrite, clean up, reconstruct, or improve decompiled functions, wants to make decompiled code readable while preserving exact behavior, or mentions code lifting.
cacheable: false
depends_on: ["decompiled-code-extractor", "reconstruct-types"]
---

# Code Lifting

## Purpose

Define the workflow and reference material for lifting IDA Pro decompiled
C/C++ functions into clean, readable source code that is **100%
functionally equivalent** to the original binary. Uses both the
decompiled C++ (structural base) and assembly code (ground truth) to
produce accurate, human-readable output.

This is a **workflow/recipe skill** -- it has no scripts of its own. The
code-lifter agent follows this workflow, using data extracted by the
[decompiled-code-extractor](../decompiled-code-extractor/SKILL.md)
skill and types from the
[reconstruct-types](../reconstruct-types/SKILL.md) skill.

**This is NOT security analysis.** Do not add vulnerability annotations,
security tags, trust boundary markers, or perform any
security/vulnerability research during lifting. The sole goal is
faithful, readable reconstruction.

## Data Sources

This skill uses function data extracted by the decompiled-code-extractor skill. Before starting a lift, extract the target function's data:

### Finding a Module DB

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py --list
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py <module_name>
```

### Extracting Function Data

```bash
python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py <db_path> <function_name>
```

### Quick Cross-Dimensional Search

To search across function names, signatures, strings, APIs, classes, and exports in one call:

```bash
python .agent/helpers/unified_search.py <db_path> --query "SearchTerm"
python .agent/helpers/unified_search.py <db_path> --query "SearchTerm" --json
```

The output includes decompiled C++, assembly, signatures, string
literals, xrefs, vtable contexts, global variable accesses, stack frame,
and loop analysis -- everything needed for lifting.

## Workflows

```
Lifting Progress:
- [ ] Step 1: Gather all function data (decompiled, assembly, signatures, context)
- [ ] Step 2: Validate decompiled code against assembly
- [ ] Step 3: Rename parameters from a1/a2 to meaningful names
- [ ] Step 4: Rename local variables from v1/v2 to meaningful names
- [ ] Step 5: Replace magic numbers with named constants
- [ ] Step 6: Reconstruct struct/class definitions from memory access patterns
- [ ] Step 7: Convert raw pointer arithmetic to struct field access
- [ ] Step 8: Simplify control flow (reduce gotos, clean up branches)
- [ ] Step 9: Add documentation and inline comments
- [ ] Step 10: Final verification -- every assembly path accounted for
- [ ] Step 11: Independent verification -- verifier agent confirms equivalence
```

**Step 1**: Gather Function Data

Always retrieve from the DB when possible -- it has assembly, which .cpp files lack.

Run `extract_function_data.py` to get everything at once:

```bash
python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py <db_path> <function_name>
```

This outputs all fields needed for lifting:

- Decompiled C++ code (structural base)
- Assembly code (ground truth -- **required** for accurate lifting)
- Both signatures (base + extended) and mangled name
- String literals (help identify function purpose)
- Outbound xrefs (what it calls -- identify API usage)
- Inbound xrefs (who calls it -- reveals usage context)
- VTable contexts (class hierarchy info)
- Global variable accesses, stack frame, loop analysis

If you don't know the DB path, run `find_module_db.py <module_name> --json` first. If you don't know the function name, run `list_functions.py <db_path> --search "<pattern>"` or use unified search: `python .agent/helpers/unified_search.py <db_path> --query "<term>"` to search across names, strings, APIs, and more in one call.

**Step 2**: Validate Against Assembly

The decompiled code is the **structural starting point** but assembly is the **ground truth**. Perform these sub-checks:

**2a. Map memory access patterns:**

- Every load/store in assembly must have a corresponding C++ operation
- Use instruction suffixes to verify data types: `mov eax,[...]` = DWORD, `mov rax,[...]` = QWORD, `movzx eax, byte ptr` = BYTE (zero-extended), `movsx` = sign-extended
- Confirm pointer arithmetic offsets match between assembly and decompiled code

**2b. Verify control flow:**

- Every branch/jump in assembly must map to a C++ path
- Identify SEH setup (`__try`/`__except`/`__finally`) from exception handler registration patterns
- Recognize synchronization primitives (`EnterCriticalSection`/`LeaveCriticalSection`, mutex ops)

**2c. Confirm calling convention:**

- x64 `__fastcall`: args in rcx, rdx, r8, r9; return in rax; shadow space at [rsp+0..0x1F]
- Verify return type matches rax usage
- Check that all side effects (global writes, volatile accesses) are preserved

**2d. Identify decompiler artifacts** -- common Hex-Rays artifacts to watch for:

- Spurious `do { ... } while(0)` wrappers
- `LOBYTE(v1) = expr` when a simple bool assignment suffices
- Redundant cast chains (e.g., `(unsigned int)(unsigned __int8)func()`)
- Reordered operations that don't match assembly instruction order
- Missing operations the decompiler optimized away

Correct all discrepancies based on assembly.

**Step 3**: Rename Parameters

Use these sources in priority order:

1. **Function signature** -- if typed names exist, use them directly
2. **Mangled name** -- decode C++ types (class names, parameter types)
3. **Type hints** -- `batdata *a1` suggests `batchFile`, `HANDLE a2` suggests `processHandle`
4. **Called API context** -- if `a2` is passed as the 2nd arg to `RegOpenKeyExW`, it is a registry subkey path; if `a3` feeds `CreateFileW` arg 1, it is a file path
5. **Usage context** -- how the parameter is used in the body

**Win32 naming conventions:** follow Hungarian-style where it aids clarity:

| Type         | Prefix         | Example                          |
| ------------ | -------------- | -------------------------------- |
| `HANDLE`     | `h`            | `hProcess`, `hFile`, `hEvent`    |
| `HWND`       | `hwnd`         | `hwndParent`, `hwndDialog`       |
| pointer      | `p`            | `pSecurityAttrs`, `pBuffer`      |
| wide string  | `wsz` / `lpsz` | `wszKeyPath`, `lpszFileName`     |
| count / size | `c` / `cb`     | `cItems`, `cbBuffer`             |
| flags / mask | none           | `accessFlags`, `dwDesiredAccess` |

**Step 4**: Rename Local Variables

IDA register comments hint at variable roles:

- `// eax` after a function call = return value -- name after what the function returns
- `// BYREF` = variable is passed by reference somewhere
- Stack variables (`[rsp+XXh]`) = genuine local storage

Name based on purpose: `statusCode`, `loopIndex`, `bufferPtr`, `outputLength`.

**From API context:** if a variable is assigned from `GetLastError()`, name it `lastError`; if from `RegQueryValueExW`, name it `registryValue` or `queryResult`; if it holds a COM interface pointer obtained via `QueryInterface`, name it after the interface (`pTaskService`, `pFolder`).

**Step 5**: Replace Magic Numbers

| Pattern                     | Strategy                                   |
| --------------------------- | ------------------------------------------ |
| Win32 constants (0x1FFFFF)  | Named SDK constant (`THREAD_ALL_ACCESS`)   |
| HRESULT values (0x80070005) | Named error (`E_ACCESSDENIED`)             |
| Message IDs (0x4000XXXX)    | `MSG_*` constant with ID in comment        |
| Struct type discriminants   | `#define NODE_TYPE_X` or enum              |
| Buffer sizes                | Named constant (`MAX_PATH`, `BUFFER_SIZE`) |
| Bit flags / masks           | Bitwise OR of named flags                  |

**Step 6**: Reconstruct Structs

When you see repeated `*((_QWORD *)obj + N)` patterns:

1. Collect ALL accesses to the same base pointer across the function
2. Compute byte offsets: `element_index * element_size` (e.g., `+14` for `_QWORD*` = offset 0x70)
3. Determine field types from access width (`_BYTE`=1, `_WORD`=2, `_DWORD`=4, `_QWORD`=8)
4. Build struct with proper field names, types, and padding for unknown regions
5. If related functions are available, cross-reference their accesses to fill gaps

For deeper struct analysis, use the reconstruct-types skill:

```bash
python .agent/skills/reconstruct-types/scripts/scan_struct_fields.py <db_path> --class <ClassName>
```

**Step 7**: Convert Pointer Arithmetic to Field Access

**Before:**

```cpp
v5 = *((_QWORD *)a1 + 14);   // byte offset 14*8 = 0x70
*(_DWORD *)a2 = 45;           // byte offset 0
```

**After:**

```cpp
commandName = cmdNode->commandName;   // +0x70
cmdNode->type = NODE_TYPE_LABEL;      // +0x00
```

Use `->` for struct field access. Include byte offset in a comment when helpful for verification.

**Step 8**: Simplify Control Flow

| IDA Pattern                        | Clean Form                          |
| ---------------------------------- | ----------------------------------- |
| `goto LABEL_X` at end of if-block  | `else` block                        |
| `if (cond) goto LABEL; ... LABEL:` | Invert condition, early return      |
| `do { ... } while(0)` wrapper      | Remove wrapper                      |
| Chained `if/goto` to same target   | Combine conditions with `\|\|`      |
| Multiple gotos to cleanup label    | Structured cleanup with single exit |

**Preserve exactly** these constructs -- they represent real control flow:

- **SEH exception handling**: `__try`/`__except`/`__finally` blocks must be reconstructed exactly as the assembly establishes them. Do not simplify or remove SEH constructs.
- **setjmp/longjmp**: Non-local jumps for error recovery are genuine gotos.
- **Lock pairs**: `EnterCriticalSection`/`LeaveCriticalSection` must appear on all execution paths as in the original. Do not restructure code in a way that changes which paths hold or release locks.

**Step 9**: Add Documentation

**Infer semantic purpose** -- go beyond literal description. Use string literals, called API names, and parameter types to determine what the function actually does at a business level.

Function doc block:

```cpp
/**
 * FunctionName - [infer high-level purpose from behavior, not literal description]
 *
 * [Explain what the function does and why]
 *
 * @param paramName  [business purpose, not just data type]
 * @return           [meaning of return value, not just type]
 */
```

**BAD** (literal, restates code):

```cpp
/** @brief Calls RegOpenKeyExW and checks the result.
 *  @param a1 A pointer. @param a2 A string. */
```

**GOOD** (semantic, insightful):

```cpp
/** @brief Opens the application compatibility registry key to check if
 *  the executable has a shim database entry.
 *  @param appPath Full path to the executable being launched.
 *  @param shimFlags Output flags indicating which compatibility shims apply. */
```

**Inline comments must explain "why", not restate "what":**

- Purpose of each code block and its role in the function's goal
- Non-obvious pointer arithmetic with byte offset annotations
- Win32 API calls: explain what they do _in this context_
- Loop invariants and exit conditions
- Constants and flags: what they mean, not just their value
- Memory lifecycle: why an allocation is made, when/how it's freed

**It is considered incomplete if the lifted function body lacks inline comments for non-trivial operations.**

**Step 10**: Final Verification

Before delivering the lifted code, confirm every item:

- [ ] Every assembly branch has a corresponding C++ path
- [ ] All memory operations (loads/stores) are accurately represented
- [ ] Memory access sizes match assembly (`mov eax` = DWORD, `mov rax` = QWORD, etc.)
- [ ] No functionality added or removed -- strictly 100% equivalent
- [ ] Return type and calling convention match assembly
- [ ] All called function names preserved exactly as original
- [ ] No decompiler variable names remain (a1, v2, arg_4, var_8, etc.)
- [ ] Data types and parameter names are consistent with the function signature
- [ ] Struct field offsets match the original pointer arithmetic
- [ ] SEH constructs (`__try`/`__except`/`__finally`) preserved exactly if present
- [ ] Lock acquire/release pairs balance on all execution paths (normal, early return, error, exception)
- [ ] Resource cleanup paths are complete (every alloc has a corresponding free on all exit paths)
- [ ] HRESULT/error handling paths match assembly branches (no missing or extra checks)
- [ ] Non-trivial operations have explanatory inline comments
- [ ] The output is syntactically valid C++

**Step 11**: Independent Verification (Verifier Agent)

After completing your own verification in Step 10, launch the **verifier subagent** for independent confirmation. The verifier operates with fresh context (no knowledge of your lifting process), which prevents confirmation bias.

**11a. Save the lifted code** to a temporary file:

```bash
# Save to a temp file in the workspace (the verifier reads from files)
# Use a descriptive name: <module>_<function>_lifted.cpp
```

**11b. Launch the verifier** using the `Task` tool with `subagent_type="verifier"`:

Provide the verifier with:

- The **DB path** (from Step 1)
- The **function name** (or function ID)
- The **path to the saved lifted code file**

Example prompt for the verifier subagent:

> Verify that the lifted code at `<lifted_file_path>` faithfully represents the original binary behavior for function `<function_name>` in `<db_path>`.
>
> Run `compare_lifted.py` with `--json`, then perform block-by-block manual verification using `extract_basic_blocks.py`. Report your verdict (PASS/WARN/FAIL) with evidence for any discrepancies.

The verifier will:

1. Run `compare_lifted.py` -- automated checks (call count, branch count, string literals, API preservation, globals, memory offsets)
2. Run `extract_basic_blocks.py` -- split assembly into basic blocks
3. Perform block-by-block manual comparison against the lifted code
4. Return a verdict (**PASS**, **WARN**, or **FAIL**) with evidence

**11c. Act on the verdict:**

| Verdict  | Action                                                                                     |
| -------- | ------------------------------------------------------------------------------------------ |
| **PASS** | Deliver the lifted code as-is                                                              |
| **WARN** | Review the specific warnings; fix if genuine, then re-verify or deliver with noted caveats |
| **FAIL** | Fix the identified discrepancies (go back to the relevant step), then re-run the verifier  |

**Why this matters:** Steps 2 and 10 are self-verification by the same agent that wrote the code. The verifier agent provides an independent second opinion with fresh eyes -- it has no memory of your lifting choices and checks purely against assembly ground truth.

## Output Format

Present lifted code as a single block:

1. `#define` / `enum` constants (if any)
2. Reconstructed struct definitions (if applicable)
3. Function documentation comment
4. The lifted function body

```cpp
// Constants
#define POLICY_DISABLED  1
#define MSG_DISABLED     0x40002729u

// Reconstructed structure (from offset analysis)
struct CmdNode {
    int type;                    // +0x00
    char _reserved[0x64];        // +0x04 (unknown fields)
    struct Redir *redirections;  // +0x68
    wchar_t *commandName;        // +0x70
    wchar_t *arguments;          // +0x78
    int flags;                   // +0x80
};

/**
 * BatLoop - Main batch file processing loop.
 *
 * Reads and executes commands from a batch file until
 * completion or error.
 *
 * @param batchFile  Batch processing state and file handle
 * @param cmdNode    Current command node to execute
 * @return           Exit code from batch execution
 */
int BatLoop(struct batdata *batchFile, struct CmdNode *cmdNode)
{
    // ... lifted function body ...
}
```

## Direct Helper Module Access

For programmatic use without skill scripts:

- `helpers.resolve_function(db, name_or_id)` -- Resolve a function by name or ID
- `helpers.extract_function_calls(source)` -- Extract function calls from decompiled source
- `helpers.scan_decompiled_struct_accesses(src)` -- Scan struct field access patterns
- `helpers.classify_api(api_name)` -- Classify a Win32/NT API call by category
- `helpers.IDA_TO_C_TYPE` -- IDA type to C type mapping for type corrections
- `helpers.parse_class_from_mangled(name)` -- Extract class name from MSVC mangled names

## Integration with Other Skills

| Skill                                                              | Role in Lifting                                                                   |
| ------------------------------------------------------------------ | --------------------------------------------------------------------------------- |
| [decompiled-code-extractor](../decompiled-code-extractor/SKILL.md) | Extract function data (decompiled code, assembly, xrefs) -- run before lifting    |
| [batch-lift](../batch-lift/SKILL.md)                               | Coordinate lifting of related function groups with shared struct context          |
| [reconstruct-types](../reconstruct-types/SKILL.md)                 | Scan memory access patterns to build struct/class definitions used during lifting |
| [verify-decompiled](../verify-decompiled/SKILL.md)                 | Verify decompiler accuracy before lifting; surgical fixes to decompiler errors    |
| [analyze-ida-decompiled](../analyze-ida-decompiled/SKILL.md)       | Reference for IDA conventions, file layout, and analysis patterns                 |

## Performance

| Operation | Typical Time | Notes |
|-----------|-------------|-------|
| Extract function data (prerequisite) | ~1-2s | Via decompiled-code-extractor |
| Lift single function (11 steps) | ~30-60s | Depends on function complexity |
| Lift with struct reconstruction | ~45-90s | Adds scan_struct_fields step |
| Batch lift (class methods) | ~2-5min | Via batch-lift skill for 5-10 functions |

## Additional Resources

- For IDA naming patterns, assembly-to-C++ mappings, and common lifting patterns (COM/WRL, HRESULT, locks, SEH, memory), see [reference.md](reference.md)
- For concrete before/after lifting examples, see [examples.md](examples.md)
- For DB schema and JSON field formats, see [data_format_reference.md](../../docs/data_format_reference.md)
- For file_info.json schema, see [file_info_format_reference.md](../../docs/file_info_format_reference.md)
