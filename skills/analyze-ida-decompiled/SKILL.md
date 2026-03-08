---
name: analyze-ida-decompiled
description: Analyze, explain, and navigate IDA Pro decompiled C/C++ code extracted by DeepExtractIDA from Windows PE binaries. Use when the user asks to understand, annotate, trace, or explain decompiled functions, needs help cross-referencing functions, wants to know what a function does, asks about control flow, imports, exports, or security features of an extracted module, or references .cpp files and file_info.json from an extraction output.
---

# Analyze IDA Decompiled Code

## Purpose

Provide comprehensive guidance for navigating, reading, and understanding IDA Pro decompiled code extracted by DeepExtractIDA from Windows PE binaries. This is a documentation-only skill with no scripts -- it teaches the agent how to interpret extraction outputs, IDA naming conventions, struct field access patterns, COM/WRL virtual calls, and HRESULT error handling.

## Data Sources

This skill works with extraction outputs produced by **DeepExtractIDA**, an IDA Pro plugin that decompiles Windows PE binaries into structured, AI-ready data. Each extraction output contains:

- `extracted_code/{module}/` -- per-module folders with grouped `.cpp` files and metadata
- `extracted_dbs/{module}_{hash}.db` -- SQLite databases with full analysis data
- `extraction_report.json` -- batch run summary

For detailed format specifications, see:

- [file_info_format_reference.md](../../docs/file_info_format_reference.md) -- `file_info.json`/`file_info.md` schema
- [data_format_reference.md](../../docs/data_format_reference.md) -- SQLite database schema and JSON field formats

### Finding a Module DB

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

## Extraction Directory Layout

```
extracted_code/
  {module_name}/              # e.g., appinfo_dll, cmd_exe, kernel32_dll
    file_info.json            # Machine-readable metadata (USE THIS for lookups)
    file_info.md              # Human-readable report (same data, Markdown)
    {module}_{Class}_group_{N}.cpp    # Class methods grouped ~250-300 lines
    {module}_standalone_group_{N}.cpp # Standalone functions grouped ~250-300 lines
```

Module names are derived as `{stem}_{extension}` (e.g., `appinfo.dll` -> `appinfo_dll`).

## Grouped File Naming

Functions are packed alphabetically into combined files of ~250-300 lines each:

| Pattern                              | Content                                     |
| ------------------------------------ | ------------------------------------------- |
| `{module}_{ClassName}_group_{N}.cpp` | Methods of `ClassName`, split across groups |
| `{module}_standalone_group_{N}.cpp`  | Standalone (non-class) functions            |

Each function within a grouped file is preceded by a **comment header block**:

```cpp
// Function Name: AiCheckSecureApplicationDirectory
// Mangled Name: ?AiCheckSecureApplicationDirectory@@YAJPEBGPEAUCSecurityDescriptor@@PEAH@Z
// Function Signature (Extended): __int64 __fastcall AiCheckSecureApplicationDirectory(const unsigned __int16 *, struct CSecurityDescriptor *, int *)
// Function Signature: long AiCheckSecureApplicationDirectory(ushort const *,CSecurityDescriptor *,int *)
```

The `Function Signature (Extended)` line appears only when it differs from the base signature.

## file_info.json -- Primary Metadata Reference

Use `file_info.json` for all programmatic lookups. Key sections:

| Section               | Use For                                                               |
| --------------------- | --------------------------------------------------------------------- |
| `basic_file_info`     | File path, size, MD5/SHA256 hashes, analysis timestamp                |
| `pe_version_info`     | Company, product, version, description, copyright                     |
| `pe_metadata`         | Compilation timestamp, PDB path, .NET status                          |
| `entry_points`        | Module entry points with confidence and detection method              |
| `imports`             | Imported DLLs and functions (includes delay-load, API-set resolution) |
| `exports`             | Exported symbols with ordinals and forwarder info                     |
| `sections`            | PE section table (names, addresses, sizes, permissions)               |
| `security_features`   | ASLR, DEP, CFG, SEH status                                            |
| `dll_characteristics` | Raw and decoded DllCharacteristics flags                              |
| `rich_header`         | Compiler/linker toolchain metadata                                    |
| `tls_callbacks`       | TLS callbacks with threat analysis                                    |
| `load_config`         | SEH/CFG guard tables                                                  |
| `function_summary`    | Categorized function index (class methods + standalone)               |

### function_summary Structure

```json
{
  "total_functions": 1173,
  "class_methods": [
    {
      "class_name": "LUATelemetry",
      "method_count": 42,
      "methods": [
        { "name": "StartActivity", "signature": "void __fastcall ..." }
      ]
    }
  ],
  "standalone_functions": [
    { "name": "AiCheckSecureApplicationDirectory", "signature": "..." }
  ]
}
```

Use `function_summary` to discover all functions without reading every `.cpp` file.

### Import Entry Structure

Each import includes API-set resolution:

```json
{
  "module_name": "kernel32.dll", // Resolved name
  "raw_module_name": "api-ms-win-...", // Original API-set name (if applicable)
  "is_api_set": true,
  "functions": [
    {
      "function_name": "CreateProcessW",
      "function_signature_extended": "BOOL (__stdcall *)(LPCWSTR, ...)",
      "is_delay_loaded": false
    }
  ]
}
```

## IDA Naming Patterns

| Pattern                              | Meaning                                                   |
| ------------------------------------ | --------------------------------------------------------- |
| `a1`, `a2`, ...                      | Function parameters (positional order)                    |
| `v1`, `v2`, ...                      | Auto-named local variables                                |
| `sub_XXXX`                           | Unnamed function at address `XXXX`                        |
| `off_XXXX`                           | Pointer/data table at address `XXXX`                      |
| `dword_XXXX` / `qword_XXXX`          | 4-byte / 8-byte global at `XXXX`                          |
| `word_XXXX` / `byte_XXXX`            | 2-byte / 1-byte global at `XXXX`                          |
| `unk_XXXX`                           | Unknown-typed data at `XXXX`                              |
| `loc_XXXX`                           | Code label at address `XXXX`                              |
| `LABEL_N`                            | Decompiler-generated goto target                          |
| `_DWORD`, `_QWORD`, `_WORD`, `_BYTE` | IDA sized-access type casts                               |
| `LODWORD(x)`, `HIDWORD(x)`           | Low/high 32 bits of 64-bit value                          |
| `__fastcall`                         | x64 calling convention (rcx, rdx, r8, r9)                 |
| `__imp_Func` / `_imp_Func`           | Import thunk for `Func`                                   |
| `wil::*`                             | Windows Implementation Library (telemetry, feature flags) |
| `Microsoft::WRL::*`                  | COM Windows Runtime Library support                       |

## Workflows

### Workflow 1: "Analyze a decompiled function from an extraction output"

Analysis Progress:
- [ ] Step 1: Orient -- read module metadata
- [ ] Step 2: Discover -- find the target function
- [ ] Step 3: Analyze -- read and understand the function
- [ ] Step 4: Cross-reference -- trace call chains
- [ ] Step 5: Contextualize -- understand the binary's role

**Step 1**: Orient -- read module metadata.

Open `file_info.json` for the target module. Check `basic_file_info` for what binary this is, review `pe_version_info` for product context, and scan `function_summary` to understand scope (class count, function count).

**Step 2**: Discover -- find the target function.

**By function_index (fastest)** -- use the function-index skill to locate the exact `.cpp` file:

```bash
python .agent/skills/function-index/scripts/lookup_function.py <function_name>
python .agent/skills/function-index/scripts/lookup_function.py --search "CheckSecure" --app-only
```

Or programmatically: `from helpers import resolve_function_file; path = resolve_function_file("AiCheckLUA")`

**By unified search (broadest)** -- when the term might match a string, API call, or class name, not just a function name:

```bash
python .agent/helpers/unified_search.py <db_path> --query "CheckSecure"
```

**By file_info.json** -- search `function_summary.standalone_functions` and `function_summary.class_methods`.

**By file** -- function names map to grouped files:

- Class method `LUATelemetry::StartActivity` -> search `{module}_LUATelemetry_group_*.cpp`
- Standalone function `AiCheckLUA` -> search `{module}_standalone_group_*.cpp`

Since functions are packed alphabetically, use text search across the group files to locate a specific function by its `// Function Name:` header.

**Step 3**: Analyze -- read and understand the function.

1. **Parse the header** -- extract function name, mangled name (encodes C++ types), and both signatures
2. **Read the body** -- identify parameters, local variables, API calls, and control flow
3. **Map struct access** -- `*((_QWORD *)a1 + 14)` means field at byte offset `14*8 = 112`
4. **Identify API calls** -- look up Win32/NT API functions in `file_info.json` imports for correct signatures

**Step 4**: Cross-reference -- trace call chains.

To find a called function's implementation:

1. Use `lookup_function(callee_name)` (from `helpers`) or `lookup_function.py` to check if it's in this or another module -- this searches all extracted modules at once. For cross-dimensional search (strings, APIs, classes), use `python .agent/helpers/unified_search.py <db_path> --query <callee_name>`
2. If found, use the returned `file_path` to read the `.cpp` file directly
3. If not found in any module, check `imports` in `file_info.json` -- it's an external DLL import
4. For `sub_XXXX` calls, search across all group files for the address
5. Use `is_library_function()` from the function_index to identify WIL/STL/WRL callees without reading their code

**Step 5**: Contextualize -- understand the binary's role.

Use metadata to ground the analysis:

- `security_features` -- what mitigations are enabled (ASLR, DEP, CFG)
- `entry_points` -- which functions are exported/entry points
- `exports` -- what API surface does this module expose
- `rich_header` -- what toolchain built this binary

## Common Analysis Patterns

### Identifying function purpose from naming

- **Library tag (definitive)**: Check `function_index.json` -- if `library` is `WIL`, `STL`, `WRL`, `CRT`, or `ETW/TraceLogging`, the function is known boilerplate. Use `from helpers import get_library_tag_for_function` or `lookup_function.py` to check.
- Exported functions (in `exports`) are the module's public API
- `sub_XXXX` functions are internal helpers without symbol names
- Functions prefixed with class names (`ClassName::Method`) are C++ class methods
- Functions starting with `Wpp`/`_tlg`/`wil_` are typically telemetry/tracing infrastructure (heuristic; use library tag above for ground truth)

### Understanding struct field access

When decompiled code accesses fields via casts:

```cpp
v5 = *((_QWORD *)a1 + 14);   // byte offset 14*8 = 112
*(_DWORD *)a2 = 45;           // writing int at offset 0
if ( *((_BYTE *)a1 + 32) )    // byte at offset 32
```

Collect all accesses to the same type across multiple functions to reconstruct struct layouts.

### Recognizing COM/WRL patterns

```cpp
// QueryInterface pattern
result = (*((__int64 (__fastcall **)(_QWORD, _QWORD, _QWORD))(*a1) + 0))(a1, riid, ppvObject);
// This is: a1->lpVtbl->QueryInterface(a1, riid, ppvObject)
// Offset 0 in vtable = QueryInterface, 1 = AddRef, 2 = Release
```

### Recognizing error handling

HRESULT-returning functions use `if ( result < 0 )` for failure checks. Common patterns:

```cpp
v3 = SomeWin32Call(...);
if ( v3 < 0 )              // FAILED(hr)
    goto cleanup;
```

## Direct Helper Module Access

For programmatic use without skill scripts:

- `helpers.load_function_index(module)` -- Load the function index for a module
- `helpers.lookup_function(index, name)` -- Look up a function in the index
- `helpers.is_application_function(entry)` -- Check if a function is application code (not library)
- `helpers.parse_class_from_mangled(name)` -- Extract class name from MSVC mangled names
- `helpers.IDA_TO_C_TYPE` -- Mapping of IDA type names to standard C types

## Integration with Other Skills

| Task | Recommended Skill |
|------|-------------------|
| Look up which file contains a function | function-index |
| Extract full function data (decompiled, assembly, xrefs) | decompiled-code-extractor |
| Classify functions by purpose after reading code | classify-functions |
| Trace what a function calls across modules | callgraph-tracer |
| Lift decompiled code to clean, readable C++ | code-lifting / batch-lift |

## Performance

| Operation | Typical Time | Notes |
|-----------|-------------|-------|
| Read file_info.json | <1s | JSON parse of module metadata |
| Navigate grouped .cpp files | <1s | File I/O only |
| Cross-reference function lookup | ~1-2s | Depends on module size |

## Additional Resources

- [reference.md](reference.md) -- IDA type casts, struct offset calculation, COM vtable slots, x64 calling convention, HRESULT patterns, library tags
- [examples.md](examples.md) -- Concrete analysis examples
- [file_info_format_reference.md](../../docs/file_info_format_reference.md) -- file_info.json schema details
- [data_format_reference.md](../../docs/data_format_reference.md) -- SQLite database schema and JSON field formats
