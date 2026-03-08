# Data Flow Tracer -- Technical Reference

Detailed reference for DB fields used in data-flow tracing, expression classification, assembly register mapping, and helper module APIs.

---

## Key DB Fields for Data Flow

### Functions Table -- Fields Used by This Skill

| Field | Use in Data Flow |
|-------|------------------|
| `decompiled_code` | Primary source for parameter tracking and expression parsing |
| `assembly_code` | Ground truth: register propagation, memory stores, call setup |
| `simple_outbound_xrefs` | Callees -- follow parameter flow into called functions |
| `simple_inbound_xrefs` | Callers -- trace backward to find who provides arguments |
| `global_var_accesses` | Global reads/writes per function -- build producer/consumer maps |
| `string_literals` | String references per function -- trace string usage chains |
| `function_signature` | Parameter names and types for the target function |
| `function_signature_extended` | Extended type info (IDA type system) |

### global_var_accesses Format

Each entry in the JSON list:

```json
{
    "address": "0x18005C380",
    "name": "dword_18005C380",
    "access_type": "Read"
}
```

`access_type` is either `"Read"` or `"Write"`. The `name` may be a symbol name (if IDA resolved one) or an IDA auto-name (`dword_XXXX`, `qword_XXXX`, etc.).

### string_literals Format

JSON list of strings referenced by the function:

```json
["COMSPEC", "cmd.exe", "%s\\cmd.exe", "PATH"]
```

Order is not guaranteed. Capped at 2000 entries per function.

### simple_outbound_xrefs / simple_inbound_xrefs

Each entry:

```json
{
    "function_name": "CreateFileW",
    "function_id": null,
    "module_name": "kernel32.dll",
    "function_type": 3,
    "xref_type": "Code_Near_Call",
    "extraction_type": "script"
}
```

Key rules:
- `function_id != null` -> internal (same-module) call, follow by ID
- `function_id == null` + DLL name -> cross-module call
- `module_name == "data"` or `function_type == 4` -> global/data ref, NOT a call
- `module_name == "vtable"` or `function_type == 8` -> vtable dispatch, indirect

---

## x64 Calling Convention (Parameter Registers)

| Param # | Integer/Pointer | IDA Name |
|---------|----------------|----------|
| 1 | RCX (ECX, CX, CL) | a1 |
| 2 | RDX (EDX, DX, DL) | a2 |
| 3 | R8 (R8D, R8W, R8B) | a3 |
| 4 | R9 (R9D, R9W, R9B) | a4 |
| 5+ | Stack [RSP+0x28], [RSP+0x30], ... | a5, a6, ... |

**Return value**: RAX (integer/pointer), XMM0 (float).

**Register preservation**: RBX, RBP, RDI, RSI, R12-R15 are callee-saved. Functions commonly save a parameter register into a callee-saved register in the prologue (e.g., `mov rbx, rcx`) to preserve it across calls.

---

## Expression Classification

The `classify_expression()` function in `_common.py` categorizes C expressions into:

| Type | Pattern | Example |
|------|---------|---------|
| `parameter` | `a1`, `a2`, ... | `a2` |
| `call_result` | `FuncName(...)` | `GetLastError()` |
| `constant` | Numeric literal | `0x80000000`, `42` |
| `string_literal` | String literal | `"COMSPEC"`, `L"cmd.exe"` |
| `global` | IDA global name | `dword_18005C380` |
| `local_variable` | IDA local var | `v5`, `v12` |
| `param_dereference` | Pointer through param | `*(DWORD *)(a1 + 0x10)` |
| `expression` | Anything else | `a1 + v3 * 8` |

When the backward tracer finds a `local_variable`, it recursively traces through assignments to find the ultimate origin.

---

## Assembly Register Tracking

The forward tracer can optionally track a parameter register through the assembly prologue. This detects patterns like:

```asm
; Function prologue -- save param 1 (rcx) to callee-saved register
mov     rbx, rcx        ; rbx now also holds param 1
mov     rdi, rdx        ; rdi now also holds param 2

; Later usage
mov     rcx, rbx        ; restore param 1 for a call
call    SomeFunction    ; param 1 is passed as arg 1
```

The tracker follows `mov dest, src` instructions where `src` is a tracked register, adding `dest` to the tracked set. This is limited to the prologue area (~30 instructions) to avoid false positives from register reuse deeper in the function.

For full data-flow analysis of assembly, cross-reference with the decompiled code analysis which captures the same information at a higher level.

---

## Helper Module API for Data Flow

### Getting Global Variable Accesses

```python
from helpers import open_individual_analysis_db

with open_individual_analysis_db("extracted_dbs/module.db") as db:
    func = db.get_function_by_name("FunctionName")[0]

    # Parsed global accesses (list of dicts)
    globals_list = func.parsed_global_var_accesses
    for g in globals_list:
        print(f"{g['name']} ({g['address']}): {g['access_type']}")

    # Parsed string literals (list of strings)
    strings = func.parsed_string_literals
    for s in strings:
        print(f"String: {s}")
```

### Scanning All Functions for Global Access

```python
with open_individual_analysis_db("extracted_dbs/module.db") as db:
    for func in db.get_all_functions():
        globals_list = func.parsed_global_var_accesses
        if globals_list:
            for g in globals_list:
                print(f"{func.function_name} -> {g['name']} ({g['access_type']})")
```

### Cross-Module Caller Resolution

```python
from helpers import open_analyzed_files_db, open_individual_analysis_db

# Find which module implements a function
with open_analyzed_files_db() as tracking:
    records = tracking.get_by_file_name("kernel32.dll")
    for r in records:
        if r.status == "COMPLETE":
            print(f"DB: {r.analysis_db_path}")
```

---

## Decompiled Code Parsing Patterns

### Function Call Extraction

The `extract_function_calls()` parser handles:

```cpp
// Simple call
result = CreateFileW(a1, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);

// Nested call
v5 = RegOpenKeyExW(HKEY_LOCAL_MACHINE, (LPCWSTR)v3, 0, KEY_READ, &v10);

// No result capture
CloseHandle(hProcess);

// Cast + call
v2 = (unsigned int)SomeFuncW(a1, a2);
```

It does NOT handle:
- Indirect calls through function pointers: `((void (*)(void))ptr)()`
- VTable dispatch: `(*(func**)(*a1 + 0x18))(a1)`

For indirect calls, use `outbound_xrefs` which captures resolved targets.

### Variable Origin Tracing

The `trace_variable_origin()` function follows simple assignment chains:

```cpp
v5 = a2;            // -> parameter (a2)
v8 = GetLastError(); // -> call_result (GetLastError)
v3 = 0x80000000u;   // -> constant
v10 = qword_18005C380; // -> global
```

It recursively follows local-to-local assignments:
```cpp
v3 = a1;    // v3 <- parameter a1
v5 = v3;    // v5 <- v3 <- parameter a1 (traced through)
```

Limitations:
- Does not handle conditional assignments (phi nodes)
- Does not track values through struct field stores/loads
- Single-pass: may miss assignments in loops

---

## Script Architecture

All scripts follow the same pattern as other skills:

1. Resolve workspace root (4 levels up from `scripts/`)
2. Add workspace root to `sys.path`
3. Import from `helpers` package via `_common.py`
4. Resolve DB paths relative to workspace root
5. Use `open_individual_analysis_db()` for function data
6. Use `open_analyzed_files_db()` for cross-module resolution

### Script Dependencies

| Script | Imports from _common.py |
|--------|------------------------|
| `forward_trace.py` | `find_param_in_calls`, `find_param_register_aliases`, `find_global_writes_in_assembly` |
| `backward_trace.py` | `classify_expression`, `extract_function_calls`, `trace_variable_origin` |
| `global_state_map.py` | `parse_json_safe`, `resolve_db_path` |
| `string_trace.py` | `parse_json_safe`, `resolve_db_path` |

All scripts also reuse `find_module_db.py` from the decompiled-code-extractor skill for module discovery.

---

## function_type Values (from xrefs)

| Value | Name | Meaning | Followable? |
|-------|------|---------|-------------|
| 0 | FT_UNK | Unknown | Maybe |
| 1 | FT_GEN | General internal | Yes (by function_id) |
| 2 | FT_LIB | Library function | Yes (by function_id) |
| 3 | FT_API | Windows API | Cross-module resolve |
| 4 | FT_MEM | Data/memory ref | **No** (not a call) |
| 8 | FT_VTB | VTable dispatch | **No** (indirect) |
| 16 | FT_SYS | System function | Cross-module resolve |
