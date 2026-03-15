# IDA Decompiled Code Conventions Reference

This document captures IDA Pro / Hex-Rays decompilation conventions, DeepExtractIDA output
formats, and analysis workflows that are referenced throughout the runtime but no longer tied
to the deprecated `analyze-ida-decompiled` skill. Use this reference when interpreting
extraction outputs, navigating decompiled code, or building new skills and helpers.

---

## 1. `function_summary` JSON Schema

`file_info.json` contains a `function_summary` section with the following structure:

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

Key fields:

| Field | Type | Description |
|---|---|---|
| `total_functions` | int | Total function count in the module |
| `class_methods` | array | C++ class groupings (each has `class_name`, `method_count`, `methods[]`) |
| `class_methods[].class_name` | string | C++ class name |
| `class_methods[].method_count` | int | Number of methods extracted for the class |
| `class_methods[].methods[]` | array | Per-method records with `name` and `signature` |
| `standalone_functions` | array | Non-class functions, each with `name` and `signature` |

Use `function_summary` to discover all functions without reading every `.cpp` file.

---

## 2. Grouped File Naming Conventions

Functions are packed alphabetically into combined files of ~250–300 lines each:

| Pattern | Content |
|---|---|
| `{module}_{ClassName}_group_{N}.cpp` | Methods of `ClassName`, split across numbered groups |
| `{module}_standalone_group_{N}.cpp` | Standalone (non-class) functions, split across numbered groups |

Where `{module}` is derived as `{stem}_{extension}` from the PE file name
(e.g., `appinfo.dll` → `appinfo_dll`).

**Examples:**

- Class method `LUATelemetry::StartActivity` → search `appinfo_dll_LUATelemetry_group_*.cpp`
- Standalone function `AiCheckLUA` → search `appinfo_dll_standalone_group_*.cpp`

Since functions are packed alphabetically, search for a specific function by its
`// Function Name:` header comment across the matching group files.

---

## 3. Comment Header Block Format

Every function within a grouped `.cpp` file is preceded by a comment header block:

```cpp
// Function Name: AiCheckSecureApplicationDirectory
// Mangled Name: ?AiCheckSecureApplicationDirectory@@YAJPEBGPEAUCSecurityDescriptor@@PEAH@Z
// Function Signature (Extended): __int64 __fastcall AiCheckSecureApplicationDirectory(const unsigned __int16 *, struct CSecurityDescriptor *, int *)
// Function Signature: long AiCheckSecureApplicationDirectory(ushort const *,CSecurityDescriptor *,int *)
```

Notes:

- `Mangled Name` is the MSVC-decorated symbol; it encodes the class, parameters, and calling
  convention and can be passed to `undname` or `CxxFilt` to reconstruct the full C++ signature.
- `Function Signature (Extended)` appears **only** when it differs from the base `Function Signature`.
- Use the header to identify the function quickly when scanning across multiple group files.

---

## 4. Import Entry JSON Structure

Each entry in `file_info.json` → `imports[].functions[]` includes API-set resolution fields:

```json
{
  "module_name": "kernel32.dll",
  "raw_module_name": "api-ms-win-core-processthreads-l1-1-0.dll",
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

Key fields:

| Field | Type | Description |
|---|---|---|
| `module_name` | string | Resolved DLL name (after API-set forwarding) |
| `raw_module_name` | string | Original import table name (API-set alias if applicable) |
| `is_api_set` | bool | `true` when the original name is an `api-ms-win-*` API-set contract |
| `is_delay_loaded` | bool | `true` for delay-loaded imports (loaded on first call, not at startup) |
| `function_signature_extended` | string | Full typed signature for the imported function |

---

## 5. Worked Analysis Examples

### Example 1: Orienting in a Module

**Question:** "What is appinfo.dll and what does it do?"

Read `file_info.json` metadata sections:

```json
// basic_file_info
"file_name": "appinfo.dll",
"size_bytes": 413696,

// pe_version_info
"company_name": "Microsoft Corporation",
"product_name": "Microsoft® Windows® Operating System",
"file_description": "Application Information Service"
```

Then check `function_summary` for scope:
- **Total functions**: 1173
- **Classes**: LUATelemetry (53 methods), StateRepository (45 methods), Windows (42 methods),
  wil (428 methods — WIL infrastructure), plus many lambda classes
- **Standalone functions**: ~900+

**Answer:** `appinfo.dll` is the Windows Application Information Service (AIS), responsible
for UAC elevation decisions and application compatibility.

---

### Example 2: Finding and Analyzing a Specific Function

**Question:** "How does AiCheckSecureApplicationDirectory work?"

1. Search `function_summary.standalone_functions` in `file_info.json` to confirm it exists.
2. Find it in `appinfo_dll_standalone_group_9.cpp` (standalone, alphabetical order).
3. Read the header block to get the mangled name and both signatures.
4. Trace the body: opens the directory with `CreateFileW`, resolves the final path via
   `GetFinalPathNameByHandleW`, compares via `RtlEqualUnicodeString` against a secure path.
5. Look up `CreateFileW` in `imports` to confirm parameter types.

---

### Example 3: Analyzing a Class Method

**Question:** "What does LUATelemetry::AppXSyncActivity::StartActivity do?"

1. Confirm class exists in `function_summary.class_methods`: `"class_name": "LUATelemetry"`.
2. Search `appinfo_dll_LUATelemetry_group_*.cpp` for `StartActivity`.
3. Found in group 1; reads the ETW telemetry event path via `wil::ActivityBase::zInternalStart`.

---

### Example 4: Cross-Referencing Imports for Security-Sensitive APIs

Scan `imports` in `file_info.json` for notable APIs:

```
advapi32.dll: SetSecurityInfo, GetTokenInformation, ImpersonateLoggedOnUser,
              RevertToSelf, AdjustTokenPrivileges
kernel32.dll: CreateProcessAsUserW, CreateProcessW
rpcrt4.dll:   RpcServerRegisterIf3, RpcImpersonateClient
```

These indicate token manipulation, process creation with alternate credentials, and an RPC
server interface — the classic UAC elevation pattern.

---

### Example 5: Browsing Alphabetically in a Grouped File

In `appinfo_dll_standalone_group_9.cpp`:

```
// Function Name: AiCheckLUA                         (line ~1)
// Function Name: AiCheckSecureApplicationDirectory  (line ~114)
// Function Name: AiCreateProcess                    (line ~200)
```

Functions starting with "Ai" are grouped together due to alphabetical ordering within each
group file.

---

## 6. Struct Offset Calculation Formulas

When IDA shows pointer arithmetic like `*(TYPE*)(base + offset)`:

```
*((_QWORD *)a1 + N)  →  byte offset = N × 8   (QWORD = 8 bytes)
*((_DWORD *)a1 + N)  →  byte offset = N × 4   (DWORD = 4 bytes)
*((_WORD *)a1 + N)   →  byte offset = N × 2   (WORD = 2 bytes)
*((_BYTE *)a1 + N)   →  byte offset = N × 1   (BYTE = 1 byte)
```

**Mixed casts to the same base pointer reveal different fields of the same struct:**

```cpp
*((_QWORD *)a1 + 0)   // offset 0x00: QWORD field (likely vtable pointer)
*((_DWORD *)a1 + 4)   // offset 0x10: DWORD field
*((_BYTE *)a1 + 24)   // offset 0x18: BYTE field (flag or status)
```

**IDA sized-access type reference:**

| Cast | Size | C Equivalent |
|---|---|---|
| `_BYTE` | 1 byte | `uint8_t` / `char` |
| `_WORD` | 2 bytes | `uint16_t` / `short` |
| `_DWORD` | 4 bytes | `uint32_t` / `int` |
| `_QWORD` | 8 bytes | `uint64_t` / `__int64` |
| `_OWORD` | 16 bytes | `__int128` / SSE register |
| `LOBYTE(x)` | low byte of x | `(uint8_t)(x)` |
| `HIBYTE(x)` | high byte of x | `(uint8_t)((x) >> 8)` |
| `LOWORD(x)` | low 16 bits | `(uint16_t)(x)` |
| `HIWORD(x)` | high 16 bits | `(uint16_t)((x) >> 16)` |
| `LODWORD(x)` | low 32 bits of 64-bit x | `(uint32_t)(x)` |
| `HIDWORD(x)` | high 32 bits of 64-bit x | `(uint32_t)((x) >> 32)` |
| `BYTE1(x)` | 2nd byte | `(uint8_t)((x) >> 8)` |
| `BYTE2(x)` | 3rd byte | `(uint8_t)((x) >> 16)` |
| `BYTE3(x)` | 4th byte | `(uint8_t)((x) >> 24)` |

Collect all accesses to the same base pointer type across multiple functions to reconstruct
full struct layouts (see `reconstruct-types` skill for automation).

---

## 7. Five-Step Analysis Workflow

The standard workflow for analyzing a decompiled function from an extraction output:

### Step 1 — Orient: Read Module Metadata

Open `file_info.json` for the target module. Check:
- `basic_file_info` — file name, size, hashes, timestamp
- `pe_version_info` — company, product description
- `function_summary` — total function count, class list, standalone function count

### Step 2 — Discover: Find the Target Function

**Fastest — function-index lookup:**

```bash
python .agent/skills/function-index/scripts/lookup_function.py <function_name>
python .agent/skills/function-index/scripts/lookup_function.py --search "CheckSecure" --app-only
```

Or programmatically:

```python
from helpers import resolve_function_file
path = resolve_function_file("AiCheckLUA")
```

**Broadest — unified search** (matches strings, APIs, classes, not just names):

```bash
python .agent/helpers/unified_search.py <db_path> --query "CheckSecure"
```

**By file** — functions map to predictable grouped files:
- Class method `LUATelemetry::StartActivity` → `{module}_LUATelemetry_group_*.cpp`
- Standalone function `AiCheckLUA` → `{module}_standalone_group_*.cpp`

### Step 3 — Analyze: Read and Understand the Function

1. **Parse the header** — extract function name, mangled name (encodes C++ types), and both
   signatures to understand parameter types.
2. **Read the body** — identify parameters (`a1`, `a2`, …), local variables (`v1`, `v2`, …),
   API calls, and control flow branches.
3. **Map struct access** — `*((_QWORD *)a1 + 14)` means field at byte offset `14×8 = 112`
   (see section 6 above).
4. **Identify API calls** — look up imported functions in `file_info.json` → `imports` for
   correct type signatures.

### Step 4 — Cross-Reference: Trace Call Chains

1. Use `lookup_function.py` (or `resolve_function_file()` from helpers) to check if a callee
   is in this or another extracted module — searches all modules at once.
2. If found, use the returned `file_path` to read the `.cpp` file directly.
3. If not found, check `imports` in `file_info.json` — it's an external DLL import.
4. For `sub_XXXX` calls, search across all group files for the address in any `// Function Name:` header.
5. Use `is_library_function()` (from `helpers` or `function-index` skill) to identify
   WIL/STL/WRL callees without reading their code — skip them unless the interface matters.

### Step 5 — Contextualize: Understand the Binary's Role

Use metadata to ground the analysis:
- `entry_points` — which functions are exported or are service entry points
- `exports` — the module's public API surface
- `rich_header` — compiler/linker toolchain used to build the binary

**Helper module access (programmatic use):**

```python
from helpers import load_function_index, lookup_function, is_application_function
from helpers import parse_class_from_mangled, IDA_TO_C_TYPE

index = load_function_index(module)
entry = lookup_function(index, "SomeFunction")
if is_application_function(entry):
    # analyze
    pass
class_name = parse_class_from_mangled(entry["mangled_name"])
```
