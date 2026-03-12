# Function Index -- Technical Reference

## function_index.json Schema

Each module directory (`extracted_code/{module}/`) contains a `function_index.json`
that maps every extracted function to its generated `.cpp` file(s) and metadata.

### Entry Format

```json
{
  "<function_name>": {
    "files": ["string", ...],
    "library": "WIL | STL | WRL | CRT | ETW/TraceLogging | null",
    "function_id": 123,
    "has_decompiled": true,
    "has_assembly": true
  }
}
```

> **Legacy format**: Older extraction outputs use `"file": "string | null"` instead
> of `"files"`. The helper API (`get_files()`, `get_primary_file()`) handles both
> transparently.

### Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `function_name` (key) | string | Extracted function name matching `functions.function_name` in the DB. Includes C++ class methods (`Class::Method`), thunks, and demangled names. |
| `files` | list of strings | The `.cpp` filename(s) containing the function, located in the same directory as the index. Empty list (`[]`) when decompilation failed. Most functions appear in a single file (one-element list). |
| `library` | string or null | Library boilerplate tag (see Library Tag Detection below). `null` = application code. |
| `function_id` | int | Primary key from `functions.function_id` in the analysis database. Stable across queries. |
| `has_decompiled` | bool | `true` if Hex-Rays decompiled output was available and emitted to a `.cpp` file. |
| `has_assembly` | bool | `true` if `functions.assembly_code` was stored for this function. |

### Examples

Application function (standalone):

```json
"IsFamilyProvisioned": {
  "files": ["appinfo_dll_standalone_group_50.cpp"],
  "library": null,
  "function_id": 861,
  "has_decompiled": true,
  "has_assembly": true
}
```

Class method:

```json
"CSyncMLDPU::AppendAlertStatus": {
  "files": ["coredpus_dll_CSyncMLDPU_group_1.cpp"],
  "library": null,
  "function_id": 1732,
  "has_decompiled": true,
  "has_assembly": true
}
```

Library boilerplate (WIL):

```json
"wil::details_abi::ProcessLocalStorageData<...>::MakeAndInitialize": {
  "files": ["appinfo_dll_standalone_group_1.cpp"],
  "library": "WIL",
  "function_id": 37,
  "has_decompiled": true,
  "has_assembly": true
}
```

Failed decompilation:

```json
"SomeFailedFunc": {
  "files": [],
  "library": null,
  "function_id": 42,
  "has_decompiled": false,
  "has_assembly": true
}
```

---

## Library Tag Detection

Library tags identify known library/runtime boilerplate so agents can
filter it out and focus on application code. Detection uses name prefix
and namespace matching on the function name.

### Detection Patterns

| Tag | Detection Patterns | What It Covers |
|-----|-------------------|----------------|
| `WIL` | `wil::`, `wistd::`, mangled `@wil@@`, `@wistd@@` | Windows Implementation Library -- RAII wrappers, result macros, telemetry helpers, `wil::details*`, `wistd::unique_ptr` |
| `STL` | `std::`, `stdext::`, mangled `@std@@`, `@stdext@@` | C++ standard library -- containers, algorithms, iterators, `std::vector<>`, `std::basic_string<>` |
| `WRL` | `Microsoft::WRL::` | Windows Runtime C++ Template Library -- COM support, `ComPtr`, `RuntimeClass`, activation factories |
| `CRT` | `__scrt_`, `__acrt_`, `_CRT_` | C/C++ runtime support -- process startup, exception handling, security cookie init, `__scrt_common_main_seh` |
| `ETW/TraceLogging` | `_tlgWrite`, `TraceLoggingCorrelationVector::` | TraceLogging and ETW telemetry -- `_tlgWriteTransfer_EtwEventWriteTransfer`, provider registration |

### Filtering API

```python
from helpers import load_function_index, filter_by_library, is_application_function

index = load_function_index("appinfo_dll")

app_funcs = filter_by_library(index, app_only=True)

wil_only = filter_by_library(index, library="WIL")

all_lib = filter_by_library(index, lib_only=True)

is_application_function(index["AiCheckLUA"])       # True
is_application_function(index["wil::details::..."])  # False
```

### Typical Library Distribution

| Module | Total | App | WIL | STL | WRL | CRT | ETW |
|--------|-------|-----|-----|-----|-----|-----|-----|
| appinfo_dll | 1166 | ~598 | ~465 | ~50 | ~47 | ~5 | ~1 |
| cmd_exe | 817 | ~753 | ~45 | ~15 | ~0 | ~4 | ~0 |
| coredpus_dll | 1080 | ~1032 | ~30 | ~12 | ~4 | ~2 | ~0 |

---

## .cpp File Naming Convention

Functions are grouped into combined files of ~250-300 lines each:

| Pattern | Content |
|---------|---------|
| `{module}_{ClassName}_group_{N}.cpp` | Methods of a C++ class |
| `{module}_standalone_group_{N}.cpp` | Standalone (non-class) functions |
| `{module}_{library}_group_{N}.cpp` | Library boilerplate (WIL, STL, WRL, CRT, ETW) |

Examples:
- `appinfo_dll_CSecurityDescriptor_group_1.cpp` -- methods of `CSecurityDescriptor`
- `appinfo_dll_standalone_group_5.cpp` -- standalone application functions
- `appinfo_dll_WIL_group_2.cpp` -- WIL library boilerplate

The `group_by_file()` helper returns a mapping of filename to function names:

```python
from helpers.function_index import group_by_file, load_function_index

by_file = group_by_file(load_function_index("appinfo_dll"))
# {"appinfo_dll_standalone_group_5.cpp": ["AiCheckLUA", "AiLaunchProcess", ...], ...}
```

---

## Edge Cases

### Duplicate Function Names

If a function name appears in multiple `.cpp` files (rare, can happen with
template instantiations or duplicate demangled names across grouping
boundaries), all files are recorded in the `"files"` list and a warning
is logged during extraction.

### Failed Decompilation

Functions where Hex-Rays decompilation failed or was unavailable are
included in the index with `"files": []` and `"has_decompiled": false`.
This ensures the index is a complete map of all functions in the analysis
database, not just successfully decompiled ones.

### Template Instantiations

C++ template instantiations appear with their full demangled name:

```json
"wil::details_abi::ProcessLocalStorageData<WilStaging_Struct>::MakeAndInitialize": {
  "files": ["appinfo_dll_standalone_group_1.cpp"],
  "library": "WIL",
  "function_id": 37,
  "has_decompiled": true,
  "has_assembly": true
}
```

Search for these with regex (`--regex`) or substring (`--search`) since exact
name matching requires the full template arguments.

### Overloaded / Mangled Names

The index uses the demangled function name as its key. For overloaded
functions (same name, different parameters), the demangled name typically
includes sufficient type information to distinguish them. The `function_id`
field provides an unambiguous identifier when names collide.

### Module Name Resolution

Module names in the index directory use the sanitized form: `appinfo_dll`
(not `appinfo.dll`). The `resolve_module_dir()` helper accepts both forms:

```python
from helpers import resolve_module_dir

resolve_module_dir("appinfo.dll")   # works
resolve_module_dir("appinfo_dll")   # also works
```

---

## Script Argument Reference

### lookup_function.py

| Argument | Type | Description |
|----------|------|-------------|
| `function_name` | positional (optional) | Exact function name to look up |
| `--search` | string | Substring search (case-insensitive) |
| `--regex` | flag | Treat `--search` as regex pattern |
| `--module` | string | Restrict to one module |
| `--app-only` | flag | Exclude library boilerplate |
| `--json` | flag | JSON output |

### index_functions.py

| Argument | Type | Description |
|----------|------|-------------|
| `module_name` | positional (optional) | Module to list functions for |
| `--all` | flag | List all modules |
| `--app-only` | flag | Exclude library boilerplate |
| `--library` | string | Filter to one library tag (WIL, STL, etc.) |
| `--by-file` | flag | Group output by `.cpp` file |
| `--file` | string | Show functions in a specific `.cpp` file |
| `--stats` | flag | Statistics only (counts, breakdown) |
| `--json` | flag | JSON output |

### resolve_function_file.py

| Argument | Type | Description |
|----------|------|-------------|
| `function_name` | positional (optional) | Single function name to resolve |
| `--names` | string | Comma-separated batch of function names |
| `--file` | string | List all functions in a specific `.cpp` file |
| `--module` | string | Restrict to one module |
| `--json` | flag | JSON output |

Default output is pipe-delimited: `module|file_path|library_tag`.

---

## Helper API Quick Reference

Available via `from helpers import ...` or `from helpers.function_index import ...`:

| Function | Returns | Purpose |
|----------|---------|---------|
| `load_function_index(mod)` | `dict` or `None` | Load a module's function_index.json |
| `load_function_index_for_db(db_path)` | `dict` or `None` | Load index by resolving DB path to module dir |
| `load_all_function_indexes()` | `dict[str, dict]` | Load indexes for every module |
| `lookup_function(name, mod?)` | `list[dict]` | Find function by exact name across modules |
| `resolve_function_file(name, mod?)` | `Path` or `None` | Resolve function name to absolute .cpp path |
| `resolve_module_dir(mod)` | `Path` or `None` | Module name to its extracted_code/ directory |
| `function_index_path(mod)` | `Path` or `None` | Absolute path to a module's function_index.json |
| `list_extracted_modules()` | `list[str]` | All module folders containing function_index.json |
| `get_files(entry)` | `list[str]` | List of .cpp files (handles both `files` and legacy `file`) |
| `get_primary_file(entry)` | `str` or `None` | Primary (first) .cpp file, or None |
| `filter_by_library(idx, ...)` | `dict` | Filter entries by library/app_only/lib_only |
| `is_application_function(entry)` | `bool` | True when library tag is null |
| `is_library_function(entry)` | `bool` | True when library tag is set |
| `get_library_tag(entry)` | `str` or `None` | Return the library tag |
| `group_by_file(idx)` | `dict[str, list[str]]` | Group function names by .cpp filename |
| `group_by_library(idx)` | `dict[str\|None, list[str]]` | Group function names by library tag |
| `compute_stats(idx)` | `dict` | Total/app/lib counts, breakdown, file count |

---

## Related Documentation

- [function_index_format_reference.md](../../docs/function_index_format_reference.md) -- Full format spec with generation details
- [data_format_reference.md](../../docs/data_format_reference.md) -- SQLite DB schema
- [file_info_format_reference.md](../../docs/file_info_format_reference.md) -- file_info.json (PE metadata, imports, exports)
