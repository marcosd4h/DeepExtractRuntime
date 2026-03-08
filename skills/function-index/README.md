# Function Index

Fast function-to-file resolution for DeepExtractIDA extraction outputs. Maps function names to their `.cpp` files and separates application code from library boilerplate (WIL/STL/WRL/CRT/ETW).

**This skill is a building block for other skills.** It provides both CLI scripts and a Python helper module that any skill can import.

## Quick Start

```bash
# Where is this function?
python .agent/skills/function-index/scripts/lookup_function.py AiCheckSecureApplicationDirectory

# What application functions does this module have?
python .agent/skills/function-index/scripts/index_functions.py appinfo_dll --app-only --stats

# Resolve function name to absolute .cpp path
python .agent/skills/function-index/scripts/resolve_function_file.py BatLoop

# Cross-dimensional search (names, signatures, strings, APIs, classes, exports)
python .agent/helpers/unified_search.py <db_path> --query "CreateProcess"
```

## Two Ways to Consume

### 1. CLI Scripts

Run from the workspace root. All scripts support `--json` for machine-readable output.

| Script                    | Purpose                                                   |
| ------------------------- | --------------------------------------------------------- |
| `lookup_function.py`      | Find functions by exact name, substring, or regex         |
| `index_functions.py`      | List/filter/group/stats for module functions              |
| `resolve_function_file.py`| Resolve function names to absolute `.cpp` file paths      |

```bash
# Exact lookup across all modules
python .agent/skills/function-index/scripts/lookup_function.py AiCheckLUA

# Substring search, application code only
python .agent/skills/function-index/scripts/lookup_function.py --search "Launch" --app-only

# Regex search within one module
python .agent/skills/function-index/scripts/lookup_function.py --search "Ai.*Build" --regex --module appinfo_dll

# Module stats
python .agent/skills/function-index/scripts/index_functions.py appinfo_dll --stats

# All modules stats
python .agent/skills/function-index/scripts/index_functions.py --all --stats

# Filter by library tag
python .agent/skills/function-index/scripts/index_functions.py appinfo_dll --library WIL

# Group by .cpp file
python .agent/skills/function-index/scripts/index_functions.py appinfo_dll --app-only --by-file

# Batch resolve (comma-separated)
python .agent/skills/function-index/scripts/resolve_function_file.py --names "FuncA,FuncB,FuncC" --json

# List all functions in a specific .cpp file
python .agent/skills/function-index/scripts/resolve_function_file.py --file appinfo_dll_standalone_group_5.cpp --module appinfo_dll
```

### 2. Python Helper Module

The core logic lives in `helpers/function_index/`, importable by any script that has `.agent` on `sys.path` (the standard pattern all skill scripts already use).

```python
# Every skill's _common.py already does this:
#   sys.path.insert(0, str(WORKSPACE_ROOT / ".agent"))

# Then import what you need:
from helpers import (
    load_function_index,       # Load a module's function_index.json
    lookup_function,           # Find function across modules (returns list of dicts)
    resolve_function_file,     # Function name -> absolute .cpp Path
    resolve_module_dir,        # Module name -> extracted_code/ Path
    list_extracted_modules,    # All module folder names with indexes
    filter_by_library,         # Filter index by library tag / app_only / lib_only
    is_application_function,   # True if library tag is null
    is_library_function,       # True if library tag is set
)
```

#### Common Patterns

**Find and read a function's source file:**

```python
from helpers import resolve_function_file

path = resolve_function_file("AiLaunchProcess")
if path:
    code = path.read_text(encoding="utf-8")
```

**Look up a function with full details:**

```python
from helpers import lookup_function

matches = lookup_function("BatLoop")
# [{"function_name": "BatLoop", "module": "cmd_exe", "file": "cmd_exe_standalone_group_7.cpp",
#   "file_path": "C:/.../extracted_code/cmd_exe/cmd_exe_standalone_group_7.cpp", "library": None}]
```

**List all application functions in a module:**

```python
from helpers import load_function_index, filter_by_library

index = load_function_index("appinfo_dll")
app_funcs = filter_by_library(index, app_only=True)
print(f"{len(app_funcs)} application functions")
```

**Get module statistics:**

```python
from helpers.function_index import compute_stats, load_function_index

index = load_function_index("appinfo_dll")
stats = compute_stats(index)
# {"total_functions": 1152, "app_functions": 598, "library_functions": 554,
#  "library_breakdown": {"WIL": 465, "WRL": 47, ...}, "file_count": 240, "files": [...]}
```

**Group functions by `.cpp` file:**

```python
from helpers.function_index import group_by_file, load_function_index

index = load_function_index("cmd_exe")
by_file = group_by_file(index)
for filename, funcs in sorted(by_file.items()):
    print(f"{filename}: {len(funcs)} functions")
```

**Search across all modules at once:**

```python
from helpers import load_all_function_indexes

all_indexes = load_all_function_indexes()
for module, index in all_indexes.items():
    for func_name in index:
        if "Security" in func_name:
            print(f"{module}: {func_name}")
```

## Full Helper API Reference

Available via `from helpers import ...` or `from helpers.function_index import ...`:

| Function                          | Returns                        | Description                                        |
| --------------------------------- | ------------------------------ | -------------------------------------------------- |
| `load_function_index(mod)`        | `dict` or `None`               | Load a module's function_index.json                |
| `load_all_function_indexes()`     | `dict[str, dict]`              | Load indexes for every module                      |
| `lookup_function(name, mod?)`     | `list[dict]`                   | Find function by exact name across modules         |
| `resolve_function_file(name, mod?)` | `Path` or `None`             | Resolve function name to absolute .cpp path        |
| `resolve_module_dir(mod)`         | `Path` or `None`               | Module name to its extracted_code/ directory        |
| `function_index_path(mod)`        | `Path` or `None`               | Absolute path to a module's function_index.json    |
| `list_extracted_modules()`        | `list[str]`                    | All module folders containing function_index.json  |
| `filter_by_library(idx, ...)`     | `dict`                         | Filter entries by library / app_only / lib_only    |
| `is_application_function(entry)`  | `bool`                         | True when library tag is null                      |
| `is_library_function(entry)`      | `bool`                         | True when library tag is set                       |
| `get_library_tag(entry)`          | `str` or `None`                | Return the library tag                             |
| `group_by_file(idx)`              | `dict[str, list[str]]`         | Group function names by .cpp filename              |
| `group_by_library(idx)`           | `dict[str\|None, list[str]]`  | Group function names by library tag                |
| `compute_stats(idx)`              | `dict`                         | Total/app/lib counts, breakdown, file count        |

## Library Tags

| Tag                | Meaning                                            |
| ------------------ | -------------------------------------------------- |
| `null`             | Application code (the module's own logic)          |
| `WIL`              | Windows Implementation Library (RAII, telemetry)   |
| `STL`              | C++ standard library (`std::`, `stdext::`)         |
| `WRL`              | Windows Runtime C++ Template Library (COM)         |
| `CRT`              | C/C++ runtime (`__scrt_*`, `__acrt_*`, `_CRT_*`)  |
| `ETW/TraceLogging` | TraceLogging / ETW telemetry helpers               |

Use `--app-only` (CLI) or `filter_by_library(index, app_only=True)` (Python) to skip boilerplate.

## Files

```
function-index/
├── SKILL.md                        # Agent skill instructions (read by Cursor)
├── README.md                       # This file
└── scripts/
    ├── _common.py                  # Thin re-export from helpers (+ sys.path setup)
    ├── lookup_function.py          # Find functions by name across modules
    ├── index_functions.py          # List/filter/group/stats for module functions
    └── resolve_function_file.py    # Resolve function names to absolute .cpp paths

helpers/function_index/             # Core logic (importable by any skill)
├── __init__.py                     # Re-exports all public functions
└── index.py                        # Module discovery, loading, filtering, resolution
```

## Dependencies

- Python 3.10+
- `extracted_code/` directory with `function_index.json` files (generated by DeepExtractIDA with `--generate-cpp`)

## Related Skills

- [analyze-ida-decompiled](../analyze-ida-decompiled/SKILL.md) -- Navigate and understand decompiled code
- [code-lifting](../code-lifting/SKILL.md) -- Lift decompiled functions into clean source
- [classify-functions](../classify-functions/SKILL.md) -- Classify functions by purpose
- [batch-lift](../batch-lift/SKILL.md) -- Lift groups of related functions together
- [data-flow-tracer](../data-flow-tracer/SKILL.md) -- Trace data flow through binaries
- [callgraph-tracer](../callgraph-tracer/SKILL.md) -- Trace call graphs across modules
