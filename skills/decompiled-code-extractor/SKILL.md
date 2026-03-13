---
name: decompiled-code-extractor
description: Extract function data from DeepExtractIDA analysis databases -- decompiled C++, raw x64 assembly, signatures, string literals, xrefs, vtable contexts, global variable accesses, stack frames, and loop analysis. Use when you need to locate a module's analysis database, list or search functions within it, or extract all data for a specific function. This is the foundational data-access skill that other skills depend on.
cacheable: false
depends_on: []
---

# Decompiled Code Extractor

## Purpose

Extract structured function data from DeepExtractIDA analysis databases.
This skill provides the core scripts for locating module databases,
listing and searching functions, and extracting complete per-function
records. It is the foundational data-access layer that nearly every other
skill depends on.

The scripts do not perform any analysis, lifting, or rewriting. They
are purely data retrieval tools.

## When NOT to Use

- Classifying functions by purpose or triaging a module -- use **classify-functions**
- Understanding what a function does (explanation, not raw data) -- use **re-analyst** or `/explain`
- Tracing call chains or cross-module execution paths -- use **callgraph-tracer**
- Scanning for vulnerabilities in extracted code -- use **memory-corruption-detector** or **logic-vulnerability-detector**
- Lifting or rewriting decompiled code to readable C++ -- use **code-lifting** or the **code-lifter** agent

## Data Sources

### Finding a Module DB

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py --list
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll
```

### Locating the Target Function

Functions come from two sources:

**1. Generated .cpp files** in `extracted_code/{module}/`:

- Class methods: `{module}_{ClassName}_group_{N}.cpp`
- Standalone: `{module}_standalone_group_{N}.cpp`
- Each function has a comment header: `// Function Name:`, `// Mangled Name:`, `// Function Signature (Extended):`, `// Function Signature:`

**2. SQLite databases** in `extracted_dbs/` (preferred -- contains assembly):

- Use the utility scripts in `scripts/` to extract function data
- Each function record has `decompiled_code`, `assembly_code`, signatures, xrefs, strings, and more

**3. Function index** (fastest): `python .agent/skills/function-index/scripts/lookup_function.py <name>` resolves the function name to its .cpp file path across all modules. Use `--app-only` to skip library boilerplate.

**4. Unified search** (broadest): When you don't know whether the target is a function name, string literal, API call, or class name, use the unified search to check all dimensions at once:

```bash
python .agent/helpers/unified_search.py <db_path> --query "CreateProcess"
# Searches: function names, signatures, strings, APIs, classes, exports
# Returns: grouped results by match dimension with function IDs
```

## Utility Scripts

Pre-built scripts in the `scripts/` subdirectory handle all DB extraction. **Execute these** instead of writing inline Python.

All scripts auto-resolve workspace root and `.agent/helpers/` imports. Run from the workspace root directory.

### find_module_db.py -- Map Module Name to Analysis DB (Start Here)

```bash
# Find DB for a specific module
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll

# List all analyzed modules
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py --list

# Search by extension
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py --ext .dll
```

### list_functions.py -- List or Search Functions in a Module DB

```bash
# List all functions
python .agent/skills/decompiled-code-extractor/scripts/list_functions.py extracted_dbs/appinfo_dll_e98d25a9e8.db

# Search by name pattern with signatures
python .agent/skills/decompiled-code-extractor/scripts/list_functions.py extracted_dbs/appinfo_dll_e98d25a9e8.db --search "Check" --with-signatures

# Only functions with decompiled code
python .agent/skills/decompiled-code-extractor/scripts/list_functions.py extracted_dbs/cmd_exe_6d109a3a00.db --has-decompiled
```

### extract_function_data.py -- Extract All Data for a Function

```bash
# By function name
python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py extracted_dbs/appinfo_dll_e98d25a9e8.db AiCheckSecureApplicationDirectory

# By function ID (from list_functions.py output)
python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py extracted_dbs/appinfo_dll_e98d25a9e8.db --id 124

# Search for functions matching a pattern
python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py extracted_dbs/cmd_exe_6d109a3a00.db --search "BatLoop"
```

Output includes: signatures, decompiled C++, assembly, string literals, outbound/inbound xrefs, vtable contexts, global variable accesses, stack frame, and loop analysis.

## Workflows

### Workflow 1: "Extract all data for a specific function"

Extraction Progress:
- [ ] Step 1: Locate the module database
- [ ] Step 2: Find the target function
- [ ] Step 3: Extract full function data

**Step 1**: Locate the module database.

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py <module_name>
```

**Step 2**: Find the target function by name or search pattern.

```bash
python .agent/skills/decompiled-code-extractor/scripts/list_functions.py <db_path> --search "<pattern>"
```

**Step 3**: Extract the full function record.

```bash
python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py <db_path> <function_name> --json
```

### Workflow 2: "List all functions in a module"

- [ ] Step 1: Locate the module database
- [ ] Step 2: List functions with optional filtering

**Step 1**: Locate the module database.

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py <module_name>
```

**Step 2**: List all functions, optionally filtering to those with decompiled code.

```bash
python .agent/skills/decompiled-code-extractor/scripts/list_functions.py <db_path> --has-decompiled --json
```

### discover_workspace_ipc.py -- Discover Workspace IPC Servers

Intersect workspace modules with the COM, RPC, and WinRT indexes to find
which modules implement IPC servers.

```bash
python .agent/skills/decompiled-code-extractor/scripts/discover_workspace_ipc.py --json
python .agent/skills/decompiled-code-extractor/scripts/discover_workspace_ipc.py --type com --json
python .agent/skills/decompiled-code-extractor/scripts/discover_workspace_ipc.py --type rpc --type winrt --json
```

## Direct Helper Module Access

For advanced queries not covered by the scripts, use the `.agent/helpers/` Python modules directly:

```python
from helpers import open_individual_analysis_db, open_analyzed_files_db

# Custom queries on individual DB
with open_individual_analysis_db("extracted_dbs/module_hash.db") as db:
    db.search_functions_by_signature("%keyword%")
    db.get_function_by_mangled_name("?Name@@...")
    db.get_file_info()  # binary metadata (imports, exports, sections)
```

See [reference.md](reference.md) for full API details.

## Integration with Other Skills

| Task | Recommended Skill |
|------|-------------------|
| Classify extracted functions by purpose | classify-functions |
| Trace call graphs from extracted functions | callgraph-tracer |
| Reconstruct struct types from extracted code | reconstruct-types |
| Lift extracted functions to clean code | code-lifting / batch-lift |
| Verify decompiler accuracy for extracted functions | verify-decompiled |

## Performance

| Operation | Typical Time | Notes |
|-----------|-------------|-------|
| Extract function data | ~1-2s | Single function DB lookup |
| List/search functions | ~1-3s | Index-based when available |
| Find module DB | <1s | Tracking DB lookup |

## Additional Resources

- For detailed technical reference (DB fields, query patterns), see [reference.md](reference.md)
- For DB schema and JSON field formats, see [data_format_reference.md](../../docs/data_format_reference.md)
- For file_info.json schema, see [file_info_format_reference.md](../../docs/file_info_format_reference.md)
- For code lifting workflow, see [code-lifting](../code-lifting/SKILL.md)
- For code analysis skill, see [analyze-ida-decompiled](../analyze-ida-decompiled/SKILL.md)
