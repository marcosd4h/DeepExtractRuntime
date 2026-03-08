# Decompiled Code Extractor

Answer: **"Find any module's database, search its functions, and extract everything the DB knows about a function."**

The foundational data-access skill that nearly every other skill depends on. Its three scripts locate analysis databases, list and search functions within them, and extract complete per-function records -- decompiled C++, raw x64 assembly, signatures, string literals, xrefs, vtable contexts, global variable accesses, stack frames, and loop analysis. The scripts are purely data retrieval; they do not perform any lifting, classification, or rewriting.

## Quick Start

```bash
# 1. Find the DB for a module
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll

# 2. Search for a function by name
python .agent/skills/decompiled-code-extractor/scripts/list_functions.py extracted_dbs/appinfo_dll_e98d25a9e8.db --search "Check" --with-signatures

# 3. Extract ALL data for a function (decompiled + assembly + context)
python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py extracted_dbs/appinfo_dll_e98d25a9e8.db AiCheckSecureApplicationDirectory
```

## Scripts

| Script                     | Purpose                                                                                              |
| -------------------------- | ---------------------------------------------------------------------------------------------------- |
| `find_module_db.py`        | Resolve a module name/extension to its analysis DB path via the `analyzed_files.db` tracking database |
| `list_functions.py`        | List, search, and filter functions in a module DB (by name pattern, decompiled status, signatures)    |
| `extract_function_data.py` | Extract all function data (decompiled code, assembly, signatures, xrefs, strings, vtables, globals, stack frame, loops) in one shot |

All scripts auto-resolve workspace root and `.agent/helpers/` imports. Run from the workspace root directory.

## Script Details

### find_module_db.py -- Module Resolution (Start Here)

Maps module names to their analysis database paths using the `analyzed_files.db` tracking database.

```bash
# Exact or partial name lookup
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll

# List ALL analyzed modules
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py --list

# Filter by extension
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py --ext .dll

# JSON output
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py --list --json
```

### list_functions.py -- Function Discovery

Lists and filters functions within a module database.

```bash
# List all functions (shows [asm|dec] availability indicators)
python .agent/skills/decompiled-code-extractor/scripts/list_functions.py extracted_dbs/appinfo_dll_e98d25a9e8.db

# Search by name pattern (case-insensitive)
python .agent/skills/decompiled-code-extractor/scripts/list_functions.py extracted_dbs/appinfo_dll_e98d25a9e8.db --search "Launch"

# Only functions that have decompiled code
python .agent/skills/decompiled-code-extractor/scripts/list_functions.py extracted_dbs/cmd_exe_6d109a3a00.db --has-decompiled --limit 50

# JSON output
python .agent/skills/decompiled-code-extractor/scripts/list_functions.py extracted_dbs/appinfo_dll_e98d25a9e8.db --json
```

### extract_function_data.py -- Complete Data Extraction

Extracts every piece of data the DB holds for a function in labeled sections.

```bash
# By function name
python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py extracted_dbs/appinfo_dll_e98d25a9e8.db AiCheckSecureApplicationDirectory

# By function ID (from list_functions.py output)
python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py extracted_dbs/cmd_exe_6d109a3a00.db --id 42

# Search for functions matching a pattern
python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py extracted_dbs/cmd_exe_6d109a3a00.db --search "BatLoop"

# JSON output
python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py extracted_dbs/appinfo_dll_e98d25a9e8.db AiCheckSecureApplicationDirectory --json
```

Output includes: function signatures, decompiled C++, assembly code, outbound/inbound xrefs, string literals, vtable contexts, global variable accesses, stack frame layout, and loop analysis.

## Data Sources

Functions come from two sources:

| Source                              | Location                   | Assembly? | When to Use                                                      |
| ----------------------------------- | -------------------------- | --------- | ---------------------------------------------------------------- |
| **SQLite databases** (preferred)    | `extracted_dbs/*.db`       | Yes       | Always -- contains assembly, xrefs, strings, vtables, everything |
| **Generated .cpp files** (fallback) | `extracted_code/{module}/` | No        | Only when DB is unavailable; lacks assembly ground truth         |

## Ecosystem Role

This skill is the **data extraction foundation** that other skills build on:

| Downstream Skill | How It Uses Extracted Data |
| --- | --- |
| [code-lifting](../code-lifting/SKILL.md) | Lifts extracted function data into clean C++ |
| [batch-lift](../batch-lift/SKILL.md) | Orchestrates extraction of related function groups |
| [verify-decompiled](../verify-decompiled/SKILL.md) | Compares extracted decompiled code against assembly |
| [classify-functions](../classify-functions/SKILL.md) | Classifies functions using extracted xrefs and strings |
| [callgraph-tracer](../callgraph-tracer/SKILL.md) | Builds call graphs from extracted xref data |
| [reconstruct-types](../reconstruct-types/SKILL.md) | Scans extracted code for struct field access patterns |
| [security-dossier](../security-dossier/SKILL.md) | Builds dossiers using extracted function context |

## Files

```
decompiled-code-extractor/
├── SKILL.md              # Agent skill instructions: data sources, scripts, workflows
├── reference.md          # Technical reference: FunctionRecord fields, DB tables, query patterns
├── README.md             # This file
└── scripts/
    ├── _common.py               # Shared bootstrap and helper re-exports
    ├── find_module_db.py        # Module name -> DB path resolution
    ├── list_functions.py        # Function listing/searching with filters
    └── extract_function_data.py # Complete function data extraction
```

## Dependencies

- Python 3.10+
- `.agent/helpers/` module (workspace root) -- provides `open_individual_analysis_db`, `open_analyzed_files_db`
- SQLite analysis databases from DeepExtractIDA (`extracted_dbs/`)
- Optional: `extracted_code/{module}/` directories for .cpp fallback and `file_info.json`

## Additional Resources

- [reference.md](reference.md) -- FunctionRecord fields, DB tables, query patterns
- [data_format_reference.md](../../docs/data_format_reference.md) -- DB schema and JSON field formats
- [file_info_format_reference.md](../../docs/file_info_format_reference.md) -- file_info.json schema
