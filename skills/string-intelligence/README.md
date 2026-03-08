# String Intelligence

Standalone string analysis skill for the DeepExtractIDA Agent Analysis Runtime.

## Overview

Categorizes all string literals in a module's analysis database into
security-relevant categories (file paths, registry keys, URLs, RPC endpoints,
named pipes, certificates, GUIDs, format strings, error messages, ETW
providers, debug traces, ALPC paths, service accounts).

Previously embedded in `generate-re-report/scripts/analyze_strings.py`, this
skill provides the same analysis as an independently invocable and cacheable
pipeline step.

## Quick Start

```bash
# List available modules
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py --list

# Analyze strings in a module
python .agent/skills/string-intelligence/scripts/analyze_strings_deep.py extracted_dbs/appinfo_dll_f2bbf324a1.db

# JSON output
python .agent/skills/string-intelligence/scripts/analyze_strings_deep.py extracted_dbs/appinfo_dll_f2bbf324a1.db --json

# Single function
python .agent/skills/string-intelligence/scripts/analyze_strings_deep.py extracted_dbs/appinfo_dll_f2bbf324a1.db --id 42
```

## Scripts

| Script | Purpose | Key Flags |
|--------|---------|-----------|
| `analyze_strings_deep.py` | Categorize all strings in a module or function | `--json`, `--id`, `--function`, `--top`, `--category`, `--no-cache` |

## Output Format (JSON)

```json
{
  "status": "ok",
  "categories": {"file_path": [...], "registry_key": [...]},
  "summary": {"file_path": 42, "registry_key": 15},
  "total_unique_strings": 300,
  "total_string_refs": 850,
  "top_referenced": [{"string": "...", "category": "...", "count": 12}]
}
```

## Dependencies

- `decompiled-code-extractor` (for DB resolution)
- `helpers.string_taxonomy` (canonical categorization patterns)
