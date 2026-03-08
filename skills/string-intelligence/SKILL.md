---
name: string-intelligence
description: >-
  Analyze string literals extracted from decompiled functions for
  security-relevant patterns including URLs, file paths, registry keys,
  format strings, error messages, ETW provider GUIDs, and hardcoded
  credentials. Use when the user asks to find URLs, file paths, or
  registry keys in strings, wants to understand what strings a function
  or module references, asks about hardcoded secrets, or needs string
  categorization for triage.
---

# String Intelligence

## Purpose

Scan string literals from individual analysis databases and classify them
into security-relevant categories. Researchers use this to quickly identify
interesting strings (URLs pointing to C2 infrastructure, registry keys
indicating persistence, format strings suggesting logging) without manually
reading every function.

## Data Sources

### SQLite Databases (primary)

- `string_literals` JSON field in the `functions` table of individual analysis DBs
- `function_name` for context on which function owns each string
- See [data_format_reference.md](../../docs/data_format_reference.md) for schema

### Finding a Module DB

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py --list
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll
```

### Quick Cross-Dimensional Search

```bash
python .agent/helpers/unified_search.py <db_path> --query "CreateProcess" --json
```

## Utility Scripts

### analyze_strings_deep.py -- Deep String Categorization (Start Here)

Scan all string literals in a module and classify them by security relevance.
Supports module-wide scan or single-function targeting.

```bash
# Full module scan (human-readable)
python .agent/skills/string-intelligence/scripts/analyze_strings_deep.py <db_path>

# JSON output for downstream processing
python .agent/skills/string-intelligence/scripts/analyze_strings_deep.py <db_path> --json

# Filter to a specific function by ID
python .agent/skills/string-intelligence/scripts/analyze_strings_deep.py <db_path> --id <func_id>

# Filter to a specific function by name
python .agent/skills/string-intelligence/scripts/analyze_strings_deep.py <db_path> --function <name>

# Show only top N per category
python .agent/skills/string-intelligence/scripts/analyze_strings_deep.py <db_path> --top 20

# Filter to a specific category
python .agent/skills/string-intelligence/scripts/analyze_strings_deep.py <db_path> --category file_path

# Bypass cache
python .agent/skills/string-intelligence/scripts/analyze_strings_deep.py <db_path> --no-cache
```

Output includes: category, matched pattern description, source function(s), reference count, and risk indicator for each string.

## Workflows

### Workflow 1: "What interesting strings does this binary reference?"

String Triage Progress:
- [ ] Step 1: Resolve the module DB
- [ ] Step 2: Run deep string analysis
- [ ] Step 3: Review high-value categories

**Step 1**: Resolve the module DB.

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py <module_name>
```

**Step 2**: Run the analysis.

```bash
python .agent/skills/string-intelligence/scripts/analyze_strings_deep.py <db_path> --json
```

**Step 3**: Review output -- focus on `url`, `registry_key`, `named_pipe`, `rpc_endpoint`, and `certificate` categories. These are the highest-value categories for security research.

### Workflow 2: "What strings does this function use?"

**Step 1**: Identify the function.

```bash
python .agent/skills/function-index/scripts/lookup_function.py <function_name> --json
```

**Step 2**: Run string analysis on that function.

```bash
python .agent/skills/string-intelligence/scripts/analyze_strings_deep.py <db_path> --id <func_id> --json
```

## Direct Helper Module Access

For programmatic use without the script wrapper:

- `helpers.categorize_string(s)` -- Classify a single string, returns `(category, description)` or `None`
- `helpers.STRING_TAXONOMY` -- Full taxonomy list of `(pattern, category, description)` tuples
- `helpers.categorize_strings(strings)` -- Batch-categorize into `{category: [strings...]}`

## Integration with Other Skills

| Task | Recommended Skill |
|------|-------------------|
| Classify functions that reference interesting strings | classify-functions |
| Build security dossier for functions with dangerous strings | security-dossier |
| Trace data flow from string usage to API calls | data-flow-tracer |
| Taint-trace string parameters to sinks | taint-analysis |

## Performance

| Operation | Typical Time | Notes |
|-----------|-------------|-------|
| Analyze single function | ~0.1s | Per-function string scan |
| Full module scan | ~3-5s | Scales linearly with total string count |
| Module with 10k+ strings | ~5-8s | I/O bound on large DBs |

## Additional Resources

- [reference.md](reference.md) -- Regex patterns and category definitions
- [data_format_reference.md](../../docs/data_format_reference.md) -- `string_literals` table schema
- Related skills: [classify-functions](../classify-functions/SKILL.md) for function-level triage,
  [security-dossier](../security-dossier/SKILL.md) for per-function security context
