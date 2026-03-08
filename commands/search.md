# Search

## Overview

Search across all analysis dimensions in one call -- function names, signatures, string literals, API calls, dangerous APIs, class names, and exports. Wraps `unified_search.py` to find everything related to a search term without needing to know which dimension it belongs to.

Supports three matching modes:
- **substring** (default) -- case-insensitive substring matching
- **regex** -- Python regex via `re.search()`
- **fuzzy** -- typo-tolerant matching via `difflib.SequenceMatcher`

Results are ranked by relevance score (match quality + context signals like application vs library code, decompiled availability, export status, dangerous API presence, and multi-dimension hits).

The text after `/search` specifies the **search term** and optionally the **module**, **mode**, and **dimensions**:
- `/search CreateProcess` -- search all modules, all dimensions (substring)
- `/search appinfo.dll CreateProcess` -- search specific module
- `/search appinfo.dll --dimensions name,api CreateProcess` -- restrict to name and API dimensions
- `/search --all registry` -- explicitly search all modules
- `/search appinfo.dll --regex "^Ai.*Process$"` -- regex mode
- `/search --fuzzy CreateProces` -- fuzzy mode (typo-tolerant)
- `/search appinfo.dll CreateProcess --sort score` -- explicitly sort by relevance

If no search term is provided, ask the user.

## IMPORTANT: Execution Model

**This is an execute-immediately command. Do NOT present anything for user confirmation.** Run and write the final search results straight to the chat as your response. The user expects to see the completed output.

## Execution Context

> **IMPORTANT**: Any inline Python that imports `helpers.*` must run with `cd <workspace>/.agent`
> (so the `.agent/` directory is on `sys.path`), **not** from the workspace root.
> Script invocations like `python .agent/skills/.../script.py` can be run from the workspace root
> because those scripts manage their own path setup.

## Steps

### Step 0: Preflight Validation

Validate arguments using `helpers.command_validation.validate_command_args("search", {"module": "<module>", "term": "<search_term>"})`.
If validation fails, report the errors and stop. On success, use `result.resolved["db_path"]` for subsequent script calls.

1. **Resolve the search target**
   - If a module name is provided:
     Use `python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py <module>` to resolve the DB path.
   - If no module is specified (or `--all` is used):
     Use the `--all` flag to search across all analyzed module databases.

> **Tip:** `unified_search.py` supports `--json` for machine-readable output. Use `--json` when parsing script output programmatically.

2. **Run the search**

   ```bash
   # Search all dimensions in a specific module (substring, default)
   python .agent/helpers/unified_search.py <db_path> --query <term>

   # Regex mode: find functions matching a pattern
   python .agent/helpers/unified_search.py <db_path> --query "^Ai.*Process$" --regex

   # Fuzzy mode: typo-tolerant search
   python .agent/helpers/unified_search.py <db_path> --query "CreateProces" --fuzzy

   # Fuzzy with custom threshold (0.0-1.0, default 0.6)
   python .agent/helpers/unified_search.py <db_path> --query "CretFle" --fuzzy --threshold 0.5

   # Search all modules
   python .agent/helpers/unified_search.py --all --query <term>

   # Restrict to specific dimensions
   python .agent/helpers/unified_search.py <db_path> --query <term> --dimensions name,api,string

   # Limit results per dimension
   python .agent/helpers/unified_search.py <db_path> --query <term> --limit 10

   # Sort by name or ID instead of relevance score
   python .agent/helpers/unified_search.py <db_path> --query <term> --sort name

   # JSON output
   python .agent/helpers/unified_search.py <db_path> --query <term> --json
   ```

   Available modes: `substring` (default), `regex`, `fuzzy`. Shorthand flags: `--regex`, `--fuzzy`.

   Available dimensions: `name`, `signature`, `string`, `api`, `dangerous`, `class`, `export`.

   Sort options: `score` (default), `name`, `id`.

   Use the user's `--dimensions`, `--limit`, `--mode`, `--threshold`, and `--sort` values if provided. Defaults: all dimensions, limit 25, substring mode, threshold 0.6, sort by score.

3. **Present results**
   - **Search Summary**: total unique functions matched, result counts per dimension, match mode used
   - **Results by Dimension**: grouped results showing function ID, relevance score, name, and match context for each dimension (sorted by relevance by default)
   - **Highlights**: call out the most interesting hits -- high-scoring results, functions that appear across multiple dimensions, exports, functions with dangerous APIs
   - **Recommended Next Steps**: suggest follow-up commands based on what was found

## Output

Present the search results in chat, grouped by dimension. This is a lightweight retrieval command; file output is on-request only.

**Follow-up suggestions based on result types**:
- Function name hit: `/explain <module> <function>` -- understand what it does
- API call hit: `/explain <module> <function>` -- see how the API is used in context
- String hit: `/explain <module> <function>` -- see the string's role in the function
- Export hit: `/trace-export <module> <export>` -- trace the export's call chain
- Dangerous API hit: `/audit <module> <function>` -- security audit the function
- Class hit: `/lift-class <module> <class>` -- reconstruct the class

## Error Handling

- **Module not found**: List available modules and ask the user to choose, or suggest `--all`
- **No results found**: Suggest broadening the search with `--fuzzy`, `--regex`, or different `--dimensions`
- **DB access failure**: Report the error with the DB path and suggest running `/health`
- **Invalid regex pattern**: Report the regex syntax error and suggest correcting the pattern
