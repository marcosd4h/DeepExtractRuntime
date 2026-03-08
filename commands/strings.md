# String Intelligence

## Overview

Categorize and analyze string literals by security relevance. Identifies credentials, file paths, registry keys, named pipes, URLs, format strings, embedded commands, certificate references, and other security-interesting string patterns in decompiled functions.

Usage:

- `/strings appinfo.dll` -- full module string analysis with security categorization
- `/strings appinfo.dll --top 20` -- top 20 security-relevant strings
- `/strings appinfo.dll --category credentials` -- filter by category
- `/strings appinfo.dll AiLaunchProcess` -- strings in a specific function
- `/strings appinfo.dll --category format_string` -- find potential format string sinks

## IMPORTANT: Execution Model

**This is an execute-immediately command. Do NOT present anything for user confirmation.** Run and write the string analysis straight to the chat as your response. The user expects to see the completed output.

## Execution Context

> **IMPORTANT**: Any inline Python that imports `helpers.*` must run with `cd <workspace>/.agent`
> (so the `.agent/` directory is on `sys.path`), **not** from the workspace root.
> Script invocations like `python .agent/skills/.../script.py` can be run from the workspace root
> because those scripts manage their own path setup.

## Steps

### Step 0: Preflight Validation

Validate arguments using `helpers.command_validation.validate_command_args("strings", {"module": "<module>"})`.
If validation fails, report the errors and stop. On success, use `result.resolved["db_path"]` for subsequent script calls.

### 1. Find the module DB

Use the **decompiled-code-extractor** skill (`find_module_db.py`) to resolve the module name to its DB path.

> **Tip:** All skill scripts support `--json` for machine-readable output. Use `--json` when parsing script output programmatically.

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py <module_name> --json
```

### 2. Run string intelligence analysis

**Module-wide analysis** (default):

```bash
python .agent/skills/string-intelligence/scripts/analyze_strings_deep.py <db_path> --json
```

**With top-N limit**:

```bash
python .agent/skills/string-intelligence/scripts/analyze_strings_deep.py <db_path> --top 20 --json
```

**Filter by category** (`--category`):

```bash
python .agent/skills/string-intelligence/scripts/analyze_strings_deep.py <db_path> --category credentials --json
python .agent/skills/string-intelligence/scripts/analyze_strings_deep.py <db_path> --category format_string --json
```

**Specific function** (function name or ID):

```bash
python .agent/skills/string-intelligence/scripts/analyze_strings_deep.py <db_path> --function <function_name> --json
python .agent/skills/string-intelligence/scripts/analyze_strings_deep.py <db_path> --id <function_id> --json
```

### 3. Present results

**String Category Distribution:**
- Total strings analyzed, breakdown by category
- Security-relevant string count vs benign

**Security-Relevant Strings** (ranked by relevance):

| # | Category | String (truncated) | Function | Risk |
|---|----------|--------------------|----------|------|
| 1 | credentials | "password=%s" | AuthLogin | HIGH |
| 2 | named_pipe | "\\\\.\\pipe\\..." | ConnectPipe | MEDIUM |
| 3 | registry_key | "SOFTWARE\\Microsoft\\..." | ReadConfig | LOW |

**Category-Specific Details:**
- **Credentials**: hardcoded passwords, API keys, tokens
- **File paths**: absolute paths, temp directories, sensitive file locations
- **Registry keys**: security-relevant registry access patterns
- **Named pipes**: IPC surface for privilege escalation
- **URLs**: network endpoints, update servers, C2-like patterns
- **Format strings**: `%s`, `%n` patterns in security-sensitive contexts
- **Embedded commands**: shell commands, PowerShell strings, WMI queries

## Output

Present the analysis in chat. This is a lightweight retrieval command; no workspace protocol needed.

**Follow-up suggestions:**

- `/audit <module> <function>` -- security audit a function with interesting strings
- `/taint <module> <function>` -- trace if string-consuming functions receive tainted input
- `/data-flow string <module> --string "<pattern>"` -- trace where a specific string is used
- `/search <module> <string_pattern>` -- find functions containing a string pattern

## Error Handling

- **Module not found**: List available modules via `find_module_db.py --list` and ask user to choose
- **Function not found**: Run a fuzzy search and suggest close matches
- **No strings found**: Report explicitly -- modules with no embedded strings are a data point
- **DB access failure**: Report the error with the DB path and suggest running `/health`
