# Quickstart

## Overview

Guided first experience for new users. Auto-detects available modules, runs
a lightweight triage on the best candidate, and presents results with
annotated follow-up suggestions.

Usage:
- `/quickstart` -- auto-detect and analyze the best candidate module
- `/quickstart <module>` -- quickstart with a specific module

This command is designed for users who have just opened the workspace and
want to get productive quickly. It replaces the need to read the onboarding
doc for basic orientation.

## Execution Model

Execute immediately -- no confirmation needed.

## Steps

### Step 1: Discover Available Modules

Check the session context for available modules. If not present, scan:

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py --list --json
```

### Step 2: Select Target Module and Resolve DB Path

If the user specified a module, use it. Otherwise:

1. If only one module exists, use it.
2. If multiple modules exist, pick the **most interesting** module -- not the smallest. Rank by: number of entry points (exports + COM + RPC), classification diversity (more distinct categories = more interesting), and presence of security-relevant APIs. Mention the others as available for later.

**Resolve `<db_path>`:** The `--list` output from Step 1 includes an `analysis_db_path` field for each module -- extract the value for the selected module and prefix it with `extracted_dbs/` to form the full `<db_path>` used in all subsequent script calls. If you need to resolve a single module directly:

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py <module_name> --json
# Returns: { "status": "ok", "db_path": "extracted_dbs/<module>_<hash>.db", ... }
# Use the "db_path" value as <db_path> in all subsequent calls.
```

> **Critical:** All scripts below require an **exact** DB path -- not a glob pattern, not a module name. Always resolve the path first.

### Step 3: Run Lightweight Triage

> **Tip:** All skill scripts support `--json` for machine-readable output. Use `--json` when parsing script output programmatically.

> **Important:** Never use `2>/dev/null` on script invocations -- stderr carries structured error JSON needed for diagnosis. Never write inline `python -c` commands when a skill script already exists for the operation.

Run these three lightweight analyses (all are fast, cached operations):

**a. Classification** -- categorize functions by purpose:

```bash
python .agent/skills/classify-functions/scripts/triage_summary.py <db_path> --json --top 5 --app-only
```

**b. Entry points** -- discover the top attack surface entries:

```bash
python .agent/skills/map-attack-surface/scripts/discover_entrypoints.py <db_path> --json
```

**c. Call graph stats** -- get topology overview:

```bash
python .agent/skills/callgraph-tracer/scripts/build_call_graph.py <db_path> --stats --json
```

Steps (a), (b), and (c) are independent -- run them concurrently for speed.

**d. Function lookup** (when the user specifies a function of interest) -- extract full data for the named function:

```bash
python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py <db_path> <function_name> --json
```

If the exact name is uncertain, search within the selected module:

```bash
python .agent/skills/decompiled-code-extractor/scripts/list_functions.py <db_path> --search "<name_fragment>" --json
```

If the **module** is also uncertain (user named a function but not a module), search across all modules first to find which module(s) contain it:

```bash
python .agent/skills/function-index/scripts/lookup_function.py "<name_fragment>"
```

This returns the module and .cpp file path for every match. Use the module name from the result to resolve `<db_path>` via `find_module_db.py <module_name> --json`, then proceed with `extract_function_data.py`.

Run concurrently with steps (a), (b), and (c).

### Step 4: Present Results

Format the output as a concise orientation:

```markdown
## Quick Start: <module_name>

**Module**: <file_name> -- <description>
**Functions**: <total> total (<app_count> application, <lib_count> library)
**Call Graph**: <nodes> nodes, <edges> edges, <hub_count> hub functions
**Entry Points**: <entry_count> discovered (<export_count> exports, <com_count> COM, <rpc_count> RPC)

### Top Interesting Functions

| Score | Category | Function |
|-------|----------|----------|
| 9 | security/process_launch | AiLaunchProcess |
| 8 | security/token | AiCheckToken |
| ... | ... | ... |

### Top Entry Points

| Type | Function | Description |
|------|----------|-------------|
| export | DllMain | Main entry point |
| COM | CAppInfo::LaunchElevated | COM method |
| ... | ... | ... |

### Recommended Next Step

Based on the analysis results, suggest the **single best next command** with a concrete explanation:

- If the module is **COM-heavy** (high COM entry point count): suggest `/reconstruct-types <module>` to understand the COM interface layout
- If the module is **security-relevant** (dangerous APIs, security classification): suggest `/audit <module> <top_security_function>` to investigate the most interesting security function
- If the module has **many entry points**: suggest `/triage <module>` for a full attack surface assessment
- If the module has **complex call graph** (many hub functions, deep chains): suggest `/callgraph <module> --stats` to understand the architecture
- **Default**: suggest `/explain <module> <top_function>` to understand the highest-scored function

### Other Things You Can Do

1. **Full module triage**: `/triage <module>` -- deep orientation with attack surface ranking
2. **Security audit**: `/audit <module> <function>` -- focused security assessment
3. **Call graph exploration**: `/callgraph <module>`
4. **Trace an export**: `/trace-export <module> <export_name>`
5. **Search for patterns**: `/search <module> CreateProcess`
```

### Step 5: Module Landscape (when multiple modules exist)

If other modules are available, present a brief comparative landscape:

```markdown
### Module Landscape

| Module | Functions | Exports | Entry Points | Key Traits |
|--------|-----------|---------|--------------|------------|
| **appinfo_dll** (selected) | 423 | 12 | 18 | COM-heavy, security-relevant |
| cmd_exe | 817 | 3 | 5 | dispatch-heavy |
| coredpus_dll | 1080 | 45 | 52 | class-heavy |

Try `/quickstart <module>` for any other module, or `/compare-modules <A> <B>` to compare.
```

Use module profiles from session context if available; otherwise just list names and function counts.

## Error Handling

| Failure | Recovery |
|---------|----------|
| No modules found | Explain that no extraction data is present. Suggest running DeepExtractIDA first. |
| Module not found | List available modules and ask the user to choose. |
| Classification fails | Show module identity info from file_info.json as fallback. |
| DB access failure | Report error, suggest `/health` for diagnostics. |
