# Import/Export Resolver

## Overview

Query PE import/export relationships across modules: who exports a function, who imports it, inter-module dependency graphs, and DLL forwarder chain resolution.

Usage:

- `/imports appinfo.dll` -- show import/export dependency summary for the module
- `/imports --function CreateProcessW` -- find who exports and who imports a function
- `/imports appinfo.dll --consumers` -- which modules depend on appinfo.dll's exports
- `/imports appinfo.dll --diagram` -- Mermaid diagram of module dependencies
- `/imports --forwarders appinfo.dll` -- resolve DLL forwarder chains
- `/imports --forwarders --function NtCreateFile` -- trace a forwarder chain for a specific function

## IMPORTANT: Execution Model

**This is an execute-immediately command. Do NOT present anything for user confirmation.** Run and write the results straight to the chat as your response. The user expects to see the completed output.

## Execution Context

> **IMPORTANT**: Any inline Python that imports `helpers.*` must run with `cd <workspace>/.agent`
> (so the `.agent/` directory is on `sys.path`), **not** from the workspace root.
> Script invocations like `python .agent/skills/.../script.py` can be run from the workspace root
> because those scripts manage their own path setup.

## Steps

### 1. Ensure the import/export index is built

The **import-export-resolver** skill requires an index of all modules' imports and exports. Build it if not cached:

> **Tip:** All skill scripts support `--json` for machine-readable output. Use `--json` when parsing script output programmatically.

```bash
python .agent/skills/import-export-resolver/scripts/build_index.py --json
```

This scans all modules in the workspace and builds a cross-reference index. Results are cached.

### 2. Query the index

**Function lookup** (`--function`): Find who exports and who imports a specific function:

```bash
python .agent/skills/import-export-resolver/scripts/query_function.py --function <function_name> --json
```

**Module dependencies** (module name given): Show which modules this module imports from and exports to:

```bash
python .agent/skills/import-export-resolver/scripts/module_deps.py --module <module_name> --json
```

**Consumer analysis** (`--consumers`): Which modules depend on this module's exports:

```bash
python .agent/skills/import-export-resolver/scripts/module_deps.py --module <module_name> --consumers --json
```

**Dependency diagram** (`--diagram`): Generate a Mermaid diagram of module dependencies:

```bash
python .agent/skills/import-export-resolver/scripts/module_deps.py --module <module_name> --diagram --json
```

**Forwarder resolution** (`--forwarders`): Trace DLL forwarder chains:

```bash
python .agent/skills/import-export-resolver/scripts/resolve_forwarders.py --module <module_name> --json
python .agent/skills/import-export-resolver/scripts/resolve_forwarders.py --function <function_name> --json
python .agent/skills/import-export-resolver/scripts/resolve_forwarders.py --all --json
```

### 3. Present results

**For function queries**, present:
- **Exported by**: module(s) that export this function, with ordinal if available
- **Imported by**: module(s) that import this function, with import type (by name / by ordinal)
- **Forwarder chain** (if forwarded): full resolution chain (e.g., `api-ms-win-* -> kernel32.dll -> kernelbase.dll`)

**For module dependency views**, present:
- **Import Summary**: count of imported DLLs, total imported functions
- **Top Import Sources**: ranked by function count
- **Export Summary**: total exports, named vs ordinal-only
- **Consumer Modules** (if `--consumers`): which modules import from this one
- **Mermaid Diagram** (if `--diagram`): visual dependency graph

**For forwarder resolution**, present:
- **Forwarder Chains**: table of `Export Name -> Forward Target -> Resolved Module`
- **Unresolved Forwarders**: any forwarders pointing to modules not in the workspace

## Output

Present the analysis in chat. Include Mermaid diagrams inline when requested. No workspace protocol needed for this lightweight command.

**Follow-up suggestions:**

- `/callgraph <module>` -- internal call graph topology
- `/trace-export <module> <export>` -- trace an export through its call chain
- `/compare-modules <moduleA> <moduleB>` -- cross-module comparison
- `/data-flow-cross forward <module> <function>` -- trace data flow across module boundaries

## Error Handling

- **No tracking DB found**: Report that no modules have been indexed. Suggest running `/health` or checking `extracted_dbs/`
- **Module not found**: List available modules and ask user to choose
- **Function not found**: Report not found in any module's imports or exports
- **Index not built**: Automatically run `build_index.py` and retry
