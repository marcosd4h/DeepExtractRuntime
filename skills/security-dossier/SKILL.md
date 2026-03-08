---
name: security-dossier
description: Build comprehensive security context dossiers for functions in DeepExtractIDA binaries -- gathering identity, attack reachability, data flow exposure, dangerous operations, resource patterns, complexity metrics, and neighboring context in one command. Use when the user asks to audit a function's security posture, build a security dossier, assess attack surface, check function reachability from exports, find dangerous API usage, or needs pre-audit context gathering for a decompiled function.
---

# Security Context Dossier

## Purpose

One-command deep context gathering for security auditing. Before manually reviewing a decompiled function, the researcher needs to understand its security landscape. This skill builds a comprehensive dossier covering:

1. **Function Identity** -- Name, signature, class membership, mangled name
2. **Attack Reachability** -- Exported? Entry point? Reachable from exports? Shortest path from entry?
3. **Untrusted Data Exposure** -- Which export callers can feed external data? How many hops?
4. **Dangerous Operations** -- Direct dangerous APIs, security-relevant callees by category, callee-depth analysis
5. **Resource Patterns** -- Synchronization, memory operations, global variable reads/writes
6. **Complexity Assessment** -- Instructions, branches, loops, cyclomatic complexity, stack frame
7. **Neighboring Context** -- Class methods, direct callees/callers
8. **Module Security Posture** -- ASLR, DEP, CFG, SEH status

## Data Sources

- **Individual analysis DBs** (`extracted_dbs/{module}_{hash}.db`): Function records, xrefs, assembly, loop analysis, stack frame, dangerous APIs, global accesses
- **Tracking DB** (`extracted_dbs/analyzed_files.db`): Module name to DB path mapping
- **Exports/Entry points**: From `file_info` table in individual DBs
- **Security features**: From `file_info.security_features`

For DB schema details, see [data_format_reference.md](../../docs/data_format_reference.md).

### Finding a Module DB

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py --list
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll
```

### Quick Cross-Dimensional Search

To search across function names, signatures, strings, APIs, classes, and exports in one call:

```bash
python .agent/helpers/unified_search.py <db_path> --query "SearchTerm"
python .agent/helpers/unified_search.py <db_path> --query "SearchTerm" --json
```

## Utility Scripts

All scripts are in `scripts/`. Run from the workspace root.

### build_dossier.py -- Build Security Dossier (Start Here)

Single command to produce the full dossier:

```bash
# By function name
python .agent/skills/security-dossier/scripts/build_dossier.py <db_path> <function_name>

# By function ID
python .agent/skills/security-dossier/scripts/build_dossier.py <db_path> --id <function_id>

# Search for functions matching a pattern
python .agent/skills/security-dossier/scripts/build_dossier.py <db_path> --search <pattern>

# JSON output (machine-readable)
python .agent/skills/security-dossier/scripts/build_dossier.py <db_path> <function_name> --json

# Deeper callee analysis (check callees' callees for dangerous APIs)
python .agent/skills/security-dossier/scripts/build_dossier.py <db_path> <function_name> --callee-depth 2
```

Examples:

```bash
python .agent/skills/security-dossier/scripts/build_dossier.py extracted_dbs/appinfo_dll_e98d25a9e8.db AiCheckSecureApplicationDirectory
python .agent/skills/security-dossier/scripts/build_dossier.py extracted_dbs/cmd_exe_6d109a3a00.db --search "BatLoop"
python .agent/skills/security-dossier/scripts/build_dossier.py extracted_dbs/cmd_exe_6d109a3a00.db BatLoop --json
```

## Workflows

```
Security Dossier Progress:
- [ ] Step 1: Find the module DB
- [ ] Step 2: Build the dossier
- [ ] Step 3: Review the dossier sections
- [ ] Step 4: Deep dive into flagged areas
```

**Step 1**: Find the Module DB

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll
```

**Step 2**: Build the Dossier

```bash
python .agent/skills/security-dossier/scripts/build_dossier.py <db_path> <function_name>
```

**Step 3**: Review the Dossier

Focus on these high-priority indicators:

| Indicator                        | Meaning                                                          |
| -------------------------------- | ---------------------------------------------------------------- |
| **Externally Reachable = YES**   | Function can be triggered from outside the module                |
| **Direct Dangerous APIs**        | Immediate dangerous behavior (memory-unsafe, command exec, etc.) |
| **Security-Relevant Callees**    | Sensitive operations performed via callees                       |
| **Receives External Data = YES** | Untrusted data can flow to this function                         |
| **Global Writes**                | State mutation affecting other functions                         |
| **No Canary + Large Stack**      | Stack buffer overflow risk                                       |
| **High Cyclomatic Complexity**   | Complex control flow, higher bug probability                     |

**Step 4**: Deep Dive

Based on dossier findings, use complementary skills:

- **Taint analysis** -- trace tainted parameters forward to dangerous sinks with guard/bypass analysis:

```bash
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> <function> --depth 2
```

- **Code lifting** -- lift the function for detailed review:

```bash
python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py <db_path> <function>
```

- **Call graph tracing** -- follow execution paths across modules:

```bash
python .agent/skills/callgraph-tracer/scripts/chain_analysis.py <db_path> <function> --depth 3
```

- **Data flow tracing** -- trace specific parameter flows:

```bash
python .agent/skills/data-flow-tracer/scripts/forward_trace.py <db_path> <function> --param 1
```

- **Decompiler verification** -- verify decompiled code accuracy:

```bash
python .agent/skills/verify-decompiled/scripts/verify_function.py <db_path> <function>
```

## Dossier Section Reference

### 1. Function Identity

Source: `functions` table -- `function_name`, `function_signature`, `function_signature_extended`, `mangled_name`. Class membership inferred from `::` in the function name.

**Library tag**: When available, `lookup_function()` from helpers provides the function's library tag (WIL/STL/WRL/CRT/ETW) and `.cpp` source file path.

### 2. Attack Reachability

Source: `file_info.exports`, `file_info.entry_point`, `simple_inbound_xrefs`. BFS upward through callers to find paths from exports/entry points. Reports whether the function is externally reachable and the shortest path from an entry point.

### 3. Untrusted Data Exposure

Combines reachability with exports analysis. Functions reachable from exports may receive untrusted external input. Traces data paths from export callers to the target.

### 4. Dangerous Operations

Source: `dangerous_api_calls` (direct), `simple_outbound_xrefs` classified by security API category. With `--callee-depth >= 1`, also checks internal callees' dangerous APIs. Categories: memory_unsafe, command_execution, code_injection, privilege, file_write, registry_write, network, crypto, sync, memory_alloc.

### 5. Resource Patterns

Source: `simple_outbound_xrefs` classified for sync/memory/file APIs. `global_var_accesses` for global state reads/writes.

### 6. Complexity Assessment

Source: `assembly_code` (instruction/branch/call counts), `loop_analysis` (loop count, cyclomatic complexity), `stack_frame` (sizes, canary, exception handler).

### 7. Neighboring Context

Source: Functions sharing the same `ClassName::` prefix. Direct callees/callers from xrefs.

## Direct Helper Module Access

For programmatic use without skill scripts:

- `helpers.classify_api_security(api_name)` -- Classify API for security relevance
- `helpers.get_dangerous_api_set()` -- Get the set of known dangerous APIs
- `helpers.CallGraph.from_functions(functions)` -- Build call graph for reachability analysis
- `helpers.categorize_string(string)` -- Categorize a string literal for security relevance
- `helpers.resolve_function(db, name_or_id)` -- Resolve function by name or ID

## Integration with Other Skills

| Task | Recommended Skill |
|------|-------------------|
| Trace tainted parameters to dangerous sinks | taint-analysis |
| Trace call chains from audited functions | callgraph-tracer |
| Trace data flow for sensitive parameters | data-flow-tracer |
| Classify functions in the audit neighborhood | classify-functions |
| Map entry points reachable from audited function | map-attack-surface |
| Lift audited functions to clean code for review | code-lifting / batch-lift |

## Performance

| Operation | Typical Time | Notes |
|-----------|-------------|-------|
| Build single function dossier | ~5-10s | Gathers from multiple skills |
| Build dossier (deep callee scan) | ~15-30s | With --callee-depth 2+ |

## Additional Resources

- For detailed technical reference, see [reference.md](reference.md)
- For DB schema and JSON formats, see [data_format_reference.md](../../docs/data_format_reference.md)
- For file_info.json schema, see [file_info_format_reference.md](../../docs/file_info_format_reference.md)
- For code lifting, see [code-lifting](../code-lifting/SKILL.md)
- For call graph tracing, see [callgraph-tracer](../callgraph-tracer/SKILL.md)
- For data flow tracing, see [data-flow-tracer](../data-flow-tracer/SKILL.md)
- For function classification, see [classify-functions](../classify-functions/SKILL.md)
