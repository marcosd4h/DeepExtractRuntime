# DeepExtractIDA Agent Analysis Runtime -- Onboarding Guide

Welcome to the DeepExtractIDA agent analysis runtime. This guide gets you productive
in 5 minutes with the extracted output from your analyzed binaries.

## What Is This?

DeepExtractIDA extracts decompiled code and metadata from Windows PE binaries
using IDA Pro. The `.agent` directory provides the Agent Analysis Runtime
built on top of that extracted data: specialized agents, analysis skills,
slash commands, and a shared helper library.

## Quickstart (5 Minutes)

### 1. Check health

```
/health
```

Verifies that extraction data, databases, and runtime infrastructure are present
and functional. Start here to confirm everything is wired up.

### 2. Triage a module

```
/triage appinfo.dll
```

Classifies every function, discovers entry points, and generates a summary.
This is the best first step for any module -- it tells you what the binary
does at a high level and identifies the most interesting functions.

### 3. Explain a function

```
/explain appinfo.dll AiLaunchProcess
```

Gets a structured explanation of what a specific function does: purpose,
parameters, security implications, called APIs, and cross-references.

### 4. Audit a function

```
/audit appinfo.dll AiLaunchProcess
```

Builds a security dossier: attack reachability, dangerous API calls, data
flow exposure, and resource patterns. Use this for security-relevant functions.

### 5. Lift a class

```
/lift-class appinfo.dll CSecurityDescriptor
```

Rewrites all methods of a C++ class into clean, readable code while preserving
exact behavioral equivalence. Builds shared struct definitions and naming maps
across methods.

## Available Modules

Run `/health` to see which modules are available in your workspace. As an example,
this workspace contains extracted data for:

| Module         | Description                                     |
| -------------- | ----------------------------------------------- |
| `appinfo.dll`  | Application Information Service (UAC elevation) |
| `cmd.exe`      | Windows Command Processor                       |
| `coredpus.dll` | Core DPS (Diagnostic Policy Service)            |

> **Note**: Your workspace may contain different modules depending on which
> binaries were processed by DeepExtractIDA. The list above reflects the
> modules present at the time this guide was written.

Each module has:

- **Extracted code** in `extracted_code/<module>/` (`.cpp` files, `file_info.json`, `function_index.json`)
- **Analysis database** in `extracted_dbs/<module>_<hash>.db` (SQLite with functions, xrefs, strings, loops)

## Common Workflows

### Security Audit Workflow

```
/triage appinfo.dll                    # Step 1: understand the module
/triage appinfo.dll --with-security    # Step 2: quick security scan
/audit appinfo.dll <top-function>      # Step 3: deep audit top entries
```

### Code Understanding Workflow

```
/explain appinfo.dll <function>       # What does it do?
/search appinfo.dll CreateProcess     # Find related functions
/audit appinfo.dll <export> --diagram  # Audit export with call graph
/data-flow appinfo.dll <function>     # Where does data go?
```

### Code Lifting Workflow

```
/reconstruct-types appinfo.dll        # Discover structs/classes
/lift-class appinfo.dll CMyClass      # Lift all class methods
/verify-decompiler appinfo.dll <method>          # Verify lifted code accuracy
```

### Full Analysis Workflow

```
/full-report appinfo.dll              # Runs everything: triage + security +
                                      # types + topology + deep research
```

## All Commands

| Command                           | Purpose                                   |
| --------------------------------- | ----------------------------------------- |
| `/health`                         | Check infrastructure health               |
| `/triage <module>`                | Classify functions, discover entry points |
| `/explain <module> <function>`    | Explain what a function does              |
| `/search <module> <term>`         | Search functions, strings, APIs           |
| `/audit <module> <function>`      | Security audit with dossier               |
| `/verify-decompiler <module> <function>`     | Check decompiler accuracy                 |
| `/verify-decompiler-batch <module>`          | Batch verify all functions                |
| `/lift-class <module> <class>`    | Lift C++ class methods                    |
| `/audit <module> <export> --diagram` | Audit with call graph from export      |
| `/data-flow <module> <function>`  | Trace data flow (forward/backward)        |
| `/data-flow-cross <function>`     | Cross-module data flow                    |
| `/reconstruct-types <module>`     | Reconstruct struct/class types            |
| `/state-machines <module>`        | Find dispatch tables and state machines   |
| `/compare-modules <A> <B>`        | Compare two modules                       |
| `/full-report <module>`           | Comprehensive multi-phase report          |
| `/cache-manage`                   | View/clear analysis cache                 |

## Architecture Overview

```
.agent/
  agents/          # Specialized subagents
    code-lifter/     # Lifts decompiled functions with shared context
    re-analyst/      # General RE analysis and explanation
    triage-coordinator/  # Orchestrates multi-skill pipelines
    type-reconstructor/  # Reconstructs C++ structs/classes
    verifier/        # Verifies lifted code against assembly
  skills/          # Analysis skills (each with scripts/)
  helpers/         # Shared library: DB access, errors, caching, search
  commands/        # Slash command definitions
  hooks/           # Session start (context injection) + grind loop
  rules/           # Workspace conventions (errors, JSON, workspace handoff)
  docs/            # This documentation
  config/          # Configuration files
  cache/           # Cached analysis results (per-module)
  tests/           # Test suite
```

### Key Conventions

- **Error handling**: `emit_error()` for fatal errors, `ScriptError` for library errors, `log_warning()` for non-fatal
- **JSON output**: All `--json` output includes `{"status": "ok", ...}` wrapping
- **DB access**: Always wrap with `db_error_handler(db_path, "operation")`
- **Caching**: Results cached in `.agent/cache/<module>/` with TTL + mtime validation
- **Workspace handoff**: Multi-step workflows use `.agent/workspace/` run directories

## Troubleshooting

### "No extraction data found"

Run `/health` to check what's available. Make sure `extracted_code/` and
`extracted_dbs/` directories exist with module data.

### "Database not found"

The module's analysis DB may not exist. Check `extracted_dbs/` for `.db` files.
Module names are case-insensitive: `appinfo.dll` = `Appinfo.dll`.

### "No functions with decompiled code"

The module was extracted but IDA couldn't decompile any functions. This can
happen with very small or heavily obfuscated binaries.

### Commands seem slow

First run for a module is slower because it builds caches. Subsequent runs
use cached results. Use `/cache-manage` to see cache status.

### Want more detail?

- `docs/architecture.md` -- Full system design, agent/skill/helper inventory
- `docs/integration_guide.md` -- End-to-end data flow walkthrough (how `/triage` works)
- `docs/performance_guide.md` -- Optimizing analysis for large modules (1000+ functions)
- `docs/troubleshooting.md` -- Detailed debugging guides
- `docs/helper_api_reference.md` -- Shared helper library API reference
