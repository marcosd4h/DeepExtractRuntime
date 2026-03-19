# DeepExtract Agent Analysis Runtime

## Overview

**DeepExtract Agent Analysis Runtime** is an AI-driven binary analysis toolkit that operates on top of [DeepExtractIDA](https://github.com/marcosd4h/DeepExtractIDA) extraction outputs. It transforms per-binary SQLite databases, decompiled C++ source files, and JSON metadata into a queryable runtime with slash commands, specialized subagents, analysis skills, lifecycle hooks, and a shared helper library.

AI coding agents (Cursor, Claude Code, Codex) parse source code repositories effectively: they resolve imports, follow type definitions, and navigate call hierarchies through language servers and syntax trees. Compiled binaries present a structural gap. The cross-references, PE metadata, assembly instructions, and stack frame layouts required for binary analysis are locked inside reverse engineering frameworks and are inaccessible to these agents through their native code navigation tools. Decompiled C++ output compounds the problem: it consists of isolated function definitions grouped into flat `.cpp` files with no project structure, no `#include` headers, and no shared type definitions. Standard code indexing mechanisms (LSPs, Tree-sitter parsers, embedding-based search) fail to resolve cross-references across these files, forcing the agent to fall back to unreliable text search for callgraph traversal.

DeepExtractIDA addresses the extraction side by running a deterministic pipeline through IDA Pro 9.x and the Hex-Rays decompiler, producing structured SQLite databases with full function records, cross-reference tables, PE metadata, and JSON indexes. The Agent Analysis Runtime addresses the consumption side: it provides deterministic Python scripts that query those databases directly, replacing semantic search with structured tool invocation. The agent invokes a skill script through its shell tool, the script queries the database, and the agent reasons on the structured result. Large payloads (function bodies, callgraph data, scan results) remain on disk in workspace directories; the agent operates on compact summaries and loads full data on demand.

The runtime deploys as an `.agent/` directory alongside the extraction data and operates across Claude Code, Cursor, Codex, and any AI coding environment that supports `AGENTS.md` or equivalent agent configuration.

> **New here?** Start with the [Onboarding Guide](docs/ONBOARDING.md).

---

## How It Works

The runtime is organized into five layers. Each layer depends only on the layers below it.

```
User
  |
  v
Slash Commands (/triage, /audit, /scan, ...)
  |
  v
Specialized Agents (re-analyst, security-auditor, ...)
  |
  v
Analysis Skills (callgraph-tracer, map-attack-surface, ...)
  |
  v
Shared Helper Library (DB access, function resolution, caching, ...)
  |
  v
Data: Analysis DBs (SQLite) + JSON Metadata + Decompiled C++
```

Execution proceeds through three stages:

**Stage 1: Session Initialization.** The `sessionStart` hook scans the extraction output directory, reads skill and agent registries, resolves module databases, and injects a compact workspace context table into the agent session. Context injection uses progressive disclosure: module summaries and registry frontmatter load at session start; full skill instructions and function data load only when the agent activates a specific workflow.

**Stage 2: Command Dispatch.** The user issues a slash command (for example, `/triage appinfo.dll`). The agent reads the corresponding command definition (a Markdown file with step-by-step instructions), then executes the prescribed sequence of skill scripts and subagent delegations. Each skill script queries the analysis databases through the helper library and returns structured JSON or writes results to a workspace directory. Subagents run in isolated context windows, absorbing the cost of large code payloads and returning only their conclusions to the parent agent.

**Stage 3: Result Synthesis.** The agent synthesizes outputs from multiple skills and subagents into a consolidated report. For multi-step workflows, intermediate results are written to run directories under `.agent/workspace/` with a `manifest.json` tracking each step. This workspace handoff pattern keeps large payloads out of the agent's context window and prevents reasoning degradation across complex analysis pipelines.

---

## Key Concepts

- **Command:** A user-facing slash command defined in a Markdown file under `commands/`. Commands orchestrate agents and skills, specifying which scripts to run, in what order, and how to synthesize the results. Commands range from lightweight single-skill lookups (`/explain`, `/xref`) to multi-phase analysis pipelines (`/full-report`, `/scan`).

- **Agent:** A specialized subagent that runs in its own context window. Agents are defined in `agents/` and registered in `agents/registry.json`. Some agents execute Python entry scripts (for example, the triage-coordinator runs `analyze_module.py`); others operate as LLM-only subagents with no scripts, relying on skill-prepared context and their own reasoning (for example, the memory-corruption-scanner).

- **Skill:** A reusable analysis pipeline consisting of a `SKILL.md` descriptor and one or more Python scripts under `skills/<skill-id>/scripts/`. Skills perform the actual data retrieval and computation: querying databases, building call graphs, scanning for vulnerability patterns, reconstructing types. Each script supports `--json` for machine-readable output.

- **Helper:** A shared Python module under `helpers/`. Helpers own all database access, function resolution, API classification, caching, error handling, JSON output formatting, and workspace I/O. Every skill imports from the same library. No script reimplements database queries or output formatting.

- **Hook:** A lifecycle script triggered by the host IDE at specific events. Hooks are configured in `hooks.json` and execute Python scripts under `hooks/`. The runtime uses hooks for session context injection, iterative task continuation, and workspace cleanup.

- **Workspace Handoff:** The pattern used by multi-step workflows to keep large payloads out of the agent context. Run directories under `.agent/workspace/` store per-step `results.json` and `summary.json` files alongside a `manifest.json` that tracks step completion. The agent coordinates using summaries and file paths, not by holding full data in its context window.

- **Grind Loop:** A batch processing mechanism for iterative workflows. The agent writes a Markdown scratchpad with checkbox items. When the agent's turn ends, the `stop` hook checks for unchecked items and re-invokes the agent to continue, bounded by a configurable iteration limit. Used by commands that process multiple functions or phases (`/batch-audit`, `/scan`, `/full-report`).

- **Pipeline:** A headless batch execution mode defined by YAML configuration files. Pipelines specify a sequence of analysis steps (triage, security scan, type reconstruction) to run across one or more modules without interactive input. The `/pipeline` command and `pipeline_cli.py` provide interactive and CLI access respectively.

---

## Installation

The headless batch extractor in DeepExtractIDA writes two bootstrap files (`AGENTS.md` and `CLAUDE.md`) into the extraction output directory. These files contain the full installation procedure and are recognized automatically by AI coding agents.

**Install:**

1. Open the extraction output directory (the `StorageDir` passed to `headless_batch_extractor.ps1`) as a project in Cursor, Claude Code, or Codex.
2. Type `install DeepExtractRuntime` in the agent chat.

The agent reads the bootstrap instructions and executes the setup automatically: cloning the [DeepExtractRuntime](https://github.com/marcosd4h/DeepExtractRuntime) repository into `.agent/`, creating the `.claude` symlink for Claude Code, copying `hooks.json` and rule files into `.cursor/` for Cursor, and verifying the installation.

**Update:**

Type `update DeepExtractRuntime` in the agent chat. The agent pulls the latest changes into `.agent/` and re-copies hooks and rules.

**Bootstrap Templates:**

Example bootstrap files are available in the [`bootstrap/`](bootstrap/) directory. `bootstrap/AGENTS.md` targets Cursor and Codex; `bootstrap/CLAUDE.md` targets Claude Code. These are the templates that the headless batch extractor writes into each extraction output directory.

**Installed Workspace Layout:**

```text
<extraction_output_root>/
  AGENTS.md                  Bootstrap instructions (written by extractor)
  CLAUDE.md                  Claude Code bootstrap pointer
  extraction_report.json     Batch extraction provenance and status
  logs/                      Extractor and symbol resolution logs
  idb_cache/                 Optional cached IDA databases
  extracted_code/
    <module>/
      *.cpp                  Grouped decompiled functions
      file_info.json         PE metadata and analysis report
      function_index.json    Function-to-file index with library tags
      module_profile.json    Pre-computed module fingerprint
      reports/               Generated analysis reports
  extracted_dbs/
    analyzed_files.db        Tracking database (module index)
    <module>_<hash>.db       Per-module analysis database (read-only)
  .agent/                    Installed DeepExtractRuntime
    commands/                Slash command definitions
    agents/                  Subagent definitions and entry scripts
    skills/                  Analysis skills with Python scripts
    helpers/                 Shared Python library
    hooks/                   Lifecycle hook scripts
    rules/                   Behavioral convention rules
    config/
      defaults.json          Runtime configuration
      assets/                COM, RPC, WinRT, and misc ground-truth data
      pipelines/             YAML pipeline definitions
    cache/                   Cached analysis outputs
    workspace/               Run directories for multi-step workflows
    tests/                   Test suite
    docs/                    Documentation
  .cursor/                   Cursor IDE integration (created by bootstrap)
    hooks.json               Copy of .agent/hooks.json
    rules/                   Copies of .agent/rules/ with .mdc extension
```

In this source checkout, the runtime content lives at repository root. When installed, that source tree becomes `.agent/`.

---

## Quick Start

**Verify the installation:**

```
/health
```

Validates that extraction data, databases, and runtime infrastructure are present and functional.

**Triage a module:**

```
/triage appinfo.dll
```

Classifies every function, discovers entry points, maps the attack surface, and generates a summary report. This is the recommended first step for any module.

**Explain a function:**

```
/explain appinfo.dll AiLaunchProcess
```

Produces a structured explanation: purpose, parameters, return value, called APIs, cross-references, and security implications.

**Audit a function:**

```
/audit appinfo.dll AiLaunchProcess
```

Builds a security dossier with attack reachability, dangerous API mapping, data flow exposure, resource patterns, and risk assessment.

**Scan a module for vulnerabilities:**

```
/scan appinfo.dll
```

Runs unified memory corruption, logic vulnerability, and taint analysis scanners with independent skeptic verification and exploitability scoring.

---

## Analysis Capabilities

The following table summarizes the analysis operations the runtime provides on top of the extraction data produced by DeepExtractIDA.

| Category                      | Operations                                                                                                                                                                                                                                                                           |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Module Triage**             | Function classification across multiple categories, entry point discovery, attack surface ranking by callgraph reachability                                                                                                                                                          |
| **Call Graph Analysis**       | Forward and backward traversal, cross-module resolution, topology analysis (SCCs, hubs, roots, leaves), path queries, Mermaid diagram generation                                                                                                                                     |
| **IPC Analysis**              | RPC procedure enumeration with client correlation, COM server mapping with SDDL permission parsing, WinRT activation server analysis, privilege boundary auditing across all three IPC mechanisms                                                                                    |
| **AI Vulnerability Scanning** | Memory corruption scanning (buffer overflows, integer issues, use-after-free), logic vulnerability scanning (auth bypass, TOCTOU, confused deputy), taint analysis (entry point to dangerous sink tracing with trust boundary detection), each with independent skeptic verification |
| **Security Auditing**         | Per-function security dossiers, attack reachability verification, dangerous API mapping, batch auditing of top-ranked entry points                                                                                                                                                   |
| **Code Lifting**              | Batch lifting of decompiled functions into clean C++ with shared struct definitions, constant maps, and dependency ordering across class methods                                                                                                                                     |
| **Type Reconstruction**       | Struct and class inference from assembly memory access patterns, vtable reconstruction, COM interface reconstruction, compilable C++ header generation with per-field confidence annotations                                                                                         |
| **PE Analysis**               | Import and export resolution across modules, dependency graphs, forwarded export chain resolution, cross-module consumer mapping                                                                                                                                                     |
| **Batch Processing**          | YAML pipeline definitions for headless execution across multiple modules, parallel module processing, cross-module result aggregation                                                                                                                                                |
| **Finding Management**        | Finding persistence with SQLite-backed store, cross-report comparison (new, recurring, missed), cross-module prioritization by exploitability, reachability, and impact                                                                                                              |

---

## Extraction Data

The runtime operates on extraction outputs produced by [DeepExtractIDA](https://github.com/marcosd4h/DeepExtractIDA). Each analyzed binary produces:

- **SQLite analysis database** (`extracted_dbs/<module>_<hash>.db`) containing three tables: `file_info` (binary-level metadata, PE headers, security features), `functions` (per-function decompiled code, assembly, cross-references, strings, dangerous APIs, loop analysis, stack frames), and `function_xrefs` (deduplicated caller-callee edges for SQL-based callgraph queries).

- **Grouped C++ source files** (`extracted_code/<module>/*.cpp`) containing decompiled functions organized by class and namespace, sized to fit within LLM context windows.

- **JSON metadata**: `function_index.json` (function-to-file mapping with library tags), `module_profile.json` (pre-computed module fingerprint covering scale, library composition, API surface, complexity), and `file_info.json` (PE metadata and analysis report).

A typical Windows DLL contains 30 to 60 percent library boilerplate: C++ runtime support, Windows Implementation Library (WIL) helpers, Windows Runtime (WRL) template instantiations, STL internals, and ETW tracing stubs. The runtime filters these functions automatically using the library classification in `function_index.json`, allowing every skill, agent, and command to focus on application-specific logic by default.

All analysis databases are treated as **read-only**. Helper-mediated connections enforce `PRAGMA query_only = ON`.

See the [DeepExtractIDA README](https://github.com/marcosd4h/DeepExtractIDA) for full extraction capabilities and database schema details.

---

## Commands

The runtime ships slash commands under `commands/`, organized by analysis category. The live command set is defined in [`commands/registry.json`](commands/registry.json).

### Reconnaissance

| Command                                     | Purpose                                                                                                    |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `/triage <module> [--with-security]`        | Module orientation: identity, classification, call graph, attack surface, optional quick taint pass        |
| `/full-report <module> [--brief]`           | End-to-end multi-phase analysis: RE report, classification, attack surface, topology, specialized analysis |
| `/compare-modules <A> <B> [C ...] \| --all` | Cross-module comparison: dependencies, API overlap, classification distributions                           |

### Function Analysis

| Command                                      | Purpose                                                                               |
| -------------------------------------------- | ------------------------------------------------------------------------------------- |
| `/explain [module] <function> [--depth N]`   | Structured explanation of a function: purpose, parameters, APIs, call context         |
| `/search [module] <term> [--dimensions ...]` | Cross-dimensional search: function names, signatures, strings, APIs, classes, exports |
| `/xref [module] <function> [--depth N]`      | Cross-reference lookup: callers and callees in compact tables                         |

### Code and Type Reconstruction

| Command                                            | Purpose                                                                    |
| -------------------------------------------------- | -------------------------------------------------------------------------- |
| `/lift-class [module] <class>`                     | Batch-lift all methods of a C++ class with shared struct context           |
| `/reconstruct-types <module> [class] [--validate]` | Reconstruct C/C++ struct and class definitions from memory access patterns |

### Security Auditing

| Command                                                  | Purpose                                                               |
| -------------------------------------------------------- | --------------------------------------------------------------------- |
| `/audit [module] <function> [--diagram]`                 | Security audit: dossier, verification, call chain, risk assessment    |
| `/batch-audit <module> [--top N] [--privilege-boundary]` | Batch audit of top-ranked entry points or privilege-boundary handlers |
| `/taint <module> [function] [--from-entrypoints]`        | AI-driven taint analysis from entry points to dangerous sinks         |

### Vulnerability Scanning

| Command                                                      | Purpose                                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------------------ |
| `/scan <module> [--memory-only\|--logic-only\|--taint-only]` | Unified vulnerability scan: memory, logic, and taint with verification   |
| `/memory-scan <module> [function]`                           | AI-driven memory corruption scan: buffer overflows, integer issues, UAF  |
| `/ai-logical-bug-scan <module> [function]`                   | AI-driven logic scan: auth bypass, state errors, TOCTOU, confused deputy |

### Research Planning

| Command                                       | Purpose                                                                      |
| --------------------------------------------- | ---------------------------------------------------------------------------- |
| `/hunt-plan [mode] [module] [target]`         | VR campaign planning, hypothesis testing, cross-module research, re-planning |
| `/hunt-execute [module] [--plan-file <path>]` | Execute a hunt plan: run commands, collect evidence, score confidence        |

### Call Graph and Structure

| Command                                                       | Purpose                                                                         |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `/callgraph <module> [function] [--stats\|--scc\|--path A B]` | Call graph queries: topology, SCCs, hubs, roots, leaves, path finding, diagrams |
| `/imports [module] [--function name] [--consumers]`           | PE import/export relationships, dependency graphs, forwarder chains             |

### IPC and Interface Analysis

| Command                                                             | Purpose                                                                                   |
| ------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| `/rpc <module> \| surface \| audit \| trace \| clients \| topology` | RPC interface enumeration, attack surface, audit, trace, clients, topology                |
| `/winrt <module> \| surface \| methods \| audit \| privesc`         | WinRT server enumeration, attack surface, methods, audit, EoP targets                     |
| `/com <module_or_clsid> \| surface \| methods \| audit \| privesc`  | COM server enumeration, attack surface, audit (permissions, elevation, DCOM), EoP targets |

### Findings and Version Analysis

| Command                                                 | Purpose                                                                           |
| ------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `/diff <module_old> <module_new>`                       | Compare two module versions: function deltas, classification shifts, code diffs   |
| `/prioritize [--modules A B C \| --all]`                | Cross-module finding prioritization by exploitability, reachability, impact       |
| `/compare-scans <module> [--type logic\|memory\|taint]` | Compare findings across AI scan reports: recurring, new, missed, severity changes |

### Utilities

| Command                                                      | Purpose                                                               |
| ------------------------------------------------------------ | --------------------------------------------------------------------- |
| `/health [--quick\|--full]`                                  | Pre-flight workspace validation: extraction data, DBs, skills, config |
| `/cache-manage stats\|clear\|refresh\|purge-runs`            | Cache and workspace run management                                    |
| `/runs list\|show\|latest`                                   | List, inspect, and reopen prior workspace runs                        |
| `/pipeline run <yaml> [--dry-run] \| validate \| list-steps` | Run or validate headless batch analysis pipelines                     |

See [commands/README.md](commands/README.md) for the full command catalog.

---

## Agents

The runtime ships specialized subagents under `agents/`. The live agent set is defined in [`agents/registry.json`](agents/registry.json). Agents divide into two categories: script-backed agents that execute Python entry scripts, and LLM-only agents that operate purely through prepared context and model reasoning.

**Script-backed agents:**

| Agent                | Type          | Purpose                                                                                   | Entry Scripts                                                   |
| -------------------- | ------------- | ----------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| `re-analyst`         | analyst       | Explain and analyze decompiled functions using IDA domain knowledge                       | `re_query.py`, `explain_function.py`                            |
| `triage-coordinator` | coordinator   | Orchestrate multi-skill analysis workflows for module triage, security, and full analysis | `analyze_module.py`, `generate_analysis_plan.py`                |
| `security-auditor`   | analyst       | Vulnerability scanning, exploitability analysis, finding verification                     | `run_security_scan.py`                                          |
| `code-lifter`        | lifter        | Lift related function groups with shared struct context across methods                    | `batch_extract.py`, `track_shared_state.py`                     |
| `type-reconstructor` | reconstructor | Reconstruct C/C++ struct and class definitions from memory access patterns                | `reconstruct_all.py`, `merge_evidence.py`, `validate_layout.py` |

**LLM-only agents:**

| Agent                       | Type    | Purpose                                                                                   |
| --------------------------- | ------- | ----------------------------------------------------------------------------------------- |
| `memory-corruption-scanner` | analyst | AI-driven memory corruption scanning with callgraph navigation and adversarial prompting  |
| `logic-scanner`             | analyst | AI-driven logic vulnerability scanning (auth bypass, state confusion, TOCTOU)             |
| `taint-scanner`             | analyst | AI-driven taint analysis with cross-module data flow tracing and trust boundary detection |

LLM-only agents receive skill-prepared context (threat models, callgraph JSON, preloaded function code) and navigate the analysis space through their own reasoning. Each uses a mandatory skeptic verification pass before reporting findings.

See [agents/README.md](agents/README.md) for the full agent architecture and decision table.

---

## Skills

The runtime ships analysis skills under `skills/`. Each skill consists of a `SKILL.md` descriptor and Python scripts under `scripts/`. The live skill set is defined in [`skills/registry.json`](skills/registry.json).

**Foundation and Indexing:**

| Skill                       | Type       | Purpose                                                                                                         |
| --------------------------- | ---------- | --------------------------------------------------------------------------------------------------------------- |
| `decompiled-code-extractor` | foundation | Extract function data from analysis DBs: decompiled code, assembly, xrefs, signatures, strings, vtable contexts |
| `function-index`            | index      | Fast function-to-file resolution and library-tag filtering via `function_index.json`                            |

**Analysis:**

| Skill                    | Type     | Purpose                                                                                      |
| ------------------------ | -------- | -------------------------------------------------------------------------------------------- |
| `callgraph-tracer`       | analysis | Build and query call graphs, trace execution paths, cross-module chain traversal             |
| `classify-functions`     | analysis | Classify every function by purpose (file I/O, registry, crypto, security) and interest score |
| `import-export-resolver` | analysis | PE-level import/export resolution across modules, dependency graphs, forwarder chains        |

**Reconstruction:**

| Skill                          | Type            | Purpose                                                                             |
| ------------------------------ | --------------- | ----------------------------------------------------------------------------------- |
| `reconstruct-types`            | reconstruction  | Reconstruct C/C++ struct and class layouts from assembly memory access patterns     |
| `com-interface-reconstruction` | reconstruction  | Reconstruct COM/WRL interface definitions from vtable patterns and mangled names    |
| `batch-lift`                   | code_generation | Lift related function groups with shared struct definitions and dependency ordering |

**Security:**

| Skill                          | Type     | Purpose                                                                                        |
| ------------------------------ | -------- | ---------------------------------------------------------------------------------------------- |
| `map-attack-surface`           | security | Discover entry points (exports, COM, RPC, WinRT, callbacks) and rank by attack value           |
| `security-dossier`             | security | Build pre-audit dossiers: identity, reachability, dangerous ops, data exposure, complexity     |
| `ai-memory-corruption-scanner` | security | LLM-driven memory corruption scanning with adversarial prompting and skeptic verification      |
| `ai-logic-scanner`             | security | LLM-driven logic vulnerability scanning with callgraph navigation                              |
| `ai-taint-scanner`             | security | LLM-driven taint tracing from entry points to dangerous sinks with trust boundary analysis     |
| `rpc-interface-analysis`       | security | RPC interface enumeration, surface mapping, audit, chain tracing, client correlation, topology |
| `winrt-interface-analysis`     | security | WinRT server analysis: enumeration, privilege-boundary risk scoring, audit, EoP detection      |
| `com-interface-analysis`       | security | COM server analysis: CLSID enumeration, SDDL parsing, elevation/UAC audit, EoP detection       |

**Reporting:**

| Skill                | Type      | Purpose                                                                                    |
| -------------------- | --------- | ------------------------------------------------------------------------------------------ |
| `generate-re-report` | reporting | Multi-section RE reports: provenance, imports, architecture, complexity, strings, topology |

See [skills/README.md](skills/README.md) for per-skill documentation and the full inventory.

---

## Helpers

The `helpers/` directory is the shared Python library for the entire runtime. It includes importable modules, standalone CLI scripts, and subpackages (`analyzed_files_db/`, `function_index/`, `individual_analysis_db/`). Public symbols are re-exported via lazy imports in `helpers/__init__.py`.

The library covers the following functional areas:

- **Database access and path resolution:** `db_paths`, `individual_analysis_db`, `analyzed_files_db`, `sql_utils`
- **Function resolution:** `function_resolver` (name and ID lookup with index-exact, index-partial, and DB fallback), `batch_operations` (bulk function loading)
- **API classification:** `api_taxonomy` (Win32/NT API prefix classification across functional and security categories, dangerous API set)
- **Call graph:** `callgraph` (in-module graph construction, BFS/DFS, Tarjan SCC), `cross_module_graph` (cross-module resolution via tracking DB and forwarded exports)
- **Module profiles:** `module_profile` (pre-computed fingerprints for scale, library composition, complexity)
- **IPC indexes:** `com_index`, `rpc_index`, `winrt_index`, `rpc_stub_parser`, `ipc_workspace` (COM/RPC/WinRT server and client correlation)
- **Parameter and type analysis:** `param_risk` (C-style parameter surface risk classification), `type_constants`, `calling_conventions`, `struct_scanner` (assembly memory access pattern scanning)
- **Parsing:** `decompiled_parser` (function call extraction), `mangled_names` (MSVC C++ name demangling)
- **Findings:** `finding_schema`, `finding_merge`, `findings_store` (SQLite-backed persistence), `report_comparison`, `taint_helpers`
- **Error handling and output:** `errors` (`ScriptError`, `emit_error`, error codes), `json_output` (`emit_json`, `emit_json_list`), `progress` (throttled stderr progress reporting)
- **Caching:** `cache` (filesystem cache with DB mtime-based TTL and atomic writes)
- **Pipeline:** `pipeline_schema` (YAML parsing and validation), `pipeline_executor` (batch module dispatch)
- **Configuration:** `config` (hierarchical config from `defaults.json` with `DEEPEXTRACT_*` env-var overrides)
- **Workspace and session:** `workspace`, `workspace_bootstrap`, `workspace_validation`, `session_utils`, `module_discovery`
- **Validation:** `validation` (DB schema and integrity checks), `command_validation` (command argument preflight)
- **Security analysis:** `sddl_parser` (SDDL ACE parsing with deny-before-allow evaluation)

**Standalone CLI scripts** (not importable, run directly): `unified_search.py`, `health_check.py`, `pipeline_cli.py`, `qa_runner.py`, `cleanup_workspace.py`, `select_audit_callees.py`, `select_backward_traces.py`, `json_extract.py`, `ipc_index_inspect.py`.

Key rule: use helpers instead of reimplementing DB queries, path logic, classification, or output formatting in commands, skills, agents, or hooks.

Developer references: [helpers/README.md](helpers/README.md), [docs/helper_api_reference.md](docs/helper_api_reference.md).

---

## Hooks

Installed workspaces configure hook events in the root-level [`hooks.json`](hooks.json). Hook commands execute relative to the output root, not relative to `.agent/`.

| Trigger        | Script                                  | Timeout | Purpose                                                                                              |
| -------------- | --------------------------------------- | ------- | ---------------------------------------------------------------------------------------------------- |
| `sessionStart` | `.agent/hooks/inject-module-context.py` | 15s     | Scan extraction data and runtime registries; inject workspace context into the agent session         |
| `stop`         | `.agent/hooks/grind-until-done.py`      | 5s      | Read the session scratchpad; re-invoke the agent if unchecked items remain (bounded by `loop_limit`) |
| `sessionEnd`   | `.agent/hooks/cleanup-workspace.py`     | 10s     | Remove stale run directories, agent state files, and cache entries                                   |

The `sessionStart` hook supports three context levels controlled by the `DEEPEXTRACT_CONTEXT_LEVEL` environment variable:

- **minimal:** Module count, database list, skill/agent/command names.
- **standard** (default): Full module table, registry tables, quick-reference command list.
- **full:** Module profiles, RPC/COM/WinRT tables, README summaries, cached results, triage highlights.

For workspaces with many modules, compact mode activates automatically, reducing context size by caching the module list and trimming per-module detail.

Scratchpads are session-scoped and live at `.agent/hooks/scratchpads/{session_id}.md`. Run directories live under `.agent/workspace/`.

See [hooks/README.md](hooks/README.md) for lifecycle details.

---

## Rules

The runtime ships always-on rules under `rules/`. Each rule is a Markdown file with optional YAML frontmatter (`alwaysApply`, `description`, `globs`). For Cursor, rules are copied to `.cursor/rules/` with a `.mdc` extension during installation.

| Rule                          | Purpose                                                                     |
| ----------------------------- | --------------------------------------------------------------------------- |
| `workspace-pattern`           | Filesystem handoff contract for multi-step workflows                        |
| `workspace-layout`            | Path conventions for the output root and the `.agent/` overlay              |
| `script-invocation-guide`     | Canonical script signatures, DB path resolution, common invocation mistakes |
| `call-discovery-convention`   | Ground-truth call discovery via xrefs; forbidden regex-only patterns        |
| `grind-loop-protocol`         | Scratchpad structure and iterative task protocol                            |
| `error-handling-convention`   | `ScriptError`, `emit_error()`, error codes, and warning conventions         |
| `json-output-convention`      | stdout/stderr separation and `--json` behavior                              |
| `missing-dependency-handling` | Graceful degradation when data or tools are missing                         |
| `ai-scanner-orchestration`    | Self-driving AI scanner phases, escalation protocol, skeptic verification   |
| `agent-tool-guardrails`       | Shell pre-flight checklist, data access decision tree, path quoting         |
| `cache-conventions`           | Cache location, TTL, DB-mtime invalidation, `--no-cache` bypass             |

---

## Configuration

Runtime configuration lives in [`config/defaults.json`](config/defaults.json). Individual values can be overridden via environment variables using the `DEEPEXTRACT_*` prefix (see [`helpers/config.py`](helpers/config.py) for override behavior).

Configuration sections cover:

- **`classification`**: Weights for API, structural, and library signals used in function classification
- **`scoring`**: Severity thresholds, guard weights, scanner defaults
- **`callgraph`**: Vtable edge inclusion, max traversal depths for reachability and taint
- **`triage`**: COM/RPC/security density thresholds, worker counts, step timeouts
- **`security_auditor`**: Step timeouts, dynamic top-N selection based on module size
- **`pipeline`**: Default step timeout, worker counts, continue-on-error, parallel module processing
- **`script_runner`**: Default timeout, max retries
- **`explain`**: Max callee depth and count
- **`cache`**: Max age (hours), max size (MB)
- **`findings_store`**: SQLite path, retention days
- **`hooks`**: Session timeout, grind loop limit, scratchpad stale hours, cleanup age
- **`rpc`**: Server index path, client stubs path, enabled flag, cache behavior
- **`winrt`**: Data root, enabled flag, cache behavior
- **`com`**: Data root, enabled flag, cache behavior
- **`dangerous_apis`**: JSON path to the API list, auto-classify flag
- **`scale`**: Compact mode threshold, context truncation limits, cross-scan limits, connection pool size

Ground-truth asset data for COM, RPC, and WinRT server registrations, dangerous API lists, and vulnerability patterns lives in `config/assets/`.

See [docs/cache_conventions.md](docs/cache_conventions.md) for cache policy.

---

## Pipelines

The runtime supports headless batch execution via YAML pipeline definitions stored in `config/pipelines/`. Pipelines specify a sequence of analysis steps to run across one or more modules without interactive input.

Built-in pipelines:

| Pipeline                  | Purpose                                                                        |
| ------------------------- | ------------------------------------------------------------------------------ |
| `quick-triage.yaml`       | Triage for all modules, minimal cost                                           |
| `security-sweep.yaml`     | Triage, security analysis, and vulnerability scan for selected modules         |
| `full-analysis.yaml`      | Triage, full analysis, type reconstruction, memory scan, logic scan, callgraph |
| `function-deep-dive.yaml` | Entry points, security dossiers, taint analysis, classification, callgraph     |

**CLI access:**

```bash
python .agent/helpers/pipeline_cli.py run config/pipelines/security-sweep.yaml
python .agent/helpers/pipeline_cli.py validate config/pipelines/security-sweep.yaml
python .agent/helpers/pipeline_cli.py list-steps
```

**Interactive access:** The `/pipeline` slash command wraps the same CLI.

Pipeline output is written to `.agent/workspace/batch_{name}_{timestamp}/` with per-module results and a batch summary.

See [docs/pipeline_guide.md](docs/pipeline_guide.md) for YAML schema, step mapping, and configuration options.

---

## Data Layout

The installed workspace consists of two layers: extractor-managed root artifacts produced by DeepExtractIDA, and the runtime-managed overlay installed at `.agent/`.

**Extractor-managed data:**

- `extracted_code/<module>/` with grouped `.cpp` files, `file_info.json`, `function_index.json`, and `module_profile.json`
- `extracted_dbs/<module>_<hash>.db` with per-module SQLite analysis databases
- `extracted_dbs/analyzed_files.db` as the tracking database (module index, status, hashes)
- `extraction_report.json`, `logs/`, and optional `idb_cache/`

**Runtime-managed data:**

- `.agent/cache/` for cached skill-script results (TTL-based, DB mtime-validated)
- `.agent/workspace/` for multi-step workflow manifests and per-step results
- `.agent/hooks/scratchpads/` for grind-loop session state
- `.agent/config/assets/` for ground-truth COM, RPC, WinRT, and miscellaneous data files
- `.agent/config/pipelines/` for YAML pipeline definitions

All analysis databases are **read-only**. Helper-mediated connections enforce `PRAGMA query_only = ON`. The tracking database normally resides at `extracted_dbs/analyzed_files.db`; for compatibility with single-file or older layouts, `helpers/db_paths.py` also accepts a root-level `analyzed_files.db`.

Format references:
[file_info](docs/file_info_format_reference.md) |
[function_index](docs/function_index_format_reference.md) |
[module_profile](docs/module_profile_format_reference.md) |
[database schema](docs/data_format_reference.md)

---

## Testing

**Installed-workspace command:**

```bash
cd <extraction_output_root>/.agent && python -m pytest tests/ -v
```

**Source-checkout command:**

```bash
python -m pytest tests/ -v
```

The test suite covers registry consistency, helper behavior, hook behavior, workspace handoff, pipeline execution, and integration across commands, agents, and skills.

Integration tests are executed via:

```bash
python helpers/qa_runner.py
```

The runner parses the testing guide, resolves database paths, executes script-level test cases, and validates output against the JSON output convention.

See [docs/testing_guide.md](docs/testing_guide.md) for the full test documentation.

---

## Technical Requirements

- **Python:** 3.10 or later
- **Runtime dependency:** `pyyaml>=6.0`
- **Optional test dependencies:** `pytest>=7.0`, `pytest-timeout>=2.0`
- **Optional development dependencies:** `ruff>=0.4`, `mypy>=1.10`
- **Supported AI environments:** Claude Code, Cursor, Codex, and any environment that supports `AGENTS.md` or equivalent agent configuration
- **License:** MIT

---

## Documentation

| Document                                                                   | Description                                           |
| -------------------------------------------------------------------------- | ----------------------------------------------------- |
| [Onboarding Guide](docs/ONBOARDING.md)                                     | Getting started in 5 minutes                          |
| [Architecture](docs/architecture.md)                                       | Full system design and installed workspace model      |
| [Integration Guide](docs/integration_guide.md)                             | End-to-end request flow for `/triage` and `/pipeline` |
| [Data Format Reference](docs/data_format_reference.md)                     | SQLite schema, data architecture, analysis heuristics |
| [File Info Format Reference](docs/file_info_format_reference.md)           | `file_info.json` and `file_info.md` layout            |
| [Function Index Format Reference](docs/function_index_format_reference.md) | `function_index.json` format and library tagging      |
| [Module Profile Format Reference](docs/module_profile_format_reference.md) | `module_profile.json` computation and fields          |
| [Helper API Reference](docs/helper_api_reference.md)                       | Full helper module reference                          |
| [Command Authoring Guide](docs/command_authoring_guide.md)                 | How to add or update slash commands                   |
| [Agent Authoring Guide](docs/agent_authoring_guide.md)                     | How to create or extend subagents                     |
| [Skill Authoring Guide](docs/skill_authoring_guide.md)                     | How to create or extend skills                        |
| [AI Scanner Authoring Guide](docs/ai_scanner_authoring_guide.md)           | How to create AI vulnerability scanners               |
| [Pipeline Guide](docs/pipeline_guide.md)                                   | Headless batch execution and YAML pipelines           |
| [Cache Conventions](docs/cache_conventions.md)                             | Cache location, TTL, invalidation policy              |
| [Performance Guide](docs/performance_guide.md)                             | Optimization strategies for large modules             |
| [VR Workflow Overview](docs/vr_workflow_overview.md)                       | Vulnerability research workflow and methodology       |
| [Scan-Audit-Taint Workflow](docs/scan-audit-taint-workflow.md)             | Security scanning workflow patterns                   |
| [Cross-Module Callgraph Guide](docs/cross_module_callgraph_guide.md)       | Cross-module call graph traversal                     |
| [IDA Conventions Reference](docs/ida_conventions_reference.md)             | IDA Pro output conventions and Hex-Rays artifacts     |
| [Technical Reference](docs/technical_reference.md)                         | Internal architecture and implementation details      |
| [Persistence and Lifecycle](docs/persistence-and-lifecycle.md)             | Data persistence and session lifecycle                |
| [Command Depth Spectrum](docs/command_depth_spectrum.md)                   | Lightweight vs heavyweight command classification     |
| [Examples](docs/examples.md)                                               | Concrete usage examples and walkthroughs              |
| [Testing Guide](docs/testing_guide.md)                                     | Full test suite documentation                         |
| [Testing Guide Prompts](docs/testing_guide_prompts.md)                     | Prompt templates for testing guide generation         |
| [Troubleshooting](docs/troubleshooting.md)                                 | Common failures and recovery guidance                 |
| [commands/README.md](commands/README.md)                                   | Complete command catalog and file inventory           |
| [agents/README.md](agents/README.md)                                       | Agent architecture, files, and usage guidance         |
| [skills/README.md](skills/README.md)                                       | Skill inventory and per-skill documentation           |
| [hooks/README.md](hooks/README.md)                                         | Hook lifecycle and generated artifacts                |
| [helpers/README.md](helpers/README.md)                                     | Helper library import patterns and module index       |

Feature requests and planned capabilities are tracked in `docs/feature_requests/`.

---

_DeepExtract Agent Analysis Runtime, developed by Marcos Oviedo for Agentic Vulnerability Research._
