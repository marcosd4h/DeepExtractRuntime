# DeepExtract VR Workflow Overview Guide

> Comprehensive reference for vulnerability research workflows using the DeepExtract Agent Analysis Runtime. Covers every command (36), subagent (6), skill (29), rule (6), and helper module (35+).

---

## Table of Contents

1. [Introduction and Architecture](#1-introduction-and-architecture)
2. [Rules and Conventions](#2-rules-and-conventions)
3. [Skills Reference](#3-skills-reference)
4. [Agents Reference](#4-agents-reference)
5. [Commands Reference](#5-commands-reference)
6. [Helper Library Overview](#6-helper-library-overview)
7. [VR Workflow Patterns](#7-vr-workflow-patterns)
8. [Cross-Reference Tables](#8-cross-reference-tables)
9. [Glossary](#9-glossary)

---

## 1. Introduction and Architecture

### What Is DeepExtract

DeepExtract is an AI-driven analysis runtime that operates on IDA Pro extraction outputs from Windows PE binaries. It provides automated vulnerability research capabilities through a layered system of shared helpers, analysis skills, specialized agents, and user-facing slash commands.

### Workspace Data Layout

| Path | Contents |
|------|----------|
| `extracted_code/{module}/` | Decompiled `.cpp` files, `file_info.json`, `file_info.md`, `function_index.json`, `module_profile.json` |
| `extracted_code/{module}/reports/` | Saved reports, visualizations, and analysis artifacts (`.md`, `.html`, `.h`) |
| `extracted_dbs/` | Per-binary SQLite analysis databases (read-only) |
| `.agent/helpers/` | Shared Python library (35+ modules) |
| `.agent/skills/` | Analysis skills with scripts in `scripts/` subdirectories |
| `.agent/agents/` | Subagent definitions, entry scripts, and `registry.json` |
| `.agent/commands/` | Slash command definitions (`.md` files) |
| `.agent/hooks/` | Lifecycle hooks (session start context injector, grind-loop stop hook) |
| `.agent/cache/` | Cached skill-script results (24h TTL, DB mtime validated) |
| `.agent/workspace/` | Run directories for multi-step workflow handoff |
| `.agent/config/` | `defaults.json` -- classification weights, thresholds, timeouts |
| `.agent/docs/` | Data format references, guides |
| `.agent/tests/` | Test files and `conftest.py` |

### Three-Layer Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Commands (36)          User-facing slash commands           │
│  /triage /scan /audit /hunt /lift-class /com /rpc ...       │
├─────────────────────────────────────────────────────────────┤
│  Agents (6)             Specialized subagents                │
│  re-analyst  triage-coordinator  security-auditor            │
│  code-lifter  type-reconstructor  verifier                   │
├─────────────────────────────────────────────────────────────┤
│  Skills (29)            Analysis capabilities with scripts   │
│  classify-functions  taint-analysis  map-attack-surface ...  │
├─────────────────────────────────────────────────────────────┤
│  Helpers (35+)          Shared Python library                │
│  individual_analysis_db  callgraph  api_taxonomy  errors ... │
├─────────────────────────────────────────────────────────────┤
│  Data Layer             SQLite DBs + Decompiled .cpp files   │
│  extracted_dbs/*.db     extracted_code/{module}/*.cpp        │
└─────────────────────────────────────────────────────────────┘
```

**Data flow:** SQLite analysis DBs + decompiled `.cpp` files are read by skill scripts, which produce structured JSON. Agents orchestrate multiple skills and synthesize results into reports. Commands are the user-facing entry points that compose skills and agents into complete workflows.

**Key architectural constraints:**
- Subagents cannot launch other subagents; only the parent agent orchestrates delegation
- Multiple subagents can run in parallel when their work is independent
- All analysis databases are read-only
- Assembly is always ground truth when it disagrees with decompiled code

---

## 2. Rules and Conventions

Six workspace rules govern all script development and agent behavior. All rules have `alwaysApply: true`.

### 2.1 Error Handling Convention

Layer-based error handling using different mechanisms depending on the code layer.

**Entry-point scripts** (`if __name__ == "__main__"`): Use `emit_error(message, code)` for fatal errors. Writes structured JSON to stderr and exits with code 1.

```python
from helpers.errors import emit_error, ErrorCode

if not args.db_path:
    emit_error("No database path provided", ErrorCode.INVALID_ARGS)
```

**Library / helper functions**: Raise `ScriptError(message, code)` so callers retain control.

```python
from helpers.errors import ScriptError, ErrorCode

def resolve_something(name):
    if not found:
        raise ScriptError(f"Not found: {name}", ErrorCode.NOT_FOUND)
```

**Non-fatal conditions**: Use `log_warning(message, code)` for issues that don't require aborting.

```python
from helpers.errors import log_warning
log_warning("Cache expired, recomputing", "DB_ERROR")
```

**Database operations**: Wrap with `db_error_handler(db_path, operation)` context manager.

```python
with db_error_handler(db_path, "loading functions"):
    db = open_individual_analysis_db(db_path)
```

**Error codes** (always use `ErrorCode` enum):

| Code | Meaning |
|------|---------|
| `NOT_FOUND` | Entity does not exist |
| `INVALID_ARGS` | Bad command-line arguments |
| `DB_ERROR` | Database open/query failure |
| `PARSE_ERROR` | JSON/assembly parse failure |
| `NO_DATA` | Query succeeded, empty results |
| `AMBIGUOUS` | Multiple matches when one expected |
| `UNKNOWN` | Catch-all |

### 2.2 Grind Loop Protocol

The workspace has a stop hook (`.agent/hooks/grind-until-done.py`) that re-invokes the agent when a task scratchpad has unchecked items. Used for workflows processing multiple discrete items.

**Session-scoped scratchpads** prevent concurrent sessions from interfering:
```
.agent/hooks/scratchpads/{session_id}.md
```

**When to create a scratchpad:**
- Task involves 3+ discrete items to process sequentially
- User says "all", "every", "each", "batch"
- A slash command workflow has multiple tracked steps

**Scratchpad format:**
```markdown
# Task: <short description>

## Items
- [ ] Item 1 -- brief description
- [ ] Item 2 -- brief description
- [ ] Item 3 -- brief description

## Status
IN_PROGRESS
```

**Lifecycle:**
1. Check off items as completed: `[ ]` -> `[x]`
2. Set Status to `DONE` when all items are complete or cancelled
3. The hook deletes the scratchpad automatically once `DONE` or all items checked
4. If unchecked items remain at agent stop, the hook sends a followup message listing remaining items
5. Repeats up to 10 times (configured `loop_limit` in `hooks.json`)

### 2.3 JSON Output Convention

**When to produce JSON:**
- `--json` flag passed on command line
- `--workspace-dir` is active
- stdout is being piped to another process

**Stdout vs stderr separation:**
- **stdout**: Data output only (JSON with `--json`, or human-readable tables/text)
- **stderr**: Progress messages, warnings, structured errors -- never data

**JSON rules:**
1. Emit exactly one JSON document to stdout
2. Document must be a dict (not a bare list or string)
3. Include `"status"` key (`"ok"` or `"error"`) at top level
4. Progress via `helpers.progress.status_message()` (stderr)
5. Errors via `helpers.errors.emit_error()` (stderr)

**Human-readable rules:**
1. Use formatted tables for multi-row data
2. Use section headers (`=== Section ===`) for visual grouping
3. Keep line widths under 120 characters
4. Print to stdout for data output

### 2.4 Missing Dependency Handling

**Pre-flight validation:**
```python
from helpers.validation import validate_workspace_data

status = validate_workspace_data(workspace_root)
if not status.ok:
    emit_error("No extraction data found", "NO_DATA")
if status.json_only:
    log_warning("No analysis DBs; some features unavailable", "NO_DATA")
```

**Missing database degradation:**
1. **Required DB**: `emit_error()` with `NOT_FOUND`
2. **Optional DB** (e.g., cross-module): `log_warning()` and continue with reduced functionality
3. **Tracking DB**: If `resolve_tracking_db()` returns `None`, cross-module features unavailable; report but don't abort

**Missing skill scripts:**
```python
script = find_skill_script("optional-skill", "some_script.py")
if script is None:
    log_warning("optional-skill not available; skipping", "NOT_FOUND")
```

**JSON-only mode** (when `extracted_dbs/` absent but `extracted_code/` exists):
1. Fall back to `function_index.json` for function listing
2. Fall back to `file_info.json` for module identity
3. Report which DB-dependent features are unavailable
4. Never crash with an opaque error

### 2.5 Workspace Layout

| Path | Contents |
|------|----------|
| `extracted_code/{module}/` | Decompiled `.cpp` files + `file_info.json`/`.md` + `module_profile.json` |
| `extracted_dbs/` | SQLite analysis DBs (assembly, xrefs, strings, loops) |
| `.agent/helpers/` | Shared Python library (35+ modules) |
| `.agent/docs/` | Data format references |
| `.agent/skills/` | Analysis skills with helper scripts in `scripts/` subdirs |
| `.agent/agents/` | Subagent definitions and scripts |
| `.agent/commands/` | Slash command definitions (`.md` files) |
| `.agent/hooks/` | Lifecycle hooks |
| `.agent/cache/` | Cached skill-script results (24h TTL, DB mtime validated) |
| `.agent/workspace/` | Run directories for multi-step workflow handoff |
| `.agent/config/` | `defaults.json` -- classification weights, thresholds, timeouts |
| `.agent/tests/` | Test files + `conftest.py` |

**Data source guidance:**
- Use `file_info.json` (not `.md`) for programmatic lookups
- Use `module_profile.json` for pre-computed module-level metrics
- Use analysis DBs for assembly, xrefs, strings, and loop data not in `.cpp` files
- Import from `.agent/helpers/` for all shared operations; never reimplement

### 2.6 Workspace Pattern

Filesystem handoff for multi-step or multi-skill workflows to keep coordinator context compact.

**When required:**
- Coordinator runs 2+ skill scripts or subagents
- Command performs phased analysis (triage, security, full, batch lifting)
- Intermediate outputs are large JSON payloads

**Run directory:** `.agent/workspace/<module>_<goal>_<timestamp>/` with `manifest.json`.

**Invocation contract:** Every pipeline step receives:
- `--workspace-dir <run_dir>`
- `--workspace-step <step_name>` (stable, unique, path-safe)

**Step output contract:** When workspace args present, each step must:
1. Write full payload to `<run_dir>/<step_name>/results.json`
2. Write compact summary to `<run_dir>/<step_name>/summary.json`
3. Update `<run_dir>/manifest.json` with step status and summary path
4. Print only the compact summary JSON to stdout

**Context policy:**
- Keep only compact summaries and file references in coordinator context
- Never inline full multi-step JSON into coordinator responses
- Load `results.json` only on demand for synthesis or targeted follow-up

**Failure handling:**
- Failed steps still write summary/error info and update manifest
- Coordinators continue where possible using manifest state as source of truth

---

EOF## 3. Skills Reference

### Skills Summary Table

| # | Skill | Type | Cacheable | Scripts |
|---|-------|------|-----------|---------|
| 1 | adversarial-reasoning | methodology | no | none |
| 2 | analyze-ida-decompiled | documentation | no | none |
| 3 | batch-lift | orchestration | no | 2 |
| 4 | brainstorming | methodology | no | none |
| 5 | callgraph-tracer | analysis | no | 6 |
| 6 | classify-functions | analysis | no | 3 |
| 7 | code-lifting | workflow/recipe | no | none |
| 8 | com-interface-analysis | security | no | 6 |
| 9 | com-interface-reconstruction | reconstruction | no | 4 |
| 10 | data-flow-tracer | analysis | no | 4 |
| 11 | decompiled-code-extractor | foundation | no | 3 |
| 12 | deep-context-builder | methodology | no | none |
| 13 | deep-research-prompt | meta | yes | 3 |
| 14 | exploitability-assessment | security | no | 2 |
| 15 | finding-verification | verification | no | none |
| 16 | function-index | index | no | 3 |
| 17 | generate-re-report | reporting | no | 6 |
| 18 | import-export-resolver | analysis | no | 4 |
| 19 | logic-vulnerability-detector | security | no | 6 |
| 20 | map-attack-surface | security | no | 3 |
| 21 | memory-corruption-detector | security | no | 5 |
| 22 | reconstruct-types | reconstruction | no | 4 |
| 23 | rpc-interface-analysis | security | no | 6 |
| 24 | security-dossier | security | no | 1 |
| 25 | state-machine-extractor | analysis | no | 4 |
| 26 | string-intelligence | analysis | no | 1 |
| 27 | taint-analysis | security | no | 5 |
| 28 | verify-decompiled | verification | yes | 2 |
| 29 | winrt-interface-analysis | security | no | 6 |

---

### 3.1 Foundation / Data Access

#### 3.1.1 decompiled-code-extractor

**Purpose:** Extract structured function data from DeepExtractIDA analysis databases. Foundational data-access layer that nearly every other skill depends on. Purely data retrieval -- no analysis, lifting, or rewriting.

**Scripts:**

**`find_module_db.py`** -- Map module name to analysis DB path

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module_name` | positional | no | Module to find |
| `--list` | flag | no | List all analyzed modules |
| `--ext` | string | no | Search by file extension |

**`list_functions.py`** -- List or search functions in a module

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB path |
| `--search` | string | no | Name pattern search |
| `--with-signatures` | flag | no | Include signatures |
| `--has-decompiled` | flag | no | Only functions with decompiled code |
| `--json` | flag | no | JSON output |

**`extract_function_data.py`** -- Extract all data for a function

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB path |
| `function_name` | positional | no | Function name |
| `--id` | string | no | Function ID |
| `--search` | string | no | Search pattern |
| `--json` | flag | no | JSON output |

**Workflow:**
1. Find module DB: `find_module_db.py <module>`
2. List/search functions: `list_functions.py <db_path> --search <pattern>`
3. Extract full data: `extract_function_data.py <db_path> <function> --json`

**Dependencies:** None (foundational -- other skills depend on this).

---

#### 3.1.2 function-index

**Purpose:** Fast function-to-file resolution using `function_index.json` files. Maps function names to `.cpp` files and library tags for boilerplate filtering. No dependencies on other skills.

**Scripts:**

**`lookup_function.py`** -- Find functions by name

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `function_name` | positional | no | Exact function name |
| `--module` | string | no | Specific module |
| `--search` | string | no | Substring search |
| `--regex` | flag | no | Regex search |
| `--app-only` | flag | no | Application code only |
| `--json` | flag | no | JSON output |

**`index_functions.py`** -- List and filter module functions

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module` | positional | no | Module name |
| `--all` | flag | no | All modules |
| `--app-only` | flag | no | Application code only |
| `--library` | string | no | Filter by library tag |
| `--by-file` | flag | no | Group by `.cpp` file |
| `--file` | string | no | Functions in specific file |
| `--stats` | flag | no | Statistics only |
| `--json` | flag | no | JSON output |

**`resolve_function_file.py`** -- Resolve to absolute file paths

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `function_name` | positional | no | Function name |
| `--module` | string | no | Specific module |
| `--names` | string | no | Batch resolve (comma-separated) |
| `--file` | string | no | All functions in a `.cpp` file |
| `--json` | flag | no | JSON output |

**Library tags:** `null` (application code), `WIL`, `STL`, `WRL`, `CRT`, `ETW/TraceLogging`

**Dependencies:** None (foundational).

---

#### 3.1.3 import-export-resolver

**Purpose:** Resolve PE-level import and export relationships across all analyzed modules. Works from PE import/export tables (authoritative record of what the Windows loader resolves). Distinct from code-level xrefs.

**Scripts:**

**`query_function.py`** -- Resolve function importers/exporters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `--function` | string | yes | Function name |
| `--direction` | string | no | `export`, `import`, or `both` (default: both) |
| `--json` | flag | no | JSON output |

**`build_index.py`** -- Build cross-module import/export index

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `--json` | flag | no | JSON output |
| `--no-cache` | flag | no | Bypass cache |

**`module_deps.py`** -- PE-level module dependency graph

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `--module` | string | no | Focus on module |
| `--consumers` | flag | no | Reverse dependencies |
| `--json` | flag | no | JSON output |
| `--diagram` | flag | no | Generate diagram |

**`resolve_forwarders.py`** -- Follow forwarded export chains

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `--module` | string | yes | Source module |
| `--function` | string | no | Specific function |
| `--all` | flag | no | All forwarded exports |
| `--json` | flag | no | JSON output |

**Workflow:**
1. Build index: `build_index.py --json`
2. Query: `query_function.py --function CreateProcessW --json`
3. Module deps: `module_deps.py --module appinfo.dll --diagram`
4. Forwarders: `resolve_forwarders.py --module ntdll.dll --all`

**Dependencies:** callgraph-tracer (code-level), generate-re-report, map-attack-surface, taint-analysis.

---

### 3.2 Analysis

#### 3.2.1 callgraph-tracer

**Purpose:** Trace call graphs, execution paths, and cross-module xref chains. Builds directed call graphs from xrefs, supports path finding, reachability analysis, SCC detection, and cross-module chain analysis.

**Scripts:**

**`build_call_graph.py`** -- Single-module graph analysis

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--stats` | flag | no | Graph statistics |
| `--path <src> <tgt>` | strings | no | Shortest path |
| `--all-paths <src> <tgt>` | strings | no | All paths |
| `--reachable` | string | no | Reachable functions |
| `--callers` | string | no | Transitive callers |
| `--scc` | flag | no | Strongly connected components |
| `--leaves` | flag | no | Leaf functions |
| `--roots` | flag | no | Root functions |
| `--neighbors` | string | no | Direct neighbors |
| `--max-depth` | int | no | Max depth (default 10) |
| `--limit` | int | no | Cap results |
| `--id` | int | no | Function ID |

**`cross_module_resolve.py`** -- Resolve external functions

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `function_name` | positional | no | Function to search |
| `--from-function <db> <func>` | strings | no | External calls from function |
| `--resolve-all <db> <func>` | strings | no | Resolve ALL outbound xrefs |
| `--id` | string | no | Function ID |

**`chain_analysis.py`** -- Cross-module xref chain traversal

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `function` | positional | yes | Target function |
| `--follow` | string | no | Follow specific callee |
| `--depth` | int | no | Recursive depth |
| `--summary` | flag | no | Compact call tree, no code |
| `--no-code` | flag | no | Skip code output |
| `--id` | string | no | Function ID |

**`module_dependencies.py`** -- Inter-module dependency mapping

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `--overview` | flag | no | All modules overview |
| `--module` | string | no | Detailed deps for one module |
| `--surface` | string | no | API surface |
| `--shared-functions <m1> <m2>` | strings | no | Shared functions between modules |

**`analyze_detailed_xrefs.py`** -- Detailed xref analysis

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--function` | string | no | Per-function |
| `--id` | string | no | By function ID |
| `--summary` | flag | no | Summary mode |
| `--json` | flag | no | JSON output |

**`generate_diagram.py`** -- Mermaid/DOT diagram generation

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--function` | string | no | Function subgraph |
| `--id` | string | no | By function ID |
| `--depth` | int | no | Depth |
| `--path <src> <tgt>` | strings | no | Path diagram |
| `--cross-module` | flag | no | Cross-module dependency diagram |
| `--format` | string | no | `dot` format instead of Mermaid |

**Xref sentinel values:** `"data"` (type=4), `"vtable"` (type=8), `"internal"` (type=1), `"static_library"` (type=2)

**Dependencies:** decompiled-code-extractor, classify-functions, security-dossier, data-flow-tracer, map-attack-surface.

---

#### 3.2.2 classify-functions

**Purpose:** Automatically categorize every function by purpose using API usage signatures, string analysis, naming patterns, assembly metrics, and structural metrics.

**Scripts:**

**`triage_summary.py`** -- Quick module overview

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--top` | int | no | Top-N most interesting (default 10) |
| `--json` | flag | no | JSON output |

**`classify_module.py`** -- Full categorized index

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--json` | flag | no | JSON output |
| `--category` | string | no | Filter to category (repeatable) |
| `--min-interest` | int | no | Minimum interest score |
| `--no-telemetry` | flag | no | Exclude telemetry |
| `--no-compiler` | flag | no | Exclude compiler-generated |

**`classify_function.py`** -- Detailed single function analysis

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `function_name` | positional | no | Function name |
| `--id` | string | no | Function ID |
| `--search` | string | no | Search pattern |
| `--json` | flag | no | JSON output |

**20 classification categories:** initialization, error_handling, data_parsing, com_rpc, ui, telemetry, crypto, resource_management, dispatch_routing, file_io, registry, network, process_thread, security, sync, memory, service, compiler_generated, utility, unknown

**Interest score:** 0-10 scale computed from dangerous API calls, string references, complexity, entry point status, and classification signals.

**Dependencies:** decompiled-code-extractor, callgraph-tracer, security-dossier, map-attack-surface.

---

#### 3.2.3 data-flow-tracer

**Purpose:** Trace how data moves through binaries -- forward parameter flow, backward argument origins, global variable producer/consumer maps, and string literal usage chains.

**Scripts:**

**`forward_trace.py`** -- Parameter forward trace

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `function` | positional | yes | Function name |
| `--param` | int | yes | Parameter number to trace |
| `--depth` | int | no | Recursive depth (default 1) |
| `--assembly` | flag | no | Include assembly register tracking |
| `--id` | string | no | Function ID |

**`backward_trace.py`** -- Argument origin trace

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `function` | positional | yes | Function name |
| `--target` | string | yes | Target API call |
| `--arg` | int | no | Specific argument number |
| `--callers` | flag | no | Show what each caller passes |
| `--depth` | int | no | Caller trace depth |

**`global_state_map.py`** -- Global variable producer/consumer map

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--global` | string | no | Focus on specific global |
| `--summary` | flag | no | Summary mode |
| `--shared-only` | flag | no | Only globals with both readers/writers |
| `--writers-only` | flag | no | Only written globals |
| `--json` | flag | no | JSON output |

**`string_trace.py`** -- String origin tracking

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--string` | string | no | Find functions referencing string |
| `--function` | string | no | All strings used by function |
| `--id` | string | no | Function ID |
| `--callers` | flag | no | Include caller chain |
| `--depth` | int | no | Caller depth |
| `--list-strings` | flag | no | List all unique strings |
| `--limit` | int | no | Limit results |
| `--assembly` | flag | no | Include assembly context |

**Argument origin classifications:** parameter, call_result, constant, global, local_variable, expression.

**Dependencies:** callgraph-tracer, classify-functions, security-dossier, reconstruct-types.

---

#### 3.2.4 generate-re-report

**Purpose:** Generate synthesized reverse engineering reports from analysis databases. Cross-correlates data, computes derived metrics, produces actionable guidance.

**Scripts:**

**`generate_report.py`** -- Full 10-section report

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--output` | string | no | Write to file |
| `--summary` | flag | no | Brief mode (sections 1,3,4,10) |
| `--top` | int | no | Control table sizes (default 10) |
| `--json` | flag | no | JSON output |

**`analyze_imports.py`** -- Import capability categorization

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--json` | flag | no | JSON output |
| `--exports` | flag | no | Include exports |
| `--include-delay-load` | flag | no | Include delay-loaded |

**`analyze_complexity.py`** -- Function complexity ranking

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--json` | flag | no | JSON output |
| `--top` | int | no | Top N |

**`analyze_topology.py`** -- Call graph metrics

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--json` | flag | no | JSON output |

**`analyze_strings.py`** -- String literal categorization

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--json` | flag | no | JSON output |
| `--top` | int | no | Top N |
| `--category` | string | no | Filter by category |

**`analyze_decompilation_quality.py`** -- Decompilation quality metrics

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--json` | flag | no | JSON output |
| `--no-cache` | flag | no | Bypass cache |

**Report sections (10):** Executive Summary, Provenance & Build Environment, Security Posture, External Interface (Import/Export), Internal Architecture, Complexity Hotspots, String Intelligence, Cross-Reference Topology, Notable Patterns & Anomalies, Recommended Focus Areas.

**Dependencies:** security-dossier, callgraph-tracer, map-attack-surface, classify-functions, deep-research-prompt.

---

#### 3.2.5 map-attack-surface

**Purpose:** Discover, classify, and rank every possible entry point in a Windows PE binary. Each entry point ranked by attack value using callgraph reachability to dangerous operations.

**Scripts:**

**`discover_entrypoints.py`** -- Discover all entry points

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--json` | flag | no | JSON output |
| `--type` | string | no | Filter to types (repeatable) |

**`rank_entrypoints.py`** -- Rank by attack value

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--top` | int | no | Top N |
| `--depth` | int | no | Callgraph depth |
| `--json` | flag | no | JSON output |
| `--min-score` | float | no | Minimum score |

**`generate_entrypoints_json.py`** -- Generate CRS-compatible output

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `-o` | string | no | Output file |
| `--top` | int | no | Top N |
| `--min-score` | float | no | Minimum score |
| `--depth` | int | no | Callgraph depth |

**20 entry point types detected:** EXPORT_DLL, EXPORT_ORDINAL_ONLY, MAIN_ENTRY, DLLMAIN, SERVICE_MAIN, COM_METHOD, WINRT_METHOD, RPC_HANDLER, NAMED_PIPE_HANDLER, CALLBACK_REGISTRATION, WINDOW_PROC, SERVICE_CTRL_HANDLER, TLS_CALLBACK, IPC_DISPATCHER, TCP_UDP_HANDLER, EXCEPTION_HANDLER, COM_CLASS_FACTORY, SCHEDULED_CALLBACK, HOOK_PROCEDURE, FORWARDED_EXPORT.

**Ranking factors (5 weighted dimensions):**

| Factor | Weight |
|--------|--------|
| Dangerous operations reachable | 30% |
| Parameter risk | 25% |
| Proximity to danger | 15% |
| Reachability breadth | 15% |
| Entry type risk | 15% |

**Dependencies:** callgraph-tracer, classify-functions, data-flow-tracer, reconstruct-types.

---

#### 3.2.6 security-dossier

**Purpose:** One-command deep context gathering for security auditing. Builds comprehensive dossier covering function identity, attack reachability, untrusted data exposure, dangerous operations, resource patterns, complexity, neighboring context, and module security posture.

**Scripts:**

**`build_dossier.py`** -- Build security dossier

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `function_name` | positional | no | Function name |
| `--id` | string | no | Function ID |
| `--search` | string | no | Search pattern |
| `--json` | flag | no | JSON output |
| `--callee-depth` | int | no | Callee analysis depth (default 1) |

**8 dossier sections:** Function Identity, Attack Reachability, Untrusted Data Exposure, Dangerous Operations, Resource Patterns, Complexity Assessment, Neighboring Context, Module Security Posture.

**7 high-priority indicators:** reachable from export, receives untrusted data, calls dangerous APIs, handles privileged resources, high cyclomatic complexity, has decompiler issues, error handling gaps.

**Dependencies:** taint-analysis, callgraph-tracer, data-flow-tracer, classify-functions, map-attack-surface.

---

#### 3.2.7 state-machine-extractor

**Purpose:** Detect and reconstruct command dispatchers, switch/case dispatch tables, and state machines from analysis databases.

**Scripts:**

**`detect_dispatchers.py`** -- Scan module for dispatch functions

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--min-cases` | int | no | Minimum case count (default 3) |
| `--with-loops` | flag | no | Only state machine candidates |
| `--json` | flag | no | JSON output |
| `--app-only` | flag | no | Skip WIL/STL/CRT |

**`extract_dispatch_table.py`** -- Extract case-to-handler mapping

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `function_name` | positional | no | Function name |
| `--id` | string | no | Function ID |
| `--search` | string | no | Search pattern |
| `--json` | flag | no | JSON output |

**`extract_state_machine.py`** -- Reconstruct state machine

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `function_name` | positional | no | Function name |
| `--id` | string | no | Function ID |
| `--with-code` | flag | no | Include decompiled code |
| `--json` | flag | no | JSON output |

**`generate_state_diagram.py`** -- Mermaid/DOT diagrams

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--function` | string | no | Function name |
| `--id` | string | no | Function ID |
| `--mode` | string | no | `dispatch` or `state-machine` |
| `--format` | string | no | `dot` format |

**Candidate types:** loop_switch, loop_if_chain, switch, if_chain, jump_table.

**Dependencies:** callgraph-tracer, classify-functions, security-dossier, data-flow-tracer.

---

#### 3.2.8 string-intelligence

**Purpose:** Scan string literals from analysis databases and classify them into security-relevant categories.

**Scripts:**

**`analyze_strings_deep.py`** -- Deep string categorization

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--json` | flag | no | JSON output |
| `--id` | string | no | Specific function ID |
| `--function` | string | no | Specific function name |
| `--top` | int | no | Top N per category |
| `--category` | string | no | Filter to category |
| `--no-cache` | flag | no | Bypass cache |

**Categories:** url, file_path, registry_key, named_pipe, rpc_endpoint, certificate, format_string, error_message, ETW provider GUID, debug string.

**Dependencies:** classify-functions, security-dossier, data-flow-tracer, taint-analysis.

---

### 3.3 Interface Analysis

#### 3.3.1 com-interface-analysis

**Purpose:** Analyze COM server interfaces using pre-built extraction data. Maps binaries to CLSIDs, interface methods, pseudo-IDL, SDDL permissions, service identities, elevation flags, and activation types. Privilege-boundary risk scoring across four access contexts.

**Scripts:**

**`resolve_com_server.py`** -- List COM servers for a module or lookup by CLSID

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module_or_clsid` | positional | yes | Module name or CLSID |
| `--context` | string | no | Access context |
| `--json` | flag | no | JSON output |

**`map_com_surface.py`** -- Risk-ranked COM attack surface

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `--system-wide` | flag | no | System-wide scan |
| `--top` | int | no | Top N |
| `--tier` | string | no | Filter by tier |
| `--privileged-only` | flag | no | Privileged servers only |
| `--context` | string | no | Access context |
| `--json` | flag | no | JSON output |

**`enumerate_com_methods.py`** -- List methods with pseudo-IDL

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module_or_clsid` | positional | yes | Module or CLSID |
| `--show-pseudo-idl` | flag | no | Show pseudo-IDL |
| `--json` | flag | no | JSON output |

**`classify_com_entrypoints.py`** -- Semantic classification

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module` | positional | no | Module name |
| `--system-wide` | flag | no | System-wide |
| `--json` | flag | no | JSON output |

**`audit_com_security.py`** -- Security audit

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module_or_clsid` | positional | yes | Module or CLSID |
| `--json` | flag | no | JSON output |

**`find_com_privesc.py`** -- Privilege escalation targets

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `--json` | flag | no | JSON output |
| `--top` | int | no | Top N |
| `--include-uac` | flag | no | Include UAC bypass candidates |

**Four access contexts:** high_il/all, high_il/privileged, medium_il/all, medium_il/privileged.

**Dependencies:** decompiled-code-extractor, map-attack-surface, com-interface-reconstruction.

---

#### 3.3.2 com-interface-reconstruction

**Purpose:** Reconstruct COM/WRL interface definitions from vtable patterns, QueryInterface/AddRef/Release patterns, mangled names, and WRL template instantiations.

**Scripts:**

**`scan_com_interfaces.py`** -- Discover all COM interfaces

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--json` | flag | no | JSON output |
| `--vtable-only` | flag | no | VTable contexts only |

**`decode_wrl_templates.py`** -- Decode WRL template instantiations

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--json` | flag | no | JSON output |
| `--type` | string | no | Filter to WRL type |

**`map_class_interfaces.py`** -- Map interfaces to classes

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--json` | flag | no | JSON output |
| `--class` | string | no | Focus on specific class |

**`generate_idl.py`** -- Generate IDL-like descriptions

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--output` | string | no | Write to file |
| `--interface` | string | no | Filter to interface |

**Evidence priority:** WRL templates (highest) > QI dispatch code > VTable contexts > Mangled name patterns.

**Dependencies:** com-interface-analysis, reconstruct-types, callgraph-tracer, map-attack-surface.

---

#### 3.3.3 rpc-interface-analysis

**Purpose:** Analyze RPC interfaces using pre-built NtApiDotNet extraction data. Maps binaries to interfaces, procedure names, endpoint protocols, service associations, and NDR types. Enriches with C# client stub signatures (414 auto-generated stubs) and procedure semantic classification.

**Scripts:**

**`resolve_rpc_interface.py`** -- List all RPC interfaces for a module

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module` | positional | yes | Module name |
| `--json` | flag | no | JSON output |
| `--with-stubs` | flag | no | Include C# stub signatures |

**`map_rpc_surface.py`** -- Risk-ranked RPC attack surface

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module` | positional | no | Module name |
| `--system-wide` | flag | no | System-wide scan |
| `--top` | int | no | Top N |
| `--with-blast-radius` | flag | no | Blast-radius analysis |
| `--json` | flag | no | JSON output |

**`audit_rpc_security.py`** -- RPC-specific security audit

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--json` | flag | no | JSON output |

**`trace_rpc_chain.py`** -- Trace RPC handler data flow

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--function` | string | yes | Function name |
| `--json` | flag | no | JSON output |

**`find_rpc_clients.py`** -- Find RPC interface consumers

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `interface_uuid` | positional | yes | Interface UUID |
| `--json` | flag | no | JSON output |

**`rpc_topology.py`** -- Client-server topology graph

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `--json` | flag | no | JSON output |
| `module` | positional | no | Module name |
| `--top` | int | no | Top N |

**Dependencies:** decompiled-code-extractor, map-attack-surface, callgraph-tracer, taint-analysis.

---

#### 3.3.4 winrt-interface-analysis

**Purpose:** Analyze WinRT server registrations. Maps binaries to activation classes, interface methods, pseudo-IDL, trust levels, SDDL permissions, server identities, and activation types. Privilege-boundary risk scoring across four access contexts.

**Scripts:**

**`resolve_winrt_server.py`** -- List all WinRT server classes

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module` | positional | yes | Module name |
| `--json` | flag | no | JSON output |
| `--context` | string | no | Access context |

**`map_winrt_surface.py`** -- Risk-ranked WinRT attack surface

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `--system-wide` | flag | no | System-wide scan |
| `--top` | int | no | Top N |
| `--tier` | string | no | Filter by tier |
| `--privileged-only` | flag | no | Privileged servers only |
| `--context` | string | no | Access context |
| `--json` | flag | no | JSON output |

**`enumerate_winrt_methods.py`** -- List methods with pseudo-IDL

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module_or_class` | positional | yes | Module or class name |
| `--show-pseudo-idl` | flag | no | Show pseudo-IDL |
| `--json` | flag | no | JSON output |

**`classify_winrt_entrypoints.py`** -- Semantic classification

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module` | positional | no | Module name |
| `--system-wide` | flag | no | System-wide |
| `--json` | flag | no | JSON output |

**`audit_winrt_security.py`** -- Security audit (requires analysis DB)

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--json` | flag | no | JSON output |

**`find_winrt_privesc.py`** -- Privilege escalation targets

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `--json` | flag | no | JSON output |
| `--top` | int | no | Top N |

**Dependencies:** decompiled-code-extractor, map-attack-surface, com-interface-reconstruction.

---
EOF### 3.5 Verification

#### 3.5.1 verify-decompiled

**Purpose:** Find and fix specific places where Hex-Rays got something wrong compared to assembly. Produces the original decompiler output with minimal, targeted fixes -- not a rewrite. Cacheable.

**Scripts:**

**`scan_module.py`** -- Triage all functions for decompiler issues

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--min-severity` | string | no | Minimum severity filter (e.g., `HIGH`) |
| `--top` | int | no | Top N |
| `--json` | flag | no | JSON output |

**`verify_function.py`** -- Deep verification per function

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `function_name` | positional | no | Function name |
| `--id` | string | no | Function ID |
| `--search` | string | no | Search pattern |
| `--json` | flag | no | JSON output |

**7 heuristic checks:** Return type mismatch, call count mismatch, branch count mismatch, NULL check detection, signedness mismatch, access size mismatch, decompiler artifacts.

**Issue severity:** CRITICAL (missing operations/wrong control flow), HIGH (wrong types/sizes), MODERATE (wrong return/param types), LOW (cosmetic/artifacts).

**Key distinction from code-lifting:** Fixes only what the decompiler got wrong. Keeps IDA names, keeps gotos, makes surgical patches with `[FIX #N: description]` annotations.

**Dependencies:** analyze-ida-decompiled, security-dossier, callgraph-tracer.

---

#### 3.5.2 finding-verification

**Purpose:** Structured verification workflow forcing the agent to prove each vulnerability finding against assembly ground truth before accepting or rejecting. Produces TRUE POSITIVE or FALSE POSITIVE verdicts.

**Scripts:** None of its own (uses verify-decompiled, data-flow-tracer, callgraph-tracer scripts).

**Workflow:**
1. **Restate the claim** -- Document function, claim, root cause, trigger, impact, bug class
2. **Route: Standard vs Deep** -- Standard is default; Deep for cross-module, race conditions, logic, or inconclusive results
3. **Standard verification (4 steps):**
   1. Verify data flow (`forward_trace.py`)
   2. Verify attacker control (`chain_analysis.py --depth 3`)
   3. Devil's advocate review
   4. Render verdict (TRUE POSITIVE or FALSE POSITIVE)
4. **Deep verification:** Delegate to verifier subagent for fresh-eyes assembly comparison

**Mandatory language:** "does/is/will" in verdicts. NEVER "might/could/possibly/may/theoretically."

**Dependencies:** taint-analysis, data-flow-tracer, security-dossier, exploitability-assessment, import-export-resolver, callgraph-tracer.

---

### 3.6 Code Reconstruction

#### 3.6.1 code-lifting

**Purpose:** Define the 11-step workflow for lifting decompiled functions into clean, readable, functionally equivalent code. Workflow/recipe skill with no scripts of its own.

**11-step workflow:**
1. **Gather function data** -- `extract_function_data.py`
2. **Validate against assembly** -- Map memory access patterns, verify control flow, confirm calling convention, identify artifacts
3. **Rename parameters** -- Using signature, mangled name, type hints, API context
4. **Rename local variables** -- Based on purpose, register comments, API context
5. **Replace magic numbers** -- Win32 constants, HRESULT, message IDs, struct discriminants, bit flags
6. **Reconstruct structs** -- Collect accesses, compute offsets, determine field types
7. **Convert pointer arithmetic to field access** -- `*(TYPE*)(base + offset)` -> `obj->field`
8. **Simplify control flow** -- goto -> else, invert conditions, remove wrappers. Preserve SEH, setjmp/longjmp, lock pairs.
9. **Add documentation** -- Function doc block, inline comments explaining "why" not "what"
10. **Final verification** -- 15-point checklist
11. **Independent verification** -- Launch verifier subagent (PASS/WARN/FAIL)

**Core principle:** Assembly is ground truth. Decompiled code is the structural starting point.

**Dependencies:** decompiled-code-extractor, batch-lift, reconstruct-types, verify-decompiled, analyze-ida-decompiled.

---

#### 3.6.2 batch-lift

**Purpose:** Lift related function groups together with shared context -- class methods, call chains, or export subtrees. Builds shared struct definitions accumulated across all functions, determines dependency order, generates cohesive output.

**Scripts:**

**`collect_functions.py`** -- Multi-mode function collection

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--class` | string | no | All methods of a class |
| `--chain` | string | no | Call chain from function |
| `--export` | string | no | From named export |
| `--depth` | int | no | Call chain depth |
| `--id` | string | no | Function ID |
| `--json` | flag | no | JSON output |

**`prepare_batch_lift.py`** -- Generate lift plan with shared structs

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `--from-json` | string | no | From collect output |
| `db_path` | positional | no | Direct DB path |
| `--ids` | string | no | Direct function IDs (comma-separated) |
| `--summary` | flag | no | Summary only |
| `--structs-only` | flag | no | Structs only |

**Three batch modes:** Class methods, Call chain, Export-down.

**Batch-specific rules:**
- Shared struct definition across all functions
- Consistent naming propagation
- Cross-reference comments between lifted functions
- Constants propagate from any function to all
- Constructor lifted first (reveals struct layout)

**Dependencies:** decompiled-code-extractor, code-lifting, callgraph-tracer, reconstruct-types, verify-decompiled, classify-functions.

---

#### 3.6.3 reconstruct-types

**Purpose:** Module-wide type reconstruction from analysis databases. Scans ALL functions using both decompiled C++ and raw x64 assembly, merges with vtable contexts and mangled names, produces compilable C/C++ header files.

**Scripts:**

**`list_types.py`** -- Quick overview of all C++ classes

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--with-vtables` | flag | no | Include vtable context availability |
| `--json` | flag | no | JSON output |

**`extract_class_hierarchy.py`** -- Full class hierarchy

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--class` | string | no | Filter to class |
| `--json` | flag | no | JSON output |

**`scan_struct_fields.py`** -- Core memory access pattern scanner

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--class` | string | no | Scan all methods of class |
| `--function` | string | no | Scan single function |
| `--id` | string | no | Function ID |
| `--all-classes` | flag | no | Scan all classes |
| `--json` | flag | no | JSON output |
| `--no-asm` | flag | no | Skip assembly scanning |

**`generate_header.py`** -- Produce compilable `.h` header files

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | no | Analysis DB |
| `--class` | string | no | For one class |
| `--all` | flag | no | For all types |
| `--output` | string | no | Output file |
| `--from-json` | string | no | From pre-computed JSON |

**Confidence scoring:**

| Factor | Score |
|--------|-------|
| 4+ source functions | +0.50 |
| 2-3 source functions | +0.30 |
| 1 source function | +0.15 |
| Assembly-verified | +0.30 |
| 2+ access type patterns | +0.20 |
| 1 access type pattern | +0.10 |

Labels: high (>=0.70), medium (>=0.40), low (<0.40).

**Dependencies:** code-lifting/batch-lift, com-interface-reconstruction, data-flow-tracer, classify-functions, security-dossier.

---

### 3.7 Methodology / Strategy

#### 3.7.1 adversarial-reasoning

**Purpose:** Encode the methodology that separates elite vulnerability researchers from routine auditors. Hypothesis-driven investigation, attack pattern recognition, variant analysis, and structured validation. No scripts -- produces approved research designs.

**Five research modes:**

1. **Campaign** ("Where should I look?") -- Full research campaign planning against a module. Produces 3-7 ranked hypotheses with investigation commands.
2. **Hypothesis** ("Is this vulnerability real?") -- Classify into vulnerability class, map to validation strategy, produce 3-5 investigation commands.
3. **Variant** ("Are there more like this?") -- Decompose known pattern into searchable signals, design search queries, produce focused hypotheses per candidate.
4. **Validate** ("How do I confirm this finding?") -- Check decompiler accuracy, apply validation strategy matrix, produce confirmation checklist and PoC skeleton.
5. **Surface** ("Where can an attacker get in?") -- Enumerate trust boundaries, identify security checks and failure modes per boundary, rank attack vectors.

**Hypothesis generation framework:** Templates from entry point types (7), classification signals (7), data flow patterns (6), code patterns (7).

**Research prioritization rubric:** 4 dimensions (Exploitability, Impact, Novelty, Feasibility), each 1-5, multiplied. Focus on composite >= 45.

**Validation strategy matrix:** Maps 8 vulnerability classes to static/dynamic validation approaches and PoC skeletons.

**Windows security mental models:** Trust boundary diagram, 7 privilege escalation vectors, IPC security pitfalls (RPC/ALPC, Named Pipes, COM), 5 file system attacks, 6 memory safety risks.

**Dependencies:** security-dossier, taint-analysis, data-flow-tracer, map-attack-surface, classify-functions, callgraph-tracer, reconstruct-types.

---

#### 3.7.2 brainstorming

**Purpose:** Collaborative design dialogue before implementation. Gather context, ask focused questions, propose approaches with trade-offs, validate before building.

**Workflow:**
1. Gather context from available modules, prior analysis
2. Clarify requirements via AskQuestion tool
3. Propose 2-3 approaches with trade-offs and recommended option
4. Present design, check incrementally
5. Transition to implementation plan via CreatePlan tool

**Questioning focus areas:** VR research planning (target, hypothesis, threat model, scope) and tool/skill design (purpose, constraints, success criteria).

**Dependencies:** References all major analysis and security skills.

---

#### 3.7.3 deep-context-builder

**Purpose:** Build deep, accurate understanding of decompiled code before vulnerability hunting. Forces block-by-block analysis using First Principles, 5 Whys, and 5 Hows to reduce hallucinations and missed assumptions.

**Three phases:**

1. **Initial Orientation** -- Identify function groups (`triage_summary.py`), note exports (`discover_entrypoints.py`), identify globals (`global_state_map.py --summary`), build preliminary structure.

2. **Ultra-Granular Function Analysis** -- Per-block analysis with: What, Why, Assumptions, Invariants, Dependencies + First Principles, 5 Whys, 5 Hows. Model external calls as adversarial. Cross-function flow via internal calls.

3. **Global System Understanding** -- State/invariant reconstruction, workflow reconstruction, trust boundary mapping, complexity/fragility clustering.

**Quality thresholds per function:** Minimum 3 invariants, 5 assumptions, 3 risk considerations.

**Anti-hallucination rules:** Never reshape evidence, periodically anchor facts, avoid vague guesses, cross-reference constantly.

**Dependencies:** decompiled-code-extractor, classify-functions, callgraph-tracer, data-flow-tracer, map-attack-surface.

---

### 3.8 Meta / Orchestration

#### 3.8.1 deep-research-prompt

**Purpose:** Generate structured, evidence-based deep research prompts by orchestrating all other skills to gather maximum context, then synthesizing into comprehensive research prompts and reports. Cacheable.

**Scripts:**

**`gather_function_context.py`** -- Deep function intelligence

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `function_name` | positional | no | Function name |
| `--id` | string | no | Function ID |
| `--depth` | int | no | Call graph depth (default 3) |
| `--cross-module` | flag | no | Cross-module resolution |
| `--with-code` | flag | no | Include decompiled code |
| `--json` | flag | no | JSON output |

**`gather_module_context.py`** -- Module-level intelligence

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--categories` | string | no | Focus on specific categories |
| `--top` | int | no | Top-N interesting functions |
| `--json` | flag | no | JSON output |

**`generate_research_prompt.py`** -- Main prompt generator

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | no | Analysis DB |
| `function_name` | positional | no | Function name |
| `--area` | string | no | Module area |
| `--from-json` | string | no | From pre-gathered context |
| `--detail` | string | no | `full` or `brief` |
| `--output` | string | no | Write to file |
| `--cross-module` | flag | no | Cross-module context |
| `--depth` | int | no | Call graph depth |

**Research prompt template:** Target Description, Known Context (7 subsections), Research Questions (4 priority levels), Requested Output.

**Dependencies:** classify-functions, callgraph-tracer, data-flow-tracer, generate-re-report, state-machine-extractor, com-interface-reconstruction, reconstruct-types, taint-analysis, decompiled-code-extractor.

---

#### 3.8.2 analyze-ida-decompiled

**Purpose:** Reference documentation for navigating, reading, and understanding IDA Pro decompiled code from DeepExtractIDA outputs. Teaches how to interpret extraction outputs, IDA naming conventions, struct field patterns, COM/WRL virtual calls, and HRESULT error handling.

**Workflow:**
1. **Orient** -- Read module metadata (`file_info.json`)
2. **Discover** -- Find target function (via index, search, grep)
3. **Analyze** -- Read and understand (parse header, read body, map struct access, identify API calls)
4. **Cross-reference** -- Trace call chains, check imports, search for `sub_XXXX`
5. **Contextualize** -- Understand binary role (security_features, entry_points, exports, rich_header)

**IDA naming patterns:** `a1`/`a2` (parameters), `v1`/`v2` (locals), `sub_XXXX` (unnamed functions), `off_XXXX` (global pointer data), `dword_XXXX` (global DWORD data), `??0ClassName` (constructor), `??1ClassName` (destructor).

**Dependencies:** function-index, decompiled-code-extractor, classify-functions, callgraph-tracer.

---

## 4. Agents Reference

### Agent Routing Table

| You want to... | Use |
|-----------------|-----|
| Understand what a function does | **re-analyst** |
| Triage an unknown module | **triage-coordinator** (`--goal triage`) |
| Run a focused security scan | **security-auditor** |
| Run a security audit | **triage-coordinator** (`--goal security`) |
| Generate a comprehensive report | **triage-coordinator** (`--goal full`) |
| Reconstruct struct/class definitions | **type-reconstructor** |
| Lift all methods of a C++ class | **code-lifter** |
| Verify lifted code is correct | **verifier** |

---

### 4.1 re-analyst

**Type:** analyst | **Skills:** 8 | **Methodology:** adversarial-reasoning

**Purpose:** General reverse engineering analyst. Explains functions, understands modules, traces call chains, and classifies code using IDA naming conventions, Hex-Rays artifact recognition, Windows internals, and DeepExtractIDA data.

**Entry Scripts:**

**`re_query.py`** -- Multi-mode module/function query

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--overview` | flag | no | Module overview mode |
| `--function` | string | no | Function name to query |
| `--class` | string | no | C++ class name |
| `--exports` | flag | no | List exports |
| `--search` | string | no | Search pattern |
| `--context` | flag | no | Include full context |
| `--with-classification` | flag | no | Classification data with exports |
| `--id` | string | no | Function ID |
| `--json` | flag | no | JSON output |

**`explain_function.py`** -- Structured function explanation

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `function_name` | positional | no | Function name |
| `--id` | string | no | Function ID |
| `--depth` | int | no | Callee depth |
| `--no-assembly` | flag | no | Omit assembly |
| `--json` | flag | no | JSON output |

**Composed skills:** analyze-ida-decompiled, classify-functions, generate-re-report, decompiled-code-extractor, callgraph-tracer, data-flow-tracer, deep-research-prompt, taint-analysis.

**Workflows:**
1. "What does this function do?" -- `explain_function.py` -> read code -> map params/APIs/control flow -> structured explanation with confidence
2. "What does this module do?" -- `re_query.py --overview` -> `triage_summary.py` -> exports -> synthesize
3. "How does A reach B?" -- `build_call_graph.py --path A B` -> `chain_analysis.py`
4. "What class is this?" -- `re_query.py --class` -> inspect ctors/dtors/vtables

**When to use:** Explaining functions, understanding modules, tracing call chains, identifying IDA artifacts, navigating class hierarchies.

**When NOT to use:** Lifting (code-lifter), verification (verifier), orchestration (triage-coordinator), type reconstruction (type-reconstructor), VR planning (adversarial-reasoning skill).

---

### 4.2 triage-coordinator

**Type:** coordinator | **Skills:** 11

**Purpose:** Orchestrates multi-skill analysis workflows. Given a high-level goal, produces and executes a structured analysis plan by running skill scripts, collecting results, and synthesizing reports. Adapts analysis paths based on module characteristics.

**Entry Scripts:**

**`analyze_module.py`** -- Direct execution mode

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--goal` | string | yes | `triage`, `security`, `full`, `understand-function`, `types` |
| `--function` | string | no | Function name |
| `--json` | flag | no | JSON output |
| `--timeout` | int | no | Timeout |
| `--workspace-run-dir` | string | no | Workspace run directory |

**`generate_analysis_plan.py`** -- Plan generation mode

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--goal` | string | yes | Analysis goal |
| `--function` | string | no | Function name |
| `--json` | flag | no | JSON output |

**Composed skills:** classify-functions, map-attack-surface, callgraph-tracer, security-dossier, reconstruct-types, deep-research-prompt, com-interface-reconstruction, state-machine-extractor, decompiled-code-extractor, taint-analysis, import-export-resolver.

**Goals and pipelines:**

| Goal | Steps | Key Skills |
|------|-------|------------|
| `triage` | 3 | classify-functions, map-attack-surface |
| `security` | 13 | triage + rank, callgraph, dossier x5, taint x3 |
| `full` | 12+ | security + types, research prompt, optional COM/dispatch |
| `understand-function` | 5-6 | classify, extract, callgraph, data-flow, dossier, optional taint |
| `types` | 1-2 | reconstruct-types, optional COM |

**Adaptive routing (module fingerprinting):**

| Trait | Threshold | Effect |
|-------|-----------|--------|
| COM-heavy | >5 COM functions or >10% | + COM reconstruction, + types priority |
| RPC-heavy | >3 RPC functions | + RPC handler focus |
| Security-relevant | >3 security, >2 crypto, >10 dangerous APIs | + dossiers, + taint |
| Dispatch-heavy | >5 dispatch/handler functions | + state-machine-extractor |
| Class-heavy | >3 C++ classes | + reconstruct-types, + batch-lift |
| Library-heavy | library/total > 0.5 | Pre-filter with `--app-only` |

**Parallelization:** triage_summary + discover_entrypoints + classify_module (parallel); rank_entrypoints depends on discover; dossiers depend on rank; taint depends on rank.

**When to use:** First look at unknown module, security audit, comprehensive analysis, deep-dive into function, type reconstruction. **When NOT to use:** Single-function explanation (re-analyst), lifting (code-lifter), verification (verifier).

---

### 4.3 security-auditor

**Type:** analyst | **Skills:** 8 | **Methodologies:** adversarial-reasoning, finding-verification

**Purpose:** Dedicated security assessment: vulnerability scanning, exploitability analysis, and finding verification.

**Entry Script:**

**`run_security_scan.py`**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--goal` | string | no | Scan goal |
| `--function` | string | no | Focus on function |
| `--top` | int | no | Top results |
| `--json` | flag | no | JSON output |
| `--timeout` | int | no | Timeout |

**Composed skills:** decompiled-code-extractor, classify-functions, map-attack-surface, security-dossier, taint-analysis, exploitability-assessment, memory-corruption-detector, logic-vulnerability-detector.

**6-phase workflow:**

1. **Reconnaissance** -- Resolve DB, discover entry points, rank by attack value
2. **Vulnerability scanning** -- Run 8 scanners (4 memory + 4 logic) in parallel
3. **Taint analysis** -- `taint_function.py` and `trace_taint_cross_module.py` for top findings
4. **Verification** -- `verify_findings.py` for both memory and logic; drop confidence < 0.7
5. **Exploitability assessment** -- `assess_finding.py` for verified findings
6. **Report synthesis** -- Security dossiers, consolidated report with evidence

**Severity criteria:**

| Level | Definition |
|-------|-----------|
| CRITICAL | Confirmed data flow from untrusted source to dangerous sink, no guards |
| HIGH | One additional precondition needed |
| MEDIUM | Multiple preconditions, defense-in-depth gap |
| LOW | Code quality concern without direct security impact |

**Rationalizations to reject:** "A guard exists" (may be bypassable), "Path is too deep" (depth != exploitability), "Internal function" (may be reachable via exports), "Only a DoS" (DoS in system services = boundary violation), "Mitigations block it" (mitigations raise bar, don't eliminate).

**When to use:** Security audits with taint/exploitability/verification, batch scanning, finding verification, consolidated security reports.

**When NOT to use:** Explanation (re-analyst), lifting (code-lifter), orchestration (triage-coordinator), type reconstruction (type-reconstructor), lifted-code verification (verifier).

---

### 4.4 code-lifter

**Type:** lifter | **Skills:** 6

**Purpose:** Lift decompiled functions and class methods into clean, readable C++ while preserving exact behavior. Maintains shared struct definitions, naming conventions, constants, and already-lifted code across all methods in a batch.

**Entry Scripts:**

**`batch_extract.py`** -- Extraction and state initialization

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--class` | string | no | C++ class name |
| `--functions` | list | no | Specific function names |
| `--id-list` | string | no | Comma-separated function IDs |
| `--init-state` | flag | no | Initialize shared state file |
| `--summary` | flag | no | Summary output |
| `--json` | flag | no | JSON output |

**`track_shared_state.py`** -- Persistent state tracker

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `--dump` | flag | no | Get current shared state |
| `--list` | flag | no | List active state files |
| `--record-field` | multi | no | Record struct field: `class offset name type` |
| `--record-constant` | multi | no | Record constant: `NAME VALUE` |
| `--record-naming` | multi | no | Record name mapping: `ida_name clean_name` |
| `--mark-lifted` | string | no | Mark function as lifted |
| `--record-signature` | multi | no | Record clean signature |
| `--init` | string | no | Initialize state for class |
| `--reset` | string | no | Reset state |
| `--class` | string | no | Class filter |
| `--source` | string | no | Source function for provenance |
| `--asm-verified` | flag | no | Mark field as assembly-verified |
| `--json` | flag | no | JSON output |

**Composed skills:** decompiled-code-extractor, code-lifting, batch-lift, reconstruct-types, verify-decompiled, function-index.

**7-step workflow:**
1. **Orient** -- find module DB
2. **Extract** -- `batch_extract.py --class <Name>` for all method data
3. **Init state** -- `batch_extract.py --init-state` creates state JSON
4. **Scan struct** -- deep scan via `scan_struct_fields.py`, record fields
5. **Lift (loop)** -- for each function in dependency order (constructors first): read state -> lift (10-step code-lifting workflow) -> update state -> mark lifted
6. **Assemble** -- combine into single `.cpp` file
7. **Report** -- include `verification_needed` for verifier handoff

**5 shared state rules:**
1. Struct definitions accumulate across methods
2. Naming propagates (if `field_30` becomes `pDacl`, use everywhere)
3. Constants propagate from any function to all
4. Cross-reference by clean lifted names
5. Constructor first (reveals struct layout most clearly)

**When to use:** Lifting all class methods, related function groups, batch lifting with shared context.

**When NOT to use:** Explaining (re-analyst), verifying (verifier), type reconstruction (type-reconstructor), orchestration (triage-coordinator), security analysis.

---

### 4.5 type-reconstructor

**Type:** reconstructor | **Skills:** 3

**Purpose:** Reconstruct C/C++ structs and classes from memory access patterns. Scans for `*(TYPE*)(base+offset)` and `[reg+offset]` patterns, merges evidence, resolves vtables and COM layouts, generates compilable headers with per-field confidence annotations.

**Entry Scripts:**

**`reconstruct_all.py`** -- Main orchestrator

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--class` | string | no | Single class |
| `--output` | string | no | Output file |
| `--include-com` | flag | no | Include COM integration |
| `--json` | flag | no | JSON output |

**`merge_evidence.py`** -- Evidence merger

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `--scan-output` | string | yes | Scan output JSON |
| `--com-data` | string | no | COM data JSON |
| `--class` | string | no | Filter to class |
| `--json` | flag | no | JSON output |
| `--output` | string | no | Output file |

**`validate_layout.py`** -- Layout validator

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `--header` | string | yes | Generated header file |
| `--class` | string | no | Validate one class |
| `--json` | flag | no | JSON output |

**Composed skills:** decompiled-code-extractor, reconstruct-types, com-interface-reconstruction.

**9-phase workflow:**
1. Orient -- find module DB
2. Discover -- list C++ classes
3. Hierarchy -- extract ctors/dtors/vtables
4. Scan -- memory access patterns (decompiled + assembly)
5. Merge -- conflict resolution, padding, confidence
6. COM (optional) -- COM vtable layouts, WRL templates
7. Generate -- compilable C++ header
8. Validate -- cross-check header vs assembly
9. Refine -- improve field names from semantic context

**Conflict resolution:** Same offset, different sizes -> assembly-verified wins, else wider type. Same offset, different types -> more specific wins. Overlapping fields -> annotated as potential union.

**When to use:** Struct/class reconstruction, header generation, type preparation for lifting, COM object layouts.

**When NOT to use:** Lifting (code-lifter), explaining (re-analyst), verifying (verifier), security analysis.

---

### 4.6 verifier

**Type:** verifier | **Skills:** 3

**Purpose:** Independently verify that lifted code matches original binary behavior. Operates with fresh eyes in separate context to prevent confirmation bias. Compares against assembly ground truth using systematic checks, basic block mapping, and x64 analysis.

**Entry Scripts:**

**`compare_lifted.py`** -- Core comparison with 7 automated checks

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `function_name` | positional | no | Function name |
| `--id` | string | no | Function ID |
| `--lifted` | string | no | Path to lifted code file |
| `--lifted-stdin` | flag | no | Read lifted code from stdin |
| `--json` | flag | no | JSON output |

**7 automated checks:**

| Check | Severity on Fail |
|-------|------------------|
| Call count match | CRITICAL |
| Branch count match | CRITICAL |
| String literal usage | FAIL/WARNING |
| Return path analysis | WARNING |
| API name preservation | CRITICAL |
| Global variable access | WARNING |
| Memory access coverage | WARNING |

**`extract_basic_blocks.py`** -- Basic block splitter

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db_path` | positional | yes | Analysis DB |
| `function_name` | positional | no | Function name |
| `--id` | string | no | Function ID |
| `--json` | flag | no | JSON output |

**`generate_verification_report.py`** -- Report generator

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `--compare-output` | string | yes | compare_lifted.py JSON output |
| `--agent-findings` | string | no | Agent findings JSON |
| `--output` | string | no | Output file |
| `--json` | flag | no | JSON output |

**Composed skills:** verify-decompiled, decompiled-code-extractor, code-lifting.

**5-phase verification methodology:**
1. **Gather original data** -- save lifted code, run compare_lifted.py, extract function data, split basic blocks
2. **Automated checks** -- review compare_lifted.py output, examine discrepancies
3. **Manual block-by-block** -- for each basic block, verify every instruction has C++ equivalent
4. **Check for common lifting errors** -- 9 error types (missing branches, wrong access sizes, missing NULL guards, lost volatile reads, incorrect offsets, missing error checks, SEH omissions, lock mismatches, wrong signedness)
5. **Produce verdict** -- PASS (faithful), WARN (minor discrepancies), FAIL (behavioral mismatches)

**5 core principles:** Assume nothing, assembly is ground truth, be systematic, report evidence, no false positives (uncertain = INVESTIGATE).

**When to use:** After lifting, checking code transformations, auditing decompiler accuracy on specific function.

**When NOT to use:** Lifting (code-lifter), explaining (re-analyst), type reconstruction (type-reconstructor), security analysis, decompiler-only verification (verify-decompiled skill).

---

EOF## 5. Commands Reference

### Command Master Table

| Phase | Command | Purpose | Grind Loop |
|-------|---------|---------|------------|
| **Getting Started** | `/quickstart` | Guided first experience | no |
| | `/health` | Workspace validation | no |
| **Reconnaissance** | `/triage` | Module triage | no |
| | `/full-report` | End-to-end analysis | yes |
| | `/explain` | Explain a function | no |
| | `/search` | Cross-dimensional search | no |
| | `/xref` | Cross-reference lookup | no |
| **Module Understanding** | `/callgraph` | Call graph analysis | no |
| | `/data-flow` | Data flow trace | no |
| | `/data-flow-cross` | Cross-module data flow | no |
| | `/imports` | PE import/export relationships | no |
| | `/strings` | String intelligence | no |
| | `/state-machines` | State machine extraction | no |
| | `/compare-modules` | Cross-module comparison | no |
| | `/diff` | Compare binary versions | no |
| | `/trace-export` | Trace export call chain | no |
| **Interface Analysis** | `/com` | COM server analysis | no |
| | `/rpc` | RPC interface analysis | no |
| | `/winrt` | WinRT server analysis | no |
| **Vulnerability Scanning** | `/scan` | Unified vulnerability scan | yes |
| | `/memory-scan` | Memory corruption scan | no |
| | `/logic-scan` | Logic vulnerability scan | no |
| | `/taint` | Taint analysis | no |
| **Security Auditing** | `/audit` | Audit single function | no |
| | `/batch-audit` | Audit multiple functions | yes |
| **VR Campaigns** | `/hunt` | VR planning | no |
| | `/hunt-execute` | Execute hunt plan | yes |
| | `/brainstorm` | Research planning | no |
| **Code Quality** | `/verify` | Verify decompiler accuracy | no |
| | `/verify-batch` | Batch verify | yes |
| | `/lift-class` | Batch-lift class methods | yes* |
| | `/reconstruct-types` | Reconstruct types | no |
| **Reporting & Ops** | `/prioritize` | Cross-module prioritization | no |
| | `/pipeline` | Batch pipeline | no |
| | `/runs` | Browse prior runs | no |
| | `/cache-manage` | Manage cache | no |

*\* Grind loop as fallback only; primary mechanism uses code-lifter subagent.*

---

### 5.1 Getting Started

#### `/quickstart`

**Purpose:** Guided first-time experience. Auto-detects modules and runs lightweight triage.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module` | positional | no | Target module |

**Workflow:**
1. Discover available modules (`find_module_db.py --list`)
2. Select target (user-specified or auto-pick most interesting by entry points, classification diversity, security APIs)
3. Run 3 concurrent analyses: `triage_summary.py`, `discover_entrypoints.py`, `build_call_graph.py --stats`
4. Present orientation: module summary, top interesting functions table, top entry points, recommended next command, "Other Things You Can Do" list
5. Module landscape (when multiple modules, comparative table)

**Skills:** classify-functions, map-attack-surface, callgraph-tracer, decompiled-code-extractor.

---

#### `/health`

**Purpose:** Pre-flight workspace validation.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `--quick` | flag | no | Skip DB integrity and function indexes |
| `--full` | flag | no | Exhaustive check (validate every DB, every index, run tests) |

**Workflow:**
1. Check extraction data (`validate_workspace_data`)
2. Validate analysis databases (skip if `--quick`; sample if >50 DBs without `--full`)
3. Verify skill scripts exist (check `registry.json`)
4. Verify agent scripts exist (check `registry.json`)
5. Verify command registry consistency
6. Validate configuration (`validate_config`)
7. Check function index consistency (skip if `--quick`; sample if >50 modules without `--full`)
8. Run test suite (only if `--full`, via `pytest`)
9. Synthesize health report

**Skills:** None (uses helpers directly: `validation`, `config`)

---

### 5.2 Reconnaissance

#### `/triage`

**Purpose:** Full module triage -- identity, classification, attack surface, recommendations.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module_name` | positional | yes | Module name |
| `--with-security` | flag | no | Add lightweight taint scan on top entries |

**Workflow:**
1. Find module DB
2. Binary identity and security posture (`generate_report.py --summary`, `file_info.json`, `module_profile.json`)
3. Classify all functions (`triage_summary.py --top 15`)
4. Call graph topology (`build_call_graph.py --stats`)
5. Attack surface (`discover_entrypoints.py`, `rank_entrypoints.py --top 10`)
6. (Optional) Quick taint scan on top 3-5 entries (`taint_function.py`)
7. Synthesize report (binary identity, capability profile, scale/complexity, top 10 interesting, attack surface, quick findings, next steps)

**Skills:** decompiled-code-extractor, generate-re-report, classify-functions, callgraph-tracer, map-attack-surface, taint-analysis (optional), function-index.

**Output:** `extracted_code/<module>/reports/triage_<module>_<timestamp>.md`

**Parallelism:** Steps 3+4+5 concurrent.

---

#### `/full-report`

**Purpose:** End-to-end multi-phase analysis -- the most thorough single-command analysis.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module_name` | positional | yes | Module name |
| `--brief` | flag | no | Abbreviated (sections 1,3,4,10 only) |

**Workflow (6 phases):**
1. **Setup** -- Find DB, generate adaptive plan (`generate_analysis_plan.py --goal full`), create scratchpad
2. **Phase 1: Identity** -- `generate_report.py --top 15`
3. **Phase 2: Classification** -- `triage_summary.py`, `classify_module.py`
4. **Phase 3: Attack Surface** -- Discover, rank, generate `entrypoints.json`, dossiers for top 3-5, taint on top 3
5. **Phase 4: Topology** -- Call graph stats, cross-module deps, Mermaid diagrams
6. **Phase 5: Specialized** (adaptive) -- COM interfaces, dispatch tables, global state, decompilation quality, types -- triggered by triage-coordinator traits
7. **Phase 6: Synthesis** -- Assemble 11-section comprehensive report

**Skills:** decompiled-code-extractor, generate-re-report, classify-functions, map-attack-surface, callgraph-tracer, com-interface-reconstruction, state-machine-extractor, data-flow-tracer, taint-analysis, security-dossier, reconstruct-types, verify-decompiled, function-index. **Agent:** triage-coordinator.

**Grind loop:** Yes -- one checkbox per phase (6 items).

**Output:** `extracted_code/<module>/reports/full_report_<module>_<timestamp>.md`

---

#### `/explain`

**Purpose:** Quick structured explanation of what a function does.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module` | positional | no | Module name |
| `function_name` | positional | yes | Function name |
| `--depth` | int | no | Callee depth (default 1) |
| `--search` | string | no | Pattern search |

**Workflow:**
1. Locate function (`lookup_function.py` or `unified_search.py`)
2. Gather context (`explain_function.py` from re-analyst; fallback: `extract_function_data.py` + `classify_function.py`; deep: `gather_function_context.py`)
3. Synthesize: Purpose, Parameters, Return Value, Behavior, Key API Calls, Strings, Call Context, Confidence, Decompiler Notes

**Skills:** function-index, decompiled-code-extractor, classify-functions, deep-research-prompt. **Agent:** re-analyst.

---

#### `/search`

**Purpose:** Cross-dimensional search across functions, strings, APIs, classes, exports.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module` | positional | no | Module name |
| `search_term` | positional | yes | Search term |
| `--dimensions` | string | no | Comma-separated: name, signature, string, api, dangerous, class, export (default: all) |
| `--all` | flag | no | All modules |
| `--regex` | flag | no | Regex mode |
| `--fuzzy` | flag | no | Fuzzy mode (typo-tolerant) |
| `--threshold` | float | no | Fuzzy threshold 0.0-1.0 (default 0.6) |
| `--limit` | int | no | Results per dimension (default 25) |
| `--sort` | string | no | `score`, `name`, or `id` |

**Workflow:**
1. Resolve target (module DB or `--all`)
2. Run `unified_search.py` with mode/flags
3. Present grouped results with relevance scores

**Skills:** Uses `helpers/unified_search.py` directly.

---

#### `/xref`

**Purpose:** Quick cross-reference lookup showing callers and callees.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module` | positional | no | Module name |
| `function_name` | positional | yes | Function name |
| `--depth` | int | no | Levels (default 1) |
| `--search` | string | no | Pattern search |

**Workflow:**
1. Locate function (`lookup_function.py` or `find_module_db.py`)
2. Extract xrefs (`analyze_detailed_xrefs.py`; depth 2+: `build_call_graph.py --neighbors`; cross-module: `cross_module_resolve.py`)
3. Present: inbound callers table, outbound callees table (with security API categories)

**Skills:** callgraph-tracer, function-index.

---

### 5.3 Module Understanding

#### `/callgraph`

**Purpose:** Build and query call graphs.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module` | positional | yes | Module name |
| `function` | positional | no | Function (for neighborhood) |
| `--scc` | flag | no | Strongly connected components |
| `--roots` | flag | no | Functions with no callers |
| `--leaves` | flag | no | Functions that call nothing |
| `--diagram` | flag | no | Mermaid diagram |
| `--path <A> <B>` | strings | no | Path between functions |
| `--reachable <A>` | string | no | Reachable from function |

**Skills:** decompiled-code-extractor, callgraph-tracer.

---

#### `/data-flow`

**Purpose:** Trace data flow within a module (forward, backward, string, globals).

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| direction | positional | yes | `forward`, `backward`, `string`, or `globals` |
| `module` | positional | yes | Module name |
| `function` | positional | no | Function name |
| `--param` | int | no | Parameter index (forward) |
| `--target` | string | no | Target API (backward) |
| `--arg` | int | no | Argument index (backward) |
| `--callers` | flag | no | Include caller chain |
| `--depth` | int | no | Trace depth |
| `--assembly` | flag | no | Include assembly |
| `--string` | string | no | String to trace |
| `--list-strings` | flag | no | List all strings |
| `--limit` | int | no | Limit results |
| `--address` | string | no | Global variable address |

**Skills:** data-flow-tracer, decompiled-code-extractor, function-index.

---

#### `/data-flow-cross`

**Purpose:** Cross-module data flow tracing across DLL boundaries.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| direction | positional | yes | `forward` or `backward` |
| `module` | positional | yes | Starting module |
| `function` | positional | yes | Starting function |
| `--param` | int | no | Parameter index (forward) |
| `--target` | string | no | Target API (backward) |
| `--depth` | int | no | Trace depth |

**Workflow:**
1. Locate starting point (module DB + tracking DB)
2. Trace within module, resolve external callees via import-export/callgraph, continue in target modules
3. Synthesize cross-module report (trace path, module transitions, parameter mapping)

**Skills:** data-flow-tracer, callgraph-tracer, import-export-resolver, decompiled-code-extractor, function-index.

**Output:** `extracted_code/<module>/reports/data_flow_cross_<function>_<timestamp>.md`

---

#### `/imports`

**Purpose:** Query PE import/export relationships.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module` | positional | no | Module name |
| `--function` | string | no | Look up specific function |
| `--consumers` | flag | no | Modules depending on this module |
| `--diagram` | flag | no | Mermaid dependency diagram |
| `--forwarders` | flag | no | Resolve forwarder chains |

**Skills:** import-export-resolver.

---

#### `/strings`

**Purpose:** Categorize string literals by security relevance.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module` | positional | yes | Module name |
| `function` | positional | no | Function name |
| `--top` | int | no | Limit results |
| `--category` | string | no | Filter by category |
| `--id` | string | no | Function ID |

**Skills:** string-intelligence, decompiled-code-extractor.

---

#### `/state-machines`

**Purpose:** Extract state machines, dispatch tables, and command dispatchers.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module` | positional | yes | Module name |
| `function` | positional | no | Function name |
| `--diagram` | flag | no | Mermaid diagram |
| `--detect` | flag | no | Detect all dispatchers |

**Workflow:**
1. Find DB
2. Detect dispatchers (`detect_dispatchers.py`) or target specific function
3. Extract dispatch table (`extract_dispatch_table.py`)
4. Reconstruct state machine (`extract_state_machine.py`)
5. Generate diagram (`generate_state_diagram.py`)

**Skills:** state-machine-extractor, decompiled-code-extractor, function-index.

---

#### `/compare-modules`

**Purpose:** Compare two or more modules (dependencies, API overlap, classification distributions).

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module_A module_B [...]` | positional | yes | Two or more modules |
| `--all` | flag | no | All modules (capped at 50) |

**Workflow (11 steps):**
1. Find all module DBs
2. Cross-module dependency overview
3. Pairwise dependency analysis
4. PE-level import/export dependencies
5. API surface comparison
6. String intelligence comparison
7. Classification comparison
8. Security posture comparison
9. Cross-module call chain analysis
10. Generate cross-module diagram
11. Synthesize comparison report

**Skills:** decompiled-code-extractor, callgraph-tracer, generate-re-report, classify-functions, import-export-resolver, function-index.

---

#### `/diff`

**Purpose:** Compare two binary versions (function deltas, classification shifts, attack surface changes).

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module_old` | positional | yes | Old version |
| `module_new` | positional | yes | New version |

**Workflow:**
1. Resolve both DBs
2. Extract function inventories (added/removed/common)
3. Classify changes
4. Attack surface delta
5. Code-level diff for top 5-10 changed functions
6. Synthesis
7. Verification (spot-check top 3)

**Skills:** decompiled-code-extractor, classify-functions, map-attack-surface.

---

#### `/trace-export`

**Purpose:** Trace an export through its full call chain with code and Mermaid diagram.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module` | positional | no | Module name |
| `export_name` | positional | yes | Export name |
| `--depth` | int | no | Trace depth (default 3) |
| `--list` | flag | no | List all exports first |

**Workflow (10 steps):**
1. Find DB
2. Verify export (`analyze_imports.py --exports`)
3. Compact call tree (`chain_analysis.py --depth 3 --summary`)
4. Classify key functions (5-8 most interesting callees)
5. Security dossier (`build_dossier.py`)
6. Deep trace with code (`chain_analysis.py --depth 2 --follow`)
7. Data flow (`forward_trace.py`)
8. Taint analysis (conditional, `taint_function.py`)
9. Cross-module resolution
10. Generate Mermaid diagram

**Skills:** decompiled-code-extractor, generate-re-report, callgraph-tracer, classify-functions, security-dossier, data-flow-tracer, taint-analysis, import-export-resolver, function-index.

**Output:** `extracted_code/<module>/reports/trace_export_<export>_<timestamp>.md`

**Parallelism:** Steps 3+4 parallel; Steps 5+6+7+8+9+10 parallel.

---

### 5.4 Interface Analysis

#### `/com`

**Purpose:** COM server interface analysis (6 subcommands).

**Subcommands:** default (resolve), `surface`, `methods`, `classify`, `audit`, `privesc`.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module_or_clsid` | positional | no | Module name or CLSID |
| `--system-wide` | flag | no | System-wide surface |
| `--top` | int | no | Limit results |
| `--show-pseudo-idl` | flag | no | Show pseudo-IDL |

**Skills:** com-interface-analysis, decompiled-code-extractor, map-attack-surface.

---

#### `/rpc`

**Purpose:** RPC interface analysis (8 subcommands).

**Subcommands:** default (resolve), `surface`, `audit`, `trace`, `clients`, `topology`, `blast-radius`, `stubs`.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module` | positional | no | Module name |
| `function` | positional | no | Function (for `trace`) |
| `uuid` | positional | no | Interface UUID (for `clients`, `blast-radius`, `stubs`) |
| `--system-wide` | flag | no | System-wide |
| `--top` | int | no | Limit results |
| `--servers-only` | flag | no | Servers only |

**Skills:** rpc-interface-analysis, decompiled-code-extractor, map-attack-surface.

---

#### `/winrt`

**Purpose:** WinRT server interface analysis (6 subcommands).

**Subcommands:** default (resolve), `surface`, `methods`, `classify`, `audit`, `privesc`.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module_or_class` | positional | no | Module or class name |
| `--system-wide` | flag | no | System-wide surface |
| `--top` | int | no | Limit results |
| `--show-pseudo-idl` | flag | no | Show pseudo-IDL |

**Skills:** winrt-interface-analysis, decompiled-code-extractor, map-attack-surface.

---
### 5.5 Vulnerability Scanning

#### `/scan`

**Purpose:** Unified vulnerability scan (memory + logic + taint with verification and exploitability scoring).

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module` | positional | yes | Module name |
| `function` | positional | no | Specific function |
| `--top` | int | no | Limit per-category findings |
| `--memory-only` | flag | no | Memory corruption only |
| `--logic-only` | flag | no | Logic vulnerabilities only |
| `--taint-only` | flag | no | Taint analysis only |
| `--auto-audit` | flag | no | Auto-audit top 3 CRITICAL/HIGH |

**Workflow (5-6 phases):**
1. **Detection** -- Run memory (4 scanners), logic (4 scanners), taint (top 5 entries) in parallel
2. **Merge/Deduplicate** -- Normalize to common schema, cross-reference intersections
3. **Verify** -- `verify_findings.py` for memory + logic; apply FALSE_POSITIVE/UNCERTAIN adjustments
4. **Score Exploitability** -- `assess_finding.py` / `batch_assess.py` for CRITICAL/HIGH
5. **Synthesize** -- Executive summary, top findings, pipeline breakdown, mitigations, recommendations
6. (Optional) **Auto-audit** -- `/audit` pipeline on top 3 CRITICAL/HIGH

**Skills:** memory-corruption-detector, logic-vulnerability-detector, taint-analysis, map-attack-surface, exploitability-assessment, decompiled-code-extractor.

**Grind loop:** Yes -- 5-6 phase checkboxes.

**Output:** `extracted_code/<module>/reports/scan_<module>_<timestamp>.md`

---

#### `/memory-scan`

**Purpose:** Scan for memory corruption (buffer overflows, integer issues, use-after-free, format strings).

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module` | positional | yes | Module name |
| `function` | positional | no | Function name |
| `--top` | int | no | Limit findings |

**Workflow:**
1. Resolve DB
2. Run 4 scanners in parallel
3. Merge and deduplicate
4. Verify (`verify_findings.py`)
5. Present results

**Skills:** memory-corruption-detector, decompiled-code-extractor.

---

#### `/logic-scan`

**Purpose:** Scan for logic vulnerabilities (auth bypass, state errors, TOCTOU, API misuse).

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module` | positional | yes | Module name |
| `function` | positional | no | Function name |
| `--top` | int | no | Top N |
| `--id` | string | no | Function ID |

**Workflow:**
1. Resolve DB
2. Run auth bypass scanner
3. Run state machine scanner
4. Run general logic flaw scanner
5. Run API misuse scanner
6. Merge findings
7. Verify (`verify_findings.py`)
8. Generate report (`generate_logic_report.py`)
9. Present results

**Skills:** logic-vulnerability-detector, decompiled-code-extractor.

---

#### `/taint`

**Purpose:** Trace attacker-controlled inputs to dangerous sinks with guard/bypass analysis.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module` | positional | yes | Module name |
| `function` | positional | no | Function name |
| `--params` | string | no | Parameter indices (comma-separated) |
| `--depth` | int | no | Recursion depth |
| `--direction` | string | no | `forward`, `backward`, or `both` |
| `--cross-module` | flag | no | Cross-DLL tracing |
| `--cross-depth` | int | no | DLL boundary hops |
| `--from-entrypoints` | flag | no | Auto-discover top entries |
| `--top` | int | no | Entry point limit |
| `--min-score` | float | no | Minimum attack score |
| `--no-trust-analysis` | flag | no | Disable trust analysis |
| `--no-com-resolve` | flag | no | Disable COM vtable resolution |

**Workflow:**
1. Locate function
2. Run taint (`taint_function.py` or `trace_taint_cross_module.py`)
3. Present results (forward sinks/guards/logic effects, backward origins, cross-module boundary transitions)

**Skills:** taint-analysis, function-index, decompiled-code-extractor.

---

### 5.6 Security Auditing

#### `/audit`

**Purpose:** Security audit of a single function with dossier, verification, call chain, and risk assessment.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module` | positional | no | Module name |
| `function_name` | positional | yes | Function name |
| `--search` | string | no | Pattern search |

**Workflow (7 steps):**
1. Locate function
2. Build security dossier (`build_dossier.py`)
3. Extract full data + attack surface ranking + backward trace (if dangerous APIs) + module profile + forward taint (conditional)
4. Trace call chain (`chain_analysis.py`)
5. Classify function purpose (`classify_function.py`)
6. Synthesize audit report (8-concern checklist C1-C8, risk rubric with 4 dimensions)
7. Verify concerns with fresh-eyes subagent (re-analyst or verifier, readonly)

**Skills:** decompiled-code-extractor, security-dossier, map-attack-surface, data-flow-tracer, callgraph-tracer, classify-functions, taint-analysis, function-index.

**Output:** `extracted_code/<module>/reports/audit_<function>_<timestamp>.md`

**Parallelism:** Steps 2+3+3b parallel; Steps 4+5+3e parallel.

---

#### `/batch-audit`

**Purpose:** Audit multiple functions (top entry points, privilege-boundary handlers, explicit list, or class methods).

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module` | positional | yes | Module name |
| `func1 func2 ...` | positional | no | Explicit function list |
| `--top` | int | no | Top N entries (default 5) |
| `--min-score` | float | no | Minimum attack score (default 0.2) |
| `--class` | string | no | All methods of a class |
| `--privilege-boundary` | flag | no | Auto-discover RPC/COM/WinRT handlers |

**Workflow:**
1. Resolve targets (4 sub-paths: explicit, `--class`, `--privilege-boundary`, or `--top N` default)
2. Create scratchpad (one checkbox per function)
3. Per-function: dossier + taint + exploitability + classify + synthesize + update scratchpad
4. Synthesize batch report (executive summary, per-function table, cross-function patterns, recommendations)

**Skills:** security-dossier, taint-analysis, exploitability-assessment, classify-functions, map-attack-surface, rpc-interface-analysis, com-interface-analysis, winrt-interface-analysis, function-index, decompiled-code-extractor.

**Grind loop:** Yes -- one checkbox per function.

**Output:** `extracted_code/<module>/reports/batch_audit_<target>_<timestamp>.md`

---

### 5.7 VR Campaigns

#### `/hunt`

**Purpose:** Hypothesis-driven vulnerability research planning.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `mode` | positional | no | `campaign` (default), `hypothesis`, `variant`, `validate`, `surface` |
| `module` | positional | no | Module name |
| `target` | positional | no | Vulnerability class, function, or pattern |

**Workflow:**
1. Detect research mode
2. Gather existing context (session, cache, workspace)
3. Mode-specific questioning via AskQuestion
4. Apply adversarial-reasoning methodology
5. Present research plan (threat model, ranked hypotheses, estimated effort)
6. Iterate on disagreement
7. Persist plan to `.agent/workspace/<module>_hunt_plan_<timestamp>.json`
8. Transition via CreatePlan

**Skills:** adversarial-reasoning, classify-functions, map-attack-surface, security-dossier, taint-analysis.

**Note:** Collaborative dialogue only -- does NOT execute analysis.

---

#### `/hunt-execute`

**Purpose:** Execute a previously created `/hunt` plan.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module` | positional | no | Module name |
| `--plan-file` | string | no | Explicit plan file path |

**Workflow:**
1. Locate hunt plan (explicit file > workspace files > conversation history)
2. Create scratchpad (one item per hypothesis)
3. Per hypothesis: run mapped commands, collect evidence, score confidence (CONFIRMED/LIKELY/POSSIBLE/UNLIKELY/REFUTED), update scratchpad
4. Score exploitability for CONFIRMED/LIKELY findings
5. Synthesize findings report

**Skills:** taint-analysis, security-dossier, map-attack-surface, data-flow-tracer, callgraph-tracer, exploitability-assessment.

**Grind loop:** Yes -- one checkbox per hypothesis.

**Output:** `extracted_code/<module>/reports/hunt_execute_<timestamp>.md`

---

#### `/brainstorm`

**Purpose:** Collaborative research planning before implementation.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `topic` | free-text | yes | Research goal or topic |

**Workflow:**
1. Gather context (modules, cached results)
2. Clarify requirements via AskQuestion
3. Propose 2-3 approaches with trade-offs
4. Present design
5. Iterate
6. Transition via CreatePlan

**Skills:** brainstorming. **Note:** Dialogue only -- no scripts executed.

---

### 5.8 Code Quality

#### `/verify`

**Purpose:** Verify decompiler accuracy for a function or module scan.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module` | positional | no | Module name |
| `function_name` | positional | no | Function (omit for module scan) |
| `--top` | int | no | Limit for module scan (default 20) |

**Workflow:**
- **Per-function:** `verify_function.py` (deep assembly comparison)
- **Module-wide:** `scan_module.py` (rank all functions by issue severity)

**Skills:** verify-decompiled, function-index.

---

#### `/verify-batch`

**Purpose:** Batch verify decompiler accuracy for multiple functions or a class.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module` | positional | yes | Module name |
| `func1 [func2 ...]` | positional | no | Function names |
| `ClassName` | positional | no | Class name (all methods) |

**Workflow:**
1. Resolve functions (via lookup or class methods)
2. Create scratchpad (one per function)
3. Launch verifier subagent per function (up to 3-4 concurrent)
4. Synthesize batch report

**Skills:** verify-decompiled, function-index, reconstruct-types, decompiled-code-extractor. **Agent:** verifier (readonly).

**Grind loop:** Yes -- one checkbox per function.

**Output:** `extracted_code/<module>/reports/verify_batch_<target>_<timestamp>.md`

---

#### `/lift-class`

**Purpose:** Batch-lift all methods of a C++ class with shared struct context.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module` | positional | no | Module name |
| `ClassName` | positional | yes | Class name |
| `--list` | flag | no | List all detected classes |

**Workflow:**
1. Find DB
2. Collect and preview class methods (`batch_extract.py --summary`)
3. Delegate to code-lifter subagent (extracts, initializes state, lifts in dependency order, assembles `.cpp`)
4. Handle results
5. (Optional) Verify with verifier subagent (readonly, separate context)
6. Summary

**Skills:** decompiled-code-extractor, code-lifting, batch-lift, reconstruct-types. **Agents:** code-lifter (primary), verifier (optional).

**Grind loop:** Yes (fallback only when subagent unavailable).

**Output:** `extracted_code/<module>/lifted_<ClassName>.cpp`

---

#### `/reconstruct-types`

**Purpose:** Reconstruct C/C++ struct and class definitions from memory access patterns.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module` | positional | yes | Module name |
| `ClassName` | positional | no | Specific class |
| `--include-com` | flag | no | Include COM reconstruction |
| `--validate` | flag | no | Validate against assembly |

**Workflow:**
1. Find DB
2. Discover types (`list_types.py`)
3. Extract hierarchy (`extract_class_hierarchy.py`)
4. Scan struct fields (`scan_struct_fields.py`)
5. Generate header (`generate_header.py`)
6. (Optional) COM reconstruction
7. (Optional) Validate (`validate_layout.py`)

**Skills:** reconstruct-types, decompiled-code-extractor, com-interface-reconstruction. **Agent:** type-reconstructor (for validation).

**Output:** `extracted_code/<module>/reports/reconstructed_types_<module>_<timestamp>.h`

---

### 5.9 Reporting and Operations

#### `/prioritize`

**Purpose:** Cross-module finding prioritization from prior scans and audits.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `--modules` | strings | no | Specific modules |
| `--all` | flag | no | All modules |
| `--top` | int | no | Top N findings |
| `--min-score` | float | no | Minimum composite score |

**Workflow:**
1. Discover modules
2. Load cached results (`scan_*.json`, `audit_*.json`, `hunt_execute_*.json`, `batch_audit_*.json`)
3. Normalize to unified schema (`helpers.finding_schema`)
4. Score and rank (composite = exploitability x reachability x impact)
5. Synthesize priority report

**Reachability weights:** exported=1.0, internally reachable=0.7, deep internal=0.4.

**Skills:** decompiled-code-extractor. Uses helpers: `finding_schema`, `finding_merge`.

---

#### `/pipeline`

**Purpose:** Run batch analysis pipelines from YAML definitions.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| subcommand | positional | yes | `run`, `validate`, or `list-steps` |
| `yaml` | positional | no | YAML pipeline file |
| `--dry-run` | flag | no | Preview without executing |
| `--modules` | string | no | Override modules (comma-separated) |
| `--output` | string | no | Custom output directory |

**Skills:** Agents: triage-coordinator, security-auditor. Uses `helpers/pipeline_cli.py`.

---

#### `/runs`

**Purpose:** Browse prior workspace runs and step summaries.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| subcommand | positional | no | `list` (default), `show`, `latest` |
| `module` | positional | no | Module filter |
| `run_id` | positional | no | Run ID (for `show`) |

**Skills:** None (uses helpers: `workspace`, `workspace_validation`).

---

#### `/cache-manage`

**Purpose:** Manage cached analysis results.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| subcommand | positional | yes | `stats`, `clear`, `refresh`, `purge-runs` |
| `module` | positional | no | Module (for clear/refresh) |
| `--older-than` | int | no | Days threshold (default 7, for purge-runs) |
| `--dry-run` | flag | no | Preview (for purge-runs) |

**Workflow:**
- `stats`: Total size, file count, module breakdown
- `clear`: Remove all or module-specific cache
- `refresh`: Clear + re-run classification, callgraph, topology
- `purge-runs`: Delete stale workspace run directories

---

## 6. Helper Library Overview

The shared Python library (`.agent/helpers/`) provides 35+ modules used by every skill, agent, and command. The golden rule: never reimplement what helpers already provide.

### Module Summary

| Module | Category | Purpose |
|--------|----------|---------|
| `individual_analysis_db` | Database | Open per-module analysis DB, query functions/xrefs/strings |
| `analyzed_files_db` | Database | Tracking DB for module index, cross-module xrefs |
| `db_paths` | Database | Resolve DB paths, tracking DB, Windows long-path support |
| `function_resolver` | Resolution | Resolve functions by name/ID, regex search |
| `function_index` | Resolution | Load JSON index, lookup, filter app-only, detect library code |
| `batch_operations` | Resolution | Batch resolve/extract functions |
| `api_taxonomy` | Classification | Classify Win32/NT APIs by area and security impact (~500 prefixes, 17 categories) |
| `string_taxonomy` | Classification | Categorize strings by security relevance |
| `guard_classifier` | Classification | Classify guard conditions in decompiled code |
| `rpc_procedure_classifier` | Classification | Classify RPC procedures by semantics |
| `callgraph` | Graph | Build directed call graphs, BFS path, reachability, SCCs |
| `cross_module_graph` | Graph | Cross-module call graph with module resolver |
| `module_discovery` | Discovery | Iterate module directories and DBs, normalize names |
| `module_profile` | Discovery | Load pre-computed module fingerprints (noise ratio, tech flags) |
| `com_index` | Interface | COM server index (CLSID, methods, risk tiers, elevation) |
| `winrt_index` | Interface | WinRT server index (classes, methods, trust levels) |
| `rpc_index` | Interface | RPC interface index (UUIDs, procedures) |
| `rpc_stub_parser` | Interface | Parse C# RPC client stubs |
| `import_export_index` | Interface | PE import/export index across modules |
| `def_use_chain` | Taint/Flow | Parse def-use chains, analyze taint, propagate |
| `constraint_collector` | Taint/Flow | Collect path constraints |
| `constraint_solver` | Taint/Flow | Check constraint feasibility |
| `decompiled_parser` | Parsing | Extract function calls, split arguments |
| `struct_scanner` | Parsing | Scan struct access patterns (decompiled + assembly) |
| `mangled_names` | Parsing | Parse C++ class from mangled name |
| `asm_patterns` | Parsing | x64 assembly regex patterns |
| `asm_metrics` | Parsing | Assembly metrics (instruction/call/branch counts) |
| `calling_conventions` | Parsing | x64 param registers, register-to-param mapping |
| `type_constants` | Parsing | IDA-to-C type mapping, type sizes |
| `errors` | Output | `emit_error`, `ScriptError`, `log_warning`, `db_error_handler` |
| `json_output` | Output | `emit_json`, `emit_json_list`, `should_force_json` |
| `progress` | Output | `status_message`, `progress_iter`, `ProgressReporter` |
| `logging_config` | Output | Configure logging levels |
| `cache` | Cache | Filesystem cache (24h TTL, DB mtime validated) |
| `validation` | Validation | Validate workspace data, analysis DBs, function IDs |
| `command_validation` | Validation | Validate command arguments |
| `finding_schema` | Findings | Unified finding schema, normalize scanner outputs |
| `finding_merge` | Findings | Merge, deduplicate, rank findings |
| `workspace` | Workspace | Run directory I/O, manifest management |
| `workspace_bootstrap` | Workspace | Step setup and completion |
| `workspace_validation` | Workspace | Validate workspace runs |
| `pipeline_schema` | Pipeline | Load/validate YAML pipelines, step registry |
| `pipeline_executor` | Pipeline | Execute pipelines, dispatch skill steps |
| `pipeline_cli` | Pipeline | CLI: run, validate, list-steps |
| `cleanup_workspace` | Pipeline | Clean old run directories |
| `config` | Infrastructure | Load configuration, env overrides via `DEEPEXTRACT_*` |
| `script_runner` | Infrastructure | Find/run skill and agent scripts |
| `session_utils` | Infrastructure | Resolve session ID, scratchpad paths |
| `agent_common` | Infrastructure | Agent base class, orchestrator |
| `unified_search` | Infrastructure | Multi-dimension search CLI |

### Anti-Patterns

| Don't Do This | Use This Instead |
|---------------|-----------------|
| Raw `sqlite3.connect()` | `open_individual_analysis_db(db_path)` |
| `SELECT * FROM functions WHERE ...` | `resolve_function(db, name_or_id)` |
| Manual path joining for DBs | `resolve_db_path_auto(workspace, module)` |
| `print(json.dumps(...))` for output | `emit_json(data)` |
| `sys.exit(1)` with print to stderr | `emit_error(msg, code)` |
| Hand-parsing function/class names | `parse_class_from_mangled(name)` |
| Custom API categorization | `classify_api(name)` |
| `print("Processing...")` to stdout | `status_message("Processing...")` |
| Ad-hoc string classification | `categorize_string(s)` |
| Manual cache file management | `get_cached()` / `cache_result()` |

---

## 7. VR Workflow Patterns

Concrete end-to-end workflows composing commands, agents, and skills.

### 7.1 Quick Triage

For first contact with an unknown module:

```
/quickstart                          Auto-detect modules, lightweight triage
    │
    ▼
/triage <module>                     Identity, classification, attack surface
    │
    ▼
/scan <module>                       Memory + logic + taint detection
    │
    ▼
/prioritize --modules <module>       Rank findings by exploitability
```

### 7.2 Deep Audit

For thorough security assessment:

```
/triage <module> --with-security     Triage + quick taint
    │
    ▼
/batch-audit <module> --top 10       Audit top 10 entry points
    │                                (or --privilege-boundary for RPC/COM/WinRT)
    ▼
/prioritize --modules <module>       Cross-function ranking
    │
    ▼
/audit <module> <function>           Deep dive on top findings
```

### 7.3 Hypothesis-Driven Hunt

For targeted vulnerability research:

```
/hunt <module>                       Plan research campaign
    │                                (generates hypotheses + investigation commands)
    ▼
/hunt-execute <module>               Execute the plan
    │                                (tests each hypothesis, scores confidence)
    ▼
/audit <module> <function>           Deep audit confirmed findings
    │
    ▼
[finding-verification]               Verify against assembly ground truth
```

### 7.4 Export Deep-Dive

For tracing a specific export end-to-end:

```
/trace-export <module> <export>      Full call chain with code + diagram
    │
    ▼
/taint <module> <export>             Taint trace from export parameters
    │                                (--cross-module for DLL boundaries)
    ▼
/audit <module> <export>             Security audit
```

### 7.5 Cross-Module Analysis

For understanding module relationships:

```
/imports <module> --diagram           PE-level dependencies
    │
    ▼
/data-flow-cross forward <mod> <fn>  Trace data across DLL boundaries
    │
    ▼
/compare-modules <mod_A> <mod_B>     Compare capabilities, APIs, classification
```

### 7.6 Interface Attack Surface

For COM/RPC/WinRT privilege escalation research:

```
/com surface --system-wide            Map all COM servers by risk
/rpc surface --system-wide            Map all RPC interfaces by risk
/winrt surface --system-wide          Map all WinRT classes by risk
    │
    ▼
/com privesc --top 20                 Find privilege escalation targets
/rpc audit <module>                   Audit RPC security
/winrt privesc --top 20               Find WinRT privesc targets
    │
    ▼
/batch-audit <module>                 Audit discovered handlers
    --privilege-boundary
```

### 7.7 Code Lifting Pipeline

For producing readable C++ from decompiled code:

```
/reconstruct-types <module>           Reconstruct structs/classes
    │
    ▼
/lift-class <module> <ClassName>      Lift all methods with shared context
    │                                 (code-lifter agent, 10-step workflow)
    ▼
[verifier agent]                      Independent verification
    │                                 (fresh context, assembly comparison)
    ▼
/verify-batch <module> <ClassName>    Batch verify all methods
```

---

## 8. Cross-Reference Tables

### Command-to-Skill Mapping

| Command | Skills Used |
|---------|------------|
| `/audit` | decompiled-code-extractor, security-dossier, map-attack-surface, data-flow-tracer, callgraph-tracer, classify-functions, taint-analysis, function-index |
| `/batch-audit` | security-dossier, taint-analysis, exploitability-assessment, classify-functions, map-attack-surface, rpc-interface-analysis, com-interface-analysis, winrt-interface-analysis, function-index, decompiled-code-extractor |
| `/brainstorm` | brainstorming |
| `/cache-manage` | classify-functions, callgraph-tracer, generate-re-report |
| `/callgraph` | decompiled-code-extractor, callgraph-tracer |
| `/com` | com-interface-analysis, decompiled-code-extractor, map-attack-surface |
| `/compare-modules` | decompiled-code-extractor, callgraph-tracer, generate-re-report, classify-functions, import-export-resolver, function-index |
| `/data-flow` | data-flow-tracer, decompiled-code-extractor, function-index |
| `/data-flow-cross` | data-flow-tracer, callgraph-tracer, import-export-resolver, decompiled-code-extractor, function-index |
| `/diff` | decompiled-code-extractor, classify-functions, map-attack-surface |
| `/explain` | function-index, decompiled-code-extractor, classify-functions, deep-research-prompt |
| `/full-report` | decompiled-code-extractor, generate-re-report, classify-functions, map-attack-surface, callgraph-tracer, com-interface-reconstruction, state-machine-extractor, data-flow-tracer, taint-analysis, security-dossier, reconstruct-types, verify-decompiled, function-index |
| `/health` | (helpers only) |
| `/hunt` | adversarial-reasoning, classify-functions, map-attack-surface, security-dossier, taint-analysis |
| `/hunt-execute` | taint-analysis, security-dossier, map-attack-surface, data-flow-tracer, callgraph-tracer, exploitability-assessment |
| `/imports` | import-export-resolver |
| `/lift-class` | decompiled-code-extractor, code-lifting, batch-lift, reconstruct-types |
| `/logic-scan` | logic-vulnerability-detector, decompiled-code-extractor |
| `/memory-scan` | memory-corruption-detector, decompiled-code-extractor |
| `/pipeline` | (agents: triage-coordinator, security-auditor) |
| `/prioritize` | decompiled-code-extractor |
| `/quickstart` | classify-functions, map-attack-surface, callgraph-tracer, decompiled-code-extractor |
| `/reconstruct-types` | reconstruct-types, decompiled-code-extractor, com-interface-reconstruction |
| `/rpc` | rpc-interface-analysis, decompiled-code-extractor, map-attack-surface |
| `/runs` | (helpers only) |
| `/scan` | memory-corruption-detector, logic-vulnerability-detector, taint-analysis, map-attack-surface, exploitability-assessment, decompiled-code-extractor |
| `/search` | (helpers: unified_search) |
| `/state-machines` | state-machine-extractor, decompiled-code-extractor, function-index |
| `/strings` | string-intelligence, decompiled-code-extractor |
| `/taint` | taint-analysis, function-index, decompiled-code-extractor |
| `/trace-export` | decompiled-code-extractor, generate-re-report, callgraph-tracer, classify-functions, security-dossier, data-flow-tracer, taint-analysis, import-export-resolver, function-index |
| `/triage` | decompiled-code-extractor, generate-re-report, classify-functions, callgraph-tracer, map-attack-surface, taint-analysis, function-index |
| `/verify` | verify-decompiled, function-index |
| `/verify-batch` | verify-decompiled, function-index, reconstruct-types, decompiled-code-extractor |
| `/winrt` | winrt-interface-analysis, decompiled-code-extractor, map-attack-surface |
| `/xref` | callgraph-tracer, function-index |

### Agent-to-Skill Mapping

| Agent | Composed Skills |
|-------|----------------|
| **re-analyst** | analyze-ida-decompiled, classify-functions, generate-re-report, decompiled-code-extractor, callgraph-tracer, data-flow-tracer, deep-research-prompt, taint-analysis |
| **triage-coordinator** | classify-functions, map-attack-surface, callgraph-tracer, security-dossier, reconstruct-types, deep-research-prompt, com-interface-reconstruction, state-machine-extractor, decompiled-code-extractor, taint-analysis, import-export-resolver |
| **security-auditor** | decompiled-code-extractor, classify-functions, map-attack-surface, security-dossier, taint-analysis, exploitability-assessment, memory-corruption-detector, logic-vulnerability-detector |
| **code-lifter** | decompiled-code-extractor, code-lifting, batch-lift, reconstruct-types, verify-decompiled, function-index |
| **type-reconstructor** | decompiled-code-extractor, reconstruct-types, com-interface-reconstruction |
| **verifier** | verify-decompiled, decompiled-code-extractor, code-lifting |

### Grind-Loop Commands

| Command | Scratchpad Items |
|---------|-----------------|
| `/full-report` | One per phase (6 phases) |
| `/scan` | One per phase (5-6 phases) |
| `/batch-audit` | One per function |
| `/hunt-execute` | One per hypothesis |
| `/verify-batch` | One per function |
| `/lift-class` | One per method (fallback only) |

### Cacheable Skills

| Skill | Cache Key |
|-------|-----------|
| `deep-research-prompt` | DB path + function + options |
| `verify-decompiled` | DB path + function ID |

All cacheable skills accept `--no-cache` to force recomputation. Cache uses 24h TTL validated against DB file modification time.

---

## 9. Glossary

| Term | Definition |
|------|-----------|
| **Analysis DB** | Per-binary SQLite database containing decompiled code, assembly, xrefs, strings, loops, and metadata. Read-only. |
| **Dossier** | Comprehensive security context report for a function, covering identity, reachability, dangerous operations, complexity, and more. |
| **Entry point** | Any function reachable by an external attacker: exports, COM methods, RPC handlers, WinRT methods, callbacks, etc. |
| **Grind loop** | Automated re-invocation mechanism using scratchpad files. When unchecked items remain at agent stop, the stop hook re-invokes the agent to continue. |
| **Lifting** | Rewriting decompiled code into clean, readable C++ while preserving exact functional equivalence with the original binary. |
| **Manifest** | JSON file in workspace run directories tracking per-step status, summary paths, and error information. |
| **Module** | A single Windows PE binary (DLL/EXE) that has been extracted and analyzed by DeepExtractIDA. |
| **Module profile** | Pre-computed fingerprint (`module_profile.json`) containing function counts, noise ratio, technology flags, canary coverage, and classification distribution. |
| **Run directory** | Workspace directory under `.agent/workspace/` used for filesystem handoff in multi-step workflows. Contains step subdirectories, `manifest.json`, and summaries. |
| **Scratchpad** | Session-scoped markdown file (`.agent/hooks/scratchpads/{session_id}.md`) used by the grind-loop protocol to track multi-item task progress. |
| **Skill** | A self-contained analysis capability with optional Python scripts, a SKILL.md definition, and defined inputs/outputs. |
| **Subagent** | A specialized AI agent running in isolated context that processes context-heavy tasks and returns compact results. |
| **Taint** | Tracking the flow of attacker-controlled data from sources (entry point parameters) through transformations to dangerous sinks (security-sensitive API calls). |
| **Tracking DB** | The `analyzed_files.db` database that indexes all analyzed modules and enables cross-module resolution. |
| **Trust boundary** | The interface between code running at different privilege levels (e.g., medium IL user process to SYSTEM service via RPC). |
| **Workspace pattern** | Convention for filesystem handoff in multi-step workflows: run directories, manifest, step output contracts, and compact summary context. |
