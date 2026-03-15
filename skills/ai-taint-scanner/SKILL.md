---
name: ai-taint-scanner
description: >-
  AI-driven taint analysis scanner that traces attacker-controlled data through
  cross-module callgraphs using LLM agents with taint-specific context enrichment,
  trust boundary analysis, and skeptic verification. Use when the user asks to
  trace taint, find where attacker data reaches dangerous sinks, analyze data
  flow security, or wants AI-driven taint analysis of decompiled Windows binaries.
cacheable: false
depends_on: ["decompiled-code-extractor", "map-attack-surface"]
---

# AI Taint Scanner

## Purpose

Trace **attacker-controlled data from entry points to dangerous sinks** across
module boundaries using LLM-driven analysis.  The scanner builds a cross-module
callgraph from attacker-reachable entry points, classifies every node
(MUST_READ / KNOWN_API / TELEMETRY / LIBRARY), enriches each node with
taint-specific metadata (sink density, parameter types, trust boundaries,
assembly CFG summary), and delivers the enriched context to the AI agent in
depth-level batches.  The agent traces taint forward through each batch,
returns requests for deeper functions, and the coordinator batch-fetches the
next level -- iterating until max depth or taint termination.

This is NOT a pattern scanner.  All taint propagation decisions are made by
the LLM agent using the enriched callgraph context.  A separate skeptic agent
independently verifies each finding against assembly ground truth.

## When to Use

- Trace attacker-controlled parameters from RPC/COM/export entry points to
  dangerous sinks (file writes, memory copies, privilege operations)
- Analyze cross-module data flow security across DLL boundaries
- Find where untrusted input reaches trust boundary crossings
- Identify parameter propagation chains from network-facing handlers to
  privileged operations
- AI-driven taint analysis on decompiled Windows binaries when deeper
  cross-module context is needed

## When NOT to Use

- Memory corruption scanning (buffer overflows, UAF) -- use **ai-memory-corruption-scanner**
- Logic vulnerabilities (auth bypass, state errors) -- use **ai-logic-scanner**
- Code lifting or rewriting -- use **code-lifter**
- General function explanation -- use **re-analyst** or `/explain`

## Data Sources

### SQLite Databases (primary)

Individual analysis DBs in `extracted_dbs/` provide the raw data:

- `functions.decompiled_code` -- Hex-Rays decompiled C (read on demand)
- `functions.assembly_code` -- x64 assembly ground truth (read on demand)
- `functions.simple_outbound_xrefs` -- Callgraph edges
- `functions.function_signature` -- Parameter types and names
- `functions.global_var_accesses` -- Global variable reads/writes
- `functions.loop_analysis` -- Loop structure and complexity
- `file_info.exports` -- Exported functions
- `file_info.imports` -- Imported APIs
- `file_info.entry_point` -- PE entry points

### Finding a Module DB

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py --list
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py srvsvc.dll
```

### Cross-Module Callgraph

Uses `CrossModuleGraph` from `helpers/cross_module_graph.py` for callgraphs
spanning multiple modules.  IPC edges (RPC/COM/WinRT) are NOT injected into
the BFS -- IPC reachability is recorded as metadata on entry-point nodes.
This produces a focused forward call tree instead of a bloated graph of
lateral IPC peers.

### On-Demand Function Data

The LLM agent retrieves function code via:

```bash
python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py <db_path> --function "FunctionName" --json
```

## Utility Scripts

### `build_threat_model.py` -- Taint-Focused Threat Model (Start Here)

Build a compact threat model anchoring the scanner's attention on taint flow.

```bash
python .agent/skills/ai-taint-scanner/scripts/build_threat_model.py <db_path> --json
python .agent/skills/ai-taint-scanner/scripts/build_threat_model.py <db_path> --json \
    --workspace-dir <run_dir> --workspace-step threat_model
```

Output: module identity, trust boundary classification, service type, attacker
model, top entry points with sink density and taint parameter hints,
trust transition opportunities, RPC/COM context.

### `prepare_context.py` -- Taint-Enriched Callgraph Context

Build the cross-module callgraph JSON with taint-specific enrichments for AI
agent navigation.  IPC edges are NOT injected into the BFS -- IPC reachability
is recorded as metadata on entry-point nodes instead.

The output includes a `traversal_plan` that classifies every node as
MUST_READ, KNOWN_API, TELEMETRY, or LIBRARY, grouped by depth level.
Additionally, each MUST_READ node is enriched with `taint_hints` containing:

- `dangerous_api_calls` -- sink classifications for outbound xrefs
- `global_var_accesses` -- global variables read or written
- `loop_analysis` -- loop count and structure
- `parameter_count` and `parameter_types` -- from the function signature
- `outbound_call_arguments` -- argument expressions for each call site

```bash
python .agent/skills/ai-taint-scanner/scripts/prepare_context.py <db_path> \
    --function "NetrShareGetInfo" --depth 3 --with-code --json
python .agent/skills/ai-taint-scanner/scripts/prepare_context.py <db_path> \
    --entry-points --depth 5 --with-code --json \
    --workspace-dir <run_dir> --workspace-step context
```

Output: JSON with callgraph nodes, edges, `traversal_plan` (by-depth
classification), `taint_hints_per_node` (sink density, globals, loops,
parameters, call arguments per MUST_READ function), entry point metadata with
IPC reachability and taint parameter hints, trust boundary classification,
and optionally `preloaded_code` (decompiled code + assembly for depth 0+1
MUST_READ functions).  Deeper levels are batch-fetched by the coordinator
based on the scanner agent's `next_depth_requests`.

## Workflows

### Workflow 1: "Trace taint across a module" (`/taint-scan`)

- [ ] Phase 0: Build threat model (`build_threat_model.py`)
- [ ] Phase 1: Prepare taint-enriched callgraph context (`prepare_context.py --entry-points --with-code`)
- [ ] Phase 2: **(MANDATORY)** Quick triage -- LLM assesses likely/unlikely per
      entry point based on callgraph structure and sink density (no code reading).
      Write result to workspace `triage/` step.  See **Mandatory Quick Triage Protocol**.
- [ ] Phase 3: Iterative depth analysis -- for each **likely** entry point, LLM
      receives depth 0+1 code plus taint hints, traces data flow forward,
      returns `next_depth_requests`; coordinator batch-fetches deeper functions
      and resumes the agent until max depth or taint termination
- [ ] Phase 4: Skeptic verification -- independent LLM verifies each finding
- [ ] Phase 5: Report -- merge verified findings, include coverage report

### Workflow 2: "Trace taint from a specific function"

- [ ] Phase 0: Build threat model
- [ ] Phase 1: Prepare callgraph context (`prepare_context.py --function <name> --with-code`)
- [ ] Phase 2: **(MANDATORY)** Quick triage -- single-function scans produce a
      trivial "likely" assessment with recorded reasoning (user-directed target).
      Write result to workspace `triage/` step.
- [ ] Phase 3: Iterative depth analysis on the single function's callgraph
- [ ] Phase 4: Skeptic verification
- [ ] Phase 5: Report with per-depth taint flow breakdown

## Depth-Expansion Strategy

The scanner uses an iterative depth-expansion pattern for efficient context usage:

1. **Depth 0+1 upfront**: Entry point code and immediate callees are pre-loaded.
   The LLM reads these first to identify which parameters carry attacker data
   and which callees receive tainted arguments.

2. **Taint-guided expansion**: After analyzing depth 0+1, the LLM returns
   `next_depth_requests` -- a list of functions at deeper levels that received
   tainted data and need code reading.  Functions where taint terminates
   (validated, copied to local, consumed by safe API) are NOT requested.

3. **Batch fetch**: The coordinator batch-extracts code for requested functions
   using `batch_extract_function_data` and delivers the next batch.

4. **Iteration**: Steps 2-3 repeat until max depth or the LLM reports all
   taint paths are resolved (terminated at sinks, validated, or dead-ended).

This avoids pre-loading code for the entire callgraph (expensive for deep
trees) while ensuring every tainted path is followed to its conclusion.

## Taint-Specific Enrichments (vs. Memory Corruption Scanner)

| Enrichment | Purpose |
|------------|---------|
| `dangerous_api_calls` per node | Pre-classified sinks so the LLM knows where taint terminates dangerously |
| `global_var_accesses` per node | Global state that may carry taint between functions |
| `loop_analysis` per node | Loops that amplify taint (repeated operations on tainted data) |
| `parameter_count` / `parameter_types` | Helps the LLM track which params are tainted |
| `outbound_call_arguments` | Argument expressions showing how taint propagates to callees |
| `trust_boundary` | Module-level trust classification for boundary crossing detection |
| `ipc_reachability` | RPC/COM/WinRT metadata identifying cross-process entry points |
| `assembly_cfg_summary` | Basic block and branch counts for complexity estimation |

## Mandatory Quick Triage Protocol

Phase 2 (Quick Triage) is **MANDATORY** for every scan -- both module-wide
and single-function.  The coordinator MUST NOT proceed to Phase 3 without
first completing this phase and writing its output to the workspace.

### What the Triage Reads

The triage operates on **callgraph structure and taint hints only** -- it does
NOT read any decompiled code or assembly.  It receives:

1. The **callgraph JSON** from Phase 1 (nodes, edges, traversal plan with
   classifications per depth, plus taint_hints_per_node)
2. The **threat model JSON** from Phase 0 (service type, privilege level,
   attacker model, entry point metadata with sink density)

It does NOT receive `preloaded_code`, `decompiled_code`, or `assembly_code`.
Code reading is exclusively Phase 3.

### Decision Signals (Taint Analysis)

For each entry point, the triage LLM assesses "likely" or "unlikely" based on:

- **Sink density** -- how many dangerous sinks are reachable from this entry
  point, weighted by sink severity?
- **Parameter count** -- entry points with more parameters have more potential
  taint sources
- **Trust boundary crossings** -- does taint cross from a lower-trust to a
  higher-trust module?
- **MUST_READ count** -- more application functions means more custom code
  where taint validation may be missing
- **Global variable writes** -- functions that write to globals can propagate
  taint to other call chains
- **Call chain depth** -- deeper chains mean more data transformation and
  more opportunity for validation gaps

Be conservative: if any doubt, say **likely**.

### Workspace Output Contract

The triage MUST produce a workspace step at `<run_dir>/triage/`:

- `results.json`: JSON object with `status: "ok"` and `triage` array
- `summary.json`: compact summary with likely/unlikely counts

```json
{
  "status": "ok",
  "triage": [
    {
      "entry_point": "NetrShareAdd",
      "assessment": "likely",
      "reasoning": "RPC handler with 12 dangerous sinks reachable (file_write, memory_unsafe), 6 parameters, trust boundary from rpc_server to system_service, 45 MUST_READ callees"
    }
  ],
  "counts": {"likely": 1, "unlikely": 0, "total": 1}
}
```

### Single-Function Scans

For single-function scans, the triage array has exactly ONE entry with
`assessment: "likely"`.  The reasoning should still describe the taint
characteristics (sink density, parameter count, trust boundary, globals)
rather than just saying "user-directed."

### Enforcement

- A scan that skips Phase 2 and proceeds directly to Phase 3 is a
  **protocol violation**.
- The `triage/` step MUST appear in the workspace manifest before any
  Phase 3 workspace steps.
- Only entry points assessed as **likely** proceed to Phase 3.

### Subagent Enforcement (Non-Negotiable)

Phases 2-3 are LLM-driven and MUST execute in subagents launched via the
Task tool. The coordinator (main agent session) MUST NOT perform triage
or taint analysis inline.

- Phase 2: `Task(subagent_type="security-auditor")` for triage
- Phase 3: `Task(subagent_type="taint-scanner")` for deep analysis

Each finding from Phase 3 MUST include `verification_subgraph` (nodes,
edges, must_read, db_path) for downstream consumers (exploitability
assessment, cross-scanner correlation).

## Integration with Other Skills

| Task | Recommended Skill |
|------|-------------------|
| Memory corruption scanning | ai-memory-corruption-scanner |
| Logic vulnerability scanning | ai-logic-scanner |
| Assess exploitability of findings | exploitability-assessment |
| Check function reachability from exports | security-dossier |
| Reconstruct struct layouts | reconstruct-types |
| Map full attack surface | map-attack-surface |
| Trace call chains | callgraph-tracer |

## Performance

| Operation | Typical Time | Notes |
|-----------|-------------|-------|
| Threat model | ~3-8s | Entry point discovery + trust classification + sink density |
| Callgraph prep (depth 3) | ~30-60s | Cross-module with taint enrichments |
| Callgraph prep (depth 5) | ~45-120s | Larger graph, more enrichment per node |
| Quick triage (per entry point) | ~5-10s | Cheap LLM assessment on structure only |
| Deep analysis (per entry point) | ~3-8 min | Multi-round taint tracing with depth expansion |
| Skeptic verification (per finding) | ~1-3 min | Independent code re-reading |

## Additional Resources

- [taint_patterns.md](reference/taint_patterns.md) -- 8-10 concrete taint
  vulnerability patterns with decompiled code examples
- [decompiler_pitfalls.md](reference/decompiler_pitfalls.md) -- Hex-Rays
  misreadings and assembly verification guidance
