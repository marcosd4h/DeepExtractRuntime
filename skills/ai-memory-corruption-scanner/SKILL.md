---
name: ai-memory-corruption-scanner
description: >-
  AI-driven memory corruption vulnerability scanner that navigates cross-module
  callgraphs using LLM agents with adversarial prompting, type-specific
  specialists, and skeptic verification. Use when the user asks to scan for
  memory corruption, buffer overflows, integer overflows, use-after-free, or
  wants AI-driven vulnerability analysis of decompiled Windows binaries.
cacheable: false
depends_on: ["decompiled-code-extractor", "map-attack-surface"]
---

# AI Memory Corruption Scanner

## Purpose

Find **exploitable memory corruption vulnerabilities** in Windows PE binaries
using LLM-driven code analysis instead of regex pattern matching. The scanner
builds a cross-module callgraph from attacker-reachable entry points, classifies
every node (MUST_READ / KNOWN_API / TELEMETRY / LIBRARY), and delivers code to
the AI agent in depth-level batches.  The agent analyzes each batch, returns
taint-guided requests for deeper functions, and the coordinator batch-fetches
the next level -- iterating until max depth or taint termination.

This is NOT a pattern scanner. All vulnerability detection decisions are made
by the LLM agent using adversarial prompting, invariant decomposition, and
type-specific specialist knowledge. A separate skeptic agent independently
verifies each finding.

## When to Use

- Scan a module for memory corruption vulnerabilities (buffer overflows,
  integer overflows, UAF, double-free, type confusion)
- Analyze a specific RPC handler or COM method for memory safety issues
- Deep analysis of a call chain from an entry point to dangerous operations
- AI-driven vulnerability research on decompiled Windows binaries
- When static analysis produces too many false positives or misses subtle bugs

## When NOT to Use

- Logic vulnerabilities (auth bypass, state errors) -- use **ai-logic-scanner**
- Format string scanning -- deprecated bug class on modern Windows
- Code lifting or rewriting -- use **code-lifter**
- General function explanation -- use **re-analyst** or `/explain`

## Data Sources

### SQLite Databases (primary)

Individual analysis DBs in `extracted_dbs/` provide the raw data:

- `functions.decompiled_code` -- Hex-Rays decompiled C (read on demand)
- `functions.assembly_code` -- x64 assembly ground truth (read on demand)
- `functions.simple_outbound_xrefs` -- Callgraph edges
- `functions.function_signature` -- Parameter types and names
- `file_info.exports` -- Exported functions
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

### `build_threat_model.py` -- Module Threat Model (Start Here)

Build a compact threat model anchoring the scanner's attention.

```bash
python .agent/skills/ai-memory-corruption-scanner/scripts/build_threat_model.py <db_path> --json
python .agent/skills/ai-memory-corruption-scanner/scripts/build_threat_model.py <db_path> --json \
    --workspace-dir <run_dir> --workspace-step threat_model
```

Output: module identity, service type, privilege level, attacker model, top
entry points, RPC/COM context, API profile.

### `prepare_context.py` -- Callgraph Context Preparation

Build the cross-module callgraph JSON for AI agent navigation.  IPC edges
(RPC/COM/WinRT) are NOT injected into the BFS -- IPC reachability is
recorded as metadata on entry-point nodes instead.  This produces a focused
forward call tree rather than a bloated graph of lateral IPC peers.

The output includes a `traversal_plan` that classifies every node as
MUST_READ, KNOWN_API, TELEMETRY, or LIBRARY, grouped by depth level.

```bash
python .agent/skills/ai-memory-corruption-scanner/scripts/prepare_context.py <db_path> \
    --function "NetrShareGetInfo" --depth 3 --with-code --json
python .agent/skills/ai-memory-corruption-scanner/scripts/prepare_context.py <db_path> \
    --entry-points --depth 5 --with-code --json \
    --workspace-dir <run_dir> --workspace-step context
```

Output: JSON with callgraph nodes, edges, `traversal_plan` (by-depth
classification), entry point metadata with IPC reachability, and optionally
`preloaded_code` (decompiled code + assembly for depth 0+1 MUST_READ
functions).  Deeper levels are batch-fetched by the coordinator based on
the scanner agent's `next_depth_requests`.

## Workflows

### Workflow 1: "Scan a module for memory corruption" (`/memory-scan`)

- [ ] Phase 0: Build threat model (`build_threat_model.py`)
- [ ] Phase 1: Prepare callgraph context (`prepare_context.py --entry-points --with-code`)
- [ ] Phase 2: **(MANDATORY)** Quick triage -- LLM assesses likely/unlikely per
      entry point based on callgraph structure alone (no code reading).  Write
      result to workspace `triage/` step.  See **Mandatory Quick Triage Protocol**.
- [ ] Phase 3: Iterative depth analysis -- for each **likely** entry point, LLM
      receives depth 0+1 code, analyzes, returns `next_depth_requests`;
      coordinator batch-fetches deeper functions and resumes the agent until
      max depth or no more requests
- [ ] Phase 4: Skeptic verification -- independent LLM verifies each finding
- [ ] Phase 5: Report -- merge verified findings, include coverage report

### Workflow 2: "Analyze a specific function"

- [ ] Phase 0: Build threat model
- [ ] Phase 1: Prepare callgraph context (`prepare_context.py --function <name> --with-code`)
- [ ] Phase 2: **(MANDATORY)** Quick triage -- single-function scans produce a
      trivial "likely" assessment with recorded reasoning (user-directed target).
      Write result to workspace `triage/` step.  See **Mandatory Quick Triage
      Protocol**.
- [ ] Phase 3: Iterative depth analysis on the single function's callgraph
- [ ] Phase 4: Skeptic verification
- [ ] Phase 5: Report with per-depth coverage breakdown

### Subagent Enforcement (Non-Negotiable)

Phases 2-4 are LLM-driven and MUST execute in subagents launched via the
Task tool. The coordinator (main agent session) MUST NOT perform triage,
deep analysis, or skeptic verification inline. Inline analysis creates
confirmation bias between the scanner and skeptic and skips the structured
adversarial prompting protocol.

- Phase 2: `Task(subagent_type="security-auditor")` for triage
- Phase 3: `Task(subagent_type="memory-corruption-scanner")` for deep analysis
- Phase 4: `Task(subagent_type="security-auditor")` per finding for skeptic

Each finding from Phase 3 MUST include `verification_subgraph` (nodes,
edges, must_read, db_path) so the skeptic has a focused verification target.

## Integration with Other Skills

| Task | Recommended Skill |
|------|------------------|
| Assess exploitability of findings | exploitability-assessment |
| Check function reachability from exports | security-dossier |
| Reconstruct struct layouts | reconstruct-types |
| Map full attack surface | map-attack-surface |
| Trace call chains | callgraph-tracer |

## Performance

| Operation | Typical Time | Notes |
|-----------|-------------|-------|
| Threat model | ~3-5s | Entry point discovery + metadata |
| Callgraph prep (depth 3) | ~30-60s | Cross-module with IPC edges |
| Callgraph prep (depth 5) | ~45-90s | Larger graph, more modules |
| Quick triage (per entry point) | ~5-10s | Cheap LLM assessment |
| Deep analysis (per entry point) | ~2-5 min | Multi-round adversarial prompting |
| Skeptic verification (per finding) | ~1-3 min | Independent code re-reading |

## Mandatory Quick Triage Protocol

Phase 2 (Quick Triage) is **MANDATORY** for every scan -- both module-wide
and single-function.  The coordinator MUST NOT proceed to Phase 3 without
first completing this phase and writing its output to the workspace.

### What the Triage Reads

The triage operates on **callgraph structure only** -- it does NOT read any
decompiled code or assembly.  It receives:

1. The **callgraph JSON** from Phase 1 (nodes, edges, traversal plan with
   MUST_READ / KNOWN_API / TELEMETRY / LIBRARY classifications per depth)
2. The **threat model JSON** from Phase 0 (service type, privilege level,
   attacker model, entry point metadata with parameter signatures)

It does NOT receive `preloaded_code`, `decompiled_code`, or `assembly_code`.
Code reading is exclusively Phase 3.  This is what makes the triage cheap.

### Decision Signals (Memory Corruption)

For each entry point, the triage LLM assesses "likely" or "unlikely" based on:

- **Reachable callee count** -- how many functions does this entry point reach?
- **Allocation APIs in subtree** -- do HeapAlloc, LocalAlloc, VirtualAlloc,
  CoTaskMemAlloc appear as KNOWN_API nodes in the forward call tree?
- **Copy APIs in subtree** -- do memcpy, memmove, RtlCopyMemory, strcpy,
  wcscpy, StringCb*, StringCch* appear as KNOWN_API nodes?
- **Call chain depth** -- deeper chains mean more data transformation and
  more opportunity for size/type mismatches
- **Parameter types** -- entry points with pointer + size parameter pairs,
  DWORD counts, or buffer length arguments have higher attack surface
- **MUST_READ count** -- more application functions in the subtree means
  more custom code where bugs can hide

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
      "reasoning": "RPC handler with 67 MUST_READ callees, HeapAlloc/LocalAlloc/memcpy reachable, 6-deep call chain with pointer+size parameters"
    }
  ],
  "counts": {"likely": 1, "unlikely": 0, "total": 1}
}
```

### Single-Function Scans

For single-function scans, the triage array has exactly ONE entry with
`assessment: "likely"`.  The reasoning should still describe the callgraph
characteristics (MUST_READ count, dangerous APIs reachable, parameter types)
rather than just saying "user-directed."  This produces a useful audit
record even when the outcome is predetermined.

### Enforcement

- A scan that skips Phase 2 and proceeds directly to Phase 3 is a
  **protocol violation**.
- The `triage/` step MUST appear in the workspace manifest before any
  Phase 3 workspace steps.
- Only entry points assessed as **likely** proceed to Phase 3.

## Additional Resources

- [vulnerability_patterns.md](reference/vulnerability_patterns.md) -- 10 modern
  Windows memory corruption patterns with code examples
- [decompiler_pitfalls.md](reference/decompiler_pitfalls.md) -- Hex-Rays
  misreadings and assembly verification guidance
