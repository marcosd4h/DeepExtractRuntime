# Hunt-Plan, Hunt-Execute, Data-Flow-Cross, and Cross-Module Analysis

This document describes how `/hunt-plan`, `/hunt-execute`, and `/data-flow-cross` work, their per-module vs cross-module scope, the gap between hunt workflow and cross-module taint tracing, and existing campaign-level orchestration concepts.

---

## 1. `/hunt-plan` and `/hunt-execute` — Commands, Scripts, and Scope

### 1.1 `/hunt-plan` — Hypothesis-Driven VR Planning

| Aspect | Details |
|--------|---------|
| **File** | `.agent/commands/hunt-plan.md` |
| **Registry** | `commands/registry.json` → `hunt-plan` |
| **Skills** | classify-functions, map-attack-surface, security-dossier, taint-analysis |
| **Methodologies** | adversarial-reasoning |
| **Execution model** | **Collaborative dialogue** — does NOT run analysis. Produces an approved research design; all investigation happens after user approval. |

**Modes and usage:**

| First argument | Mode | Description |
|----------------|------|-------------|
| *(module name only)* | `campaign` | Plan a full VR campaign against the module |
| `hypothesis` | `hypothesis` | Formulate and test a specific vulnerability hypothesis |
| `variant` | `variant` | Find variants of a known bug class or attack pattern |
| `validate` | `validate` | Confirm/refute a suspected vulnerability and plan PoC |
| `surface` | `surface` | Map trust boundaries and prioritize attack vectors |

**Examples:**
```
/hunt-plan appinfo.dll
/hunt-plan hypothesis TOCTOU appinfo.dll
/hunt-plan variant junction appinfo.dll
/hunt-plan validate appinfo.dll AiLaunchProcess
/hunt-plan surface appinfo.dll
```

**Output:** Approved research design in chat + CreatePlan. Persists to `.agent/workspace/<module>_hunt_plan_<timestamp>.json` for `/hunt-execute`.

**Per-module scope:** `/hunt-plan` is **single-module**. The plan targets one module; hypotheses and commands reference that module only.

---

### 1.2 `/hunt-execute` — Execute Hunt Plan

| Aspect | Details |
|--------|---------|
| **File** | `.agent/commands/hunt-execute.md` |
| **Registry** | `commands/registry.json` → `hunt-execute` |
| **Skills** | taint-analysis, security-dossier, map-attack-surface, data-flow-tracer, callgraph-tracer, exploitability-assessment |
| **Methodologies** | finding-verification |
| **Execution model** | **Execute-immediately** — runs the full investigation pipeline. Uses grind loop for multi-hypothesis workflows. |

**Usage:**
```
/hunt-execute appinfo.dll
/hunt-execute
/hunt-execute --plan-file .agent/workspace/appinfo_hunt_plan_20260304.json
```

**Plan resolution order:**
1. Explicit `--plan-file` (highest priority)
2. `.agent/workspace/*_hunt_plan_*.json` (filter by module if provided)
3. Conversation history (fallback)

**Per-hypothesis commands (from adversarial-reasoning workspace integration):**

| Hypothesis Type | Commands to Run |
|-----------------|-----------------|
| Missing access check | `/audit <module> <func>` → `/taint <module> <func>` |
| TOCTOU / file race | `/data-flow forward <module> <func>` → `/audit <module> <func>` |
| Integer overflow | `/verify <module> <func>` → `/taint <module> <func>` |
| COM privilege escalation | `/reconstruct-types <module> <class>` → `/audit <module> <export> --diagram` |
| Variant of known CVE | `/search <module> <pattern>` → `/taint <module> <candidate>` |

**Workspace protocol:**
- Creates `.agent/workspace/<module>_hunt_execute_<timestamp>/`
- Stores per-hypothesis results in `<run_dir>/hypothesis_<N>/results.json`
- Uses manifest to track which hypotheses have been investigated

**Per-module scope:** `/hunt-execute` is **single-module**. It runs commands from the hunt plan, all of which target one module. There is no built-in cross-module orchestration.

---

## 2. `/data-flow-cross` — Implementation and Cross-Module Capabilities

### 2.1 Overview

| Aspect | Details |
|--------|---------|
| **File** | `.agent/commands/data-flow-cross.md` |
| **Registry** | `commands/registry.json` → `data-flow-cross` |
| **Skills** | decompiled-code-extractor, data-flow-tracer, callgraph-tracer |
| **Parameters** | `forward|backward <module> <function>` (plus optional `--param N`, `--target <api>`) |
| **Execution model** | **Execute-immediately** — runs and writes cross-module trace results to chat. |

**Usage:**
```
/data-flow-cross forward appinfo.dll AiLaunchProcess --param 1
/data-flow-cross backward cmd.exe BatLoop --target CreateProcessW
```

### 2.2 Implementation

`/data-flow-cross` **orchestrates** multiple skills; it does not have a single dedicated script. The command:

1. **Resolves the starting point** via `find_module_db.py` and function resolution.
2. **Runs cross-module trace** by:
   - **Forward trace:** Uses `data-flow-tracer` (`forward_trace.py`) within the first module. For each external call:
     - Tries **import-export-resolver** (`query_function.py --direction export`) to resolve the implementing module (handles API-set forwarders).
     - Falls back to **callgraph-tracer** (`cross_module_resolve.py`) if import-export fails.
     - If the target module is analyzed, continues the trace in that module's DB.
     - Repeats until `--depth` is reached.
   - **Backward trace:** Uses `data-flow-tracer` (`backward_trace.py`) within the current module. For parameter origins:
     - Tries **import-export-resolver** (`query_function.py --direction import`) to find importing modules.
     - Uses **callgraph-tracer** (`chain_analysis.py`) for caller resolution in those modules.
     - Continues backward trace in each caller's module.
     - Repeats until `--depth` is reached.
3. **Synthesizes** a cross-module report: trace path, module transitions, argument/parameter mapping.

**Key scripts:**
- `data-flow-tracer/scripts/forward_trace.py` — within-module forward parameter flow
- `data-flow-tracer/scripts/backward_trace.py` — within-module argument origin
- `import-export-resolver` (query_function.py) — PE import/export resolution
- `callgraph-tracer/scripts/cross_module_resolve.py` — resolve external functions
- `callgraph-tracer/scripts/chain_analysis.py` — cross-module chain traversal

**Workspace protocol:**
- Creates `.agent/workspace/<module>_data_flow_cross_<timestamp>/`
- Passes `--workspace-dir` and `--workspace-step` to skill invocations
- Keeps only summary output in context; full payloads in `results.json`

**Cross-module capabilities:** Full. Traces data flow across DLL boundaries with parameter/argument mapping at each boundary crossing. Requires tracking DB (`analyzed_files.db`) for cross-module resolution.

---

## 3. Gap Between Hunt Workflow and Cross-Module Taint Tracing

### 3.1 Hunt Workflow Does Not Invoke Cross-Module by Default

- **Hunt plan schema** (`hunt-plan.md`): Hypotheses map to commands like `/taint <module> <func>` and `/audit <module> <func>`. `/audit` now includes cross-module resolution by default; `/data-flow-cross` is not in the default mapping.
- **Adversarial-reasoning workspace integration** (`adversarial-reasoning/SKILL.md`): The table maps hypothesis types to commands but does not mention:
  - `/taint <module> <func> --cross-module`
  - `/data-flow-cross forward|backward <module> <func>`
  - `trace_taint_cross_module.py`
- **Hunt-execute follow-up suggestions** (`hunt-execute.md`): After execution, it suggests `/taint <module> <function> --cross-module` as a follow-up for confirmed findings — but this is **manual**, not part of the automated hypothesis investigation.

### 3.2 Cross-Module Taint Exists but Is Disconnected from Hunt

**Taint-analysis skill** provides:
- `taint_function.py --cross-module --cross-depth N`
- `trace_taint_forward.py --cross-module`
- `trace_taint_cross_module.py` — full orchestrator with trust boundaries, COM vtable resolution, RPC boundary detection, parameter mapping

**`/taint` command** supports:
- `/taint <module> <func> --cross-module`
- `/taint <module> --from-entrypoints` — auto-discover top entry points and taint-trace each across modules

These are **not** automatically invoked by `/hunt-execute`. The hunt plan would need to explicitly include `/taint ... --cross-module` or `/data-flow-cross` in its hypothesis commands.

### 3.3 Data-Flow vs Data-Flow-Cross

- **`/data-flow`** (single-module): `forward|backward|string|globals <module> <function>` — uses `data-flow-tracer` only, no cross-module.
- **`/data-flow-cross`**: Separate command that orchestrates `data-flow-tracer` + `import-export-resolver` + `callgraph-tracer` for cross-DLL tracing.

The adversarial-reasoning workspace integration table lists `/data-flow forward` for TOCTOU/symlink hypotheses, not `/data-flow-cross`. Cross-DLL TOCTOU (e.g., path flows from module A into module B) would require `/data-flow-cross` or manual orchestration.

### 3.4 Summary of Gaps

| Gap | Description |
|-----|-------------|
| **Hunt plan generation** | Adversarial-reasoning does not suggest cross-module commands for hypotheses that span DLL boundaries. |
| **Hunt-execute automation** | No automatic cross-module taint or data-flow-cross for hypotheses involving external callees. |
| **Hypothesis-to-command mapping** | Workspace integration table is single-module; no guidance for "taint crosses into another DLL" or "TOCTOU across modules." |
| **Campaign-level hunt** | No `/hunt-plan cross` or `/hunt-execute` variant that spans multiple modules. |

---

## 4. Existing Cross-Module Orchestration and Campaign Concepts

### 4.1 `/brainstorm` — Strategic Multi-Module Planning

| Aspect | Details |
|--------|---------|
| **Modes** | `campaign` (single-module), `cross-module` (multi-module), `replan`, `design` |
| **Usage** | `/brainstorm cross appinfo.dll consent.exe` — cross-module campaign |
| **Relationship to hunt-plan** | `/brainstorm` is the **strategist**; `/hunt-plan` is the **tactician**. When single-module hypothesis-driven VR is needed, recommend `/hunt-plan`. |

**Cross-module workflow (from brainstorm.md):**
```
Dependency chain (A calls B calls C):
  Per-module /triage -> /imports for dependency graph -> /data-flow-cross for cross-DLL tracking -> /taint with --cross-module
```

**Cross-Module Taint Pipeline (brainstorm.md):**
```
/triage <mod_entry>
/triage <mod_target>
/imports --function <api> --consumers
/data-flow-cross forward <mod_entry> <func>
/taint <mod_target> <handler> --cross-module
/audit <mod_target> <sink_func>
```

### 4.2 `/prioritize` — Cross-Module Finding Ranking

- Loads cached scan/audit/hunt_execute results from multiple modules.
- Normalizes via unified finding schema.
- Ranks by exploitability × reachability × impact.
- Usage: `/prioritize --modules A B` or `/prioritize --all`.

### 4.3 Skills with Cross-Module Support

| Skill | Cross-module capability |
|-------|-------------------------|
| **callgraph-tracer** | `chain_analysis.py`, `cross_module_resolve.py`, `generate_diagram.py --cross-module` |
| **taint-analysis** | `taint_function.py --cross-module`, `trace_taint_cross_module.py` |
| **data-flow-tracer** | Single-module only; `/data-flow-cross` command orchestrates cross-module |
| **deep-research-prompt** | `gather_function_context.py --cross-module`, `generate_research_prompt.py --cross-module` |
| **import-export-resolver** | PE-level import/export resolution for cross-module callee/caller lookup |

### 4.4 Agents with Cross-Module Awareness

| Agent | Cross-module usage |
|-------|--------------------|
| **triage-coordinator** | Cross-module dependency overview when tracking DB exists |
| **security-auditor** | `trace_taint_cross_module.py` for cross-module taint with trust boundaries |
| **re-analyst** | Cross-module resolution via ModuleResolver; `gather_function_context.py --cross-module` |

### 4.5 Helpers and Infrastructure

- **`helpers.cross_module_graph`** — `CrossModuleGraph`, `ModuleResolver` for cross-module call graph resolution.
- **`extracted_dbs/analyzed_files.db`** — Tracking DB for module-to-DB mapping; required for cross-module resolution.
- **`build_index.py`** (callgraph-tracer) — Builds and caches cross-module index.

### 4.6 What Is Missing for Campaign-Level Hunt

- **No `/hunt-plan cross` or `/hunt-execute --modules A B`** — Hunt is single-module only.
- **No hunt plan schema for multi-module** — Hypotheses do not reference multiple modules or cross-boundary flows.
- **No automatic cross-module phase in hunt-execute** — User must manually add `/taint --cross-module` or `/data-flow-cross` as follow-up.
- **Brainstorm recommends the pipeline** — But it is a manual sequence; no single command or agent orchestrates "run hunt across modules with cross-module taint."

---

## 5. Quick Reference

| Command | Scope | Cross-module | Key scripts |
|---------|-------|--------------|-------------|
| `/hunt-plan` | Single module | No | adversarial-reasoning (methodology) |
| `/hunt-execute` | Single module | No (follow-up suggests `--cross-module`) | Runs hunt plan commands |
| `/data-flow` | Single module | No | forward_trace.py, backward_trace.py |
| `/data-flow-cross` | Cross-module | Yes | forward_trace.py, backward_trace.py + import-export + cross_module_resolve |
| `/taint` | Single or cross | Optional `--cross-module` | taint_function.py, trace_taint_cross_module.py |
| `/brainstorm` | Single or cross | Yes (cross-module mode) | brainstorming skill |
| `/prioritize` | Cross-module | Yes | Loads/ranks findings from multiple modules |
