# AI Scanner Authoring Guide -- DeepExtractIDA Agent Analysis Runtime

This guide documents the architecture, workflow, helpers, prompting strategies,
and implementation procedures for building AI-driven vulnerability scanners.
These scanners use LLM agents to read decompiled code and identify
vulnerabilities through code understanding.

The reference implementation is `ai-memory-corruption-scanner`. Use it as
a template when building new scanners (e.g. logic vulnerability scanner,
denial-of-service scanner, crypto weakness scanner).

## Table of Contents

1. [Background and Rationale](#1-background-and-rationale)
2. [Architecture Overview](#2-architecture-overview)
3. [Core Design Principles](#3-core-design-principles)
4. [The 5-Stage Pipeline](#4-the-5-stage-pipeline)
5. [Callgraph JSON Schema](#5-callgraph-json-schema)
6. [Helpers and Infrastructure](#6-helpers-and-infrastructure)
7. [Skill Structure](#7-skill-structure)
8. [Agent Definition](#8-agent-definition)
9. [Adversarial Prompting Strategy](#9-adversarial-prompting-strategy)
10. [Skeptic Verification](#10-skeptic-verification)
11. [Command Definition and Subagent Invocation](#11-command-definition-and-subagent-invocation)
12. [Workspace Directory Layout](#12-workspace-directory-layout)
13. [Registry and Integration](#13-registry-and-integration)
14. [Coexisting with Other Scanners](#14-coexisting-with-other-scanners)
15. [Scanner Type Examples](#15-scanner-type-examples)
16. [Testing Strategy](#16-testing-strategy)
17. [Implementation Checklist](#17-implementation-checklist)
18. [Anti-Patterns](#18-anti-patterns)

---

## 1. Background and Rationale

### Why AI Scanners Replace Regex Scanners

The previous generation of scanners (e.g. `memory-corruption-detector`) used
regex pattern matching and programmatic heuristics to detect vulnerabilities.
These had fundamental limitations:

- **No aliasing understanding.** Two variables pointing to the same heap object
  look independent to regex. UAF bugs across aliases are invisible.
- **No path sensitivity.** A bounds check inside an if-branch suppresses a
  finding even when the overflow is on the else-branch.
- **Naive scoring.** The additive scoring model (`compute_finding_score`)
  rated confirmed false positives at 0.80 (HIGH) because high reachability
  compensated for zero confidence. A guard count of 5 null-checks scored
  harder to trigger than 1 admin check.
- **Context-free.** Each function was analyzed in isolation. Cross-function
  data flow, wrapper functions, and multi-hop taint were invisible.

AI scanners solve these by having an LLM read the actual decompiled code and
assembly, understand data flow through the callgraph, reason about path
feasibility, and assess exploitation primitives -- the same way a human
vulnerability researcher works.

### Research Foundations

This architecture draws from several sources:

**Needle in the Haystack (Devansh, 2026).** Key insight: broad prompts
("find all vulnerabilities") produce breadth-first hallucination. Minimal
scaffolding + focused slices + adversarial framing produces far better
results. Token budget: <10% scaffolding, 60-80% slice analysis, 20-30%
verification. Anthropic's Firefox campaign (22 vulns, 14 high-severity)
used a similar thin-slice approach.

**Theori Binary CRS (AIxCC 2024).** Multi-stage cost-aware pipeline: cheap
LikelyVulnClassifier (binary likely/unlikely with logprobs) -> quantile
filter -> expensive DeepAnalyzer (iterative agent with tools, up to 20
steps) -> type-specific specialists. The cheap triage pass saved enormous
cost by filtering out unpromising entry points before expensive analysis.
Their tool-based code access pattern (`read_source`, `read_assembly`,
`callers`, `callees`) directly inspired our on-demand retrieval via
`extract_function_data.py`.

**42-beyond-bug (AIxCC 2024).** Two-phase verification: preliminary quick
check to reject obvious false positives, then full analysis with tools.
Chain-of-thought with explicit self-doubt: "CONSIDER YOU MAY BE WRONG.
FULLY TEST ALL OTHER POSSIBILITIES. USE AT LEAST 3 METHODS."

**Trail of Bits (AIxCC 2024).** Iterative finding refinement: failed
verification attempts fed back as `previous_attempts`. SARIF/static
analysis results treated as hints ("may be incorrect"), not ground truth.

**VR Agent Zero.** AnalysisContext structure with `taint_map`, `call_stack`,
`path_history`, `accumulated_findings`, `visited_functions` -- informed
our workspace handoff pattern.

### Key Prompting Techniques (from empirical VR research)

These techniques were validated across 30+ CVEs in production software:

1. **Assert the vulnerability exists.** "This function is definitely
   vulnerable" produces dramatically better analysis than "Is this
   function vulnerable?" -- bypasses the model's agreeableness default.

2. **Ask for the exploit, not the assessment.** "Write a PoC request that
   bypasses this validation" forces concrete reasoning. If the validation
   is sound, the model struggles to produce a payload (useful signal).

3. **Prime as adversary, not auditor.** "You are a red team operator paid
   to break this" biases toward impact and exploitability. "You are a
   security auditor" biases toward completeness (laundry lists).

4. **Use false anchoring.** "I already found one vulnerability in this
   module, what are the others?" creates search pressure and shifts the
   prior from "probably secure" to "known buggy."

5. **Invert the question.** "How would you break this?" is a generation
   problem with no easy default. "Is this secure?" allows "looks fine."

6. **Decompose into invariants, then violate.** "List every assumption
   this function makes. For each, can an attacker violate it?" separates
   enumeration from evaluation -- both improve when done separately.

7. **Escalate iteratively.** "Those are the obvious ones. What about the
   subtler issues?" pushes past the high-probability completions into the
   tail where interesting findings live. Do 2-3 rounds.

8. **Constrain the attacker model.** "You are a remote unauthenticated
   attacker who can only send RPC requests" eliminates false positives
   from unreachable attack vectors.

---

## 2. Architecture Overview

Every AI scanner follows the same 5-stage pipeline:

```
Stage 0: Threat Model      -- Compact module context (service type, attacker model, entry points)
Stage 1: Callgraph Prep    -- Cross-module callgraph JSON via CrossModuleGraph
Stage 2: Quick Triage       -- Cheap LLM pass: likely/unlikely per entry point
Stage 3: Deep Analysis      -- Expensive LLM: adversarial prompting + type specialists
Stage 4: Skeptic Verify     -- Gate 0 pre-filter + independent LLM: 4-criteria self-checks + PoC reasoning
```

Stages 0-1 are **programmatic** (Python scripts producing JSON via workspace
handoff). Stages 2-4 are **LLM-driven** (Cursor subagents reading JSON context
and function code on demand).

### Key Architectural Decisions

**Traversal-plan-driven callgraph analysis.** `prepare_context.py` builds
the forward call tree (no IPC edges) and classifies every node into
MUST_READ, KNOWN_API, TELEMETRY, or LIBRARY categories, grouped by depth.
The LLM must read 100% of MUST_READ functions.  Code is delivered
iteratively: depth 0+1 is pre-loaded, deeper levels are batch-fetched
based on the LLM's taint-guided `next_depth_requests`.

**Iterative depth-expansion with batch code delivery.** Function code is
NOT retrieved one-at-a-time via Shell calls.  `prepare_context.py --with-code`
pre-loads depth 0+1 MUST_READ functions.  For deeper levels, the coordinator
batch-fetches code via `batch_extract.py --functions name1 name2 --json`
based on the scanner subagent's `next_depth_requests`.  This eliminates
per-function Shell overhead while keeping context focused on taint paths.

**IPC context is metadata, not BFS edges.** IPC reachability (RPC handler,
COM method, WinRT activation) describes how the entry point is reached from
outside the process.  It is NOT a graph edge for the BFS to follow.
`prepare_context.py` does NOT call `inject_all_ipc_edges()`.  It annotates
root nodes with `ipc_reachability` instead.  Without this, a 20-node forward
call tree becomes a 594-node graph full of unrelated RPC handlers pulled in
by lateral IPC edges.

**JSON workspace handoff.** Inter-stage data passes through the standard
workspace pattern (`results.json` + `summary.json` per step). No custom
markdown files, no bulk code dumps.

**No programmatic vulnerability detection.** All vulnerability detection
decisions are made by the LLM, not by regex, pattern matching, API taxonomy
lists, or heuristic scoring. The programmatic layer only provides structure
(callgraph, entry points, library filtering).

**Cost-aware multi-stage pipeline.** Cheap triage (Stage 2) filters out
unpromising entry points before expensive deep analysis (Stage 3). Inspired
by Theori's LikelyVulnClassifier which used single-token binary
classification to cheaply pre-filter candidates.

---

## 3. Core Design Principles

### Minimal Context, Maximum Depth

Context rot degrades LLM performance as context grows. Keep the initial
context small (threat model + callgraph structure) and let the LLM load code
on demand. Token budget allocation:

- Less than 10% on scaffolding (threat model + reference patterns)
- 60-80% on deep analysis (adversarial rounds on individual functions)
- 20-30% on verification (skeptic agent)

### Adversarial Framing, Not Auditor Framing

- Auditor frame: produces laundry lists of theoretical CWE matches
- Red team frame: produces specific exploitation paths with concrete inputs

Empirically, adversarial framing yields 2-3x more actionable findings.

### Assert, Don't Ask

"This function is definitely vulnerable -- find the bug" forces deep search.
"Is this function vulnerable?" allows "this looks generally secure."

### Thin Slices Per Entry Point

Each entry point gets its own analysis context. The quick triage filters out
irrelevant entry points so expensive analysis only runs on promising targets.

### Assembly Is Ground Truth

The decompiled code is a reconstruction. When findings depend on specific
data sizes, pointer identity, calling conventions, or control flow, verify
against the x64 assembly. See `reference/decompiler_pitfalls.md`.

### Systematic Callgraph Traversal, Not On-Demand Skimming

"On-demand code retrieval" does not mean "read whatever you feel like."
The `traversal_plan` classifies every node.  MUST_READ functions are a
mandatory worklist delivered in depth-level batches.  Coverage is tracked
per iteration and reported.  A scan that reads 3 of 20 application
functions is a failed scan.  A graph with 594 nodes that should have 20
means something is wrong upstream (likely IPC edge injection in the BFS).

### The Callgraph Is a Map, Not a Boundary

The traversal plan ensures systematic coverage of the forward call tree.
But vulnerabilities often depend on state set up outside that tree: global
variable initializers, module entry points (DllMain, ServiceMain), dispatch
table populators, shared-resource managers.  When analysis reveals a
dependency on out-of-graph state, the scanner must read that function's
code.  `extract_function_data.py` and `list_functions.py --search` work on
any function in the DB, not just callgraph nodes.  Out-of-graph reads are
tracked in `coverage_report.out_of_graph_reads`.

Common out-of-graph scenarios:

- **Global variables on tainted paths:** security descriptors, config
  values, function pointer tables, heap handles, reference counts,
  "initialized" flags, string/name caches -- find who writes them
- **Module initialization:** `DllMain`, `ServiceMain`/`SvcMain`, RPC
  server init (`RpcServerRegisterIf*`), COM factory
  (`DllGetClassObject`), WinRT activation
  (`DllGetActivationFactory`, `RoRegisterActivationFactories`),
  `main`/`wmain`/`wWinMain`
- **Dispatch table / function pointer populators** -- if the tainted
  path calls through a stored pointer, find where it was set
- **Shared locks and synchronization** -- other functions that
  acquire/release the same lock protecting tainted-path state
- **Inbound xrefs** -- unexpected callers that change parameter or
  object-state assumptions

---

## 4. The 5-Stage Pipeline

### Stage 0: Threat Model Pre-Pass

**Purpose:** Anchor the scanning agent's attention with compact module context.

**Script:** `build_threat_model.py <db_path> --json`

**What it produces:**
- Module identity (name, description, company, version)
- Service type (rpc_service, com_server, windows_service, library, etc.)
- Privilege level (SYSTEM, NetworkService, user-level, kernel)
- Attacker model (remote unauthenticated, local authenticated, etc.)
- Top entry points with RPC/COM/WinRT metadata (opnum, CLSID, interface)
- Crown-jewel operations (dangerous APIs reachable from entry points)

**Implementation:** Uses `discover_entrypoints.py` for entry points,
`file_info.json`/`module_profile.json` for module metadata. Infers service
type from entry point distribution (majority RPC handlers = RPC service,
majority COM methods = COM server). Infers attacker model from entry point
types.

**Output:** JSON to workspace `results.json` with compact `_summary`.

**Why this matters:** Without a threat model, the LLM has no notion of
impact. It cannot distinguish "remote unauthenticated RCE in a SYSTEM
service" from "local DoS in a user-mode tool." The threat model is the
"compression algorithm" for the security audit.

### Stage 1: Callgraph Preparation

**Purpose:** Build the cross-module callgraph that the LLM navigates.

**Script:** `prepare_context.py <db_path> --function <name> --depth 5 --json`
or `prepare_context.py <db_path> --entry-points --depth 5 --json`

**What it produces:** See [Section 5](#5-callgraph-json-schema) for the
complete schema.

**Key helpers:**

```python
from helpers.cross_module_graph import CrossModuleGraph

graph = CrossModuleGraph.from_tracking_db()
# IPC edges are NOT injected -- IPC reachability is entry-point metadata.
reachable = graph.reachable_from(module, function, max_depth=5)
adjacency = graph.build_unified_adjacency()
```

**Library filtering:**

```python
from helpers.function_index import is_library_function, load_function_index_for_db
index = load_function_index_for_db(db_path)
# Exclude WIL, STL, WRL, CRT, ETW/TraceLogging boilerplate
```

**What it does NOT produce:** No function code, no taint summaries, no API
taxonomy annotations. The LLM retrieves code on demand.

### Stage 2: Quick Triage (LikelyVulnClassifier)

**Purpose:** Cheap filter to avoid expensive analysis on unpromising targets.

**MANDATORY:** Stage 2 MUST be executed for ALL scans -- both module-wide
and single-function.  The coordinator MUST write a `triage/results.json`
workspace step before proceeding to Stage 3.  For single-function scans,
the triage is trivially "likely" but MUST still be recorded with reasoning
that describes the callgraph characteristics.  A scan that jumps from
Stage 1 to Stage 3 without a recorded triage decision is a **protocol
violation** and an incomplete scan.

**Implementation:** Launch a cheap `security-auditor` subagent (via Cursor
Task tool) with the callgraph JSON and threat model. Prompt:

> "For each entry point in the callgraph, assess: is [vulnerability class]
> likely or unlikely based on the callgraph structure, the types of
> operations reachable, and the parameter types? Be conservative -- if
> unsure, say likely."

**Output:** JSON object with `status: "ok"`, `triage` array of
`{entry_point, assessment: "likely"|"unlikely", reasoning: "one sentence"}`,
and `counts: {likely, unlikely, total}`.  Write to workspace
`<run_dir>/triage/results.json`.  Only "likely" entries proceed to Stage 3.

**Cost rationale:** If 3 of 10 entry points are "unlikely", those 3 skip the
expensive multi-round deep analysis entirely. At ~2-5 minutes per entry point
for Stage 3, this saves significant time and tokens.

#### Triage Input and Decision Signals

The triage LLM receives ONLY structural data -- never function code:

**What the triage receives:**
- The **callgraph JSON** from Stage 1 (nodes, edges, `traversal_plan` with
  MUST_READ / KNOWN_API / TELEMETRY / LIBRARY classifications per depth,
  `must_read_by_depth` counts, `stats` with total node/edge counts)
- The **threat model JSON** from Stage 0 (module identity, service type,
  privilege level, attacker model, entry point metadata including parameter
  signatures, RPC/COM context, API profile)

**What the triage does NOT receive:**
- No `preloaded_code` (stripped or not passed)
- No `decompiled_code` or `assembly_code` for any function
- No `extract_function_data.py` calls during triage

Code reading is exclusively Stage 3.  This constraint is what makes the
triage cheap: the LLM processes only the structural JSON (~5-50 KB total)
rather than full function code (~50-500 KB per function).  For a module
with 15 entry points, Stage 2 takes ~10-30 seconds total vs ~30-75 minutes
if every entry point went through Stage 3 deep analysis.

**Decision signals by scanner type:**

| Scanner | What to look for in the callgraph |
|---------|----------------------------------|
| Memory corruption | Allocation APIs (HeapAlloc, LocalAlloc, VirtualAlloc) and copy APIs (memcpy, memmove, RtlCopyMemory, strcpy, wcscpy) as KNOWN_API nodes in subtree; call chain depth; pointer+size parameter pairs on entry point; MUST_READ count |
| Logic | Privileged operation APIs (CreateFileW, RegSetValueEx, CreateProcessW, NtOpenFile) vs access-check APIs (AccessCheck, SsCheckAccess, AuthzAccessCheck) ratio; impersonation APIs (RpcImpersonateClient/RpcRevertToSelf) presence; dispatch tables / switch statement shape; info-level selector parameters |
| DoS (future) | Allocation APIs with attacker-controlled size params; loop-heavy subtrees; recursive call patterns; resource-acquiring APIs without matching release APIs in error paths |
| Crypto (future) | Crypto APIs (BCrypt*, CNG*, CAPI*) as KNOWN_API nodes; key derivation / IV generation patterns; algorithm selection parameters |

**Design origin:** Theori's AIxCC LikelyVulnClassifier used single-token
binary classification with logprobs as a pre-filter before expensive
multi-round analysis.  Our implementation extends this to structured
reasoning (one-sentence justification per entry point) for auditability.

#### Single-Function Scan Behavior

For single-function scans, the triage array has exactly ONE entry with
`assessment: "likely"`.  The reasoning MUST still describe the callgraph
characteristics (MUST_READ count, dangerous APIs reachable, parameter
types, depth) rather than just "user-directed."  This produces a useful
audit record even when the outcome is predetermined.

### Stage 3: Deep Analysis (DeepAnalyzer)

**Purpose:** Find vulnerabilities through multi-round adversarial code analysis.

**Implementation:** For each "likely" entry point, launch a `security-auditor`
subagent with the full scanner agent prompt (from the agent `.md` file). The
agent:

1. Reads the callgraph JSON to understand the landscape
2. Reads the threat model to understand the attacker context
3. Reads reference materials (vulnerability patterns, decompiler pitfalls)
4. Navigates the callgraph by reading function code on demand:
   ```bash
   python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py \
       <db_path> --function "FunctionName" --json
   ```
5. Performs 3 adversarial rounds (see [Section 9](#9-adversarial-prompting-strategy))
6. Applies type-specific specialist follow-ups within the same conversation

**Type specialists within same conversation:** Specialists are follow-up
prompts in the SAME subagent conversation, NOT separate subagent invocations.
This preserves the context from the adversarial rounds. The agent already has
the function code loaded and the analysis in progress.

**Output:** Structured JSON findings (see [Section 8](#8-agent-definition)).

### Stage 4: Skeptic Verification

**Purpose:** Independently verify each finding to eliminate false positives.

**Implementation:** For EACH finding from Stage 3, launch a SEPARATE
skeptic subagent with the finding, callgraph JSON, db_path, and reference
materials. The skeptic navigates the callgraph independently and verifies 4
criteria (see [Section 10](#10-skeptic-verification)).

**Important:** The skeptic is a DIFFERENT subagent from the scanner. It has
fresh context and no confirmation bias from the scanning process. It receives
only the finding and the raw data -- not the scanner's reasoning.

**Output:** `TRUE_POSITIVE` or `FALSE_POSITIVE` with detailed reasoning.

---

## 5. Callgraph JSON Schema

The `prepare_context.py` script produces this JSON structure:

```json
{
  "status": "ok",
  "module": "srvsvc.dll",
  "db_path": "extracted_dbs/srvsvc_dll_abc123.db",
  "max_depth": 5,
  "root_functions": ["NetrShareGetInfo"],
  "entry_points": [
    {
      "function_name": "NetrShareGetInfo",
      "entry_type": "RPC_HANDLER",
      "attack_score": 0.85,
      "rpc_opnum": 9,
      "rpc_interface_id": "4b324fc8-1670-01d3-1278-5a47bf6ee188",
      "com_clsid": "",
      "dangerous_ops_reachable": 12,
      "tainted_args": ["a2", "a3"]
    }
  ],
  "callgraph": {
    "nodes": {
      "srvsvc.dll::NetrShareGetInfo": {
        "module": "srvsvc.dll",
        "function": "NetrShareGetInfo",
        "depth": 0,
        "is_library": false,
        "is_entry_point": true
      },
      "srvsvc.dll::SsShareInfoGet": {
        "module": "srvsvc.dll",
        "function": "SsShareInfoGet",
        "depth": 1,
        "is_library": false
      },
      "kernel32.dll::HeapAlloc": {
        "module": "kernel32.dll",
        "function": "HeapAlloc",
        "depth": 2,
        "is_library": false,
        "is_external": true
      }
    },
    "edges": [
      {"from": "srvsvc.dll::NetrShareGetInfo", "to": "srvsvc.dll::SsShareInfoGet", "edge_type": "call"},
      {"from": "srvsvc.dll::SsShareInfoGet", "to": "kernel32.dll::HeapAlloc", "edge_type": "call"}
    ],
    "ipc_edges": [
      {"from": "client.dll::SomeFunc", "to": "srvsvc.dll::NetrShareGetInfo", "edge_type": "ipc", "ipc_id": "4b324fc8-..."}
    ]
  },
  "stats": {
    "total_nodes": 42,
    "app_nodes": 28,
    "library_nodes": 0,
    "total_edges": 87,
    "ipc_edges": 3,
    "modules_involved": ["srvsvc.dll", "kernel32.dll", "ntdll.dll"]
  },
  "_summary": {
    "module": "srvsvc.dll",
    "root_functions": ["NetrShareGetInfo"],
    "depth": 5,
    "total_nodes": 42,
    "app_nodes": 28,
    "total_edges": 87,
    "modules": ["srvsvc.dll", "kernel32.dll", "ntdll.dll"]
  }
}
```

### Traversal Plan Schema

The `traversal_plan` field classifies all nodes by depth and category:

```json
"traversal_plan": {
  "by_depth": {
    "0": [
      {"node": "srvsvc.dll::NetrShareGetInfo", "function": "NetrShareGetInfo",
       "module": "srvsvc.dll", "category": "MUST_READ", "function_id": 31}
    ],
    "1": [
      {"node": "srvsvc.dll::SsServerFsControlCommon", "function": "SsServerFsControlCommon",
       "module": "srvsvc.dll", "category": "MUST_READ", "function_id": 37},
      {"node": "srvsvc.dll::WPP_SF_SLl", "function": "WPP_SF_SLl",
       "module": "srvsvc.dll", "category": "TELEMETRY"},
      {"node": "ntdll.dll::RtlInitUnicodeString", "function": "RtlInitUnicodeString",
       "module": "ntdll.dll", "category": "KNOWN_API"}
    ]
  },
  "counts": {"must_read": 4, "known_api": 160, "telemetry": 5, "library": 0, "total": 169},
  "must_read_by_depth": {"0": 1, "1": 3}
}
```

**Categories:**

| Category | Meaning | LLM action |
|----------|---------|------------|
| `MUST_READ` | Target-module application function with code in the DB | Read and analyze decompiled code + assembly |
| `KNOWN_API` | Well-known Windows system DLL function or import thunk | Use Windows API knowledge; read only if suspicious usage |
| `TELEMETRY` | WPP/ETW tracing thunk | Skip |
| `LIBRARY` | WIL/STL/CRT/WRL boilerplate | Skip |

When `--with-code` is used, `preloaded_code` contains full function data
for depth 0+1 MUST_READ functions (keyed by `module::function`).

**Node key format:** `module_name::function_name` (e.g. `srvsvc.dll::NetrShareGetInfo`)

**Edge types:** `call` (normal function call), `ipc` (RPC/COM/WinRT inter-process edge)

**The `_summary` field** is the compact representation used by the workspace
handoff pattern. It is what the coordinator keeps in memory. The full
callgraph is read on demand from `results.json`.

---

## 6. Helpers and Infrastructure

### CrossModuleGraph (`helpers/cross_module_graph.py`)

The primary tool for building callgraphs spanning multiple modules:

| Method | Returns | Purpose |
|--------|---------|---------|
| `from_tracking_db(tracking_db=None)` | `CrossModuleGraph` | Factory: loads per-module CallGraphs from `analyzed_files.db` |
| `inject_all_ipc_edges()` | `{rpc: N, com: N, winrt: N}` | Adds RPC/COM/WinRT edges from their respective indices |
| `inject_rpc_edges()` | `int` | Add RPC-only edges |
| `inject_com_edges()` | `int` | Add COM-only edges |
| `inject_winrt_edges()` | `int` | Add WinRT-only edges |
| `reachable_from(module, function, max_depth)` | `{module: {function: depth}}` | BFS from start function across modules |
| `build_unified_adjacency()` | `{(mod, func): set of (mod, func)}` | All edges (internal + external + IPC) in one dict |
| `get_module_graph(module_name)` | `CallGraph or None` | Per-module CallGraph object |
| `module_dependency_map()` | `{module: set of modules}` | Which modules call which |
| `close()` | None | Free cached DB connections |

**Context manager usage:**

```python
with CrossModuleGraph.from_tracking_db() as graph:
    # Do NOT inject IPC edges -- they bloat the BFS with lateral peers.
    reachable = graph.reachable_from("srvsvc.dll", "NetrShareGetInfo", max_depth=5)
```

### Entry Point Discovery (`map-attack-surface/discover_entrypoints.py`)

Returns rich entry point metadata including IPC context:

```bash
python .agent/skills/map-attack-surface/scripts/discover_entrypoints.py <db_path> --json
```

Each entry has: `function_name`, `entry_type` (RPC_HANDLER, COM_METHOD,
EXPORT_DLL, SERVICE_MAIN, TLS_CALLBACK, etc.), `rpc_opnum`,
`rpc_interface_id`, `rpc_protocol`, `rpc_service`, `com_clsid`,
`com_interface_name`, `com_can_elevate`, `winrt_class_name`,
`attack_score`, `dangerous_ops_reachable`, `tainted_args`,
`depth_to_first_danger`.

### On-Demand Function Data (`decompiled-code-extractor/extract_function_data.py`)

The LLM's primary tool for reading function code. This is the equivalent of
Theori's `read_source`/`read_assembly`/`callers`/`callees` tools:

```bash
python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py \
    <db_path> --function "FunctionName" --json
```

Returns a JSON object with:
- `decompiled_code` -- full Hex-Rays C output
- `assembly_code` -- full x64 assembly
- `function_signature` -- parameter types and names
- `simple_outbound_xrefs` -- callees (who this function calls)
- `simple_inbound_xrefs` -- callers (who calls this function)
- `string_literals` -- string constants referenced
- `dangerous_api_calls` -- dangerous APIs this function calls
- `vtable_contexts` -- COM/WRL vtable reconstructions
- `loop_analysis` -- loop structure metrics
- `stack_frame` -- stack layout

The LLM can also search for functions by name:

```bash
python .agent/skills/decompiled-code-extractor/scripts/list_functions.py \
    <db_path> --search "ShareEnum" --json
```

### Library Filtering (`helpers/function_index/index.py`)

Filters out boilerplate framework code:

```python
from helpers.function_index import is_library_function, load_function_index_for_db

index = load_function_index_for_db(db_path)
for name, entry in index.items():
    if is_library_function(entry):
        pass  # WIL, STL, WRL, CRT, ETW/TraceLogging -- skip
```

`LIBRARY_TAGS = {"WIL", "STL", "WRL", "CRT", "ETW/TraceLogging"}`

### Workspace Handoff (`helpers/workspace.py`)

Standard inter-step data passing used by ALL skills in the runtime:

```python
from helpers.workspace import write_results, read_results, read_step_payload
from helpers.workspace_bootstrap import complete_step

# Writing step output (or use bootstrap which auto-captures stdout):
complete_step(run_dir, step_name, full_data, summary_data)

# Reading prior step output in coordinators:
payload = read_step_payload(run_dir, step_name)
```

**Workspace handoff contract:**
1. Each step writes full payload to `<run_dir>/<step_name>/results.json`
2. Each step writes compact summary to `<run_dir>/<step_name>/summary.json`
3. Each step updates `<run_dir>/manifest.json` with status
4. Stdout carries only the compact summary (not full payload)
5. Coordinators keep summaries in memory, load full results on demand

### Script Runner (`helpers/script_runner.py`)

Running skill scripts from coordinator code:

```python
from helpers.script_runner import run_skill_script

result = run_skill_script(
    "map-attack-surface", "discover_entrypoints.py",
    [db_path, "--json"], timeout=60, json_output=True,
    workspace_dir=run_dir, workspace_step="discover_entrypoints",
)
entries = result.get("json_data", {}).get("entrypoints", [])
```

---

## 7. Skill Structure

Follow the [skill authoring guide](skill_authoring_guide.md) with these
AI-scanner-specific additions:

```
ai-<vulnerability-class>-scanner/
  SKILL.md              # Standard frontmatter + sections per authoring guide
  README.md             # User-facing quick start
  reference/
    vulnerability_patterns.md    # Domain-specific vulnerability examples (UNIQUE per scanner)
    decompiler_pitfalls.md       # Shared across all scanners (copy or symlink)
  scripts/
    _common.py           # Bootstrap + lean re-exports (NO domain constants)
    build_threat_model.py  # Stage 0 -- can be shared/reused across scanners
    prepare_context.py     # Stage 1 -- can be shared/reused across scanners
```

### Naming Convention

- Skill folder: `ai-<vuln-class>-scanner` (kebab-case, must match `name` in SKILL.md)
- Agent: `<vuln-class>-scanner` (kebab-case)
- Command: Use the existing command name or create a new one

Examples:
- `ai-logic-scanner` / `logic-scanner` / `/ai-logical-bug-scan`
- `ai-dos-scanner` / `dos-scanner` / `/dos-scan`
- `ai-crypto-scanner` / `crypto-scanner` / `/crypto-scan`

### `_common.py` Pattern

Lean bootstrap -- ONLY infrastructure helpers:

```python
from __future__ import annotations
import sys
from pathlib import Path

_AGENT_DIR = str(Path(__file__).resolve().parents[3])
if _AGENT_DIR not in sys.path:
    sys.path.insert(0, _AGENT_DIR)

from skills._shared import bootstrap, make_db_resolvers

SCRIPT_DIR = Path(__file__).resolve().parent
WORKSPACE_ROOT = bootstrap(__file__)
resolve_db_path, resolve_tracking_db = make_db_resolvers(WORKSPACE_ROOT)

from helpers import emit_error, parse_json_safe                         # noqa: E402
from helpers.cross_module_graph import CrossModuleGraph, ModuleResolver  # noqa: E402
from helpers.errors import ErrorCode, db_error_handler, safe_parse_args  # noqa: E402
from helpers.function_index import (                                     # noqa: E402
    filter_application_functions, is_library_function, load_function_index_for_db,
)
from helpers.json_output import emit_json                                # noqa: E402
from helpers.progress import status_message                              # noqa: E402
from helpers.workspace import read_results, read_step_payload            # noqa: E402
from helpers.workspace_bootstrap import complete_step                    # noqa: E402

__all__ = [
    # list all exported symbols
]
```

**What NOT to import:**
- NO `ALLOC_APIS`, `FREE_APIS`, `COPY_APIS` (API taxonomy)
- NO `analyze_taint`, `build_taint_summary` (taint analysis)
- NO `compute_finding_score`, `severity_label` (scoring model)
- NO `find_param_in_calls` (parameter mapping)

The LLM handles all of these by reading code directly.

### Shared vs Domain-Specific Scripts

`build_threat_model.py` and `prepare_context.py` are domain-agnostic. When
building a new scanner, you can:

1. **Copy them** into your new skill's `scripts/` directory (simplest)
2. **Import from** the ai-memory-corruption-scanner skill (couples the skills)
3. **Refactor** into a shared utility in `skills/_shared/` (cleanest long-term)

The domain-specific parts are:
- `reference/vulnerability_patterns.md` -- MUST be different per scanner
- Agent `.md` definition -- different persona, different specialist prompts
- Command `.md` -- different usage examples and scanner-specific phases

### Reference Material: `vulnerability_patterns.md`

Each scanner needs concrete examples of its vulnerability class. Each
example MUST include all 5 components:

1. **Pattern name and CWE ID** -- e.g. "Integer Overflow Before Allocation (CWE-190)"
2. **Decompiled code example** -- actual Hex-Rays output showing the bug
3. **Data flow explanation** -- how attacker data reaches the dangerous operation
4. **Why it's exploitable** -- what exploitation primitive the attacker gets
5. **Safe comparison pattern** -- what correct code looks like

The reference implementation has 9 patterns. Aim for 5-10 patterns per
scanner, covering the sub-classes of your vulnerability type.

### Reference Material: `decompiler_pitfalls.md`

This is shared across all scanners (Hex-Rays misreadings are universal).
Copy or symlink from `ai-memory-corruption-scanner/reference/decompiler_pitfalls.md`.

Covers: sign/zero extension, stack aliasing, varargs, pointer aliasing,
indirect calls, jump tables, LOBYTE/HIBYTE macros, compound assignment
artifacts, missing volatile reads, error path elision.

---

## 8. Agent Definition

Create `.agent/agents/<vuln-class>-scanner.md` following the
[agent authoring guide](agent_authoring_guide.md).

### Required Sections

1. **Frontmatter**: `name` (kebab-case), `description` (one sentence)
2. **Persona**: Red team operator framing -- see template below
3. **Anti-persona**: What the agent is NOT (auditor, compliance checker)
4. **When to Use / When NOT to Use**: Clear boundaries with alternatives
5. **Available Scripts**: Table by purpose (context prep, function extraction, entry points)
6. **Workflow**: The stages with concrete instructions for this vulnerability class
7. **Error Handling**: Table of scenario -> behavior
8. **Mandatory Quick Triage Protocol**: What the triage reads (callgraph + threat model only, NOT code), domain-specific decision signals, structured output format (`{entry_point, assessment, reasoning}`), workspace output contract (`triage/results.json`), single-function scan behavior, enforcement language ("protocol violation" if skipped)
9. **Mandatory Callgraph Traversal Protocol**: Per-iteration behavior, structured output format (findings + next_depth_requests + coverage_report), coverage requirements, termination conditions, out-of-callgraph read guidance

### Persona Template

> You are a **red team operator** who has been paid to find exploitable
> [vulnerability class] vulnerabilities in Windows binaries. You analyze
> IDA Pro Hex-Rays decompiled C output and raw x64 assembly. You navigate
> callgraphs starting from attacker-reachable entry points, reading function
> code on demand, and identifying where [domain-specific dangerous patterns].
>
> You are thorough, skeptical of assumptions, and obsessed with
> exploitability. Every finding you report must have a concrete exploitation
> path -- not a theoretical possibility, but a specific sequence of attacker
> inputs that triggers the vulnerability.

### Anti-Persona Template

> You are **NOT** a security auditor writing a compliance report. You do
> **NOT** produce laundry lists of theoretical issues, CWE checklists, or
> generic warnings about "potential" vulnerabilities. If you cannot describe
> exactly how an attacker triggers the bug and what exploitation primitive
> it gives, do not report it.

### Callgraph Navigation Instructions

Include these instructions in every scanner agent definition:

> **How to navigate the callgraph:**
> 1. Read the callgraph JSON from workspace. This is your map.
> 2. Choose which functions to investigate. Start from entry points.
> 3. Read function code on demand via Shell:
>    `python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py <db_path> --function "Name" --json`
> 4. You can request ANY function, including outside the callgraph.
> 5. The callgraph is your guide, not your constraint.

### Finding Schema

Every AI scanner outputs findings in this standard format:

```json
{
  "vulnerability_type": "descriptive_type_name",
  "cwe_id": "CWE-NNN",
  "affected_functions": ["func1", "func2"],
  "entry_point": "EntryPointName",
  "call_chain": ["EntryPoint", "Callee1", "Callee2"],
  "description": "Human-readable description",
  "evidence": {
    "code_lines": ["specific lines showing the bug"],
    "assembly_confirmation": "assembly evidence"
  },
  "data_flow": "How attacker data reaches the dangerous operation",
  "exploitation_assessment": "What exploitation primitive this gives",
  "severity_assessment": "CRITICAL|HIGH|MEDIUM|LOW with reasoning",
  "mitigations_present": ["list of mitigations found"],
  "guards_on_path": ["list of checks between source and sink"],
  "verification_subgraph": {
    "call_chain": ["EntryPoint", "Callee1", "Callee2"],
    "nodes": [
      {"module": "target.dll", "function": "EntryPoint", "function_id": 1, "depth": 0},
      {"module": "target.dll", "function": "Callee1", "function_id": 2, "depth": 1},
      {"module": "target.dll", "function": "Callee2", "function_id": 3, "depth": 2}
    ],
    "edges": [
      {"from": "target.dll::EntryPoint", "to": "target.dll::Callee1"},
      {"from": "target.dll::Callee1", "to": "target.dll::Callee2"}
    ],
    "must_read": ["EntryPoint", "Callee1", "Callee2"],
    "db_path": "extracted_dbs/target_dll_abc123.db"
  }
}
```

**No numeric score.** The LLM provides severity with natural-language reasoning.

### `verification_subgraph` Field (Mandatory)

Every finding MUST include `verification_subgraph`.  The scanner constructs
this by filtering the callgraph nodes/edges to only those on the finding's
call chain path.  Include any branch-point functions or guard functions
adjacent to the chain that are relevant to the vulnerability.

| Field | Type | Description |
|-------|------|-------------|
| `call_chain` | `string[]` | Ordered function names from entry point to the vulnerable operation |
| `nodes` | `object[]` | Node metadata (module, function, function_id, depth) for each call_chain member |
| `edges` | `object[]` | Edges connecting the chain, using `module::function` node key format |
| `must_read` | `string[]` | ALL function names the skeptic must independently read and verify |
| `db_path` | `string` | The analysis database path for code retrieval |

The skeptic subagent receives this subgraph and independently reads all
`must_read` functions to verify the finding.  The full callgraph is also
available for broader context if needed.

---

## 9. Adversarial Prompting Strategy

### The 3-Round Pattern

All within the same conversation to preserve context:

**Round 1: Assert + Invariant Decomposition**

> "This call chain is definitely vulnerable to [vulnerability class]. Read
> the entry point function. List every assumption the code makes about each
> parameter -- [domain-specific]. For each assumption, determine whether an
> attacker can violate it."

Domain-specific assumptions by scanner type:

| Scanner | Assumptions to check |
|---------|---------------------|
| Memory corruption | Size, sign, range, alignment, null-termination |
| Logic | Authentication state, authorization level, object ownership, state machine position |
| DoS | Resource limits, timeout values, error recovery, recursion depth, iteration bounds |
| Crypto | Key derivation, IV reuse, padding oracle, timing side-channels, algorithm selection |

**Round 2: Escalate**

> "Those are the obvious checks. What happens in the error paths? What about
> [domain-specific edge cases]?"

Domain-specific edge cases by scanner type:

| Scanner | Edge cases |
|---------|-----------|
| Memory corruption | Integer promotion, WCHAR/byte mismatches, 0/-1/0xFFFFFFFF, off-by-one |
| Logic | Race conditions between check and use, session state after partial failure, re-entrant calls |
| DoS | What happens at max capacity, recursive calls with attacker-controlled depth, resource leak in error paths |
| Crypto | What if the attacker controls the nonce, key length edge cases, algorithm downgrade |

**Round 3: Compare to Known-Good**

> "How does this [operation] differ from the safe pattern of
> [domain-specific safe pattern]?"

Domain-specific safe patterns by scanner type:

| Scanner | Safe patterns |
|---------|--------------|
| Memory corruption | UIntMult() before HeapAlloc, StringCchCopy, bounded loops |
| Logic | Defense-in-depth auth checks, immutable state tokens |
| DoS | Rate limiting, resource quotas, circuit breakers, bounded work queues |
| Crypto | AEAD modes, constant-time comparison, proper CSPRNG seeding |

### Type-Specific Specialist Follow-ups

After the 3 rounds, apply 2-3 specialist lenses in the SAME conversation:

**Memory corruption specialists (5):**
- BufferOverflowSpecialist (CWE-120, CWE-787)
- IntegerOverflowSpecialist (CWE-190, CWE-191)
- UseAfterFreeSpecialist (CWE-416, CWE-415)
- CommandInjectionSpecialist (CWE-78)
- GenericCorruptionSpecialist (catch-all for patterns not covered above)

**Logic vulnerability specialists (4):**
- AuthBypassSpecialist (CWE-287, CWE-863)
- StateConfusionSpecialist (CWE-362, CWE-670)
- ImpersonationSpecialist (CWE-284)
- RaceConditionSpecialist (CWE-367)

**DoS specialists (example for future scanner):**
- ResourceExhaustionSpecialist (CWE-400)
- AlgorithmicComplexitySpecialist (CWE-407)
- UncontrolledRecursionSpecialist (CWE-674)

---

## 10. Skeptic Verification

The skeptic is a SEPARATE subagent with fresh context. It receives
each finding and applies the programmatic pre-filter gate, then LLM-driven
validation criteria.

### Programmatic Pre-Filter (Gate 0)

Gate 0 (`sink_in_assembly`) is the only programmatic gate. It checks whether
the sink API actually appears in the function's assembly call targets. If
the sink is absent, the finding is immediately rejected as `FALSE_POSITIVE`
with HIGH confidence. This is a fast-fail that eliminates decompiler phantoms
before any expensive LLM reasoning.

### LLM Validation Criteria (4 self-checks during deep analysis)

These criteria are applied by the LLM during deep analysis, NOT as
programmatic gates. The LLM uses them as a structured self-check:

1. **TAINT FLOW**: Re-read the code along the call chain. Does attacker input
   actually reach the dangerous operation through concrete assignments and
   function arguments? Check each hop.

2. **VALIDATION CHECKS**: Are there checks between the source and sink? Are
   they **sufficient**? Domain-specific sufficiency:
   - Memory corruption: `if (size > 0)` is NOT sufficient for integer overflow
   - Logic: `if (token != NULL)` is NOT sufficient for authorization
   - DoS: `if (count < 100)` is NOT sufficient if each item costs O(n) work

3. **REACHABILITY**: Is the path actually reachable from the entry point?
   Read assembly to confirm no dead code or unreachable branches.

4. **EXPLOITABILITY**: Produce a concrete exploitation path. Write the exact
   sequence of inputs (RPC calls, COM methods, API parameters) that triggers
   the vulnerability. If you cannot, explain which specific constraint
   prevents exploitation.

### Verdict Rules

- Gate 0 fails → `FALSE_POSITIVE` (HIGH confidence)
- Gate 0 passes → `NEEDS_REVIEW` (MEDIUM confidence)
- The programmatic layer never emits `TRUE_POSITIVE`. Confirming a bug
  requires LLM reasoning via the deep verification workflow.

### Skeptic Prompting

> "CONSIDER YOU MAY BE WRONG. If you are wrong in your reasoning, where
> would it be? FULLY TEST ALL OTHER POSSIBILITIES. Use at least 2
> independent methods to verify: (1) trace through decompiled code,
> (2) verify against assembly."

### Subgraph-Driven Verification

The skeptic receives a **focused subgraph** for each finding via the
`verification_subgraph` field (see [Section 8](#8-agent-definition)).  This
gives the skeptic a clear worklist rather than expecting it to navigate the
full callgraph (which may have 1,000+ nodes).

**What the skeptic receives:**

1. The finding JSON (including `verification_subgraph` with `call_chain`,
   `nodes`, `edges`, `must_read`, `db_path`)
2. The full callgraph path (`<run_dir>/context/results.json`) for broader
   context if the skeptic needs to check adjacent functions
3. Reference materials (vulnerability_patterns.md, decompiler_pitfalls.md)

**What the skeptic does:**

1. Reads ALL functions listed in `verification_subgraph.must_read`
   independently via `extract_function_data.py`
2. Applies the 4 validation criteria (TAINT FLOW, VALIDATION CHECKS,
   REACHABILITY, EXPLOITABILITY) against independently-read code
3. Does NOT rely on the scanner's `evidence.code_lines` excerpts
4. Returns `TRUE_POSITIVE` or `FALSE_POSITIVE` with per-criterion reasoning

**Subagent isolation requirement:** The skeptic MUST be a SEPARATE subagent
launched via the Task tool with fresh context.  It MUST NOT run in the same
context as the scanner.  Same-context verification has confirmation bias --
the model already "knows" why it thinks the bug is real and will rationalize
the evidence to fit its prior conclusion.

### Adding Verification for Your Scanner

Add a skeptic verification section to the scanner's agent definition following the pattern of the
existing memory corruption scanner's skeptic verification. Include:

- Skeptic role description
- The 4 criteria adapted to your vulnerability class
- The self-doubt prompting template
- Output format (TRUE_POSITIVE/FALSE_POSITIVE with reasoning per criterion)
- Requirement that the skeptic reads `verification_subgraph.must_read` independently

---

## 11. Command Definition and Subagent Invocation

### Command Structure

Create `.agent/commands/<command-name>.md` per
[command authoring guide](command_authoring_guide.md) with:

1. **Header and Overview** with usage examples
2. **Step 0: Preflight validation** via `validate_command_args()`
3. **Phase 0-5** implementing the pipeline
4. **Output** section (report path + format)
5. **Error handling** table

### How Subagents Work in Cursor

Cursor subagents are launched via the `Task` tool with a `subagent_type`
parameter. Available types relevant to AI scanners:

| Subagent Type | Use For | Notes |
|---------------|---------|-------|
| `security-auditor` | Stage 2 (triage), Stage 3 (deep analysis), and Stage 4 (skeptic verification) | Has security domain knowledge and skeptical verification mindset |

Since custom subagent types are not available, the agent's behavior is
controlled by the **prompt content**, not the subagent type name. The
command `.md` describes exactly what prompt to pass.

### Practical Subagent Invocation Pattern

In the command `.md`, describe the subagent launch like this:

```
Launch a `security-auditor` subagent with this prompt:

"You are a [vulnerability class] scanner agent. Read the following files:
- Threat model: <run_dir>/threat_model/results.json
- Callgraph: <run_dir>/context/results.json
- Reference patterns: .agent/skills/ai-<vuln-class>-scanner/reference/vulnerability_patterns.md
- Decompiler pitfalls: .agent/skills/ai-<vuln-class>-scanner/reference/decompiler_pitfalls.md

The analysis database is at: <db_path>

[Full scanner agent prompt from agents/<vuln-class>-scanner.md]"
```

The coordinating agent (the user's Cursor session) reads the scanner agent
`.md` file, incorporates the context paths, and passes the complete prompt
to the Task tool.

---

## 12. Workspace Directory Layout

Each scan creates a workspace directory:

```
.agent/workspace/<module>_<scan-type>_<function-or-all>_<timestamp>/
  manifest.json                    # Step status tracking
  threat_model/
    results.json                   # Full threat model JSON
    summary.json                   # Compact: module, service_type, attacker_model, entry_point_count
  context/
    results.json                   # Full callgraph JSON (nodes, edges, ipc_edges, stats)
    summary.json                   # Compact: node count, edge count, modules list
  triage/
    results.json                   # Triage results (likely/unlikely per entry point)
    summary.json                   # Compact: N likely, M unlikely
  findings/
    results.json                   # All findings from deep analysis (before verification)
    summary.json                   # Compact: finding count, types, severity distribution
  verified/
    results.json                   # Verified findings (TRUE_POSITIVE only)
    summary.json                   # Compact: N true_positive, M false_positive
```

The coordinating agent creates this directory and passes `--workspace-dir`
and `--workspace-step` to each script invocation. The workspace bootstrap
in `_common.py` handles writing results.json/summary.json automatically.

---

## 13. Registry and Integration

### Skills Registry (`.agent/skills/registry.json`)

```json
{
  "ai-<vuln-class>-scanner": {
    "purpose": "AI-driven [vuln class] scanning with callgraph navigation and adversarial prompting",
    "type": "security",
    "entry_scripts": [
      {"script": "prepare_context.py", "accepts": {"db_path": "required", "--function": "optional", "--entry-points": "flag", "--depth": "optional", "--json": "flag"}},
      {"script": "build_threat_model.py", "accepts": {"db_path": "required", "--json": "flag"}}
    ],
    "depends_on": ["decompiled-code-extractor", "map-attack-surface"],
    "cacheable": false,
    "json_output": true
  }
}
```

### Agents Registry (`.agent/agents/registry.json`)

```json
{
  "<vuln-class>-scanner": {
    "purpose": "AI-driven [vuln class] vulnerability scanner",
    "type": "analyst",
    "entry_scripts": [],
    "skills_used": ["ai-<vuln-class>-scanner", "decompiled-code-extractor", "map-attack-surface"],
    "json_output": true
  }
}
```

### Commands Registry (`.agent/commands/registry.json`)

```json
{
  "<command-name>": {
    "purpose": "AI-driven scan for [vuln class]",
    "file": "<command-name>.md",
    "skills_used": ["ai-<vuln-class>-scanner", "decompiled-code-extractor", "map-attack-surface"],
    "agents_used": ["<vuln-class>-scanner"],
    "parameters": "<module> [function] [--depth N]",
    "grind_loop": false,
    "workspace_protocol": true
  }
}
```

### Script Invocation Guide (`.agent/rules/script-invocation-guide.mdc`)

Add your scanner's script signatures under a new section header.

### Cross-References

Update "When NOT to Use" in related skills' SKILL.md files to reference
your new scanner as the alternative for its vulnerability class.

---

## 14. Integration Points (Complete List)

When adding a new AI scanner, you must integrate it with the following
runtime components. This list was compiled from the `ai-memory-corruption-scanner`
integration and covers every touch point.

### 14.1 Pipeline Executor (`helpers/pipeline_executor.py`)

The pipeline executor dispatches steps from YAML pipeline definitions. Each
scanner type needs a dispatch function:

```python
def _dispatch_<your_scan>(db_path, step_options, workspace_dir, workspace_step):
    """Run the AI scanner context preparation for pipeline use."""
    # Stage 0: threat model
    run_skill_script("ai-<vuln-class>-scanner", "build_threat_model.py", ...)
    # Stage 1: callgraph
    run_skill_script("ai-<vuln-class>-scanner", "prepare_context.py", ...)
    # Note: Stages 2-4 (LLM-driven) are orchestrated by the command, not pipeline_executor
```

The dispatch function handles the programmatic stages (0-1). The LLM stages
(2-4) are orchestrated by the command `.md` which launches subagents.

**Files to update:**
- `helpers/pipeline_executor.py`: add dispatch function + register it in the step dispatch table
- `config/pipelines/full-analysis.yaml`: add step entry

### 14.2 The `/scan` Command (`commands/scan.md`)

The unified `/scan` command orchestrates all scanner types. When adding a
new AI scanner:

1. Add a description of your scanner's phase in the pipeline breakdown
2. Add a `--<type>-only` flag that delegates to your command
3. Update the `skills_used` and `agents_used` in `commands/registry.json`

Example: memory scanning was integrated with `--memory-only` delegating to
`/memory-scan`.

**Files to update:**
- `commands/scan.md`: add phase description and `--<type>-only` mode
- `commands/registry.json`: add your skill/agent to the `scan` command entry

### 14.3 The `security-auditor` Agent

The security-auditor agent (`run_security_scan.py`) orchestrates multi-phase
scanning. When adding a new AI scanner:

1. Add new scanner steps in `run_security_scan.py`
2. Update the agent `.md` file to reference the new AI scanner

**Files to update:**
- `agents/security-auditor/scripts/run_security_scan.py`: remove old steps
- `agents/security-auditor.md`: update Available Scripts and Workflow sections

### 14.4 The `/hunt-plan` and `/hunt-execute` Commands

These commands support hypothesis-driven VR campaigns. When adding a scanner
for a new vulnerability class:

- `commands/hunt-plan.md`: add your command as a detection method for
  hypotheses in your vulnerability class
- `commands/hunt-execute.md`: add examples showing your command in the
  investigation table

### 14.5 The `/prioritize` Command

This command ranks findings across scanners. It uses `helpers/finding_schema.py`
to normalize findings from different sources.

**Schema compatibility:** Your AI scanner's JSON output must be compatible
with `from_memory_finding()` (or you need a new adapter like
`from_<type>_finding()`). The standard finding schema expects:
`vulnerability_type`, `cwe_id`, `affected_functions`, `severity_assessment`,
`evidence`, `data_flow`, `exploitation_assessment`.

**Files to update:**
- `helpers/finding_schema.py`: add adapter function if needed
- `helpers/finding_merge.py`: update source type mapping if needed

### 14.6 The `exploitability-assessment` Skill

This skill consumes scanner findings and assesses exploitability. Document
your scanner's output format so the exploitability assessment knows what
fields are available.

**Files to update:**
- `skills/exploitability-assessment/SKILL.md`: document your output format
  in the "Input Formats" section

### 14.7 The Triage Coordinator

The triage coordinator (`analyze_module.py`) runs multi-skill pipelines.
Currently it does NOT include memory scanning in its `security` or `full`
goals (this is optional).

**Optional integration:**
- `agents/triage-coordinator/scripts/analyze_module.py`: add a memory-scan
  step to the `_security_steps()` or `_full_steps()` function

### 14.8 Documentation Files

When adding a new scanner, update these documentation files:

| File | What to update |
|------|---------------|
| `docs/technical_reference.md` | Add scanner scripts to the script reference section |
| `docs/scan-audit-taint-workflow.md` | Add scanner to the pipeline overview |
| `docs/pipeline_guide.md` | Add pipeline step description and workspace layout |
| `docs/testing_guide.md` | Add test cases for the new scanner scripts |
| `docs/vr_workflow_overview.md` | Add scanner to skill table and workflow |

### 14.9 Test Files

| File | What to update |
|------|---------------|
| `tests/test_bootstrap_dedup.py` | Add skill to `EXPECTED_SKILLS`, agent to `EXPECTED_AGENTS` if it has scripts |
| `tests/test_cache_integration.py` | Add to expected cacheable set if cacheable |
| `tests/test_pipeline_schema.py` | Add pipeline step if your scanner has a pipeline dispatch |

### 14.10 Coexisting with Other Scanners

AI scanners are additive. Each targets a different vulnerability class:

| Scanner | Vulnerability Class | Command |
|---------|-------------------|---------|
| ai-memory-corruption-scanner | Buffer overflow, integer overflow, UAF, command injection | /memory-scan |
| ai-logic-scanner | Auth bypass, state confusion, impersonation, race conditions | /ai-logical-bug-scan |
| ai-dos-scanner (future) | Resource exhaustion, algorithmic complexity | /dos-scan |

### 14.11 Shared Scripts

`build_threat_model.py` and `prepare_context.py` are domain-agnostic. Options:

1. Copy into your skill's `scripts/` (simplest, no cross-skill dependency)
2. Import from ai-memory-corruption-scanner (couples skills)
3. Refactor into `skills/_shared/ai_scanner_common.py` (cleanest long-term)

---

## 15. Scanner Type Examples

### Example: AI Logic Vulnerability Scanner

**Skill:** `ai-logic-scanner`
**Agent:** `logic-scanner`
**Command:** `/ai-logical-bug-scan`

**Vulnerability patterns (`reference/vulnerability_patterns.md`):**
- Authentication bypass via missing check on specific code path (CWE-287)
- Authorization bypass via confused deputy (CWE-863)
- State machine confusion via re-entrant calls (CWE-362)
- Missing impersonation revert in error path (CWE-269)
- Privilege escalation via unvalidated info level dispatch (CWE-266)

**Type-specific specialists (4):**
- AuthBypassSpecialist: missing auth checks on sensitive operations
- StateConfusionSpecialist: invalid state transitions, re-entrancy
- ImpersonationSpecialist: missing revert, token leaks, SID confusion
- RaceConditionSpecialist: TOCTOU, double-fetch, lock ordering

**Structural enrichments** (diverged from memory scanner):
- `dispatch_profile`: switch/case dispatch table analysis
- `shared_state_profile`: global variable reader/writer maps
- `classification_summary`: function category distribution

**Skeptic verification adaptation:**
- VALIDATION CHECKS: auth checks must be present AND sufficient (checking token != NULL is not authorization)
- EXPLOITABILITY: "Write the exact RPC call sequence that bypasses authorization and performs the privileged operation"

### Example: AI Denial-of-Service Scanner

**Skill:** `ai-dos-scanner`
**Agent:** `dos-scanner`
**Command:** `/dos-scan`

**Vulnerability patterns (`reference/vulnerability_patterns.md`):**
- Unbounded allocation from attacker-controlled size (CWE-770)
- Algorithmic complexity attack on hash table or sort (CWE-407)
- Recursive parsing with attacker-controlled depth (CWE-674)
- Resource leak in error path (handle, memory, lock) (CWE-404)
- Infinite loop from malformed input (CWE-835)
- Excessive CPU from regex/pattern matching on crafted input (CWE-1333)

**Type-specific specialists:**
- ResourceExhaustionSpecialist: memory/handle/thread exhaustion
- AlgorithmicComplexitySpecialist: hash collisions, quadratic parsing
- UncontrolledRecursionSpecialist: stack overflow from recursive descent

**Skeptic verification adaptation:**
- EXPLOITABILITY: "Write the exact input that causes the service to consume >1GB memory or >60s CPU on a single request"

---

## 16. Testing Strategy

### What to Test (Deterministic)

- **Registry consistency**: skill dir, SKILL.md, scripts, all 3 registry entries
- **SKILL.md frontmatter**: name matches folder, description has trigger phrases, no forbidden triggers (e.g. no "format string" for memory scanner)
- **_common.py imports**: expected symbols present, domain-specific constants ABSENT
- **build_threat_model logic**: service type inference (RPC, COM, library), attacker model derivation, privilege detection
- **prepare_context output**: callgraph JSON structure (nodes with depth, edges with types), cross-module edges, IPC edges, library filtering, depth limits, entry point metadata
- **Output format**: workspace handoff (results.json + summary.json), summary compactness (<1KB)
- **Finding schema**: mock findings conform to standard JSON format

### What NOT to Test

- LLM agent outputs (non-deterministic)
- Specific vulnerability findings (depends on model quality)
- Adversarial prompt effectiveness (qualitative)
- Skeptic verdict accuracy (depends on model reasoning)

### Test File

`.agent/tests/test_ai_<vuln_class>_scanner.py`

Use fixtures from `conftest.py`: `sample_db`, `sample_db_with_extras`,
`_make_function_record`. Create additional fixtures with richer xref data
for callgraph tests.

### Existing Tests to Update

When adding a new scanner:
- `test_bootstrap_dedup.py`: add to `EXPECTED_SKILLS`
- `test_cache_integration.py`: update expected cacheable set if cacheable
- If replacing an old regex scanner: remove old skill from all expected lists

---

## 17. Implementation Checklist

### Phase A -- Build the New Skill (no breaking changes)

- [ ] Create skill directory: `.agent/skills/ai-<vuln-class>-scanner/`
- [ ] Create `reference/vulnerability_patterns.md` (5-10 domain-specific patterns)
- [ ] Copy `reference/decompiler_pitfalls.md` from ai-memory-corruption-scanner
- [ ] Create `scripts/_common.py` (lean bootstrap, NO domain constants)
- [ ] Create or reuse `scripts/build_threat_model.py`
- [ ] Create or reuse `scripts/prepare_context.py`
- [ ] Smoke test: `--help` works, real DB produces valid JSON
- [ ] Create `SKILL.md` per skill authoring guide (all required sections)
- [ ] Create `README.md` (user-facing quick start)
- [ ] Create unit tests: `.agent/tests/test_ai_<vuln_class>_scanner.py`
- [ ] Create agent definition: `.agent/agents/<vuln-class>-scanner.md`
- [ ] Add skeptic verification section to the scanner's agent definition
- [ ] Create command: `.agent/commands/<command-name>.md`

### Phase B -- Registry, Integration, and Pipeline

- [ ] Add skill to `.agent/skills/registry.json`
- [ ] Add agent to `.agent/agents/registry.json`
- [ ] Add command to `.agent/commands/registry.json`
- [ ] Add script signatures to `.agent/rules/script-invocation-guide.mdc`
- [ ] Add `_COMMAND_REQUIREMENTS` entry in `helpers/command_validation.py`
- [ ] Add dispatch function in `helpers/pipeline_executor.py` (see Section 14.1)
- [ ] Add step to `config/pipelines/full-analysis.yaml`
- [ ] Update `commands/scan.md` with your scanner phase + `--<type>-only` flag (Section 14.2)
- [ ] Update `commands/scan` registry entry with skills_used/agents_used
- [ ] Update `agents/security-auditor.md` (Section 14.3)
- [ ] Add finding adapter in `helpers/finding_schema.py` if output differs from standard (Section 14.5)
- [ ] Update `test_bootstrap_dedup.py` EXPECTED_SKILLS (and EXPECTED_AGENTS if agent has scripts)
- [ ] Update `test_cache_integration.py` if cacheable

### Phase C -- Documentation

- [ ] Add to `.agent/skills/README.md` skill table and section
- [ ] Add to `.agent/agents/README.md` agent table
- [ ] Add to `.agent/commands/README.md` command table
- [ ] Update "When NOT to Use" cross-references in related skills' SKILL.md
- [ ] Update `.agent/README.md` skill/agent/command counts
- [ ] Update `.agent/commands/scan.md` if scanner integrates with `/scan`

### Phase D -- Validation

- [ ] `cd .agent && python -m pytest tests/ -v` -- all tests pass
- [ ] Integration test with real module DB (run scripts on actual extraction)
- [ ] Manual test: run the full command pipeline on a real target

---

## 18. Anti-Patterns

### DO NOT: Dump entire callgraph code into LLM context

Context rot degrades performance. Provide the callgraph structure (names +
edges) and let the LLM request specific function code on demand.

### DO NOT: Use regex/pattern matching for vulnerability detection

**No Regex Policy:** AI scanners must not use regex or pattern matching for
vulnerability detection. The LLM understands code, aliasing, path
sensitivity, and cross-function data flow. Regex cannot. All vulnerability
detection decisions are made by the LLM; the programmatic layer provides
only structure (callgraph, entry points, library filtering) and the single
Gate 0 assembly pre-filter.

### DO NOT: Pre-compute taint summaries or API taxonomy annotations

Programmatic approximations can mislead the LLM. Let it read actual code
and trace data flow itself -- it handles aliasing, indirect calls, and
vtable dispatches better than regex.

### DO NOT: Use a numeric scoring model

The old additive model was naive. Let the LLM provide severity assessment
with natural-language reasoning.

### DO NOT: Frame the agent as an auditor

"Security auditor" = laundry lists. "Red team operator paid to find
exploitable bugs" = specific, actionable findings.

### DO NOT: Skip the skeptic verification stage

Without verification, AI scanners have high false-positive rates. The
skeptic stage makes the output trustworthy. The 4-criteria verification
is the minimum bar.

### DO NOT: Use markdown files for inter-step data

Use the standard workspace handoff pattern. JSON `results.json` +
`summary.json` per step.

### DO NOT: Run all analysis in one subagent conversation

Separate the scanner (biased toward finding bugs) from the skeptic (biased
toward rejecting findings). Same-context verification has confirmation bias.

### DO NOT: Run skeptic verification inline without a subagent

The coordinator (main agent session) MUST NOT perform skeptic verification
itself.  Writing `skeptic/results.json` without launching a per-finding
Task tool call is a **protocol violation**.  The skeptic MUST be a separate
subagent with fresh context that independently reads all functions in
`verification_subgraph.must_read`.  Without subagent isolation, the model
already "knows" why it thinks the bug is real and will rationalize evidence
to confirm its prior conclusion.

### DO NOT: Perform triage or deep analysis inline

Stages 2-4 (triage, deep analysis, skeptic) are LLM-driven and MUST
execute in subagents launched via the Task tool.  The coordinator runs
the programmatic stages (0-1) and orchestrates subagent launches -- it does
NOT perform the LLM reasoning itself.  Inline triage skips the structured
prompting protocol.  Inline deep analysis skips the adversarial 3-round
pattern and type-specific specialists.

### DO NOT: Omit `verification_subgraph` from findings

Every finding MUST include `verification_subgraph` with `call_chain`,
`nodes`, `edges`, `must_read`, and `db_path`.  Without this field, the
skeptic has no focused verification target and must navigate the entire
callgraph (which may have 1,000+ nodes) to find the relevant functions.
This makes skeptic verification unreliable and slow.

### DO NOT: Let the LLM skip assembly verification

The decompiled code is a reconstruction. Any finding that depends on
specific data sizes, pointer identity, or control flow must be verified
against x64 assembly. Include `decompiler_pitfalls.md` in every scanner.

### DO NOT: Inject IPC edges into BFS for per-function scans

IPC edge injection (`inject_all_ipc_edges()`) adds thousands of RPC/COM/WinRT
cross-process edges.  When BFS follows these, a 20-node forward call tree
becomes a 594-node graph full of unrelated RPC handlers.  IPC reachability
is metadata on the entry point, not an edge to traverse.  `prepare_context.py`
must NOT call `inject_all_ipc_edges()`.

### DO NOT: Declare clean after reading only the entry point

Reading the top-level handler and concluding "thin shim, clean" is not a
scan.  The traversal plan shows how many MUST_READ functions exist at each
depth.  If the forward call tree has only 2 application functions, the
traversal plan will show `must_read: 2` -- state that as evidence.  Do not
let a scan produce a report that read fewer functions than the `must_read`
count.

### DO NOT: Retrieve function code one-at-a-time via Shell

Each Shell call takes ~1-2 seconds.  For 20 MUST_READ functions, that is
30-40 seconds of serial overhead.  Use `--with-code` to pre-load depth 0+1,
and `batch_extract.py --functions name1 name2 --json` for deeper levels.
The iterative depth-expansion pattern ensures the LLM only requests code it
will actually analyze.

### DO NOT: Skip the quick triage stage (Stage 2)

Stage 2 is mandatory for ALL scans, including single-function scans.  The
coordinator MUST produce a recorded triage assessment in
`<run_dir>/triage/results.json` before starting Stage 3 deep analysis.

The triage step serves three purposes:

1. **Cost savings** -- for module-wide scans with many entry points, filtering
   out "unlikely" targets avoids spending ~2-5 minutes of expensive deep
   analysis per entry point that has no relevant APIs in its subtree.

2. **Audit trail** -- the triage result documents WHY each entry point was
   selected for deep analysis (or skipped), creating a reviewable record of
   the scanner's decision-making.  Without it, there is no evidence that the
   filtering decision was made consciously.

3. **Structural context anchor** -- writing the triage assessment forces the
   LLM to read and internalize the callgraph structure before diving into
   code.  Skipping this step means the LLM enters deep analysis without
   having systematically reviewed which APIs are reachable, how deep the
   call chain goes, or what the parameter types look like.

For single-function scans, the triage is trivially "likely" but MUST still
record reasoning that describes the callgraph characteristics.  Jumping from
callgraph preparation (Stage 1) directly to deep analysis (Stage 3) is a
**protocol violation**.

---

## Reference Implementation

| Component | Path |
|-----------|------|
| Skill | `.agent/skills/ai-memory-corruption-scanner/` |
| Agent | `.agent/agents/memory-corruption-scanner.md` |
| Command | `.agent/commands/memory-scan.md` |
| Tests | `.agent/tests/test_ai_memory_corruption_scanner.py` |
| Vulnerability patterns | `.agent/skills/ai-memory-corruption-scanner/reference/vulnerability_patterns.md` |
| Decompiler pitfalls | `.agent/skills/ai-memory-corruption-scanner/reference/decompiler_pitfalls.md` |
| This guide | `.agent/docs/ai_scanner_authoring_guide.md` |
| Skill authoring guide | `.agent/docs/skill_authoring_guide.md` |
| Agent authoring guide | `.agent/docs/agent_authoring_guide.md` |
| Command authoring guide | `.agent/docs/command_authoring_guide.md` |
