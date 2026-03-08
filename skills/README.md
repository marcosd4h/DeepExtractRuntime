# Analysis Skills

Skills are reusable analysis pipelines that form the core analytical
capabilities of the Agent Analysis Runtime. Each skill lives in
`skills/<name>/` with a `SKILL.md` manifest describing its purpose,
data sources, scripts, and workflows, plus a `scripts/` directory
containing Python entry points. Skills are invoked by agents and slash
commands, and they call shared helpers to query analysis databases and
JSON files produced by DeepExtractIDA.

The machine-readable registry of all skills is in
[`registry.json`](registry.json). It defines entry scripts, accepted
arguments, dependencies, and caching contracts for each skill.

---

## Overview

| Skill | Type | Purpose | Scripts | Cacheable | Dependencies |
|-------|------|---------|---------|-----------|--------------|
| [analyze-ida-decompiled](#analyze-ida-decompiled) | documentation | Navigate, explain, and annotate IDA decompiled code | -- | No | function-index |
| [batch-lift](#batch-lift) | code_generation | Lift related function groups with shared context | 2 | No | decompiled-code-extractor, code-lifting, callgraph-tracer, reconstruct-types |
| [callgraph-tracer](#callgraph-tracer) | analysis | Build call graphs, trace paths, cross-module deps | 6 | Yes | decompiled-code-extractor |
| [classify-functions](#classify-functions) | analysis | Classify every function by purpose | 3 | Yes | decompiled-code-extractor |
| [code-lifting](#code-lifting) | code_generation | Lifting workflow for rewriting decompiled functions | -- | No | decompiled-code-extractor, reconstruct-types, verify-decompiled |
| [com-interface-reconstruction](#com-interface-reconstruction) | reconstruction | Reconstruct COM/WRL interfaces from vtable patterns | 4 | Yes | decompiled-code-extractor |
| [data-flow-tracer](#data-flow-tracer) | analysis | Trace parameter flow, argument origins, global state | 4 | Yes | decompiled-code-extractor |
| [decompiled-code-extractor](#decompiled-code-extractor) | foundation | Extract function data from analysis databases | 3 | No | -- |
| [deep-research-prompt](#deep-research-prompt) | meta | Generate research prompts from multi-skill context | 3 | Yes | classify-functions, callgraph-tracer, data-flow-tracer, generate-re-report, state-machine-extractor, com-interface-reconstruction, reconstruct-types, taint-analysis |
| [function-index](#function-index) | index | Fast function-to-file resolution and library filtering | 3 | No | -- |
| [generate-re-report](#generate-re-report) | reporting | Comprehensive RE reports (identity, security, architecture) | 6 | Yes | decompiled-code-extractor |
| [map-attack-surface](#map-attack-surface) | security | Discover entry points, rank by attack value | 3 | Yes | decompiled-code-extractor, callgraph-tracer, import-export-resolver |
| [reconstruct-types](#reconstruct-types) | reconstruction | Reconstruct structs/classes from memory access patterns | 4 | Yes | decompiled-code-extractor |
| [security-dossier](#security-dossier) | security | Security context dossier (reachability, dangerous ops) | 1 | Yes | decompiled-code-extractor, callgraph-tracer |
| [state-machine-extractor](#state-machine-extractor) | analysis | Extract dispatch tables and state machines | 4 | Yes | decompiled-code-extractor |
| [verify-decompiled](#verify-decompiled) | verification | Verify decompiler accuracy against assembly | 2 | Yes | decompiled-code-extractor |
| [taint-analysis](#taint-analysis) | security | Trace tainted params to dangerous sinks with guard/bypass analysis | 5 | Yes | data-flow-tracer, callgraph-tracer, decompiled-code-extractor, com-interface-reconstruction |
| [brainstorming](#brainstorming) | documentation | Collaborate on VR research strategy and design before implementation | -- | No | -- |
| [deep-context-builder](#deep-context-builder) | documentation | Build deep block-by-block understanding of decompiled functions | -- | No | decompiled-code-extractor, classify-functions, callgraph-tracer, data-flow-tracer, map-attack-surface |
| [adversarial-reasoning](#adversarial-reasoning) | methodology | Hypothesis-driven VR methodology with Windows attack pattern playbooks | -- | No | classify-functions, map-attack-surface, security-dossier, taint-analysis, data-flow-tracer, callgraph-tracer |
| [import-export-resolver](#import-export-resolver) | analysis | Resolve PE import/export relationships across modules | 4 | Yes | decompiled-code-extractor |
| [string-intelligence](#string-intelligence) | analysis | Categorize string literals by security relevance (URLs, registry keys, pipes, certs) | 1 | Yes | decompiled-code-extractor |
| [memory-corruption-detector](#memory-corruption-detector) | security | Detect memory corruption: buffer overflows, integer issues, UAF, format strings | 5 | Yes | decompiled-code-extractor, callgraph-tracer, taint-analysis |
| [exploitability-assessment](#exploitability-assessment) | security | Assess exploitability of taint findings with mitigations and guard analysis | 2 | No | taint-analysis, security-dossier, map-attack-surface, memory-corruption-detector, logic-vulnerability-detector |
| [finding-verification](#finding-verification) | security | Verify findings against assembly ground truth to eliminate false positives | -- | No | taint-analysis, verify-decompiled, data-flow-tracer, security-dossier, exploitability-assessment, import-export-resolver |
| [logic-vulnerability-detector](#logic-vulnerability-detector) | security | Detect logic bugs: auth bypasses, state machine errors, TOCTOU, API misuse | 6 | Yes | decompiled-code-extractor, callgraph-tracer, taint-analysis, state-machine-extractor, security-dossier, map-attack-surface |
| [rpc-interface-analysis](#rpc-interface-analysis) | security | Analyze RPC interfaces: enumerate UUIDs, map attack surface, audit security, trace chains, find clients, build topology, blast-radius, query stubs | 6 | No | decompiled-code-extractor, map-attack-surface, callgraph-tracer |
| [winrt-interface-analysis](#winrt-interface-analysis) | security | Analyze WinRT servers: enumerate classes, map privilege-boundary surface, audit security, classify methods, find EoP | 6 | No | decompiled-code-extractor, map-attack-surface |
| [com-interface-analysis](#com-interface-analysis) | security | Analyze COM servers: enumerate CLSIDs, map privilege-boundary surface, audit security (permissions, elevation, DCOM), classify methods, find EoP/UAC bypass | 6 | No | decompiled-code-extractor, map-attack-surface |

---

## Skill Dependency Graph

```mermaid
flowchart BT
    subgraph foundation [Foundation]
        decompiledCodeExtractor["decompiled-code-extractor"]
        functionIndex["function-index"]
    end

    subgraph analysis [Analysis]
        callgraphTracer["callgraph-tracer"]
        classifyFunctions["classify-functions"]
        dataFlowTracer["data-flow-tracer"]
        importExportResolver["import-export-resolver"]
        stateMachineExtractor["state-machine-extractor"]
        stringIntelligence["string-intelligence"]
    end

    subgraph reconstruction [Reconstruction]
        reconstructTypes["reconstruct-types"]
        comInterfaceReconstruction["com-interface-reconstruction"]
    end

    subgraph security [Security]
        mapAttackSurface["map-attack-surface"]
        securityDossier["security-dossier"]
        taintAnalysis["taint-analysis"]
        adversarialReasoning["adversarial-reasoning"]
        findingVerification["finding-verification"]
        logicVulnDetector["logic-vulnerability-detector"]
        winrtInterfaceAnalysis["winrt-interface-analysis"]
        comInterfaceAnalysis["com-interface-analysis"]
    end

    subgraph reporting [Reporting]
        generateReReport["generate-re-report"]
    end

    subgraph verification [Verification]
        verifyDecompiled["verify-decompiled"]
    end

    subgraph codeGeneration [Code Generation]
        codeLift["code-lifting"]
        batchLift["batch-lift"]
    end

    subgraph meta [Meta]
        deepResearchPrompt["deep-research-prompt"]
    end

    subgraph documentation [Documentation]
        analyzeIdaDecompiled["analyze-ida-decompiled"]
        brainstorming["brainstorming"]
        deepContextBuilder["deep-context-builder"]
    end

    callgraphTracer --> decompiledCodeExtractor
    classifyFunctions --> decompiledCodeExtractor
    dataFlowTracer --> decompiledCodeExtractor
    stateMachineExtractor --> decompiledCodeExtractor
    stringIntelligence --> decompiledCodeExtractor
    importExportResolver --> decompiledCodeExtractor
    reconstructTypes --> decompiledCodeExtractor
    comInterfaceReconstruction --> decompiledCodeExtractor
    generateReReport --> decompiledCodeExtractor
    verifyDecompiled --> decompiledCodeExtractor
    mapAttackSurface --> decompiledCodeExtractor
    mapAttackSurface --> callgraphTracer
    securityDossier --> decompiledCodeExtractor
    securityDossier --> callgraphTracer
    codeLift --> decompiledCodeExtractor
    codeLift --> reconstructTypes
    codeLift --> verifyDecompiled
    batchLift --> decompiledCodeExtractor
    batchLift --> codeLift
    batchLift --> callgraphTracer
    batchLift --> reconstructTypes
    analyzeIdaDecompiled --> functionIndex
    deepContextBuilder --> decompiledCodeExtractor
    deepContextBuilder --> classifyFunctions
    deepContextBuilder --> callgraphTracer
    deepResearchPrompt --> classifyFunctions
    deepResearchPrompt --> callgraphTracer
    deepResearchPrompt --> dataFlowTracer
    deepResearchPrompt --> generateReReport
    deepResearchPrompt --> stateMachineExtractor
    deepResearchPrompt --> comInterfaceReconstruction
    deepResearchPrompt --> reconstructTypes
    taintAnalysis --> dataFlowTracer
    taintAnalysis --> callgraphTracer
    taintAnalysis --> decompiledCodeExtractor
    adversarialReasoning --> classifyFunctions
    adversarialReasoning --> mapAttackSurface
    adversarialReasoning --> securityDossier
    adversarialReasoning --> taintAnalysis
    adversarialReasoning --> callgraphTracer
    adversarialReasoning --> dataFlowTracer
    findingVerification --> taintAnalysis
    findingVerification --> verifyDecompiled
    findingVerification --> dataFlowTracer
    findingVerification --> securityDossier
    deepResearchPrompt --> taintAnalysis
    logicVulnDetector --> decompiledCodeExtractor
    logicVulnDetector --> callgraphTracer
    logicVulnDetector --> taintAnalysis
    logicVulnDetector --> stateMachineExtractor
    logicVulnDetector --> securityDossier
    logicVulnDetector --> mapAttackSurface
    winrtInterfaceAnalysis --> decompiledCodeExtractor
    winrtInterfaceAnalysis --> mapAttackSurface
    comInterfaceAnalysis --> decompiledCodeExtractor
    comInterfaceAnalysis --> mapAttackSurface
```

---

## Skill Details

### Foundation

#### decompiled-code-extractor

The foundational data-extraction skill that nearly every other skill
depends on. Its scripts locate module analysis databases, list and search
functions within them, and extract all raw data for a given function --
decompiled C++, raw x64 assembly, signatures, string literals, xrefs,
vtable contexts, global variable accesses, stack frames, and loop
analysis. The scripts are purely data retrieval and do not perform any
lifting or rewriting.

**Key scripts:** `find_module_db.py` (map module name to DB path),
`list_functions.py` (list/search functions), `extract_function_data.py`
(extract all data for a single function). All three are data extraction
only.

**Typical use:** Starting point for any function-level analysis. Run
`find_module_db.py` first to get the DB path, then use
`extract_function_data.py` to retrieve everything needed for lifting,
verification, or deeper analysis. The actual lifting is performed by the
code-lifter agent following the [code-lifting](#code-lifting) workflow.

---

#### function-index

Provides fast, JSON-based function-to-file resolution without touching
SQLite databases. Every extracted module has a `function_index.json` that
maps each function name to its `.cpp` file and a library tag (`WIL`,
`STL`, `WRL`, `CRT`, `ETW/TraceLogging`, or `null` for application
code). This skill wraps that index with lookup, filtering, and
resolution scripts, and is the recommended first step for locating a
function's source file. It has no dependencies on other skills and is
itself depended on by `analyze-ida-decompiled`.

**Key scripts:** `lookup_function.py` (find functions by exact name,
substring, or regex across all modules), `index_functions.py` (list and
filter module functions, show stats), `resolve_function_file.py`
(resolve function names to absolute `.cpp` file paths).

**Typical use:** Before reading any decompiled code, use
`lookup_function.py` to find which module and file contains the target
function, then read the resolved path directly. Use `--app-only` to
skip library boilerplate and focus on application logic.

---

### Analysis

#### callgraph-tracer

Builds directed call graphs from per-function cross-reference data in
analysis databases and supports a rich set of graph queries: shortest
path, all paths, reachability from entry points, transitive callers,
strongly connected components (recursive clusters), leaf functions, and
root functions. Its headline capability is **cross-module chain
analysis** -- following function calls across DLL boundaries by
resolving external xrefs through the tracking database, retrieving
decompiled code at each hop. It also generates Mermaid and DOT diagrams,
and maps inter-module dependency relationships across all analyzed
binaries.

**Key scripts:** `build_call_graph.py` (single-module graph queries),
`chain_analysis.py` (cross-module xref chain traversal with code
retrieval), `cross_module_resolve.py` (resolve external functions),
`module_dependencies.py` (inter-module dependency mapping),
`analyze_detailed_xrefs.py` (rich xref analysis with vtable and jump
table resolution), `generate_diagram.py` (Mermaid/DOT output).

**Typical use:** Trace what a function calls and how deep the chain goes
with `chain_analysis.py`. Use `--summary` for a compact call tree, then
`--follow` to selectively trace interesting branches across module
boundaries.

---

#### classify-functions

Automatically categorizes every function in a module into purpose
categories (file I/O, registry, network, crypto, security, telemetry,
dispatch, initialization, and more) using multiple signal sources: API
usage signatures, string analysis, naming patterns, assembly metrics,
and loop complexity. Each function receives an interest score (0-10) for
triage prioritization that penalises telemetry and compiler noise while
boosting functions with dangerous APIs, complex loops, and rich string
context. The triage summary gives researchers a high-level overview of
any module in seconds, enabling focus on the most interesting functions
in binaries with 1000+ functions.

**Key scripts:** `triage_summary.py` (quick module overview with
category distribution and top-N interesting functions),
`classify_module.py` (full categorized index with filtering by category
and minimum interest), `classify_function.py` (detailed single-function
classification with all signal evidence).

**Typical use:** Start with `triage_summary.py` to understand what a
module does at a high level, then use `classify_module.py --category
security` to drill into specific categories of interest.

---

#### data-flow-tracer

Traces how specific data moves through extracted binaries. Supports four
tracing modes: **forward parameter trace** (where does parameter N flow
to -- which calls receive it, which globals it is written to),
**backward argument origin** (where does the 3rd argument to
`CreateFileW` come from -- a parameter, another call's return value, a
constant, or a global), **global variable producer/consumer mapping**
(which functions read and write each global), and **string literal usage
chains** (which functions reference a string, with caller context). All
traces use decompiled code parsing with optional assembly register
tracking as ground truth, and support recursive depth for following data
through callee chains.

**Key scripts:** `forward_trace.py` (parameter forward trace),
`backward_trace.py` (argument origin trace), `global_state_map.py`
(global variable reader/writer mapping), `string_trace.py` (string
literal usage tracking).

**Typical use:** Use `forward_trace.py --param 1` to see where a
function's first parameter flows, or `backward_trace.py --target
CreateProcessW --arg 2 --callers` to trace the origin of a sensitive API
argument back through the caller chain.

---

#### import-export-resolver

Resolves PE-level import and export relationships across all analyzed
modules. Unlike callgraph-tracer (which uses code-level xrefs from
disassembly), this skill queries the PE import/export tables stored in
`file_info.imports` and `file_info.exports` -- the authoritative
record of what the Windows loader resolves at load time. Supports
finding which module exports a function, which modules import it,
building module dependency graphs from PE tables, and following
forwarded export chains across DLLs.

**Key scripts:** `query_function.py` (find exporters/importers for a
function name), `build_index.py` (build and cache cross-module index),
`module_deps.py` (PE-level dependency graph with reverse deps),
`resolve_forwarders.py` (follow forwarded export chains).

**Typical use:** Run `query_function.py --function CreateProcessW` to
find which module exports it and which modules import it. Use
`module_deps.py --module appinfo.dll --consumers` to see which other
modules depend on appinfo.dll at the PE level.

---

#### string-intelligence

Categorizes string literals by security relevance instead of treating all
strings as equal. It groups registry paths, URLs, named pipes, certificate
subjects, mutex names, command lines, and other high-signal artifacts so
researchers can focus on strings that reveal trust boundaries, IPC surfaces,
and dangerous operations.

**Key scripts:** `analyze_strings_deep.py` (deep string categorization by
module, function, or category with cache support).

**Typical use:** Run `analyze_strings_deep.py <db_path> --top 100 --json`
to surface the most interesting strings in a module, or scope with
`--function` / `--id` when triaging a specific routine.

---

#### state-machine-extractor

Detects and reconstructs command dispatchers, switch/case dispatch
tables, and state machines from decompiled code. Combines three
detection strategies: decompiled code parsing (switch/case blocks and
if-else chains comparing the same variable against constants), jump
table resolution from outbound xrefs, and state machine reconstruction
from dispatch-inside-loop patterns using loop analysis data. Produces
structured dispatch tables (case value to handler function) and state
transition models. Generates Mermaid and DOT diagrams for visual
exploration.

**Key scripts:** `detect_dispatchers.py` (scan module for all dispatch
functions), `extract_dispatch_table.py` (extract case-to-handler
mapping for a specific function), `extract_state_machine.py`
(reconstruct state machine model with transitions),
`generate_state_diagram.py` (Mermaid/DOT diagram output).

**Typical use:** Run `detect_dispatchers.py` to find all dispatch
functions in a module, then `extract_dispatch_table.py` on the most
interesting candidate to get the full command-ID-to-handler table. Use
`--with-loops` to focus on state machine candidates.

---

### Code Generation

#### code-lifting

Defines the 11-step workflow for lifting IDA Pro decompiled C/C++
functions into clean, readable, 100% functionally equivalent source
code. This is a **workflow/recipe skill** with no scripts of its own --
the code-lifter agent follows this recipe, using data extracted by
decompiled-code-extractor and types from reconstruct-types. The workflow
covers gathering function data, validating against assembly ground
truth, renaming parameters and variables, replacing magic numbers,
reconstructing structs, converting pointer arithmetic to field access,
simplifying control flow, adding documentation, and running independent
verification via the verifier agent. Also provides IDA naming pattern
reference, assembly-to-C++ translation tables, and common lifting
patterns (COM virtual calls, unique_ptr moves, HRESULT error chains,
lock pair reconstruction, SEH exception handling, memory lifecycle, and
callback dispatch).

**Key scripts:** None (workflow/recipe skill).

**Supporting files:** `examples.md` contains 7 concrete before/after
lifting examples with detailed change explanations; `README.md` covers
the skill's role and dependency relationships.

**Typical use:** The code-lifter agent reads this skill's `SKILL.md`
and follows the 11-step workflow when asked to lift or rewrite a
decompiled function. Data is extracted first via
decompiled-code-extractor, then each step transforms the code
progressively. For batch lifting of related functions, see
[batch-lift](#batch-lift).

---

#### batch-lift

Orchestrates lifting of related function groups together instead of
one-at-a-time, preserving shared context that individual lifting loses.
Supports three collection modes: **class methods** (all methods of a C++
class by mangled name), **call chains** (BFS from a function through N
levels of internal calls), and **export subtrees** (from a named export
down N levels). Builds shared struct definitions accumulated across all
functions in the set, determines dependency order (callees before
callers), and generates a single cohesive `.cpp` output with constants,
types, and functions. Integrates with the grind loop protocol for
batches larger than 10 functions.

**Key scripts:** `collect_functions.py` (multi-mode function collection
with dependency ordering), `prepare_batch_lift.py` (extract all data,
scan shared struct patterns, produce the full lift plan).

**Typical use:** Collect all class methods with `collect_functions.py
--class CSecurityDescriptor --json`, pipe to `prepare_batch_lift.py` for
the lift plan, then lift each function in dependency order with
progressively accumulated struct definitions. Depends on
decompiled-code-extractor, code-lifting, callgraph-tracer, and
reconstruct-types.

---

### Reconstruction

#### reconstruct-types

Module-wide C/C++ struct and class reconstruction from analysis
databases. Scans all functions using both decompiled code (for
`*(TYPE*)(base + offset)` patterns) and raw x64 assembly (for exact
field sizes from instruction operands), merges with vtable contexts and
mangled name data, and produces compilable header files with per-field
confidence annotations. Assembly is the ground truth -- it provides
exact sizes and catches accesses the decompiler may optimise away.
Fields confirmed by assembly are marked `asm_verified`. The output feeds
directly into code lifting, replacing raw pointer arithmetic with
readable struct field access.

**Key scripts:** `list_types.py` (overview of all C++ classes),
`extract_class_hierarchy.py` (class relationships, vtables,
constructors/destructors), `scan_struct_fields.py` (core field scanner
using decompiled + assembly patterns), `generate_header.py` (compilable
`.h` output).

**Typical use:** Start with `list_types.py --with-vtables` to see all
classes, then `scan_struct_fields.py --class ClassName` to scan memory
access patterns, and `generate_header.py --class ClassName --output
types.h` to produce the header. Refine incrementally as more functions
are lifted.

---

#### com-interface-reconstruction

Reconstructs complete COM interface and WRL class definitions from
analysis databases. Windows binaries are heavily COM-based, and this
skill extracts structured metadata from vtable slot analysis,
QueryInterface/AddRef/Release patterns, MSVC mangled name decoding, and
WRL template instantiation parsing (`Microsoft::WRL::RuntimeClassImpl`,
`ComPtr`, `FtmBase`). Produces per-class interface maps with evidence
sources (QI dispatch, WRL templates, vtable contexts) and IDL-like
interface descriptions with method signatures, parameter types, and
vtable slot comments.

**Key scripts:** `scan_com_interfaces.py` (discover all COM interfaces,
QI patterns, vtable layouts), `decode_wrl_templates.py` (parse WRL
template parameters from mangled names),
`map_class_interfaces.py` (build class-to-interface mappings),
`generate_idl.py` (produce IDL-syntax interface blocks).

**Typical use:** Run `scan_com_interfaces.py` to inventory all COM
structures, then `decode_wrl_templates.py` to recover WRL class
hierarchies and interface lists, and `generate_idl.py --output
interfaces.idl` to produce IDL descriptions.

---

### Security

#### map-attack-surface

Answers "Where can an attacker enter this binary?" by discovering,
classifying, and ranking every possible entry point in an analyzed
Windows PE binary. Goes well beyond DLL exports to detect COM vtable
methods, RPC handlers, WinRT methods, callback registrations, window
procedures, service handlers, TLS callbacks, IPC dispatchers, socket
handlers, named pipe handlers, and more (20+ entry point types). Each
entry point is ranked by a weighted composite attack score (0-1) using
callgraph reachability to dangerous operations, parameter risk, proximity
to danger, reachability breadth, and inherent entry type risk. Produces
CRS-compatible `entrypoints.json` for downstream tooling and fuzzing
harness generation.

**Key scripts:** `discover_entrypoints.py` (scan for all entry point
types), `rank_entrypoints.py` (rank by attack value with callgraph
reachability), `generate_entrypoints_json.py` (structured output for
downstream tools).

**Typical use:** Run `discover_entrypoints.py` to find all entry points,
`rank_entrypoints.py --top 20` to prioritize by attack value, and
`generate_entrypoints_json.py -o entrypoints.json` for structured
output. Drill into top targets with callgraph-tracer and
classify-functions.

---

#### security-dossier

One-command deep context gathering for security auditing of individual
functions. Builds a comprehensive dossier covering function identity,
attack reachability (is it exported? reachable from exports? shortest
path from entry?), untrusted data exposure, dangerous operations (direct
and via callees), resource patterns (synchronization, memory, global
state), complexity assessment (instructions, branches, loops, cyclomatic
complexity, stack frame), neighbouring context (class methods,
callers/callees), and module security posture (ASLR, DEP, CFG, SEH).
Designed as pre-audit context gathering -- run it before manually
reviewing a decompiled function.

**Key scripts:** `build_dossier.py` (single command producing the full
dossier; supports `--callee-depth` for deeper transitive dangerous API
analysis).

**Typical use:** Run `build_dossier.py <db_path> <function_name>` to get
the full security landscape for a function, then use the dossier findings
to guide deeper investigation with decompiled-code-extractor,
callgraph-tracer, and data-flow-tracer.

---

#### taint-analysis

Vulnerability-research-focused parameter taint tracing. Given a function
and optionally a set of parameters, traces attacker-controlled inputs
forward to dangerous sinks (CreateProcess, memcpy, LoadLibrary, etc.)
and backward to discover caller origins. For each path to a sink,
reports the severity score, the guards that must be bypassed (with
attacker-controllability and bypass difficulty), and how tainted data
affects internal logic (branch steering, array indexing, loop bounds,
allocation sizes). Covers ~250 dangerous API prefixes including Nt*
syscalls, COM/OLE/DDE, named pipes, ALPC, and DeviceIoControl.

**Key scripts:** `taint_function.py` (full forward + backward taint
analysis in one call), `trace_taint_forward.py` (forward-only trace),
`trace_taint_backward.py` (backward-only trace),
`generate_taint_report.py` (merge forward/backward into unified report).

**Typical use:** Run `taint_function.py <db_path> <function_name>
--depth 2 --json` to trace all parameters forward to dangerous sinks.
Use `--params 1,3` to trace specific parameters, `--direction both` for
combined forward + backward analysis. Review CRITICAL/HIGH findings for
sinks reached with weak or attacker-controllable guards.

---

#### memory-corruption-detector

Detects classic memory corruption bug classes in extracted binaries:
buffer overflows, integer overflow/truncation issues, use-after-free,
double-free, and format-string problems. The skill is tuned for VR-style
triage, ranking findings and then providing a separate verification step to
weed out noisy decompiler artifacts before deeper exploitability analysis.

**Key scripts:** `scan_buffer_overflows.py`, `scan_integer_issues.py`,
`scan_use_after_free.py`, `scan_format_strings.py`, `verify_findings.py`.

**Typical use:** Run the scanners across a module with `--json`, merge the
result sets, then use `verify_findings.py` to confirm the high-severity
candidates before escalating them into a full audit report.

---

#### exploitability-assessment

Assesses how practical a candidate vulnerability is to turn into a real
security issue. Instead of just reporting that a sink is reachable, it
scores the quality of the primitive, required attacker control, available
guards, mitigations, and reachability context across taint, memory, and
logic findings.

**Key scripts:** `assess_finding.py` (single finding assessment from taint,
memory, or logic inputs), `batch_assess.py` (score the top module findings
in one pass).

**Typical use:** Run `assess_finding.py` when you already have a dossier or
scanner output for a suspected bug, or `batch_assess.py <db_path> --top 20`
to prioritize the most realistically exploitable findings in a module.

---

### Reporting

#### generate-re-report

Generates synthesized, 10-section reverse engineering reports from
analysis databases. Unlike raw metadata dumps, it cross-correlates data,
computes derived metrics, and produces actionable guidance -- the report
you would write manually after hours with the binary, generated in
seconds. Sections cover executive summary, provenance and build
environment (Rich header, PDB path), security posture (ASLR/DEP/CFG/SEH,
section permissions, stack canaries), external interface (imports and
exports categorized by capability across ~500 Win32/NT APIs), internal
architecture (class hierarchy, symbol quality), complexity hotspots
(ranked by loops, xrefs, globals, assembly size), string intelligence
(paths, registry keys, URLs, GUIDs, error messages), cross-reference
topology (entry point reachability, dead code, recursive groups), notable
anomalies, and recommended focus areas with skill integration
suggestions.

**Key scripts:** `generate_report.py` (full 10-section report
orchestrator), `analyze_imports.py` (import/export categorization),
`analyze_complexity.py` (function complexity ranking),
`analyze_topology.py` (call graph metrics),
`analyze_strings.py` (string categorization),
`analyze_decompilation_quality.py` (decompilation quality metrics).

**Typical use:** Run `generate_report.py <db_path> --output
re_report.md` for the full report, or `--summary` for a quick 4-section
overview. Individual analyzers can be run standalone for focused
investigation.

---

### Verification

#### verify-decompiled

Finds and fixes specific places where IDA Hex-Rays got something wrong
compared to assembly ground truth. The output is the original decompiler
output with minimal, targeted fixes -- not a rewrite. Variables stay as
`a1`/`v5`, gotos stay as gotos. This differs fundamentally from lifting:
verification makes decompiler output trustworthy, lifting makes it
readable. They are sequential -- verify first, then lift if needed.
Automated heuristic checks cover return type mismatches, call count
discrepancies, missing branches, NULL check detection, signedness
mismatches, access size mismatches, and decompiler artifacts. Agent-driven
deep comparison catches collapsed multi-step operations, wrong offset
calculations, lost volatile reads, and missing error checks.

**Key scripts:** `scan_module.py` (triage all functions in a module,
ranked by severity), `verify_function.py` (deep per-function
verification with automated findings, full assembly, and decompiled
code).

**Typical use:** Start with `scan_module.py` to get a ranked list of
functions with decompiler issues, then `verify_function.py --id
<function_id>` for deep verification of the most problematic functions.
Supports the grind loop for batch verification across a module.

---

### Meta

#### deep-research-prompt

A meta-skill that orchestrates all other skills to gather maximum context
about a target function or module area, then synthesizes findings into a
structured research prompt driving detailed investigation. Works in two
phases: the **gather phase** runs classification, call graph tracing,
data flow analysis, string intelligence, COM interface scanning, dispatch
table detection, type reconstruction, and taint analysis to collect all available
evidence; the **synthesize phase** combines gathered context into a
research prompt with target description, known context, internal
architecture, cross-module integration, prioritized research questions,
and requested output format. This is the skill with the most
dependencies -- it coordinates output from 8 other skills into a unified
research workflow.

**Key scripts:** `gather_function_context.py` (deep single-function
intelligence across all skill dimensions),
`gather_module_context.py` (module-level intelligence for area research),
`generate_research_prompt.py` (main orchestrator producing the structured
prompt).

**Typical use:** Run `gather_function_context.py <db_path>
<function_name> --cross-module --with-code` to collect all evidence, then
`generate_research_prompt.py` to produce the prompt. Use `--area
security` for area-focused research across all security functions in a
module.

---

### Documentation

#### analyze-ida-decompiled

A documentation skill that provides comprehensive guidance for
navigating, reading, and understanding IDA Pro decompiled code extracted
by DeepExtractIDA. It does not contain executable scripts but instead
defines the extraction directory layout, grouped file naming conventions,
`file_info.json` section reference, IDA naming patterns (`a1`/`v1`,
`sub_XXXX`, `_DWORD`/`_QWORD` casts, `LODWORD`/`HIDWORD`,
`__fastcall`, WIL/WRL namespaces), and a 5-step analysis workflow
(orient, discover, analyze, cross-reference, contextualize). It is the
recommended starting point for anyone new to reading DeepExtractIDA
extraction outputs.

**Typical use:** Read the `SKILL.md` to understand the extraction output
structure, file naming, IDA conventions, and common analysis patterns
(struct field access, COM/WRL virtual calls, HRESULT error handling)
before diving into decompiled code.

---

#### brainstorming

A documentation skill for collaborative VR research planning. Guides the
agent through a structured dialogue workflow: gather context from
available modules and prior analysis, ask focused questions about target,
vulnerability hypothesis, threat model, and scope, propose 2-3 analysis
approaches mapped to available skills and commands, present a design for
approval, and transition to an implementation plan via CreatePlan. Has no
dependencies and no scripts -- it teaches the agent how to plan before
acting.

**Typical use:** Invoked via the `/brainstorm` command or when a user
requests help planning a vulnerability research campaign, analysis
strategy, or new tool/skill design.

---

#### deep-context-builder

A documentation skill that governs how the agent thinks during the
context-building phase of binary analysis. Forces block-by-block
analysis of IDA Pro decompiled functions using First Principles,
5 Whys, and 5 Hows to build deep understanding before vulnerability
hunting. Includes IDA/Hex-Rays artifact recognition (HIDWORD/LODWORD,
recovered `this` pointers, vtable dispatch patterns), anti-hallucination
rules, quality thresholds, and a completeness checklist.

Three phases: Initial Orientation (module structure mapping), Ultra-
Granular Function Analysis (block-by-block with invariant tracking),
and Global System Understanding (cross-function workflows and trust
boundaries).

**Dependencies:** decompiled-code-extractor, classify-functions,
callgraph-tracer, data-flow-tracer, map-attack-surface (referenced for data
extraction, flow analysis, and attack-surface context).

**Typical use:** Invoked before `/audit` on complex functions or when
a researcher asks for thorough understanding of decompiled code. Also
wired into `/explain` for deep comprehension requests.

---

#### adversarial-reasoning

A security methodology skill that encodes hypothesis-driven vulnerability
research methodology for Windows PE binaries. Provides five research
modes (campaign planning, hypothesis testing, variant analysis, finding
validation, and trust boundary mapping), a hypothesis generation
framework that derives testable hypotheses from entry point types,
classification signals, data flow patterns, and code patterns, Windows
security mental models (trust boundaries, privilege escalation vectors,
IPC pitfalls, file system attacks, memory safety), a research
prioritization rubric, and a validation strategy matrix mapping each
vulnerability class to specific workspace commands.

The skill includes a comprehensive reference file with a vulnerability
class encyclopedia (15 classes), 10 named Windows attack patterns from
Forshaw/P0/MSRC research, 8 step-by-step research playbooks with exact
commands, variant analysis methodology, and fill-in-the-blank hypothesis
templates. No scripts -- the skill's value is encoded domain expertise
that guides the researcher to use existing tools effectively.

**Dependencies:** classify-functions, map-attack-surface,
security-dossier, taint-analysis, data-flow-tracer, callgraph-tracer
(referenced in tool chain recommendations).

**Typical use:** Invoked via the `/hunt` command or when a user asks to
plan a VR campaign, generate attack hypotheses, find bug variants,
validate a suspected vulnerability, or reason about Windows attack
patterns against an extracted module.

---

#### finding-verification

A security methodology skill that provides structured false-positive
elimination for findings produced by taint-analysis,
memory-corruption-detector, and logic-vulnerability-detector. Forces
verification against assembly ground truth before accepting any finding.

Uses a 5-gate verification workflow: assembly ground truth (via
verify-decompiled), data flow confirmation (via data-flow-tracer),
attacker control reachability (via callgraph-tracer), cross-module
boundary checks (via import-export-resolver), and devil's advocate
review. Includes a catalog of false-positive patterns specific to
Hex-Rays decompiled PE binaries (type recovery errors, library
boilerplate triggers, optimized-away code paths, COM/WRL template
expansions).

**Dependencies:** taint-analysis, verify-decompiled, data-flow-tracer,
security-dossier, exploitability-assessment, import-export-resolver
(consumed as input sources and verification tools).

**Typical use:** Invoked during `/audit` and `/hunt-execute` workflows
when findings need confirmation. Also usable standalone when a
researcher asks "is this bug real?"

---

#### logic-vulnerability-detector

Detects logic vulnerability classes that bypass hardware memory mitigations
(ASLR, DEP, CFG, CET). Three detection scripts scan for auth/authz bypasses
(missing checks, auth-after-action, impersonation leaks), state machine
errors (state bypass, unrestricted transitions), and general logic flaws
(TOCTOU/double-fetch, missing return value checks, confused deputy, error
path privilege leaks). An independent verification script re-reads raw code
and assembly with fresh eyes to confirm or reject each finding before the
final report. Scoring model accounts for the fact that logic bugs are not
blocked by memory mitigations.

**Key scripts:** `scan_auth_bypass.py` (auth/authz bypass detection),
`scan_state_errors.py` (state machine vulnerabilities),
`scan_logic_flaws.py` (TOCTOU, missing checks, confused deputy),
`scan_api_misuse.py` (sensitive API parameter misuse),
`verify_findings.py` (independent fresh-eyes verification),
`generate_logic_report.py` (prioritized report synthesis).

**Typical use:** Run all three scanners on a module, merge the findings,
run `verify_findings.py` to confirm/reject each, and
`generate_logic_report.py` to produce a prioritized report. Use the
`/logic-scan` command for the full pipeline.

---

#### rpc-interface-analysis

Analyzes RPC server registrations and handler surfaces with a
privilege-boundary mindset. It inventories UUIDs, maps exposed interfaces,
audits security posture, traces handler call chains, identifies likely
client relationships, and builds a topology view for cross-module RPC
research.

**Key scripts:** `resolve_rpc_interface.py` (enumerate RPC interfaces and
stubs), `map_rpc_surface.py` (risk-ranked RPC surface), `audit_rpc_security.py`
(security review), `trace_rpc_chain.py` (handler chain tracing),
`find_rpc_clients.py` (client discovery), `rpc_topology.py` (server/client
topology).

**Typical use:** Run `resolve_rpc_interface.py` to enumerate a module's RPC
surface, `map_rpc_surface.py --system-wide --top 20` to rank interfaces by
research value, and `audit_rpc_security.py <db_path> --json` when you want
to drill into a specific RPC server's security posture.

---

#### winrt-interface-analysis

Analyzes WinRT (Windows Runtime) server registrations across four
access contexts defined by caller integrity level and server privilege.
Maps every binary to its WinRT activation classes, interface methods,
pseudo-IDL definitions, trust levels, SDDL permissions, and server
identities. The core capability is **privilege-boundary risk scoring**:
a medium-IL caller reaching a SYSTEM-level WinRT server is rated
critical, enabling focused EoP target identification.

**Key scripts:** `resolve_winrt_server.py` (enumerate server classes for
a module), `map_winrt_surface.py` (risk-ranked attack surface),
`enumerate_winrt_methods.py` (method listing with pseudo-IDL),
`classify_winrt_entrypoints.py` (semantic method classification),
`audit_winrt_security.py` (security audit with decompiled code),
`find_winrt_privesc.py` (privilege escalation target finder).

**Typical use:** Run `resolve_winrt_server.py` to see what WinRT
classes a module hosts, `map_winrt_surface.py --system-wide --tier
critical` to find the highest-risk servers across the system, and
`find_winrt_privesc.py --top 20` to identify the best EoP targets.

---

#### com-interface-analysis

Analyzes COM (Component Object Model) server registrations across four
access contexts defined by caller integrity level and server privilege.
Maps every binary to its COM CLSIDs, interface methods, pseudo-IDL
definitions, SDDL permissions, service identities, elevation flags,
and activation types. Builds on the same privilege-boundary risk model
as WinRT analysis, adding **elevation/UAC analysis** (CanElevate,
AutoElevation), **DCOM exposure** (SupportsRemoteActivation), and
**trusted marshaller** detection unique to COM.

**Key scripts:** `resolve_com_server.py` (enumerate servers by module or
CLSID), `map_com_surface.py` (risk-ranked attack surface),
`enumerate_com_methods.py` (method listing with pseudo-IDL),
`classify_com_entrypoints.py` (semantic method classification),
`audit_com_security.py` (security audit: permissions, elevation,
marshalling, DCOM), `find_com_privesc.py` (privilege escalation and
UAC bypass target finder).

**Typical use:** Run `resolve_com_server.py` to see what COM servers a
module hosts, `map_com_surface.py --system-wide --tier critical` to find
the highest-risk servers, `find_com_privesc.py --include-uac --top 20`
to identify EoP and UAC bypass targets, and `audit_com_security.py
<clsid>` for a detailed security review of a specific COM server.

---

## Shared Infrastructure

All skills share common infrastructure in `skills/_shared/` and
`helpers/`. When developing new skill scripts, **always use helpers
for common operations** -- never reimplement database access, function
resolution, error handling, classification, or output formatting.

### `skills/_shared/` -- Workspace Bootstrap

Provides `bootstrap(__file__)` and `make_db_resolvers()` for automatic
workspace root resolution and `sys.path` setup. Every skill's
`scripts/_common.py` calls these at import time.

### `helpers/` -- Shared Python Library (30+ modules)

The helpers library is the mandatory foundation for all script development.
It provides database access, function resolution, call graph construction,
API/string taxonomy, assembly metrics, caching, progress reporting,
structured error output, and much more.

### Import Pattern for Skill Scripts

Each skill should have a `scripts/_common.py` that bootstraps the workspace
and re-exports the helpers used by the skill's scripts:

```python
# scripts/_common.py
from skills._shared import bootstrap, make_db_resolvers

WORKSPACE_ROOT = bootstrap(__file__)
resolve_db_path, resolve_tracking_db = make_db_resolvers(WORKSPACE_ROOT)

from helpers import (  # noqa: E402
    open_individual_analysis_db,
    resolve_function,
    emit_error,
)
from helpers.errors import db_error_handler  # noqa: E402
from helpers.json_output import emit_json    # noqa: E402
```

Individual scripts then import from `_common`:

```python
from _common import resolve_db_path, open_individual_analysis_db, emit_error
from helpers.callgraph import CallGraph  # helpers not in _common
```

### Most-Used Helpers Across Skills

Based on actual usage across all existing skills:

| Helper | Used By | Purpose |
|--------|---------|---------|
| `helpers.errors` | ~90% of scripts | `emit_error()`, `db_error_handler()`, `ScriptError` |
| `helpers.json_output` | ~85% of scripts | `emit_json()`, `emit_json_list()` |
| `helpers` (root) | ~80% of scripts | `open_individual_analysis_db()`, `resolve_function()` |
| `helpers.cache` | ~40% of scripts | `get_cached()`, `cache_result()` |
| `helpers.callgraph` | ~25% of scripts | `CallGraph` class |
| `helpers.api_taxonomy` | ~20% of scripts | `classify_api()`, `API_TAXONOMY` |

### What Not to Do

| Anti-Pattern | Use Instead |
|-------------|-------------|
| Raw `sqlite3.connect()` | `open_individual_analysis_db(db_path)` |
| `SELECT * FROM functions` | `resolve_function(db, name_or_id)` |
| `print(json.dumps(...))` | `emit_json(data)` |
| `sys.exit(1)` with print | `emit_error(msg, code)` |
| Manual path resolution | `resolve_db_path_auto(db_path)` |
| Custom API categorization | `classify_api(name)` |

### Developer References

- **[`helpers/README.md`](../helpers/README.md)** -- Complete categorized
  reference with every operation mapped to its helper call
- **[Skill Authoring Guide](../docs/skill_authoring_guide.md)** -- Section 7:
  Helper Integration Reference with full tables by functional area
- **[Helper API Reference](../docs/helper_api_reference.md)** -- Public API
  for all 30+ helper modules

---

## Further Reading

| Document | Description |
|----------|-------------|
| [registry.json](registry.json) | Machine-readable skill contracts (entry scripts, args, deps, caching) |
| [Skill Authoring Guide](../../docs/skill_authoring_guide.md) | How to create new analysis skills |
| [Architecture](../../docs/architecture.md) | Full system design and component inventory |
| [Helper API Reference](../../docs/helper_api_reference.md) | Public API for all 35+ helper modules |
