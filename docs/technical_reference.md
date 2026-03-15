DeepExtract Agent Analysis Runtime Technical Reference

# Vulnerability Research Workflow Patterns

The runtime supports deterministic state transitions for vulnerability research. These operational sequences map discrete input states to specific analytical outputs through the orchestration of specialized subagents and capabilities.

## Module Triage Initialization
For preliminary analysis of unindexed binaries, the system executes the following operational chain:
- **Classification**: Executes triage command to extract binary identity, functional classification, and entry point distribution.
- **Vulnerability Scanning**: Executes scan command to perform parallel memory corruption, logic flaw, and taint analyses.
- **Prioritization**: Executes prioritize command to normalize and score findings based on a calculated exploitability index.

## Comprehensive Security Audit
For systematic evaluation of known high-risk components:
- **Baseline Establishment**: Executes triage command with security parameters to generate preliminary taint data.
- **Batch Evaluation**: Executes batch-audit command against the top ten entry points or across explicit privilege boundaries (RPC, COM, WinRT).
- **Ranking**: Executes prioritize command to establish cross-function risk rankings.
- **Deep Inspection**: Executes audit command on identified high-risk functions for localized verification and context generation.

## Hypothesis-Driven Investigation
For targeted research based on specific vulnerability classes or patterns:
- **Planning Phase**: Executes hunt-plan command to synthesize a structured research schema and generate verifiable hypotheses.
- **Execution Phase**: Executes hunt-execute command to systematically apply the generated schema against the target binary, recording confidence scores for each hypothesis.
- **Validation Phase**: Executes audit command on confirmed findings to evaluate the results against assembly-level ground truth.

## Export Dependency Tracing
For exhaustive mapping of specific exported interfaces:
- **Execution Path Mapping**: Executes audit command with `--diagram` to construct a call tree, retrieve decompiled syntax, and generate a topological diagram.
- **Data Flow Analysis**: Executes taint command with cross-module parameters to map parameter propagation across trust boundaries.
- **Security Assessment**: Executes audit command for localized vulnerability assessment.

## Cross-Boundary Impact Analysis
For evaluating inter-module dependencies and data propagation:
- **Dependency Graphing**: Executes imports command to construct PE-level dependency structures.
- **Comparative Assessment**: Executes compare-modules command to evaluate capability overlap, functional classification, and security posture across related binaries.

## Interface Attack Surface Mapping
For systematic enumeration of privilege escalation vectors:
- **Surface Discovery**: Executes com, rpc, or winrt commands with surface and system-wide parameters to inventory all accessible endpoints.
- **Target Identification**: Executes privesc or audit subcommands to identify specific escalation candidates based on access context and elevation flags.
- **Detailed Evaluation**: Executes batch-audit command utilizing the privilege-boundary parameter to assess discovered handlers.

## Code Reconstruction Pipeline
For generating functionally equivalent source representations:
- **Type Resolution**: Executes reconstruct-types command to extract structure definitions from memory access patterns.
- **Stateful Lifting**: Executes lift-class command to initialize a shared state context and orchestrate the code-lifter subagent through a deterministic translation sequence.

# Introduction and Architecture

## System Definition

DeepExtract is a programmatic analysis runtime designed to interface with IDA Pro extraction outputs from Windows PE binaries. The system implements a hierarchical architecture consisting of foundational utilities, analytical capabilities, specialized subagents, and direct operational commands to automate vulnerability research processes.

## Workspace Data Layout

The runtime requires a specific directory structure for operational execution:

- **extracted_code module directory**: Contains decompiled source files, file information metadata, function indexes, and pre-computed module profiles.
- **extracted_dbs directory**: Contains read-only SQLite analysis databases storing assembly instructions, cross-references, string literals, and control flow loop data.
- **agent helpers directory**: Contains the shared Python function library.
- **agent skills directory**: Contains discrete analysis capabilities and corresponding execution scripts.
- **agent agents directory**: Contains subagent configuration definitions, entry scripts, and the primary agent registry.
- **agent commands directory**: Contains command definitions for user interaction.
- **agent hooks directory**: Contains lifecycle event handlers including session initialization and task iteration protocols.
- **agent cache directory**: Contains temporary execution results validated by database modification timestamps with a 24-hour retention period.
- **agent workspace directory**: Contains isolated execution environments for multi-step workflow state management.
- **agent config directory**: Contains default parameters, classification weights, and execution thresholds.
- **agent docs directory**: Contains schema references and architectural documentation.
- **agent tests directory**: Contains system validation tests.

## Architectural Layers

The system operates across a strict, four-tier architecture:

1. **Commands Layer**: The primary user interface. Commands parse input parameters and orchestrate the lower layers to execute predefined workflows.
2. **Agents Layer**: Specialized execution units operating in isolated contexts. Agents manage complex, multi-stage operations and synthesize data from multiple capabilities. Subagents cannot spawn other subagents.
3. **Skills Layer**: Discrete analytical functions implemented as Python scripts. Skills perform specific operations and return structured JSON output.
4. **Helpers Layer**: A shared library of foundational Python modules providing database access, data parsing, and error handling.

Data propagation strictly follows an upward trajectory: SQLite databases and decompiled source files are parsed by Helper modules, processed by Skill scripts, synthesized by Agents, and presented by Commands. All original extraction databases remain read-only. Assembly code is universally treated as the authoritative ground truth for all analytical operations.

# Rules and Conventions

The runtime enforces six operational constraints. These constraints apply uniformly to all script implementations and agent behaviors.

## Error Handling Convention

The system implements a multi-layer error handling protocol dependent on the execution context.

- **Execution Endpoints**: Entry scripts implement the emit_error function. This function writes a structured JSON payload to standard error and terminates the process with exit code 1.
- **Library Modules**: Shared functions raise the ScriptError exception. This mechanism allows calling routines to intercept and process the exception logic.
- **Non-Fatal Operations**: The log_warning function outputs diagnostic information for conditions that do not necessitate process termination.
- **Database Interfacing**: All database connections use the db_error_handler context manager to intercept SQLite exceptions and format them into structured error payloads.

Standardized error codes include:
- **NOT_FOUND**: The specified entity does not exist within the current context.
- **INVALID_ARGS**: The provided parameters do not conform to expected schemas.
- **DB_ERROR**: The database initialization or query operation failed.
- **PARSE_ERROR**: The JSON payload or assembly instruction failed parsing constraints.
- **NO_DATA**: The query completed successfully but returned an empty dataset.
- **AMBIGUOUS**: The resolution logic identified multiple targets when strictly one was expected.
- **UNKNOWN**: An unhandled exception state occurred.

## Task Iteration Protocol

The system utilizes a stop hook to manage iterative processing for multi-item workloads. This mechanism re-invokes the active agent when uncompleted items remain in a designated state file.

- **State File Initialization**: The system creates a session-scoped markdown file when processing three or more discrete items, when responding to batch commands, or during multi-stage command execution.
- **State File Path**: The file resides in the agent hooks scratchpads directory, indexed by a unique session identifier.
- **Format Requirements**: The file requires a specific markdown structure containing a task descriptor, a bulleted list of items with checkbox syntax, and a status indicator initialized to IN_PROGRESS.
- **State Management**: The agent updates the checkbox syntax as discrete operations complete. The status indicator transitions to DONE when all items complete or if the operation aborts prematurely.
- **Loop Execution**: Upon agent termination, the hook evaluates the state file. If unchecked items exist and the status does not equal DONE, the hook transmits the remaining items back to the agent and triggers a re-invocation. This sequence repeats until completion, subject to a configured maximum loop limit.

## JSON Output Convention

The system enforces strict formatting for structured data output.

- **Trigger Conditions**: The system emits JSON when the json parameter is present, when the workspace directory parameter is active, or when standard output is piped to another process.
- **Stream Segregation**: The system strictly isolates data output to standard output and routes progress indicators, warnings, and error messages exclusively to standard error.
- **Formatting Constraints**: The JSON payload must consist of exactly one dictionary object containing a status key. The system must not emit bare arrays or string primitives.
- **Human-Readable Fallback**: When JSON is not requested, the system outputs formatted text tables and delimits sections with standardized headers, maintaining line widths below 120 characters.

## Missing Dependency Handling

The runtime implements specific degradation protocols for incomplete extraction data.

- **Pre-Flight Execution**: The system executes a validation function to verify workspace integrity prior to analysis operations.
- **Missing Required Databases**: The system triggers a fatal error using the NOT_FOUND code.
- **Missing Optional Databases**: The system logs a warning to standard error and continues execution with a restricted feature set.
- **Missing Tracking Database**: The system logs the unavailability of cross-module features and proceeds with localized, single-module analysis.
- **JSON-Only Operation**: If SQLite databases are unavailable but decompiled source exists, the system defaults to parsing the JSON function index and file information metadata. The system must explicitly document which database-reliant features are disabled and must not terminate with unhandled exceptions.

## Workspace Layout Conventions

The system relies on predefined directories to locate specific data types.

- Programmatic metadata queries must use the JSON file information artifact, rather than the markdown summary.
- Module-level statistical data requires the pre-computed module profile artifact.
- Assembly instructions, cross-references, string literals, and control flow properties necessitate direct interaction with the read-only SQLite analysis databases.
- Script implementations must import shared logic from the helpers directory; developers must not reimplement existing foundational logic.

## Workspace Pattern

The system employs a standardized filesystem handoff protocol to manage state during multi-step operations and prevent context window exhaustion.

- **Implementation Criteria**: The pattern applies when a coordinator orchestrates multiple capability scripts, executes phased analysis, or generates payload data exceeding context limits.
- **Directory Structure**: The system generates an isolated run directory containing a manifest JSON file to track operational state.
- **Parameter Interface**: Orchestrated scripts must accept the workspace directory path and a unique, path-safe step identifier.
- **Output Constraints**: Each executed step writes the full operational payload and a distinct compact summary to the run directory, updates the manifest file, and outputs only the compact summary to standard output.
- **Context Management**: The orchestrating agent maintains only the compact summaries and file paths in active memory. The full result payloads are loaded strictly on demand for synthesis operations.
- **Error Recovery**: Scripts that encounter fatal errors must still write an error summary, update the manifest file accordingly, and terminate. The orchestrating agent evaluates the manifest and continues the sequence if subsequent steps do not depend on the failed operation.

# Skills Reference

The runtime implements 17 distinct skills, categorized by functional purpose. These capabilities operate as discrete analytical units, processing extraction data and generating structured output.

## Foundation and Data Access

### decompiled-code-extractor
This capability provides the foundational data-access layer to retrieve structured function data from analysis databases. It executes data retrieval exclusively without performing structural analysis or rewriting.
- **find_module_db.py**: Maps a module name to the corresponding database path. Accepts module name, list flag, and extension parameters.
- **list_functions.py**: Retrieves function indices based on pattern matching. Accepts database path, search pattern, signature flag, decompiled filter flag, and json flag.
- **extract_function_data.py**: Retrieves the complete dataset for a specified function. Accepts database path, function name, identifier string, search pattern, and json flag.

### function-index
This capability provides file resolution mapping by linking function names to corresponding source files and categorizing boilerplate code via library tags. It operates independently of other analytical capabilities.
- **lookup_function.py**: Locates specific functions by name or pattern. Accepts function name, module string, search string, regex flag, application-only flag, and json flag.
- **index_functions.py**: Generates a filtered module function index. Accepts module name, all modules flag, application-only flag, library string, file grouping flag, file string, statistics flag, and json flag.
- **resolve_function_file.py**: Computes absolute file paths for function definitions. Accepts function name, module string, batch names string, file string, and json flag.

### import-export-resolver
This capability parses PE-level import and export tables to establish module dependencies, distinct from execution-level cross-references.
- **query_function.py**: Identifies functions based on export or import definitions. Accepts function string, direction string, and json flag.
- **build_index.py**: Initializes the cross-module dependency index. Accepts json flag and cache bypass flag.
- **module_deps.py**: Computes the PE-level dependency graph. Accepts module string, consumers flag, json flag, and diagram flag.
- **resolve_forwarders.py**: Traces forwarded export chains to their final destination. Accepts module string, function string, all flag, and json flag.

## Analysis

### callgraph-tracer
This capability constructs directed execution graphs from cross-reference data. It calculates execution paths, reachability matrices, and cross-module traversal chains.
- **build_call_graph.py**: Computes single-module graphs. Parameters dictate statistical output, shortest path, transitive reachability, strongly connected components, terminal leaves, and root origins.
- **cross_module_resolve.py**: Maps external calls to adjacent modules.
- **chain_analysis.py**: Executes recursive traversal of cross-module chains based on defined depth limits.
- **module_dependencies.py**: Maps inter-module API surface boundaries.
- **analyze_detailed_xrefs.py**: Extracts detailed cross-reference structures.
- **generate_diagram.py**: Renders topological representations in Mermaid or DOT syntax.

### classify-functions
This capability categorizes function logic into 20 distinct operational domains utilizing API usage, string references, and structural metrics. It generates an interest score scaled from 0 to 10 based on security relevance.
- **triage_summary.py**: Computes the top-level functional distribution.
- **classify_module.py**: Generates the complete categorized index with threshold filtering parameters.
- **classify_function.py**: Executes detailed classification analysis on a single targeted function.

### generate-re-report
This capability synthesizes data from multiple databases to construct a 10-section reverse engineering report. It cross-correlates external interfaces, complexity hotspots, and security posture.
- **generate_report.py**: Orchestrates the synthesis process.
- **analyze_imports.py**: Categorizes the external API surface.
- **analyze_complexity.py**: Computes the structural complexity ranking.
- **analyze_topology.py**: Computes call graph metrics.
- **analyze_strings.py**: Categorizes string references.
- **analyze_decompilation_quality.py**: Computes decompiler accuracy metrics.

### map-attack-surface
This capability inventories 20 distinct entry point structures and computes an attack value score based on reachability to sensitive operations.
- **discover_entrypoints.py**: Executes pattern matching to locate system boundaries.
- **rank_entrypoints.py**: Computes the relative attack risk across five weighted dimensions.
- **generate_entrypoints_json.py**: Synthesizes the data into a standardized JSON format.

### security-dossier
This capability aggregates function identity, reachability data, data exposure metrics, dangerous operations, and surrounding execution context into a unified dataset.
- **build_dossier.py**: Executes the aggregation logic to produce an 8-section context block and flags high-priority security indicators.

## Interface Analysis

### com-interface-analysis
This capability maps Component Object Model servers to class identifiers, methods, interface definitions, and security parameters including execution levels and SDDL permissions.
- **resolve_com_server.py**: Enumerates servers or performs CLSID lookups.
- **map_com_surface.py**: Generates a risk-ranked index of the attack surface across four privilege contexts.
- **enumerate_com_methods.py**: Extracts pseudo-IDL for discovered interfaces.
- **classify_com_entrypoints.py**: Applies semantic categorization to entry points.
- **audit_com_security.py**: Assesses server security parameters.
- **find_com_privesc.py**: Identifies configurations susceptible to privilege escalation.

### com-interface-reconstruction
This capability reverse-engineers COM and WRL definitions from vtable arrays, pointer instantiation patterns, and mangled symbols.
- **scan_com_interfaces.py**: Identifies COM implementations.
- **decode_wrl_templates.py**: Reconstructs WRL object structures.
- **map_class_interfaces.py**: Associates definitions with C++ classes.
- **generate_idl.py**: Outputs IDL syntax representing the reconstructed interfaces.

### rpc-interface-analysis
This capability maps Remote Procedure Call interfaces to UUIDs, protocols, and endpoints, enriched by auto-generated C# client stubs.
- **resolve_rpc_interface.py**: Enumerates RPC endpoints.
- **map_rpc_surface.py**: Generates a risk-ranked index including blast-radius metrics.
- **audit_rpc_security.py**: Assesses RPC-specific security controls.
- **trace_rpc_chain.py**: Tracks data propagation from RPC handlers.
- **find_rpc_clients.py**: Locates interdependent consumers.
- **rpc_topology.py**: Computes client-server network graphs.

### winrt-interface-analysis
This capability maps Windows Runtime activation classes, methods, trust levels, and security descriptors across specified privilege contexts.
- **resolve_winrt_server.py**: Enumerates server implementations.
- **map_winrt_surface.py**: Generates a risk-ranked index.
- **enumerate_winrt_methods.py**: Extracts pseudo-IDL representations.
- **classify_winrt_entrypoints.py**: Applies semantic categorization.
- **audit_winrt_security.py**: Assesses execution parameters.
- **find_winrt_privesc.py**: Identifies privilege escalation vectors.

## Vulnerability Detection

### ai-memory-corruption-scanner
This capability uses LLM agents with adversarial prompting to detect memory safety violations, navigating cross-module callgraphs with type-specific specialists and skeptic verification.
- **build_threat_model.py**: Builds a threat model identifying memory-corruption-prone entry points and callgraph paths.
- **prepare_context.py**: Prepares rich function context (decompiled code, assembly, xrefs, data flow) for LLM-driven analysis.
- Actual scanning is LLM-driven via the `/memory-scan` command, which orchestrates specialist and skeptic agents.

### ai-logic-scanner
This capability uses LLM agents with adversarial prompting to detect control flow bypasses, state invalidation, impersonation flaws, and absent validation checks, navigating cross-module callgraphs with 4 type-specific specialists (AuthBypass, StateConfusion, Impersonation, RaceCondition) and skeptic verification. Structural enrichments include dispatch_profile, shared_state_profile, and classification_summary alongside the standard callgraph context.
- **build_threat_model.py**: Builds a threat model identifying logic-vulnerability-prone entry points and callgraph paths.
- **prepare_context.py**: Prepares rich function context (decompiled code, assembly, xrefs, data flow) for LLM-driven analysis.
- Actual scanning is LLM-driven via the `/ai-logical-bug-scan` command, which orchestrates specialist and skeptic agents.

### ai-taint-scanner
This capability uses LLM agents with taint-specific context enrichment to trace attacker-controlled data through cross-module callgraphs, analyzing trust boundary crossings, insufficient input validation, and dangerous sink reachability with skeptic verification.
- **build_threat_model.py**: Builds a threat model identifying taint-analysis-prone entry points and callgraph paths.
- **prepare_context.py**: Prepares rich function context (decompiled code, assembly, xrefs, data flow) for LLM-driven taint analysis.
- Actual scanning is LLM-driven via the `/taint` command, which orchestrates specialist and skeptic agents.

### exploitability-assessment
This capability processes output from detection capabilities, normalizing data into a unified schema and calculating a comprehensive exploitability index based on reachability and guard bypass difficulty.
- **assess_finding.py**: Calculates exploitability for discrete findings across five weighted dimensions.
- **batch_assess.py**: Processes aggregate finding sets for prioritization sorting.

## Code Reconstruction

### batch-lift
This capability coordinates the reconstruction of related function arrays, managing the progressive accumulation of shared definitions across multiple discrete functions.
- **collect_functions.py**: Aggregates target functions based on shared class definitions or execution chains.
- **prepare_batch_lift.py**: Initializes the shared state context and sequences the lifting queue based on caller/callee dependencies.

### reconstruct-types
This capability processes memory access offsets across an entire module to synthesize C++ structure definitions, assigning confidence scores based on validation sources.
- **list_types.py**: Enumerates detected classes.
- **extract_class_hierarchy.py**: Constructs object inheritance and method mappings.
- **scan_struct_fields.py**: Processes pointer offsets from both decompiled code and assembly to identify field boundaries.
- **generate_header.py**: Synthesizes the computed offsets into a compilable C++ header artifact.

## Methodology and Strategy

### brainstorming
Merged into `/hunt-plan`. Strategic campaign planning, cross-module campaigns, post-analysis re-planning, and tool/skill design are now available as modes `cross`, `replan`, and `design` within the `/hunt-plan` command.

# Agents Reference

The runtime deploys eight specialized subagents operating in isolated context environments to orchestrate complex operations and synthesize capability outputs.

## re-analyst

- **Type**: analyst
- **Purpose**: Processes extracted C++ syntax, resolves Hex-Rays artifacts, and maps Win32 structures to generate deterministic explanations of function behavior.
- **Entry Scripts**:
  - **re_query.py**: Executes multi-mode module and function queries. Parameters include database path, overview flag, function string, class string, exports flag, search string, context flag, classification flag, ID string, and JSON flag.
  - **explain_function.py**: Executes granular control flow mapping to output structured function explanations. Parameters include database path, function string, ID string, depth integer, assembly suppression flag, and JSON flag.
- **Composed Skills**: classify-functions, generate-re-report, decompiled-code-extractor, callgraph-tracer, ai-taint-scanner.
- **Workflow**:
  - Validates input syntax and locates function data.
  - Maps parameters, API invocations, and branching logic.
  - Correlates findings with module strings and classification indices.
  - Outputs structured documentation containing purpose, parameters, return state, execution sequence, and a derived confidence coefficient.
- **Usage Boundaries**: Employ this agent for explaining existing code states and evaluating cross-module call chains. Do not utilize this agent for structural rewriting or orchestrating secondary pipelines.

## triage-coordinator

- **Type**: coordinator
- **Purpose**: Processes execution parameters to compute an analysis schema, dispatches corresponding capability scripts, and aggregates disparate data sources into a unified module report.
- **Entry Scripts**:
  - **analyze_module.py**: Executes the direct analysis pipeline. Parameters include database path, goal string, function string, JSON flag, timeout integer, and workspace run directory string.
  - **generate_analysis_plan.py**: Outputs a hierarchical task schema without execution. Parameters include database path, goal string, function string, and JSON flag.
- **Composed Skills**: classify-functions, map-attack-surface, callgraph-tracer, security-dossier, reconstruct-types, com-interface-reconstruction, decompiled-code-extractor, ai-taint-scanner, import-export-resolver.
- **Adaptive Execution**: Evaluates the pre-computed module profile to selectively append specialized analysis phases.
- **Usage Boundaries**: Employ this agent for complete module triage and security baseline initialization. Do not utilize for single-function explanations or localized instruction verification.

## security-auditor

- **Type**: analyst
- **Purpose**: Executes vulnerability detection routines, correlates taint propagation data, computes exploitability indices, and synthesizes security audit reports.
- **Entry Scripts**:
  - **run_security_scan.py**: Orchestrates the detection and verification sequence. Parameters include database path, goal string, function string, top integer, JSON flag, and timeout integer.
- **Composed Skills**: decompiled-code-extractor, classify-functions, map-attack-surface, security-dossier, ai-taint-scanner, exploitability-assessment, ai-memory-corruption-scanner, ai-logic-scanner.
- **Workflow**:
  - Executes entry point discovery and risk ranking.
  - Deploys memory corruption and logic vulnerability capabilities in parallel.
  - Maps taint flow across high-priority boundaries.
  - Discards findings exhibiting a verification confidence coefficient below 0.70.
  - Calculates the final exploitability score and generates the composite audit payload.
- **Usage Boundaries**: Employ this agent for batch vulnerability detection and exploitability assessment. Do not utilize for code rewriting or type structure reconstruction.

## code-lifter

- **Type**: lifter
- **Purpose**: Converts decompiled pseudo-code into functional C++ syntax while initializing and updating a persistent state schema to ensure variable naming and struct definition consistency across multiple methods.
- **Entry Scripts**:
  - **batch_extract.py**: Extracts target functions and initializes the shared state schema. Parameters include database path, class string, functions list, ID list, initialization flag, summary flag, and JSON flag.
  - **track_shared_state.py**: Manages read/write operations against the persistent JSON state schema. Parameters manage field offsets, constant values, naming mappings, and execution status tracking.
- **Composed Skills**: decompiled-code-extractor, batch-lift, reconstruct-types, function-index.
- **Workflow**:
  - Extracts the target method array and establishes the dependency execution sequence.
  - Executes the predefined 11-step code lifting sequence per method.
  - Pushes newly discovered struct fields and constant definitions to the shared state schema.
  - Assembles the independently processed methods into a single unified source file.
- **Usage Boundaries**: Employ this agent exclusively for generating equivalent C++ code arrays. Do not utilize for theoretical explanation, vulnerability scanning, or orchestration tasks.

## type-reconstructor

- **Type**: reconstructor
- **Purpose**: Computes C++ structure layouts by cross-referencing memory access offsets extracted from both decompiled syntax trees and raw assembly instructions.
- **Entry Scripts**:
  - **reconstruct_all.py**: Orchestrates the detection and extraction sequence. Parameters include database path, class string, output path, COM inclusion flag, and JSON flag.
  - **merge_evidence.py**: Resolves conflicting offset definitions and calculates confidence thresholds. Parameters process scan output JSON, COM data JSON, and output paths.
  - **validate_layout.py**: Cross-checks generated headers against assembly definitions.
- **Composed Skills**: decompiled-code-extractor, reconstruct-types, com-interface-reconstruction.
- **Usage Boundaries**: Employ this agent for generating header files and establishing type layouts. Do not utilize for control flow analysis or vulnerability detection.

## memory-corruption-scanner

- **Type**: analyst (LLM-only)
- **Purpose**: AI-driven memory corruption vulnerability scanner. Operates as an LLM subagent receiving callgraph + code batches prepared by the `ai-memory-corruption-scanner` skill.
- **Composed Skills**: ai-memory-corruption-scanner, decompiled-code-extractor, map-attack-surface.
- **Usage Boundaries**: Launched by `/memory-scan` and `/scan`. Do not utilize for explanation, lifting, or orchestration tasks.

## logic-scanner

- **Type**: analyst (LLM-only)
- **Purpose**: AI-driven logic vulnerability scanner. Operates as an LLM subagent receiving callgraph + code batches prepared by the `ai-logic-scanner` skill.
- **Composed Skills**: ai-logic-scanner, decompiled-code-extractor, map-attack-surface.
- **Usage Boundaries**: Launched by `/ai-logical-bug-scan` and `/scan`. Do not utilize for explanation, lifting, or orchestration tasks.

## taint-scanner

- **Type**: analyst (LLM-only)
- **Purpose**: AI-driven taint analysis scanner. Operates as an LLM subagent receiving callgraph + code batches prepared by the `ai-taint-scanner` skill. Uses taint-specific context enrichment, trust boundary analysis, and skeptic verification.
- **Composed Skills**: ai-taint-scanner, decompiled-code-extractor, map-attack-surface.
- **Usage Boundaries**: Launched by `/taint` and `/scan`. Do not utilize for explanation, lifting, or orchestration tasks.

# Commands Reference

The runtime executes 28 predefined operational sequences triggered via slash commands.

## Initialization Operations

### health
Executes system state validation.
- **Parameters**: quick execution flag, full execution flag.
- **Execution Sequence**:
  - Validates extraction data integrity.
  - Verifies SQLite database schemas.
  - Confirms skill and agent registration consistency.
  - Validates the environment configuration variables.
  - Executes the pytest validation suite.
- **Composed Elements**: Foundational helper modules exclusively.

## Reconnaissance Operations

### triage
Executes baseline module data extraction and classification.
- **Parameters**: module name, security scan inclusion flag.
- **Execution Sequence**:
  - Resolves the target database.
  - Computes binary identity using pre-computed profiles and generate_report.py.
  - Classifies the function inventory via triage_summary.py.
  - Computes call graph topology via build_call_graph.py.
  - Identifies the entry point surface via discover_entrypoints.py and rank_entrypoints.py.
  - Triggers a localized taint scan on the highest-ranked entries.
- **Composed Elements**: decompiled-code-extractor, generate-re-report, classify-functions, callgraph-tracer, map-attack-surface, ai-taint-scanner.

### full-report
Executes an exhaustive, multi-phase synthesis utilizing the Task Iteration Protocol.
- **Parameters**: module name, brief execution flag.
- **Execution Sequence**:
  - Initializes the scratchpad iteration state.
  - Executes Phase 1: Generates the foundational identity report.
  - Executes Phase 2: Classifies the module inventory.
  - Executes Phase 3: Computes the attack surface, generates the entrypoints JSON artifact, and builds dossiers for the highest-ranked vectors.
  - Executes Phase 4: Calculates topological and cross-module metrics.
  - Executes Phase 5: Conditionally extracts COM, state machine, and type layout structures based on module profiling thresholds.
  - Executes Phase 6: Assembles the 11-section output markdown artifact.
- **Composed Elements**: triage-coordinator, decompiled-code-extractor, generate-re-report, classify-functions, map-attack-surface, callgraph-tracer, com-interface-reconstruction, ai-taint-scanner, security-dossier, reconstruct-types, function-index.

### explain
Executes focused extraction to define specific function logic.
- **Parameters**: module name, function name, callee depth integer, pattern search string.
- **Execution Sequence**:
  - Locates the function index pointer.
  - Executes explain_function.py to process control flow and API usage.
  - Synthesizes the operational purpose, parameter structure, return state, and a calculated confidence threshold.
- **Composed Elements**: re-analyst, function-index, decompiled-code-extractor, classify-functions.

### search
Executes multidimensional cross-referencing across functions, APIs, and string literals.
- **Parameters**: module name, search term, dimension targets, regex mode flag, fuzzy mode flag, threshold float, limit integer, sort sequence string.
- **Execution Sequence**:
  - Resolves the target scope.
  - Executes unified_search.py passing the search mode parameters.
  - Sorts the output vectors by the computed relevance score.
- **Composed Elements**: unified_search helper.

### xref
Executes extraction of localized cross-references.
- **Parameters**: module name, function name, depth integer, search string.
- **Execution Sequence**:
  - Locates the function definition.
  - Computes callers and callees utilizing analyze_detailed_xrefs.py.
  - Computes extended depth relationships via build_call_graph.py.
  - Resolves cross-module boundaries utilizing cross_module_resolve.py.
- **Composed Elements**: callgraph-tracer, function-index.

## Structural Understanding Operations

### callgraph
Executes graph generation from cross-reference mappings.
- **Parameters**: module name, function name, strongly connected components flag, root elements flag, leaf elements flag, diagram output flag, traversal path strings, reachability target string.
- **Execution Sequence**:
  - Resolves the database context.
  - Executes build_call_graph.py specifying the desired topological calculation.
  - Conditionally executes generate_diagram.py to render the topological structure.
- **Composed Elements**: decompiled-code-extractor, callgraph-tracer.

### imports
Executes queries against PE-level dependency structures.
- **Parameters**: module name, lookup function string, consumers resolution flag, diagram generation flag, forwarder resolution flag.
- **Execution Sequence**:
  - Verifies the cross-module index state.
  - Executes query_function.py, module_deps.py, or resolve_forwarders.py based on passed flags.
- **Composed Elements**: import-export-resolver.

### compare-modules
Executes comparative logic across multiple binaries.
- **Parameters**: target module strings, all modules inclusion flag.
- **Execution Sequence**:
  - Resolves the specified databases.
  - Calculates topological overlaps.
  - Calculates PE-level structures.
  - Calculates comparative metrics across API classifications, string taxonomies, and function categories.
  - Generates cross-module call chain definitions.
- **Composed Elements**: decompiled-code-extractor, callgraph-tracer, generate-re-report, classify-functions, import-export-resolver, function-index.

### diff
Executes differential calculations across discrete binary versions.
- **Parameters**: primary module string, secondary module string.
- **Execution Sequence**:
  - Extracts the baseline function inventory for both modules.
  - Computes the delta vector for added, removed, and common function identifiers.
  - Identifies shifts in the attack surface utilizing discover_entrypoints.py.
  - Executes code-level differential analysis on functions demonstrating the highest change variation.
- **Composed Elements**: decompiled-code-extractor, classify-functions, map-attack-surface.

## Interface Analysis Operations

### com
Executes extraction of Component Object Model parameters.
- **Parameters**: subcommand string, target module or CLSID string, system-wide inclusion flag, result limit integer, pseudo-IDL inclusion flag.
- **Execution Sequence**:
  - Dispatches to the corresponding capability scripts.
  - Calculates elevation structures and risk categorizations based on the four required access contexts.
- **Composed Elements**: com-interface-analysis, decompiled-code-extractor, map-attack-surface.

### rpc
Executes extraction of Remote Procedure Call endpoint structures.
- **Parameters**: subcommand string, module name, function name, interface UUID string, system-wide inclusion flag, result limit integer, server-only limitation flag.
- **Execution Sequence**:
  - Evaluates the provided subcommand parameters.
  - Computes the respective structure utilizing pre-extracted boundary data and generated C# stub definitions.
  - Computes blast-radius indices based on co-hosted interface logic.
- **Composed Elements**: rpc-interface-analysis, decompiled-code-extractor, map-attack-surface.

### winrt
Executes extraction of Windows Runtime server parameters.
- **Parameters**: subcommand string, target module or class string, system-wide inclusion flag, result limit integer, pseudo-IDL inclusion flag.
- **Execution Sequence**:
  - Dispatches execution to defined scripts mapping activation types, trust levels, and execution level permissions.
- **Composed Elements**: winrt-interface-analysis, decompiled-code-extractor, map-attack-surface.

## Vulnerability Scanning Operations

### scan
Executes a composite diagnostic utilizing iterative state tracking.
- **Parameters**: module name, function string, result limit integer, memory-only restriction flag, logic-only restriction flag, taint-only restriction flag, auto-audit integration flag.
- **Execution Sequence**:
  - Initializes the scratchpad iteration file.
  - Executes parallel arrays of memory detection scripts and logic detection scripts.
  - Executes parallel taint tracking mapped to the top 5 discovered entry points.
  - Merges and deduplicates overlapping data vectors.
  - Applies verification against the merged vector set to establish confidence thresholds.
  - Computes the derived exploitability score for findings validated at CRITICAL or HIGH levels.
  - Conditionally executes the audit pipeline for the highest-ranking vulnerabilities.
- **Composed Elements**: ai-memory-corruption-scanner, ai-logic-scanner, ai-taint-scanner, map-attack-surface, exploitability-assessment, decompiled-code-extractor.

### memory-scan
Executes deterministic bounds-checking and memory safety analysis.
- **Parameters**: module name, function string, result limit integer.
- **Execution Sequence**:
  - Executes four independent sub-processes targeting buffer constraints, integer arithmetic conditions, use-after-free sequences, and format string input mappings.
  - Reconciles findings and executes cross-referencing against the assembly source.
- **Composed Elements**: ai-memory-corruption-scanner, decompiled-code-extractor.

### ai-logical-bug-scan
Executes AI-driven logic vulnerability scanning with adversarial prompting and skeptic verification.
- **Parameters**: module name, function string, result limit integer, function ID string.
- **Execution Sequence**:
  - Builds threat model and prepares rich function context.
  - Orchestrates specialist and skeptic LLM agents for each vulnerability type.
  - Merges results and produces verified findings with confidence scores.
- **Composed Elements**: ai-logic-scanner, decompiled-code-extractor.

### taint
Executes source-to-sink parameter tracking.
- **Parameters**: module name, function name, parameter indices, recursion depth integer, trace direction string, cross-module activation flag, cross-module depth integer, entry point generation flag, entry point limit integer, minimum score float, trust analysis bypass flag, COM resolution bypass flag.
- **Execution Sequence**:
  - Computes the trace vector from the defined starting state, logging specific memory and structure transfers.
  - Flags encountered bounds checks or validation routines.
  - Identifies module transitions, recalculating state at trust boundaries.
- **Composed Elements**: ai-taint-scanner, function-index, decompiled-code-extractor.

## Security Auditing Operations

### audit
Executes context aggregation and independent verification for a localized function definition.
- **Parameters**: module name, function name, search string.
- **Execution Sequence**:
  - Computes the function context dossier.
  - Compiles adjacent structural data.
  - Conditionally executes a forward taint track based on API parameter consumption.
  - Formats output against the standardized criteria checklist.
  - Executes the verification subagent, establishing a strict boundary between initial analysis and subsequent validation.
- **Composed Elements**: decompiled-code-extractor, security-dossier, map-attack-surface, callgraph-tracer, classify-functions, ai-taint-scanner, function-index.

### batch-audit
Executes parallel initialization of multiple audit processes.
- **Parameters**: module name, function enumeration array, top entry point integer, minimum score float, class restriction string, privilege boundary identification flag.
- **Execution Sequence**:
  - Calculates the input vector targets.
  - Instantiates the iteration scratchpad mapped to the specific function array.
  - Triggers the dossier compilation, taint evaluation, exploitability calculation, and semantic classification sequence for each iteration target.
  - Synthesizes findings into a unified matrix structure.
- **Composed Elements**: security-dossier, ai-taint-scanner, exploitability-assessment, classify-functions, map-attack-surface, rpc-interface-analysis, com-interface-analysis, winrt-interface-analysis, function-index, decompiled-code-extractor.

## VR Campaign Operations

### hunt-plan
Executes the generation of a verifiable analysis sequence.
- **Parameters**: operation mode string, module name, target string.
- **Execution Sequence**:
  - Aggregates existing workspace context variables.
  - Determines threat models and verification strategies without altering codebase logic.
  - Serializes the generated task definitions to a workspace execution file.
- **Composed Elements**: classify-functions, map-attack-surface, security-dossier, ai-taint-scanner.

### hunt-execute
Executes the operations specified within a structured task definition file.
- **Parameters**: module name, explicit task file path.
- **Execution Sequence**:
  - Loads the generated JSON payload.
  - Orchestrates the defined command executions.
  - Appends confidence thresholds to findings arrays.
  - Renders the resulting payload to an output file.
- **Composed Elements**: ai-taint-scanner, security-dossier, map-attack-surface, callgraph-tracer, exploitability-assessment.

### brainstorm (removed -- use /hunt-plan)
This command has been merged into `/hunt-plan`. Use `/hunt-plan cross`, `/hunt-plan replan`, or `/hunt-plan design` for strategic campaign planning, post-analysis re-planning, or tool/skill design respectively.
- **Composed Elements**: now part of hunt-plan.

## Code Quality Operations

### lift-class
Executes structural reconstruction of interdependent functions.
- **Parameters**: module name, class identification string, list flag.
- **Execution Sequence**:
  - Extracts the defined method array using batch_extract.py.
  - Initializes the shared variable space payload.
  - Spawns the code-lifter subagent to sequentially process the array, applying state updates back to the shared payload.
  - Assembles the resulting definitions into a contiguous compilation unit.
- **Composed Elements**: decompiled-code-extractor, batch-lift, reconstruct-types.

### reconstruct-types
Executes compilation of structural layouts derived from base pointer offsets.
- **Parameters**: module name, class string, COM integration flag, validation activation flag.
- **Execution Sequence**:
  - Extracts raw offset arrays from assembly code paths and decompiled instructions.
  - Executes merge_evidence.py to resolve differential conflicts.
  - Calculates inferred padding segments.
  - Conditionally executes structural checks via validate_layout.py.
- **Composed Elements**: reconstruct-types, decompiled-code-extractor, com-interface-reconstruction.

## Reporting and Ops Operations

### prioritize
Executes multi-module sorting logic against raw discovery artifacts.
- **Parameters**: module array, all modules flag, top integer, minimum score float.
- **Execution Sequence**:
  - Traverses the defined workspace context to identify scan payloads.
  - Computes standard deviations and ranking structures against uniform severity arrays.
  - Outputs a synthesized execution plan targeting the highest identified differentials.
- **Composed Elements**: decompiled-code-extractor.

### pipeline
Executes declarative script arrays based on YAML definition constraints.
- **Parameters**: subcommand string, configuration path string, dry-run flag, module override string, output path string.
- **Execution Sequence**:
  - Executes the pipeline_cli.py framework based on defined subcommand criteria.
- **Composed Elements**: triage-coordinator, security-auditor.

### runs
Executes inventory procedures against generated workspace payloads.
- **Parameters**: subcommand string, module filter string, unique run identifier.
- **Execution Sequence**:
  - Executes structural read commands specific to the target execution schema without reprocessing raw indices.
- **Composed Elements**: None.

### cache-manage
Executes state invalidation procedures for persistent storage elements.
- **Parameters**: subcommand string, module filter string, age threshold integer, dry-run flag.
- **Execution Sequence**:
  - Triggers filesystem removal scripts to conform to requested data freshness policies.
- **Composed Elements**: classify-functions, callgraph-tracer, generate-re-report.

# Helper Library Overview

The shared Python library operates at the foundational tier, exposing core programmatic logic to all higher-tier functions. Direct code reproduction from these elements into skill or agent scripts violates established DRY principles.

## Module Index

| Module | Category | Functional Purpose |
|---|---|---|
| **individual_analysis_db** | Database | Initializes per-module read-only SQLite connections. |
| **analyzed_files_db** | Database | Initializes the global tracking database for module indexing. |
| **db_paths** | Database | Computes valid filesystem paths and manages long-path constraints. |
| **function_resolver** | Resolution | Calculates function offsets based on identifiers and regex mappings. |
| **function_index** | Resolution | Evaluates JSON indexes to filter non-application library code. |
| **batch_operations** | Resolution | Executes simultaneous resolution across function arrays. |
| **api_taxonomy** | Classification | Maps API invocations to predefined security and functional categories. |
| **callgraph** | Graph | Computes directed topologies and traversal vectors. |
| **cross_module_graph** | Graph | Computes multi-module topology transitions. |
| **module_discovery** | Discovery | Enumerates the localized database array. |
| **module_profile** | Discovery | Evaluates pre-computed baseline fingerprint metrics. |
| **com_index** | Interface | Structures COM identifiers against extracted security configurations. |
| **winrt_index** | Interface | Structures WinRT classes against extracted activation conditions. |
| **rpc_index** | Interface | Structures RPC procedures against exposed endpoint metrics. |
| **rpc_stub_parser** | Interface | Parses auto-generated C# client templates. |
| **import_export_index** | Interface | Structures PE-level execution dependencies. |
| **def_use_chain** | Taint/Flow | Maps variable assignment arrays for propagation computation. |
| **decompiled_parser** | Parsing | Extracts structural components from decompiled syntax trees. |
| **struct_scanner** | Parsing | Processes base offset arithmetic. |
| **mangled_names** | Parsing | Computes standard class terminology from compiler naming conventions. |
| **calling_conventions** | Parsing | Maps x64 registers to parameter definitions. |
| **type_constants** | Parsing | Translates IDA type syntax to standardized C representations. |
| **errors** | Output | Manages the uniform error handling schema. |
| **json_output** | Output | Formats data structures conforming to JSON conventions. |
| **progress** | Output | Manages standard error diagnostic output formatting. |
| **logging_config** | Output | Configures standard environment log parameters. |
| **cache** | Cache | Manages read/write invalidation using timestamp checks. |
| **validation** | Validation | Computes schema conformity parameters. |
| **command_validation** | Validation | Computes user input adherence values. |
| **finding_schema** | Findings | Restructures discrete module output to unified payload templates. |
| **finding_merge** | Findings | Executes deduplication logic against concurrent arrays. |
| **workspace** | Workspace | Manages payload reads and structured directory instantiation. |
| **workspace_bootstrap** | Workspace | Processes pre-flight configuration for specific isolated processes. |
| **workspace_validation** | Workspace | Computes state confirmation indices across isolated sequences. |
| **pipeline_schema** | Pipeline | Loads and evaluates declarative configuration formats. |
| **pipeline_executor** | Pipeline | Dispatches structural actions based on schema parameters. |
| **pipeline_cli** | Pipeline | The primary operational interface for headless executions. |
| **cleanup_workspace** | Pipeline | Deletes outdated execution outputs based on retention policies. |
| **config** | Infrastructure | Modulates operating variables based on JSON parameter sets. |
| **script_runner** | Infrastructure | Manages execution path derivation logic. |
| **session_utils** | Infrastructure | Computes global identifiers for transient session states. |
| **agent_common** | Infrastructure | Provides base class definitions for agent structures. |
| **unified_search** | Infrastructure | Computes aggregate relevance rankings across heterogeneous search vectors. |

## Operational Anti-Patterns

| Deprecated Implementation | Authorized Implementation |
|---|---|
| Initializing raw SQLite connections | Execute open_individual_analysis_db |
| Hard-coding SQL syntax filters | Execute resolve_function |
| Rebuilding dynamic paths manually | Execute resolve_db_path_auto |
| Managing output serialization directly | Execute emit_json |
| Forcing manual process termination | Execute emit_error |
| Calculating class logic manually | Execute parse_class_from_mangled |
| Ad-hoc system categorizations | Execute classify_api |
| Writing standard diagnostics to standard output | Execute status_message |
| Constructing custom invalidation timers | Execute get_cached or cache_result |

# Cross-Reference Tables

## Command to Skill Matrix

- **audit**: decompiled-code-extractor, security-dossier, map-attack-surface, callgraph-tracer, classify-functions, ai-taint-scanner, function-index
- **batch-audit**: security-dossier, ai-taint-scanner, exploitability-assessment, classify-functions, map-attack-surface, rpc-interface-analysis, com-interface-analysis, winrt-interface-analysis, function-index, decompiled-code-extractor
- **cache-manage**: classify-functions, callgraph-tracer, generate-re-report
- **callgraph**: decompiled-code-extractor, callgraph-tracer
- **com**: com-interface-analysis, decompiled-code-extractor, map-attack-surface
- **compare-modules**: decompiled-code-extractor, callgraph-tracer, generate-re-report, classify-functions, import-export-resolver, function-index
- **diff**: decompiled-code-extractor, classify-functions, map-attack-surface
- **explain**: function-index, decompiled-code-extractor, classify-functions
- **full-report**: decompiled-code-extractor, generate-re-report, classify-functions, map-attack-surface, callgraph-tracer, com-interface-reconstruction, ai-taint-scanner, security-dossier, reconstruct-types, function-index
- **hunt-plan**: classify-functions, map-attack-surface, security-dossier, ai-taint-scanner
- **hunt-execute**: ai-taint-scanner, security-dossier, map-attack-surface, callgraph-tracer, exploitability-assessment
- **imports**: import-export-resolver
- **lift-class**: decompiled-code-extractor, batch-lift, reconstruct-types
- **ai-logical-bug-scan**: ai-logic-scanner, decompiled-code-extractor
- **memory-scan**: ai-memory-corruption-scanner, decompiled-code-extractor
- **prioritize**: decompiled-code-extractor
- **reconstruct-types**: reconstruct-types, decompiled-code-extractor, com-interface-reconstruction
- **rpc**: rpc-interface-analysis, decompiled-code-extractor, map-attack-surface
- **scan**: ai-memory-corruption-scanner, ai-logic-scanner, ai-taint-scanner, map-attack-surface, exploitability-assessment, decompiled-code-extractor
- **taint**: ai-taint-scanner, function-index, decompiled-code-extractor
- **audit**: decompiled-code-extractor, security-dossier, map-attack-surface, callgraph-tracer, classify-functions, ai-taint-scanner, import-export-resolver, function-index
- **triage**: decompiled-code-extractor, generate-re-report, classify-functions, callgraph-tracer, map-attack-surface, ai-taint-scanner, function-index
- **winrt**: winrt-interface-analysis, decompiled-code-extractor, map-attack-surface
- **xref**: callgraph-tracer, function-index

## Agent to Skill Matrix

- **re-analyst**: classify-functions, generate-re-report, decompiled-code-extractor, callgraph-tracer, ai-taint-scanner
- **triage-coordinator**: classify-functions, map-attack-surface, callgraph-tracer, security-dossier, reconstruct-types, com-interface-reconstruction, decompiled-code-extractor, ai-taint-scanner, import-export-resolver
- **security-auditor**: decompiled-code-extractor, classify-functions, map-attack-surface, security-dossier, ai-taint-scanner, exploitability-assessment, ai-memory-corruption-scanner, ai-logic-scanner
- **code-lifter**: decompiled-code-extractor, batch-lift, reconstruct-types, function-index
- **type-reconstructor**: decompiled-code-extractor, reconstruct-types, com-interface-reconstruction
- **memory-corruption-scanner**: ai-memory-corruption-scanner, decompiled-code-extractor, map-attack-surface
- **logic-scanner**: ai-logic-scanner, decompiled-code-extractor, map-attack-surface
- **taint-scanner**: ai-taint-scanner, decompiled-code-extractor, map-attack-surface

## Task Iteration Commands

The following operations mandate the instantiation of a scratchpad artifact:
- **full-report**
- **scan**
- **batch-audit**
- **hunt-execute**
- **lift-class**

## Cache Target Execution

The following processes generate payload artifacts governed by timestamp invalidation matrices:

# Glossary

- **Analysis Database**: A read-only SQLite artifact populated with assembly instructions, variable configurations, and pre-computed loops.
- **Dossier**: An aggregated output block defining isolated function identity parameters and computed risk values.
- **Entry Point**: A programmatic boundary condition permitting external parameter instantiation.
- **Task Iteration Protocol**: A recursive execution logic handling arrays of sequential parameters until the array index zeroes out.
- **Lifting**: The systemic translation of unformatted assembly derivations into syntactically sound C++ control flow variables.
- **Manifest**: A serialized JSON mapping index regulating stage execution and failure boundaries.
- **Module**: The parsed and verified representation of a Windows PE artifact.
- **Module Profile**: The deterministic schema containing baseline statistics to configure downstream agent orchestration values.
- **Run Directory**: An isolated namespace mapped specifically for localized temporary output logic strings.
- **Scratchpad**: The markdown-formatted persistent state file mapping progress across the Task Iteration Protocol.
- **Skill**: A standardized execution logic bound into individual processing modules.
- **Subagent**: An autonomous control script bound by defined contextual limits and executing specific programmatic loops.
- **Taint**: A tracked logic chain mapping variable ingestion to terminal endpoint usage execution blocks.
- **Tracking Database**: The core multi-binary index containing resolution definitions mapping disparate functions.
- **Trust Boundary**: An execution delimiter indicating state change conditions based on execution permission arrays.
- **Workspace Pattern**: A defined filesystem interface governing intermediate state transfers to bypass memory saturation limits.