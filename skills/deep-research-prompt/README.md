# Deep Research Prompt Generator

Generate structured, evidence-based deep research prompts by orchestrating **all other skills** to gather maximum context about a target function or module area, then synthesizing findings into a comprehensive research prompt with prioritized questions.

## Quick Start

```bash
# 1. Find the module DB
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll

# 2. Generate a research prompt for a function
python .agent/skills/deep-research-prompt/scripts/generate_research_prompt.py extracted_dbs/appinfo_dll_e98d25a9e8.db AiLaunchProcess --cross-module

# 3. Or research an entire area (e.g., all security functions)
python .agent/skills/deep-research-prompt/scripts/generate_research_prompt.py extracted_dbs/appinfo_dll_e98d25a9e8.db --area security
```

## What It Does

Two-phase approach: **gather** all available evidence, then **synthesize** into a structured prompt.

| Phase | What Happens |
|-------|-------------|
| **Gather** | Runs classification, call graph tracing, data flow analysis, string intelligence, COM/dispatch detection, and cross-module resolution |
| **Synthesize** | Combines all gathered context into a markdown prompt with evidence-based research questions at 5 priority levels, plus suggested follow-up commands |

### Context Gathered Per Function

| Data Source | Skill Used | What's Extracted |
|-------------|-----------|-----------------|
| Classification | classify-functions | Category, interest score, API signals, dangerous APIs |
| Call graph | callgraph-tracer | Internal/external callees, callers, reachability, call depth |
| Cross-module | callgraph-tracer | Resolvable external calls, target module DBs |
| Data flow | data-flow-tracer | Parameter forwarding, global reads/writes |
| Strings | generate-re-report | File paths, registry keys, GUIDs, URLs, error messages |
| COM/WRL | com-interface-reconstruction | COM interfaces, vtable contexts |
| Dispatch | state-machine-extractor | Switch/case dispatchers, state machines |
| Code | decompiled-code-extractor | Decompiled C++, assembly, signatures |

## Scripts

| Script | Purpose |
|--------|---------|
| `gather_function_context.py` | Deep context for a single function (classification + call graph + data flow + strings + patterns) |
| `gather_module_context.py` | Module-level context (category distribution + imports + top functions + architecture) |
| `generate_research_prompt.py` | Main orchestrator -- gathers context and synthesizes a structured research prompt |

## Usage

### Function-Level Research Prompt

```bash
# Basic prompt
python .agent/skills/deep-research-prompt/scripts/generate_research_prompt.py <db_path> <function_name>

# With cross-module resolution and deeper call graph
python .agent/skills/deep-research-prompt/scripts/generate_research_prompt.py <db_path> <function_name> --cross-module --depth 4

# By function ID (when multiple matches exist)
python .agent/skills/deep-research-prompt/scripts/generate_research_prompt.py <db_path> --id <function_id> --cross-module

# Write to file
python .agent/skills/deep-research-prompt/scripts/generate_research_prompt.py <db_path> <function_name> --output research_prompt.md
```

### Area-Level Research Prompt

```bash
# Research all security functions
python .agent/skills/deep-research-prompt/scripts/generate_research_prompt.py <db_path> --area security

# Research process/thread management
python .agent/skills/deep-research-prompt/scripts/generate_research_prompt.py <db_path> --area process_thread

# Available areas: security, process_thread, file_io, registry, network, crypto,
#   com_rpc, memory, sync, dispatch_routing, initialization, data_parsing, ...
```

### Context Gathering (Standalone)

```bash
# Gather function context (human-readable)
python .agent/skills/deep-research-prompt/scripts/gather_function_context.py <db_path> <function_name> --cross-module

# Gather function context as JSON (for pipeline)
python .agent/skills/deep-research-prompt/scripts/gather_function_context.py <db_path> <function_name> --cross-module --with-code --json > context.json

# Generate prompt from pre-gathered context
python .agent/skills/deep-research-prompt/scripts/generate_research_prompt.py --from-json context.json

# Gather module-level context
python .agent/skills/deep-research-prompt/scripts/gather_module_context.py <db_path> --categories security,crypto --top 20
```

## Example Output

```markdown
# Deep Research: AiLaunchConsentUI
## Module: appinfo.dll (v10.0.26100.7462, Microsoft Corporation)

## 1. Target Description

**AiLaunchConsentUI** is a **process_thread** function in **appinfo.dll**
with an interest score of **5/10**.

**Why research this function:**
- Uses dangerous APIs: ResumeThread, TerminateProcess, memset
- Large execution subtree (44 reachable functions)
- Significant cross-module interaction (12 external calls)
- Complex function (261 assembly instructions)

## 2. Known Context from Binary Analysis
### 2.1 Function Identity
### 2.2 API Usage Profile
### 2.4 Internal Call Graph
### 2.5 Cross-Module Integration
### 2.6 Data Flow Summary

## 3. Research Questions
### Priority 1: Core Behavior
### Priority 2: Integration & Architecture
### Priority 3: Cross-Module Chains
### Priority 4: Edge Cases & Error Handling
### Priority 5: Domain-Specific (Process Thread)

## 4. Requested Output
## 5. Suggested Follow-Up Commands
```

### Research Question Generation

Questions are evidence-based, derived from what the binary analysis actually found:

| Evidence Found | Generated Questions |
|----------------|-------------------|
| Calls `CreateProcessW` | "What processes does this function spawn? What are the command lines and security contexts?" |
| Cross-module call to `appinfo.dll` | "How does this function interact with the AppInfo service?" |
| Registry path strings | "What registry keys are read/written? What configuration data is stored?" |
| COM interfaces detected | "What COM interfaces are used? What servers are activated?" |
| Dispatch table (10+ cases) | "Map all dispatch cases to handler functions and document each handler." |
| Dangerous APIs | "What security-sensitive operations are performed? What validation guards each call?" |

## Tested Results

| Module | Script | Target | Lines | Sections | Exit |
|--------|--------|--------|-------|----------|------|
| cmd.exe | function prompt | BatLoop | 185 | 5 | 0 |
| cmd.exe | area prompt | file_io | 164 | 5 | 0 |
| appinfo.dll | function prompt | AiLaunchConsentUI | 202 | 5 | 0 |
| appinfo.dll | area prompt | security | 154 | 5 | 0 |
| coredpus.dll | function prompt | CWapDPU::ProcessData | 245 | 5 | 0 |
| coredpus.dll | area prompt | registry | 116 | 5 | 0 |
| (pipeline) | gather -> JSON -> prompt | ExecPgm | 369 | 5 | 0 |

## Files

```
deep-research-prompt/
├── SKILL.md                          # Agent skill instructions (read by Cursor)
├── reference.md                      # Prompt templates, JSON schemas, question logic
├── README.md                         # This file
└── scripts/
    ├── _common.py                    # Shared: workspace root, importlib bridge to
    │                                 #   classify-functions, string categorization,
    │                                 #   xref helpers, JSON parsing
    ├── gather_function_context.py    # Deep function intelligence (classification +
    │                                 #   call graph + data flow + strings + patterns)
    ├── gather_module_context.py      # Module-level context (category distribution +
    │                                 #   imports + top functions + architecture)
    └── generate_research_prompt.py   # Main orchestrator -- gathers + synthesizes
                                      #   structured research prompts
```

## Dependencies

- Python 3.10+
- `.agent/helpers/` module (workspace root) -- provides `open_individual_analysis_db`, `open_analyzed_files_db`
- `classify-functions` skill -- provides function classification (imported via `importlib.util`)
- SQLite analysis databases from DeepExtractIDA

## Related Skills

- [classify-functions](../classify-functions/SKILL.md) -- Classify functions by purpose (used internally)
- [callgraph-tracer](../callgraph-tracer/SKILL.md) -- Trace call chains across modules
- [data-flow-tracer](../data-flow-tracer/SKILL.md) -- Trace parameter and data flow
- [generate-re-report](../generate-re-report/SKILL.md) -- Generate full RE reports
- [code-lifting](../code-lifting/SKILL.md) -- Lift functions into clean code
- [state-machine-extractor](../state-machine-extractor/SKILL.md) -- Extract dispatch tables
- [com-interface-reconstruction](../com-interface-reconstruction/SKILL.md) -- Reconstruct COM interfaces
- [security-dossier](../security-dossier/SKILL.md) -- Security-focused function context
- [map-attack-surface](../map-attack-surface/SKILL.md) -- Map module attack surface
