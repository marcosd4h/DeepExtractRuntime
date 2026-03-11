---
name: deep-research-prompt
description: Generate comprehensive deep research prompts from DeepExtractIDA analysis databases by gathering function classification, call graphs, data flow, string intelligence, COM interfaces, and module context, then synthesizing structured research prompts and detailed research reports. Use when the user asks to research a function deeply, understand what a function does end-to-end, generate research prompts for a binary component, trace the full behavior of an API or export, create analysis prompts for deep research, or wants to understand the complete behavior of a function across module boundaries.
cacheable: true
depends_on: ["decompiled-code-extractor", "classify-functions", "callgraph-tracer", "data-flow-tracer", "state-machine-extractor", "generate-re-report", "com-interface-reconstruction", "reconstruct-types", "taint-analysis"]
---

# Deep Research Prompt Generator

## Purpose for reverse engineering analysis. This skill **orchestrates all other skills** to gather maximum context about a target function or module area, then synthesizes findings into a comprehensive research prompt that drives detailed investigation.

The two-phase approach:

1. **Gather Phase**: Run classification, call graph tracing, data flow analysis, string intelligence, and module context scripts to collect all available evidence about the target
2. **Synthesize Phase**: Combine all gathered context into a structured research prompt with specific questions, then use that prompt to produce a detailed research report

**This is a meta-skill.** It coordinates the output of other skills into a unified research workflow.

## When NOT to Use

- Quick function explanation without full context gathering -- use **re-analyst** or `/explain`
- Scanning for specific vulnerability patterns -- use **memory-corruption-detector** or **logic-vulnerability-detector**
- Generating a module overview report (not function-focused research) -- use **generate-re-report**
- Tracing a single parameter or API argument origin -- use **data-flow-tracer**
- Planning a vulnerability research campaign with attack hypotheses -- use **adversarial-reasoning**

## Data Sources

All data comes from existing skill infrastructure:

| Source                    | Skill Used                   | Data Extracted                                         |
| ------------------------- | ---------------------------- | ------------------------------------------------------ |
| Function classification   | classify-functions           | Category, interest score, API signals, dangerous APIs  |
| Call graph (internal)     | callgraph-tracer             | Internal callees, reachable functions, call depth      |
| Call graph (cross-module) | callgraph-tracer             | Cross-DLL calls, resolvable external chains            |
| Data flow                 | data-flow-tracer             | Parameter forward traces, argument origins, globals    |
| String intelligence       | generate-re-report           | Categorized strings (paths, registry, URLs, GUIDs)     |
| COM/WRL interfaces        | com-interface-reconstruction | COM interfaces, vtable layouts, QI patterns            |
| Dispatch tables           | state-machine-extractor      | Switch/case dispatchers, state machines                |
| Taint analysis            | taint-analysis               | Sink reachability, guards, bypass difficulty, severity |
| Type information          | reconstruct-types            | Struct layouts, class hierarchies, vtable contexts     |
| Module overview           | generate-re-report           | Import/export analysis, architecture                   |
| Decompiled code           | decompiled-code-extractor    | Raw decompiled C++, assembly, signatures               |

### Finding a Module DB

Reuse the decompiled-code-extractor skill's `find_module_db.py`:

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py --list
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py explorer.exe
```

### Quick Cross-Dimensional Search

To search across function names, strings, APIs, classes, and exports in one call:

```bash
python .agent/helpers/unified_search.py <db_path> --query "SearchTerm"
python .agent/helpers/unified_search.py <db_path> --query "SearchTerm" --json
```

## Utility Scripts

Pre-built scripts in `scripts/` handle all data gathering and prompt generation. Run from the workspace root.

### gather_function_context.py -- Deep Function Intelligence (Start Here)

Gather comprehensive context for a single function by running classification, call graph, data flow, and string analysis:

```bash
# Full context gathering for a function
python .agent/skills/deep-research-prompt/scripts/gather_function_context.py <db_path> <function_name>

# By function ID
python .agent/skills/deep-research-prompt/scripts/gather_function_context.py <db_path> --id <function_id>

# Control call graph depth (default: 3)
python .agent/skills/deep-research-prompt/scripts/gather_function_context.py <db_path> <function_name> --depth 4

# Include cross-module resolution
python .agent/skills/deep-research-prompt/scripts/gather_function_context.py <db_path> <function_name> --cross-module

# Include decompiled code for the function and its top callees
python .agent/skills/deep-research-prompt/scripts/gather_function_context.py <db_path> <function_name> --with-code

# JSON output for piping to generate_research_prompt.py
python .agent/skills/deep-research-prompt/scripts/gather_function_context.py <db_path> <function_name> --json
```

Output includes:

- Function identity (name, signature, mangled name, module)
- Classification result (category, interest score, all signals)
- Call graph summary (internal callees, external callees, reachable count, call depth)
- Cross-module resolution (which external calls are resolvable, their module DBs)
- Data flow summary (parameters forwarded to API calls, global state accessed)
- String context (all strings referenced, categorized)
- Dangerous API calls
- COM/WRL involvement (if detected)
- Dispatch/state machine patterns (if detected)

### gather_module_context.py -- Module-Level Intelligence

Gather broad context about a module for area-level research prompts:

```bash
# Full module context
python .agent/skills/deep-research-prompt/scripts/gather_module_context.py <db_path>

# Focus on specific function categories
python .agent/skills/deep-research-prompt/scripts/gather_module_context.py <db_path> --categories security,crypto,process_thread

# Include top-N most interesting functions detail
python .agent/skills/deep-research-prompt/scripts/gather_module_context.py <db_path> --top 20

# JSON output
python .agent/skills/deep-research-prompt/scripts/gather_module_context.py <db_path> --json
```

Output includes:

- Module identity (binary name, version, vendor, description)
- Category distribution (what the module primarily does)
- Import/export capability map
- Top interesting functions with classification
- Cross-module dependency map
- String intelligence summary
- COM density and class list (if applicable)
- Architecture overview (class hierarchy, function count by type)

### generate_research_prompt.py -- Main Prompt Generator

The primary orchestrator. Runs gathering scripts and synthesizes a structured research prompt.

```bash
# Generate research prompt for a single function
python .agent/skills/deep-research-prompt/scripts/generate_research_prompt.py <db_path> <function_name>

# Generate research prompt for a module area (by category)
python .agent/skills/deep-research-prompt/scripts/generate_research_prompt.py <db_path> --area security

# From pre-gathered context (output of gather_function_context.py --json)
python .agent/skills/deep-research-prompt/scripts/generate_research_prompt.py --from-json context.json

# Control prompt detail level
python .agent/skills/deep-research-prompt/scripts/generate_research_prompt.py <db_path> <function_name> --detail full
python .agent/skills/deep-research-prompt/scripts/generate_research_prompt.py <db_path> <function_name> --detail brief

# Write prompt to file
python .agent/skills/deep-research-prompt/scripts/generate_research_prompt.py <db_path> <function_name> --output research_prompt.md

# Include cross-module context
python .agent/skills/deep-research-prompt/scripts/generate_research_prompt.py <db_path> <function_name> --cross-module --depth 4
```

The generated prompt includes:

1. **Target Description** -- What is being researched and why it's interesting
2. **Known Context** -- Everything gathered from analysis (classification, APIs, strings, call graph)
3. **Internal Architecture** -- Call graph topology, dispatch patterns, data flow paths
4. **Cross-Module Integration** -- How this function interacts with other DLLs
5. **Research Questions** -- Specific, evidence-based questions organized by priority
6. **Requested Output Format** -- What the research should produce

## Workflows

### Workflow 1: "Deep research a specific function"

The primary use case. Understand what a function does end-to-end, including cross-module behavior.

```
Deep Research Progress:
- [ ] Step 1: Find the module DB
- [ ] Step 2: Gather deep function context
- [ ] Step 3: Generate the research prompt
- [ ] Step 4: Review and refine the prompt
- [ ] Step 5: Execute the research (use prompt with deep research tools or manual analysis)
- [ ] Step 6: Generate the research report using the generate-re-report skill
```

**Step 1**: Find the module DB

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py explorer.exe
```

**Step 2**: Gather deep function context

```bash
python .agent/skills/deep-research-prompt/scripts/gather_function_context.py <db_path> ShellExecuteW --cross-module --with-code --depth 3
```

Review the output -- it shows everything known about this function from binary analysis: what it calls, what strings it uses, what globals it touches, what APIs it invokes, and how it connects to other modules. For security-focused research, also run taint analysis to add sink reachability and guard/bypass context:

```bash
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> <function_name> --depth 2 --json
```

**Step 3**: Generate the research prompt

```bash
python .agent/skills/deep-research-prompt/scripts/generate_research_prompt.py <db_path> ShellExecuteW --cross-module --depth 3
```

This produces a structured prompt with:

- Context section (everything known from the binary)
- Research questions (derived from the gathered evidence)
- Output format requirements

**Step 4**: Review and refine. The agent should:

- Check if important call paths are missing (increase `--depth`)
- Verify cross-module context is complete (add `--cross-module`)
- Add domain-specific questions relevant to the research goal

**Step 5**: Use the prompt for deep research -- paste into a deep research tool, or use it as the basis for manual investigation across the extracted code.

**Step 6**: Generate a formal report

```bash
python .agent/skills/generate-re-report/scripts/generate_report.py <db_path> --output research_report.md
```

### Workflow 2: "Research a module area" (e.g., all security functions)

```
Area Research Progress:
- [ ] Step 1: Find the module DB
- [ ] Step 2: Triage the module to understand scope
- [ ] Step 3: Gather module-level context for the target area
- [ ] Step 4: Generate area-focused research prompt
- [ ] Step 5: Drill into specific functions from the prompt
```

**Step 1**: Find the module DB

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll
```

**Step 2**: Triage the module

```bash
python .agent/skills/classify-functions/scripts/triage_summary.py <db_path> --top 15
```

**Step 3**: Gather module context for the area

```bash
python .agent/skills/deep-research-prompt/scripts/gather_module_context.py <db_path> --categories security,process_thread,crypto --top 20
```

**Step 4**: Generate the area-focused prompt

```bash
python .agent/skills/deep-research-prompt/scripts/generate_research_prompt.py <db_path> --area security --output security_research.md
```

**Step 5**: For each high-priority function in the prompt, drill into function-level research:

```bash
python .agent/skills/deep-research-prompt/scripts/generate_research_prompt.py <db_path> AiLaunchProcess --cross-module
```

### Workflow 3: "Trace a cross-module execution flow"

For understanding how a function works across DLL boundaries (e.g., Start Menu click -> explorer -> RPCSS -> activation):

```
Cross-Module Research Progress:
- [ ] Step 1: Find all involved module DBs
- [ ] Step 2: Gather context for the entry function with cross-module resolution
- [ ] Step 3: For each resolvable external call, gather its context too
- [ ] Step 4: Generate a cross-module research prompt
```

**Step 1**: Find modules

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py --list
```

**Step 2**: Gather entry function context

```bash
python .agent/skills/deep-research-prompt/scripts/gather_function_context.py <db_path> <entry_function> --cross-module --depth 4 --json > entry_context.json
```

**Step 3**: The gather script automatically identifies resolvable external calls. For the most interesting ones, gather their context too:

```bash
python .agent/skills/deep-research-prompt/scripts/gather_function_context.py <external_db_path> <external_function> --cross-module --depth 2 --json > external_context.json
```

**Step 4**: Generate the cross-module prompt

```bash
python .agent/skills/deep-research-prompt/scripts/generate_research_prompt.py --from-json entry_context.json --detail full
```

### Workflow 4: "Pipeline -- Gather, Prompt, Research, Report"

The full end-to-end pipeline, designed for automated deep analysis:

```bash
# 1. Gather all context
python .agent/skills/deep-research-prompt/scripts/gather_function_context.py <db_path> <function> --cross-module --with-code --depth 3 --json > context.json

# 2. Generate the research prompt
python .agent/skills/deep-research-prompt/scripts/generate_research_prompt.py --from-json context.json --output research_prompt.md

# 3. [Agent/Human performs deep research using the prompt]

# 4. Generate formal RE report
python .agent/skills/generate-re-report/scripts/generate_report.py <db_path> --output re_report.md
```

## Research Prompt Structure

Generated prompts follow this template:

```markdown
# Deep Research: [Function/Area Name]

## Module: [binary name] ([version], [vendor])

## 1. Target Description

[What is being researched and why it's interesting based on classification]

## 2. Known Context from Binary Analysis

### 2.1 Function Identity

[Signatures, module, classification category, interest score]

### 2.2 API Usage Profile

[Categorized outbound API calls with per-API purpose annotations]

### 2.3 String Intelligence

[Categorized strings: paths, registry keys, GUIDs, error messages]

### 2.4 Internal Call Graph

[Call tree structure -- what this function calls internally]

### 2.5 Cross-Module Integration

[External calls that were resolved to other analyzed modules]

### 2.6 Data Flow Summary

[Parameter propagation, global state access patterns]

### 2.7 COM/Dispatch Patterns (if applicable)

[COM interfaces, vtable usage, dispatch tables]

### 2.8 Taint Analysis (if security-relevant)

[Tainted parameter sinks, severity scores, guard/bypass analysis, logic effects]

## 3. Research Questions

### Priority 1: Core Behavior

[Questions about what the function fundamentally does]

### Priority 2: Integration & Architecture

[Questions about how it fits into the larger system]

### Priority 3: Cross-Module Chains

[Questions about cross-DLL execution paths]

### Priority 4: Edge Cases & Error Handling

[Questions about failure paths, error recovery]

## 4. Requested Output

[Specific deliverables: document structure, diagrams, comparisons]
```

## Integration with Other Skills

This skill orchestrates these other skills:

| Skill                        | Phase           | What It Provides                                   |
| ---------------------------- | --------------- | -------------------------------------------------- |
| classify-functions           | Gather          | Function category, interest score, API signals     |
| callgraph-tracer             | Gather          | Call graph, cross-module resolution, reachability  |
| data-flow-tracer             | Gather          | Parameter flow, argument origins, globals map      |
| generate-re-report           | Gather + Report | String analysis, import categorization, complexity |
| state-machine-extractor      | Gather          | Dispatch tables, state machines                    |
| com-interface-reconstruction | Gather          | COM interfaces, WRL templates                      |
| reconstruct-types            | Gather          | Struct layouts, class hierarchies                  |
| taint-analysis               | Gather          | Tainted parameter sinks, guard/bypass analysis, severity |
| decompiled-code-extractor    | Gather          | Decompiled code, assembly, function data           |
| analyze-ida-decompiled       | Gather          | Module metadata, function summaries                |

## Direct Helper Module Access

For custom queries beyond what scripts provide:

```python
from helpers import open_individual_analysis_db, open_analyzed_files_db

with open_individual_analysis_db("extracted_dbs/module_hash.db") as db:
    func = db.get_function_by_name("FunctionName")[0]
    # Access all parsed fields for custom context gathering
    print(func.parsed_simple_outbound_xrefs)
    print(func.parsed_string_literals)
    print(func.parsed_global_var_accesses)
```

## Performance

| Operation | Typical Time | Notes |
|-----------|-------------|-------|
| Gather function context | ~5-10s | Collects classification, call graph, data flow |
| Gather module context | ~15-30s | Full module summary across all skills |
| Generate research prompt | ~2-5s | Template rendering from gathered context |

## Additional Resources

- For detailed prompt templates and example outputs, see [reference.md](reference.md)
- For function classification taxonomy, see [classify-functions](../classify-functions/SKILL.md)
- For call graph analysis, see [callgraph-tracer](../callgraph-tracer/SKILL.md)
- For data flow tracing, see [data-flow-tracer](../data-flow-tracer/SKILL.md)
- For taint analysis, see [taint-analysis](../taint-analysis/SKILL.md)
- For RE report generation, see [generate-re-report](../generate-re-report/SKILL.md)
- For DB schema and JSON formats, see [data_format_reference.md](../../docs/data_format_reference.md)
