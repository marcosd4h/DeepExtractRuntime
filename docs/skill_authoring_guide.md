# Skill Authoring Guide -- DeepExtractIDA Agent Analysis Runtime

This guide documents the design principles, conventions, and procedures for creating new analysis skills within the runtime. It covers both the conceptual approach to skill design and the technical implementation requirements.

## 1. Introduction

A skill is a set of instructions -- packaged as a folder -- that teaches the agent how to handle specific analysis tasks or workflows. Skills are the primary mechanism for extending the runtime's capabilities. Instead of re-explaining reverse engineering methodology, analysis procedures, and domain expertise in every conversation, skills encode that knowledge once and apply it consistently.

Skills are powerful when you have repeatable workflows: classifying functions across an entire module, tracing call graphs to map attack surfaces, building security dossiers for audit targets, or orchestrating multi-phase analysis pipelines. They work with the runtime's built-in helpers (DB access, function resolution, caching) and with each other through composable pipelines.

**What this guide covers:**

- Design principles and progressive disclosure architecture
- Planning use cases and defining success criteria before writing code
- SKILL.md structure, YAML frontmatter, and effective description writing
- Script conventions, helper integration, and caching
- Testing strategies: triggering, functional, and iteration-based
- Workflow patterns adapted to binary analysis pipelines
- Troubleshooting common failure modes
- A pre-release checklist

## 2. Fundamentals

### Progressive Disclosure

Skills use a three-level system to minimize token usage while maintaining specialized expertise:

- **Level 1 -- YAML frontmatter**: Always loaded at session start. The `inject-module-context.py` hook scans every `SKILL.md` and injects the `name` and `description` fields into the agent's context. This gives the agent just enough information to decide _when_ each skill is relevant -- without loading any of the instructions.

- **Level 2 -- SKILL.md body**: Loaded when the agent determines the skill is relevant to the current task. Contains the full instructions: purpose, data sources, utility scripts, workflows, and error handling. This is the skill's "recipe."

- **Level 3 -- Linked files**: Scripts in `scripts/`, reference documents, and cross-links to other skills or docs. The agent navigates and discovers these only when it needs to execute a specific operation or look up detailed reference material.

**Implication for authors**: Keep the YAML description concise but trigger-rich. Put operational detail in the SKILL.md body. Move reference-heavy content (schema details, exhaustive API lists) into linked docs or let scripts handle it.

### Context Economy

The context window is a shared resource. Your skill competes for space with the system prompt, conversation history, other skills' metadata, and the user's actual request. Conciseness is a design goal, not just a nice-to-have.

**Default assumption**: The agent is already an expert in general programming, OS concepts, and common data structures. Only add context it genuinely lacks -- binary analysis domain knowledge, runtime-specific conventions, DB schemas, and workflow sequences unique to this system.

Challenge every piece of content:

- "Does the agent already know this?" (e.g., don't explain what a DLL is)
- "Does this paragraph justify its token cost?"
- "Can I move this to a reference file loaded on demand?"

**Concise** (~50 tokens):

```markdown
## Extract function data

Use `extract_function_data.py` for the complete function record:

python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py <db_path> --id <func_id> --json
```

**Too verbose** (~150 tokens):

```markdown
## Extract function data

Functions in the analysis database contain decompiled C/C++ code, assembly
instructions, string literals, cross-references, and other metadata. To get
all of this data for a specific function, you need to use the extraction
script. This script connects to the SQLite database, queries the functions
table, and returns a comprehensive record. First, make sure you have the
correct database path...
```

### Degrees of Freedom

Match the level of specificity in your instructions to the task's fragility. Think of the agent navigating a path: a narrow bridge with cliffs requires exact steps; an open field allows many valid routes.

**Low freedom** (exact commands, no variation) -- use when operations are fragile and consistency is critical:

```markdown
Run exactly this command:
python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py <db_path> --id <func_id> --json
Do not modify flags or add additional arguments.
```

**Medium freedom** (preferred pattern with parameters) -- use when a pattern exists but details vary:

```markdown
Use `build_dossier.py` with callee depth 1-3 depending on function complexity.
For simple utility functions, depth 1 suffices. For exported entry points
with deep call trees, use depth 3.
```

**High freedom** (guidelines, agent decides) -- use when multiple approaches are valid and context determines the best one:

```markdown
Review the classification output and identify the most security-relevant
functions. Consider attack reachability, dangerous API usage, and complexity
when prioritizing.
```

Embedding validation in scripts (low freedom) is more reliable than asking the agent to "validate carefully" (high freedom). Reserve high freedom for tasks that genuinely require judgment.

### Composability

The agent can load multiple skills simultaneously. A typical session might combine `classify-functions` for triage, `callgraph-tracer` for path analysis, and `security-dossier` for deep audit -- all in one conversation. Your skill should:

- Not assume it is the only active skill
- Use standard helper APIs so data flows between skills naturally
- Declare dependencies in `registry.json` when it relies on another skill's scripts

### Helpers-First Development

The `.agent/helpers/` library (35+ modules, 100+ public symbols) is the shared foundation that all skills build on. It provides DB access, function resolution, API classification, call graph construction, string taxonomy, caching, error handling, progress reporting, validation, and more.

**The rule: never reimplement what helpers already provide.** Before writing any utility code in a skill script, check whether a helper already exists for the operation. Common violations:

- Writing raw SQLite queries instead of using `open_individual_analysis_db()` and `FunctionRecord` accessors
- Hand-parsing function names instead of using `resolve_function()` or `search_functions_by_pattern()`
- Building custom path resolution instead of using `resolve_db_path()` / `resolve_tracking_db()`
- Writing ad-hoc API classification instead of using `classify_api()` or `classify_api_security()`
- Rolling custom error output instead of using `emit_error()` / `log_warning()`

Using helpers ensures consistency across skills, prevents subtle bugs from divergent implementations, and lets every skill benefit when a helper is improved. Import helpers through your skill's `scripts/_common.py` so they are available to every script in the skill via a single import.

The standalone helper script `unified_search.py` deserves special mention: it searches across function names, signatures, strings, APIs, classes, and exports in a single call. Skills that need cross-dimensional lookup should call it rather than implementing their own search logic:

```bash
python .agent/helpers/unified_search.py <db_path> --query "CreateProcess" --json
```

For the complete API surface, see [helper_api_reference.md](helper_api_reference.md).

### Portability Across Agents

Skills work identically whether invoked by the `re-analyst`, `triage-coordinator`, `code-lifter`, or any other agent in the runtime. The same `SKILL.md` and scripts are available to all agents. Write skills with this in mind -- avoid assumptions about which agent is executing.

## 3. Planning a New Skill

Before writing any code, define the skill's purpose and boundaries.

### Start with Use Cases

Identify 2-3 concrete use cases the skill should enable. A well-defined use case looks like:

```
Use Case: Module-wide function classification
Trigger: User says "classify all functions" or "triage this binary"
Steps:
  1. Resolve module DB path
  2. Load all functions from the analysis database
  3. Classify each function by API usage, strings, naming, and metrics
  4. Produce a categorized summary with top-N interesting functions
Result: Prioritized function index grouped by purpose category
```

Ask yourself:

- What does a researcher want to accomplish?
- What multi-step workflow does this require?
- Which helpers and data sources are needed?
- What domain knowledge should be embedded (rather than left to the user)?

### Define Success Criteria

How will you know the skill is working?

**Quantitative targets** (rough benchmarks, not rigid thresholds):

- Skill triggers on ~90% of relevant queries. Test with 10-20 prompts that should activate it.
- Workflow completes in a predictable number of script calls. Compare the same task with and without the skill.
- Zero unhandled errors per workflow run. Monitor stderr output during test runs.

**Qualitative targets:**

- The agent does not need user redirection mid-workflow.
- Running the same request 3-5 times produces structurally consistent output.
- A new user can accomplish the task on the first try with minimal guidance.

### Common Skill Categories in This Runtime

| Category        | Purpose                                     | Examples                                                            |
| --------------- | ------------------------------------------- | ------------------------------------------------------------------- |
| Analysis        | Automated inspection of binary data         | `classify-functions`, `callgraph-tracer`                            |
| Reconstruction  | Recovering higher-level structures          | `reconstruct-types`, `com-interface-reconstruction`                 |
| Security        | Attack surface and vulnerability assessment | `map-attack-surface`, `security-dossier`                            |
| Code Generation | Producing cleaned or lifted code            | `batch-lift`                                                        |
| Reporting       | Synthesizing multi-source summaries         | `generate-re-report`                                                |
| Foundation      | Infrastructure used by other skills         | `decompiled-code-extractor`, `function-index`                       |

## 4. Skill Directory Structure

A skill is a directory in `.agent/skills/<skill-name>/` containing:

- `SKILL.md` -- The primary definition file (required). Contains YAML frontmatter for discovery, then the full instructions: purpose, data sources, utility scripts, workflows, and error handling. This file is read by the agent to understand the skill's capabilities.
- `README.md` -- User-facing documentation containing CLI usage examples and functional descriptions.
- `reference.md` -- Detailed reference material (schema notes, domain tables, extended examples) that the agent loads on demand. Linked from the `## Additional Resources` section in SKILL.md.
- `scripts/_common.py` -- A shared utility module for the skill. It re-exports symbols from `helpers` and defines skill-specific constants, dataclasses, and helper functions.
- `scripts/*.py` -- Standalone Python scripts, each implementing a specific analysis operation.

```
your-skill-name/
├── SKILL.md              # Required -- main skill file with YAML frontmatter
├── README.md             # User-facing documentation
├── reference.md          # Optional -- detailed reference loaded on demand
└── scripts/
    ├── _common.py        # Shared utilities (bootstrap, DB resolvers, re-exports, domain logic)
    ├── analyze.py        # Example analysis script
    └── summarize.py      # Example summary script
```

**Folder naming rules:**

- Use kebab-case: `map-attack-surface`, `com-interface-reconstruction`
- No spaces, no underscores, no capitals
- The folder name must match the `name` field in YAML frontmatter

**Documentation-only and workflow-only skills:** Not all skills require scripts. Some skills contain only SKILL.md, README.md, and reference material. They teach the agent _how to think_ about a task rather than providing executable entry points. If your skill is pure guidance with no computation, omit the `scripts/` directory entirely.

## 5. The SKILL.md File

The SKILL.md file is the most important artifact in a skill. It has two parts: the YAML frontmatter (Level 1 -- always loaded) and the Markdown body (Level 2 -- loaded on activation).

### 5.1 YAML Frontmatter

The frontmatter is how the agent decides whether to load your skill. It appears at the very top of SKILL.md between `---` delimiters.

**Minimal required format:**

```yaml
---
name: your-skill-name
description: What it does. Use when user asks to [specific trigger phrases].
---
```

**Field requirements:**

| Field         | Required | Rules                                                                                  |
| ------------- | -------- | -------------------------------------------------------------------------------------- |
| `name`        | Yes      | kebab-case, no spaces or capitals, must match folder name                              |
| `description` | Yes      | Under 1024 characters. Must include WHAT and WHEN. No XML angle brackets (`<` or `>`). |

**Naming conventions:**

- **Folder name**: kebab-case (`classify-functions`, `map-attack-surface`)
- **Display name** (the `# Heading` in SKILL.md): Use a clear noun phrase or gerund form that describes the activity. Good: "Function Classification", "Mapping Attack Surface", "COM Interface Reconstruction". Avoid vague names like "Helper", "Utils", or "Analyzer".

**Critical rules:**

- The file must be named exactly `SKILL.md` (case-sensitive). No variations (`SKILL.MD`, `skill.md`).
- YAML delimiters must be exactly `---` on their own line.
- No XML angle brackets in frontmatter -- frontmatter appears in the agent's system prompt, and angle brackets could be parsed as injection.

### 5.2 Writing Effective Descriptions

The description field is the single most important line in your skill. It controls whether the agent loads the skill at the right time.

**Structure formula:**

```
[What it does] + [When to use it] + [Key capabilities]
```

**Good descriptions -- specific, trigger-rich, domain-grounded:**

```yaml
# Good -- clear purpose, multiple trigger phrases, specific capabilities
description: >-
  Automatically classify and triage every function in a DeepExtractIDA
  module by purpose (file I/O, registry, network, crypto, security,
  telemetry, dispatch, initialization, etc.) using API calls, string
  analysis, naming patterns, assembly metrics, and loop complexity. Use
  when the user asks to classify functions, triage a binary, understand
  what a module does at a high level, find functions by category, identify
  interesting functions, filter out noise, or asks about function purpose
  distribution in an extracted module.

# Good -- covers both the capability and the user intent
description: >-
  Trace call graphs, execution paths, and cross-module xref chains across
  DeepExtractIDA analysis databases. Use when the user asks to trace a
  function's call chain, find paths between functions, understand
  cross-module dependencies, show what a function calls across DLL
  boundaries, generate call graph diagrams, find reachable functions from
  an entry point, identify recursive call clusters, or asks about
  execution flow across extracted modules.

# Good -- security domain with clear trigger surface
description: >-
  Build comprehensive security context dossiers for functions in
  DeepExtractIDA binaries -- gathering identity, attack reachability,
  data flow exposure, dangerous operations, resource patterns, complexity
  metrics, and neighboring context in one command. Use when the user asks
  to audit a function's security posture, build a security dossier,
  assess attack surface, check function reachability from exports, find
  dangerous API usage, or needs pre-audit context gathering for a
  decompiled function.
```

**Bad descriptions -- too vague, missing triggers, or too technical:**

```yaml
# Too vague -- agent cannot decide when to activate
description: Helps with analysis.

# Missing triggers -- describes capability but not when to use it
description: Classifies functions using multi-signal heuristics with weighted scoring.

# Too technical, no user-facing triggers
description: >-
  Implements the CallGraph entity model with adjacency list traversal
  and Dijkstra shortest-path computation over xref edges.
```

**Write descriptions in third person.** The description is injected into the system prompt. Inconsistent point-of-view causes discovery problems.

- Good: `"Classifies functions by API usage category in DeepExtractIDA modules."`
- Bad: `"I can help you classify functions in extracted modules."`
- Bad: `"You can use this to classify functions."`

**Provide one clear capability statement, not a menu.** Don't list every alternative approach. State what the skill does and when to use it. If edge cases exist, handle them in the SKILL.md body, not the description.

**Descriptions must contain triggering conditions, not workflow summaries.** When a description includes process steps ("classifies then ranks then builds dossiers"), the agent treats it as an executive summary and shortcuts past the SKILL.md body -- following the description's abbreviated version instead of the full instructions. This is especially dangerous when the description omits steps that the body includes. Keep workflow details exclusively in the body; descriptions should only say _what_ the skill does and _when_ to use it.

```yaml
# Bad -- workflow steps in description cause the agent to shortcut past SKILL.md
description: >-
  Classifies functions, then ranks by interest, then builds dossiers for
  the top results, then generates a summary report.

# Good -- triggering conditions only
description: >-
  Classify and triage every function in a module by purpose. Use when the
  user asks to classify functions, triage a binary, or understand what a
  module does at a high level.
```

**How to test your description:** Ask the agent "When would you use the [skill name] skill?" It will quote the description back. If the answer doesn't match your intended use cases, revise.

### 5.3 Writing the Instruction Body

After the frontmatter, write the full instructions in Markdown. This is Level 2 content -- loaded only when the skill activates.

**Recommended structure (reflects the pattern used by all 16 existing skills):**

````markdown
---
name: your-skill-name
description: [What + When + Capabilities]
---

# Skill Display Name

## Purpose

Detailed description of what the skill does and why it exists.
Explain the analysis problem it solves for the researcher.

## When to Use

- [4-6 specific scenarios where this skill applies]
- Scope the agent's behavior after the skill activates
- Be concrete: "when tracing tainted parameters to dangerous sinks"

## When NOT to Use

- [3-5 scenarios where a different skill or approach is better]
- Name the alternative: "use callgraph-tracer for cross-module path tracing"
- Not just "not for other tasks" -- say which other task and which tool

## Data Sources

### SQLite Databases (primary)

- Which tables/columns are used
- Cross-references to data format docs

### Finding a Module DB

Reuse the decompiled-code-extractor skill's `find_module_db.py`:

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py --list
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll
```
````

### Quick Cross-Dimensional Search

To search across function names, strings, APIs, classes, and exports in one call:

```bash
python .agent/helpers/unified_search.py <db_path> --query "CreateProcess"
python .agent/helpers/unified_search.py <db_path> --query "registry" --json
```

## Execution Guardrails (if applicable)

Use a tri-part structure when the skill involves operations that could
modify data or have side effects:

**Never allowed** (hard deny-list):
- Modifying analysis databases, deleting extraction output
- Writing to `extracted_dbs/` or `extracted_code/`

**Never allowed unless user explicitly asks:**
- Running external tools, modifying files outside `.agent/`
- Rebuilding caches or indexes

**Allowed** (explicit allow-list):
- Reading databases, running skill scripts, file reading, search
- Writing to `.agent/workspace/` and `.agent/cache/`

If further validation (manual review, external tool runs) is needed,
state it as a recommendation in the report rather than executing it.

## Exclusions (if applicable)

What the skill deliberately does NOT analyze. Explicit exclusions prevent
the agent from wasting tokens on out-of-scope work:

- "This skill does not analyze library boilerplate (WIL, STL, WRL, CRT) functions."
- "This skill does not perform cross-module tracing; use callgraph-tracer for that."

## Utility Scripts

Document each script in its own `###` subsection (not a flat table).
Mark the primary entry-point script with `(Start Here)` or `(Primary Tool)`.

**Make execution intent explicit.** For each script, clearly state whether the
agent should execute it or read it as reference. Ambiguity causes the agent to
load script contents into context instead of running them (wasting tokens), or
to run scripts it should be studying for algorithm understanding.

- **Execute** (most common): `"Run analyze_form.py to extract fields"`
- **Read as reference** (for complex algorithms): `"See classify_function.py for the scoring algorithm"`

For most utility scripts, execution is preferred -- it's more reliable and the
agent only needs the script's output, not its source code.

### primary_script.py -- Descriptive Subtitle (Start Here)

Brief description of what this script does and when to use it.

```bash
# Basic usage
python .agent/skills/<skill>/scripts/primary_script.py <db_path>

# JSON output for downstream processing
python .agent/skills/<skill>/scripts/primary_script.py <db_path> --json

# With filtering options
python .agent/skills/<skill>/scripts/primary_script.py <db_path> --top 20
```

Output includes: [describe what the output contains]

### secondary_script.py -- Descriptive Subtitle

Brief description. Additional scripts follow the same pattern.

```bash
python .agent/skills/<skill>/scripts/secondary_script.py <db_path> [options]
```

## Workflows

### Workflow 1: "User-facing task description in quotes"

Analysis Progress:
- [ ] Step 1: Discover and resolve module
- [ ] Step 2: Run primary analysis
- [ ] Step 3: Interpret results
- [ ] Step 4: Follow-up deep analysis

**Step 1**: Resolve the module DB.

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py <module>
```

**Step 2**: Run the primary analysis script.

```bash
python .agent/skills/<skill>/scripts/primary_script.py <db_path> --json
```

**Step 3**: Review the output. Focus on [specific areas].

**Step 4**: For functions of interest, follow up with deeper analysis:

```bash
python .agent/skills/<related-skill>/scripts/deep_script.py <db_path> <function>
```

## [Skill-Specific Sections]

Domain-specific sections as needed (e.g., Classification Categories,
COM VTable Layout Reference, Issue Categories and Severity, etc.)

## Integration with Other Skills

| Task | Recommended Skill |
|------|------------------|
| Follow up with deeper call chain analysis | callgraph-tracer |
| Lift interesting functions to clean code | batch-lift |
| Reconstruct struct types used by functions | reconstruct-types |

## Direct Helper Module Access

Document which helpers can be called directly for programmatic
use beyond the skill's scripts:

- `helpers.classify_api(api_name)` -- API taxonomy lookup
- `helpers.CallGraph.from_functions(functions)` -- Build call graph

## Performance

| Operation | Typical Time | Notes |
|-----------|-------------|-------|
| Primary analysis | ~X-Ys | Scales linearly with function count |
| Deep single-function analysis | ~1-2s | Per-function |
| Full module pipeline | ~30-60s | Runs all scripts sequentially |

## Additional Resources

- [reference.md](reference.md) -- Extended reference material
- [data_format_reference.md](../docs/data_format_reference.md) -- DB schema
- [file_info_format_reference.md](../docs/file_info_format_reference.md) -- Module metadata
- Links to related skills for follow-up analysis

````

**Section conventions observed across all 16 existing skills:**

- `## Purpose`, `## Data Sources`, `## Utility Scripts`, `## Performance`, and `## Additional Resources` are present in every skill.
- `## Direct Helper Module Access` appears in 10 of 16 skills -- include it when the skill's helpers are useful outside script invocation.
- `## Integration with Other Skills` appears in several skills -- include it when natural follow-up analysis is available in other skills.
- The "Finding a Module DB" subsection under Data Sources appears in 13 of 16 skills -- include it unless the skill does not use analysis databases.
- In Utility Scripts, each script gets its own `###` subsection with multiple code examples, not a flat summary table. Mark the primary script with `(Start Here)`.
- In Workflows, use progress checklists (`- [ ] Step N:`) and `**Step N**:` bold formatting for multi-step procedures.
- In Performance, use the 3-column table format: `| Operation | Typical Time | Notes |`.

**Best practices for instructions:**

Be specific and actionable:

```markdown
<!-- Good -->
Run `python .agent/skills/classify-functions/scripts/triage_summary.py <db_path>`
to get a module overview. If the output shows 0 classified functions, verify the
DB contains `simple_outbound_xrefs` data.

<!-- Bad -->
Classify the functions before proceeding.
````

Use helpers, not raw implementations. Skill instructions should direct the agent to use the `.agent/helpers/` library for all common operations rather than writing raw SQL or ad-hoc logic:

```markdown
<!-- Good -- delegates to the helpers library -->

Resolve the function using `helpers.resolve_function(db, name_or_id)`.
If resolution is ambiguous, use `helpers.search_functions_by_pattern(db, pattern)`
to list candidates.

<!-- Bad -- reimplements what helpers already provide -->

Query the `functions` table directly with
`SELECT * FROM functions WHERE function_name LIKE '%pattern%'`.
```

When writing skill instructions, always direct the agent to use helpers for DB access, function resolution, API classification, error reporting, and caching. The helper library guarantees consistent behavior across all skills and ensures improvements benefit every skill at once. See section 7 for the full categorized reference.

Reference bundled resources clearly:

```markdown
Before writing classification queries, consult
[data_format_reference.md](../docs/data_format_reference.md) for:

- The `simple_outbound_xrefs` table schema
- API category taxonomy
- String categorization rules
```

Put critical instructions first. The agent processes instructions top-down. If a step is essential, put it early and use strong headers (`## Critical` or `## Important`).

Use progressive disclosure within the body. Keep the SKILL.md focused on core workflows. Move exhaustive reference material (full schema docs, domain tables, extended examples) to a `reference.md` file at the skill root and link to it from the `## Additional Resources` section. The agent will load it on demand. 13 of 16 existing skills follow this pattern.

**Keep SKILL.md body under 500 lines.** If your content exceeds this, split into separate reference files. Once the agent loads SKILL.md, every token competes with conversation history and other context.

**Sizing guidelines for all skill files:**

| File type    | Target lines | Maximum |
| ------------ | ------------ | ------- |
| SKILL.md     | 200-400      | 500     |
| reference.md | 100-300      | 400     |
| README.md    | 50-150       | 200     |

If a reference file exceeds 400 lines, split it into two files that SKILL.md links to separately.

**Keep references one level deep from SKILL.md.** All reference files should be linked directly from SKILL.md. Avoid chains where SKILL.md links to A.md which links to B.md -- the agent may only partially read nested references, resulting in incomplete information.

```markdown
<!-- Good: one level deep -->
# SKILL.md
**Basic usage**: [instructions here]
**Advanced features**: See [advanced.md](advanced.md)
**API reference**: See [reference.md](reference.md)

<!-- Bad: nested chain -->
# SKILL.md → advanced.md → details.md
```

**Add a table of contents to reference files over 100 lines.** This ensures the agent can see the full scope of available information even when previewing with partial reads:

```markdown
# API Reference

## Contents
- Authentication and setup
- Core methods (list, extract, classify)
- Advanced features (batch operations, cross-module)
- Error handling patterns
- Code examples

## Authentication and setup
...
```

### Common Instruction Patterns

These patterns appear repeatedly across well-written skills. Use them as building blocks in your SKILL.md body.

**Template pattern.** When a skill produces structured output, provide a template with an explicit strictness level. This tells the agent whether it must match the format exactly or can adapt.

Strict (for JSON schemas, report sections, data formats):

```markdown
ALWAYS produce output matching this structure:
{"status": "ok", "function": "<name>", "categories": [...], "interest_score": <0-10>}
```

Flexible (for prose, explanations, analysis narratives):

```markdown
Use this as a sensible default structure, but adapt sections based on what
the analysis reveals:

## Function Purpose
[Describe what the function does]

## Security Relevance
[Omit if the function has no security implications]
```

**Examples pattern.** When output quality depends on matching a specific style or format, provide input/output pairs directly in the instructions. Examples calibrate the agent's output more precisely than descriptions alone:

```markdown
## Classification output format

**Example 1:**
Input function: `AiLaunchAdminProcess`
Output:
  Category: security/process_launch
  Interest: 9/10
  Reason: Launches elevated process with user-controlled parameters

**Example 2:**
Input function: `wil::details::FeatureLogging::ReportUsageError`
Output:
  Category: telemetry/error_reporting
  Interest: 2/10
  Reason: WIL library boilerplate, not application logic
```

**Conditional workflow pattern.** When user intent determines which path to follow, provide explicit decision points. This complements Pattern 3 (Context-Aware Tool Selection) which handles data-availability branching:

```markdown
## Analysis workflow

1. Determine the analysis type:

   **Single function?** → Follow "Function Deep Dive" below
   **Entire module?** → Follow "Module Triage" below
   **Specific class?** → Follow "Class Reconstruction" below

2. Function Deep Dive:
   - Extract function data
   - Build security dossier
   - Trace call chain

3. Module Triage:
   - Classify all functions
   - Rank by interest score
   - Select top-N for deep dive
```

If conditional workflows become large, push each branch into a separate file and let the agent read only the relevant one.

**Prompt patterns.** Map the 2-3 most common user prompts to exact script invocations. This gives the agent a fast-lookup table so it can skip reasoning through the full workflow for typical requests:

```markdown
## Prompt Patterns

### Pattern A: Module-wide triage

> "classify all functions in appinfo.dll"

- Resolve DB: `find_module_db.py appinfo.dll`
- Run: `triage_summary.py <db_path> --json`

### Pattern B: Single function deep dive

> "what does AiLaunchAdminProcess do?"

1. Resolve function: `--id <func_id>` or `--function AiLaunchAdminProcess`
2. Run: `classify_function.py <db_path> --id <func_id> --json`
3. Follow up: `build_dossier.py <db_path> --id <func_id> --json`
```

Each pattern starts with a quoted user prompt, then lists the exact commands. Keep to 2-3 patterns that cover ~80% of invocations; the full workflow section handles the rest.

**Qualifying and disqualifying examples.** For skills with classification or scoring systems (interest scores, risk ratings, severity tiers), provide **both qualifying and disqualifying examples**. Qualifying examples show what meets the bar; disqualifying examples show what to reject. The disqualifying set is often more valuable because it prevents false positives:

```markdown
### Security-relevant qualifies as

- Exported function reachable in 1-2 hops from an entry point
- Calls dangerous APIs (memcpy, CreateProcess) with non-constant arguments
- Handles user-controlled input (network buffers, registry values, file paths)

### Discard these (do NOT report as security-relevant)

- WIL/STL/CRT library boilerplate that wraps safe APIs
- Telemetry and logging functions that only read state
- Functions with high cyclomatic complexity but no dangerous API calls
- "Under heavy load this could..." -- speculative, not evidence-based
```

**Language constraints pattern.** When a skill produces natural-language output where certainty or tone matters, define required and forbidden vocabulary explicitly. This is more reliable than "be precise" or "avoid speculation" because it gives the agent concrete tokens to match against:

```markdown
## Mandatory language

Use "does / is / will" in all findings.
NEVER use "might / could / possibly / may / theoretically".
```

Use this pattern for any skill whose output feeds into decisions (security assessments, risk classifications, audit findings, code review verdicts).

**Rationalizations to reject pattern.** For security, assessment, and audit skills, explicitly list the shortcuts and rationalizations the agent must reject. LLMs naturally minimize effort -- without explicit rejection rules, the agent talks itself into skipping important analysis steps. This is the single most common cause of missed findings in security-oriented skills:

```markdown
## Rationalizations to Reject

| Rationalization | Why It's Wrong |
|-----------------|----------------|
| "A guard exists on this path, so it's safe" | Guards may be attacker-controllable or bypassable. Analyze the guard, don't assume it works. |
| "The path is too deep to be exploitable" | Depth doesn't determine exploitability. A 5-hop chain with no guards is worse than a 1-hop chain with strong validation. |
| "This function is internal, so it's unreachable" | Internal functions may be reachable via exported callers. Check reachability before dismissing. |
| "Only a DoS, not worth reporting" | DoS in system services is a security boundary violation. Report it with appropriate severity. |
| "Mitigations make this unexploitable" | Mitigations raise the bar, they don't eliminate risk. Report the finding with mitigation context. |
```

Include this pattern in any skill that produces security assessments, risk scores, or audit findings. The table should contain 3-7 domain-specific rationalizations -- enough to cover common shortcuts without becoming a reference dump.

## 6. Script Conventions

### Argument Parsing

Scripts must use `argparse` with a `description=` string explaining what the script does. Every script must implement these standard arguments:

- `db_path` (positional): The absolute path to the analysis database.
- `--json` (flag): When present, the script must output only valid JSON to stdout.
- `--no-cache` (flag): For cacheable operations, this flag must bypass the filesystem cache.

Beyond these, existing skills use a common vocabulary of additional arguments. Use the same names when your skill needs similar functionality to keep the CLI surface consistent:

| Argument               | Purpose                                         | Used by                                                                    |
| ---------------------- | ----------------------------------------------- | -------------------------------------------------------------------------- |
| `--id <function_id>`   | Select function by numeric ID                   | callgraph-tracer, security-dossier                                          |
| `--function <name>`    | Select function by name                         | callgraph-tracer                                                            |
| `--search <pattern>`   | Regex pattern search                            | security-dossier, reconstruct-types                                        |
| `--class <ClassName>`  | Filter to class methods                         | batch-lift, reconstruct-types                                              |
| `--depth N`            | Traversal depth limit                           | callgraph-tracer, security-dossier                                          |
| `--top N`              | Limit to top-N results                          | classify-functions, map-attack-surface                                     |
| `--output <file>`      | Write output to file                            | generate-re-report, com-interface-reconstruction, reconstruct-types        |
| `--summary`            | Produce abbreviated output                      | batch-lift, callgraph-tracer, generate-re-report                           |
| `--module <name>`      | Scope to a specific module                      | function-index, callgraph-tracer                                           |
| `--tracking-db <path>` | Provide tracking DB for cross-module resolution | callgraph-tracer                                                            |

### Script Entry Point Pattern

All scripts must use a dedicated `main()` function called from the `if __name__` guard. Never put logic directly in the `if __name__` block:

```python
def main():
    parser = argparse.ArgumentParser(description="...")
    parser.add_argument("db_path", help="Path to analysis database")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    db_path = resolve_db_path(args.db_path)
    result = run_analysis(db_path)

    if args.json:
        emit_json(result)
    else:
        print_text_result(result)


if __name__ == "__main__":
    main()
```

### Separate Formatters for JSON vs Human Output

Use separate functions for JSON and human-readable output, not a single function with a `json_mode` parameter. This keeps formatting logic cleanly separated from analysis logic:

```python
def run_analysis(db_path):
    """Core analysis -- returns a data dict."""
    with db_error_handler(db_path, "running analysis"):
        with open_individual_analysis_db(db_path) as db:
            # ... analysis logic ...
            return {"status": "ok", "results": results}


def print_text_result(data):
    """Human-readable formatting."""
    for item in data["results"]:
        print(f"  {item['name']}: {item['score']}")


# In main():
if args.json:
    emit_json(result)
else:
    print_text_result(result)
```

This pattern is used by `triage_summary.py`, `build_dossier.py`, `forward_trace.py`, `discover_entrypoints.py`, and most other scripts. Use `helpers.emit_json()` for JSON output -- it handles serialization, status wrapping, and defaults.

### DB Access and Error Handling

Wrap database operations with the `db_error_handler` context manager. It catches SQLite exceptions and emits structured errors:

```python
with db_error_handler(db_path, "building call graph"):
    with open_individual_analysis_db(db_path) as db:
        # ... DB operations ...
```

For fatal errors outside DB access, call `emit_error()` directly:

```python
if not func:
    emit_error(f"Function '{name}' not found", ErrorCode.NOT_FOUND)
```

### Solve, Don't Punt

Scripts should handle foreseeable error conditions themselves rather than failing and leaving the agent to figure it out. Provide fallback behavior, not just stack traces.

```python
def resolve_module_db(module_name):
    """Resolve module DB, with fallback to extracted_code."""
    db_path = resolve_db_path_auto(WORKSPACE_ROOT, module_name)
    if db_path:
        return db_path
    index_path = find_function_index(module_name)
    if index_path:
        status_message(f"No analysis DB for {module_name}; using function_index.json")
        return None
    emit_error(f"Module '{module_name}' not found in extracted_dbs/ or extracted_code/", "NOT_FOUND")
```

**No voodoo constants.** Configuration parameters must be justified and documented. If you don't know the right value, the agent won't either.

```python
CALLEE_DEPTH = 3
MAX_RESULTS = 50
```

### Input Validation

Validate user-provided identifiers before processing. Use helpers where available:

```python
args.function_id = validate_function_id(args.function_id)  # Validates format
db_path = resolve_db_path(args.db_path)                     # Resolves and checks existence
```

For custom argument validation, use `emit_error()` to produce structured JSON errors:

```python
if args.param < 1:
    emit_error("Parameter number must be >= 1", ErrorCode.INVALID_ARGS)
if not args.function_name and args.function_id is None:
    emit_error("Provide either a function name or --id", ErrorCode.INVALID_ARGS)
```

### Output Channels

- **Stdout**: Reserved for the primary analysis result (JSON or human-readable text).
- **Stderr**: Reserved for progress indicators and error messages.
- **Error Reporting**: Call `helpers.errors.emit_error(message, code)` on terminal failures. This writes a structured JSON object to stderr and exits with code 1.

### Output Quality

**Document scales and units for numeric fields.** Any numeric field in JSON
output that uses a non-obvious scale must be documented in the skill's SKILL.md
or reference.md. Include the scale, range, and a trap example if the field is
commonly misread. Downstream consumers (commands, other skills, the agent) will
misinterpret values if the scale isn't stated:

| Field                | Scale   | Misread Trap                   |
|----------------------|---------|--------------------------------|
| `param_surface`      | dict    | Structured metadata: `has_buffer_size_pair`, `has_string_pointer`, `has_com_interface`, etc. |
| `interest_score`     | 0-10    | Integer, not a fraction        |

**Treat empty results as data points.** When an analysis produces zero results,
still return a valid output structure with an empty results list. Never return
nothing or error out on empty results -- empty results are information that
downstream consumers need:

```python
return {"status": "ok", "results": [], "note": "No entry points detected -- function is internal-only"}
```

**Include provenance metadata.** JSON output should include a `_meta` block with
the DB path used, key parameters, and a timestamp. This enables consumers to
assess freshness and reproduce results:

```python
result = {
    "status": "ok",
    "_meta": {"db": str(db_path), "generated": datetime.utcnow().isoformat(), "params": vars(args)},
    "results": results,
}
```

**Preserve original data fidelity.** Skill scripts should output raw function
signatures, names, and type annotations exactly as stored in the DB.
Transformation (renaming parameters, improving types) belongs in dedicated
lifting/reconstruction workflows, not in analysis scripts. Mixing data retrieval
with data improvement makes it impossible to distinguish DB ground truth from
inference.

### Import Pattern

The preferred import pattern is to import from the skill's `_common.py` module, which handles workspace bootstrap and re-exports helpers. Scripts set up the path to `_common`, then import everything they need from it:

```python
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))

from _common import (
    resolve_db_path,
    open_individual_analysis_db,
    emit_error,
    # ... whatever _common exports
)
```

For scripts that need helpers not re-exported by `_common`, import them directly after the `_common` import:

```python
from _common import resolve_db_path, emit_error
from helpers.callgraph import CallGraph
```

The older pattern of `sys.path.insert(0, str(Path(__file__).resolve().parents[3]))` followed by direct `from helpers import ...` still works but is discouraged for new skills. Routing through `_common` keeps imports centralized and makes skill-wide refactoring easier.

### `_common.py` Bootstrap Pattern

Every skill with scripts should have a `scripts/_common.py`. It serves two purposes:

1. **Infrastructure**: Workspace bootstrap, DB path resolution, and helper re-exports.
2. **Skill-specific domain logic**: Dataclasses, classification algorithms, regex patterns, enums, parsing functions, and constants that are shared across the skill's scripts.

To reduce boilerplate, `skills/_shared/skill_common.py` re-exports the most commonly needed helpers (`emit_error`, `emit_json`, `parse_json_safe`, `open_individual_analysis_db`, `resolve_function`, `get_cached`, `cache_result`, `db_error_handler`, `ScriptError`, etc.). New skills can import it to avoid listing the same helpers individually:

```python
"""Shared utilities for <skill-name> skill."""

from __future__ import annotations
from skills._shared import bootstrap, make_db_resolvers
from skills._shared.skill_common import *  # noqa: F401,F403

WORKSPACE_ROOT = bootstrap(__file__)
resolve_db_path, resolve_tracking_db = make_db_resolvers(WORKSPACE_ROOT)

# Add skill-specific imports and domain logic below...
```

Alternatively, the explicit-import form remains valid and is preferred when only a few helpers are needed:

Minimal `_common.py` (re-export only):

```python
"""Shared utilities for <skill-name> skill."""

from __future__ import annotations
from pathlib import Path
from skills._shared import bootstrap, make_db_resolvers

WORKSPACE_ROOT = bootstrap(__file__)
resolve_db_path, resolve_tracking_db = make_db_resolvers(WORKSPACE_ROOT)

from helpers import (  # noqa: E402
    open_individual_analysis_db,
    emit_error,
)

__all__ = [
    "WORKSPACE_ROOT",
    "resolve_db_path",
    "resolve_tracking_db",
    "open_individual_analysis_db",
    "emit_error",
]
```

In practice, most skills add substantial domain logic to `_common.py`. Examples from existing skills:

- **classify-functions**: `ClassificationResult` dataclass, `classify_function()` algorithm, `NAME_RULES` constants, category definitions
- **com-interface-reconstruction**: `COMInterface`/`WRLClassInfo`/`QIImplementation` dataclasses, COM vtable constants, mangled name parsing functions
- **map-attack-surface**: `EntryPointType` enum, `EntryPoint` dataclass, callback/dangerous-sink API pattern lists, risk scoring functions

When your skill has domain types or algorithms used by multiple scripts, define them in `_common.py` rather than duplicating across scripts.

### Cross-Skill Imports

Skills can import logic from other skills using `helpers.load_skill_module()`. For example, a skill can import the classification algorithm from `classify-functions`:

```python
classify_mod = load_skill_module("classify-functions", "classify_function")
result = classify_mod.classify_single(db, func_id)
```

This is preferable to duplicating classification logic. Declare the dependency in `registry.json` via `depends_on`.

### Workspace Bootstrap

Scripts participating in multi-step pipelines must call `skills._shared.install_workspace_bootstrap()` to enable the workspace handoff protocol.

## 7. Helper Integration Reference

All helpers are importable from the top-level `helpers` package. Skills should use these rather than implementing equivalent logic directly. The tables below are organized by functional area.

### Database Access

| Operation                        | Helper Call                                       |
| -------------------------------- | ------------------------------------------------- |
| Open per-module analysis DB      | `helpers.open_individual_analysis_db(db_path)`    |
| Open tracking DB (module index)  | `helpers.open_analyzed_files_db(db_path)`         |
| Resolve DB path from module name | `helpers.resolve_db_path_auto(workspace, module)` |
| Resolve tracking DB path         | `helpers.resolve_tracking_db_auto(workspace)`     |
| Safe long path (Windows)         | `helpers.safe_long_path(path)`                    |

### Function Resolution

| Operation                            | Helper Call                                         |
| ------------------------------------ | --------------------------------------------------- |
| Resolve by name or ID                | `helpers.resolve_function(db, name_or_id)`          |
| Search by pattern (regex)            | `helpers.search_functions_by_pattern(db, pattern)`  |
| Load function index from JSON        | `helpers.load_function_index_for_db(db_path)`       |
| Lookup function in index             | `helpers.lookup_function(index, name)`              |
| Batch resolve multiple functions     | `helpers.batch_resolve_functions(db, names_or_ids)` |
| Batch extract function data          | `helpers.batch_extract_function_data(db, func_ids)` |
| Batch resolve xref targets           | `helpers.batch_resolve_xref_targets(db, func_ids)`  |
| Filter to application-only functions | `helpers.filter_application_functions(index)`       |
| Filter to decompiled functions       | `helpers.filter_decompiled(index)`                  |
| Check if function has assembly       | `helpers.has_assembly(func_entry)`                  |

### API and String Classification

| Operation                           | Helper Call                                  |
| ----------------------------------- | -------------------------------------------- |
| Classify API by category            | `helpers.classify_api(api_name)`             |
| Classify API for security relevance | `helpers.classify_api_security(api_name)`    |
| Get fingerprint for API set         | `helpers.classify_api_fingerprint(api_list)` |
| Get known dangerous API set         | `helpers.get_dangerous_api_set()`            |
| Access API taxonomy                 | `helpers.API_TAXONOMY`                       |

### Call Graph and Cross-Module Analysis

| Operation                        | Helper Call                                   |
| -------------------------------- | --------------------------------------------- |
| Build call graph from functions  | `helpers.CallGraph.from_functions(functions)` |
| Cross-module graph               | `helpers.CrossModuleGraph(...)`               |
| Module resolver for cross-module | `helpers.ModuleResolver(...)`                 |

### Module Profiles

| Operation                | Helper Call                             |
| ------------------------ | --------------------------------------- |
| Load profile for a DB    | `helpers.load_profile_for_db(db_path)`  |
| Load all module profiles | `helpers.load_all_profiles(workspace)`  |
| Get noise ratio          | `helpers.get_noise_ratio(profile)`      |
| Get technology flags     | `helpers.get_technology_flags(profile)` |

### Error Handling and Output

| Operation                 | Helper Call                                    |
| ------------------------- | ---------------------------------------------- |
| Fatal error (exit 1)      | `helpers.emit_error(msg, "NOT_FOUND")`         |
| Non-fatal warning         | `helpers.log_warning(msg)`                     |
| Non-fatal error log       | `helpers.log_error(msg)`                       |
| DB error context manager  | `helpers.db_error_handler(db_path, operation)` |
| Emit JSON to stdout       | `helpers.emit_json(data)`                      |
| Progress status to stderr | `helpers.status_message(msg)`                  |
| Progress iterator         | `helpers.progress_iter(items, label)`          |

### Caching

| Operation           | Helper Call                                        |
| ------------------- | -------------------------------------------------- |
| Check cache         | `helpers.get_cached(db_path, key, params)`         |
| Store in cache      | `helpers.cache_result(db_path, key, data, params)` |
| Clear cache entries | `helpers.clear_cache(db_path, key)`                |

### Validation

| Operation                      | Helper Call                                  |
| ------------------------------ | -------------------------------------------- |
| Validate workspace data exists | `helpers.validate_workspace_data(workspace)` |
| Validate analysis DB integrity | `helpers.validate_analysis_db(db_path)`      |
| Quick-validate a DB            | `helpers.quick_validate(db_path)`            |
| Validate function ID format    | `helpers.validate_function_id(func_id)`      |

### Parsing and Type Utilities

| Operation                          | Helper Call                                    |
| ---------------------------------- | ---------------------------------------------- |
| Parse class from mangled name      | `helpers.parse_class_from_mangled(name)`       |
| Extract function calls from source | `helpers.extract_function_calls(source)`       |
| Scan struct accesses in assembly   | `helpers.scan_assembly_struct_accesses(asm)`   |
| Scan struct accesses in decompiled | `helpers.scan_decompiled_struct_accesses(src)` |
| IDA type to C type mapping         | `helpers.IDA_TO_C_TYPE`                        |

### Script Runner (Inter-Skill Calls)

| Operation                      | Helper Call                                     |
| ------------------------------ | ----------------------------------------------- |
| Find a skill script by name    | `helpers.find_skill_script(skill, script)`      |
| Run a skill script             | `helpers.run_skill_script(skill, script, args)` |
| Load a skill module in-process | `helpers.load_skill_module(skill, script)`      |
| Get workspace root path        | `helpers.get_workspace_root()`                  |

### Standalone Helper Scripts

These scripts in `.agent/helpers/` can be run directly from the command line:

| Script                 | Purpose                                                           | Usage                                                                        |
| ---------------------- | ----------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `unified_search.py`    | Cross-dimensional search (names, strings, APIs, classes, exports) | `python .agent/helpers/unified_search.py <db> --query <term> [--json]`       |
| `cleanup_workspace.py` | Clean old workspace run directories                               | `python .agent/helpers/cleanup_workspace.py [--older-than DAYS] [--dry-run]` |

For detailed documentation of every symbol, see [helper_api_reference.md](helper_api_reference.md).

## 8. Adding Caching to a Skill Script

Follow the 7-step checklist from [Cache Conventions](cache_conventions.md):

1. Import `get_cached` and `cache_result`.
2. Add `no_cache` keyword argument to the computation function.
3. Implement a cache check at the function entry.
4. Implement a cache store before returning the result.
5. Add the `--no-cache` flag to the `argparse` configuration.
6. Forward the flag to the computation function.
7. Register the operation in the skill's metadata.

## 9. Testing and Iteration

Skills should be tested at varying levels of rigor depending on their complexity and visibility. A foundation skill used by multiple pipelines needs more rigorous testing than a single-purpose analysis script.

### 9.1 Test Fixtures

Use the fixtures defined in `.agent/tests/conftest.py`:

- `sample_db`: Provides a temporary SQLite database with seed data.
- `import_skill_module(skill_name, script_name)`: Dynamically imports a skill script for testing.

Test scripts should validate both human-readable and JSON output modes. Use `subprocess.run()` to execute the script and assert the exit code and stdout content.

### 9.2 Triggering Tests

Verify that the skill loads at the right times based on its description.

**Test cases to cover:**

| Category              | Example Prompts                                   | Expected         |
| --------------------- | ------------------------------------------------- | ---------------- |
| Obvious match         | "Classify all functions in this module"           | Triggers         |
| Paraphrased           | "What does each function in this DLL do?"         | Triggers         |
| Related but different | "Show me the call graph" (for classify-functions) | Does NOT trigger |
| Unrelated             | "Lift the constructor to clean code"              | Does NOT trigger |

**How to test:** Ask the agent directly: "When would you use the [skill-name] skill?" The agent will quote the description back. If its understanding doesn't match your intent, revise the description.

### 9.3 Functional Tests

Verify that the skill produces correct outputs end-to-end.

**Test structure:**

```
Test: Classify functions for a module with 50+ functions
Given: A valid analysis DB with populated xrefs, strings, and assembly
When: triage_summary.py is run with --json
Then:
  - Exit code is 0
  - Output is valid JSON with "status": "ok"
  - Every function has a non-empty "categories" list
  - Category distribution matches known module profile
  - No unhandled exceptions on stderr
```

Run the same request 3-5 times and compare outputs for structural consistency.

### 9.4 Unit Tests for Scripts

Place test files in `.agent/tests/` alongside other test modules. Use pytest and `subprocess.run()` to test each script as a black box:

```python
def test_triage_summary_json_mode(sample_db):
    """Verify JSON mode produces valid structured output."""
    script_path = ".agent/skills/classify-functions/scripts/triage_summary.py"
    result = subprocess.run(
        ["python", script_path, str(sample_db), "--json"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["status"] == "ok"
    assert "functions" in data
```

Test both output modes (human-readable and JSON) for every script. Use the fixtures from `.agent/tests/conftest.py` (`sample_db`, `import_skill_module`) to avoid duplicating setup logic.

### 9.5 Iteration Based on Feedback

Skills are living documents. Watch for these signals and adjust:

**Under-triggering** (skill doesn't load when it should):

- Signal: Users manually invoking the skill or asking "can you classify these functions?"
- Fix: Add more trigger phrases and domain synonyms to the description. Include specific technical terms users might say.

**Over-triggering** (skill loads for unrelated queries):

- Signal: Skill activates when the user asks about something else entirely.
- Fix: Make the description more specific. Add negative scope: "Use for module-wide classification, NOT for individual function analysis."

**Execution issues** (skill loads but produces wrong results):

- Signal: Inconsistent outputs, unhandled errors, agent needing user correction mid-workflow.
- Fix: Improve instructions -- make steps more explicit, add validation gates, add error handling for common edge cases. For critical checks, embed validation in scripts rather than relying on natural language instructions.

**Pro tip:** Iterate on a single challenging task until it succeeds, then extract the winning approach into the skill. This provides faster signal than broad testing across many scenarios.

### 9.6 Evaluation-Driven Development

Create evaluations BEFORE writing extensive documentation. This ensures your skill solves real problems rather than documenting imagined ones.

1. **Identify gaps**: Run the agent on representative tasks without the skill. Document specific failures or missing context.
2. **Create evaluations**: Build 3 scenarios that test these gaps.
3. **Establish baseline**: Measure performance without the skill.
4. **Write minimal instructions**: Create just enough content to address the gaps and pass evaluations.
5. **Iterate**: Run evaluations, compare against baseline, refine.

This approach prevents over-engineering. A skill that passes 3 concrete evaluations is better than a 1000-line skill that was never tested on real tasks.

### 9.7 Observe Navigation Patterns

Watch how the agent actually uses your skill files in practice:

- **Unexpected exploration paths**: Does the agent read files in an order you didn't anticipate? Your structure may not be as intuitive as you thought.
- **Missed references**: Does the agent fail to follow links to important files? Links may need to be more prominent or explicit.
- **Overreliance on one file**: If the agent repeatedly re-reads the same file, that content may belong in SKILL.md directly.
- **Ignored content**: If a bundled file is never accessed, it may be unnecessary or poorly signaled in the main instructions.

Iterate based on observed behavior, not assumptions about how the agent should navigate.

### 9.8 Iterative Development with Agent Instances

The most effective skill development uses two separate agent contexts: one to design the skill and one to test it.

1. **Complete a task without the skill.** Work through a representative problem using normal prompting. Notice what context you repeatedly provide -- DB schemas, analysis procedures, filtering rules, domain conventions.

2. **Extract the reusable pattern.** After completing the task, identify what context would be useful for all similar future tasks. Ask the agent: "Create a skill that captures the workflow we just used. Include the DB access patterns, the classification rules, and the filtering conventions."

3. **Review for conciseness.** Check that the generated SKILL.md doesn't over-explain things the agent already knows. Remove generic programming explanations; keep domain-specific conventions and runtime-specific patterns.

4. **Test with a fresh agent instance.** Use the skill in a new session that has never seen the development context. Give it a real task and observe: Does it find the right information? Does it follow the workflow? Does it apply the rules correctly?

5. **Iterate based on observation.** If the test instance struggles, return to the design instance with specifics: "The agent forgot to pass `--json` when invoking the dossier script. The skill mentions it, but maybe it's not prominent enough." The design instance can suggest restructuring, stronger language, or moving critical rules higher.

6. **Repeat.** Continue this design-test cycle as you encounter new scenarios. Each iteration improves the skill based on real agent behavior, not assumptions.

This works because the design instance understands agent needs, you provide domain expertise, and the test instance reveals gaps through real usage.

### 9.9 Test with Different Model Tiers

Skills may be invoked by subagents using different model tiers (fast vs. standard). A skill that works perfectly with a highly capable model may need more explicit instructions for a faster, less capable one. If your skill may be used across model tiers:

- Test with both fast and standard models
- If the fast model skips steps or misinterprets instructions, add more explicit guidance (exact commands, numbered steps, validation gates)
- Low-freedom instructions (Section 2, Degrees of Freedom) are more reliable across tiers than high-freedom ones

### 9.10 Automated Test Requirements

Every new or modified skill must have corresponding automated tests in `.agent/tests/`. Tests are mandatory, not optional -- they serve as regression guards and prevent silent breakage when skills evolve.

**What to test:**

1. **Registry consistency**: Verify the skill appears in `skills/registry.json` with the correct type, dependencies, and entry scripts. The infrastructure suite (`test_infrastructure_consistency.py`) covers generic consistency, but skill-specific tests should validate domain expectations (e.g., a security skill's `type` is `"security"`, its `depends_on` includes the right foundations).

2. **Script-level functionality**: For each entry script, test the core analysis function with a minimal fixture (not the full DB). Use `helpers.script_runner.load_skill_module()` to import skill modules and call their internal functions directly.

3. **Cross-references**: If the skill is integrated into commands, agents, or other skills, verify those references exist (registry `skills_used` entries, `.md` file mentions of script names). This prevents integration links from silently disappearing during refactoring.

4. **Edge cases**: Empty inputs, missing data, malformed arguments. Verify the skill produces structured errors (`emit_error()`) rather than unhandled exceptions.

**Test file naming**: Use `test_<skill_name_underscored>.py` (e.g., `test_taint_analysis.py`, `test_classify.py`). For integration-focused tests that span multiple skills/commands/agents, use `test_<skill>_integration.py`.

**Running tests:**

```bash
cd .agent && python -m pytest tests/ -v
cd .agent && python -m pytest tests/test_my_skill.py -v
```

Always run the full test suite before considering a skill change complete. A passing `test_infrastructure_consistency.py` validates registry and structural consistency across the entire framework.

## 10. Skill Registration and Discovery

The runtime uses a discovery-based registration model:

1. The `inject-module-context.py` hook scans `.agent/skills/*/SKILL.md` at session start.
2. YAML frontmatter (`name` + `description`) from each skill is extracted and injected into the agent's context as Level 1 metadata.
3. `helpers.script_runner.find_skill_script()` resolves script paths based on the skill directory name.
4. The `registry.json` file provides machine-readable contracts for all skills, including entry scripts, accepted arguments, dependencies, and cacheability.

When adding a new skill, three files outside the skill directory itself must also be updated:

### `registry.json` (required)

Add an entry to `.agent/skills/registry.json` with:

- `purpose`: Brief description
- `type`: Category (`analysis`, `code_generation`, `reconstruction`, `security`, `reporting`, `foundation`, `verification`, `meta`, `index`)
- `entry_scripts`: Array of script objects with `script` name and `accepts` specification
- `depends_on`: Array of skill dependencies (by name)
- `cacheable`: Boolean
- `json_output`: Boolean

This file is consumed by `inject-module-context.py` for session context enrichment and by other tooling for skill routing. If you skip this step, the skill will still be discovered via SKILL.md frontmatter, but agents and coordinators will lack the machine-readable contract needed for automated orchestration.

### `skills/README.md` (required)

Update `.agent/skills/README.md` to include the new skill:

1. **Overview table** -- Add a row with skill name, type, purpose, script count, cacheability, and dependencies.
2. **Dependency graph** -- Add the skill node to the appropriate subgraph (`foundation`, `analysis`, `reconstruction`, `security`, `codeGen`, `reporting`, `meta`) in the Mermaid flowchart, and add edges for any `depends_on` relationships.
3. **Per-skill section** -- Add a `## <skill-name>` section with a brief description, data sources, script table, and example usage.

This README is the primary human-readable catalog of all skills. Omitting it means the skill is invisible to developers browsing the repository.

### `.agent/README.md` (required)

Update the top-level `.agent/README.md`:

1. **Skill count** -- Increment the skill count in the opening paragraph and architecture diagram labels (e.g., "15 analysis skills" becomes "16 analysis skills").
2. **Skills table** -- Add a row to the Skills overview table with skill name, type, script count, cacheability, and purpose.

## 11. Workflow Patterns

These patterns are adapted from common skill architectures to fit the binary analysis domain.

### Pattern Selection

Choose the right pattern before writing workflow instructions. Most skills combine a primary pattern with one or two modifiers.

```
What does the skill's workflow look like?
|
+-- One path, always the same steps
|   +-- Does it modify data or have side effects?
|   |   +-- YES -> Sequential Multi-Phase (Pattern 1) + Safety Gates
|   |   +-- NO  -> Sequential Multi-Phase (Pattern 1)
|   +-- Does it process a batch of items?
|       +-- YES -> add Grind Loop (Pattern 2)
|
+-- Multiple paths depending on user intent or available data
|   +-- Context-Aware Tool Selection (Pattern 3)
|
+-- Output requires iterative validation
|   +-- Feedback Loop (Pattern 5) or Verifiable Intermediates (Pattern 6)
|
+-- Independent steps that can run concurrently
    +-- Parallel Execution (Pattern 7) with Step Dependencies section
```

| Primary Pattern | Use When | Modifiers to Add |
|-----------------|----------|-----------------|
| Sequential Multi-Phase (1) | Ordered pipeline with stage dependencies | + Grind Loop (2) for batch items |
| Context-Aware (3) | Different tools based on available data | + Degradation Paths (8) for missing data |
| Feedback Loop (5) | Output quality depends on iterative validation | + Verifiable Intermediates (6) for expensive steps |
| Parallel Execution (7) | Independent steps that benefit from concurrency | + Resource Lifecycle (9) for temp artifacts |

Domain-Specific Intelligence (Pattern 4) is not a workflow structure -- it's embedded expertise that applies to any pattern. Add it when the skill's value comes from reverse engineering or security knowledge.

### Pattern 1: Sequential Multi-Phase Analysis

Use when the analysis has a natural pipeline with dependencies between stages. Every phase must have **entry criteria** (what must be true before starting) and **exit criteria** (how to know it's done). Without exit criteria, the agent may produce incomplete work for a phase and move on, or loop endlessly.

```markdown
## Workflow: Full Module Triage

### Phase 1: Discovery

**Entry:** User has provided a module name or DB path
1. Resolve module DB via `find_module_db.py`
2. Load module profile from `file_info`
**Exit:** DB path resolves to an existing file; profile contains a valid `module_name`

### Phase 2: Classification

**Entry:** Phase 1 exit criteria met
1. Run `triage_summary.py` to classify all functions
2. Validate: at least 1 function classified
**Exit:** Classification JSON contains >= 1 function with non-empty categories

### Phase 3: Focus Selection

**Entry:** Phase 2 exit criteria met
1. Rank functions by interest score
2. Select top-N for deeper analysis
**Exit:** Selected function list is non-empty; each entry has a valid function ID

### Phase 4: Deep Analysis

**Entry:** Phase 3 exit criteria met
For each selected function:
1. Run `build_dossier.py` for security context
2. Run `trace_callgraph.py` for path analysis
**Exit:** Every selected function has a dossier and call graph result (or a documented failure reason)
```

Key techniques: explicit step ordering, entry/exit criteria on every phase, validation gates between phases, data passing via script output.

### Pattern 2: Iterative Refinement with the Grind Loop

Use when the skill processes multiple discrete items and benefits from the runtime's grind loop protocol (`.agent/hooks/grind-until-done.py`).

```markdown
## Workflow: Batch Function Lifting

### Setup

1. Identify all target functions (e.g., class methods)
2. Create scratchpad with one item per function

### Per-Item Loop

For each unchecked item:

1. Load function source and assembly
2. Lift to clean code
3. Verify against assembly ground truth
4. Check off item in scratchpad

### Completion

When all items are checked, set Status to DONE.
```

Key techniques: scratchpad-driven iteration, bounded retries (up to 10 re-invocations), per-item status tracking. See the [Grind Loop Protocol](../../.cursor/rules/grind-loop-protocol.mdc) for scratchpad format.

### Pattern 3: Context-Aware Tool Selection

Use when the same user goal can be served by different scripts depending on available data.

```markdown
## Workflow: Function Lookup

### Decision Tree

1. Check if analysis DB exists for the module
   - Yes: Use DB-backed resolution via `resolve_function()`
   - No: Fall back to `function_index.json` from `extracted_code/`
2. Check if tracking DB is available
   - Yes: Enable cross-module resolution
   - No: Report single-module scope, continue
3. Check if assembly data is present
   - Yes: Include structural metrics
   - No: Skip assembly-dependent analysis, log warning
```

Key techniques: graceful degradation when data sources are missing, clear fallback paths, transparency about reduced scope.

### Pattern 4: Domain-Specific Intelligence

Use when the skill's value comes from embedded reverse engineering or security expertise, not just tool orchestration.

```markdown
## Workflow: Security Dossier Construction

### Embedded Expertise

Before presenting results, apply domain knowledge:

- **Attack reachability**: An exported function reachable in 1 hop is
  higher priority than one reachable in 5 hops
- **Dangerous API assessment**: `memcpy` with user-controlled size is
  critical; `GetTickCount` is informational noise
- **Complexity thresholds**: Cyclomatic complexity > 25 warrants manual
  review; < 5 is likely trivial
- **Resource patterns**: Functions holding locks across API calls are
  deadlock candidates
```

Key techniques: domain rules embedded in instructions, classification taxonomy baked into scripts (not left to the agent's judgment), risk-ranked output.

### Pattern 5: Feedback Loop

Use when output quality depends on iterative validation. The pattern: run analysis, validate output, fix errors, re-validate.

```markdown
## Workflow: Type Reconstruction with Validation

1. Run `reconstruct_all.py` to scan memory access patterns across all functions
2. Validate output: `python scripts/validate_layout.py reconstructed_types.json`
3. If validation fails:
   - Review the error messages (overlapping fields, impossible sizes)
   - Adjust confidence thresholds or exclude false-positive functions
   - Re-run reconstruction
4. Only proceed to header generation when validation passes
5. Generate headers: `python scripts/generate_headers.py reconstructed_types.json`
```

Key techniques: machine-verifiable validation between steps, explicit re-entry points, the agent iterates on the intermediate output rather than retrying the whole pipeline. Make validation scripts verbose with specific error messages so the agent can fix issues.

**Always bound the loop.** Define a maximum iteration count and an escalation exit. Without a bound, the agent can loop indefinitely trying to fix a structural problem that requires human judgment:

```markdown
3. If validation fails:
   - Review the error messages (overlapping fields, impossible sizes)
   - Adjust confidence thresholds or exclude false-positive functions
   - Re-run reconstruction
   - **If 3 consecutive attempts fail, stop and report**: what was tried, what failed,
     and what the user should investigate manually.
```

**Confidence scoring and drop thresholds.** When a validation pass assigns confidence, define the scale and a hard cutoff:

```markdown
Rate confidence for each surviving finding:
- **1.0**: Evidence directly observed in code, trace fully verified
- **0.8-0.9**: Code matches, finding likely real, minor uncertainty
- **0.6-0.7**: Code mostly matches, finding plausible but not fully traced
- **Below 0.6**: Significant doubts

**Drop** any finding with confidence below 0.7.
```

Also define **priority adjustment rules** (downgrade only, never upgrade) so the agent corrects overstated severity rather than inflating it:

```markdown
- Critical finding not on a commonly-exercised code path --> downgrade to High
- High finding affecting only edge cases or error handlers --> downgrade to Medium
- Never upgrade a finding's priority during validation
```

Explicit thresholds and adjustment rules remove subjective judgment from the validation pass, producing more consistent output across runs.

### Pattern 6: Verifiable Intermediate Outputs

Use for complex multi-step operations where mistakes are expensive. Produce an intermediate plan file, validate it with a script, then execute.

```markdown
## Workflow: Batch Function Lifting with Plan

1. Generate a lift plan:
   `python scripts/batch_extract.py <db_path> --class CMyClass --plan-only --json > lift_plan.json`
   The plan lists functions, dependency order, and shared types.

2. Validate the plan:
   `python scripts/validate_plan.py lift_plan.json`
   Checks: all function IDs exist, dependency order is acyclic, shared types are consistent.

3. If validation fails, fix the plan and re-validate.

4. Execute the plan:
   `python scripts/execute_lift.py lift_plan.json --output lifted/`
```

Key techniques: the intermediate plan file is machine-verifiable, the agent can iterate on the plan without touching original data, and validation catches errors before the expensive lifting step.

### Pattern 7: Parallel Execution

Use when independent steps can run concurrently. Skills with 3+ workflow steps must include a **Step Dependencies** section that maps the full dependency graph so the agent knows which steps to parallelize.

```markdown
## Step Dependencies

- **Step 1 --> Steps 2 + 3**: Classification and string analysis are independent -- run in parallel.
- **Within Step 2**: Batch-classify up to 4 functions at a time.
- **Steps 2 + 3 --> Step 4**: Both must complete before dossier construction begins.
- **Within Step 4**: Functions are independent -- build 2-3 dossiers concurrently for large modules.
- **Step 4 --> Step 5**: Sequential. Reporting requires all dossiers.
```

### Pattern 8: Degradation Paths

Use when a workflow has foreseeable failure modes and partial completion is more useful than a hard stop. List each failure scenario and its fallback behavior in a dedicated **Degradation Paths** section of SKILL.md:

```markdown
## Degradation Paths

1. **Analysis DB missing or corrupted**
   - Report the exact missing DB.
   - Suggest `find_module_db.py --list` to verify available modules.
   - Stop cleanly with a structured error.
2. **Assembly data missing for a function**
   - Continue with decompiled-code-only analysis.
   - Note in the output that assembly-dependent metrics were unavailable.
3. **Cross-module tracking DB unavailable**
   - Continue with single-module scope.
   - Log warning that cross-module resolution was skipped.
4. **A downstream analysis step fails**
   - Report what was completed and flag what was skipped.
   - Do not silently discard completed findings.
```

The key principle: **never silently discard completed work when a later step fails.** Report what was completed, flag what was skipped, and let the user decide whether the partial result is sufficient.

### Pattern 9: Resource Lifecycle

Use when a workflow creates temporary resources (workspace run directories, cached intermediate results, temporary files) that must be cleaned up regardless of outcome.

```markdown
### Step 0: Setup

Create the workspace run directory for multi-step output:
python .agent/helpers/cleanup_workspace.py --create <module>_<goal>

### Step N: Cleanup (mandatory)

Remove temporary workspace artifacts after the report is complete:
python .agent/helpers/cleanup_workspace.py --older-than 1 --dry-run

This step is mandatory even if the workflow was interrupted or produced
no findings.
```

Place setup as the first step and cleanup as the last step. Mark cleanup as **mandatory** and unconditional -- it must run even if intermediate steps fail, produce empty results, or are interrupted.

### Subagent Descriptions

When a workflow delegates parallel work to subagents, the description must name the step and its target so the user can see what each agent is doing.

- Good: `"Classify functions in appinfo.dll"`, `"Build security dossier for AiLaunchAdminProcess"`, `"Trace call graph from export CreateAppInfoService"`
- Bad: `"Process file"`, `"Run analysis"`, `"Step 2"`

### Progress Visibility

Multi-step workflows must emit brief status lines after each major step so the user has visibility into long-running workflows:

- After classification: `"Classified 247 functions (38 interesting, 12 security-relevant). Starting dossier construction..."`
- After batch completion: `"Built 4/12 dossiers. Continuing..."`
- After validation: `"Validated 8 findings (5 survived, 3 dropped). Generating report..."`

The **first progress line** should include scope statistics so the user can verify the target matches their expectations. For example, a module triage outputs function count, noise ratio, and category totals immediately after classification so the researcher can cross-check before the deep analysis begins.

## 12. Troubleshooting

### Skill Does Not Trigger

**Symptom:** The agent never activates the skill even on directly relevant queries.

**Diagnostic:** Ask the agent "When would you use the [skill-name] skill?" If it cannot answer, the frontmatter is not being loaded.

**Fixes:**

- Verify `SKILL.md` is named exactly right (case-sensitive) and has valid `---` delimiters.
- Check that the description includes actual trigger phrases users would say, not just technical implementation details.
- Add more synonyms and paraphrases to the description.

### Skill Triggers Too Often

**Symptom:** The skill loads for unrelated queries.

**Fixes:**

- Make the description more specific. Replace broad terms ("analyzes code") with narrow ones ("classifies functions by API usage category in DeepExtractIDA modules").
- Add scope boundaries: "Use for module-wide triage, NOT for single-function analysis or code lifting."

### Import Errors on Script Execution

**Symptom:** `ModuleNotFoundError: No module named 'helpers'` or similar.

**Fixes:**

- Verify the `sys.path.insert(0, ...)` line uses the correct parent depth. For scripts at `.agent/skills/<name>/scripts/script.py`, the correct depth is `parents[3]` (up to the workspace root).
- Verify `scripts/_common.py` uses `bootstrap(__file__)` from `skills._shared`.
- Check that the workspace root contains the `.agent/helpers/` directory.

### Database Not Found

**Symptom:** `emit_error("...", "NOT_FOUND")` when trying to open a module DB.

**Fixes:**

- Use `find_module_db.py --list` to verify available databases.
- Check that the `extracted_dbs/` directory exists in the workspace root.
- If only `extracted_code/` exists (JSON-only mode), fall back to `function_index.json` -- see the [Missing Dependency Handling](../../.cursor/rules/missing-dependency-handling.mdc) rule.

### JSON Output Invalid or Missing

**Symptom:** Script produces no output or invalid JSON when `--json` is passed.

**Fixes:**

- Ensure the script emits exactly one JSON document to stdout when `--json` is active.
- The JSON root must be a dict with a `"status"` key (`"ok"` or `"error"`).
- Progress/status messages must go to stderr, never stdout. Use `helpers.progress.status_message()`.
- Verify no `print()` calls leak non-JSON text to stdout in JSON mode.

### Instructions Not Followed

**Symptom:** The skill loads but the agent does not follow the workflow.

**Fixes:**

- Keep instructions concise. Use numbered lists and bullet points, not prose paragraphs.
- Put critical instructions at the top with `## Critical` or `## Important` headers.
- Replace ambiguous language with concrete commands:

```markdown
<!-- Bad -->

Make sure to validate things properly.

<!-- Good -->

CRITICAL: Before running deep analysis, verify:

- DB path resolves to an existing file
- The `functions` table has at least 1 row
- The `file_info` table contains a valid `module_name`
```

- For critical checks, embed validation in scripts rather than relying on the agent to follow natural language. Code is deterministic; language interpretation is not.

### Workspace Bootstrap Errors

**Symptom:** Workspace handoff fails, `manifest.json` not created, or steps produce no output.

**Fixes:**

- Verify the script calls `install_workspace_bootstrap()` from `skills._shared`.
- Check that `--workspace-dir` and `--workspace-step` are both passed when running in pipeline mode.
- Ensure the run directory exists and is writable.
- Check `manifest.json` for step status -- failed steps should still write error info.

## 13. Anti-Patterns

Common mistakes that degrade skill quality. Avoid these.

### Avoid time-sensitive information

Don't include dates or version thresholds that will become stale:

```markdown
<!-- Bad: will become wrong -->
If you're doing this before August 2025, use the old API.
After August 2025, use the new API.

<!-- Good: evergreen structure -->
## Current method
Use `helpers.resolve_function(db, name_or_id)` for function lookup.

## Legacy patterns (deprecated)
The older `search_functions_by_name()` helper accepted only exact matches.
It has been replaced by `resolve_function()` which handles IDs, names,
and partial matches.
```

### Use consistent terminology

Pick one term and use it throughout the skill. Inconsistency confuses the agent and produces inconsistent output.

- Always "function" -- not alternating "function", "method", "routine", "procedure"
- Always "analysis DB" -- not "database", "DB file", "SQLite file"
- Always "classify" -- not mixing "classify", "categorize", "triage", "sort"

### Avoid offering too many tool choices

Provide a default tool with an escape hatch for edge cases, not a menu.

```markdown
<!-- Bad: too many choices -->
You can use classify_function.py, or triage_summary.py, or query the DB
directly, or call helpers.classify_api() in inline Python...

<!-- Good: default with escape hatch -->
Use `classify_function.py` for single-function classification:
python .agent/skills/classify-functions/scripts/classify_function.py <db_path> --id <func_id> --json

For module-wide classification, use `triage_summary.py` instead.
```

### Avoid Windows-style paths

Always use forward slashes in file paths, even on Windows. This runtime runs on Windows, but backslashes cause escaping issues in Markdown, shell commands, and JSON:

- Good: `.agent/skills/classify-functions/scripts/triage_summary.py`
- Bad: `.agent\skills\classify-functions\scripts\triage_summary.py`

### Avoid deeply nested references

Keep reference files one level deep from SKILL.md. Chains where SKILL.md links to A.md which links to B.md cause the agent to partially read nested references, resulting in incomplete information:

```markdown
<!-- Bad: too deep -->
# SKILL.md → methodology.md → detailed-checklist.md → examples.md

<!-- Good: one level deep -->
# SKILL.md
**Core workflow**: [instructions in SKILL.md]
**Analysis checklist**: See [reference.md](reference.md)
**User guide**: See [README.md](README.md)
```

### End every workflow with a verification step

Workflows that end with "output the results" and no validation produce plausible but incorrect output. Every workflow should conclude with some form of output check -- the form depends on the skill:

- **Script-based skills**: Run a validation script on the output (`validate_layout.py`)
- **Classification skills**: Spot-check a sample of results against known ground truth
- **Report skills**: Verify that all input data is represented and no placeholder text remains
- **Lifting skills**: Run the verifier agent against the lifted code

If the verification step is omitted, the agent treats the first draft as final and moves on -- even when the output contains obvious errors.

### Avoid reference dumps

Pasting raw API docs, full specifications, or exhaustive schema definitions into SKILL.md wastes tokens without improving behavior. The agent already has general programming knowledge. What it needs is _judgment_: when to use technique A vs B, what tradeoffs to consider, what mistakes to avoid.

```markdown
<!-- Bad: raw documentation dump -->
## API Reference
CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
  dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile)
  lpFileName: The name of the file or device to be created or opened...
  [200 more lines of MSDN documentation]

<!-- Good: judgment and context -->
## When to Use CreateFileW vs NtCreateFile
Use CreateFileW for standard file operations. Use NtCreateFile when:
- You need to set specific object attributes (OBJ_CASE_INSENSITIVE)
- You need to access NT-native paths (\Device\HarddiskVolume1\...)
- The decompiled code uses Nt* directly (don't convert to Win32 equivalents)
```

Teach the agent when and how to apply knowledge, not the knowledge itself.

### Avoid cartesian product tool calls

When a workflow searches N functions for M patterns, combine patterns into a single regex and search once. The agent won't actually execute N x M calls -- it will shortcut by scanning a few items, skipping patterns, or summarizing early, silently missing results.

```markdown
<!-- Bad: 50 functions x 12 patterns = 600 search calls -->
For each function, search the decompiled source for each of these 12 dangerous APIs:
  CreateProcess, memcpy, LoadLibrary, ...

<!-- Good: 1 regex search, then filter -->
Search all decompiled sources for `CreateProcess|memcpy|LoadLibrary|...` (single combined regex).
Filter results to the target function set.
```

### Avoid unbounded subagent spawning

When a workflow processes multiple items (functions, findings, modules), batch them into fixed-size groups. "Spawn one subagent per function" doesn't scale -- with 200 functions, the agent hits context limits or produces degraded results.

```markdown
<!-- Bad: 1 subagent per function -->
For each function discovered in Phase 2, spawn a subagent to build its security dossier.

<!-- Good: batched -->
Batch discovered functions into groups of 10-15. For each batch, spawn a single
subagent with the function list and instructions to build dossiers for all of them.
```

Apply the **10,000-function test**: mentally run the workflow against a large module and verify that subagent count and tool call count stay bounded. If either grows linearly with input size, redesign.

## 14. Quick Checklist

Use this checklist to validate a skill before considering it complete.

### Before You Start

- [ ] Identified 2-3 concrete use cases with expected triggers and outcomes
- [ ] Identified which helpers and data sources are needed
- [ ] Reviewed existing skills for patterns to reuse
- [ ] Planned the folder structure

### During Development

- [ ] Folder named in kebab-case, matches `name` in frontmatter
- [ ] `SKILL.md` exists with exact spelling
- [ ] YAML frontmatter has `---` delimiters, `name`, and `description`
- [ ] Description includes WHAT (capability) and WHEN (trigger phrases)
- [ ] Description contains triggering conditions only -- no workflow steps
- [ ] Description is written in third person
- [ ] No XML angle brackets in frontmatter
- [ ] "When to Use" and "When NOT to Use" sections present (naming alternatives in the NOT section)
- [ ] SKILL.md body is under 500 lines
- [ ] Reference files are one level deep from SKILL.md (no nested chains)
- [ ] No time-sensitive information (or in "legacy patterns" section)
- [ ] Consistent terminology throughout (no synonymous alternation)
- [ ] `scripts/_common.py` follows the bootstrap pattern
- [ ] All scripts use `argparse` with `db_path`, `--json`, and `--no-cache` (if cacheable)
- [ ] Scripts handle foreseeable errors themselves (solve, don't punt)
- [ ] No voodoo constants (all config values justified)
- [ ] Stdout is data only; stderr is progress/errors only
- [ ] Error handling uses `emit_error()` with appropriate error codes
- [ ] Instructions are specific and actionable, not vague
- [ ] References to other docs or scripts use correct relative paths
- [ ] File references use forward slashes (not backslashes)
- [ ] Skills with 2+ scripts use a shared `_common.py` for import bootstrap
- [ ] Skills with 3+ workflow steps include a Step Dependencies section
- [ ] Parallel subagent descriptions name the step and target (not generic)
- [ ] Multi-step workflows emit progress after each major step
- [ ] Prompt patterns documented for the 2-3 most common user inputs
- [ ] Execution guardrails use deny / conditional-deny / allow structure (if applicable)
- [ ] Degradation paths documented for foreseeable failure modes
- [ ] Resource lifecycle: cleanup/teardown steps are unconditional (if applicable)
- [ ] Output language constraints defined when certainty matters (if applicable)
- [ ] Scope exclusions documented (if applicable)
- [ ] "Rationalizations to Reject" section included (for security/assessment skills)
- [ ] No cartesian product tool calls (combine patterns into single regex)
- [ ] No unbounded subagent spawning (batch items into fixed-size groups)
- [ ] Workflow phases have entry and exit criteria
- [ ] Workflow ends with a verification step (script validation, spot-check, or verifier agent)
- [ ] No reference dumps (teach judgment, not raw documentation)
- [ ] Entry added to `skills/registry.json` with correct type, scripts, dependencies
- [ ] Row added to `skills/README.md` overview table
- [ ] Skill node added to `skills/README.md` dependency graph (Mermaid)
- [ ] Per-skill section added to `skills/README.md` with description, scripts, usage
- [ ] Skill count updated in `.agent/README.md` opening paragraph
- [ ] Row added to `.agent/README.md` Skills table

### Before Merge

- [ ] Triggering tests pass: activates on relevant queries, does not activate on unrelated queries
- [ ] Functional tests pass: correct JSON output, correct human-readable output, proper exit codes
- [ ] Edge cases handled: empty DB, missing tables, function not found
- [ ] Caching implemented (if the operation is expensive)
- [ ] Ran the workflow 3+ times and got structurally consistent results
- [ ] Observed agent navigation patterns and adjusted structure if needed
- [ ] All three external files updated: `registry.json`, `skills/README.md`, `.agent/README.md`
- [ ] Automated tests added or updated in `.agent/tests/` (see section 9.10)
- [ ] Existing test suite passes: `cd .agent && python -m pytest tests/ -v`
