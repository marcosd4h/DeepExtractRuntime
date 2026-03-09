# Brainstorm

## Overview

Strategic research planning for vulnerability research campaigns, cross-module investigations, post-analysis re-planning, and tool/skill design. Complements `/hunt` (which is tactical and hypothesis-driven for a single module) by operating at the strategic layer: deciding which workflows to use, composing end-to-end research pipelines, spanning multiple modules, and incorporating prior results.

The text after `/brainstorm` determines the **planning mode**:

- `/brainstorm appinfo.dll` -- campaign mode (default): strategic VR campaign planning
- `/brainstorm cross appinfo.dll consent.exe` -- cross-module campaign
- `/brainstorm replan` -- post-analysis re-planning from prior results
- `/brainstorm design <topic>` -- tool/skill/agent/command design

If omitted, ask the user what they want to plan.

## IMPORTANT: Execution Model

**This is a collaborative dialogue command. Do NOT run analysis, write code, or execute scripts.** The purpose is to produce an approved design that transitions into an implementation plan via CreatePlan. All implementation happens after the user approves.

Read the **brainstorming** skill (`SKILL.md`) and follow its workflow. For campaign and cross-module modes, also read **adversarial-reasoning** (`SKILL.md`) on demand when you need vulnerability class knowledge, Windows security mental models, or the research prioritization rubric to inform approach selection.

## Relationship to /hunt

`/brainstorm` is the **strategist**; `/hunt` is the **tactician**.

| Dimension | `/brainstorm` | `/hunt` |
|-----------|---------------|---------|
| Scope | Multi-module, multi-workflow | Single module, single campaign |
| Output | End-to-end pipeline with workflow selection | Ranked hypothesis list with per-hypothesis commands |
| VR depth | Selects and composes workflows | Generates and scores testable hypotheses |
| Handoff | Produces CreatePlan with specific command sequences | Produces hunt plan file for `/hunt-execute` |
| Best for | "Where do I start?", "What workflow?", "What next?" | "What specific bugs might exist in this module?" |

When the researcher's goal resolves to single-module hypothesis-driven VR, recommend `/hunt` rather than duplicating its work. Use `/brainstorm` for the strategic wrapper around `/hunt` when needed.

## Steps

### 0. Detect mode

Parse the user's input to determine the planning mode:

| Input pattern | Mode | Description |
|---|---|---|
| `<module>` or `<topic> in <module>` | `campaign` | Strategic VR campaign for one module |
| `cross <mod1> <mod2> [...]` | `cross-module` | Multi-module coordinated campaign |
| `replan` or "what next" or "what should I do" | `replan` | Re-plan from prior analysis results |
| `design <topic>` | `design` | Tool/skill/agent/command design |

Default to `campaign` when only a module name is provided.

### 1. Gather context

Check what data is already available before asking questions:

- Review session context for available modules and module profiles
- Check `.agent/cache/` and `.agent/workspace/` for prior triage, classification, attack surface, scan, or audit results
- Check for existing hunt plans in `.agent/workspace/`
- Note which skills and commands are relevant to the goal
- If a specific module is mentioned, check whether `/triage` output exists

For **replan** mode, also:
- Check `/prioritize` output or cached scan results across modules
- Review workspace run manifests for completed analysis steps
- Note which commands have already been run and their key findings

### 2. Mode-specific questioning and planning

Use the AskQuestion tool for focused questions. Tailor to the mode.

---

#### Mode: Campaign

Strategic VR campaign planning for a single module. Focuses on selecting the right workflow and composing an end-to-end pipeline.

**Questions (ask 1-2 at a time, adapt based on prior answers):**

For intermediate researchers (first time with this module, no prior triage):
- What is the module? (if not specified)
- What kind of assessment: broad reconnaissance, targeted vulnerability hunting, or privilege boundary audit?
- Any specific vulnerability class interest, or explore broadly first?
- Time budget: quick triage (30 min), focused audit (2-4 hours), or deep campaign (multi-session)?

For advanced researchers (have prior context, specific goals):
- What prior analysis exists? (triage, scan, audit results)
- What specific attack scenario or vulnerability class?
- Attacker model: privilege level, entry vector, trust boundary crossings?
- Constraints: specific functions, IPC surfaces, or code paths of interest?

**Approach selection -- read adversarial-reasoning SKILL.md for the Windows security mental models and research prioritization rubric, then recommend:**

| Researcher goal | Recommended workflow | When to use |
|---|---|---|
| "I know nothing about this binary" | Recon pipeline | No prior triage; module is unfamiliar |
| "Where are the bugs?" | Broad detection pipeline | Want automated coverage, not hypothesis-driven |
| "I think there's a privesc here" | Hypothesis-driven hunt | Have a specific vulnerability hypothesis |
| "Audit the IPC handlers" | Privilege boundary pipeline | Module exposes RPC/COM/WinRT/pipe interfaces |
| "Deep dive on one function" | Deep audit pipeline | Have a specific function of interest |
| "Find variants of CVE-XXXX" | Variant hunt pipeline | Known bug pattern to search for |

Present 2-3 approaches with trade-offs, lead with your recommendation and explain why. Include the complete pipeline template (see Pipeline Templates below).

---

#### Mode: Cross-Module

Multi-module coordinated campaign. Use when the research target spans DLL boundaries, involves loader-level dependencies, or requires cross-module taint propagation.

**Questions:**
- Which modules and why? (shared attack surface, dependency chain, same subsystem)
- Attacker model: entry module vs target module? Lateral movement path?
- What cross-module relationship matters: import/export dependencies, cross-DLL taint, shared data structures, COM client/server pairs?
- Prior analysis: any modules already triaged or scanned?

**Approach selection:**

| Cross-module scenario | Recommended workflow |
|---|---|
| Dependency chain (A calls B calls C) | Per-module `/triage` -> `/imports` for dependency graph -> `/data-flow-cross` for cross-DLL tracking -> `/taint` with `--cross-module` |
| Shared attack surface (A and B expose similar APIs) | Per-module `/triage` -> `/compare-modules` -> parallel `/batch-audit` -> `/prioritize --all` |
| COM/RPC client-server | `/com` or `/rpc` to map interfaces -> trace from client to server -> `/audit` server-side handlers |
| Variant hunting across modules | `/hunt variant <pattern>` per module -> `/prioritize` to rank cross-module |
| Privilege escalation chain | Map trust boundaries across modules -> `/taint` from low-priv entry to high-priv sink -> `/audit` boundary-crossing functions |

---

#### Mode: Replan

Post-analysis re-planning. Consume results from prior commands to decide what to investigate next.

**Context gathering (check all of these):**
- Cached scan results: `.agent/cache/<module>/`
- Workspace runs: `.agent/workspace/` manifests
- Hunt plans (executed or not): `.agent/workspace/*_hunt_plan_*.json`
- Prioritized findings: prior `/prioritize` output

**Questions:**
- What analysis has been done so far? (review cached/workspace data to pre-populate)
- What was the most interesting finding or area?
- What hasn't been explored yet?
- Should we go deeper on existing findings or broaden to new areas?

**Approach selection:**

| Situation | Recommended next step |
|---|---|
| Triage done, no scanning | `/scan` for automated detection or `/hunt` for hypothesis-driven |
| Scan done, unverified findings | `/audit` on top findings, or `/hunt validate` for specific suspects |
| Scan done, few findings | `/hunt` to generate hypotheses the scanner may have missed (logic bugs, TOCTOU, confused deputy) |
| Multiple modules scanned | `/prioritize --all` to rank cross-module, then `/audit` top hits |
| Hunt executed, confirmed findings | Exploitability deep-dive: `/audit` with full dossier, assess PoC feasibility |
| Hunt executed, all refuted | Pivot: different vulnerability class, different entry points, or `/full-report` for comprehensive recon |
| Audit done on key functions | Cross-module trace if findings touch DLL boundaries; `/hunt variant` if pattern is reusable |

---

#### Mode: Design

Structured tool/skill/agent/command design. For extending the DeepExtract runtime.

**Read the relevant authoring guide first:**
- Command design: `docs/command_authoring_guide.md`
- Skill design: `docs/skill_authoring_guide.md`
- Agent design: `docs/agent_authoring_guide.md`
- Helper design: `helpers/README.md`

**Questions:**
- What does the tool do? (single clear purpose)
- Who consumes it? (researcher via command, another skill, an agent, a pipeline)
- What existing skills/helpers does it build on?
- What data does it need? (DB tables, JSON metadata, decompiled code, assembly)
- Should it be cacheable? (deterministic output from same DB input?)
- Does it need a grind loop? (processes 3+ items iteratively)

**Design checklist (present each section, get approval incrementally):**

1. **Purpose and scope**: one sentence, clear boundaries, explicit non-goals
2. **Integration points**: which existing skills it depends on, which commands will use it
3. **Data access pattern**: DB queries, JSON reads, decompiled code parsing
4. **Helper reuse**: map operations to existing helpers (`helpers/README.md` catalog)
5. **Output format**: human-readable default, `--json` structured output, workspace protocol if multi-step
6. **Error handling**: error codes, graceful degradation, missing data fallback
7. **Caching strategy**: cache keys, TTL, invalidation triggers
8. **Pipeline integration**: can it be a pipeline step? What YAML config does it accept?
9. **Testing plan**: unit tests for logic, integration tests via `qa_runner.py`
10. **Registry entries**: `registry.json` fields, `README.md` additions

### 3. Present the plan

Structure the output based on mode:

**Campaign / Cross-Module:**
- **Situation assessment**: what data exists, what the module profile reveals, key characteristics
- **Threat model**: attacker profile, privilege level, entry vectors, trust boundaries
- **Recommended workflow**: selected pipeline template with rationale
- **Pipeline steps**: ordered sequence with specific commands, parameters, and decision points
- **Comprehension gates**: where to apply deep-context-builder before auditing complex functions
- **Scoring strategy**: how findings will be ranked (exploitability-assessment dimensions, `/prioritize`)
- **Success criteria**: what constitutes a finding, when to stop or pivot
- **Estimated effort**: command count, expected session time, decision points

**Replan:**
- **Progress summary**: what has been analyzed, key findings so far
- **Gap analysis**: what hasn't been explored, what hypotheses remain untested
- **Recommended next steps**: prioritized list with commands and rationale
- **Decision criteria**: when to stop the current line vs pivot

**Design:**
- Walk through the design checklist sections, checking after each

### 4. Iterate

Revise on disagreement. The researcher may:
- Reject an approach and request alternatives
- Add constraints (time, scope, specific targets)
- Request deeper detail on a pipeline step
- Ask for a different mode
- Want to combine elements from multiple approaches

Loop between steps 2-3 as needed until the researcher approves.

### 5. Transition

Once approved, use the CreatePlan tool to produce an actionable implementation plan with:
- Specific commands to run in order, with full parameters
- Decision points after each command (what to look for, when to pivot)
- Expected outputs and how to interpret them
- Follow-up actions based on results
- For VR campaigns: explicit recommendation of `/hunt` or `/hunt-execute` where hypothesis-driven work is needed

## Pipeline Templates

Reference these when recommending end-to-end workflows. Each template includes the full research lifecycle: reconnaissance, comprehension, investigation, and scoring.

### Recon Pipeline

For unfamiliar modules where the researcher needs orientation first.

```
/triage <module>                          # Classify, attack surface, recommendations
/full-report <module> --brief             # Deeper recon if triage reveals complexity
-> Review: entry point types, IPC surface, dangerous API categories
-> Decision: pick workflow based on findings
```

### Broad Detection Pipeline

Automated vulnerability scanning with verification and prioritization.

```
/triage <module>                          # Classify and discover entry points
/scan <module> --top 15                   # Memory + logic + taint scanning
-> Review: severity distribution, verified findings
/prioritize                               # Rank findings (if multi-module)
/audit <module> <top_finding>             # Deep audit on top 1-3 findings
```

### Hypothesis-Driven Hunt Pipeline

Strategic planning followed by structured hypothesis testing.

```
/triage <module>                          # Prerequisite reconnaissance
/hunt <module>                            # Generate ranked hypotheses
-> Review: approve/modify the hunt plan
/hunt-execute <module>                    # Automated investigation
-> Review: confirmed vs refuted hypotheses
/audit <module> <confirmed_func>          # Deep audit on confirmed findings
```

### Privilege Boundary Pipeline

Targeted at IPC handler security (RPC, COM, WinRT, named pipes).

```
/triage <module>                          # Identify IPC surface
/com <module>  | /rpc <module> | /winrt <module>  # Enumerate interfaces
/batch-audit <module> --privilege-boundary         # Audit all IPC handlers
-> Review: cross-function patterns, shared guard weaknesses
/hunt validate <module> <suspect>                  # Confirm specific findings
```

### Deep Audit Pipeline

Single-function deep dive with comprehension phase.

```
/triage <module>                          # Context (skip if already done)
/explain <module> <function>              # Structural understanding
-> Apply deep-context-builder methodology for complex functions
/audit <module> <function>                # Full security audit
/verify <module> <function>               # Decompiler accuracy check
-> If finding confirmed: /taint for full path, exploitability assessment
```

### Cross-Module Taint Pipeline

Following attacker-controlled data across DLL boundaries.

```
/triage <mod_entry>                       # Entry module recon
/triage <mod_target>                      # Target module recon
/imports --function <api> --consumers     # Map import/export relationship
/data-flow-cross forward <mod_entry> <func>       # Cross-DLL data flow
/taint <mod_target> <handler> --cross-module      # Taint with cross-module
-> Review: trust boundary crossings, guard coverage
/audit <mod_target> <sink_func>                   # Audit the sink function
```

### Variant Hunt Pipeline

Searching for siblings of a known bug pattern across modules.

```
/hunt variant <pattern> <module>          # Decompose pattern, design search
-> Review: candidate list from search queries
/taint <module> <candidate>               # Verify taint path matches pattern
/verify <module> <candidate>              # Decompiler accuracy on candidates
-> Repeat across modules if cross-module variant hunt
/prioritize --all                         # Rank all variant candidates
```

## Research Phase Reference

When proposing approaches, map research needs to the full toolkit:

| Phase | Need | Commands | Skills |
|-------|------|----------|--------|
| **Recon** | Module identity and posture | `/triage`, `/full-report` | generate-re-report, classify-functions |
| **Recon** | Function classification | `/triage`, `/search` | classify-functions |
| **Recon** | String intelligence | `/strings` | string-intelligence |
| **Recon** | Import/export relationships | `/imports` | import-export-resolver |
| **Surface** | Entry point discovery | `/triage` | map-attack-surface |
| **Surface** | IPC interface enumeration | `/com`, `/rpc`, `/winrt` | com-interface-analysis, rpc-interface-analysis, winrt-interface-analysis |
| **Surface** | Trust boundary mapping | `/hunt surface` | adversarial-reasoning, map-attack-surface |
| **Surface** | Dispatch/command handlers | `/state-machines` | state-machine-extractor |
| **Comprehension** | Function understanding | `/explain` | analyze-ida-decompiled, deep-context-builder |
| **Comprehension** | Deep pre-audit context | `/explain --depth 3` | deep-context-builder, deep-research-prompt |
| **Comprehension** | Decompiler verification | `/verify` | verify-decompiled |
| **Comprehension** | Type/struct recovery | `/reconstruct-types` | reconstruct-types, com-interface-reconstruction |
| **Comprehension** | Code lifting | `/lift-class` | code-lifting, batch-lift |
| **Investigation** | Call chain tracing | `/trace-export`, `/callgraph` | callgraph-tracer |
| **Investigation** | Data flow analysis | `/data-flow`, `/data-flow-cross` | data-flow-tracer |
| **Investigation** | Taint analysis | `/taint` | taint-analysis |
| **Investigation** | Hypothesis testing | `/hunt`, `/hunt-execute` | adversarial-reasoning |
| **Investigation** | Security audit | `/audit`, `/batch-audit` | security-dossier, taint-analysis |
| **Detection** | Memory corruption scan | `/memory-scan`, `/scan` | memory-corruption-detector |
| **Detection** | Logic vulnerability scan | `/logic-scan`, `/scan` | logic-vulnerability-detector |
| **Detection** | Unified scan | `/scan --auto-audit` | memory-corruption-detector, logic-vulnerability-detector, taint-analysis |
| **Scoring** | Exploitability assessment | (integrated in `/audit`, `/scan`) | exploitability-assessment |
| **Scoring** | Cross-module prioritization | `/prioritize` | exploitability-assessment |
| **Scoring** | Finding verification | (integrated in `/scan`, `/audit`) | finding-verification |

## Output

The output is an approved research design in the chat conversation, followed by a CreatePlan implementation plan. No files are written by this command (unlike `/hunt`, which persists a plan file).

## Error Handling

- **No modules available**: Suggest running `/health` to check workspace state
- **Module not triaged yet**: Suggest running `/triage <module>` first, then returning to `/brainstorm`
- **Vague goal**: Ask narrowing questions -- don't guess at the user's intent
- **Goal resolves to single-module hypothesis VR**: Recommend `/hunt` instead -- it has deeper adversarial-reasoning integration for that use case
- **No prior results for replan mode**: Suggest starting with `/triage` or `/quickstart`, then return to `/brainstorm replan` after initial analysis
- **Design topic overlaps existing skill/command**: Point to the existing implementation and ask if the researcher wants to extend it or build something new
