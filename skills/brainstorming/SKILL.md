---
name: brainstorming
description: "Strategic research planning for VR campaigns, cross-module investigations, post-analysis re-planning, and tool/skill design. Use when the user wants to plan a research strategy, decide which workflow to use, scope a multi-module campaign, re-plan after initial analysis, or design a new tool/skill/command."
---

# Brainstorming

Strategic planning dialogue: assess the situation, select the right workflow, compose end-to-end research pipelines, and validate the design before implementation. Complements **adversarial-reasoning** (which provides tactical hypothesis generation for single-module VR) by operating at the strategic layer.

**Do not write code, run analysis, or take implementation action until the user approves the design.**

## Planning Modes

Detect the mode from the user's request. Default to `campaign` when a module name is provided without other qualifiers.

| Mode | When | Output |
|------|------|--------|
| **campaign** | VR campaign planning for a module | End-to-end pipeline with workflow selection |
| **cross-module** | Investigation spanning multiple modules | Coordinated multi-module plan with dependency-aware ordering |
| **replan** | "What next?" after prior analysis | Gap analysis + prioritized next steps from cached results |
| **design** | Tool/skill/agent/command design | Structured design document following authoring guides |

## Workflow

1. **Gather context** -- Check available modules, module profiles, prior analysis in `.agent/cache/` and `.agent/workspace/`. For replan mode, also check workspace run manifests, hunt plans, and `/prioritize` output.
2. **Clarify requirements** -- Ask questions one at a time using the AskQuestion tool. Prefer multiple-choice when the answer space is bounded. Adapt question depth to researcher experience (fewer questions for researchers who arrive with specific goals and prior context).
3. **Select workflow** -- Match the researcher's goal to the appropriate pipeline template (see below). For campaign mode, consult **adversarial-reasoning** (`SKILL.md`) on demand for Windows security mental models and the research prioritization rubric to inform approach selection.
4. **Present design** -- Walk through in sections scaled to complexity. Check after each section. Iterate on disagreements.
5. **Transition** -- Once approved, use the CreatePlan tool to produce an implementation plan.

## Questioning Focus

### Campaign / Cross-Module

Adapt depth to the researcher's experience level:

**Intermediate researchers** (need guidance on workflow selection):
- What is the target module(s)?
- What kind of assessment: broad recon, targeted hunting, or privilege boundary audit?
- Vulnerability class interest, or explore broadly first?
- Time budget: quick triage, focused audit, or deep multi-session campaign?

**Advanced researchers** (arrive with specific goals):
- What prior analysis exists? (check cache/workspace to pre-populate)
- Specific attack scenario, vulnerability class, or threat model?
- Constraints: specific functions, IPC surfaces, code paths?

### Replan

- What has been analyzed so far? (review cached results before asking)
- Most interesting finding or area from prior work?
- Go deeper on existing findings or broaden to new areas?

### Design

- What does the tool do? (single clear purpose)
- Who consumes it? (researcher, skill, agent, pipeline)
- What existing skills/helpers does it build on?
- Should it be cacheable? Need grind loop?

## Pipeline Templates

Match researcher goals to end-to-end workflows. Each template covers the full lifecycle: reconnaissance, comprehension, investigation, and scoring.

| Researcher goal | Pipeline | Key commands |
|---|---|---|
| Unfamiliar module | Recon | `/triage` -> `/full-report --brief` -> select next workflow |
| Find bugs broadly | Broad detection | `/triage` -> `/scan --auto-audit` -> `/prioritize` |
| Test a hypothesis | Hypothesis hunt | `/triage` -> `/hunt-plan` -> `/hunt-execute` -> `/audit` confirmed |
| Audit IPC handlers | Privilege boundary | `/triage` -> `/com`/`/rpc`/`/winrt` -> `/batch-audit --privilege-boundary` |
| Deep single function | Deep audit | `/explain` -> deep-context-builder -> `/audit` -> `/verify` |
| Cross-DLL taint | Cross-module taint | per-module `/triage` -> `/imports` -> `/data-flow-cross` -> `/taint --cross-module` |
| Find bug variants | Variant hunt | `/hunt-plan variant` per module -> `/taint` candidates -> `/prioritize` |

When the researcher's goal resolves to single-module hypothesis-driven VR, recommend `/hunt-plan` instead of duplicating its work.

## Companion Skills

Read these on demand during planning:

| Skill | When to read | What it provides |
|---|---|---|
| **adversarial-reasoning** | Campaign/cross-module mode, VR approach selection | Windows security mental models, trust boundary framework, research prioritization rubric, hypothesis generation templates |
| **deep-context-builder** | Recommending comprehension gates in the pipeline | Structured pre-audit comprehension methodology |
| **deep-research-prompt** | Recommending evidence gathering during planning | Multi-skill context gathering for functions or modules |
| **exploitability-assessment** | Including scoring steps in the pipeline | Finding ranking dimensions (taint severity, primitive quality, guard bypass, reachability) |

## Research Phase Reference

Map research needs to available skills when composing pipeline steps:

| Phase | Skills |
|-------|--------|
| Recon | classify-functions, generate-re-report, string-intelligence, import-export-resolver |
| Attack surface | map-attack-surface, com-interface-analysis, rpc-interface-analysis, winrt-interface-analysis, state-machine-extractor |
| Comprehension | analyze-ida-decompiled, deep-context-builder, deep-research-prompt, verify-decompiled, reconstruct-types, com-interface-reconstruction, code-lifting, batch-lift |
| Investigation | callgraph-tracer, data-flow-tracer, taint-analysis, security-dossier, adversarial-reasoning |
| Detection | memory-corruption-detector, logic-vulnerability-detector |
| Scoring | exploitability-assessment, finding-verification |

## Design Methodology

For `design` mode, read the relevant authoring guide and follow this checklist:

1. **Purpose and scope**: one sentence, clear boundaries, explicit non-goals
2. **Integration points**: dependencies on existing skills, consumers (commands, agents, pipelines)
3. **Data access**: DB queries, JSON metadata, decompiled code, assembly
4. **Helper reuse**: map operations to `helpers/README.md` catalog
5. **Output format**: human-readable default + `--json` structured output
6. **Error handling**: error codes, graceful degradation
7. **Caching**: cache keys, TTL, invalidation
8. **Pipeline integration**: YAML step config
9. **Testing**: unit tests + `qa_runner.py` integration tests
10. **Registry**: `registry.json` + `README.md` entries

Present each section and get incremental approval.

## Design Presentation

- Scale depth to complexity: brief for straightforward decisions, detailed for nuanced ones
- Ask for approval incrementally for complex designs
- Apply YAGNI: cut speculative elements before presenting
- For pipeline recommendations, always include decision points ("if X, do Y; if Z, pivot to W")

## Completion

Terminal state: approved design transitioned into an implementation plan via the CreatePlan tool. Do not begin implementation within this skill.
