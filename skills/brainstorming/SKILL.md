---
name: brainstorming
description: "Collaborate on research strategy and design before implementation. Use when the user wants to plan a vulnerability research campaign, scope an analysis approach, design a new skill or tool, or requests any creative or design work."
---

# Brainstorming

Collaborative design dialogue: gather context, ask focused questions, propose approaches with trade-offs, validate before implementation.

**Do not write code, run analysis, or take implementation action until the user approves the design.**

## Workflow

1. **Gather context** -- Check available modules, prior analysis results, and relevant docs. For VR campaigns, review module profiles, triage output, and attack surface data if available.
2. **Clarify requirements** -- Ask questions one at a time using the AskQuestion tool. Prefer multiple-choice when the answer space is bounded.
3. **Propose 2-3 approaches** -- With trade-offs and a recommended option. For analysis campaigns, map approaches to available skills (see Analysis Toolkit below).
4. **Present design** -- Walk through in sections scaled to complexity. Check after each section. Iterate on disagreements.
5. **Transition** -- Once approved, use the CreatePlan tool to produce an implementation plan.

## Questioning Focus

**VR research planning:**
- Target: which module, component, or function class?
- Hypothesis: vulnerability class (memory corruption, logic bug, privilege escalation, race condition, type confusion)?
- Threat model: local vs remote attacker, privilege level, trust boundaries?
- Scope: deep single-function audit vs broad pattern scan vs call-chain trace?
- Prior work: any triage, classification, or attack surface mapping already done?

**Tool / skill design:**
- Purpose, constraints, success criteria
- Integration points with existing skills and helpers
- Output format and consumer expectations

## Analysis Toolkit Reference

When proposing VR strategies, map research needs to available skills:

| Need | Skills |
|------|--------|
| Reconnaissance | classify-functions, generate-re-report |
| Attack surface | map-attack-surface, security-dossier |
| Data flow | data-flow-tracer, taint-analysis |
| Call chains | callgraph-tracer |
| Code understanding | code-lifting, verify-decompiled, analyze-ida-decompiled |
| Structure recovery | reconstruct-types, com-interface-reconstruction |
| Dispatch / state | state-machine-extractor |
| Deep research | deep-research-prompt |

## Design Presentation

- Scale depth to complexity: brief for straightforward decisions, detailed for nuanced ones
- Ask for approval incrementally for complex designs
- Apply YAGNI: cut speculative elements before presenting

## Completion

Terminal state: approved design transitioned into an implementation plan via the CreatePlan tool. Do not begin implementation within this skill.
