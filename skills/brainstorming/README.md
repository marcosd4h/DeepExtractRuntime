# Brainstorming

Collaborative design dialogue for planning research strategy, scoping analysis
approaches, and designing new skills or tools -- before any implementation
begins.

**This is a documentation-only skill.** It has no scripts. It guides the
agent's behavior during design conversations to ensure structured thinking,
trade-off analysis, and user approval before action.

## When to Use

- Planning a vulnerability research campaign against a module
- Scoping an analysis approach (which commands, which order, what depth)
- Designing a new skill, agent, or command for the runtime
- Any request that benefits from structured dialogue before implementation

## Workflow

1. **Gather context** -- Check available modules, prior analysis results
   (cached triage, attack surface data), and relevant documentation.

2. **Clarify requirements** -- Ask focused questions one at a time using the
   AskQuestion tool. Prefer multiple-choice when the answer space is bounded.

3. **Propose 2-3 approaches** -- Each with trade-offs (effort vs. depth,
   breadth vs. focus) and a recommended option.

4. **Present design** -- Walk through in sections scaled to complexity. Check
   understanding after each section. Iterate on disagreements.

5. **Transition** -- Once approved, produce an implementation plan via the
   CreatePlan tool. Do not begin implementation within this skill.

## Question Templates

### Vulnerability Research Planning

| Question | Why It Matters |
|----------|---------------|
| Which module or component? | Scopes the target surface |
| What vulnerability class? (memory corruption, logic bug, privesc, race) | Determines which skills and commands to prioritize |
| Threat model? (local vs remote, privilege level, trust boundaries) | Filters relevant entry points and attack vectors |
| Deep single-function audit or broad pattern scan? | Sets the time/depth trade-off |
| Any prior triage or classification data? | Avoids redundant work |

### Tool / Skill Design

| Question | Why It Matters |
|----------|---------------|
| What problem does this solve? | Defines success criteria |
| Who consumes the output? (agent, user, another skill) | Determines output format |
| What existing helpers can it reuse? | Avoids reinventing infrastructure |
| What are the hard constraints? (performance, DB schema, caching) | Bounds the solution space |

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

## Files

```
brainstorming/
├── SKILL.md    # Agent skill instructions (read by Cursor)
└── README.md   # This file
```

## Related Skills

- [adversarial-reasoning](../adversarial-reasoning/SKILL.md) -- Structured VR methodology, hypothesis generation, attack pattern playbooks
- [classify-functions](../classify-functions/SKILL.md) -- Module-wide function categorization (often the first data gathered during brainstorming)
- [map-attack-surface](../map-attack-surface/SKILL.md) -- Entry point discovery and risk ranking
- [generate-re-report](../generate-re-report/SKILL.md) -- Comprehensive module report for context gathering
