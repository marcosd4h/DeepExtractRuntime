# Brainstorm

## Overview

Collaboratively plan a vulnerability research campaign, analysis strategy, or new tool/skill design before taking action. Uses structured dialogue to clarify goals, explore approaches, and converge on an approved design.

The text after `/brainstorm` is the **research goal or topic** (e.g., `/brainstorm privilege escalation in appinfo.dll`). If omitted, ask the user what they want to explore.

## IMPORTANT: Execution Model

**This is a collaborative dialogue command. Do NOT run analysis, write code, or execute scripts.** The purpose is to produce an approved design that transitions into an implementation plan via CreatePlan. All implementation happens after the user approves.

Read the **brainstorming** skill (`SKILL.md`) and follow its workflow.

## Steps

1. **Gather context**
   Check what data is already available for the research goal:
   - Review session context for available modules and module profiles
   - If a specific module is mentioned, check whether triage or attack surface data already exists in `.agent/workspace/` or `.agent/cache/`
   - Note which skills and commands are relevant to the goal

2. **Clarify requirements**
   Ask focused questions one at a time using the AskQuestion tool. Tailor questions to the research type:

   **VR campaign planning:**
   - Target module, component, or function class
   - Vulnerability hypothesis (memory corruption, logic bug, privilege escalation, race condition, type confusion)
   - Threat model (local vs remote, privilege level, trust boundaries)
   - Scope (deep single-function audit vs broad pattern scan vs call-chain trace)
   - Prior analysis already completed

   **Tool / skill design:**
   - Purpose, constraints, success criteria
   - Integration with existing skills and helpers
   - Output format and consumers

3. **Propose 2-3 approaches**
   Present options with trade-offs, mapping each to available commands and skills:

   | Research need | Commands | Skills |
   |---------------|----------|--------|
   | Reconnaissance | `/triage`, `/explain` | classify-functions, generate-re-report |
   | Attack surface | `/triage`, `/full-report` | map-attack-surface, security-dossier |
   | Data flow | `/data-flow`, `/data-flow-cross` | data-flow-tracer, taint-analysis |
   | Call chains | `/trace-export` | callgraph-tracer |
   | Code understanding | `/explain`, `/verify` | code-lifting, verify-decompiled |
   | Structure recovery | `/reconstruct-types`, `/lift-class` | reconstruct-types, com-interface-reconstruction |
   | Dispatch / state | `/state-machines` | state-machine-extractor |

   Lead with your recommended approach and explain why.

4. **Present design**
   Walk through the research plan in sections scaled to complexity. Check after each section. Sections to cover as applicable:
   - **Threat model**: attacker profile, entry vectors, trust boundaries
   - **Target scope**: modules, function classes, entry points
   - **Analysis pipeline**: ordered sequence of commands/skills to run
   - **Success criteria**: what a finding looks like, when to stop
   - **Validation strategy**: how to confirm findings (verify decompiler, cross-reference assembly)

5. **Iterate**
   Revise on disagreement. Loop between steps 2-4 as needed.

6. **Transition**
   Once approved, use the CreatePlan tool to produce an actionable implementation plan with specific commands and parameters.

## Output

The output is an approved research design in the chat conversation, followed by a CreatePlan implementation plan. No files are written by this command.

## Error Handling

- **No modules available**: Suggest running `/health` to check workspace state
- **Module not triaged yet**: Suggest running `/triage <module>` first, then returning to `/brainstorm`
- **Vague goal**: Ask narrowing questions -- don't guess at the user's intent
