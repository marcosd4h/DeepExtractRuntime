# Hunt Plan

## Overview

Hypothesis-driven vulnerability research planning. Uses the **adversarial-reasoning** skill to generate testable attack hypotheses, match observations to known Windows attack patterns, plan variant analysis, and validate suspected findings -- all mapped to concrete workspace commands.

The text after `/hunt-plan` specifies the **mode** and **target**:

- `/hunt-plan appinfo.dll` -- campaign mode (default): plan a full VR campaign
- `/hunt-plan hypothesis TOCTOU appinfo.dll` -- test a specific vulnerability hypothesis
- `/hunt-plan variant junction appinfo.dll` -- find variants of a known attack pattern
- `/hunt-plan validate appinfo.dll AiLaunchProcess` -- validate a suspected finding and plan PoC
- `/hunt-plan surface appinfo.dll` -- map trust boundaries and prioritize attack vectors

If no arguments are provided, ask the user what they want to investigate.

## IMPORTANT: Execution Model

**This is a collaborative dialogue command. Do NOT run analysis, write code, or execute scripts.** The purpose is to produce an approved research design with testable hypotheses that transitions into an implementation plan via CreatePlan. All investigation happens after the user approves.

Read the **adversarial-reasoning** skill (`SKILL.md`) and follow its research mode workflows. Load `reference.md` on demand when you need vulnerability class details, attack pattern specifics, or playbook steps.

## Steps

### 1. Detect mode

Parse the user's input to determine the research mode:

| First argument | Mode | Description |
|---|---|---|
| *(module name only)* | `campaign` | Plan a full VR campaign against the module |
| `hypothesis` | `hypothesis` | Formulate and test a specific vulnerability hypothesis |
| `variant` | `variant` | Find variants of a known bug class or attack pattern |
| `validate` | `validate` | Confirm/refute a suspected vulnerability and plan PoC |
| `surface` | `surface` | Map trust boundaries and prioritize attack vectors |

Default to `campaign` when only a module name is provided.

### 2. Gather existing context

Check what data is already available before asking questions:

- Review session context for available modules and module profiles
- Check `.agent/cache/` and `.agent/workspace/` for prior triage, classification, or attack surface results
- Note which modules have been analyzed and what data exists
- If a specific module is mentioned, check whether `/triage` output exists

If the module has not been triaged, recommend running `/triage <module>` first (especially for `campaign` and `surface` modes).

### 3. Mode-specific questioning

Ask focused questions using the AskQuestion tool. Tailor to the mode:

**Campaign mode:**
- Target module and any specific components of interest
- Threat model: local attacker, network client, sandboxed process? What privilege level?
- Time budget: deep single-target audit or broad pattern scan?
- Vulnerability class focus: logic bugs, memory corruption, or both?
- Prior knowledge: known CVEs in this component? Similar components with known bugs?

**Hypothesis mode:**
- What is the specific hypothesis? (e.g., "TOCTOU in the file path handler")
- What evidence supports it so far?
- What has already been ruled out?
- Which function(s) are involved?

**Variant mode:**
- What is the known bug pattern? (CVE number, bug class, code structure)
- Which aspects of the pattern should match? (API, data flow, entry type, missing check)
- Which modules to search? (specific module or all)
- What was the original exploitation outcome?

**Validate mode:**
- Which function is suspicious?
- What pattern was observed? (specific code construct, API usage, data flow)
- What makes it suspicious? (missing check, unguarded path, attacker-reachable)
- What checks have already been attempted?

**Surface mode:**
- Attacker profile: local user, network client, sandboxed process, other?
- Privilege level of the attacker (low IL, medium IL, AppContainer)
- Known entry vectors (any exports, IPC mechanisms, or handlers already identified)
- What is the privilege level of the target module?

### 4. Apply adversarial-reasoning methodology

Read the adversarial-reasoning SKILL.md and apply the framework for the detected mode:

**Campaign mode:**
1. Review the module profile: entry point types, IPC surface, dangerous API categories
2. Apply the hypothesis generation framework to produce 3-7 hypotheses from entry point types, classification signals, data flow patterns, and code patterns
3. Rank hypotheses using the prioritization rubric (Exploitability x Impact x Novelty x Feasibility)
4. For each top hypothesis, map to specific workspace commands using the workspace integration table
5. If vulnerability class details are needed, load reference.md Section A

**Hypothesis mode:**
1. Classify the hypothesis into a vulnerability class (reference.md Section A)
2. Identify confirmation and refutation criteria using the hypothesis templates (reference.md Section E)
3. Map to the validation strategy matrix (SKILL.md)
4. Produce 3-5 prioritized commands to test the hypothesis

**Variant mode:**
1. Decompose the known pattern using reference.md Section D methodology
2. Design search queries and taint traces to find candidates
3. Define the filtering criteria for each candidate
4. Produce a variant search plan with specific commands

**Validate mode:**
1. Apply the validation strategy matrix for the suspected vulnerability class
2. Determine: static confirmation possible? dynamic testing needed?
3. Produce: confirmation checklist, PoC skeleton guidance, severity assessment

**Surface mode:**
1. Enumerate trust boundaries from the module profile and entry point data
2. For each boundary crossing, identify security checks and potential weaknesses
3. Rank attack vectors using the prioritization rubric
4. Suggest investigation commands for the top vectors

### 5. Present the research plan

Structure the output as:

**Threat model summary:**
- Attacker profile, privilege level, entry vectors
- Target module identity and privilege level
- Trust boundaries identified

**Ranked hypotheses** (campaign/surface modes) or **focused investigation plan** (hypothesis/variant/validate modes):
- Each hypothesis: statement, reasoning, evidence strength, priority score
- Per-hypothesis investigation commands with specific parameters
- Validation criteria: what confirms, what refutes

**Estimated effort:**
- Number of commands to run
- Expected investigation sequence
- Decision points (when to stop or pivot)

### 6. Iterate

Revise on disagreement. The researcher may:
- Reject hypotheses as unlikely and request alternatives
- Add constraints (time budget, specific vulnerability class focus)
- Request deeper detail on a specific hypothesis or attack pattern
- Ask for a different mode

Loop between steps 3-5 as needed until the researcher approves the plan.

### 7. Persist the hunt plan

Save the approved plan to `.agent/workspace/<module>_hunt_plan_<timestamp>.json` (using `YYYYMMDD_HHMM` for timestamp) with this schema:

```json
{
  "module": "<module_name>",
  "mode": "<campaign|hypothesis|variant|validate|surface>",
  "hypotheses": [
    {
      "id": 1,
      "statement": "...",
      "priority": 8,
      "commands": ["/taint <module> <func>", "/audit <module> <func>"],
      "validation_criteria": {
        "confirms": "...",
        "refutes": "..."
      }
    }
  ],
  "threat_model": {
    "attacker_profile": "...",
    "privilege_level": "...",
    "entry_vectors": ["..."]
  },
  "created_at": "<ISO 8601 timestamp>"
}
```

This file allows `/hunt-execute` to pick up the plan even across session boundaries or after context compaction.

### 8. Transition

Once approved, use the CreatePlan tool to produce an actionable implementation plan with:
- Specific commands to run in order
- Decision points after each command
- Expected outputs and how to interpret them
- Follow-up actions based on results

## Output

The output is an approved research design in the chat conversation, followed by a CreatePlan implementation plan. The plan is also saved to `.agent/workspace/` for use by `/hunt-execute`.

## Error Handling

- **No modules available**: Suggest running `/health` to check workspace state
- **Module not triaged yet**: Suggest running `/triage <module>` first, then returning to `/hunt-plan`
- **Vague goal**: Ask narrowing questions -- don't guess at the user's intent
- **Unknown vulnerability class**: Load reference.md to check if the class is documented; if not, apply general principles from the hypothesis generation framework
- **No hypotheses generated**: The module may have minimal attack surface. Report this finding (it is still useful information) and suggest `/full-report` for comprehensive analysis
