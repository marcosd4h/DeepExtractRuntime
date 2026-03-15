# Hunt Plan

## Overview

Hypothesis-driven vulnerability research planning and strategic campaign design. Generates testable attack hypotheses, matches observations to known Windows attack patterns, plans variant analysis, and validates suspected findings -- all mapped to concrete workspace commands. Also covers strategic planning at the campaign, cross-module, replan, and design levels.

The command supports **8 modes** selected by the first argument:

- `/hunt-plan appinfo.dll` -- campaign mode (default): plan a full VR campaign
- `/hunt-plan hypothesis TOCTOU appinfo.dll` -- test a specific vulnerability hypothesis
- `/hunt-plan variant junction appinfo.dll` -- find variants of a known attack pattern
- `/hunt-plan validate appinfo.dll AiLaunchProcess` -- validate a suspected finding and plan PoC
- `/hunt-plan surface appinfo.dll` -- map trust boundaries and prioritize attack vectors
- `/hunt-plan cross appinfo.dll consent.exe` -- plan a cross-module taint and data flow campaign
- `/hunt-plan replan` -- re-plan from prior analysis results
- `/hunt-plan design <topic>` -- design a new tool, skill, agent, or command

If no arguments are provided, ask the user what they want to investigate.

## IMPORTANT: Execution Model

**This is a collaborative dialogue command. Do NOT run analysis, write code, or execute scripts.** The purpose is to produce an approved research design with testable hypotheses that transitions into an implementation plan via CreatePlan. All investigation happens after the user approves.

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
| `cross` | `cross-module` | Plan a cross-module taint and data flow investigation |
| `replan` | `replan` | Re-plan based on prior analysis results |
| `design` | `design` | Design a new tool, skill, agent, or command |

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

**Cross-Module mode:**
- Which modules and why? (shared attack surface, dependency chain, same subsystem)
- Attacker model: entry module vs target module? Lateral movement path?
- What cross-module relationship matters: import/export dependencies, cross-DLL taint, shared data structures, COM client/server pairs?
- Prior analysis: any modules already triaged or scanned?

**Approach selection for cross-module:**

| Cross-module scenario | Recommended workflow |
|---|---|
| Dependency chain (A calls B calls C) | Per-module `/triage` -> `/imports` for dependency graph -> `/taint` with `--cross-module` |
| Shared attack surface (A and B expose similar APIs) | Per-module `/triage` -> `/compare-modules` -> parallel `/batch-audit` -> `/prioritize --all` |
| COM/RPC client-server | `/com` or `/rpc` to map interfaces -> trace from client to server -> `/audit` server-side handlers |
| Variant hunting across modules | `/hunt-plan variant <pattern>` per module -> `/prioritize` to rank cross-module |
| Privilege escalation chain | Map trust boundaries across modules -> `/taint` from low-priv entry to high-priv sink -> `/audit` boundary-crossing functions |

**Replan mode:**
- What analysis has been done so far? (review cached/workspace data to pre-populate)
- What was the most interesting finding or area?
- What hasn't been explored yet?
- Should we go deeper on existing findings or broaden to new areas?

**Context gathering for replan (check all of these):**
- Cached scan results: `.agent/cache/<module>/`
- Workspace runs: `.agent/workspace/` manifests
- Hunt plans (executed or not): `.agent/workspace/*_hunt_plan_*.json`
- Prioritized findings: prior `/prioritize` output

**Approach selection for replan:**

| Situation | Recommended next step |
|---|---|
| Triage done, no scanning | `/scan` for automated detection or `/hunt-plan` for hypothesis-driven |
| Scan done, unverified findings | `/audit` on top findings, or `/hunt-plan validate` for specific suspects |
| Scan done, few findings | `/hunt-plan` to generate hypotheses the scanner may have missed (logic bugs, TOCTOU, confused deputy) |
| Multiple modules scanned | `/prioritize --all` to rank cross-module, then `/audit` top hits |
| Hunt executed, confirmed findings | Exploitability deep-dive: `/audit` with full dossier, assess PoC feasibility |
| Hunt executed, all refuted | Pivot: different vulnerability class, different entry points, or `/full-report` for comprehensive recon |
| Audit done on key functions | Cross-module trace if findings touch DLL boundaries; `/hunt-plan variant` if pattern is reusable |
| No prior results | Suggest starting with `/triage`, then return to `/hunt-plan replan` after initial analysis |

**Design mode:**

Read the relevant authoring guide first:
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

### 4. Apply adversarial reasoning methodology

**Campaign mode:**
1. Review the module profile: entry point types, IPC surface, dangerous API categories
2. Generate 3-7 hypotheses from entry point types, classification signals, data flow patterns, and code patterns
3. Rank hypotheses by Exploitability x Impact x Novelty x Feasibility
4. For each top hypothesis, map to specific workspace commands

**Hypothesis mode:**
1. Classify the hypothesis into a vulnerability class
2. Identify confirmation and refutation criteria
3. Produce 3-5 prioritized commands to test the hypothesis

**Variant mode:**
1. Decompose the known pattern into searchable characteristics
2. Design search queries and taint traces to find candidates
3. Define the filtering criteria for each candidate
4. Produce a variant search plan with specific commands

**Validate mode:**
1. Determine: static confirmation possible? dynamic testing needed?
2. Produce: confirmation checklist, PoC skeleton guidance, severity assessment

**Surface mode:**
1. Enumerate trust boundaries from the module profile and entry point data
2. For each boundary crossing, identify security checks and potential weaknesses
3. Rank attack vectors by exploitability and impact
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
- For VR campaigns: explicit recommendation of `/hunt-execute` where hypothesis-driven work is needed

## Pipeline Templates

Reference these when recommending end-to-end workflows. Each template includes the full research lifecycle: reconnaissance, comprehension, investigation, and scoring.

### T1 Recon Pipeline

For unfamiliar modules where the researcher needs orientation first.

```
/triage <module>                          # Classify, attack surface, recommendations
/full-report <module> --brief             # Deeper recon if triage reveals complexity
-> Review: entry point types, IPC surface, dangerous API categories
-> Decision: pick workflow based on findings
```

### T2 Broad Detection Pipeline

Automated vulnerability scanning with verification and prioritization.

```
/triage <module>                          # Classify and discover entry points
/scan <module> --top 15                   # Memory + logic + taint scanning
-> Review: severity distribution, verified findings
/prioritize                               # Rank findings (if multi-module)
/audit <module> <top_finding>             # Deep audit on top 1-3 findings
```

### T3 Hypothesis-Driven Hunt Pipeline

Strategic planning followed by structured hypothesis testing.

```
/triage <module>                          # Prerequisite reconnaissance
/hunt-plan <module>                       # Generate ranked hypotheses
-> Review: approve/modify the hunt plan
/hunt-execute <module>                    # Automated investigation
-> Review: confirmed vs refuted hypotheses
/audit <module> <confirmed_func>          # Deep audit on confirmed findings
```

### T4 Privilege Boundary Pipeline

Targeted at IPC handler security (RPC, COM, WinRT, named pipes).

```
/triage <module>                          # Identify IPC surface
/com <module>  | /rpc <module> | /winrt <module>  # Enumerate interfaces
/batch-audit <module> --privilege-boundary         # Audit all IPC handlers
-> Review: cross-function patterns, shared guard weaknesses
/hunt-plan validate <module> <suspect>             # Confirm specific findings
```

### T5 Deep Audit Pipeline

Single-function deep dive with comprehension phase.

```
/triage <module>                          # Context (skip if already done)
/explain <module> <function>              # Structural understanding
/audit <module> <function>                # Full security audit
-> If finding confirmed: /taint for full path, exploitability assessment
```

### T6 Cross-Module Taint Pipeline

Following attacker-controlled data across DLL boundaries.

```
/triage <mod_entry>                       # Entry module recon
/triage <mod_target>                      # Target module recon
/imports --function <api> --consumers     # Map import/export relationship
/taint <mod_target> <handler> --cross-module      # Taint with cross-module
-> Review: trust boundary crossings, guard coverage
/audit <mod_target> <sink_func>                   # Audit the sink function
```

### T7 Variant Hunt Pipeline

Searching for siblings of a known bug pattern across modules.

```
/hunt-plan variant <pattern> <module>     # Decompose pattern, design search
-> Review: candidate list from search queries
/taint <module> <candidate>               # Verify taint path matches pattern
-> Repeat across modules if cross-module variant hunt
/prioritize --all                         # Rank all variant candidates
```

## Research Phase Reference

When proposing approaches, map research needs to the full toolkit:

| Phase | Need | Commands | Skills |
|-------|------|----------|--------|
| **Recon** | Module identity and posture | `/triage`, `/full-report` | generate-re-report, classify-functions |
| **Recon** | Function classification | `/triage`, `/search` | classify-functions |
| **Recon** | Import/export relationships | `/imports` | import-export-resolver |
| **Surface** | Entry point discovery | `/triage` | map-attack-surface |
| **Surface** | IPC interface enumeration | `/com`, `/rpc`, `/winrt` | com-interface-analysis, rpc-interface-analysis, winrt-interface-analysis |
| **Surface** | Trust boundary mapping | `/hunt-plan surface` | map-attack-surface |
| **Comprehension** | Function understanding | `/explain` | re-analyst, decompiled-code-extractor |
| **Comprehension** | Type/struct recovery | `/reconstruct-types` | reconstruct-types, com-interface-reconstruction |
| **Comprehension** | Code lifting | `/lift-class` | batch-lift |
| **Investigation** | Call chain tracing | `/audit --diagram`, `/callgraph` | callgraph-tracer |
| **Investigation** | Taint analysis | `/taint` | ai-taint-scanner |
| **Investigation** | Hypothesis testing | `/hunt-plan`, `/hunt-execute` | -- |
| **Investigation** | Security audit | `/audit`, `/batch-audit` | security-dossier |
| **Detection** | Memory corruption scan | `/memory-scan`, `/scan` | ai-memory-corruption-scanner |
| **Detection** | Logic vulnerability scan | `/ai-logical-bug-scan`, `/scan` | ai-logic-scanner |
| **Detection** | Unified scan | `/scan --auto-audit` | ai-memory-corruption-scanner, ai-logic-scanner, ai-taint-scanner |
| **Scoring** | Exploitability assessment | (integrated in `/audit`, `/scan`) | exploitability-assessment |
| **Scoring** | Cross-module prioritization | `/prioritize` | exploitability-assessment |

## Output

The output is an approved research design in the chat conversation, followed by a CreatePlan implementation plan. The plan is also saved to `.agent/workspace/` for use by `/hunt-execute`.

## Error Handling

- **No modules available**: Suggest running `/health` to check workspace state
- **Module not triaged yet**: Suggest running `/triage <module>` first, then returning to `/hunt-plan`
- **Vague goal**: Ask narrowing questions -- don't guess at the user's intent
- **Unknown vulnerability class**: Load reference.md to check if the class is documented; if not, apply general principles from the hypothesis generation framework
- **No hypotheses generated**: The module may have minimal attack surface. Report this finding (it is still useful information) and suggest `/full-report` for comprehensive analysis
- **No prior results for replan mode**: Suggest starting with `/triage`, then return to `/hunt-plan replan` after initial analysis
- **Design topic overlaps existing skill/command**: Point to the existing implementation and ask if the researcher wants to extend it or build something new
- **Goal resolves to single-module hypothesis VR**: Use `campaign` mode directly
