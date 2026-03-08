# Agent Authoring Guide

This guide describes how to create new subagents for the DeepExtractIDA Agent
Analysis Runtime. Subagents are specialized agents that handle complex,
multi-step tasks by orchestrating multiple skills in isolated context windows.

**Prerequisite reading:** Skim `.agent/agents/README.md` for the agent catalog
and `.agent/docs/skill_authoring_guide.md` Section 7 for helper imports.

---

## 1. When to Create an Agent vs. Use a Skill

Use this decision matrix before creating a new agent:

| Criterion | Skill (script) | Agent (subagent) |
|-----------|----------------|------------------|
| Completes in one step | Yes | Overkill |
| Needs multi-step orchestration | No | Yes |
| Maintains state across functions | No | Yes (e.g., code-lifter) |
| Benefits from isolation / fresh eyes | No | Yes (e.g., verifier) |
| Requires a different persona/mindset | No | Yes |
| Called by multiple commands | Common | Less common |
| Needs parallel execution with other work | No | Yes |

**Rule of thumb:** If the task is a single script call with well-defined input
and output, it belongs in a skill. If it requires chaining 3+ skill scripts,
accumulating shared state, or deliberately isolating context, create an agent.

---

## 2. Directory Structure

```
.agent/agents/
├── my-agent.md                # Agent definition (system prompt)
├── my-agent/
│   └── scripts/
│       ├── _common.py         # Workspace bootstrap + shared utilities
│       ├── main_task.py       # Primary entry script
│       └── helper_task.py     # Additional scripts (optional)
├── registry.json              # Machine-readable registry (add entry here)
└── README.md                  # Human-readable catalog (add entry here)
```

---

## 3. Agent Definition File (`.md`)

The definition file is the system prompt that defines the agent's persona,
capabilities, and workflow. All five existing agents follow a consistent
structure:

### 3.1 YAML Frontmatter

```yaml
---
name: my-agent
description: "One-sentence purpose statement for registry and context injection."
---
```

### 3.2 Persona and Anti-Persona

Open with a strong identity statement. Contrast with other agents to prevent
role confusion:

```markdown
You are a **security pattern scanner** specializing in automated vulnerability
pattern detection across DeepExtractIDA module databases.

You are NOT an analyst (that is the re-analyst agent) and NOT a code lifter.
Your job is to scan, match, and rank -- not to explain or rewrite code.
```

Every existing agent uses this pattern:

| Agent | Persona | Anti-persona |
|-------|---------|--------------|
| re-analyst | "reverse engineering analyst" | (implicit: does not modify code) |
| triage-coordinator | "expert reverse-engineering analysis coordinator" | (implicit: delegates, does not deep-analyze) |
| code-lifter | "code lifting specialist" | "You are NOT an analyst" |
| verifier | "skeptical verification agent" | (implicit: assumes nothing from prior context) |
| type-reconstructor | "specialised subagent for C/C++ struct and class reconstruction" | "You are NOT a security auditor" |

### 3.3 When to Use / When NOT to Use

Include scoping sections that help the parent agent (or user) choose the right
subagent. "When NOT to Use" must name the specific alternative:

```markdown
## When to Use
- Scanning a module for known vulnerability patterns before manual review
- Quick triage of which functions to investigate for specific vuln classes

## When NOT to Use
- Explaining what a function does -- use **re-analyst**
- Lifting decompiled code to clean C++ -- use **code-lifter**
- Verifying lifted code accuracy -- use **verifier**
```

These sections scope behavior after the agent is launched. They prevent the
agent from expanding into tasks that belong to a different agent, which is the
most common source of agent role confusion in multi-agent workflows.

### 3.4 Skill Catalog

List every skill the agent can use with script paths and invocation examples.
Organize by purpose, not by skill name:

```markdown
## Available Scripts

### Module Discovery
| Script | Purpose |
|--------|---------|
| `find_module_db.py` | Resolve module name to DB path |
| `list_functions.py` | List functions in a module |

### Analysis
| Script | Purpose |
|--------|---------|
| `classify_function.py` | Classify a single function |
| `build_dossier.py` | Build security context for a function |
```

Include full invocation examples with `--json` for at least the primary scripts.

### 3.5 Workflow Templates

Define step-by-step workflows for each task the agent handles. Use numbered
steps with concrete script invocations:

```markdown
### Workflow: Scan Module for Patterns

1. Resolve module DB: `find_module_db.py <module>`
2. Classify all functions: `classify_module.py <db_path> --json`
3. For each function with dangerous APIs:
   a. Extract function data: `extract_function_data.py <db_path> --id <id> --json`
   b. Run pattern matching against the extracted code
   c. Score the match confidence
4. Rank findings by score and return top-N
```

### 3.6 Error Handling Table

Define how the agent responds to common failures:

```markdown
## Error Handling

| Scenario | Behavior |
|----------|----------|
| Module DB not found | List available modules, ask user to clarify |
| Function not found | Try fuzzy search, report best matches |
| Skill script fails (exit 1) | Parse stderr JSON error, report to user, continue if non-fatal |
| DB query returns empty | Report "no data" with explanation, do not fabricate results |
```

### 3.7 Domain Reference Material (Optional)

For domain-heavy agents, include compact reference sections:

- **re-analyst**: IDA naming glossary, Hex-Rays artifact recognition, Windows
  internals cheat sheet (x64 calling convention, COM vtable layout, SEH)
- **verifier**: x64 register reference, branch instruction signedness, memory
  access size patterns
- **type-reconstructor**: C++ object model, memory alignment rules, COM
  interface layout

Only include material the agent needs frequently during its work. Link to
external references for depth.

---

## 4. Shared Utilities (`_common.py`)

Every agent script directory needs a `_common.py` that handles workspace
resolution and provides agent-specific utilities. The bootstrap pattern:

```python
from __future__ import annotations

import sys
from pathlib import Path

from skills._shared import bootstrap

WORKSPACE_ROOT = bootstrap(__file__)
sys.path.insert(0, str(WORKSPACE_ROOT / ".agent"))

SKILLS_DIR = WORKSPACE_ROOT / ".agent" / "skills"
EXTRACTED_DBS_DIR = WORKSPACE_ROOT / "extracted_dbs"
EXTRACTED_CODE_DIR = WORKSPACE_ROOT / "extracted_code"

from helpers import emit_error, parse_json_safe
from helpers.errors import ErrorCode
from helpers.script_runner import run_skill_script
from helpers.config import get_config
```

### Agent-Specific Utilities

Add agent-specific helpers below the bootstrap. Examples from existing agents:

**triage-coordinator** -- Module fingerprinting for adaptive routing:

```python
@dataclasses.dataclass
class ModuleCharacteristics:
    is_com_heavy: bool = False
    is_rpc_heavy: bool = False
    is_security_relevant: bool = False
    has_classes: bool = False
    is_dispatch_heavy: bool = False

def get_module_characteristics(db_path: str) -> ModuleCharacteristics:
    """Lightweight fingerprint for analysis routing decisions."""
    with open_individual_analysis_db(db_path) as db:
        # single SQL query for stats
        ...
```

**code-lifter** -- State file management:

```python
STATE_DIR = WORKSPACE_ROOT / ".agent" / "agents" / "code-lifter" / "state"

def load_shared_state(class_name: str) -> dict:
    state_file = STATE_DIR / f"{class_name}_state.json"
    if state_file.exists():
        return json.loads(state_file.read_text())
    return {"fields": {}, "constants": {}, "naming": {}, "lifted": []}
```

---

## 5. Agent Scripts

### 5.1 Argument Parsing

Use `argparse` with the standard conventions. The workspace bootstrap
automatically handles `--workspace-dir` and `--workspace-step`:

```python
import argparse

def build_parser():
    p = argparse.ArgumentParser(description="Scan module for vulnerability patterns")
    p.add_argument("db_path", help="Path to analysis database")
    p.add_argument("--class", dest="class_name", help="Restrict to one class")
    p.add_argument("--top", type=int, default=10, help="Max results")
    p.add_argument("--json", action="store_true", help="JSON output")
    return p
```

### 5.2 Calling Skill Scripts

Use `run_skill_script()` from helpers, not raw `subprocess`. This handles
workspace handoff, JSON parsing, and error propagation:

```python
from helpers.script_runner import run_skill_script

result = run_skill_script(
    "classify-functions",
    "classify_module.py",
    [db_path, "--json"],
)
if result.get("status") == "ok":
    categories = result["categories"]
```

For the triage-coordinator's parallel execution pattern, group independent
steps and use `ThreadPoolExecutor`:

```python
from concurrent.futures import ThreadPoolExecutor, as_completed

independent_steps = [
    ("classify-functions", "triage_summary.py", [db_path, "--json"]),
    ("map-attack-surface", "discover_entrypoints.py", [db_path, "--json"]),
    ("callgraph-tracer", "build_call_graph.py", [db_path, "--json"]),
]

results = {}
with ThreadPoolExecutor(max_workers=4) as executor:
    futures = {
        executor.submit(run_skill_script, skill, script, args): name
        for skill, script, args in independent_steps
        for name in [script.replace(".py", "")]
    }
    for future in as_completed(futures):
        name = futures[future]
        results[name] = future.result()
```

### 5.3 Output Convention

Print a compact summary JSON to stdout. Use `emit_json()` for `--json` mode:

```python
from helpers.json_output import emit_json

if args.json:
    emit_json({
        "status": "ok",
        "module": module_name,
        "findings_count": len(findings),
        "top_findings": findings[:args.top],
    })
else:
    print(f"Found {len(findings)} patterns in {module_name}")
    for f in findings[:args.top]:
        print(f"  [{f['confidence']}] {f['function']} -- {f['pattern']}")
```

---

## 6. Inter-Agent Communication

Subagents cannot launch other subagents. The **parent agent** orchestrates all
delegation. Results flow through compact JSON responses.

### 6.1 Parent-to-Subagent Flow

```
Parent Agent
  ├─ Launch code-lifter  ──>  Lift class methods  ──>  Return lifted code
  │
  ├─ Launch verifier     ──>  Verify lifted code  ──>  Return PASS/WARN/FAIL
  │
  └─ Synthesize results and present to user
```

The parent passes context in the Task description. The subagent returns a
compact result. Large payloads go through the workspace filesystem:

1. Parent writes input to a workspace file (e.g., lifted code to a temp file)
2. Subagent reads input, produces output to a workspace file
3. Parent reads the output file

**Subagent prompts must specify four things.** Vague prompts ("analyze this
function") produce unreliable results because subagents start fresh with no
context. Every subagent prompt needs:

1. **What to analyze** -- specific DB path, function name/ID, or file path
2. **What to look for** -- explicit criteria, not "analyze" or "review"
3. **What format to return** -- markdown structure, JSON schema, or verdict format
4. **What tools to use** -- the `subagent_type` that gives appropriate tools

```markdown
<!-- Bad: vague prompt -->
Analyze the function and tell me if it's interesting.

<!-- Good: structured prompt -->
Verify that the lifted code at `.agent/workspace/appinfo_lifted.cpp`
faithfully represents the original binary behavior for function
`AiLaunchAdminProcess` in `extracted_dbs/appinfo_dll_e98d25a9e8.db`.

Run `compare_lifted.py` with `--json`, then perform block-by-block manual
verification using `extract_basic_blocks.py`. Report your verdict
(PASS/WARN/FAIL) with evidence for any discrepancies.
```

### 6.2 Parallel Subagent Execution

Launch independent subagents in parallel from the parent by including multiple
Task tool calls in a single message. This is how `/lift-class` works:

```
Parent Agent (single message):
  Task 1: code-lifter  ──>  lift method A
  Task 2: code-lifter  ──>  lift method B  (if independent)
```

But in practice, code-lifter methods are sequential (shared state). Parallel
execution is more common with independent agents:

```
Parent Agent (single message):
  Task 1: triage-coordinator  ──>  /triage module_a
  Task 2: triage-coordinator  ──>  /triage module_b
```

### 6.3 Coordinator Delegation Pattern

The triage-coordinator delegates to other agents for specialized tasks within
its pipeline. Example from the `/audit` command:

```
/audit appinfo.dll AiLaunchProcess
  │
  ├─ triage-coordinator (--goal understand-function)
  │    └─ Runs: classify, extract data, call graph, security dossier
  │
  ├─ verifier (compare_lifted.py)
  │    └─ Runs: automated checks against assembly ground truth
  │
  └─ Parent synthesizes: dossier + verification + taint results
```

The key constraint: the triage-coordinator itself does not launch the verifier.
The parent agent launches both and stitches the results.

---

## 7. Shared State Management

Three patterns exist for maintaining state across agent steps:

### 7.1 Workspace Handoff (Transient State)

Used by: triage-coordinator, type-reconstructor

Each step writes results to a run directory. Subsequent steps read from it:

```
.agent/workspace/appinfo_dll_triage_20260222T120000/
├── manifest.json              # Step status tracker
├── classify_triage/
│   ├── results.json           # Full payload
│   └── summary.json           # Compact summary
├── discover_entrypoints/
│   ├── results.json
│   └── summary.json
└── triage_summary/
    ├── results.json
    └── summary.json
```

State lives only for the duration of the run. The manifest tracks which steps
completed and their summary paths.

### 7.2 Persistent State Files (Cross-Method State)

Used by: code-lifter

State accumulates across method lifts within a class and persists on disk:

```
.agent/agents/code-lifter/state/CSecurityDescriptor_state.json
```

Contains: struct field discoveries, naming maps, constants, lifted function
signatures, and completion markers. The `track_shared_state.py` script provides
a CLI interface for recording and querying state.

**Why this pattern:** The code-lifter must propagate struct field names,
offsets, and types discovered in one method to all subsequent methods. Without
persistent state, each method would independently guess field names.

### 7.3 Fresh Context (No State)

Used by: verifier

The verifier deliberately operates with no prior state. This prevents
confirmation bias -- the same context that produced lifted code would naturally
"see" it as correct. The verifier starts with only the original assembly,
decompiled code, and the lifted code to verify.

**When to use each:**

| Pattern | Use when |
|---------|----------|
| Workspace handoff | Multi-step pipeline, steps produce large JSON, transient |
| Persistent state | State must survive across multiple agent invocations for the same class/module |
| Fresh context | Verification, auditing, or any task where prior context introduces bias |

---

## 8. Error Recovery

### 8.1 Script-Level Errors

When a skill script fails (exit code 1), parse the structured error from
stderr:

```python
import subprocess, json

proc = subprocess.run(cmd, capture_output=True, text=True)
if proc.returncode != 0:
    try:
        err = json.loads(proc.stderr.strip().split("\n")[-1])
        error_code = err.get("code", "UNKNOWN")
        error_msg = err.get("error", "Unknown error")
    except (json.JSONDecodeError, IndexError):
        error_code = "UNKNOWN"
        error_msg = proc.stderr.strip() or "Script failed with no error message"
```

### 8.2 Recovery Strategies

| Failure | Strategy | Example |
|---------|----------|---------|
| `NOT_FOUND` on function | Try fuzzy search, report best matches | `search_functions_by_pattern(db, "Check*")` |
| `NOT_FOUND` on module | List available modules, ask user | `find_module_db.py --list` |
| `DB_ERROR` on open | Check file exists and is readable, report | `os.path.exists(db_path)` |
| `NO_DATA` (empty result) | Report clearly, suggest alternative query | "No dangerous APIs found; try a broader search" |
| Script timeout | Report partial results if available | Read workspace step output so far |
| Multiple matches (`AMBIGUOUS`) | Present disambiguation list to user | Show all matches with IDs |

### 8.3 Pipeline Continuity

Coordinators should continue on non-fatal step failures. The triage-coordinator
demonstrates this: if the COM interface scan fails (because the module has no
COM classes), it skips that step and continues with the remaining pipeline.

Record failures in the workspace manifest:

```python
manifest["steps"]["com_scan"] = {
    "status": "skipped",
    "reason": "Module has no COM classes",
}
```

---

## 9. Registry Registration

Add an entry to `.agent/agents/registry.json`:

```json
{
  "my-agent": {
    "purpose": "Brief description of the agent's role",
    "type": "analyst",
    "entry_scripts": [
      {
        "script": "main_task.py",
        "accepts": {
          "db_path": "required",
          "--class": "optional",
          "--top": "optional",
          "--json": "flag"
        }
      }
    ],
    "skills_used": ["classify-functions", "decompiled-code-extractor"],
    "json_output": true
  }
}
```

**Agent types:** `analyst`, `coordinator`, `reconstructor`, `verifier`,
`lifter`. Choose the closest match for your agent's purpose.

Also add a section to `.agent/agents/README.md` following the existing pattern:
purpose, when-to-use, scripts table, invocation examples, and workflow diagram.

---

## 10. Testing Requirements

### 10.1 Infrastructure Validation

```bash
cd .agent && python -m pytest tests/test_infrastructure_consistency.py -v
```

This validates:
- Every agent directory is registered in `registry.json`
- Every registered `entry_script` exists on disk
- Every `skills_used` entry references a registered skill

### 10.2 Integration Tests

Create `tests/test_<agent_name>.py` verifying:
- Registry `skills_used` lists expected skills
- Agent `.md` definition references the correct script paths
- Scripts accept the documented arguments

### 10.3 Full Suite

```bash
cd .agent && python -m pytest tests/ -v
```

Always run the full suite before considering any agent change complete.

---

## 11. Worked Example: Security Pattern Scanner

This example walks through creating a hypothetical `pattern-scanner` agent
that scans modules for known vulnerability patterns.

### 11.1 Agent Definition (`pattern-scanner.md`)

```markdown
---
name: pattern-scanner
description: "Scan module functions for known vulnerability patterns using
  classification signals, API calls, and structural heuristics."
---

# Pattern Scanner

You are a **vulnerability pattern scanner** that systematically checks
decompiled functions against a catalog of known-bad code patterns.

You are NOT an analyst -- do not explain code. You are NOT a lifter -- do not
rewrite code. Your job is to detect, score, and rank pattern matches.

## Available Scripts

### Module Discovery
| Script | Purpose |
|--------|---------|
| `.agent/skills/decompiled-code-extractor/scripts/find_module_db.py` | Resolve module name to DB path |

### Classification
| Script | Purpose |
|--------|---------|
| `.agent/skills/classify-functions/scripts/classify_module.py` | Categorize all functions |

### Data Extraction
| Script | Purpose |
|--------|---------|
| `.agent/skills/decompiled-code-extractor/scripts/extract_function_data.py` | Extract function code + assembly |

### Own Scripts
| Script | Purpose |
|--------|---------|
| `.agent/agents/pattern-scanner/scripts/scan_patterns.py` | Scan functions against pattern catalog |

## Workflow

1. Resolve module DB: `find_module_db.py <module>`
2. Classify all functions: `classify_module.py <db_path> --json`
3. Filter to candidates (security/file_io/process_thread categories, interest >= 4)
4. For each candidate: `extract_function_data.py <db_path> --id <id> --json`
5. Run pattern matching against extracted code
6. Score and rank findings
7. Return top-N findings with evidence

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Module not found | List available modules |
| No candidates after classification | Report "no high-interest functions matched filters" |
| Pattern match on unverified decompiled code | Add WARNING: "decompiler accuracy not verified" |
```

### 11.2 Bootstrap (`_common.py`)

```python
from __future__ import annotations

import sys
from pathlib import Path

from skills._shared import bootstrap

WORKSPACE_ROOT = bootstrap(__file__)
sys.path.insert(0, str(WORKSPACE_ROOT / ".agent"))

SKILLS_DIR = WORKSPACE_ROOT / ".agent" / "skills"

from helpers import emit_error, open_individual_analysis_db
from helpers.errors import ErrorCode
from helpers.script_runner import run_skill_script
from helpers.json_output import emit_json
```

### 11.3 Entry Script (`scan_patterns.py`)

```python
#!/usr/bin/env python3
"""Scan module functions for known vulnerability patterns."""

from __future__ import annotations

import argparse
import sys

from _common import WORKSPACE_ROOT, run_skill_script, emit_error, emit_json, ErrorCode

def build_parser():
    p = argparse.ArgumentParser(description="Scan for vulnerability patterns")
    p.add_argument("db_path", help="Path to analysis database")
    p.add_argument("--top", type=int, default=10, help="Max results to return")
    p.add_argument("--min-confidence", type=float, default=0.5)
    p.add_argument("--json", action="store_true")
    return p

PATTERNS = [
    {
        "id": "TOCTOU_FILE",
        "name": "TOCTOU on file path",
        "signal": lambda f: "CreateFileW" in str(f.get("dangerous_apis", [])),
        "confidence_boost": 0.2,
    },
    # ... more patterns
]

def scan_function(func_data: dict) -> list[dict]:
    """Match a function's data against all known patterns."""
    findings = []
    for pattern in PATTERNS:
        if pattern["signal"](func_data):
            findings.append({
                "pattern": pattern["id"],
                "name": pattern["name"],
                "function": func_data["function_name"],
                "function_id": func_data["function_id"],
                "confidence": 0.5 + pattern["confidence_boost"],
            })
    return findings

def main():
    args = build_parser().parse_args()

    classification = run_skill_script(
        "classify-functions", "classify_module.py",
        [args.db_path, "--json"],
    )
    if not classification or classification.get("status") != "ok":
        emit_error("Classification failed", ErrorCode.UNKNOWN)

    candidates = [
        f for f in classification.get("functions", [])
        if f.get("interest_score", 0) >= 4
    ]

    all_findings = []
    for candidate in candidates:
        func_data = run_skill_script(
            "decompiled-code-extractor", "extract_function_data.py",
            [args.db_path, "--id", str(candidate["function_id"]), "--json"],
        )
        if func_data and func_data.get("status") == "ok":
            findings = scan_function(func_data)
            all_findings.extend(findings)

    all_findings.sort(key=lambda f: f["confidence"], reverse=True)
    top = all_findings[:args.top]

    if args.json:
        emit_json({"status": "ok", "findings": top, "total_scanned": len(candidates)})
    else:
        print(f"Scanned {len(candidates)} candidates, found {len(all_findings)} matches")
        for f in top:
            print(f"  [{f['confidence']:.1f}] {f['function']} -- {f['name']}")

if __name__ == "__main__":
    main()
```

### 11.4 Registry Entry

```json
{
  "pattern-scanner": {
    "purpose": "Scan module functions for known vulnerability patterns",
    "type": "analyst",
    "entry_scripts": [
      {
        "script": "scan_patterns.py",
        "accepts": {
          "db_path": "required",
          "--top": "optional",
          "--min-confidence": "optional",
          "--json": "flag"
        }
      }
    ],
    "skills_used": ["classify-functions", "decompiled-code-extractor"],
    "json_output": true
  }
}
```

### 11.5 README Entry

Add a section to `.agent/agents/README.md`:

```markdown
### pattern-scanner

**Purpose:** Scan module functions for known vulnerability patterns using
classification signals, API calls, and structural heuristics.

**When to use:**
- Automated scanning for known-bad patterns before manual review
- Quick triage of which functions to investigate for specific vuln classes

**Scripts:**

| Script | Purpose |
|--------|---------|
| `scan_patterns.py` | Scan functions against pattern catalog |
```

---

## 12. Checklist

Before submitting a new or modified agent:

- [ ] Agent definition `.md` has YAML frontmatter (`name`, `description`)
- [ ] Definition includes persona, anti-persona, When to Use/NOT, skill catalog, workflows, error handling
- [ ] Subagent prompts specify: what to analyze, what to look for, what format to return
- [ ] `_common.py` uses the bootstrap pattern from `skills._shared`
- [ ] All scripts support `--json` flag for machine-readable output
- [ ] Entry added to `agents/registry.json` with all required fields
- [ ] Section added to `agents/README.md` with purpose, when-to-use, scripts, examples
- [ ] `skills_used` lists every skill referenced by the agent
- [ ] Infrastructure tests pass: `python -m pytest tests/test_infrastructure_consistency.py -v`
- [ ] Full test suite passes: `python -m pytest tests/ -v`
- [ ] Workspace pattern used if agent runs 2+ skill scripts (run directory + manifest)
- [ ] Error handling covers NOT_FOUND, DB_ERROR, NO_DATA, and AMBIGUOUS cases
