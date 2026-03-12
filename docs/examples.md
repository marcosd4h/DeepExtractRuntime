# Examples

## Interactive Commands

```text
/triage appinfo.dll
/audit appinfo.dll AiLaunchProcess
/explain appinfo.dll AiCheckSecureApplicationDirectory
/verify-decompiler appinfo.dll AiLaunchProcess
/scan appinfo.dll --top 15
/compare-modules appinfo.dll consent.exe
/health
```

## Batch Pipeline CLI

```bash
python .agent/helpers/pipeline_cli.py list-steps
python .agent/helpers/pipeline_cli.py validate config/pipelines/security-sweep.yaml
python .agent/helpers/pipeline_cli.py run config/pipelines/security-sweep.yaml --dry-run
python .agent/helpers/pipeline_cli.py run config/pipelines/quick-triage.yaml --json
python .agent/helpers/pipeline_cli.py run config/pipelines/security-sweep.yaml --modules appinfo.dll,consent.exe
python .agent/helpers/pipeline_cli.py run config/pipelines/full-analysis.yaml --output workspace/custom_{timestamp}/
```

For interactive use, the `/pipeline` slash command wraps the same CLI.

## Example YAML Snippets

Minimal:

```yaml
modules: all
steps:
  - triage: {}
```

Focused security sweep:

```yaml
modules:
  - appinfo.dll
  - consent.exe
steps:
  - triage: {}
  - security:
      top: 10
  - scan:
      top: 10
```

---

## Workflow Examples

The sections below show how to chain commands for common analysis goals.
Each step includes a brief annotation explaining what it produces and why
the next step follows. All examples use `appinfo.dll` as the module and
`AiLaunchProcess` as the target function.

### Getting Started

First-time workflow for a new extraction workspace.

```text
/health                                  # validate workspace: extraction data, DBs, skills, config
/quickstart                              # auto-detect modules, lightweight classify + entry points
/triage appinfo.dll                      # deep orientation: classify, topology, attack surface ranking
/explain appinfo.dll AiLaunchProcess     # structured explanation of top-ranked function
/audit appinfo.dll AiLaunchProcess       # full security audit with risk assessment
```

Progression: `/health` -> `/quickstart` -> `/triage` -> `/explain` -> `/audit`.

---

### Security Analysis Workflow

Systematic vulnerability hunting from triage through confirmed findings.

```text
/triage appinfo.dll --with-security      # orientation + lightweight taint on top entries
/scan appinfo.dll --top 10               # all 8 scanners + taint + verification + exploitability
/audit appinfo.dll AiLaunchProcess       # deep audit on highest-risk finding from /scan
/taint appinfo.dll AiLaunchProcess --depth 5  # focused source-to-sink trace with guard analysis
/hunt-plan appinfo.dll                   # collaborative VR planning: ranked hypotheses
/hunt-execute appinfo.dll               # execute plan: per-hypothesis evidence + confidence score
```

Progression: `/triage --with-security` -> `/scan` -> `/audit` (top findings) -> `/taint` -> `/hunt-plan` -> `/hunt-execute`.

`/scan` provides breadth (8 scanner types across all functions). `/audit` provides
depth (backward trace, decompiler verification, call chain) on individual findings.
`/hunt-plan` + `/hunt-execute` add hypothesis-driven reasoning on top.

---

### Code Understanding Workflow

Understanding a function's behavior, context, and data dependencies.

```text
/explain appinfo.dll AiLaunchProcess                       # purpose, params, key APIs, behavior
/xref appinfo.dll AiLaunchProcess                          # caller/callee tables with classification
/callgraph appinfo.dll AiLaunchProcess --diagram           # visual neighborhood, hub annotations
/data-flow forward appinfo.dll AiLaunchProcess --param 1   # where does param 1 end up?
/data-flow backward appinfo.dll AiLaunchProcess            # where do this function's inputs come from?
```

Progression: `/explain` -> `/xref` -> `/callgraph` -> `/data-flow forward` -> `/data-flow backward`.

`/explain` gives you the "what", `/xref` + `/callgraph` give the structural
context, and `/data-flow` traces the actual value movement.

---

### Code Lifting Workflow

Producing clean, readable code from decompiled output.

```text
/reconstruct-types appinfo.dll CSecurityDescriptor --validate  # struct layout from memory patterns
/lift-class appinfo.dll CSecurityDescriptor                    # batch-lift all methods (grind loop)
/verify-decompiler-batch appinfo.dll --class CSecurityDescriptor          # verify decompiler accuracy per method
```

Progression: `/reconstruct-types` -> `/lift-class` -> `/verify-decompiler-batch`.

Run type reconstruction first so lifts use correct struct layouts. `/lift-class`
uses the grind loop to process each method sequentially, producing a single
`.cpp` file. `/verify-decompiler-batch` catches decompiler issues the lifter may have inherited.

---

### Cross-Module Investigation

Tracing behavior and dependencies across DLL boundaries.

```text
/data-flow-cross appinfo.dll AiLaunchProcess --depth 3  # trace params across DLL boundaries
/imports appinfo.dll                                      # PE-level import/export relationships
/compare-modules appinfo.dll consent.exe                  # side-by-side: shared APIs, topology, deps
```

Progression: `/data-flow-cross` -> `/imports` -> `/compare-modules`.

`/data-flow-cross` traces values across module boundaries at the code level.
`/imports` shows the loader-level dependency picture (PE import tables).
`/compare-modules` synthesizes both into an architectural comparison.

---

### IPC Analysis Workflow

Auditing COM, RPC, and WinRT interfaces for privilege escalation.

```text
/com surface appinfo.dll                 # enumerate COM servers, rank by privilege-boundary risk
/rpc surface appinfo.dll                 # enumerate RPC interfaces, rank by attack surface score
/winrt surface appinfo.dll               # enumerate WinRT servers, rank by privilege-boundary risk
```

These three are independent and can run in any order. They identify IPC entry
points that cross privilege boundaries (e.g., medium-IL caller to SYSTEM server).

```text
/com audit appinfo.dll                   # deep audit: permissions, elevation, marshalling, DCOM
/com privesc appinfo.dll                 # filter to EoP targets and UAC bypass candidates
/batch-audit appinfo.dll --privilege-boundary --top 8  # dossier + taint per handler function
```

Progression: `/com surface` + `/rpc surface` + `/winrt surface` -> `/com audit` -> `/com privesc` -> `/batch-audit --privilege-boundary`.

---

### Batch Operations

Processing multiple functions or modules at scale.

```text
/batch-audit appinfo.dll --top 10                          # audit top 10 entry points
/batch-audit appinfo.dll --class CSecurityDescriptor       # audit all methods of a class
/verify-decompiler-batch appinfo.dll --top 20                         # verify decompiler accuracy, top 20
```

All three use the grind loop (one checkbox per function, auto-continues until done).

Pipeline examples for headless batch processing:

```text
/pipeline run config/pipelines/security-sweep.yaml --modules appinfo.dll,consent.exe
/pipeline run config/pipelines/full-analysis.yaml --dry-run
/pipeline list-steps                                       # show available step types
```

Pipeline results are written to `.agent/workspace/` with per-module summaries and
a manifest for later inspection via `/runs`.

---

### Cache & Maintenance

Managing cached results and workspace health.

```text
/health                                  # pre-flight: extraction data, DBs, skills, config
/cache-manage                            # cache stats: entries, disk usage, staleness
/cache-manage clear appinfo.dll          # clear cached results for a module (recomputes on next use)
/runs                                    # list prior workspace runs with timestamps and goals
/runs latest appinfo.dll                 # open most recent run, drill into step results
```

Use `/health` at the start of every session. Use `/cache-manage clear` after
re-extraction or when results seem stale. Use `/runs` to revisit prior analysis
without re-running it.
