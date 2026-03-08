# DeepExtract AI Runtime -- Testing Guide

> **Purpose**: Complete testing reference for the DeepExtract Agent Analysis
> Runtime, covering both the **unit test suite** (pytest, 91 test files) and the
> **integration test plan** (359 test cases across 36 commands, 29 skills, 6
> agents, 4 pipelines, 3 hooks, and infrastructure conventions).
>
> **Test targets**: `windows.storage.dll`, `shell32.dll`, `appinfo.dll` --
> the ShellExecuteExW call chain.

---

## Test Architecture

The runtime has two complementary testing tiers.

### Tier 1: Unit Tests

| | |
|---|---|
| **Location** | `.agent/tests/` (91 pytest files + `conftest.py`) |
| **Runner** | `python -m pytest .agent/tests/ -v` |
| **Also triggered by** | `/health --full` (step 8 of the health command) |
| **Typical runtime** | ~10-30 seconds |

Unit tests validate internal libraries and modules in isolation: helper
functions, parsers, DB access layers, classification logic, caching, error
handling, JSON output compliance, configuration validation, calling
conventions, struct scanning, and more. They use synthetic fixtures modeled
on real IDA extractions and do not require live analysis databases.

Run them directly:

```bash
python -m pytest .agent/tests/ -v
```

Or through the `/health --full` command, which includes the full pytest
suite as its final validation step. The `/health` command (without `--full`)
skips the test suite for speed.

### Tier 2: Integration Tests

| | |
|---|---|
| **Location** | This document (test cases below) |
| **Runner** | `.agent/helpers/qa_runner.py` |
| **Typical runtime** | ~3-6 minutes (181 runnable tests) |

Integration tests exercise full skill scripts, agent entry points, pipeline
validation, lifecycle hooks, and infrastructure conventions end-to-end
against real analysis databases. Each test case specifies a concrete command,
expected behavior, and the conventions it validates.

Of the 359 test cases in this document, 178 are directly runnable by the QA
test runner (skill scripts, agent scripts, pipelines, hooks, infrastructure).
The remaining 181 are slash commands and multi-step workflows that require
agent-level orchestration.

Run them:

```bash
python .agent/helpers/qa_runner.py
```

### Comparison

| Aspect | Unit Tests | Integration Tests |
|--------|-----------|-------------------|
| Scope | Individual helpers, parsers, modules | Full scripts against real DBs |
| Isolation | Synthetic fixtures, no live DBs | Real extraction databases |
| Runner | pytest | `.agent/helpers/qa_runner.py` |
| Trigger | `pytest` or `/health --full` | `qa_runner.py` or manual |
| Test count | ~91 files (hundreds of cases) | 359 cases (178 auto-runnable) |
| Runtime | ~10-30s | ~3-6 min |

> **Machine-parseable**: Every integration test case uses a consistent metadata
> block that the QA runner extracts programmatically (regex on `### TEST-`
> headers and `- **Key**:` lines).

---

## Conventions

| Symbol | Meaning |
|--------|---------|
| `<db:appinfo>` | `extracted_dbs/appinfo_dll_f2bbf324a1.db` |
| `<db:shell32>` | `extracted_dbs/shell32_dll_06438e9405.db` |
| `<db:winstorage>` | `extracted_dbs/windows_storage_dll_5cb93af0c6.db` |
| `<uuid>` | Substitute a real RPC interface UUID from `/rpc appinfo.dll` output |
| `<run_id>` | Substitute a real run ID from `/runs` output |
| `<path>` | Substitute the actual filesystem path produced by a prior step |

All skill script commands assume the working directory is the workspace root
and use the canonical invocation prefix:

```
python .agent/skills/<skill-name>/scripts/<script>.py
```

Agent scripts use:

```
python .agent/agents/<agent-name>/scripts/<script>.py
```

---

## Running Tests with the QA Test Runner

All test cases in this plan that have a `python ...` command in their
**Command** field can be executed automatically using the QA test runner
helper at `.agent/helpers/qa_runner.py`. The runner parses this markdown
file, resolves `<db:...>` path variables, executes each command, and
validates results against the test metadata (JSON output convention,
expected errors, etc.).

### Quick Start

```bash
# Run ALL testable cases (skill scripts, agent scripts, pipelines, hooks, infrastructure)
python .agent/helpers/qa_runner.py

# Run a specific test section by ID prefix
python .agent/helpers/qa_runner.py --prefix TEST-SKILL
python .agent/helpers/qa_runner.py --prefix TEST-AGENT
python .agent/helpers/qa_runner.py --prefix TEST-INFRA
python .agent/helpers/qa_runner.py --prefix TEST-PIPE
python .agent/helpers/qa_runner.py --prefix TEST-HOOK

# Run a single test
python .agent/helpers/qa_runner.py --test TEST-SKILL-039

# Filter by category keyword
python .agent/helpers/qa_runner.py --section infrastructure

# List all tests and their runnability status
python .agent/helpers/qa_runner.py --list

# List only runnable tests with their resolved commands
python .agent/helpers/qa_runner.py --list-runnable

# Custom output directory and timeout
python .agent/helpers/qa_runner.py --output-dir work/qa_results --timeout 180

# JSON summary to stdout (for programmatic consumption)
python .agent/helpers/qa_runner.py --prefix TEST-SKILL --json
```

### What the Runner Does

1. **Parses** every `### TEST-*` block from this file, extracting the
   metadata fields (Category, Component, Command, Expected, etc.)
2. **Classifies** each test as runnable or skip. Tests with `python ...`
   commands are runnable. Slash commands (`/triage`, `/scan`, etc.) and
   manual steps are skipped automatically.
3. **Resolves** `<db:appinfo>`, `<db:shell32>`, `<db:winstorage>` and
   similar variables by querying `find_module_db.py --list --json`.
4. **Executes** each command via `subprocess.run()` with configurable
   timeout (default 120s).
5. **Validates** the result:
   - If the command has `--json`: checks stdout is a single JSON dict
     with `"status"` equal to `"ok"` or `"error"`.
   - If the Expected field mentions error codes: verifies structured
     JSON error on stderr with the expected code.
   - Non-zero exit codes are failures unless the test expects an error.
   - stderr output on otherwise-passing tests is captured as a warning.
6. **Persists** results: failing and warning tests get a directory under
   the output dir with `command.txt`, `result.json`, `stdout.txt`,
   `stderr.txt`, and optionally `warnings.txt`.
7. **Generates** `SUMMARY.json` and `SUMMARY.md` in the output directory.

### Test Runnability Categories

| Component type   | Runnable? | Notes |
|------------------|-----------|-------|
| `skill-script`   | Yes       | Direct Python script invocation |
| `agent-script`   | Yes       | Direct Python script invocation |
| `pipeline`       | Yes       | `pipeline_cli.py` invocations |
| `hook`           | Yes       | Hook scripts with `python ...` commands |
| `infrastructure` | Partial   | Tests with `python ...` commands run; manual tests skip |
| `command`         | No        | Slash commands require agent-level execution |
| `workflow`        | No        | Multi-step workflows require agent orchestration |

### Output Structure

```
work/testcase_output/           # default output directory
  SUMMARY.json                  # machine-readable aggregate results
  SUMMARY.md                    # human-readable summary table
  TEST-SKILL-039/               # per-test directory (failures and warnings only)
    command.txt                 # the resolved command that was run
    result.json                 # exit code, elapsed time, status, notes
    stdout.txt                  # full stdout capture
    stderr.txt                  # full stderr capture
    warnings.txt                # (warnings only) stderr content
```

### Adding New Tests

New test cases must follow the metadata format used throughout this file.
The runner extracts fields using regex on `### TEST-<PREFIX>-<NNN>:` headers
and `- **Key**: value` lines. Required fields for automatic execution:

- `**Command**:` must contain a backtick-wrapped `python ...` command
- `**Expected**:` used to determine validation strategy (error tests, JSON tests)
- `**Component**:` used to classify runnability (`skill-script`, `command`, etc.)

### Running Both Tiers Together

To run a complete validation of the runtime, execute both tiers in sequence:

```bash
# Tier 1: Unit tests (~2 min)
python -m pytest .agent/tests/ -v --tb=short 2>&1 | tee work/testcase_output/pytest_output.log

# Tier 2: Integration tests (~3-6 min)
python .agent/helpers/qa_runner.py --output-dir work/testcase_output
```

Both commands write to the same output directory. The pytest log is saved
alongside the QA runner's `SUMMARY.json` and per-test failure directories.

### Agent-Driven Testing

Instead of running tests manually, you can ask the agent to execute and
triage the full test suite (both unit and integration) in a structured
two-phase workflow. Copy the prompt for the phase you need.

**Phase 1 -- Run and capture** (read-only, no fixes):

> Run all the test cases from the testing guide at
> `@.agent/docs/testing_guide.md`. Read the entire plan before proceeding.
>
> Run **both** test tiers into `@work/testcase_output`:
>
> 1. **Unit tests**: `python -m pytest .agent/tests/ -v --tb=short` --
>    save output to `pytest_output.log` in the output directory.
> 2. **Integration tests**: `python .agent/helpers/qa_runner.py` --
>    use `--output-dir` pointed at the same output directory.
>
> Your goal is to run the test cases and capture every failing tool
> execution. Do NOT attempt to fix anything -- just capture the output.
> Capture failures, warnings, empty or misbehaving steps, and any
> behavioral deviations. These findings will be fixed in a separate phase.

**Phase 2 -- Investigate and fix** (uses Phase 1 output):

> Investigate in detail every failure and behavioral deviation captured in
> `@work/testcase_output`. For each finding: understand the root cause,
> determine whether the same issue could affect other commands, skills, or
> sub-agents, and plan a fix that prevents recurrence across all of them.
> Update code, docs, and workspace rules where needed. After all fixes are
> applied, re-run Phase 1 to verify the suite is clean.

Typical workflow: run Phase 1 first, review the `SUMMARY.md` and
`pytest_output.log` it produces, then run Phase 2 pointing at the same
output directory. Repeat until the suite reports 0 failures and 0 warnings.

---

## Section 1: Initialization Commands

### TEST-INIT-001: Quickstart auto-detect

- **Category**: initialization
- **Component**: command
- **Component-Name**: /quickstart
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `/quickstart`
- **Expected**: Selects most interesting module, runs classification + entry points + call graph stats, presents summary with recommendations
- **Validates**: Module auto-selection, concurrent skill execution, output formatting
- **Flags-Tested**: none (default)
- **Protocol**: none

### TEST-INIT-002: Quickstart specific module

- **Category**: initialization
- **Component**: command
- **Component-Name**: /quickstart
- **Target-Module**: windows.storage.dll
- **Target-Function**: N/A
- **Command**: `/quickstart windows.storage.dll`
- **Expected**: Runs triage on windows.storage.dll, shows top functions including CShellExecute and CInvokeCreateProcessVerb methods
- **Validates**: Explicit module targeting, DB path resolution
- **Flags-Tested**: module argument
- **Protocol**: none

### TEST-INIT-003: Health check standard

- **Category**: initialization
- **Component**: command
- **Component-Name**: /health
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `/health`
- **Expected**: Reports extraction data status, DB schema validation, skill/agent registration, config check
- **Validates**: Workspace integrity validation
- **Flags-Tested**: none (default)
- **Protocol**: none

### TEST-INIT-004: Health check quick

- **Category**: initialization
- **Component**: command
- **Component-Name**: /health
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `/health --quick`
- **Expected**: Faster check skipping DB integrity and function indexes
- **Validates**: Quick-mode flag skips expensive checks
- **Flags-Tested**: --quick
- **Protocol**: none

### TEST-INIT-005: Health check full

- **Category**: initialization
- **Component**: command
- **Component-Name**: /health
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `/health --full`
- **Expected**: Validates every DB, every index, runs pytest suite
- **Validates**: Full validation mode including test execution
- **Flags-Tested**: --full
- **Protocol**: none

---

## Section 2: Reconnaissance Commands

### TEST-RECON-001: Triage module

- **Category**: reconnaissance
- **Component**: command
- **Component-Name**: /triage
- **Target-Module**: windows.storage.dll
- **Target-Function**: N/A
- **Command**: `/triage windows.storage.dll`
- **Expected**: Binary identity, function classification, call graph topology, entry point surface, recommendations
- **Validates**: Full triage pipeline, workspace protocol
- **Flags-Tested**: module argument
- **Protocol**: workspace

### TEST-RECON-002: Triage with security scan

- **Category**: reconnaissance
- **Component**: command
- **Component-Name**: /triage
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/triage appinfo.dll --with-security`
- **Expected**: Standard triage plus lightweight taint scan on top 3-5 entry points
- **Validates**: --with-security flag triggers taint analysis
- **Flags-Tested**: --with-security
- **Protocol**: workspace

### TEST-RECON-003: Full report

- **Category**: reconnaissance
- **Component**: command
- **Component-Name**: /full-report
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/full-report appinfo.dll`
- **Expected**: 6-phase multi-step report: identity, classification, attack surface, topology, specialized, synthesis
- **Validates**: Grind-loop scratchpad creation, 6-phase execution, workspace run dir
- **Flags-Tested**: none (default)
- **Protocol**: grind-loop, workspace

### TEST-RECON-004: Full report brief

- **Category**: reconnaissance
- **Component**: command
- **Component-Name**: /full-report
- **Target-Module**: shell32.dll
- **Target-Function**: N/A
- **Command**: `/full-report shell32.dll --brief`
- **Expected**: Abbreviated report with fewer phases
- **Validates**: --brief flag reduces output scope
- **Flags-Tested**: --brief
- **Protocol**: grind-loop, workspace

### TEST-RECON-005: Explain cross-module search

- **Category**: reconnaissance
- **Component**: command
- **Component-Name**: /explain
- **Target-Module**: N/A
- **Target-Function**: ShellExecuteExW
- **Command**: `/explain ShellExecuteExW`
- **Expected**: Finds ShellExecuteExW in shell32.dll, explains purpose, parameters, return value, execution sequence
- **Validates**: Cross-module function search, re-analyst subagent
- **Flags-Tested**: none (default)
- **Protocol**: none

### TEST-RECON-006: Explain with depth

- **Category**: reconnaissance
- **Component**: command
- **Component-Name**: /explain
- **Target-Module**: windows.storage.dll
- **Target-Function**: CInvokeCreateProcessVerb::Execute
- **Command**: `/explain windows.storage.dll CInvokeCreateProcessVerb::Execute --depth 2`
- **Expected**: Explanation includes 2 levels of callee code
- **Validates**: --depth parameter controls callee inclusion depth
- **Flags-Tested**: --depth
- **Protocol**: none

### TEST-RECON-007: Explain pattern search

- **Category**: reconnaissance
- **Component**: command
- **Component-Name**: /explain
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/explain appinfo.dll --search LaunchProcess`
- **Expected**: Finds functions matching pattern, explains best match or prompts disambiguation
- **Validates**: --search flag pattern matching
- **Flags-Tested**: --search
- **Protocol**: none

### TEST-RECON-008: Explain no callees

- **Category**: reconnaissance
- **Component**: command
- **Component-Name**: /explain
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `/explain appinfo.dll AiLaunchProcess --depth 0`
- **Expected**: Explanation without any callee code
- **Validates**: --depth 0 suppresses callee expansion
- **Flags-Tested**: --depth 0
- **Protocol**: none

### TEST-RECON-009: Explain no assembly

- **Category**: reconnaissance
- **Component**: command
- **Component-Name**: /explain
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `/explain appinfo.dll AiLaunchProcess --no-assembly`
- **Expected**: Explanation without assembly listing
- **Validates**: --no-assembly flag omits asm
- **Flags-Tested**: --no-assembly
- **Protocol**: none

### TEST-RECON-010: Search substring default

- **Category**: reconnaissance
- **Component**: command
- **Component-Name**: /search
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `/search CreateProcess`
- **Expected**: Substring matches across all modules, all dimensions
- **Validates**: Default substring mode, cross-module search
- **Flags-Tested**: none (default)
- **Protocol**: none

### TEST-RECON-011: Search with dimensions

- **Category**: reconnaissance
- **Component**: command
- **Component-Name**: /search
- **Target-Module**: windows.storage.dll
- **Target-Function**: N/A
- **Command**: `/search windows.storage.dll --dimensions name,api Execute`
- **Expected**: Results restricted to name and api dimensions
- **Validates**: --dimensions filter
- **Flags-Tested**: --dimensions
- **Protocol**: none

### TEST-RECON-012: Search regex mode

- **Category**: reconnaissance
- **Component**: command
- **Component-Name**: /search
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/search appinfo.dll --regex "^Ai.*Process$"`
- **Expected**: Regex matches like AiLaunchProcess, AiCreateProcess
- **Validates**: --regex mode
- **Flags-Tested**: --regex
- **Protocol**: none

### TEST-RECON-013: Search fuzzy mode

- **Category**: reconnaissance
- **Component**: command
- **Component-Name**: /search
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `/search --fuzzy CreateProces`
- **Expected**: Fuzzy matches including CreateProcess variants
- **Validates**: --fuzzy mode with SequenceMatcher
- **Flags-Tested**: --fuzzy
- **Protocol**: none

### TEST-RECON-014: Search with sort and limit

- **Category**: reconnaissance
- **Component**: command
- **Component-Name**: /search
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/search appinfo.dll CreateProcess --sort score --limit 5`
- **Expected**: Top 5 results sorted by relevance score
- **Validates**: --sort and --limit flags
- **Flags-Tested**: --sort, --limit
- **Protocol**: none

### TEST-RECON-015: Search all modules

- **Category**: reconnaissance
- **Component**: command
- **Component-Name**: /search
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `/search --all registry`
- **Expected**: Results from all 195 modules containing "registry"
- **Validates**: --all cross-module mode
- **Flags-Tested**: --all
- **Protocol**: none

### TEST-RECON-016: Search with threshold

- **Category**: reconnaissance
- **Component**: command
- **Component-Name**: /search
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/search appinfo.dll CreateProcess --threshold 0.8 --limit 5`
- **Expected**: Only results with relevance >= 0.8
- **Validates**: --threshold filter
- **Flags-Tested**: --threshold, --limit
- **Protocol**: none

### TEST-RECON-017: Xref basic

- **Category**: reconnaissance
- **Component**: command
- **Component-Name**: /xref
- **Target-Module**: shell32.dll
- **Target-Function**: ShellExecuteExW
- **Command**: `/xref shell32.dll ShellExecuteExW`
- **Expected**: Callers and callees table for ShellExecuteExW
- **Validates**: Basic xref lookup
- **Flags-Tested**: none (default)
- **Protocol**: none

### TEST-RECON-018: Xref auto-detect module

- **Category**: reconnaissance
- **Component**: command
- **Component-Name**: /xref
- **Target-Module**: N/A
- **Target-Function**: AiLaunchProcess
- **Command**: `/xref AiLaunchProcess`
- **Expected**: Auto-detects appinfo.dll, shows callers/callees
- **Validates**: Cross-module function search for xref
- **Flags-Tested**: none (auto-detect)
- **Protocol**: none

### TEST-RECON-019: Xref with depth

- **Category**: reconnaissance
- **Component**: command
- **Component-Name**: /xref
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `/xref appinfo.dll AiLaunchProcess --depth 2`
- **Expected**: 2 levels of callers and callees
- **Validates**: --depth parameter for extended xref
- **Flags-Tested**: --depth
- **Protocol**: none

### TEST-RECON-020: Xref pattern search

- **Category**: reconnaissance
- **Component**: command
- **Component-Name**: /xref
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/xref appinfo.dll --search "Check*"`
- **Expected**: Xrefs for all functions matching Check*
- **Validates**: --search pattern for xref
- **Flags-Tested**: --search
- **Protocol**: none

---

## Section 3: Structural Understanding Commands

### TEST-STRUCT-001: Callgraph module stats

- **Category**: structural
- **Component**: command
- **Component-Name**: /callgraph
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/callgraph appinfo.dll`
- **Expected**: Node count, edge count, hub functions, density metrics
- **Validates**: Module-wide callgraph statistics
- **Flags-Tested**: none (default)
- **Protocol**: none

### TEST-STRUCT-002: Callgraph SCC

- **Category**: structural
- **Component**: command
- **Component-Name**: /callgraph
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/callgraph appinfo.dll --scc`
- **Expected**: Strongly connected components listed
- **Validates**: --scc flag
- **Flags-Tested**: --scc
- **Protocol**: none

### TEST-STRUCT-003: Callgraph roots

- **Category**: structural
- **Component**: command
- **Component-Name**: /callgraph
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/callgraph appinfo.dll --roots`
- **Expected**: Functions with no callers (entry points)
- **Validates**: --roots flag
- **Flags-Tested**: --roots
- **Protocol**: none

### TEST-STRUCT-004: Callgraph leaves

- **Category**: structural
- **Component**: command
- **Component-Name**: /callgraph
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/callgraph appinfo.dll --leaves`
- **Expected**: Functions that call nothing (leaf nodes)
- **Validates**: --leaves flag
- **Flags-Tested**: --leaves
- **Protocol**: none

### TEST-STRUCT-005: Callgraph neighborhood

- **Category**: structural
- **Component**: command
- **Component-Name**: /callgraph
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `/callgraph appinfo.dll AiLaunchProcess`
- **Expected**: Immediate callers and callees of AiLaunchProcess
- **Validates**: Function-scoped neighborhood
- **Flags-Tested**: function argument
- **Protocol**: none

### TEST-STRUCT-006: Callgraph diagram

- **Category**: structural
- **Component**: command
- **Component-Name**: /callgraph
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `/callgraph appinfo.dll AiLaunchProcess --diagram`
- **Expected**: Mermaid diagram of call neighborhood
- **Validates**: --diagram flag generates Mermaid output
- **Flags-Tested**: --diagram
- **Protocol**: none

### TEST-STRUCT-007: Callgraph path

- **Category**: structural
- **Component**: command
- **Component-Name**: /callgraph
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/callgraph appinfo.dll --path AiLaunchProcess AiCheckSecureApplicationDirectory`
- **Expected**: Shortest path between the two functions
- **Validates**: --path flag with two function args
- **Flags-Tested**: --path
- **Protocol**: none

### TEST-STRUCT-008: Callgraph reachable

- **Category**: structural
- **Component**: command
- **Component-Name**: /callgraph
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `/callgraph appinfo.dll --reachable AiLaunchProcess`
- **Expected**: All functions reachable from AiLaunchProcess
- **Validates**: --reachable transitive closure
- **Flags-Tested**: --reachable
- **Protocol**: none

### TEST-STRUCT-009: Data flow forward

- **Category**: structural
- **Component**: command
- **Component-Name**: /data-flow
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `/data-flow forward appinfo.dll AiLaunchProcess --param 1`
- **Expected**: Parameter 1 forward flow to callees
- **Validates**: Forward trace mode with --param
- **Flags-Tested**: forward, --param
- **Protocol**: none

### TEST-STRUCT-010: Data flow forward with depth and assembly

- **Category**: structural
- **Component**: command
- **Component-Name**: /data-flow
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `/data-flow forward appinfo.dll AiLaunchProcess --param 1 --depth 3 --assembly`
- **Expected**: Deeper trace with assembly annotations
- **Validates**: --depth and --assembly flags
- **Flags-Tested**: --depth, --assembly
- **Protocol**: none

### TEST-STRUCT-011: Data flow backward

- **Category**: structural
- **Component**: command
- **Component-Name**: /data-flow
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `/data-flow backward appinfo.dll AiLaunchProcess --target CreateProcessW`
- **Expected**: Argument origins for CreateProcessW calls
- **Validates**: Backward trace mode with --target
- **Flags-Tested**: backward, --target
- **Protocol**: none

### TEST-STRUCT-012: Data flow backward with callers

- **Category**: structural
- **Component**: command
- **Component-Name**: /data-flow
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `/data-flow backward appinfo.dll AiLaunchProcess --target CreateProcessW --arg 1 --callers`
- **Expected**: Specific arg origin traced through callers
- **Validates**: --arg and --callers flags
- **Flags-Tested**: --arg, --callers
- **Protocol**: none

### TEST-STRUCT-013: Data flow string search

- **Category**: structural
- **Component**: command
- **Component-Name**: /data-flow
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/data-flow string appinfo.dll --string "CreateProcess"`
- **Expected**: Functions referencing the string "CreateProcess"
- **Validates**: String trace mode with --string
- **Flags-Tested**: string, --string
- **Protocol**: none

### TEST-STRUCT-014: Data flow string by function

- **Category**: structural
- **Component**: command
- **Component-Name**: /data-flow
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `/data-flow string appinfo.dll --function AiLaunchProcess`
- **Expected**: Strings used by AiLaunchProcess
- **Validates**: String trace scoped to function
- **Flags-Tested**: string, --function
- **Protocol**: none

### TEST-STRUCT-015: Data flow globals

- **Category**: structural
- **Component**: command
- **Component-Name**: /data-flow
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/data-flow globals appinfo.dll`
- **Expected**: Global variable reader/writer map
- **Validates**: Globals mode
- **Flags-Tested**: globals
- **Protocol**: none

### TEST-STRUCT-016: Data flow cross-module forward

- **Category**: structural
- **Component**: command
- **Component-Name**: /data-flow-cross
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `/data-flow-cross forward appinfo.dll AiLaunchProcess --param 1`
- **Expected**: Parameter traced across DLL boundaries
- **Validates**: Cross-module forward trace
- **Flags-Tested**: forward, --param
- **Protocol**: workspace

### TEST-STRUCT-017: Data flow cross-module backward

- **Category**: structural
- **Component**: command
- **Component-Name**: /data-flow-cross
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `/data-flow-cross backward appinfo.dll AiLaunchProcess --target CreateProcessW --depth 2`
- **Expected**: Argument origins traced across modules
- **Validates**: Cross-module backward trace with depth
- **Flags-Tested**: backward, --target, --depth
- **Protocol**: workspace

### TEST-STRUCT-018: Imports summary

- **Category**: structural
- **Component**: command
- **Component-Name**: /imports
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/imports appinfo.dll`
- **Expected**: Import/export summary for appinfo.dll
- **Validates**: Basic import summary
- **Flags-Tested**: none (default)
- **Protocol**: none

### TEST-STRUCT-019: Imports function lookup

- **Category**: structural
- **Component**: command
- **Component-Name**: /imports
- **Target-Module**: N/A
- **Target-Function**: CreateProcessW
- **Command**: `/imports --function CreateProcessW`
- **Expected**: Which module(s) export and import CreateProcessW
- **Validates**: --function cross-module lookup
- **Flags-Tested**: --function
- **Protocol**: none

### TEST-STRUCT-020: Imports consumers

- **Category**: structural
- **Component**: command
- **Component-Name**: /imports
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/imports appinfo.dll --consumers`
- **Expected**: Modules that depend on appinfo.dll
- **Validates**: --consumers flag
- **Flags-Tested**: --consumers
- **Protocol**: none

### TEST-STRUCT-021: Imports diagram

- **Category**: structural
- **Component**: command
- **Component-Name**: /imports
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/imports appinfo.dll --diagram`
- **Expected**: Mermaid dependency diagram
- **Validates**: --diagram flag
- **Flags-Tested**: --diagram
- **Protocol**: none

### TEST-STRUCT-022: Imports forwarders module

- **Category**: structural
- **Component**: command
- **Component-Name**: /imports
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/imports --forwarders appinfo.dll`
- **Expected**: All forwarded export chains for appinfo.dll (requires --all with --module)
- **Validates**: --forwarders flag
- **Flags-Tested**: --forwarders
- **Protocol**: none

### TEST-STRUCT-023: Imports forwarders function

- **Category**: structural
- **Component**: command
- **Component-Name**: /imports
- **Target-Module**: N/A
- **Target-Function**: NtCreateFile
- **Command**: `/imports --forwarders --function NtCreateFile`
- **Expected**: Forwarder chain for NtCreateFile (requires --module with --function)
- **Validates**: --forwarders with --function
- **Flags-Tested**: --forwarders, --function
- **Protocol**: none

### TEST-STRUCT-024: Strings module

- **Category**: structural
- **Component**: command
- **Component-Name**: /strings
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/strings appinfo.dll`
- **Expected**: Categorized string literals for entire module
- **Validates**: Module-wide string analysis
- **Flags-Tested**: none (default)
- **Protocol**: none

### TEST-STRUCT-025: Strings top N

- **Category**: structural
- **Component**: command
- **Component-Name**: /strings
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/strings appinfo.dll --top 20`
- **Expected**: Top 20 security-relevant strings
- **Validates**: --top limit
- **Flags-Tested**: --top
- **Protocol**: none

### TEST-STRUCT-026: Strings by category

- **Category**: structural
- **Component**: command
- **Component-Name**: /strings
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/strings appinfo.dll --category credentials`
- **Expected**: Only credential-related strings
- **Validates**: --category filter
- **Flags-Tested**: --category
- **Protocol**: none

### TEST-STRUCT-027: Strings by category format_string

- **Category**: structural
- **Component**: command
- **Component-Name**: /strings
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/strings appinfo.dll --category format_string`
- **Expected**: Only format string patterns
- **Validates**: --category with format_string value
- **Flags-Tested**: --category
- **Protocol**: none

### TEST-STRUCT-028: Strings function-scoped

- **Category**: structural
- **Component**: command
- **Component-Name**: /strings
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `/strings appinfo.dll AiLaunchProcess`
- **Expected**: Strings referenced by AiLaunchProcess only
- **Validates**: Function-scoped string analysis
- **Flags-Tested**: function argument
- **Protocol**: none

### TEST-STRUCT-029: State machines module scan

- **Category**: structural
- **Component**: command
- **Component-Name**: /state-machines
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/state-machines appinfo.dll`
- **Expected**: Dispatch tables and state machines found in module
- **Validates**: Module-wide state machine scan
- **Flags-Tested**: none (default)
- **Protocol**: workspace

### TEST-STRUCT-030: State machines detect

- **Category**: structural
- **Component**: command
- **Component-Name**: /state-machines
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/state-machines appinfo.dll --detect`
- **Expected**: List of all dispatcher functions detected
- **Validates**: --detect flag
- **Flags-Tested**: --detect
- **Protocol**: none

### TEST-STRUCT-031: State machines function

- **Category**: structural
- **Component**: command
- **Component-Name**: /state-machines
- **Target-Module**: windows.storage.dll
- **Target-Function**: CInvokeCreateProcessVerb::Execute
- **Command**: `/state-machines windows.storage.dll CInvokeCreateProcessVerb::Execute`
- **Expected**: Dispatch table or state machine for the function
- **Validates**: Single-function extraction
- **Flags-Tested**: function argument
- **Protocol**: none

### TEST-STRUCT-032: State machines diagram

- **Category**: structural
- **Component**: command
- **Component-Name**: /state-machines
- **Target-Module**: windows.storage.dll
- **Target-Function**: CInvokeCreateProcessVerb::Execute
- **Command**: `/state-machines windows.storage.dll CInvokeCreateProcessVerb::Execute --diagram`
- **Expected**: Mermaid state diagram
- **Validates**: --diagram flag
- **Flags-Tested**: --diagram
- **Protocol**: none

### TEST-STRUCT-033: Compare modules two-way

- **Category**: structural
- **Component**: command
- **Component-Name**: /compare-modules
- **Target-Module**: shell32.dll, windows.storage.dll
- **Target-Function**: N/A
- **Command**: `/compare-modules shell32.dll windows.storage.dll`
- **Expected**: API overlap, classification distribution, dependency comparison
- **Validates**: Two-module comparison
- **Flags-Tested**: two module arguments
- **Protocol**: workspace

### TEST-STRUCT-034: Compare modules three-way

- **Category**: structural
- **Component**: command
- **Component-Name**: /compare-modules
- **Target-Module**: appinfo.dll, shell32.dll, windows.storage.dll
- **Target-Function**: N/A
- **Command**: `/compare-modules appinfo.dll shell32.dll windows.storage.dll`
- **Expected**: Three-way comparison matrix
- **Validates**: Multi-module comparison
- **Flags-Tested**: three module arguments
- **Protocol**: workspace

### TEST-STRUCT-035: Trace export

- **Category**: structural
- **Component**: command
- **Component-Name**: /trace-export
- **Target-Module**: shell32.dll
- **Target-Function**: ShellExecuteExW
- **Command**: `/trace-export shell32.dll ShellExecuteExW`
- **Expected**: Full call tree, decompiled code, Mermaid diagram from ShellExecuteExW
- **Validates**: Export trace pipeline
- **Flags-Tested**: none (default)
- **Protocol**: workspace

### TEST-STRUCT-036: Trace export list

- **Category**: structural
- **Component**: command
- **Component-Name**: /trace-export
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/trace-export appinfo.dll --list`
- **Expected**: All exports listed for appinfo.dll
- **Validates**: --list flag
- **Flags-Tested**: --list
- **Protocol**: none

### TEST-STRUCT-037: Trace export with depth

- **Category**: structural
- **Component**: command
- **Component-Name**: /trace-export
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `/trace-export appinfo.dll AiLaunchProcess --depth 4`
- **Expected**: Deeper call tree trace
- **Validates**: --depth parameter
- **Flags-Tested**: --depth
- **Protocol**: workspace

### TEST-STRUCT-038: Diff modules

- **Category**: structural
- **Component**: command
- **Component-Name**: /diff
- **Target-Module**: shell32.dll, windows.storage.dll
- **Target-Function**: N/A
- **Command**: `/diff shell32.dll windows.storage.dll`
- **Expected**: Function deltas, classification shifts, attack surface changes
- **Validates**: Module differential analysis
- **Flags-Tested**: two module arguments
- **Protocol**: none

---

## Section 4: Interface Analysis Commands

### TEST-IFACE-001: COM enumerate

- **Category**: interface
- **Component**: command
- **Component-Name**: /com
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/com appinfo.dll`
- **Expected**: COM servers, interfaces, CLSIDs for appinfo.dll
- **Validates**: Default COM enumeration
- **Flags-Tested**: module argument
- **Protocol**: none

### TEST-IFACE-002: COM surface system-wide

- **Category**: interface
- **Component**: command
- **Component-Name**: /com
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `/com surface`
- **Expected**: Risk-ranked COM attack surface across all modules
- **Validates**: surface subcommand, system-wide default
- **Flags-Tested**: surface
- **Protocol**: none

### TEST-IFACE-003: COM surface module-scoped

- **Category**: interface
- **Component**: command
- **Component-Name**: /com
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/com surface appinfo.dll`
- **Expected**: COM attack surface for appinfo.dll only (module name is a positional argument, not --module)
- **Validates**: surface subcommand with module scope
- **Flags-Tested**: surface, module
- **Protocol**: none

### TEST-IFACE-004: COM methods

- **Category**: interface
- **Component**: command
- **Component-Name**: /com
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/com methods appinfo.dll`
- **Expected**: COM methods listed
- **Validates**: methods subcommand
- **Flags-Tested**: methods
- **Protocol**: none

### TEST-IFACE-005: COM methods pseudo-IDL

- **Category**: interface
- **Component**: command
- **Component-Name**: /com
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/com methods appinfo.dll --show-pseudo-idl`
- **Expected**: Methods with pseudo-IDL syntax
- **Validates**: --show-pseudo-idl flag
- **Flags-Tested**: methods, --show-pseudo-idl
- **Protocol**: none

### TEST-IFACE-006: COM classify

- **Category**: interface
- **Component**: command
- **Component-Name**: /com
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/com classify appinfo.dll`
- **Expected**: Semantic classification of COM entry points
- **Validates**: classify subcommand
- **Flags-Tested**: classify
- **Protocol**: none

### TEST-IFACE-007: COM audit

- **Category**: interface
- **Component**: command
- **Component-Name**: /com
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/com audit appinfo.dll`
- **Expected**: COM security audit (permissions, elevation, marshalling)
- **Validates**: audit subcommand
- **Flags-Tested**: audit
- **Protocol**: none

### TEST-IFACE-008: COM privesc

- **Category**: interface
- **Component**: command
- **Component-Name**: /com
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `/com privesc --top 20`
- **Expected**: Top 20 COM privilege escalation targets
- **Validates**: privesc subcommand with --top
- **Flags-Tested**: privesc, --top
- **Protocol**: none

### TEST-IFACE-009: COM privesc with UAC

- **Category**: interface
- **Component**: command
- **Component-Name**: /com
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `/com privesc --top 20 --include-uac`
- **Expected**: Includes UAC bypass targets
- **Validates**: --include-uac flag
- **Flags-Tested**: privesc, --include-uac
- **Protocol**: none

### TEST-IFACE-010: RPC enumerate

- **Category**: interface
- **Component**: command
- **Component-Name**: /rpc
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/rpc appinfo.dll`
- **Expected**: RPC interfaces, UUIDs, procedures, endpoints
- **Validates**: Default RPC enumeration
- **Flags-Tested**: module argument
- **Protocol**: none

### TEST-IFACE-011: RPC surface system-wide

- **Category**: interface
- **Component**: command
- **Component-Name**: /rpc
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `/rpc surface`
- **Expected**: Risk-ranked RPC attack surface across all modules
- **Validates**: surface subcommand
- **Flags-Tested**: surface
- **Protocol**: none

### TEST-IFACE-012: RPC surface module-scoped

- **Category**: interface
- **Component**: command
- **Component-Name**: /rpc
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/rpc surface appinfo.dll`
- **Expected**: RPC attack surface for appinfo.dll
- **Validates**: surface with module scope
- **Flags-Tested**: surface, module
- **Protocol**: none

### TEST-IFACE-013: RPC audit

- **Category**: interface
- **Component**: command
- **Component-Name**: /rpc
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/rpc audit appinfo.dll`
- **Expected**: RPC security audit (script expects DB path, not module name)
- **Validates**: audit subcommand
- **Flags-Tested**: audit
- **Protocol**: none

### TEST-IFACE-014: RPC trace

- **Category**: interface
- **Component**: command
- **Component-Name**: /rpc
- **Target-Module**: appinfo.dll
- **Target-Function**: RAiLaunchAdminProcess
- **Command**: `/rpc trace appinfo.dll RAiLaunchAdminProcess`
- **Expected**: RPC handler data flow trace (function name uses --function flag)
- **Validates**: trace subcommand
- **Flags-Tested**: trace, function
- **Protocol**: none

### TEST-IFACE-015: RPC clients

- **Category**: interface
- **Component**: command
- **Component-Name**: /rpc
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `/rpc clients <uuid>`
- **Expected**: Modules implementing or consuming the UUID
- **Validates**: clients subcommand
- **Flags-Tested**: clients, uuid
- **Protocol**: none

### TEST-IFACE-016: RPC topology

- **Category**: interface
- **Component**: command
- **Component-Name**: /rpc
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `/rpc topology`
- **Expected**: Client-server topology graph
- **Validates**: topology subcommand
- **Flags-Tested**: topology
- **Protocol**: none

### TEST-IFACE-017: RPC topology module-scoped

- **Category**: interface
- **Component**: command
- **Component-Name**: /rpc
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/rpc topology appinfo.dll`
- **Expected**: Topology scoped to appinfo.dll (module is a positional argument, not --module)
- **Validates**: topology with module scope
- **Flags-Tested**: topology, module
- **Protocol**: none

### TEST-IFACE-018: RPC blast-radius

- **Category**: interface
- **Component**: command
- **Component-Name**: /rpc
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/rpc blast-radius appinfo.dll`
- **Expected**: Co-hosted interface impact analysis
- **Validates**: blast-radius subcommand
- **Flags-Tested**: blast-radius
- **Protocol**: none

### TEST-IFACE-019: RPC stubs

- **Category**: interface
- **Component**: command
- **Component-Name**: /rpc
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `/rpc stubs <uuid>`
- **Expected**: C# stub parameter signatures
- **Validates**: stubs subcommand
- **Flags-Tested**: stubs, uuid
- **Protocol**: none

### TEST-IFACE-020: WinRT enumerate

- **Category**: interface
- **Component**: command
- **Component-Name**: /winrt
- **Target-Module**: windows.storage.dll
- **Target-Function**: N/A
- **Command**: `/winrt windows.storage.dll`
- **Expected**: WinRT server classes, interfaces, methods
- **Validates**: Default WinRT enumeration
- **Flags-Tested**: module argument
- **Protocol**: none

### TEST-IFACE-021: WinRT surface

- **Category**: interface
- **Component**: command
- **Component-Name**: /winrt
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `/winrt surface`
- **Expected**: Risk-ranked WinRT attack surface
- **Validates**: surface subcommand
- **Flags-Tested**: surface
- **Protocol**: none

### TEST-IFACE-022: WinRT methods

- **Category**: interface
- **Component**: command
- **Component-Name**: /winrt
- **Target-Module**: windows.storage.dll
- **Target-Function**: N/A
- **Command**: `/winrt methods windows.storage.dll`
- **Expected**: WinRT methods listed
- **Validates**: methods subcommand
- **Flags-Tested**: methods
- **Protocol**: none

### TEST-IFACE-023: WinRT classify

- **Category**: interface
- **Component**: command
- **Component-Name**: /winrt
- **Target-Module**: windows.storage.dll
- **Target-Function**: N/A
- **Command**: `/winrt classify windows.storage.dll`
- **Expected**: Semantic classification of WinRT entry points
- **Validates**: classify subcommand
- **Flags-Tested**: classify
- **Protocol**: none

### TEST-IFACE-024: WinRT audit

- **Category**: interface
- **Component**: command
- **Component-Name**: /winrt
- **Target-Module**: windows.storage.dll
- **Target-Function**: N/A
- **Command**: `/winrt audit windows.storage.dll`
- **Expected**: WinRT security audit (script expects DB path, not module name)
- **Validates**: audit subcommand
- **Flags-Tested**: audit
- **Protocol**: none

### TEST-IFACE-025: WinRT privesc

- **Category**: interface
- **Component**: command
- **Component-Name**: /winrt
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `/winrt privesc --top 20`
- **Expected**: Top 20 WinRT privilege escalation targets
- **Validates**: privesc subcommand
- **Flags-Tested**: privesc, --top
- **Protocol**: none

---

## Section 5: Vulnerability Scanning Commands

### TEST-VULN-001: Scan full

- **Category**: vulnerability
- **Component**: command
- **Component-Name**: /scan
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/scan appinfo.dll`
- **Expected**: Memory + logic + taint + verification + exploitability scoring
- **Validates**: Full scan pipeline with grind loop
- **Flags-Tested**: none (default)
- **Protocol**: grind-loop, workspace

### TEST-VULN-002: Scan top N

- **Category**: vulnerability
- **Component**: command
- **Component-Name**: /scan
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/scan appinfo.dll --top 15`
- **Expected**: Findings capped at 15 per category
- **Validates**: --top limit
- **Flags-Tested**: --top
- **Protocol**: grind-loop, workspace

### TEST-VULN-003: Scan memory-only

- **Category**: vulnerability
- **Component**: command
- **Component-Name**: /scan
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/scan appinfo.dll --memory-only`
- **Expected**: Only memory corruption findings
- **Validates**: --memory-only restriction
- **Flags-Tested**: --memory-only
- **Protocol**: workspace

### TEST-VULN-004: Scan logic-only

- **Category**: vulnerability
- **Component**: command
- **Component-Name**: /scan
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/scan appinfo.dll --logic-only`
- **Expected**: Only logic vulnerability findings
- **Validates**: --logic-only restriction
- **Flags-Tested**: --logic-only
- **Protocol**: workspace

### TEST-VULN-005: Scan taint-only

- **Category**: vulnerability
- **Component**: command
- **Component-Name**: /scan
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/scan appinfo.dll --taint-only`
- **Expected**: Only taint analysis on entry points
- **Validates**: --taint-only restriction
- **Flags-Tested**: --taint-only
- **Protocol**: workspace

### TEST-VULN-006: Scan single function

- **Category**: vulnerability
- **Component**: command
- **Component-Name**: /scan
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `/scan appinfo.dll AiLaunchProcess`
- **Expected**: All detectors on single function
- **Validates**: Function-scoped scan
- **Flags-Tested**: function argument
- **Protocol**: workspace

### TEST-VULN-007: Scan auto-audit

- **Category**: vulnerability
- **Component**: command
- **Component-Name**: /scan
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/scan appinfo.dll --auto-audit`
- **Expected**: Auto-audits top 3 CRITICAL/HIGH findings
- **Validates**: --auto-audit flag
- **Flags-Tested**: --auto-audit
- **Protocol**: grind-loop, workspace

### TEST-VULN-008: Memory scan module

- **Category**: vulnerability
- **Component**: command
- **Component-Name**: /memory-scan
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/memory-scan appinfo.dll`
- **Expected**: Buffer overflow, integer, UAF, format string findings
- **Validates**: Full memory scan
- **Flags-Tested**: none (default)
- **Protocol**: none

### TEST-VULN-009: Memory scan function

- **Category**: vulnerability
- **Component**: command
- **Component-Name**: /memory-scan
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `/memory-scan appinfo.dll AiLaunchProcess`
- **Expected**: Memory scan on single function
- **Validates**: Function-scoped memory scan
- **Flags-Tested**: function argument
- **Protocol**: none

### TEST-VULN-010: Memory scan top N

- **Category**: vulnerability
- **Component**: command
- **Component-Name**: /memory-scan
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/memory-scan appinfo.dll --top 20`
- **Expected**: Top 20 findings
- **Validates**: --top limit
- **Flags-Tested**: --top
- **Protocol**: none

### TEST-VULN-011: Logic scan module

- **Category**: vulnerability
- **Component**: command
- **Component-Name**: /logic-scan
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/logic-scan appinfo.dll`
- **Expected**: Auth bypass, state errors, TOCTOU, confused deputy findings
- **Validates**: Full logic scan
- **Flags-Tested**: none (default)
- **Protocol**: none

### TEST-VULN-012: Logic scan function

- **Category**: vulnerability
- **Component**: command
- **Component-Name**: /logic-scan
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `/logic-scan appinfo.dll AiLaunchProcess`
- **Expected**: Logic scan on single function
- **Validates**: Function-scoped logic scan
- **Flags-Tested**: function argument
- **Protocol**: none

### TEST-VULN-013: Logic scan top N

- **Category**: vulnerability
- **Component**: command
- **Component-Name**: /logic-scan
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/logic-scan appinfo.dll --top 10`
- **Expected**: Top 10 findings
- **Validates**: --top limit
- **Flags-Tested**: --top
- **Protocol**: none

### TEST-VULN-014: Logic scan by ID

- **Category**: vulnerability
- **Component**: command
- **Component-Name**: /logic-scan
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/logic-scan appinfo.dll --id 42`
- **Expected**: Logic scan on function with ID 42
- **Validates**: --id flag
- **Flags-Tested**: --id
- **Protocol**: none

### TEST-VULN-015: Taint default forward

- **Category**: vulnerability
- **Component**: command
- **Component-Name**: /taint
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `/taint appinfo.dll AiLaunchProcess`
- **Expected**: Forward taint of all parameters to sinks
- **Validates**: Default forward taint
- **Flags-Tested**: none (default)
- **Protocol**: none

### TEST-VULN-016: Taint specific params

- **Category**: vulnerability
- **Component**: command
- **Component-Name**: /taint
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `/taint appinfo.dll AiLaunchProcess --params 1,3`
- **Expected**: Only params 1 and 3 traced
- **Validates**: --params filter
- **Flags-Tested**: --params
- **Protocol**: none

### TEST-VULN-017: Taint with depth

- **Category**: vulnerability
- **Component**: command
- **Component-Name**: /taint
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `/taint appinfo.dll AiLaunchProcess --params 1 --depth 3`
- **Expected**: Deeper recursion trace
- **Validates**: --depth parameter
- **Flags-Tested**: --params, --depth
- **Protocol**: none

### TEST-VULN-018: Taint both directions

- **Category**: vulnerability
- **Component**: command
- **Component-Name**: /taint
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `/taint appinfo.dll AiLaunchProcess --direction both`
- **Expected**: Forward and backward taint combined
- **Validates**: --direction both
- **Flags-Tested**: --direction both
- **Protocol**: none

### TEST-VULN-019: Taint backward

- **Category**: vulnerability
- **Component**: command
- **Component-Name**: /taint
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `/taint appinfo.dll AiLaunchProcess --direction backward`
- **Expected**: Caller origins only
- **Validates**: --direction backward
- **Flags-Tested**: --direction backward
- **Protocol**: none

### TEST-VULN-020: Taint cross-module

- **Category**: vulnerability
- **Component**: command
- **Component-Name**: /taint
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `/taint appinfo.dll AiLaunchProcess --cross-module`
- **Expected**: Taint traced across DLL boundaries
- **Validates**: --cross-module flag
- **Flags-Tested**: --cross-module
- **Protocol**: none

### TEST-VULN-021: Taint cross-module with depth

- **Category**: vulnerability
- **Component**: command
- **Component-Name**: /taint
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `/taint appinfo.dll AiLaunchProcess --cross-module --cross-depth 3`
- **Expected**: Deeper cross-module taint
- **Validates**: --cross-depth parameter
- **Flags-Tested**: --cross-module, --cross-depth
- **Protocol**: none

### TEST-VULN-022: Taint disable analysis features

- **Category**: vulnerability
- **Component**: command
- **Component-Name**: /taint
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `/taint appinfo.dll AiLaunchProcess --no-trust-analysis --no-com-resolve`
- **Expected**: Taint without trust boundary or COM resolution
- **Validates**: --no-trust-analysis and --no-com-resolve flags
- **Flags-Tested**: --no-trust-analysis, --no-com-resolve
- **Protocol**: none

### TEST-VULN-023: Taint from entrypoints

- **Category**: vulnerability
- **Component**: command
- **Component-Name**: /taint
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/taint appinfo.dll --from-entrypoints`
- **Expected**: Auto-discovers top entry points and taints each
- **Validates**: --from-entrypoints mode
- **Flags-Tested**: --from-entrypoints
- **Protocol**: none

### TEST-VULN-024: Taint from entrypoints with filters

- **Category**: vulnerability
- **Component**: command
- **Component-Name**: /taint
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/taint appinfo.dll --from-entrypoints --top 10 --min-score 0.4`
- **Expected**: Top 10 entry points above score 0.4
- **Validates**: --top and --min-score with entrypoints mode
- **Flags-Tested**: --from-entrypoints, --top, --min-score
- **Protocol**: none

---

## Section 6: Security Auditing Commands

### TEST-AUDIT-001: Audit specific function

- **Category**: security
- **Component**: command
- **Component-Name**: /audit
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `/audit appinfo.dll AiLaunchProcess`
- **Expected**: Security dossier, taint trace, verification, risk assessment
- **Validates**: Full audit pipeline with workspace protocol
- **Flags-Tested**: module, function
- **Protocol**: workspace

### TEST-AUDIT-002: Audit cross-module search

- **Category**: security
- **Component**: command
- **Component-Name**: /audit
- **Target-Module**: N/A
- **Target-Function**: AiCheckSecureApplicationDirectory
- **Command**: `/audit AiCheckSecureApplicationDirectory`
- **Expected**: Auto-detects module, runs full audit
- **Validates**: Cross-module function resolution for audit
- **Flags-Tested**: function only
- **Protocol**: workspace

### TEST-AUDIT-003: Audit pattern search

- **Category**: security
- **Component**: command
- **Component-Name**: /audit
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/audit appinfo.dll --search CheckSecurity`
- **Expected**: Finds matching function, audits it
- **Validates**: --search pattern matching
- **Flags-Tested**: --search
- **Protocol**: workspace

### TEST-AUDIT-004: Batch audit default

- **Category**: security
- **Component**: command
- **Component-Name**: /batch-audit
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/batch-audit appinfo.dll`
- **Expected**: Audits top 5 entry points with grind loop
- **Validates**: Default batch audit with grind loop
- **Flags-Tested**: none (default)
- **Protocol**: grind-loop, workspace

### TEST-AUDIT-005: Batch audit top N

- **Category**: security
- **Component**: command
- **Component-Name**: /batch-audit
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/batch-audit appinfo.dll --top 10`
- **Expected**: Audits top 10 entry points
- **Validates**: --top flag
- **Flags-Tested**: --top
- **Protocol**: grind-loop, workspace

### TEST-AUDIT-006: Batch audit with min score

- **Category**: security
- **Component**: command
- **Component-Name**: /batch-audit
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/batch-audit appinfo.dll --top 10 --min-score 0.4`
- **Expected**: Only entry points with attack score >= 0.4
- **Validates**: --min-score filter
- **Flags-Tested**: --top, --min-score
- **Protocol**: grind-loop, workspace

### TEST-AUDIT-007: Batch audit privilege boundary

- **Category**: security
- **Component**: command
- **Component-Name**: /batch-audit
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/batch-audit appinfo.dll --privilege-boundary`
- **Expected**: Audits RPC/COM/WinRT handlers
- **Validates**: --privilege-boundary flag
- **Flags-Tested**: --privilege-boundary
- **Protocol**: grind-loop, workspace

### TEST-AUDIT-008: Batch audit privilege boundary with top

- **Category**: security
- **Component**: command
- **Component-Name**: /batch-audit
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/batch-audit appinfo.dll --privilege-boundary --top 8`
- **Expected**: Top 8 privilege-boundary handlers
- **Validates**: --privilege-boundary with --top
- **Flags-Tested**: --privilege-boundary, --top
- **Protocol**: grind-loop, workspace

### TEST-AUDIT-009: Batch audit explicit functions

- **Category**: security
- **Component**: command
- **Component-Name**: /batch-audit
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess, AiCheckSecureApplicationDirectory
- **Command**: `/batch-audit appinfo.dll AiLaunchProcess AiCheckSecureApplicationDirectory`
- **Expected**: Audits exactly the named functions
- **Validates**: Explicit function list
- **Flags-Tested**: function arguments
- **Protocol**: grind-loop, workspace

### TEST-AUDIT-010: Prioritize multi-module

- **Category**: security
- **Component**: command
- **Component-Name**: /prioritize
- **Target-Module**: appinfo.dll, shell32.dll
- **Target-Function**: N/A
- **Command**: `/prioritize --modules appinfo.dll shell32.dll`
- **Expected**: Cross-module finding prioritization
- **Validates**: --modules flag with multiple modules
- **Flags-Tested**: --modules
- **Protocol**: workspace

### TEST-AUDIT-011: Prioritize all

- **Category**: security
- **Component**: command
- **Component-Name**: /prioritize
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `/prioritize --all`
- **Expected**: All modules prioritized
- **Validates**: --all flag
- **Flags-Tested**: --all
- **Protocol**: workspace

### TEST-AUDIT-012: Prioritize with filters

- **Category**: security
- **Component**: command
- **Component-Name**: /prioritize
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `/prioritize --all --min-score 0.5 --top 20`
- **Expected**: Top 20 findings with composite score >= 0.5
- **Validates**: --min-score and --top filters
- **Flags-Tested**: --all, --min-score, --top
- **Protocol**: workspace

---

## Section 7: VR Campaign Commands

### TEST-VR-001: Hunt campaign

- **Category**: vr-campaign
- **Component**: command
- **Component-Name**: /hunt
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/hunt appinfo.dll`
- **Expected**: Structured VR campaign plan with hypotheses
- **Validates**: Default campaign mode
- **Flags-Tested**: none (default)
- **Protocol**: none

### TEST-VR-002: Hunt hypothesis

- **Category**: vr-campaign
- **Component**: command
- **Component-Name**: /hunt
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/hunt hypothesis TOCTOU appinfo.dll`
- **Expected**: TOCTOU-specific hypothesis with verification strategy
- **Validates**: hypothesis mode with vulnerability class
- **Flags-Tested**: hypothesis, type
- **Protocol**: none

### TEST-VR-003: Hunt variant

- **Category**: vr-campaign
- **Component**: command
- **Component-Name**: /hunt
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/hunt variant junction appinfo.dll`
- **Expected**: Junction-based attack variant analysis
- **Validates**: variant mode with pattern
- **Flags-Tested**: variant, pattern
- **Protocol**: none

### TEST-VR-004: Hunt validate

- **Category**: vr-campaign
- **Component**: command
- **Component-Name**: /hunt
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `/hunt validate appinfo.dll AiLaunchProcess`
- **Expected**: Validation strategy for suspected finding
- **Validates**: validate mode with function
- **Flags-Tested**: validate, function
- **Protocol**: none

### TEST-VR-005: Hunt surface

- **Category**: vr-campaign
- **Component**: command
- **Component-Name**: /hunt
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/hunt surface appinfo.dll`
- **Expected**: Trust boundary mapping
- **Validates**: surface mode
- **Flags-Tested**: surface
- **Protocol**: none

### TEST-VR-006: Hunt execute

- **Category**: vr-campaign
- **Component**: command
- **Component-Name**: /hunt-execute
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/hunt-execute appinfo.dll`
- **Expected**: Executes most recent hunt plan with confidence scores
- **Validates**: Hunt plan execution with grind loop
- **Flags-Tested**: module
- **Protocol**: grind-loop, workspace

### TEST-VR-007: Hunt execute with plan file

- **Category**: vr-campaign
- **Component**: command
- **Component-Name**: /hunt-execute
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `/hunt-execute --plan-file <path>`
- **Expected**: Executes specific plan file
- **Validates**: --plan-file flag
- **Flags-Tested**: --plan-file
- **Protocol**: grind-loop, workspace

### TEST-VR-008: Brainstorm

- **Category**: vr-campaign
- **Component**: command
- **Component-Name**: /brainstorm
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/brainstorm privilege escalation in appinfo.dll`
- **Expected**: Interactive strategy dialogue
- **Validates**: Brainstorming skill engagement
- **Flags-Tested**: topic
- **Protocol**: none

---

## Section 8: Code Quality Commands

### TEST-QUAL-001: Verify cross-module

- **Category**: code-quality
- **Component**: command
- **Component-Name**: /verify
- **Target-Module**: N/A
- **Target-Function**: AiCheckSecureApplicationDirectory
- **Command**: `/verify AiCheckSecureApplicationDirectory`
- **Expected**: Auto-detects module, verifies decompiler accuracy
- **Validates**: Cross-module function resolution for verify
- **Flags-Tested**: function only
- **Protocol**: none

### TEST-QUAL-002: Verify specific function

- **Category**: code-quality
- **Component**: command
- **Component-Name**: /verify
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `/verify appinfo.dll AiLaunchProcess`
- **Expected**: Instruction-by-instruction verification
- **Validates**: Deep function verification
- **Flags-Tested**: module, function
- **Protocol**: none

### TEST-QUAL-003: Verify module scan

- **Category**: code-quality
- **Component**: command
- **Component-Name**: /verify
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/verify appinfo.dll`
- **Expected**: Heuristic scan of entire module
- **Validates**: Module-wide verification scan
- **Flags-Tested**: module only
- **Protocol**: none

### TEST-QUAL-004: Verify module top N

- **Category**: code-quality
- **Component**: command
- **Component-Name**: /verify
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/verify appinfo.dll --top 10`
- **Expected**: Top 10 decompiler issues
- **Validates**: --top limit for module scan
- **Flags-Tested**: --top
- **Protocol**: none

### TEST-QUAL-005: Verify batch functions

- **Category**: code-quality
- **Component**: command
- **Component-Name**: /verify-batch
- **Target-Module**: appinfo.dll
- **Target-Function**: AiCheckSecureApplicationDirectory, AiLaunchProcess
- **Command**: `/verify-batch appinfo.dll AiCheckSecureApplicationDirectory AiLaunchProcess`
- **Expected**: Parallel verification of both functions
- **Validates**: Batch verification with grind loop
- **Flags-Tested**: function list
- **Protocol**: grind-loop, workspace

### TEST-QUAL-006: Lift class list

- **Category**: code-quality
- **Component**: command
- **Component-Name**: /lift-class
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/lift-class appinfo.dll --list`
- **Expected**: All detected classes listed
- **Validates**: --list flag
- **Flags-Tested**: --list
- **Protocol**: none

### TEST-QUAL-007: Lift class execute

- **Category**: code-quality
- **Component**: command
- **Component-Name**: /lift-class
- **Target-Module**: windows.storage.dll
- **Target-Function**: N/A
- **Command**: `/lift-class windows.storage.dll CInvokeCreateProcessVerb`
- **Expected**: All methods lifted with shared context
- **Validates**: Full class lifting pipeline
- **Flags-Tested**: class argument
- **Protocol**: grind-loop, workspace

### TEST-QUAL-008: Lift class cross-module

- **Category**: code-quality
- **Component**: command
- **Component-Name**: /lift-class
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `/lift-class CInvokeCreateProcessVerb`
- **Expected**: Auto-detects module, lifts class
- **Validates**: Cross-module class resolution
- **Flags-Tested**: class only
- **Protocol**: grind-loop, workspace

### TEST-QUAL-009: Reconstruct types all

- **Category**: code-quality
- **Component**: command
- **Component-Name**: /reconstruct-types
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/reconstruct-types appinfo.dll`
- **Expected**: All types reconstructed with confidence scores
- **Validates**: Full type reconstruction
- **Flags-Tested**: module only
- **Protocol**: workspace

### TEST-QUAL-010: Reconstruct types specific class

- **Category**: code-quality
- **Component**: command
- **Component-Name**: /reconstruct-types
- **Target-Module**: windows.storage.dll
- **Target-Function**: N/A
- **Command**: `/reconstruct-types windows.storage.dll CInvokeCreateProcessVerb`
- **Expected**: Single class type reconstruction
- **Validates**: Class-scoped reconstruction
- **Flags-Tested**: class argument
- **Protocol**: workspace

### TEST-QUAL-011: Reconstruct types with COM

- **Category**: code-quality
- **Component**: command
- **Component-Name**: /reconstruct-types
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/reconstruct-types appinfo.dll --include-com`
- **Expected**: Types with COM interface reconstruction included
- **Validates**: --include-com flag
- **Flags-Tested**: --include-com
- **Protocol**: workspace

### TEST-QUAL-012: Reconstruct types with validate

- **Category**: code-quality
- **Component**: command
- **Component-Name**: /reconstruct-types
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/reconstruct-types appinfo.dll --validate`
- **Expected**: Types validated against assembly
- **Validates**: --validate flag
- **Flags-Tested**: --validate
- **Protocol**: workspace

---

## Section 9: Reporting and Ops Commands

### TEST-OPS-001: Runs list

- **Category**: ops
- **Component**: command
- **Component-Name**: /runs
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `/runs`
- **Expected**: 10 most recent workspace runs listed
- **Validates**: Default run listing
- **Flags-Tested**: none (default)
- **Protocol**: none

### TEST-OPS-002: Runs list module

- **Category**: ops
- **Component**: command
- **Component-Name**: /runs
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/runs list appinfo.dll`
- **Expected**: Recent runs filtered to appinfo.dll
- **Validates**: Module filter
- **Flags-Tested**: list, module
- **Protocol**: none

### TEST-OPS-003: Runs show

- **Category**: ops
- **Component**: command
- **Component-Name**: /runs
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `/runs show <run_id>`
- **Expected**: Reopens specific run with manifest and step summaries
- **Validates**: show subcommand
- **Flags-Tested**: show, run_id
- **Protocol**: none

### TEST-OPS-004: Runs latest

- **Category**: ops
- **Component**: command
- **Component-Name**: /runs
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/runs latest appinfo.dll`
- **Expected**: Reopens newest run for appinfo.dll
- **Validates**: latest subcommand
- **Flags-Tested**: latest, module
- **Protocol**: none

### TEST-OPS-005: Cache stats

- **Category**: ops
- **Component**: command
- **Component-Name**: /cache-manage
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `/cache-manage stats`
- **Expected**: Cache size, hit rates, oldest entries
- **Validates**: stats subcommand
- **Flags-Tested**: stats
- **Protocol**: none

### TEST-OPS-006: Cache clear module

- **Category**: ops
- **Component**: command
- **Component-Name**: /cache-manage
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/cache-manage clear appinfo.dll`
- **Expected**: Cache cleared for appinfo.dll
- **Validates**: clear subcommand with module
- **Flags-Tested**: clear, module
- **Protocol**: none

### TEST-OPS-007: Cache refresh

- **Category**: ops
- **Component**: command
- **Component-Name**: /cache-manage
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/cache-manage refresh appinfo.dll`
- **Expected**: Clear and re-run common analysis
- **Validates**: refresh subcommand
- **Flags-Tested**: refresh, module
- **Protocol**: none

### TEST-OPS-008: Cache purge runs

- **Category**: ops
- **Component**: command
- **Component-Name**: /cache-manage
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `/cache-manage purge-runs`
- **Expected**: Old workspace runs deleted
- **Validates**: purge-runs subcommand
- **Flags-Tested**: purge-runs
- **Protocol**: none

### TEST-OPS-009: Cache purge runs with age

- **Category**: ops
- **Component**: command
- **Component-Name**: /cache-manage
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `/cache-manage purge-runs --older-than 1`
- **Expected**: Runs older than 1 day deleted
- **Validates**: --older-than flag
- **Flags-Tested**: purge-runs, --older-than
- **Protocol**: none

### TEST-OPS-010: Pipeline list steps

- **Category**: ops
- **Component**: command
- **Component-Name**: /pipeline
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `/pipeline list-steps`
- **Expected**: All available pipeline steps listed
- **Validates**: list-steps subcommand
- **Flags-Tested**: list-steps
- **Protocol**: none

### TEST-OPS-011: Pipeline validate

- **Category**: ops
- **Component**: command
- **Component-Name**: /pipeline
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `/pipeline validate .agent/config/pipelines/security-sweep.yaml`
- **Expected**: YAML validated without execution
- **Validates**: validate subcommand
- **Flags-Tested**: validate
- **Protocol**: none

### TEST-OPS-012: Pipeline dry run

- **Category**: ops
- **Component**: command
- **Component-Name**: /pipeline
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `/pipeline run .agent/config/pipelines/quick-triage.yaml --dry-run`
- **Expected**: Preview without execution
- **Validates**: --dry-run flag
- **Flags-Tested**: run, --dry-run
- **Protocol**: none

### TEST-OPS-013: Pipeline run with module override

- **Category**: ops
- **Component**: command
- **Component-Name**: /pipeline
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/pipeline run .agent/config/pipelines/security-sweep.yaml --modules appinfo.dll`
- **Expected**: Pipeline runs only on appinfo.dll
- **Validates**: --modules override
- **Flags-Tested**: run, --modules
- **Protocol**: none

---

## Section 10: Direct Skill Script Tests

### TEST-SKILL-001: find_module_db list

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: decompiled-code-extractor/find_module_db.py
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py --list --json`
- **Expected**: JSON with modules array, each having analysis_db_path
- **Validates**: Module listing with --list --json
- **Flags-Tested**: --list, --json
- **Protocol**: none

### TEST-SKILL-002: find_module_db by name

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: decompiled-code-extractor/find_module_db.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll --json`
- **Expected**: JSON with db_path field
- **Validates**: Single module lookup
- **Flags-Tested**: module, --json
- **Protocol**: none

### TEST-SKILL-003: find_module_db by extension

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: decompiled-code-extractor/find_module_db.py
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py --ext .dll --json`
- **Expected**: All DLL modules listed
- **Validates**: --ext filter
- **Flags-Tested**: --ext, --json
- **Protocol**: none

### TEST-SKILL-004: list_functions search

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: decompiled-code-extractor/list_functions.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/decompiled-code-extractor/scripts/list_functions.py <db:appinfo> --search "Launch" --json`
- **Expected**: JSON with matching functions
- **Validates**: --search pattern matching
- **Flags-Tested**: --search, --json
- **Protocol**: none

### TEST-SKILL-005: list_functions with signatures

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: decompiled-code-extractor/list_functions.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/decompiled-code-extractor/scripts/list_functions.py <db:appinfo> --has-decompiled --with-signatures --limit 10 --json`
- **Expected**: 10 functions with signatures, all having decompiled code
- **Validates**: --has-decompiled, --with-signatures, --limit
- **Flags-Tested**: --has-decompiled, --with-signatures, --limit, --json
- **Protocol**: none

### TEST-SKILL-006: extract_function_data by name

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: decompiled-code-extractor/extract_function_data.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py <db:appinfo> AiLaunchProcess --json`
- **Expected**: Full function data: decompiled code, assembly, xrefs, strings
- **Validates**: Function extraction by name
- **Flags-Tested**: function, --json
- **Protocol**: none

### TEST-SKILL-007: extract_function_data search

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: decompiled-code-extractor/extract_function_data.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py <db:appinfo> --search "ShellExecute" --json`
- **Expected**: Search results as JSON
- **Validates**: --search with --json
- **Flags-Tested**: --search, --json
- **Protocol**: none

### TEST-SKILL-008: lookup_function basic

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: function-index/lookup_function.py
- **Target-Module**: N/A
- **Target-Function**: ShellExecuteExW
- **Command**: `python .agent/skills/function-index/scripts/lookup_function.py ShellExecuteExW`
- **Expected**: Module and .cpp file path for ShellExecuteExW
- **Validates**: Cross-module function lookup
- **Flags-Tested**: function name
- **Protocol**: none

### TEST-SKILL-009: lookup_function regex

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: function-index/lookup_function.py
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `python .agent/skills/function-index/scripts/lookup_function.py --search "Ai.*Process" --regex --json`
- **Expected**: All matching functions across modules
- **Validates**: --search --regex mode
- **Flags-Tested**: --search, --regex, --json
- **Protocol**: none

### TEST-SKILL-010: lookup_function module + app-only

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: function-index/lookup_function.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/function-index/scripts/index_functions.py appinfo.dll --app-only --json`
- **Expected**: Only application functions in appinfo.dll (uses index_functions for listing)
- **Validates**: Module function listing with --app-only filter
- **Flags-Tested**: --module, --app-only, --json
- **Protocol**: none

### TEST-SKILL-011: index_functions stats

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: function-index/index_functions.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/function-index/scripts/index_functions.py appinfo.dll --stats --json`
- **Expected**: Function count statistics
- **Validates**: --stats mode
- **Flags-Tested**: --stats, --json
- **Protocol**: none

### TEST-SKILL-012: index_functions all app-only

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: function-index/index_functions.py
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `python .agent/skills/function-index/scripts/index_functions.py --all --app-only --json`
- **Expected**: All application functions across all modules
- **Validates**: --all --app-only
- **Flags-Tested**: --all, --app-only, --json
- **Protocol**: none

### TEST-SKILL-013: index_functions by-file

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: function-index/index_functions.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/function-index/scripts/index_functions.py appinfo.dll --by-file --json`
- **Expected**: Functions grouped by .cpp file
- **Validates**: --by-file grouping
- **Flags-Tested**: --by-file, --json
- **Protocol**: none

### TEST-SKILL-014: resolve_function_file

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: function-index/resolve_function_file.py
- **Target-Module**: N/A
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/skills/function-index/scripts/resolve_function_file.py AiLaunchProcess --json`
- **Expected**: Absolute file path for AiLaunchProcess
- **Validates**: Single function file resolution
- **Flags-Tested**: function, --json
- **Protocol**: none

### TEST-SKILL-015: resolve_function_file batch

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: function-index/resolve_function_file.py
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `python .agent/skills/function-index/scripts/resolve_function_file.py --names "AiLaunchProcess,AiCheckLUA" --json`
- **Expected**: File paths for both functions
- **Validates**: --names batch resolution
- **Flags-Tested**: --names, --json
- **Protocol**: none

### TEST-SKILL-016: triage_summary

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: classify-functions/triage_summary.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/classify-functions/scripts/triage_summary.py <db:appinfo> --top 5 --json`
- **Expected**: Top 5 classification categories with counts
- **Validates**: Classification triage with --top
- **Flags-Tested**: --top, --json
- **Protocol**: none

### TEST-SKILL-017: triage_summary app-only

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: classify-functions/triage_summary.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/classify-functions/scripts/triage_summary.py <db:appinfo> --app-only --json`
- **Expected**: Only application function classifications
- **Validates**: --app-only filter
- **Flags-Tested**: --app-only, --json
- **Protocol**: none

### TEST-SKILL-018: triage_summary no-cache

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: classify-functions/triage_summary.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/classify-functions/scripts/triage_summary.py <db:appinfo> --json --no-cache`
- **Expected**: Fresh computation, no cache hit
- **Validates**: --no-cache bypass
- **Flags-Tested**: --json, --no-cache
- **Protocol**: none

### TEST-SKILL-019: classify_module full

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: classify-functions/classify_module.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/classify-functions/scripts/classify_module.py <db:appinfo> --json`
- **Expected**: Complete categorized function index
- **Validates**: Full module classification
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-SKILL-020: classify_module with filters

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: classify-functions/classify_module.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/classify-functions/scripts/classify_module.py <db:appinfo> --category security --min-interest 5 --no-telemetry --no-compiler --json`
- **Expected**: Only security category, interest >= 5, no telemetry/compiler
- **Validates**: --category, --min-interest, --no-telemetry, --no-compiler
- **Flags-Tested**: --category, --min-interest, --no-telemetry, --no-compiler, --json
- **Protocol**: none

### TEST-SKILL-021: classify_function

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: classify-functions/classify_function.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/skills/classify-functions/scripts/classify_function.py <db:appinfo> AiLaunchProcess --json`
- **Expected**: Detailed classification for single function
- **Validates**: Single function classification
- **Flags-Tested**: function, --json
- **Protocol**: none

### TEST-SKILL-022: classify_function search

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: classify-functions/classify_function.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/classify-functions/scripts/classify_function.py <db:appinfo> --search "Launch" --json`
- **Expected**: Classification for matching functions
- **Validates**: --search with classify
- **Flags-Tested**: --search, --json
- **Protocol**: none

### TEST-SKILL-023: build_call_graph stats

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: callgraph-tracer/build_call_graph.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/callgraph-tracer/scripts/build_call_graph.py <db:appinfo> --stats --json`
- **Expected**: Node/edge counts, hub functions, density
- **Validates**: --stats mode
- **Flags-Tested**: --stats, --json
- **Protocol**: none

### TEST-SKILL-024: build_call_graph scc

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: callgraph-tracer/build_call_graph.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/callgraph-tracer/scripts/build_call_graph.py <db:appinfo> --scc --json`
- **Expected**: Strongly connected components
- **Validates**: --scc flag
- **Flags-Tested**: --scc, --json
- **Protocol**: none

### TEST-SKILL-025: build_call_graph path

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: callgraph-tracer/build_call_graph.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/callgraph-tracer/scripts/build_call_graph.py <db:appinfo> --path AiLaunchProcess AiCheckSecureApplicationDirectory --json`
- **Expected**: Shortest path between functions
- **Validates**: --path flag
- **Flags-Tested**: --path, --json
- **Protocol**: none

### TEST-SKILL-026: build_call_graph reachable

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: callgraph-tracer/build_call_graph.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/skills/callgraph-tracer/scripts/build_call_graph.py <db:appinfo> --reachable AiLaunchProcess --json`
- **Expected**: Transitive closure of reachable functions
- **Validates**: --reachable flag
- **Flags-Tested**: --reachable, --json
- **Protocol**: none

### TEST-SKILL-027: build_call_graph neighbors

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: callgraph-tracer/build_call_graph.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/skills/callgraph-tracer/scripts/build_call_graph.py <db:appinfo> --neighbors AiLaunchProcess --json`
- **Expected**: Immediate callers and callees
- **Validates**: --neighbors flag
- **Flags-Tested**: --neighbors, --json
- **Protocol**: none

### TEST-SKILL-028: build_call_graph no-cache

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: callgraph-tracer/build_call_graph.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/callgraph-tracer/scripts/build_call_graph.py <db:appinfo> --stats --json --no-cache`
- **Expected**: Fresh computation bypassing cache
- **Validates**: --no-cache for cacheable script
- **Flags-Tested**: --stats, --json, --no-cache
- **Protocol**: none

### TEST-SKILL-029: chain_analysis

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: callgraph-tracer/chain_analysis.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/skills/callgraph-tracer/scripts/chain_analysis.py <db:appinfo> AiLaunchProcess --depth 3 --json`
- **Expected**: Cross-module chain analysis to depth 3
- **Validates**: Chain analysis with depth
- **Flags-Tested**: function, --depth, --json
- **Protocol**: none

### TEST-SKILL-030: chain_analysis summary

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: callgraph-tracer/chain_analysis.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/skills/callgraph-tracer/scripts/chain_analysis.py <db:appinfo> AiLaunchProcess --summary --no-code --json`
- **Expected**: Compact summary without code
- **Validates**: --summary and --no-code flags
- **Flags-Tested**: --summary, --no-code, --json
- **Protocol**: none

### TEST-SKILL-031: cross_module_resolve

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: callgraph-tracer/cross_module_resolve.py
- **Target-Module**: N/A
- **Target-Function**: ShellExecuteExW
- **Command**: `python .agent/skills/callgraph-tracer/scripts/cross_module_resolve.py ShellExecuteExW --json`
- **Expected**: Resolution to target module (stderr warnings about tracking DB are expected behavior)
- **Validates**: Simple function resolution
- **Flags-Tested**: function, --json
- **Protocol**: none

### TEST-SKILL-032: cross_module_resolve all

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: callgraph-tracer/cross_module_resolve.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/skills/callgraph-tracer/scripts/cross_module_resolve.py --resolve-all <db:appinfo> AiLaunchProcess --json`
- **Expected**: All external calls resolved
- **Validates**: --resolve-all mode
- **Flags-Tested**: --resolve-all, --json
- **Protocol**: none

### TEST-SKILL-033: module_dependencies overview

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: callgraph-tracer/module_dependencies.py
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `python .agent/skills/callgraph-tracer/scripts/module_dependencies.py --overview --json`
- **Expected**: Cross-module dependency overview
- **Validates**: --overview mode
- **Flags-Tested**: --overview, --json
- **Protocol**: none

### TEST-SKILL-034: module_dependencies module

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: callgraph-tracer/module_dependencies.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/callgraph-tracer/scripts/module_dependencies.py --module appinfo.dll --json`
- **Expected**: Dependencies for appinfo.dll
- **Validates**: --module mode
- **Flags-Tested**: --module, --json
- **Protocol**: none

### TEST-SKILL-035: analyze_detailed_xrefs

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: callgraph-tracer/analyze_detailed_xrefs.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/skills/callgraph-tracer/scripts/analyze_detailed_xrefs.py <db:appinfo> --function AiLaunchProcess --json`
- **Expected**: Detailed xref structures
- **Validates**: Function-scoped xref analysis
- **Flags-Tested**: --function, --json
- **Protocol**: none

### TEST-SKILL-036: generate_diagram

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: callgraph-tracer/generate_diagram.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/skills/callgraph-tracer/scripts/generate_diagram.py <db:appinfo> --function AiLaunchProcess --format mermaid --json`
- **Expected**: Mermaid diagram syntax
- **Validates**: Diagram generation
- **Flags-Tested**: --function, --format mermaid, --json
- **Protocol**: none

### TEST-SKILL-037: forward_trace

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: data-flow-tracer/forward_trace.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/skills/data-flow-tracer/scripts/forward_trace.py <db:appinfo> AiLaunchProcess --param 1 --json`
- **Expected**: Forward parameter flow
- **Validates**: Forward trace
- **Flags-Tested**: function, --param, --json
- **Protocol**: none

### TEST-SKILL-038: forward_trace deep + assembly

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: data-flow-tracer/forward_trace.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/skills/data-flow-tracer/scripts/forward_trace.py <db:appinfo> AiLaunchProcess --param 1 --depth 3 --assembly --json`
- **Expected**: Deeper trace with assembly annotations
- **Validates**: --depth and --assembly
- **Flags-Tested**: --param, --depth, --assembly, --json
- **Protocol**: none

### TEST-SKILL-039: backward_trace

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: data-flow-tracer/backward_trace.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/skills/data-flow-tracer/scripts/backward_trace.py <db:appinfo> AiLaunchProcess --target CreateProcessAsUserW --json`
- **Expected**: Argument origins for CreateProcessAsUserW (AiLaunchProcess calls CreateProcessAsUserW, not CreateProcessW). Depends on multi-line call parsing support in `decompiled_parser.py` and xref-first discovery via `discover_calls_with_xrefs()`.
- **Validates**: Backward trace with --target, xref-first call discovery
- **Flags-Tested**: function, --target, --json
- **Protocol**: none

### TEST-SKILL-040: backward_trace with callers

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: data-flow-tracer/backward_trace.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/skills/data-flow-tracer/scripts/backward_trace.py <db:appinfo> AiLaunchProcess --target CreateProcessAsUserW --arg 1 --callers --json`
- **Expected**: Origin traced through callers (AiLaunchProcess calls CreateProcessAsUserW, not CreateProcessW). Depends on multi-line call parsing support in `decompiled_parser.py` and xref-first discovery via `discover_calls_with_xrefs()`.
- **Validates**: --arg and --callers, xref-first call discovery
- **Flags-Tested**: --target, --arg, --callers, --json
- **Protocol**: none

### TEST-SKILL-041: global_state_map

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: data-flow-tracer/global_state_map.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/data-flow-tracer/scripts/global_state_map.py <db:appinfo> --summary --json`
- **Expected**: Global variable reader/writer summary
- **Validates**: Global state mapping
- **Flags-Tested**: --summary, --json
- **Protocol**: none

### TEST-SKILL-042: global_state_map filtered

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: data-flow-tracer/global_state_map.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/data-flow-tracer/scripts/global_state_map.py <db:appinfo> --shared-only --writers-only --json`
- **Expected**: Only shared globals with writers
- **Validates**: --shared-only, --writers-only
- **Flags-Tested**: --shared-only, --writers-only, --json
- **Protocol**: none

### TEST-SKILL-043: string_trace by string

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: data-flow-tracer/string_trace.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/data-flow-tracer/scripts/string_trace.py <db:appinfo> --string "CreateProcess" --json`
- **Expected**: Functions referencing the string
- **Validates**: --string search
- **Flags-Tested**: --string, --json
- **Protocol**: none

### TEST-SKILL-044: string_trace by function

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: data-flow-tracer/string_trace.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/skills/data-flow-tracer/scripts/string_trace.py <db:appinfo> --function AiLaunchProcess --json`
- **Expected**: Strings used by AiLaunchProcess
- **Validates**: --function mode
- **Flags-Tested**: --function, --json
- **Protocol**: none

### TEST-SKILL-045: string_trace list

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: data-flow-tracer/string_trace.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/data-flow-tracer/scripts/string_trace.py <db:appinfo> --list-strings --limit 20 --json`
- **Expected**: Top 20 strings
- **Validates**: --list-strings, --limit
- **Flags-Tested**: --list-strings, --limit, --json
- **Protocol**: none

### TEST-SKILL-046: discover_entrypoints

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: map-attack-surface/discover_entrypoints.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/map-attack-surface/scripts/discover_entrypoints.py <db:appinfo> --json`
- **Expected**: Entry points categorized by type
- **Validates**: Entry point discovery
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-SKILL-047: discover_entrypoints no-cache

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: map-attack-surface/discover_entrypoints.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/map-attack-surface/scripts/discover_entrypoints.py <db:appinfo> --json --no-cache`
- **Expected**: Fresh computation
- **Validates**: --no-cache bypass
- **Flags-Tested**: --json, --no-cache
- **Protocol**: none

### TEST-SKILL-048: rank_entrypoints

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: map-attack-surface/rank_entrypoints.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/map-attack-surface/scripts/rank_entrypoints.py <db:appinfo> --top 10 --json`
- **Expected**: Top 10 ranked by attack value
- **Validates**: Entry point ranking
- **Flags-Tested**: --top, --json
- **Protocol**: none

### TEST-SKILL-049: generate_entrypoints_json

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: map-attack-surface/generate_entrypoints_json.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/map-attack-surface/scripts/generate_entrypoints_json.py <db:appinfo> -o entrypoints.json --top 10`
- **Expected**: CRS-compatible entrypoints.json written to output file (stdout is empty when using -o flag)
- **Validates**: JSON export
- **Flags-Tested**: -o, --top
- **Protocol**: none

### TEST-SKILL-050: build_dossier

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: security-dossier/build_dossier.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/skills/security-dossier/scripts/build_dossier.py <db:appinfo> AiLaunchProcess --json`
- **Expected**: 8-section security context dossier
- **Validates**: Dossier construction
- **Flags-Tested**: function, --json
- **Protocol**: none

### TEST-SKILL-051: build_dossier callee-depth

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: security-dossier/build_dossier.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/skills/security-dossier/scripts/build_dossier.py <db:appinfo> AiLaunchProcess --callee-depth 2 --json`
- **Expected**: Dossier with deeper callee context
- **Validates**: --callee-depth
- **Flags-Tested**: --callee-depth, --json
- **Protocol**: none

### TEST-SKILL-052: taint_function

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: taint-analysis/taint_function.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/skills/taint-analysis/scripts/taint_function.py <db:appinfo> AiLaunchProcess --json`
- **Expected**: Taint trace results with sinks and guards
- **Validates**: Core taint analysis
- **Flags-Tested**: function, --json
- **Protocol**: none

### TEST-SKILL-053: taint_function with params and direction

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: taint-analysis/taint_function.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/skills/taint-analysis/scripts/taint_function.py <db:appinfo> AiLaunchProcess --params 1,3 --depth 3 --direction both --json`
- **Expected**: Bidirectional taint on specific params
- **Validates**: --params, --depth, --direction both
- **Flags-Tested**: --params, --depth, --direction, --json
- **Protocol**: none

### TEST-SKILL-054: trace_taint_forward

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: taint-analysis/trace_taint_forward.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/skills/taint-analysis/scripts/trace_taint_forward.py <db:appinfo> AiLaunchProcess --params 1 --depth 2 --json`
- **Expected**: Forward taint trace
- **Validates**: Dedicated forward trace
- **Flags-Tested**: --params, --depth, --json
- **Protocol**: none

### TEST-SKILL-055: trace_taint_backward

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: taint-analysis/trace_taint_backward.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/skills/taint-analysis/scripts/trace_taint_backward.py <db:appinfo> AiLaunchProcess --params 1 --json`
- **Expected**: Backward taint trace
- **Validates**: Dedicated backward trace
- **Flags-Tested**: --params, --json
- **Protocol**: none

### TEST-SKILL-056: trace_taint_cross_module

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: taint-analysis/trace_taint_cross_module.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/skills/taint-analysis/scripts/trace_taint_cross_module.py <db:appinfo> AiLaunchProcess --cross-depth 2 --json`
- **Expected**: Cross-module taint propagation
- **Validates**: Cross-module taint
- **Flags-Tested**: function, --cross-depth, --json
- **Protocol**: none

### TEST-SKILL-057: trace_taint_cross_module from-entrypoints

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: taint-analysis/trace_taint_cross_module.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/taint-analysis/scripts/trace_taint_cross_module.py <db:appinfo> --from-entrypoints --top 5 --min-score 0.3 --json`
- **Expected**: Entry point auto-discovery with taint
- **Validates**: --from-entrypoints mode
- **Flags-Tested**: --from-entrypoints, --top, --min-score, --json
- **Protocol**: none

### TEST-SKILL-058: trace_taint_cross_module disable features

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: taint-analysis/trace_taint_cross_module.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/skills/taint-analysis/scripts/trace_taint_cross_module.py <db:appinfo> AiLaunchProcess --no-trust-analysis --no-com-resolve --json`
- **Expected**: Taint without trust/COM analysis
- **Validates**: --no-trust-analysis, --no-com-resolve
- **Flags-Tested**: --no-trust-analysis, --no-com-resolve, --json
- **Protocol**: none

### TEST-SKILL-059: generate_taint_report placeholder

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: taint-analysis/generate_taint_report.py
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `python .agent/skills/taint-analysis/scripts/generate_taint_report.py --forward <path> --json`
- **Expected**: PARSE_ERROR because placeholder path has no valid JSON data
- **Validates**: Graceful handling of empty or invalid forward trace input
- **Flags-Tested**: --forward, --json
- **Protocol**: none

### TEST-SKILL-060: scan_buffer_overflows

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: memory-corruption-detector/scan_buffer_overflows.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/memory-corruption-detector/scripts/scan_buffer_overflows.py <db:appinfo> --json`
- **Expected**: Buffer overflow findings
- **Validates**: Buffer overflow scanner
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-SKILL-061: scan_buffer_overflows no-cache

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: memory-corruption-detector/scan_buffer_overflows.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/memory-corruption-detector/scripts/scan_buffer_overflows.py <db:appinfo> --top 10 --json --no-cache`
- **Expected**: Fresh scan, top 10
- **Validates**: --top, --no-cache
- **Flags-Tested**: --top, --json, --no-cache
- **Protocol**: none

### TEST-SKILL-062: scan_integer_issues

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: memory-corruption-detector/scan_integer_issues.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/memory-corruption-detector/scripts/scan_integer_issues.py <db:appinfo> --json`
- **Expected**: Integer overflow/truncation findings
- **Validates**: Integer issue scanner
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-SKILL-063: scan_use_after_free

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: memory-corruption-detector/scan_use_after_free.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/memory-corruption-detector/scripts/scan_use_after_free.py <db:appinfo> --json`
- **Expected**: Use-after-free findings
- **Validates**: UAF scanner
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-SKILL-064: scan_format_strings

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: memory-corruption-detector/scan_format_strings.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/memory-corruption-detector/scripts/scan_format_strings.py <db:appinfo> --json`
- **Expected**: Format string findings
- **Validates**: Format string scanner
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-SKILL-065: memory verify_findings placeholder

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: memory-corruption-detector/verify_findings.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/memory-corruption-detector/scripts/verify_findings.py --findings <path> --db-path <db:appinfo> --json`
- **Expected**: NOT_FOUND or PARSE_ERROR because placeholder path has no valid data
- **Validates**: Graceful handling of missing or empty findings file
- **Flags-Tested**: --findings, --db-path, --json
- **Protocol**: none

### TEST-SKILL-066: scan_auth_bypass

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: logic-vulnerability-detector/scan_auth_bypass.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/logic-vulnerability-detector/scripts/scan_auth_bypass.py <db:appinfo> --json`
- **Expected**: Authorization bypass findings
- **Validates**: Auth bypass scanner
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-SKILL-067: scan_auth_bypass no-cache

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: logic-vulnerability-detector/scan_auth_bypass.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/logic-vulnerability-detector/scripts/scan_auth_bypass.py <db:appinfo> --top 10 --json --no-cache`
- **Expected**: Fresh scan, top 10
- **Validates**: --top, --no-cache
- **Flags-Tested**: --top, --json, --no-cache
- **Protocol**: none

### TEST-SKILL-068: scan_state_errors

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: logic-vulnerability-detector/scan_state_errors.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/logic-vulnerability-detector/scripts/scan_state_errors.py <db:appinfo> --json`
- **Expected**: JSON with status ok and state-machine issue findings (may be empty)
- **Validates**: State issue scanner
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-SKILL-069: scan_logic_flaws

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: logic-vulnerability-detector/scan_logic_flaws.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/logic-vulnerability-detector/scripts/scan_logic_flaws.py <db:appinfo> --json`
- **Expected**: TOCTOU, path leakage findings
- **Validates**: Logic flaw scanner
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-SKILL-070: scan_api_misuse

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: logic-vulnerability-detector/scan_api_misuse.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/logic-vulnerability-detector/scripts/scan_api_misuse.py <db:appinfo> --json`
- **Expected**: API misuse findings
- **Validates**: API misuse scanner
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-SKILL-071: logic verify_findings placeholder

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: logic-vulnerability-detector/verify_findings.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/logic-vulnerability-detector/scripts/verify_findings.py --findings <path> --db-path <db:appinfo> --json`
- **Expected**: NOT_FOUND or PARSE_ERROR because placeholder path has no valid data
- **Validates**: Graceful handling of missing or empty findings file
- **Flags-Tested**: --findings, --db-path, --json
- **Protocol**: none

### TEST-SKILL-072: generate_logic_report placeholder

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: logic-vulnerability-detector/generate_logic_report.py
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `python .agent/skills/logic-vulnerability-detector/scripts/generate_logic_report.py --findings <path> --json`
- **Expected**: NOT_FOUND or PARSE_ERROR because placeholder path has no valid data
- **Validates**: Graceful handling of missing or empty findings file
- **Flags-Tested**: --findings, --json
- **Protocol**: none

### TEST-SKILL-073: assess_finding placeholder

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: exploitability-assessment/assess_finding.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/exploitability-assessment/scripts/assess_finding.py --taint-report <path> --module-db <db:appinfo> --json`
- **Expected**: NOT_FOUND or PARSE_ERROR because placeholder path has no valid data
- **Validates**: Graceful handling of missing or empty taint report
- **Flags-Tested**: --taint-report, --module-db, --json
- **Protocol**: none

### TEST-SKILL-074: batch_assess

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: exploitability-assessment/batch_assess.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/exploitability-assessment/scripts/batch_assess.py <db:appinfo> --top 10 --min-score 0.3 --json`
- **Expected**: Batch findings sorted by exploitability
- **Validates**: Batch assessment
- **Flags-Tested**: --top, --min-score, --json
- **Protocol**: none

### TEST-SKILL-075: verify scan_module

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: verify-decompiled/scan_module.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/verify-decompiled/scripts/scan_module.py <db:appinfo> --json`
- **Expected**: Decompiler accuracy scan results
- **Validates**: Module-wide verification scan
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-SKILL-076: verify scan_module filtered

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: verify-decompiled/scan_module.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/verify-decompiled/scripts/scan_module.py <db:appinfo> --top 10 --min-severity medium --app-only --json --no-cache`
- **Expected**: Top 10 medium+ severity issues, app-only
- **Validates**: --top, --min-severity, --app-only, --no-cache
- **Flags-Tested**: --top, --min-severity, --app-only, --json, --no-cache
- **Protocol**: none

### TEST-SKILL-077: verify verify_function

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: verify-decompiled/verify_function.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/skills/verify-decompiled/scripts/verify_function.py <db:appinfo> AiLaunchProcess --json`
- **Expected**: Instruction-level verification
- **Validates**: Single function verification
- **Flags-Tested**: function, --json
- **Protocol**: none

### TEST-SKILL-078: analyze_strings_deep

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: string-intelligence/analyze_strings_deep.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/string-intelligence/scripts/analyze_strings_deep.py <db:appinfo> --json`
- **Expected**: Categorized string intelligence
- **Validates**: String analysis
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-SKILL-079: analyze_strings_deep function

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: string-intelligence/analyze_strings_deep.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/skills/string-intelligence/scripts/analyze_strings_deep.py <db:appinfo> --function AiLaunchProcess --json`
- **Expected**: Strings for single function
- **Validates**: --function scope
- **Flags-Tested**: --function, --json
- **Protocol**: none

### TEST-SKILL-080: analyze_strings_deep filtered

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: string-intelligence/analyze_strings_deep.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/string-intelligence/scripts/analyze_strings_deep.py <db:appinfo> --top 20 --category credentials --json`
- **Expected**: Top 20 credential strings
- **Validates**: --top, --category
- **Flags-Tested**: --top, --category, --json
- **Protocol**: none

### TEST-SKILL-081: detect_dispatchers

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: state-machine-extractor/detect_dispatchers.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/state-machine-extractor/scripts/detect_dispatchers.py <db:appinfo> --json`
- **Expected**: Dispatch table locations
- **Validates**: Dispatcher detection
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-SKILL-082: detect_dispatchers filtered

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: state-machine-extractor/detect_dispatchers.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/state-machine-extractor/scripts/detect_dispatchers.py <db:appinfo> --min-cases 5 --with-loops --app-only --json`
- **Expected**: Filtered dispatchers
- **Validates**: --min-cases, --with-loops, --app-only
- **Flags-Tested**: --min-cases, --with-loops, --app-only, --json
- **Protocol**: none

### TEST-SKILL-083: extract_dispatch_table

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: state-machine-extractor/extract_dispatch_table.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/skills/state-machine-extractor/scripts/extract_dispatch_table.py <db:appinfo> AiLaunchProcess --json`
- **Expected**: Case-to-handler mappings
- **Validates**: Dispatch table extraction
- **Flags-Tested**: function, --json
- **Protocol**: none

### TEST-SKILL-084: extract_state_machine

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: state-machine-extractor/extract_state_machine.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/skills/state-machine-extractor/scripts/extract_state_machine.py <db:appinfo> AiLaunchProcess --with-code --json`
- **Expected**: NO_DATA result (AiLaunchProcess has no state machine pattern); or state transitions with code if a dispatcher function is used instead
- **Validates**: State machine extraction
- **Flags-Tested**: function, --with-code, --json
- **Protocol**: none

### TEST-SKILL-085: generate_state_diagram

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: state-machine-extractor/generate_state_diagram.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/skills/state-machine-extractor/scripts/generate_state_diagram.py <db:appinfo> --function AiLaunchProcess --mode dispatch --format mermaid`
- **Expected**: Mermaid state diagram
- **Validates**: Diagram generation
- **Flags-Tested**: --function, --mode, --format
- **Protocol**: none

### TEST-SKILL-086: generate_report

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: generate-re-report/generate_report.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/generate-re-report/scripts/generate_report.py <db:appinfo> --json`
- **Expected**: 10-section RE report
- **Validates**: Full report generation
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-SKILL-087: generate_report no-cache

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: generate-re-report/generate_report.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/generate-re-report/scripts/generate_report.py <db:appinfo> --summary --top 10 --json --no-cache`
- **Expected**: Summary report, fresh computation
- **Validates**: --summary, --top, --no-cache
- **Flags-Tested**: --summary, --top, --json, --no-cache
- **Protocol**: none

### TEST-SKILL-088: analyze_imports

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: generate-re-report/analyze_imports.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/generate-re-report/scripts/analyze_imports.py <db:appinfo> --exports --include-delay-load --json`
- **Expected**: Import/export analysis with delay-load
- **Validates**: --exports, --include-delay-load
- **Flags-Tested**: --exports, --include-delay-load, --json
- **Protocol**: none

### TEST-SKILL-089: analyze_complexity

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: generate-re-report/analyze_complexity.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/generate-re-report/scripts/analyze_complexity.py <db:appinfo> --top 10 --app-only --json`
- **Expected**: Top 10 complex functions, app only
- **Validates**: Complexity ranking
- **Flags-Tested**: --top, --app-only, --json
- **Protocol**: none

### TEST-SKILL-090: analyze_topology

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: generate-re-report/analyze_topology.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/generate-re-report/scripts/analyze_topology.py <db:appinfo> --json`
- **Expected**: Call graph topology metrics
- **Validates**: Topology analysis
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-SKILL-091: analyze_strings

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: generate-re-report/analyze_strings.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/generate-re-report/scripts/analyze_strings.py <db:appinfo> --top 20 --category security --json`
- **Expected**: Security-relevant strings
- **Validates**: String analysis for report
- **Flags-Tested**: --top, --category, --json
- **Protocol**: none

### TEST-SKILL-092: analyze_decompilation_quality

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: generate-re-report/analyze_decompilation_quality.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/generate-re-report/scripts/analyze_decompilation_quality.py <db:appinfo> --json`
- **Expected**: Decompiler accuracy metrics
- **Validates**: Quality analysis
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-SKILL-093: query_function imports

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: import-export-resolver/query_function.py
- **Target-Module**: N/A
- **Target-Function**: CreateProcessW
- **Command**: `python .agent/skills/import-export-resolver/scripts/query_function.py --function CreateProcessW --direction both --json`
- **Expected**: Export and import data for CreateProcessW
- **Validates**: Function query
- **Flags-Tested**: --function, --direction, --json
- **Protocol**: none

### TEST-SKILL-094: build_index

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: import-export-resolver/build_index.py
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `python .agent/skills/import-export-resolver/scripts/build_index.py --json`
- **Expected**: Cross-module index built
- **Validates**: Index initialization
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-SKILL-095: module_deps

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: import-export-resolver/module_deps.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/import-export-resolver/scripts/module_deps.py --module appinfo.dll --consumers --diagram --json`
- **Expected**: Dependency graph with consumers and diagram
- **Validates**: --module, --consumers, --diagram
- **Flags-Tested**: --module, --consumers, --diagram, --json
- **Protocol**: none

### TEST-SKILL-096: resolve_forwarders

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: import-export-resolver/resolve_forwarders.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/import-export-resolver/scripts/resolve_forwarders.py --module appinfo.dll --all --json`
- **Expected**: All forwarder chains resolved
- **Validates**: Forwarder resolution
- **Flags-Tested**: --module, --all, --json
- **Protocol**: none

### TEST-SKILL-097: resolve_com_server

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: com-interface-analysis/resolve_com_server.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/com-interface-analysis/scripts/resolve_com_server.py appinfo.dll --json`
- **Expected**: COM servers and CLSIDs
- **Validates**: COM server resolution
- **Flags-Tested**: module, --json
- **Protocol**: none

### TEST-SKILL-098: map_com_surface

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: com-interface-analysis/map_com_surface.py
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `python .agent/skills/com-interface-analysis/scripts/map_com_surface.py --system-wide --top 10 --json`
- **Expected**: System-wide COM attack surface
- **Validates**: COM surface mapping
- **Flags-Tested**: --system-wide, --top, --json
- **Protocol**: none

### TEST-SKILL-099: enumerate_com_methods

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: com-interface-analysis/enumerate_com_methods.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/com-interface-analysis/scripts/enumerate_com_methods.py appinfo.dll --show-pseudo-idl --json`
- **Expected**: COM methods with pseudo-IDL
- **Validates**: Method enumeration with IDL
- **Flags-Tested**: module, --show-pseudo-idl, --json
- **Protocol**: none

### TEST-SKILL-100: find_com_privesc

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: com-interface-analysis/find_com_privesc.py
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `python .agent/skills/com-interface-analysis/scripts/find_com_privesc.py --top 10 --include-uac --json`
- **Expected**: COM privesc targets with UAC
- **Validates**: Privesc discovery
- **Flags-Tested**: --top, --include-uac, --json
- **Protocol**: none

### TEST-SKILL-101: scan_com_interfaces

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: com-interface-reconstruction/scan_com_interfaces.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/com-interface-reconstruction/scripts/scan_com_interfaces.py <db:appinfo> --json`
- **Expected**: COM interface implementations found
- **Validates**: COM interface scanning
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-SKILL-102: decode_wrl_templates

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: com-interface-reconstruction/decode_wrl_templates.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/com-interface-reconstruction/scripts/decode_wrl_templates.py <db:appinfo> --json`
- **Expected**: WRL template structures
- **Validates**: WRL decoding
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-SKILL-103: generate_idl

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: com-interface-reconstruction/generate_idl.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/com-interface-reconstruction/scripts/generate_idl.py <db:appinfo> --json`
- **Expected**: IDL output for reconstructed interfaces
- **Validates**: IDL generation
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-SKILL-104: resolve_rpc_interface

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: rpc-interface-analysis/resolve_rpc_interface.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/rpc-interface-analysis/scripts/resolve_rpc_interface.py appinfo.dll --with-stubs --json`
- **Expected**: RPC interfaces with stub data
- **Validates**: RPC resolution
- **Flags-Tested**: module, --with-stubs, --json
- **Protocol**: none

### TEST-SKILL-105: map_rpc_surface

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: rpc-interface-analysis/map_rpc_surface.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/rpc-interface-analysis/scripts/map_rpc_surface.py appinfo.dll --with-blast-radius --json`
- **Expected**: RPC surface with blast-radius
- **Validates**: Surface mapping with blast-radius
- **Flags-Tested**: module, --with-blast-radius, --json
- **Protocol**: none

### TEST-SKILL-106: rpc_topology

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: rpc-interface-analysis/rpc_topology.py
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `python .agent/skills/rpc-interface-analysis/scripts/rpc_topology.py --json`
- **Expected**: RPC client-server topology
- **Validates**: Topology generation
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-SKILL-107: resolve_winrt_server

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: winrt-interface-analysis/resolve_winrt_server.py
- **Target-Module**: windows.storage.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/winrt-interface-analysis/scripts/resolve_winrt_server.py windows.storage.dll --json`
- **Expected**: WinRT servers for windows.storage.dll
- **Validates**: WinRT server resolution
- **Flags-Tested**: module, --json
- **Protocol**: none

### TEST-SKILL-108: find_winrt_privesc

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: winrt-interface-analysis/find_winrt_privesc.py
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `python .agent/skills/winrt-interface-analysis/scripts/find_winrt_privesc.py --top 10 --json`
- **Expected**: WinRT privesc targets
- **Validates**: WinRT privesc discovery
- **Flags-Tested**: --top, --json
- **Protocol**: none

### TEST-SKILL-109: collect_functions class

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: batch-lift/collect_functions.py
- **Target-Module**: windows.storage.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/batch-lift/scripts/collect_functions.py <db:winstorage> --class CInvokeCreateProcessVerb --json`
- **Expected**: All methods of the class collected
- **Validates**: Class collection
- **Flags-Tested**: --class, --json
- **Protocol**: none

### TEST-SKILL-110: collect_functions chain

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: batch-lift/collect_functions.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/skills/batch-lift/scripts/collect_functions.py <db:appinfo> --chain AiLaunchProcess --depth 3 --json`
- **Expected**: Call chain functions collected
- **Validates**: --chain mode
- **Flags-Tested**: --chain, --depth, --json
- **Protocol**: none

### TEST-SKILL-111: collect_functions export

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: batch-lift/collect_functions.py
- **Target-Module**: shell32.dll
- **Target-Function**: ShellExecuteExW
- **Command**: `python .agent/skills/batch-lift/scripts/collect_functions.py <db:shell32> --export ShellExecuteExW --json`
- **Expected**: Export subtree collected
- **Validates**: --export mode
- **Flags-Tested**: --export, --json
- **Protocol**: none

### TEST-SKILL-112: prepare_batch_lift placeholder

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: batch-lift/prepare_batch_lift.py
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `python .agent/skills/batch-lift/scripts/prepare_batch_lift.py --from-json <path> --summary --json`
- **Expected**: NOT_FOUND or PARSE_ERROR because placeholder path has no valid data
- **Validates**: Graceful handling of missing or empty input file
- **Flags-Tested**: --from-json, --summary, --json
- **Protocol**: none

### TEST-SKILL-113: list_types

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: reconstruct-types/list_types.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/reconstruct-types/scripts/list_types.py <db:appinfo> --with-vtables --json`
- **Expected**: Detected types with vtable info
- **Validates**: Type listing
- **Flags-Tested**: --with-vtables, --json
- **Protocol**: none

### TEST-SKILL-114: extract_class_hierarchy

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: reconstruct-types/extract_class_hierarchy.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/reconstruct-types/scripts/extract_class_hierarchy.py <db:appinfo> --json`
- **Expected**: Class inheritance and method mappings
- **Validates**: Hierarchy extraction
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-SKILL-115: scan_struct_fields

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: reconstruct-types/scan_struct_fields.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/reconstruct-types/scripts/scan_struct_fields.py <db:appinfo> --all-classes --app-only --json`
- **Expected**: Field boundaries for all app classes
- **Validates**: Struct field scanning
- **Flags-Tested**: --all-classes, --app-only, --json
- **Protocol**: none

### TEST-SKILL-116: generate_header

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: reconstruct-types/generate_header.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/reconstruct-types/scripts/generate_header.py <db:appinfo> --all --output all_types.h`
- **Expected**: Compilable C++ header written to output file (stdout is empty when using --output flag)
- **Validates**: Header generation
- **Flags-Tested**: --all, --output
- **Protocol**: none

### TEST-SKILL-117: gather_function_context

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: deep-research-prompt/gather_function_context.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/skills/deep-research-prompt/scripts/gather_function_context.py <db:appinfo> AiLaunchProcess --depth 2 --with-code --json`
- **Expected**: Multi-skill context aggregation
- **Validates**: Function context gathering
- **Flags-Tested**: function, --depth, --with-code, --json
- **Protocol**: none

### TEST-SKILL-118: gather_module_context

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: deep-research-prompt/gather_module_context.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/deep-research-prompt/scripts/gather_module_context.py <db:appinfo> --top 10 --json`
- **Expected**: Module-level metrics aggregation
- **Validates**: Module context gathering
- **Flags-Tested**: --top, --json
- **Protocol**: none

### TEST-SKILL-119: generate_research_prompt

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: deep-research-prompt/generate_research_prompt.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/skills/deep-research-prompt/scripts/generate_research_prompt.py <db:appinfo> AiLaunchProcess --area security --detail full`
- **Expected**: Structured research prompt
- **Validates**: Research prompt generation
- **Flags-Tested**: function, --area, --detail
- **Protocol**: none

### TEST-SKILL-120: audit_com_security

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: com-interface-analysis/audit_com_security.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/com-interface-analysis/scripts/audit_com_security.py appinfo.dll --json`
- **Expected**: COM security audit findings for appinfo.dll
- **Validates**: COM security permission auditing
- **Flags-Tested**: module, --json
- **Protocol**: none

### TEST-SKILL-121: classify_com_entrypoints

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: com-interface-analysis/classify_com_entrypoints.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/com-interface-analysis/scripts/classify_com_entrypoints.py appinfo.dll --json`
- **Expected**: COM entry points classified by attack value
- **Validates**: COM entry point classification
- **Flags-Tested**: module, --json
- **Protocol**: none

### TEST-SKILL-122: map_class_interfaces

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: com-interface-reconstruction/map_class_interfaces.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/com-interface-reconstruction/scripts/map_class_interfaces.py <db:appinfo> --json`
- **Expected**: COM class-to-interface mappings
- **Validates**: Class interface mapping
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-SKILL-123: audit_rpc_security

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: rpc-interface-analysis/audit_rpc_security.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/rpc-interface-analysis/scripts/audit_rpc_security.py <db:appinfo> --json`
- **Expected**: RPC security descriptor audit findings
- **Validates**: RPC interface security auditing
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-SKILL-124: find_rpc_clients

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: rpc-interface-analysis/find_rpc_clients.py
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `python .agent/skills/rpc-interface-analysis/scripts/find_rpc_clients.py 0497b57d-2e66-424f-a0c6-157cd5d41700 --json`
- **Expected**: Modules that are RPC clients for the given UUID
- **Validates**: RPC client discovery
- **Flags-Tested**: uuid, --json
- **Protocol**: none

### TEST-SKILL-125: trace_rpc_chain

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: rpc-interface-analysis/trace_rpc_chain.py
- **Target-Module**: appinfo.dll
- **Target-Function**: RAiLaunchAdminProcess
- **Command**: `python .agent/skills/rpc-interface-analysis/scripts/trace_rpc_chain.py <db:appinfo> --function RAiLaunchAdminProcess --json`
- **Expected**: RPC handler call chain trace
- **Validates**: RPC handler chain tracing
- **Flags-Tested**: --function, --json
- **Protocol**: none

### TEST-SKILL-126: audit_winrt_security

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: winrt-interface-analysis/audit_winrt_security.py
- **Target-Module**: windows.storage.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/winrt-interface-analysis/scripts/audit_winrt_security.py <db:winstorage> --json`
- **Expected**: WinRT server security audit findings
- **Validates**: WinRT security property auditing
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-SKILL-127: classify_winrt_entrypoints

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: winrt-interface-analysis/classify_winrt_entrypoints.py
- **Target-Module**: windows.storage.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/winrt-interface-analysis/scripts/classify_winrt_entrypoints.py windows.storage.dll --json`
- **Expected**: WinRT entry points classified by attack value
- **Validates**: WinRT entry point classification
- **Flags-Tested**: module, --json
- **Protocol**: none

### TEST-SKILL-128: enumerate_winrt_methods

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: winrt-interface-analysis/enumerate_winrt_methods.py
- **Target-Module**: windows.storage.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/winrt-interface-analysis/scripts/enumerate_winrt_methods.py windows.storage.dll --json`
- **Expected**: WinRT server methods enumerated
- **Validates**: WinRT method enumeration
- **Flags-Tested**: module, --json
- **Protocol**: none

### TEST-SKILL-129: map_winrt_surface

- **Category**: skill-script
- **Component**: skill-script
- **Component-Name**: winrt-interface-analysis/map_winrt_surface.py
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `python .agent/skills/winrt-interface-analysis/scripts/map_winrt_surface.py --system-wide --top 10 --json`
- **Expected**: System-wide WinRT attack surface ranking
- **Validates**: WinRT surface mapping
- **Flags-Tested**: --system-wide, --top, --json
- **Protocol**: none

---

## Section 11: Agent Entry Script Tests

### TEST-AGENT-001: re_query overview

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: re-analyst/re_query.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/agents/re-analyst/scripts/re_query.py <db:appinfo> --overview --json`
- **Expected**: Module overview with key metrics
- **Validates**: re-analyst overview mode
- **Flags-Tested**: --overview, --json
- **Protocol**: none

### TEST-AGENT-002: re_query function context

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: re-analyst/re_query.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/agents/re-analyst/scripts/re_query.py <db:appinfo> --function AiLaunchProcess --context --json`
- **Expected**: Full function context
- **Validates**: --function --context mode
- **Flags-Tested**: --function, --context, --json
- **Protocol**: none

### TEST-AGENT-003: re_query class

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: re-analyst/re_query.py
- **Target-Module**: windows.storage.dll
- **Target-Function**: N/A
- **Command**: `python .agent/agents/re-analyst/scripts/re_query.py <db:winstorage> --class CInvokeCreateProcessVerb --json`
- **Expected**: Class methods and metadata
- **Validates**: --class mode
- **Flags-Tested**: --class, --json
- **Protocol**: none

### TEST-AGENT-004: re_query exports

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: re-analyst/re_query.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/agents/re-analyst/scripts/re_query.py <db:appinfo> --exports --with-classification --json`
- **Expected**: Exports with classification data
- **Validates**: --exports --with-classification mode
- **Flags-Tested**: --exports, --with-classification, --json
- **Protocol**: none

### TEST-AGENT-005: re_query search

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: re-analyst/re_query.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/agents/re-analyst/scripts/re_query.py <db:appinfo> --search "Launch" --json`
- **Expected**: Search results
- **Validates**: --search mode
- **Flags-Tested**: --search, --json
- **Protocol**: none

### TEST-AGENT-006: explain_function

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: re-analyst/explain_function.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/agents/re-analyst/scripts/explain_function.py <db:appinfo> AiLaunchProcess --json`
- **Expected**: Structured function explanation
- **Validates**: Function explanation
- **Flags-Tested**: function, --json
- **Protocol**: none

### TEST-AGENT-007: explain_function depth

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: re-analyst/explain_function.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/agents/re-analyst/scripts/explain_function.py <db:appinfo> AiLaunchProcess --depth 2 --json`
- **Expected**: Explanation with 2 levels of callees
- **Validates**: --depth
- **Flags-Tested**: --depth, --json
- **Protocol**: none

### TEST-AGENT-008: explain_function no-assembly

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: re-analyst/explain_function.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/agents/re-analyst/scripts/explain_function.py <db:appinfo> AiLaunchProcess --no-assembly --json`
- **Expected**: Explanation without assembly
- **Validates**: --no-assembly
- **Flags-Tested**: --no-assembly, --json
- **Protocol**: none

### TEST-AGENT-009: analyze_module triage

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: triage-coordinator/analyze_module.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/agents/triage-coordinator/scripts/analyze_module.py <db:appinfo> --goal triage --json`
- **Expected**: Triage pipeline results
- **Validates**: triage goal
- **Flags-Tested**: --goal triage, --json
- **Protocol**: none

### TEST-AGENT-010: analyze_module security

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: triage-coordinator/analyze_module.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/agents/triage-coordinator/scripts/analyze_module.py <db:appinfo> --goal security --json`
- **Expected**: Security pipeline results
- **Validates**: security goal
- **Flags-Tested**: --goal security, --json
- **Protocol**: none

### TEST-AGENT-011: analyze_module full

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: triage-coordinator/analyze_module.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/agents/triage-coordinator/scripts/analyze_module.py <db:appinfo> --goal full --json`
- **Expected**: Full analysis pipeline
- **Validates**: full goal
- **Flags-Tested**: --goal full, --json
- **Protocol**: none

### TEST-AGENT-012: analyze_module understand-function

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: triage-coordinator/analyze_module.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/agents/triage-coordinator/scripts/analyze_module.py <db:appinfo> --goal understand-function --function AiLaunchProcess --json`
- **Expected**: Function understanding pipeline
- **Validates**: understand-function goal with --function
- **Flags-Tested**: --goal understand-function, --function, --json
- **Protocol**: none

### TEST-AGENT-013: analyze_module types

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: triage-coordinator/analyze_module.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/agents/triage-coordinator/scripts/analyze_module.py <db:appinfo> --goal types --json`
- **Expected**: Type reconstruction pipeline
- **Validates**: types goal
- **Flags-Tested**: --goal types, --json
- **Protocol**: none

### TEST-AGENT-014: analyze_module quick no-cache

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: triage-coordinator/analyze_module.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/agents/triage-coordinator/scripts/analyze_module.py <db:appinfo> --goal triage --quick --no-cache --json`
- **Expected**: Quick triage without cache
- **Validates**: --quick and --no-cache flags
- **Flags-Tested**: --goal triage, --quick, --no-cache, --json
- **Protocol**: none

### TEST-AGENT-015: generate_analysis_plan triage

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: triage-coordinator/generate_analysis_plan.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/agents/triage-coordinator/scripts/generate_analysis_plan.py <db:appinfo> --goal triage --json`
- **Expected**: Phased plan JSON without execution
- **Validates**: Plan generation for triage
- **Flags-Tested**: --goal triage, --json
- **Protocol**: none

### TEST-AGENT-016: generate_analysis_plan security

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: triage-coordinator/generate_analysis_plan.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/agents/triage-coordinator/scripts/generate_analysis_plan.py <db:appinfo> --goal security --json`
- **Expected**: Security plan
- **Validates**: Plan generation for security
- **Flags-Tested**: --goal security, --json
- **Protocol**: none

### TEST-AGENT-017: generate_analysis_plan full

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: triage-coordinator/generate_analysis_plan.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/agents/triage-coordinator/scripts/generate_analysis_plan.py <db:appinfo> --goal full --json`
- **Expected**: Full plan
- **Validates**: Plan generation for full
- **Flags-Tested**: --goal full, --json
- **Protocol**: none

### TEST-AGENT-018: run_security_scan default

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: security-auditor/run_security_scan.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/agents/security-auditor/scripts/run_security_scan.py <db:appinfo> --json`
- **Expected**: Full security scan pipeline
- **Validates**: Default scan goal
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-AGENT-019: run_security_scan audit goal

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: security-auditor/run_security_scan.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/agents/security-auditor/scripts/run_security_scan.py <db:appinfo> --goal audit --function AiLaunchProcess --json`
- **Expected**: Function-scoped audit
- **Validates**: audit goal with --function
- **Flags-Tested**: --goal audit, --function, --json
- **Protocol**: none

### TEST-AGENT-020: run_security_scan hunt goal

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: security-auditor/run_security_scan.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/agents/security-auditor/scripts/run_security_scan.py <db:appinfo> --goal hunt --json`
- **Expected**: Hunt-mode security scan
- **Validates**: hunt goal
- **Flags-Tested**: --goal hunt, --json
- **Protocol**: none

### TEST-AGENT-021: run_security_scan with top and no-cache

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: security-auditor/run_security_scan.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/agents/security-auditor/scripts/run_security_scan.py <db:appinfo> --top 5 --no-cache --json`
- **Expected**: Top 5, fresh computation
- **Validates**: --top and --no-cache
- **Flags-Tested**: --top, --no-cache, --json
- **Protocol**: none

### TEST-AGENT-022: batch_extract class

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: code-lifter/batch_extract.py
- **Target-Module**: windows.storage.dll
- **Target-Function**: N/A
- **Command**: `python .agent/agents/code-lifter/scripts/batch_extract.py <db:winstorage> --class CInvokeCreateProcessVerb --init-state --json`
- **Expected**: Class methods extracted, state initialized
- **Validates**: Class extraction with state init
- **Flags-Tested**: --class, --init-state, --json
- **Protocol**: none

### TEST-AGENT-023: batch_extract functions

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: code-lifter/batch_extract.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/agents/code-lifter/scripts/batch_extract.py <db:appinfo> --functions AiLaunchProcess --json`
- **Expected**: Specific function extracted
- **Validates**: --functions mode
- **Flags-Tested**: --functions, --json
- **Protocol**: none

### TEST-AGENT-024: track_shared_state init

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: code-lifter/track_shared_state.py
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `python .agent/agents/code-lifter/scripts/track_shared_state.py --init CInvokeCreateProcessVerb --json`
- **Expected**: Empty state file created (may fail with INVALID_ARGS if state already exists from a prior test; use --reset to reinitialize)
- **Validates**: --init
- **Flags-Tested**: --init, --json
- **Protocol**: none

### TEST-AGENT-025: track_shared_state dump

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: code-lifter/track_shared_state.py
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `python .agent/agents/code-lifter/scripts/track_shared_state.py --dump --json`
- **Expected**: Current state as JSON
- **Validates**: --dump
- **Flags-Tested**: --dump, --json
- **Protocol**: none

### TEST-AGENT-026: track_shared_state list

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: code-lifter/track_shared_state.py
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `python .agent/agents/code-lifter/scripts/track_shared_state.py --list --json`
- **Expected**: All active state files
- **Validates**: --list
- **Flags-Tested**: --list, --json
- **Protocol**: none

### TEST-AGENT-027: track_shared_state mark-lifted

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: code-lifter/track_shared_state.py
- **Target-Module**: N/A
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/agents/code-lifter/scripts/track_shared_state.py --mark-lifted "CInvokeCreateProcessVerb::Execute" --class CInvokeCreateProcessVerb --json`
- **Expected**: Function marked as lifted in state
- **Validates**: --mark-lifted
- **Flags-Tested**: --mark-lifted, --class, --json
- **Protocol**: none

### TEST-AGENT-028: reconstruct_all

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: type-reconstructor/reconstruct_all.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/agents/type-reconstructor/scripts/reconstruct_all.py <db:appinfo> --json`
- **Expected**: Full type reconstruction pipeline
- **Validates**: Default pipeline
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-AGENT-029: reconstruct_all class + COM

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: type-reconstructor/reconstruct_all.py
- **Target-Module**: windows.storage.dll
- **Target-Function**: N/A
- **Command**: `python .agent/agents/type-reconstructor/scripts/reconstruct_all.py <db:winstorage> --class CInvokeCreateProcessVerb --include-com --json`
- **Expected**: Class reconstruction with COM
- **Validates**: --class and --include-com
- **Flags-Tested**: --class, --include-com, --json
- **Protocol**: none

### TEST-AGENT-030: merge_evidence placeholder

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: type-reconstructor/merge_evidence.py
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `python .agent/agents/type-reconstructor/scripts/merge_evidence.py --scan-output <path> --json`
- **Expected**: NOT_FOUND or PARSE_ERROR because placeholder path has no valid data
- **Validates**: Graceful handling of missing or empty scan output
- **Flags-Tested**: --scan-output, --json
- **Protocol**: none

### TEST-AGENT-031: validate_layout missing header

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: type-reconstructor/validate_layout.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/agents/type-reconstructor/scripts/validate_layout.py <db:appinfo> --header types.h --json`
- **Expected**: NOT_FOUND structured error because types.h does not exist
- **Validates**: Graceful handling of missing header file
- **Flags-Tested**: --header, --json
- **Protocol**: none

### TEST-AGENT-032: compare_lifted missing --lifted error

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: verifier/compare_lifted.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/agents/verifier/scripts/compare_lifted.py <db:appinfo> AiLaunchProcess --json`
- **Expected**: INVALID_ARGS error because --lifted or --lifted-stdin is required
- **Validates**: Argparse validation for required lifted code source
- **Flags-Tested**: function, --json
- **Protocol**: none

### TEST-AGENT-033: compare_lifted missing lifted file

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: verifier/compare_lifted.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/agents/verifier/scripts/compare_lifted.py <db:appinfo> AiLaunchProcess --lifted lifted.cpp --json`
- **Expected**: NOT_FOUND structured error because lifted.cpp does not exist
- **Validates**: Graceful handling of missing lifted code file
- **Flags-Tested**: --lifted, --json
- **Protocol**: none

### TEST-AGENT-034: extract_basic_blocks

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: verifier/extract_basic_blocks.py
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `python .agent/agents/verifier/scripts/extract_basic_blocks.py <db:appinfo> AiLaunchProcess --json`
- **Expected**: Assembly parsed into basic blocks
- **Validates**: Basic block extraction
- **Flags-Tested**: function, --json
- **Protocol**: none

### TEST-AGENT-035: generate_verification_report placeholder

- **Category**: agent
- **Component**: agent-script
- **Component-Name**: verifier/generate_verification_report.py
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `python .agent/agents/verifier/scripts/generate_verification_report.py --compare-output <path> --json`
- **Expected**: NOT_FOUND or PARSE_ERROR because placeholder path has no valid data
- **Validates**: Graceful handling of missing or empty compare output
- **Flags-Tested**: --compare-output, --json
- **Protocol**: none

---

## Section 12: VR Workflow Pattern Tests

### TEST-FLOW-001: Module Triage Initialization

- **Category**: workflow
- **Component**: workflow
- **Component-Name**: module-triage-initialization
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/quickstart appinfo.dll` then `/triage appinfo.dll` then `/scan appinfo.dll` then `/prioritize --modules appinfo.dll`
- **Expected**: Each stage completes and feeds into the next; final output is ranked findings
- **Validates**: Full triage initialization workflow from technical_reference.md
- **Flags-Tested**: N/A
- **Protocol**: workspace, grind-loop

### TEST-FLOW-002: Comprehensive Security Audit

- **Category**: workflow
- **Component**: workflow
- **Component-Name**: comprehensive-security-audit
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/triage appinfo.dll --with-security` then `/batch-audit appinfo.dll --top 10` then `/prioritize --modules appinfo.dll` then `/audit appinfo.dll <top_function>`
- **Expected**: Baseline -> batch evaluation -> ranking -> deep inspection
- **Validates**: Full security audit workflow
- **Flags-Tested**: --with-security, --top
- **Protocol**: workspace, grind-loop

### TEST-FLOW-003: Hypothesis-Driven Investigation

- **Category**: workflow
- **Component**: workflow
- **Component-Name**: hypothesis-driven-investigation
- **Target-Module**: appinfo.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `/hunt appinfo.dll` then `/hunt-execute appinfo.dll` then `/audit appinfo.dll <confirmed_function>`
- **Expected**: Plan -> execute -> validate confirmed findings
- **Validates**: Full VR investigation workflow
- **Flags-Tested**: N/A
- **Protocol**: workspace, grind-loop

### TEST-FLOW-004: Export Dependency Tracing

- **Category**: workflow
- **Component**: workflow
- **Component-Name**: export-dependency-tracing
- **Target-Module**: shell32.dll
- **Target-Function**: ShellExecuteExW
- **Command**: `/trace-export shell32.dll ShellExecuteExW` then `/taint shell32.dll ShellExecuteExW --cross-module` then `/audit shell32.dll ShellExecuteExW` then `/verify shell32.dll ShellExecuteExW`
- **Expected**: Trace -> taint -> audit -> verify along execution path
- **Validates**: Full export tracing workflow
- **Flags-Tested**: --cross-module
- **Protocol**: workspace

### TEST-FLOW-005: Cross-Boundary Impact Analysis

- **Category**: workflow
- **Component**: workflow
- **Component-Name**: cross-boundary-impact
- **Target-Module**: appinfo.dll, shell32.dll, windows.storage.dll
- **Target-Function**: AiLaunchProcess
- **Command**: `/imports appinfo.dll --diagram` then `/data-flow-cross forward appinfo.dll AiLaunchProcess --param 1` then `/compare-modules shell32.dll windows.storage.dll`
- **Expected**: Dependency graph -> cross-module data flow -> comparative analysis
- **Validates**: Full cross-boundary workflow
- **Flags-Tested**: --diagram, --param
- **Protocol**: workspace

### TEST-FLOW-006: Interface Attack Surface Mapping

- **Category**: workflow
- **Component**: workflow
- **Component-Name**: interface-attack-surface
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `/com surface` and `/rpc surface` and `/winrt surface` then `/com privesc --top 10` then `/batch-audit appinfo.dll --privilege-boundary`
- **Expected**: Surface discovery -> privesc identification -> handler evaluation
- **Validates**: Full interface mapping workflow
- **Flags-Tested**: surface, privesc, --privilege-boundary
- **Protocol**: workspace, grind-loop

### TEST-FLOW-007: Code Reconstruction Pipeline

- **Category**: workflow
- **Component**: workflow
- **Component-Name**: code-reconstruction
- **Target-Module**: windows.storage.dll
- **Target-Function**: N/A
- **Command**: `/reconstruct-types windows.storage.dll CInvokeCreateProcessVerb` then `/lift-class windows.storage.dll CInvokeCreateProcessVerb` then `/verify-batch windows.storage.dll CInvokeCreateProcessVerb`
- **Expected**: Type resolution -> lifting -> batch verification
- **Validates**: Full code reconstruction workflow
- **Flags-Tested**: class
- **Protocol**: workspace, grind-loop

---

## Section 13: Pipeline and YAML Tests

### TEST-PIPE-001: Pipeline list-steps

- **Category**: pipeline
- **Component**: pipeline
- **Component-Name**: pipeline_cli.py
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `python .agent/helpers/pipeline_cli.py list-steps`
- **Expected**: All available pipeline step names listed
- **Validates**: list-steps subcommand
- **Flags-Tested**: list-steps
- **Protocol**: none

### TEST-PIPE-002: Validate security-sweep

- **Category**: pipeline
- **Component**: pipeline
- **Component-Name**: pipeline_cli.py
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `python .agent/helpers/pipeline_cli.py validate .agent/config/pipelines/security-sweep.yaml`
- **Expected**: Validation passes
- **Validates**: YAML schema validation
- **Flags-Tested**: validate
- **Protocol**: none

### TEST-PIPE-003: Validate quick-triage

- **Category**: pipeline
- **Component**: pipeline
- **Component-Name**: pipeline_cli.py
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `python .agent/helpers/pipeline_cli.py validate .agent/config/pipelines/quick-triage.yaml`
- **Expected**: Validation passes
- **Validates**: Quick-triage YAML
- **Flags-Tested**: validate
- **Protocol**: none

### TEST-PIPE-004: Validate full-analysis

- **Category**: pipeline
- **Component**: pipeline
- **Component-Name**: pipeline_cli.py
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `python .agent/helpers/pipeline_cli.py validate .agent/config/pipelines/full-analysis.yaml`
- **Expected**: Validation passes
- **Validates**: Full-analysis YAML
- **Flags-Tested**: validate
- **Protocol**: none

### TEST-PIPE-005: Validate function-deep-dive

- **Category**: pipeline
- **Component**: pipeline
- **Component-Name**: pipeline_cli.py
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `python .agent/helpers/pipeline_cli.py validate .agent/config/pipelines/function-deep-dive.yaml`
- **Expected**: Validation passes
- **Validates**: Function-deep-dive YAML
- **Flags-Tested**: validate
- **Protocol**: none

### TEST-PIPE-006: Dry run pipeline

- **Category**: pipeline
- **Component**: pipeline
- **Component-Name**: pipeline_cli.py
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `python .agent/helpers/pipeline_cli.py run .agent/config/pipelines/quick-triage.yaml --dry-run --json`
- **Expected**: Pipeline plan shown without execution
- **Validates**: --dry-run mode
- **Flags-Tested**: run, --dry-run, --json
- **Protocol**: none

---

## Section 14: Lifecycle Hooks Tests

### TEST-HOOK-002: Grind hook detects unchecked items

- **Category**: hook
- **Component**: hook
- **Component-Name**: grind-until-done.py
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: Create scratchpad with unchecked items at `.agent/hooks/scratchpads/test_session.md`, then run `python .agent/hooks/grind-until-done.py`
- **Expected**: Hook detects unchecked items, outputs followup message
- **Validates**: Grind loop unchecked item detection
- **Flags-Tested**: N/A
- **Protocol**: grind-loop

### TEST-HOOK-005: Scratchpad format validation

- **Category**: hook
- **Component**: hook
- **Component-Name**: grind-until-done.py
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: Create scratchpad with proper markdown format, check items off one by one, verify DONE detection after all checked
- **Expected**: Each state transition works correctly
- **Validates**: Scratchpad lifecycle
- **Flags-Tested**: N/A
- **Protocol**: grind-loop

### TEST-HOOK-006: Hook timeout behavior

- **Category**: hook
- **Component**: hook
- **Component-Name**: hooks.json
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: Verify hooks.json timeout values: sessionStart=15000ms, stop=5000ms, sessionEnd=10000ms
- **Expected**: Timeouts match configured values
- **Validates**: Hook configuration
- **Flags-Tested**: N/A
- **Protocol**: none

---

## Section 15: Infrastructure and Convention Tests

### TEST-INFRA-001: Error NOT_FOUND

- **Category**: infrastructure
- **Component**: infrastructure
- **Component-Name**: error-handling
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py nonexistent_db.db AiLaunchProcess --json`
- **Expected**: Structured JSON error on stderr: `{"error": "...", "code": "NOT_FOUND"}`, exit code 1
- **Validates**: NOT_FOUND error code
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-INFRA-002: Error INVALID_ARGS

- **Category**: infrastructure
- **Component**: infrastructure
- **Component-Name**: error-handling
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `python .agent/skills/decompiled-code-extractor/scripts/list_functions.py`
- **Expected**: Structured error for missing required db_path argument
- **Validates**: INVALID_ARGS error code
- **Flags-Tested**: none
- **Protocol**: none

### TEST-INFRA-003: Search multi-match listing

- **Category**: infrastructure
- **Component**: infrastructure
- **Component-Name**: error-handling
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py <db:appinfo> --search "Check" --json`
- **Expected**: JSON with status ok containing match_count and matches array for the search results
- **Validates**: Search listing returns structured matches
- **Flags-Tested**: --search, --json
- **Protocol**: none

### TEST-INFRA-004: Error NO_DATA

- **Category**: infrastructure
- **Component**: infrastructure
- **Component-Name**: error-handling
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/decompiled-code-extractor/scripts/list_functions.py <db:appinfo> --search "ZZZZNONEXISTENT" --json`
- **Expected**: NO_DATA result for zero matches
- **Validates**: NO_DATA handling
- **Flags-Tested**: --search, --json
- **Protocol**: none

### TEST-INFRA-005: Error DB_ERROR

- **Category**: infrastructure
- **Component**: infrastructure
- **Component-Name**: error-handling
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `python .agent/skills/classify-functions/scripts/triage_summary.py /dev/null --json`
- **Expected**: DB_ERROR for corrupt/invalid DB
- **Validates**: DB_ERROR error code
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-INFRA-006: Error PARSE_ERROR

- **Category**: infrastructure
- **Component**: infrastructure
- **Component-Name**: error-handling
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: Verify emit_error with PARSE_ERROR code produces `{"error": "...", "code": "PARSE_ERROR"}` on stderr
- **Expected**: Structured JSON error `{"error": "...", "code": "PARSE_ERROR"}` on stderr, exit code 1
- **Validates**: PARSE_ERROR structured format
- **Flags-Tested**: N/A
- **Protocol**: none

### TEST-INFRA-007: JSON output is single dict with status

- **Category**: infrastructure
- **Component**: infrastructure
- **Component-Name**: json-output-contract
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/classify-functions/scripts/triage_summary.py <db:appinfo> --json`
- **Expected**: Exactly one JSON dict on stdout with "status" key
- **Validates**: JSON output convention -- single dict with status
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-INFRA-008: JSON output stream separation

- **Category**: infrastructure
- **Component**: infrastructure
- **Component-Name**: json-output-contract
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/classify-functions/scripts/triage_summary.py <db:appinfo> --json 2>stderr.txt`
- **Expected**: stdout is pure JSON, stderr has progress messages only
- **Validates**: stdout/stderr separation
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-INFRA-009: Human-readable output format

- **Category**: infrastructure
- **Component**: infrastructure
- **Component-Name**: json-output-contract
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/classify-functions/scripts/triage_summary.py <db:appinfo> --top 5`
- **Expected**: Formatted table output, line widths under 120 chars
- **Validates**: Human-readable output convention
- **Flags-Tested**: --top (no --json)
- **Protocol**: none

### TEST-INFRA-010: Cache creation

- **Category**: infrastructure
- **Component**: infrastructure
- **Component-Name**: cache-behavior
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/classify-functions/scripts/triage_summary.py <db:appinfo> --json` (run twice)
- **Expected**: First run creates cache file in .agent/cache/, second run hits cache
- **Validates**: Cache file creation and hit
- **Flags-Tested**: --json
- **Protocol**: none

### TEST-INFRA-011: Cache bypass with --no-cache

- **Category**: infrastructure
- **Component**: infrastructure
- **Component-Name**: cache-behavior
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/skills/classify-functions/scripts/triage_summary.py <db:appinfo> --json --no-cache`
- **Expected**: Fresh computation regardless of existing cache
- **Validates**: --no-cache bypass
- **Flags-Tested**: --json, --no-cache
- **Protocol**: none

### TEST-INFRA-012: Workspace run directory creation

- **Category**: infrastructure
- **Component**: infrastructure
- **Component-Name**: workspace-pattern
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `/triage appinfo.dll` (or any workspace-protocol command)
- **Expected**: Run dir created under .agent/workspace/ with manifest.json
- **Validates**: Workspace directory creation
- **Flags-Tested**: N/A
- **Protocol**: workspace

### TEST-INFRA-013: Workspace manifest and step files

- **Category**: infrastructure
- **Component**: infrastructure
- **Component-Name**: workspace-pattern
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: After workspace command, inspect run dir
- **Expected**: manifest.json with step statuses, each step has results.json and summary.json
- **Validates**: Workspace step output contract
- **Flags-Tested**: N/A
- **Protocol**: workspace

### TEST-INFRA-014: Grind loop scratchpad creation

- **Category**: infrastructure
- **Component**: infrastructure
- **Component-Name**: grind-loop-protocol
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `/full-report appinfo.dll` (grind-loop command)
- **Expected**: Scratchpad created at .agent/hooks/scratchpads/{session_id}.md
- **Validates**: Scratchpad creation for multi-item tasks
- **Flags-Tested**: N/A
- **Protocol**: grind-loop

### TEST-INFRA-015: Grind loop re-invocation

- **Category**: infrastructure
- **Component**: infrastructure
- **Component-Name**: grind-loop-protocol
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: Observe grind loop during /full-report or /scan execution
- **Expected**: Agent re-invoked until all items checked or DONE
- **Validates**: Loop continuation mechanism
- **Flags-Tested**: N/A
- **Protocol**: grind-loop

### TEST-INFRA-016: Grind loop limit

- **Category**: infrastructure
- **Component**: infrastructure
- **Component-Name**: grind-loop-protocol
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: Verify hooks.json loop_limit is 10
- **Expected**: Loop stops after 10 re-invocations maximum
- **Validates**: Loop limit enforcement
- **Flags-Tested**: N/A
- **Protocol**: grind-loop

### TEST-INFRA-017: Missing tracking DB degradation

- **Category**: infrastructure
- **Component**: infrastructure
- **Component-Name**: missing-dependency
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: Run cross-module command when tracking DB is absent
- **Expected**: Warning logged, single-module analysis continues
- **Validates**: Graceful degradation for missing tracking DB
- **Flags-Tested**: N/A
- **Protocol**: none

### TEST-INFRA-018: JSON-only fallback

- **Category**: infrastructure
- **Component**: infrastructure
- **Component-Name**: missing-dependency
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: Run analysis when analysis DB is absent but extracted_code exists
- **Expected**: Falls back to function_index.json, reports unavailable features
- **Validates**: JSON-only mode degradation
- **Flags-Tested**: N/A
- **Protocol**: none

### TEST-INFRA-019: Config loading

- **Category**: infrastructure
- **Component**: infrastructure
- **Component-Name**: configuration
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: Verify .agent/config/defaults.json loads without errors
- **Expected**: All sections parsed: classification, scoring, callgraph, triage, security_auditor, pipeline, verifier, cache, hooks, rpc, winrt, com, scale
- **Validates**: Configuration loading
- **Flags-Tested**: N/A
- **Protocol**: none

### TEST-INFRA-020: Config env overrides

- **Category**: infrastructure
- **Component**: infrastructure
- **Component-Name**: configuration
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: Set `DEEPEXTRACT_CACHE_MAX_AGE_HOURS=1` and verify cache behavior changes
- **Expected**: Environment variable overrides defaults.json value
- **Validates**: Env variable override mechanism
- **Flags-Tested**: N/A
- **Protocol**: none

### TEST-INFRA-021: Unified search CLI

- **Category**: infrastructure
- **Component**: infrastructure
- **Component-Name**: unified_search.py
- **Target-Module**: appinfo.dll
- **Target-Function**: N/A
- **Command**: `python .agent/helpers/unified_search.py <db:appinfo> --query "CreateProcess" --json`
- **Expected**: JSON with status ok containing search results across dimensions
- **Validates**: Standalone unified_search.py CLI with --json output
- **Flags-Tested**: --query, --json
- **Protocol**: none

### TEST-INFRA-022: Health check CLI

- **Category**: infrastructure
- **Component**: infrastructure
- **Component-Name**: health_check.py
- **Target-Module**: N/A
- **Target-Function**: N/A
- **Command**: `python .agent/helpers/health_check.py --quick --json`
- **Expected**: JSON with status ok containing workspace health summary
- **Validates**: Standalone health_check.py CLI with --json output
- **Flags-Tested**: --quick, --json
- **Protocol**: none

---

## Coverage Cross-Check

| Component | Total | Tested | Coverage |
|-----------|-------|--------|----------|
| Commands | 36 | 36 | 100% |
| Command flags/subcommands | ~85 | ~85 | 100% |
| Skills | 29 | 29 | 100% |
| Skill scripts | ~122 | ~122 | 100% |
| Agents | 6 | 6 | 100% |
| Agent entry scripts | 13 | 13 | 100% |
| Agent goals/modes | ~16 | ~16 | 100% |
| VR workflows | 7 | 7 | 100% |
| Pipeline YAMLs | 4 | 4 | 100% |
| Lifecycle hooks | 3 | 2 | 67% |
| Error codes | 6 | 6 | 100% |
| Grind-loop commands | 6 | 6 | 100% |
| Workspace-protocol commands | 14 | 14 | 100% |
| Cacheable script --no-cache | ~30 | ~30 | 100% |

## Test ID Registry

| Prefix | Section | Count |
|--------|---------|-------|
| TEST-INIT | Initialization | 5 |
| TEST-RECON | Reconnaissance | 20 |
| TEST-STRUCT | Structural Understanding | 38 |
| TEST-IFACE | Interface Analysis | 25 |
| TEST-VULN | Vulnerability Scanning | 24 |
| TEST-AUDIT | Security Auditing | 12 |
| TEST-VR | VR Campaigns | 8 |
| TEST-QUAL | Code Quality | 12 |
| TEST-OPS | Reporting and Ops | 13 |
| TEST-SKILL | Skill Scripts | 129 |
| TEST-AGENT | Agent Scripts | 35 |
| TEST-FLOW | VR Workflows | 7 |
| TEST-PIPE | Pipeline | 6 |
| TEST-HOOK | Hooks | 3 |
| TEST-INFRA | Infrastructure | 22 |
| **TOTAL** | | **359** |
