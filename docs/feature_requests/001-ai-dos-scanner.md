# FR-001: AI-Driven Denial of Service Scanner

**Status:** Proposed
**Priority:** High
**Category:** Security Scanner
**Author:** Runtime Assessment Review
**Date:** 2026-03-16

---

## Problem Statement

No existing scanner targets Denial of Service conditions systematically.
The memory-corruption scanner finds overflows (which may crash, but it
reasons about RCE primitives), and the logic scanner finds auth bypasses
and state machine errors, but neither hunts for crash-inducing patterns:
null dereferences on error paths, infinite loops controllable by attacker
input, reachable abort/fastfail calls, or resource exhaustion from
unbounded allocation.

The MSRC Windows Insider Preview Bounty Program pays **$30,000 USD** for:

> Unauthenticated data destruction or persistent denial of service with
> no user interaction that is triggered by using a small number of packets
> and results in a remote BSOD or crash in a high value asset

This scanner fills a gap in vulnerability class coverage that the existing
three AI scanners (memory-corruption, logic, taint) do not address.

---

## Proposed Solution

Build an **AI-driven DoS scanner** following the 6-stage pipeline defined
in `docs/ai_scanner_authoring_guide.md`.  The LLM is the sole vulnerability
detection and scoring authority.  No programmatic regex or pattern-matching
detects vulnerabilities.  The programmatic layer provides only structure
(callgraph, entry points, library filtering, DoS-specific reference
material).

### What the LLM Reasons About (Not What Regex Matches)

The LLM reads decompiled code and assembly along the callgraph and reasons
about:

- **Null pointer dereferences:** Missing null checks after fallible API
  calls (HeapAlloc, CoCreateInstance, QueryInterface) where a crafted
  input causes the API to fail and the unchecked pointer is dereferenced.

- **Unbounded loops:** Loops whose exit condition or iteration count
  depends on attacker-controlled data without a cap.  Loops with
  `is_infinite == true` or `exit_condition_count == 0` in the DB
  loop_analysis metadata.

- **Reachable crash paths:** Functions that call abort, __fastfail,
  RaiseFailFastException, TerminateProcess, or similar crash APIs on
  error paths triggerable by attacker-controlled input.  The LLM must
  distinguish defensive crashes (stack cookie check -> __fastfail) from
  exploitable crashes (malformed input -> unhandled error -> abort).

- **Resource exhaustion:** Allocation inside loops without bounds,
  recursive call patterns that amplify small input into deep stack usage,
  handle/object leaks on error paths that an attacker can trigger
  repeatedly.

- **Algorithmic complexity:** Hash collision attacks, quadratic parsing,
  regex backtracking on attacker-controlled input.

---

## Architecture

### 6-Stage Pipeline (per AI Scanner Authoring Guide)

```
Stage 0: Threat Model      Compact module context (service type, attacker model, entry points)
Stage 1: Callgraph Prep    Cross-module callgraph JSON via CrossModuleGraph
Stage 2: Quick Triage      Cheap LLM pass: likely/unlikely per entry point (callgraph structure only, no code)
Stage 3: Deep Analysis     Expensive LLM: adversarial prompting + DoS-specific specialists
Stage 4: Skeptic Verify    Separate subagent: 4-criteria self-checks + PoC reasoning
Stage 5: Report + JSON     Markdown report + .findings.json companion
Stage 6: Cross-Report      Compare against previous DoS scan
```

### Components to Create

| Component | Path | Description |
|-----------|------|-------------|
| Skill | `.claude/skills/ai-dos-scanner/` | Skill directory |
| SKILL.md | `.claude/skills/ai-dos-scanner/SKILL.md` | Skill definition with YAML frontmatter |
| Reference | `.claude/skills/ai-dos-scanner/reference/vulnerability_patterns.md` | 5-10 DoS-specific vulnerability examples with decompiled code |
| Reference | `.claude/skills/ai-dos-scanner/reference/decompiler_pitfalls.md` | Copy from ai-memory-corruption-scanner |
| Scripts | `.claude/skills/ai-dos-scanner/scripts/_common.py` | Lean bootstrap (NO domain constants, NO scoring) |
| Scripts | `.claude/skills/ai-dos-scanner/scripts/build_threat_model.py` | Stage 0: reuse from ai-memory-corruption-scanner |
| Scripts | `.claude/skills/ai-dos-scanner/scripts/prepare_context.py` | Stage 1: reuse from ai-memory-corruption-scanner |
| Agent | `.claude/agents/dos-scanner.md` | Agent definition with red-team persona |
| Command | `.claude/commands/dos-scan.md` | `/dos-scan` command definition |
| Tests | `.claude/tests/test_ai_dos_scanner.py` | Registry consistency + script smoke tests |

### What the Scripts Do (Programmatic Only)

`build_threat_model.py` and `prepare_context.py` are domain-agnostic
and shared across all AI scanners.  They produce:

- **Threat model:** Module identity, service type, privilege level,
  attacker model, top entry points with IPC metadata.
- **Callgraph:** Cross-module forward call tree with nodes classified
  as MUST_READ / KNOWN_API / TELEMETRY / LIBRARY.  Preloaded code for
  depth 0+1 MUST_READ functions.

No DoS-specific programmatic detection.  No `scan_null_deref.py`.
No `scan_crash_paths.py`.  No `compute_dos_score()`.  The LLM reads
code and finds the bugs.

### What the LLM Does (Stages 2-4)

**Stage 2 -- Quick Triage (structure only, no code):**

Decision signals for DoS scanner:
- Allocation APIs (HeapAlloc, VirtualAlloc, malloc) and loop-heavy
  subtrees in the callgraph
- Recursive call patterns (SCCs in the forward tree)
- Resource-acquiring APIs without matching release APIs in error paths
- Crash APIs (abort, __fastfail, TerminateProcess) as KNOWN_API nodes
- Large MUST_READ counts suggesting complex parsing logic

**Stage 3 -- Deep Analysis (3-round adversarial + specialists):**

Round 1 (Assert + Invariant Decomposition):
> "This call chain is definitely vulnerable to denial of service. Read
> the entry point function.  List every assumption the code makes about
> resource limits, iteration bounds, allocation sizes, error recovery,
> and recursion depth.  For each assumption, determine whether an
> attacker can violate it."

Round 2 (Escalate):
> "Those are the obvious checks.  What happens at max capacity?  What
> about recursive calls with attacker-controlled depth?  Resource leaks
> in error paths?  What if the attacker sends the same malformed packet
> 10,000 times?"

Round 3 (Compare to Known-Good):
> "How does this resource handling differ from the safe pattern of rate
> limiting, resource quotas, circuit breakers, and bounded work queues?"

**DoS-Specific Specialists (3):**

| Specialist | CWE | Focus |
|------------|-----|-------|
| ResourceExhaustionSpecialist | CWE-400, CWE-770 | Memory/handle/thread exhaustion from unbounded allocation or leaks |
| AlgorithmicComplexitySpecialist | CWE-407, CWE-1333 | Hash collisions, quadratic parsing, regex backtracking |
| UncontrolledRecursionSpecialist | CWE-674, CWE-835 | Stack overflow from recursive descent, infinite loops |

**Stage 4 -- Skeptic Verification:**

4-criteria self-checks adapted for DoS:

1. **TRIGGER FLOW:** Re-read the code.  Does attacker input actually
   reach the resource-consuming operation, loop bound, or error path
   through concrete assignments and function arguments?
2. **RESOURCE LIMITS:** Are there caps, quotas, or timeouts between
   the source and the exhaustion point?  Are they *sufficient*?
   (`if (count < 100)` is NOT sufficient if each item costs O(n) work.)
3. **REACHABILITY:** Is the path actually reachable from the entry
   point?  No dead code or unreachable branches?
4. **EXPLOITABILITY:** Construct exact inputs that trigger the DoS.
   "Write the exact RPC call or network packet that causes the service
   to crash, hang, or consume >1GB memory on a single request."

---

## Vulnerability Patterns Reference

The `reference/vulnerability_patterns.md` file must contain 5-10
concrete examples.  Each example must include all 5 components per
the authoring guide:

1. Pattern name and CWE ID
2. Decompiled code example (actual Hex-Rays output)
3. Data flow explanation
4. Why it is exploitable
5. Safe comparison pattern

### Suggested Patterns (5-10)

| # | Pattern | CWE | Key Indicator |
|---|---------|-----|---------------|
| 1 | Unbounded allocation from attacker-controlled size | CWE-770 | HeapAlloc/malloc with size from parameter, no cap |
| 2 | Algorithmic complexity attack on hash table or sort | CWE-407 | Hash/sort function with attacker-controlled keys |
| 3 | Recursive parsing with attacker-controlled depth | CWE-674 | Self-recursive function processing nested structures |
| 4 | Resource leak in error path (handle, memory, lock) | CWE-404 | CreateFile/OpenProcess without CloseHandle on error goto |
| 5 | Infinite loop from malformed input | CWE-835 | Loop with exit depending on attacker-controlled sentinel |
| 6 | Null deref after unchecked fallible API | CWE-476 | HeapAlloc returns NULL, no check before dereference |
| 7 | Reachable abort/fastfail on triggerable error path | CWE-617 | __fastfail after HRESULT check on attacker-controlled op |
| 8 | Excessive CPU from regex/pattern matching on crafted input | CWE-1333 | Pattern match in loop with backtracking |

---

## DB Data Available for Context Enrichment

The analysis databases store metadata useful for DoS triage (consumed
by the threat model and callgraph preparation, NOT for programmatic
detection):

| DB Column | Relevant Fields | DoS Triage Use |
|-----------|----------------|----------------|
| `loop_analysis` | `is_infinite`, `exit_condition_count`, `has_function_calls`, `nesting_level` | Annotate callgraph nodes with loop characteristics |
| `stack_frame` | `exception_handler`, `has_canary` | Annotate nodes with error handling presence |
| `simple_outbound_xrefs` | Called functions | Callgraph construction (standard) |
| `dangerous_api_calls` | Pre-computed dangerous API list | Annotate nodes with crash API presence |

These are structural annotations for the LLM's triage and analysis
context, not programmatic detection signals.

---

## Integration Points

Per Section 14 of the AI Scanner Authoring Guide:

| Integration | File | Change |
|-------------|------|--------|
| Skills registry | `skills/registry.json` | Add `ai-dos-scanner` entry |
| Agents registry | `agents/registry.json` | Add `dos-scanner` entry |
| Commands registry | `commands/registry.json` | Add `dos-scan` entry |
| Script invocation guide | `rules/script-invocation-guide.mdc` | Add DoS script signatures |
| Command validation | `helpers/command_validation.py` | Add `dos-scan` to `_COMMAND_REQUIREMENTS` |
| Pipeline executor | `helpers/pipeline_executor.py` | Add `dos-scan` dispatch function |
| Pipeline YAML | `config/pipelines/full-analysis.yaml` | Add `dos-scan` step |
| `/scan` command | `commands/scan.md` | Add `--dos-only` flag delegating to `/dos-scan` |
| `/scan` registry | `commands/registry.json` | Add `ai-dos-scanner` to scan's `skills_used` |
| security-auditor agent | `agents/security-auditor.md` | Reference DoS scanner |
| Finding schema | `helpers/finding_schema.py` | Add `from_dos_finding()` adapter if output differs |
| Test bootstrap | `tests/test_bootstrap_dedup.py` | Add `ai-dos-scanner` to `EXPECTED_SKILLS` |
| Skills README | `skills/README.md` | Add skill entry |
| Agents README | `agents/README.md` | Add agent entry |
| Commands README | `commands/README.md` | Add command entry |

---

## What NOT to Build

Per the AI Scanner Authoring Guide anti-patterns:

- **No `scan_null_deref.py`** or any per-category regex scanner script.
  The LLM detects null derefs by reading code, not regex.
- **No `compute_dos_score()`** or programmatic scoring formula.
  The LLM assigns severity with natural-language reasoning.
- **No `DosFinding` dataclass** with category-specific fields.
  Use the standard AI scanner finding schema.
- **No `FALLIBLE_APIS` or `CRASH_APIS` constant tuples** in `_common.py`.
  The LLM knows which APIs can fail and which crash.  API taxonomy
  is structural metadata, not scanner input.
- **No `verify_findings.py`** with programmatic verification.
  Skeptic verification is LLM-driven via a separate subagent.

---

## Acceptance Criteria

1. `/dos-scan <module>` runs the full 6-stage AI scanner pipeline and
   produces a markdown report + `.findings.json` companion
2. Stage 2 triage uses callgraph structure only (no code reading)
3. Stage 3 deep analysis uses adversarial 3-round prompting with
   3 DoS-specific specialists
4. Stage 4 skeptic verification runs as a separate subagent with
   4-criteria DoS-adapted checks
5. Stage 6 cross-report comparison works against previous DoS scans
6. `/scan <module>` includes DoS findings when `--dos-only` is not set
7. `--dos-only` flag on `/scan` delegates to `/dos-scan`
8. All findings include `verification_subgraph` for skeptic navigation
9. No programmatic regex or pattern-matching detects vulnerabilities
10. The LLM assigns severity -- no programmatic scoring formula
11. All registry entries (skills, agents, commands) are consistent
12. Test suite passes with new skill/agent/command additions

---

## References

- [AI Scanner Authoring Guide](../ai_scanner_authoring_guide.md)
- [ai-memory-corruption-scanner SKILL.md](../../skills/ai-memory-corruption-scanner/SKILL.md) (reference implementation)
- [memory-corruption-scanner.md](../../agents/memory-corruption-scanner.md) (agent template)
- [memory-scan.md](../../commands/memory-scan.md) (command template)
- MSRC Windows Insider Preview Bounty Program: https://www.microsoft.com/en-us/msrc/bounty-windows-insider-preview
