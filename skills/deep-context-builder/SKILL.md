---
name: deep-context-builder
description: >-
  Build deep, line-by-line understanding of IDA Pro decompiled functions
  before vulnerability hunting, using structured block-by-block analysis
  with First Principles, 5 Whys, and 5 Hows to reduce hallucinations
  and missed assumptions. Use when the user asks for deep understanding
  of a decompiled function, thorough comprehension before auditing,
  line-by-line analysis of Hex-Rays output, building context before a
  security review, or needs to understand complex decompiled code with
  many branches, casts, and indirect calls.
depends_on: ["decompiled-code-extractor", "classify-functions", "callgraph-tracer", "data-flow-tracer", "map-attack-surface"]
cacheable: false
---

# Deep Context Builder

## Purpose

Build deep, accurate understanding of IDA Pro decompiled C/C++ code
before vulnerability hunting begins. This skill governs how the agent
thinks during the context-building phase -- forcing block-by-block
analysis instead of surface-level skimming.

Decompiled code is an approximation. Hex-Rays naming conventions
(`v1`, `a1`), recovered `this` pointers, reconstructed vtable calls,
and other artifacts require careful interpretation. This skill teaches
the agent to recognize these artifacts, cross-reference against
assembly, and build a stable mental model that doesn't degrade over
long analysis sessions.

The skill does not find vulnerabilities. It builds the understanding
that makes vulnerability discovery accurate. All vulnerability
hunting happens after context building is complete.

## When to Use

- Deep comprehension before `/audit` on a complex function
- Understanding a decompiled function with many branches, casts, or indirect calls
- Preparing for security review of a Windows service, COM component, or RPC handler
- Architecture understanding of an extracted module before campaign planning
- When prior analysis produced hallucinated findings due to shallow understanding

## When NOT to Use

- Finding vulnerabilities -- use **adversarial-reasoning**
- Quick explanation of what a function does -- use `/explain` with **re-analyst**
- Scoring findings by exploitability -- use **exploitability-assessment**
- Building factual dossiers (reachability, dangerous ops) -- use **security-dossier**
- Verifying decompiler accuracy on specific functions -- use **verify-decompiled**

## Rationalizations to Reject

| Rationalization | Why It's Wrong | Required Action |
|-----------------|----------------|-----------------|
| "I get the gist" | Gist-level understanding of decompiled code misses edge cases in type casts, error paths, and optimized branches | Block-by-block analysis required |
| "This function is simple" | Simple decompiled functions compose into complex bugs. A 20-line wrapper around `CreateFileW` may be the key link in a symlink attack chain. | Apply 5 Whys anyway |
| "The decompiled output is self-explanatory" | Hex-Rays output is an approximation. Check assembly for sign extension, actual branch targets, and optimized-away checks. | Cross-reference suspicious constructs against assembly |
| "External call is probably fine" | External DLL calls are adversarial until proven otherwise by checking the callee via cross-module resolution | Jump into the callee or model as hostile |
| "I can skip this helper function" | Helper functions contain assumptions about buffer sizes, string formats, and error handling that propagate to all callers | Trace the full call chain |
| "This is taking too long" | Rushed context = hallucinated vulnerabilities later. Slow is fast. | Continue block-by-block; anchor progress periodically |

## Data Sources

Context building uses data from:
- `decompiled-code-extractor`: Function decompiled code, assembly, xrefs, strings
- `classify-functions`: Function purpose categories, interest scores
- `callgraph-tracer`: Call chains, cross-module resolution
- `data-flow-tracer`: Global variable producer/consumer maps
- `map-attack-surface`: Entry point discovery and classification

### Finding a Module DB

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py --list
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py <module>
```

## Workflow

### Phase 1: Initial Orientation

**Entry**: User has provided a module name or specific function.
**Exit**: Preliminary structure map with anchors for detailed analysis.

Orientation Progress:
- [ ] Step 1: Identify module structure
- [ ] Step 2: Note entry points
- [ ] Step 3: Map shared state
- [ ] Step 4: Preliminary structure

**Step 1**: Identify major code files and function groups.

```bash
python .agent/skills/classify-functions/scripts/triage_summary.py <db_path> --json
```

**Step 2**: Note exported entry points (DLL exports, COM methods, RPC
handlers, service entry points).

```bash
python .agent/skills/map-attack-surface/scripts/discover_entrypoints.py <db_path> --json
```

**Step 3**: Identify important global variables and shared state.

```bash
python .agent/skills/data-flow-tracer/scripts/global_state_map.py <db_path> --summary --json
```

**Step 4**: Build preliminary structure without assuming behavior.

### Phase 2: Ultra-Granular Function Analysis

**Entry**: Phase 1 complete, target function identified.
**Exit**: Every block analyzed with invariants, assumptions, and
cross-function dependencies documented.

Analysis Progress:
- [ ] Step 1: Extract function data
- [ ] Step 2: Per-block analysis
- [ ] Step 3: Cross-function flow
- [ ] Step 4: Anchor summary

**Step 1**: Extract function via `extract_function_data.py`.

```bash
python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py <db_path> --id <func_id> --json
```

**Step 2**: For each logical block in the decompiled code, document:
- **What** it does
- **Why** it appears at this position (ordering logic)
- **Assumptions** it relies on
- **Invariants** it establishes or maintains
- **Dependencies** -- what later logic depends on this block

Apply per block:
- **First Principles**: What is the fundamental operation here?
- **5 Whys**: Why does this block exist? Why this specific approach?
- **5 Hows**: How does the data reach this point? How is the result used?

IDA-specific awareness during block analysis:
- Recognize `HIDWORD`/`LODWORD`/`BYTE1` as Hex-Rays 64-bit access macros
- Recognize recovered `this` parameters in `__thiscall`/`__fastcall`
- Check assembly when type casts look suspicious (signed/unsigned confusion)
- Verify vtable dispatch targets against assembly `call [reg+offset]`

**Step 3**: Follow cross-function dependencies via IDA xrefs.

For **internal calls**: Jump into the callee, continue block-by-block
analysis, propagate invariants and assumptions across the boundary.

For **external DLL calls** (two cases):
- **Code available** (resolved via cross-module): Jump in, analyze as internal
- **Code unavailable** (true external): Model as adversarial -- consider
  all outcomes: revert, unexpected return values, state changes, reentrancy

Treat the entire call chain as one continuous execution flow. Never
reset context when crossing function boundaries.

**Step 4**: Anchor key findings. Summarize:
- Core invariants discovered
- Key assumptions documented
- Risk considerations identified
- Unresolved questions (mark as "unclear; need to inspect X")

### Phase 3: Global System Understanding

**Entry**: Phase 2 complete for sufficient functions.
**Exit**: System-level model connecting individual function analyses.

- **State/invariant reconstruction**: Map reads/writes of each global,
  derive multi-function invariants
- **Workflow reconstruction**: Identify end-to-end flows (service
  startup, RPC dispatch, COM activation, file I/O sequences)
- **Trust boundary mapping**: Actor -> entry point -> behavior, using
  `map-attack-surface` output
- **Complexity/fragility clustering**: Functions with many assumptions,
  high branching, coupled state changes across modules

## Anti-Hallucination Rules

- **Never reshape evidence to fit earlier assumptions.** When
  contradicted: update the model, state the correction explicitly.
- **Periodically anchor key facts.** Summarize core invariants, state
  relationships, actor roles, and workflows.
- **Avoid vague guesses.** Use "Unclear; need to inspect assembly at
  offset X" instead of "It probably..."
- **Cross-reference constantly.** Connect new insights to previous
  state, flows, and invariants to maintain global coherence.

## Quality Thresholds

Per analyzed function, the analysis must include at minimum:
- 3 invariants (what must be true for the function to work correctly)
- 5 assumptions (what the function assumes about its inputs, callers, and environment)
- 3 risk considerations (what could go wrong if assumptions are violated)

## Scope Exclusions

- Does not find vulnerabilities (use adversarial-reasoning after context building)
- Does not analyze library boilerplate (WIL, STL, WRL, CRT) unless it affects application logic
- Does not produce scored assessments or reports

## Degradation Paths

1. **Assembly data missing**: Continue with decompiled-code-only analysis. Note that IDA-specific artifact verification is unavailable.
2. **Cross-module tracking DB unavailable**: Limit analysis to single module. Note external calls as unresolved.
3. **Function too large (1000+ instructions)**: Focus Phase 2 on the most interesting blocks (security-relevant, complex branches). Document which blocks were skipped.

## Prompt Patterns

### Pattern A: Deep function understanding

> "I need to deeply understand AiLaunchProcess before auditing it"

1. Run Phase 1 orientation on the module
2. Extract the target function (Phase 2, Step 1)
3. Perform full block-by-block analysis (Phase 2, Steps 2-4)

### Pattern B: Module architecture understanding

> "Help me understand how this service works before I look for bugs"

1. Run Phase 1 fully (all 4 steps)
2. Run Phase 2 on the top 3-5 entry point functions
3. Run Phase 3 to connect the pieces

## Integration with Other Skills

| Task | Skill |
|------|-------|
| Extract function data (decompiled + assembly) | decompiled-code-extractor |
| Classify functions by purpose | classify-functions |
| Trace call chains and cross-module flow | callgraph-tracer |
| Map global variable producers/consumers | data-flow-tracer |
| Discover and classify entry points | map-attack-surface |
| Verify decompiler accuracy on specific code | verify-decompiled |
| Build factual security context | security-dossier |

## Performance

| Operation | Typical Time | Notes |
|-----------|-------------|-------|
| Phase 1 (orientation) | ~30-60s | 3-4 script calls + synthesis |
| Phase 2 (single function) | ~2-5 min | Agent reasoning-heavy |
| Phase 2 (complex function, 500+ instructions) | ~5-10 min | More blocks to analyze |
| Phase 3 (system understanding) | ~5-10 min | Depends on module complexity |

## Additional Resources

- [reference.md](reference.md) -- Microstructure checklist, completeness checklist, worked example, output template
- [analyze-ida-decompiled SKILL.md](../analyze-ida-decompiled/SKILL.md) -- IDA naming patterns and extraction layout
- [adversarial-reasoning SKILL.md](../adversarial-reasoning/SKILL.md) -- Vulnerability research methodology (runs after context building)
