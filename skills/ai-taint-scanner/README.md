# AI Taint Scanner Skill

Traces attacker-controlled data from entry points to dangerous sinks across
module boundaries using LLM-driven analysis. Builds a cross-module callgraph,
enriches nodes with taint-specific metadata (sink density, parameter types,
trust boundaries), and delivers batches to the AI agent for iterative depth
expansion and skeptic verification.

## Directory Structure

```
ai-taint-scanner/
├── README.md
├── SKILL.md              # Full skill definition, workflows, triage protocol
├── reference/
│   ├── taint_patterns.md # 8 concrete taint vulnerability patterns
│   └── decompiler_pitfalls.md  # Hex-Rays misreadings (assembly verification)
└── scripts/
    ├── build_threat_model.py   # Taint-focused threat model (entry points, trust, sinks)
    └── prepare_context.py     # Taint-enriched callgraph with traversal plan
```

## Key Scripts

- **`build_threat_model.py`** — Produces module identity, trust boundary, attacker
  model, and top entry points with sink density. Start here for any scan.
- **`prepare_context.py`** — Builds cross-module callgraph with taint hints
  (dangerous APIs, globals, loops, parameters). Supports `--function <name>`
  or `--entry-points` with `--with-code` for upfront code preloading.

## Dependencies

- **decompiled-code-extractor** — DB resolution, function listing, code extraction
- **map-attack-surface** — Entry point discovery, attack scoring

## Related

- **taint-scanner agent** (`.agent/agents/taint-scanner.md`) — AI agent that
  consumes this skill's outputs; runs iterative depth analysis and skeptic
  verification.
- **`/taint` command** — Traces taint via `taint-analysis` skill for single-function
  or cross-module flows; uses `taint_function.py` / `trace_taint_cross_module.py`.
- **`/taint-scan`** — Invokes the taint-scanner agent for AI-driven module-wide
  taint analysis.
