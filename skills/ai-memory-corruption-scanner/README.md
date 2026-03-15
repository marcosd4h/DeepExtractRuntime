# AI Memory Corruption Scanner

AI-driven memory corruption vulnerability scanner for IDA Pro decompiled
Windows PE binaries. Uses LLM agents with adversarial prompting to navigate
cross-module callgraphs, identify vulnerabilities, and verify findings
against assembly ground truth.

## Quick Start

```bash
# Build threat model
python .agent/skills/ai-memory-corruption-scanner/scripts/build_threat_model.py <db_path> --json

# Prepare callgraph context for a specific function
python .agent/skills/ai-memory-corruption-scanner/scripts/prepare_context.py <db_path> \
    --function "NetrShareGetInfo" --depth 5 --json

# Prepare callgraph context from auto-discovered entry points
python .agent/skills/ai-memory-corruption-scanner/scripts/prepare_context.py <db_path> \
    --entry-points --depth 5 --json
```

## Scripts

| Script | Purpose |
|--------|---------|
| `build_threat_model.py` | Module threat model (service type, attacker model, entry points) |
| `prepare_context.py` | Cross-module callgraph JSON for AI agent navigation |

## Reference Materials

| File | Purpose |
|------|---------|
| `reference/vulnerability_patterns.md` | 10 memory corruption patterns with decompiled code examples |
| `reference/decompiler_pitfalls.md` | Common Hex-Rays misreadings and assembly verification |

## Architecture

The skill provides context preparation. The actual vulnerability detection
is performed by the `memory-corruption-scanner` agent (defined in
`.agent/agents/memory-corruption-scanner.md`) which reads the callgraph JSON
and retrieves function code on demand via `extract_function_data.py`.

See [SKILL.md](SKILL.md) for full documentation.
