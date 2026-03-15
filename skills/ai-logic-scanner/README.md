# AI Logic Scanner

AI-driven logic vulnerability scanner for IDA Pro decompiled Windows PE
binaries. Uses LLM agents with adversarial prompting to navigate cross-module
callgraphs, identify logic flaws (auth bypass, state machine errors,
confused deputy, privilege escalation), and verify findings against assembly
ground truth.

## Quick Start

```bash
# Build threat model (includes programmatic hints from regex scanners)
python .agent/skills/ai-logic-scanner/scripts/build_threat_model.py <db_path> --json

# Prepare callgraph context for a specific function
python .agent/skills/ai-logic-scanner/scripts/prepare_context.py <db_path> \
    --function "NetrShareGetInfo" --depth 5 --json

# Prepare callgraph context from auto-discovered entry points
python .agent/skills/ai-logic-scanner/scripts/prepare_context.py <db_path> \
    --entry-points --depth 5 --json

# Gather programmatic hints only
python .agent/skills/ai-logic-scanner/scripts/gather_logic_hints.py <db_path> --json
```

## Scripts

| Script | Purpose |
|--------|---------|
| `build_threat_model.py` | Module threat model (service type, attacker model, entry points, programmatic hints) |
| `prepare_context.py` | Cross-module callgraph JSON for AI agent navigation |
| `gather_logic_hints.py` | Aggregate hints from scan_logic_flaws + scan_api_misuse |
| `scan_logic_flaws.py` | Hint generator: missing return checks, confused deputy, symlink redirect |
| `scan_api_misuse.py` | Hint generator: sensitive API parameter injection (CreateProcess, LoadLibrary, etc.) |

## Reference Materials

| File | Purpose |
|------|---------|
| `reference/vulnerability_patterns.md` | 11 logic vulnerability patterns with decompiled code examples |
| `reference/decompiler_pitfalls.md` | Common Hex-Rays misreadings and assembly verification |

## Architecture

The skill provides context preparation and programmatic hints. The actual
vulnerability detection is performed by the `logic-scanner` agent (defined in
`.agent/agents/logic-scanner.md`) which reads the callgraph JSON, considers
the programmatic hints, and retrieves function code on demand via
`extract_function_data.py`.

See [SKILL.md](SKILL.md) for full documentation.
