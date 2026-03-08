# deep-context-builder

Structured methodology for building deep understanding of IDA Pro
decompiled functions before vulnerability hunting. Forces block-by-block
analysis with First Principles, 5 Whys, and 5 Hows to reduce
hallucinations and missed assumptions.

## When to Use

- Before auditing a complex decompiled function
- When shallow analysis led to hallucinated or missed findings
- Understanding a Windows service, COM component, or RPC handler architecture

## How It Works

Three-phase approach:

1. **Initial Orientation**: Map the module structure, entry points,
   globals, and function groups using classify-functions and
   map-attack-surface.

2. **Ultra-Granular Function Analysis**: Block-by-block analysis of
   decompiled code with IDA artifact recognition, invariant tracking,
   assumption documentation, and cross-function flow analysis.

3. **Global System Understanding**: Connect individual function analyses
   into system-level workflows, trust boundaries, and fragility clusters.

## Key Principles

- Decompiled code is an approximation -- verify against assembly
- Never reshape evidence to fit earlier assumptions
- Use "unclear; need to inspect X" instead of "it probably..."
- Treat external DLL calls as adversarial until proven otherwise

## Integration

This is a methodology skill with no scripts. It directs the agent to
use existing skills for data extraction and teaches analysis methodology.

| Phase | Primary Skills |
|-------|---------------|
| Orientation | classify-functions, map-attack-surface, data-flow-tracer |
| Function analysis | decompiled-code-extractor, verify-decompiled |
| System understanding | callgraph-tracer, security-dossier |

## Usage in Commands

Wired into `/explain` (for deep comprehension) and `/audit` (for
pre-audit context building).

## Files

| File | Purpose |
|------|---------|
| `SKILL.md` | Full methodology with 3-phase workflow |
| `reference.md` | Microstructure checklist, IDA artifacts, completeness checklist, output template |
| `README.md` | This file |

## Related Skills

- [analyze-ida-decompiled](../analyze-ida-decompiled/) -- IDA naming patterns
- [adversarial-reasoning](../adversarial-reasoning/) -- runs after context building
- [security-dossier](../security-dossier/) -- factual security data gathering
