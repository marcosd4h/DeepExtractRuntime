# WinRT Analysis

## Overview

Analyze WinRT server interfaces in Windows binaries using ground-truth extraction data. Enumerates server classes, maps the privilege-boundary attack surface, audits security properties, classifies entry points, and identifies privilege escalation targets.

The text after `/winrt` is the **module name** and optional **subcommand** (e.g., `/winrt TaskFlowDataEngine.dll`, `/winrt surface`, `/winrt privesc`).

### Subcommands

| Subcommand | Usage | Purpose |
|------------|-------|---------|
| *(default)* | `/winrt <module>` | Enumerate WinRT server classes, interfaces, methods |
| `surface` | `/winrt surface [module]` | Risk-ranked WinRT attack surface (module or system-wide) |
| `methods` | `/winrt methods <module_or_class>` | List methods with optional pseudo-IDL |
| `classify` | `/winrt classify <module>` | Semantic classification of WinRT entry points |
| `audit` | `/winrt audit <module>` | WinRT-specific security audit |
| `privesc` | `/winrt privesc [--top N]` | Find privilege escalation targets |

## IMPORTANT: Execution Model

Execute immediately. Do NOT ask for confirmation before running scripts. Read the **winrt-interface-analysis** SKILL.md to understand available scripts and their options, then run the appropriate script(s) for the subcommand.

## Execution Context

- **Working directory**: Workspace root (scripts handle their own path setup)
- **Output**: Scripts support `--json` for machine-readable output
- **Data**: Read-only access to WinRT extraction data via `helpers.winrt_index`

## Steps

### Step 0: Preflight Validation

Parse the user's input to determine the subcommand and target. If a module name is given, verify it exists in the WinRT index by running:

```bash
python .agent/skills/winrt-interface-analysis/scripts/resolve_winrt_server.py <module> --json
```

If no servers are found, report this and suggest checking module name spelling or using `surface --system-wide` to see all available modules.

### Step 1: Subcommand Dispatch

Based on the parsed subcommand:

**Default (module enumeration):**
```bash
python .agent/skills/winrt-interface-analysis/scripts/resolve_winrt_server.py <module> --json
```

**Surface:**
```bash
python .agent/skills/winrt-interface-analysis/scripts/map_winrt_surface.py <module> --json
python .agent/skills/winrt-interface-analysis/scripts/map_winrt_surface.py --system-wide --top 30 --json
```

**Methods:**
```bash
python .agent/skills/winrt-interface-analysis/scripts/enumerate_winrt_methods.py <module_or_class> --show-pseudo-idl --json
```

**Classify:**
```bash
python .agent/skills/winrt-interface-analysis/scripts/classify_winrt_entrypoints.py <module> --json
```

**Audit:**
1. Resolve the module to its analysis DB using `find_module_db.py`.
2. Run:
```bash
python .agent/skills/winrt-interface-analysis/scripts/audit_winrt_security.py <db_path> --json
```

**Privesc:**
```bash
python .agent/skills/winrt-interface-analysis/scripts/find_winrt_privesc.py --top 20 --json
```

### Step 2: Synthesis

Present the results in a structured format:
- For enumeration: table of server classes with risk tier, activation type, method count
- For surface: ranked list with risk tiers and counts
- For methods: interface list with method names and pseudo-IDL
- For classification: category breakdown with counts and examples
- For audit: severity-ordered findings with recommendations
- For privesc: ranked targets with EoP scores and high-value methods

Suggest concrete follow-up commands based on results (e.g., `/audit` for high-risk servers, `/explain` for interesting methods).

## Output Format

Structured markdown with tables for enumeration, ranked lists for surface/privesc, and severity-ordered findings for audit. Always include:
- Scope (module or system-wide)
- Total counts (servers, methods, findings)
- Risk tier distribution
- Top recommendations for next steps

## Skills Used

- **winrt-interface-analysis**: All subcommands
- **decompiled-code-extractor**: For `audit` subcommand (resolve module DB)
- **map-attack-surface**: Cross-reference WinRT entry points with attack surface ranking

## Error Handling

| Failure | Recovery |
|---------|----------|
| Module not found in WinRT index | List modules with WinRT servers, suggest closest match |
| WinRT index not loaded | Report missing data, suggest checking `winrt.data_root` config |
| Analysis DB not found (audit) | Fall back to metadata-only audit using WinRT index |
| No servers found | Report clearly, suggest `surface --system-wide` |
