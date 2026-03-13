# COM Analysis

## Overview

Analyze COM server interfaces in Windows binaries using ground-truth extraction data. Enumerates COM servers by module or CLSID, maps the privilege-boundary attack surface, audits security properties (permissions, elevation, marshalling, DCOM), classifies entry points, and identifies privilege escalation and UAC bypass targets.

The text after `/com` is the **module name or CLSID** and optional **subcommand** (e.g., `/com wuapi.dll`, `/com surface`, `/com privesc`).

### Subcommands

| Subcommand | Usage | Purpose |
|------------|-------|---------|
| *(default)* | `/com <module_or_clsid>` | Enumerate COM servers, interfaces, methods |
| `workspace` | `/com workspace` | Discover which workspace modules implement COM servers |
| `surface` | `/com surface [module]` | Risk-ranked COM attack surface (module or system-wide) |
| `methods` | `/com methods <module_or_clsid>` | List methods with optional pseudo-IDL |
| `classify` | `/com classify <module>` | Semantic classification of COM entry points |
| `audit` | `/com audit <module_or_clsid>` | COM-specific security audit |
| `privesc` | `/com privesc [--top N]` | Find privilege escalation targets |

## IMPORTANT: Execution Model

Execute immediately. Do NOT ask for confirmation before running scripts. Read the **com-interface-analysis** SKILL.md to understand available scripts and their options, then run the appropriate script(s) for the subcommand.

## Execution Context

- **Working directory**: Workspace root (scripts handle their own path setup)
- **Output**: Scripts support `--json` for machine-readable output
- **Data**: Read-only access to COM extraction data via `helpers.com_index`

## Steps

### Step 0: Preflight Validation

Parse the user's input to determine the subcommand and target. If a module name or CLSID is given, verify it exists in the COM index by running:

```bash
python .agent/skills/com-interface-analysis/scripts/resolve_com_server.py <module_or_clsid> --json
```

If no servers are found, report this and suggest checking module name spelling or using `surface --system-wide` to see all available modules.

### Step 1: Subcommand Dispatch

Based on the parsed subcommand:

**Workspace (discovery):**
```bash
python .agent/skills/com-interface-analysis/scripts/resolve_com_server.py --workspace --json
```

Show which workspace modules implement COM servers with access contexts and security metadata. Use this as a discovery step before drilling into a specific module. Only `resolve_com_server.py` supports `--workspace`; do NOT use `--workspace` on `map_com_surface.py` (use `--system-wide` there instead).

**Default (module/CLSID enumeration):**
```bash
python .agent/skills/com-interface-analysis/scripts/resolve_com_server.py <module_or_clsid> --json
```

**Surface:**
```bash
python .agent/skills/com-interface-analysis/scripts/map_com_surface.py <module> --json
python .agent/skills/com-interface-analysis/scripts/map_com_surface.py --system-wide --top 30 --json
```

**Methods:**
```bash
python .agent/skills/com-interface-analysis/scripts/enumerate_com_methods.py <module_or_clsid> --show-pseudo-idl --json
```

**Classify:**
```bash
python .agent/skills/com-interface-analysis/scripts/classify_com_entrypoints.py <module> --json
```

**Audit:**
```bash
python .agent/skills/com-interface-analysis/scripts/audit_com_security.py <module_or_clsid> --json
```

**Privesc:**
```bash
python .agent/skills/com-interface-analysis/scripts/find_com_privesc.py --top 20 --json
```

### Step 2: Synthesis

Present the results in a structured format:
- For enumeration: table of COM servers with CLSID, risk tier, server type, method count
- For surface: ranked list with risk tiers and counts
- For methods: interface list with method names and pseudo-IDL
- For classification: category breakdown with counts and examples
- For audit: severity-ordered findings with recommendations
- For privesc: ranked targets with EoP scores and high-value methods

Suggest concrete follow-up commands based on results (e.g., `/audit` for high-risk servers, `/explain` for interesting methods, `/com audit <clsid>` for detailed security review).

## Output Format

Structured markdown with tables for enumeration, ranked lists for surface/privesc, and severity-ordered findings for audit. Always include:
- Scope (module, CLSID, or system-wide)
- Total counts (servers, methods, findings)
- Risk tier distribution
- Top recommendations for next steps

## Skills Used

- **com-interface-analysis**: All subcommands
- **decompiled-code-extractor**: For cross-referencing with decompiled code
- **map-attack-surface**: Cross-reference COM entry points with attack surface ranking

## Error Handling

| Failure | Recovery |
|---------|----------|
| Module not found in COM index | List modules with COM servers, suggest closest match |
| COM index not loaded | Report missing data, suggest checking `com.data_root` config |
| CLSID not found | Report clearly, suggest `surface --system-wide` to find available servers |
| No servers found | Report clearly, suggest `surface --system-wide` |
