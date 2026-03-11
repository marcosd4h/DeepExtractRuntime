---
name: winrt-interface-analysis
description: >
  Analyze WinRT server interfaces in Windows binaries using ground-truth
  extraction data across four access contexts (caller integrity level x
  server privilege). Use when the user asks about WinRT servers, WinRT
  attack surface, WinRT security, WinRT privilege escalation, WinRT
  method signatures, WinRT entry points, or needs to audit WinRT
  activation servers.
cacheable: false
depends_on: []
---

# WinRT Interface Analysis

## Purpose

Query and analyze WinRT (Windows Runtime) server registrations extracted
from Windows system binaries. Uses pre-built extraction data that maps
every binary to its WinRT activation classes, interface methods, pseudo-IDL
definitions, trust levels, SDDL permissions, server identities, and
activation types. The unique value is **privilege-boundary risk scoring**
across four access contexts defined by caller integrity level and server
process privilege.

## When to Use

- Enumerate WinRT classes and interfaces in a module
- Map the WinRT attack surface ranked by privilege-boundary risk
- Find privilege escalation targets (medium-IL caller to SYSTEM server)
- Classify WinRT entry points by semantic category
- Audit WinRT server security (permissive SDDL, SYSTEM identity, BaseTrust)
- Confirm decompiled functions are WinRT entry points
- View pseudo-IDL interface definitions

## When NOT to Use

- General function explanation -- use **re-analyst**
- COM interface reconstruction from vtable patterns -- use **com-interface-reconstruction**
- RPC interface analysis -- use **rpc-interface-analysis**
- Non-WinRT attack surface mapping -- use **map-attack-surface**

## Data Sources

- **WinRT index** (`helpers/winrt_index.py`): Singleton loaded from
  `config/assets/winrt_data/` across four access contexts.
- **Access contexts** (caller IL x server privilege):
  - `extracted_high_il/all_servers` -- high-IL caller, elevated + regular processes
  - `extracted_high_il/privileged_servers` -- high-IL caller, privileged processes (SYSTEM/high)
  - `extracted_medium_il/medium_il/all_servers` -- medium-IL caller, elevated + regular processes
  - `extracted_medium_il/medium_il/privileged_servers` -- medium-IL caller, privileged processes (SYSTEM/high)
- **Per-context file**: `winrt_servers.json` (binary-keyed; contains server metadata,
  interfaces, methods, pseudo-IDL, and procedure lists per binary).
- **Per-module analysis DB**: Decompiled code for WinRT handler functions.

## Scripts

### `resolve_winrt_server.py` (Start Here)

List all WinRT server classes for a module with full metadata.

```bash
python .agent/skills/winrt-interface-analysis/scripts/resolve_winrt_server.py TaskFlowDataEngine.dll
python .agent/skills/winrt-interface-analysis/scripts/resolve_winrt_server.py TaskFlowDataEngine.dll --json
python .agent/skills/winrt-interface-analysis/scripts/resolve_winrt_server.py TaskFlowDataEngine.dll --context medium_il_privileged --json
```

### `map_winrt_surface.py`

Risk-ranked WinRT attack surface, per module or system-wide.

```bash
python .agent/skills/winrt-interface-analysis/scripts/map_winrt_surface.py --system-wide --top 20
python .agent/skills/winrt-interface-analysis/scripts/map_winrt_surface.py --system-wide --tier critical --json
python .agent/skills/winrt-interface-analysis/scripts/map_winrt_surface.py --privileged-only --context medium_il_privileged --json
```

### `enumerate_winrt_methods.py`

List methods for a class or module, optionally with pseudo-IDL.

```bash
python .agent/skills/winrt-interface-analysis/scripts/enumerate_winrt_methods.py TaskFlowDataEngine.dll --json
python .agent/skills/winrt-interface-analysis/scripts/enumerate_winrt_methods.py Windows.Internal.Data.Activities.ActivityImageManager --show-pseudo-idl
```

### `classify_winrt_entrypoints.py`

Semantic classification of WinRT method names into functional categories.

```bash
python .agent/skills/winrt-interface-analysis/scripts/classify_winrt_entrypoints.py TaskFlowDataEngine.dll --json
python .agent/skills/winrt-interface-analysis/scripts/classify_winrt_entrypoints.py --system-wide --json
```

### `audit_winrt_security.py`

Security audit combining WinRT metadata with decompiled code analysis.

```bash
python .agent/skills/winrt-interface-analysis/scripts/audit_winrt_security.py <db_path> --json
```

### `find_winrt_privesc.py`

Find privilege escalation targets: medium-IL reachable SYSTEM servers.

```bash
python .agent/skills/winrt-interface-analysis/scripts/find_winrt_privesc.py --json
python .agent/skills/winrt-interface-analysis/scripts/find_winrt_privesc.py --top 20 --json
```

## Direct Helper Module Access

- `helpers.winrt_index.get_winrt_index()` -- cached singleton WinRT index
- `helpers.winrt_index.WinrtIndex.get_servers_for_module(name)` -- servers by binary
- `helpers.winrt_index.WinrtIndex.is_winrt_procedure(module, func)` -- entry point confirmation
- `helpers.winrt_index.WinrtIndex.get_privileged_surface(caller_il)` -- EoP targets
- `helpers.winrt_index.WinrtIndex.search_methods(pattern)` -- regex search

## Workflows

### Module WinRT Enumeration

1. Run `resolve_winrt_server.py <module>` to list all server classes.
2. Run `map_winrt_surface.py <module>` to rank by risk.

### Privilege Escalation Analysis

1. Run `find_winrt_privesc.py --top 20 --json` for top EoP targets.
2. Run `enumerate_winrt_methods.py <class> --show-pseudo-idl` for method details.
3. Run `audit_winrt_security.py <db_path>` for security findings.

### System-Wide Surface

1. Run `map_winrt_surface.py --system-wide --top 30` for global ranking.
2. Run `classify_winrt_entrypoints.py --system-wide --json` for category breakdown.

## Integration with Other Skills

| Task | Recommended Skill |
|------|------------------|
| Decompiled code for WinRT handlers | decompiled-code-extractor |
| Entry point ranking including WinRT | map-attack-surface |
| COM interface details for WinRT classes | com-interface-reconstruction |

## Performance

| Operation | Typical Time | Notes |
|-----------|-------------|-------|
| WinRT index load | ~2-4s | Loads all 4 contexts; cached after first load |
| Per-module server resolve | <100ms | Index lookup |
| System-wide surface ranking | <500ms | Full index scan |
| Privilege escalation scan | <300ms | Filtered + scored |

## Error Handling

- If the WinRT index is not loaded (files missing or `winrt.enabled` is false),
  scripts exit with an informative message.
- Module-specific commands require either a module name or DB path.
- Pseudo-IDL is omitted silently when PseudoInterfaces data is absent.

## Degradation Paths

1. **WinRT data root missing**: Report the missing path. Suggest checking
   `winrt.data_root` in `config/defaults.json` (default: `config/assets/winrt_data`).
2. **One or more access contexts missing**: Load available contexts, log
   warning for missing ones. Analysis continues with partial data.
3. **Analysis DB unavailable** (for `audit_winrt_security.py`): Fall back
   to metadata-only audit using WinRT index data.
