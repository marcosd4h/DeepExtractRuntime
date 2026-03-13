---
name: com-interface-analysis
description: >
  Analyze COM server interfaces in Windows binaries using ground-truth
  extraction data across four access contexts (caller integrity level x
  server privilege). Use when the user asks about COM servers, COM
  attack surface, COM security, COM privilege escalation, COM entry
  points, DCOM, UAC bypass via COM, CLSID lookup, COM activation,
  COM service identity, or needs to audit COM server permissions.
cacheable: false
depends_on: []
---

# COM Interface Analysis

## Purpose

Query and analyze COM (Component Object Model) server registrations extracted
from Windows system binaries. Uses pre-built extraction data that maps
every binary to its COM CLSIDs, interface methods, pseudo-IDL
definitions, SDDL permissions, service identities, elevation flags,
and activation types. The unique value is **privilege-boundary risk scoring**
and **elevation/UAC analysis** across four access contexts defined by
caller integrity level and server process privilege.

## When to Use

- Enumerate COM servers and interfaces in a module
- Look up a CLSID to find its hosting binary and security properties
- Map the COM attack surface ranked by privilege-boundary risk
- Find privilege escalation targets (medium-IL caller to SYSTEM server)
- Identify UAC bypass candidates (CanElevate/AutoElevation servers)
- Classify COM entry points by semantic category
- Audit COM server security (permissions, elevation, marshalling, DCOM)
- Confirm decompiled functions are COM entry points
- View pseudo-IDL interface definitions

## When NOT to Use

- General function explanation -- use **re-analyst**
- COM interface reconstruction from vtable patterns in decompiled code -- use **com-interface-reconstruction**
- WinRT server analysis -- use **winrt-interface-analysis**
- RPC interface analysis -- use **rpc-interface-analysis**
- Non-COM attack surface mapping -- use **map-attack-surface**

## Data Sources

- **COM index** (`helpers/com_index.py`): Singleton loaded from
  `config/assets/com_data/` across four access contexts.
- **Access contexts** (caller IL x server privilege):
  - `extracted_high_il/all_servers` -- high-IL caller, elevated + regular processes
  - `extracted_high_il/privileged_servers` -- high-IL caller, privileged processes (SYSTEM/high)
  - `extracted_medium_il/medium_il/all_servers` -- medium-IL caller, elevated + regular processes
  - `extracted_medium_il/medium_il/privileged_servers` -- medium-IL caller, privileged processes (SYSTEM/high)
- **Per-context file**: `com_servers.json` (binary-keyed; contains server metadata,
  interfaces, methods, pseudo-IDL, typelib interfaces, and procedure lists per binary).

## Scripts

### `resolve_com_server.py` (Start Here)

List all COM servers for a module or look up by CLSID with full metadata.
Use `--workspace` to discover which workspace modules implement COM servers.

```bash
python .agent/skills/com-interface-analysis/scripts/resolve_com_server.py wuapi.dll --json
python .agent/skills/com-interface-analysis/scripts/resolve_com_server.py bfe18e9c-6d87-4450-b37c-e02f0b373803 --json
python .agent/skills/com-interface-analysis/scripts/resolve_com_server.py wbengine.exe --context medium_il_privileged --json
python .agent/skills/com-interface-analysis/scripts/resolve_com_server.py --workspace --json
```

### `map_com_surface.py`

Risk-ranked COM attack surface, per module or system-wide. Use `--system-wide`
to rank the full COM index. This script does **not** support `--workspace` --
to discover which workspace modules implement COM servers, use
`resolve_com_server.py --workspace` above instead.

```bash
python .agent/skills/com-interface-analysis/scripts/map_com_surface.py --system-wide --top 20
python .agent/skills/com-interface-analysis/scripts/map_com_surface.py --system-wide --tier critical --json
python .agent/skills/com-interface-analysis/scripts/map_com_surface.py --privileged-only --context medium_il_privileged --json
```

### `enumerate_com_methods.py`

List methods for a CLSID or module, optionally with pseudo-IDL.

```bash
python .agent/skills/com-interface-analysis/scripts/enumerate_com_methods.py wuapi.dll --json
python .agent/skills/com-interface-analysis/scripts/enumerate_com_methods.py bfe18e9c-6d87-4450-b37c-e02f0b373803 --show-pseudo-idl
```

### `classify_com_entrypoints.py`

Semantic classification of COM method names into functional categories.

```bash
python .agent/skills/com-interface-analysis/scripts/classify_com_entrypoints.py wuapi.dll --json
python .agent/skills/com-interface-analysis/scripts/classify_com_entrypoints.py --system-wide --json
```

### `audit_com_security.py`

Security audit: permissions, elevation, identity, marshalling, DCOM exposure.

```bash
python .agent/skills/com-interface-analysis/scripts/audit_com_security.py wuapi.dll --json
python .agent/skills/com-interface-analysis/scripts/audit_com_security.py bfe18e9c-6d87-4450-b37c-e02f0b373803 --json
```

### `find_com_privesc.py`

Find privilege escalation targets: medium-IL reachable SYSTEM servers.

```bash
python .agent/skills/com-interface-analysis/scripts/find_com_privesc.py --json
python .agent/skills/com-interface-analysis/scripts/find_com_privesc.py --top 20 --json
python .agent/skills/com-interface-analysis/scripts/find_com_privesc.py --include-uac --json
```

## Direct Helper Module Access

- `helpers.com_index.get_com_index()` -- cached singleton COM index
- `helpers.com_index.ComIndex.get_servers_for_module(name)` -- servers by binary
- `helpers.com_index.ComIndex.get_server_by_clsid(clsid)` -- direct CLSID lookup
- `helpers.com_index.ComIndex.is_com_procedure(module, func)` -- entry point confirmation
- `helpers.com_index.ComIndex.get_privileged_surface(caller_il)` -- EoP targets
- `helpers.com_index.ComIndex.get_elevatable_servers()` -- UAC bypass candidates
- `helpers.com_index.ComIndex.search_methods(pattern)` -- regex search

## Workflows

### Module COM Enumeration

1. Run `resolve_com_server.py <module>` to list all COM servers.
2. Run `map_com_surface.py <module>` to rank by risk.

### Privilege Escalation Analysis

1. Run `find_com_privesc.py --top 20 --json` for top EoP targets.
2. Run `enumerate_com_methods.py <clsid> --show-pseudo-idl` for method details.
3. Run `audit_com_security.py <clsid>` for security findings.

### UAC Bypass Candidate Discovery

1. Run `find_com_privesc.py --include-uac --json` for elevation-capable servers.
2. Run `audit_com_security.py <clsid>` to check elevation and permission details.

### System-Wide Surface

1. Run `map_com_surface.py --system-wide --top 30` for global ranking.
2. Run `classify_com_entrypoints.py --system-wide --json` for category breakdown.

## Integration with Other Skills

| Task | Recommended Skill |
|------|------------------|
| Decompiled code for COM handlers | decompiled-code-extractor |
| Entry point ranking including COM | map-attack-surface |
| COM interface details from vtables | com-interface-reconstruction |
| WinRT server analysis | winrt-interface-analysis |
| RPC interface analysis | rpc-interface-analysis |

## Performance

| Operation | Typical Time | Notes |
|-----------|-------------|-------|
| COM index load | ~3-6s | Loads all 4 contexts; cached after first load |
| Per-module server resolve | <100ms | Index lookup |
| System-wide surface ranking | <500ms | Full index scan |
| Privilege escalation scan | <300ms | Filtered + scored |

## Error Handling

- If the COM index is not loaded (files missing or `com.enabled` is false),
  scripts exit with an informative message.
- Module-specific commands accept either a module name or CLSID.
- Pseudo-IDL is omitted silently when PseudoInterfaces data is absent.

## Degradation Paths

1. **COM data root missing**: Report the missing path. Suggest checking
   `com.data_root` in `config/defaults.json` (default: `config/assets/com_data`).
2. **One or more access contexts missing**: Load available contexts, log
   warning for missing ones. Analysis continues with partial data.
3. **No interfaces on server**: Server metadata is still available for
   security audit; interface/method enumeration returns empty.
