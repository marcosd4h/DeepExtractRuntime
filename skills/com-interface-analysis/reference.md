# COM Interface Analysis -- Technical Reference

## Data Model

### ComServer Record

| Field | Type | Description |
|-------|------|-------------|
| `name` | str | COM class display name |
| `clsid` | str | Class ID GUID |
| `hosting_binary` | str | Binary filename hosting this server |
| `server_type` | str | InProcServer32, LocalServer32, etc. |
| `service_name` | str? | Windows service name (if service-hosted) |
| `service_user` | str? | Service account (e.g. LocalSystem) |
| `run_as` | str? | RunAs identity override |
| `can_elevate` | bool | CanElevate moniker support |
| `auto_elevation` | bool | AutoElevation registry flag |
| `supports_remote_activation` | bool | DCOM remote activation enabled |
| `trusted_marshaller` | bool | Trusted marshaller flag |
| `has_permissive_launch` | bool | Launch SDDL grants wide access |
| `has_permissive_access` | bool | Access SDDL grants wide access |
| `has_low_il_access` | bool | Accessible from low integrity |
| `has_low_il_launch` | bool | Launchable from low integrity |
| `service_protection_level` | int | 0 = unprotected |
| `runs_as_system` | bool | Service runs as LocalSystem |
| `is_out_of_process` | bool | OOP server (LocalServer32) |
| `is_service` | bool | Hosted in a Windows service |
| `access_contexts` | set | Which access contexts include this server |
| `interfaces` | list[ComInterface] | Interfaces exposed by this server |
| `method_count` | int | Total methods across all interfaces |
| `best_risk_tier` | str | Highest risk tier across all access contexts |

### ComInterface / ComMethod

| Field | Type | Description |
|-------|------|-------------|
| `name` | str | Interface name (e.g. IUpdate3) |
| `guid` | str? | Interface IID GUID |
| `methods` | list[ComMethod] | Methods on this interface |
| `pseudo_idl` | list[str]? | Pseudo-IDL definition lines |
| `method.short_name` | str | Unqualified method name |
| `method.binary_name` | str | Full mangled/binary name |
| `method.access` | str | Access level (public/private) |
| `method.interface_name` | str | Parent interface name |

### Access Contexts

| Context Key | Caller IL | Server Privilege |
|-------------|-----------|-----------------|
| `high_il_all` | high | elevated + regular |
| `high_il_privileged` | high | SYSTEM/high only |
| `medium_il_all` | medium | elevated + regular |
| `medium_il_privileged` | medium | SYSTEM/high only |

## Output Schemas

### resolve_com_server.py

```json
{ "status": "ok", "target": "<module_or_clsid>", "scope": "module|clsid",
  "server_count": N, "total_methods": N,
  "servers": [{ ...ComServer.to_dict(), "risk_tier": "..." }] }
```

### map_com_surface.py

```json
{ "status": "ok", "scope": "<module|system_wide>", "total_servers": N,
  "by_tier": { "critical": N, "high": N, "medium": N, "low": N },
  "servers": [{ ...ComServer.to_dict() }] }
```

### enumerate_com_methods.py

```json
{ "status": "ok", "target": "<module_or_clsid>", "scope": "module|clsid",
  "total_interfaces": N, "total_methods": N,
  "interfaces": [{ ...ComInterface.to_dict(), "server_name": "...", "clsid": "..." }] }
```

### classify_com_entrypoints.py

```json
{ "status": "ok", "scope": "<module|system_wide>", "total_methods": N,
  "by_category": { "authentication": N, "file_io": N, ... },
  "categories": { "<category>": [{ "method": "...", "short_name": "...",
    "server_name": "...", "clsid": "...", "binary": "...", "risk_tier": "..." }] } }
```

Semantic categories: `authentication`, `crypto`, `file_io`, `network`, `process`, `registry`, `system_management`, `elevation`, `marshalling`, `data_access`, `event`, `async_operation`, `other`.

### audit_com_security.py

```json
{ "status": "ok", "target": "<module_or_clsid>", "server_count": N,
  "finding_count": N,
  "findings": [{ "severity": "CRITICAL|HIGH|MEDIUM|LOW", "server": "...",
    "clsid": "...", "finding": "...", "detail": "...", "sddl": "..." }] }
```

### find_com_privesc.py

```json
{ "status": "ok", "caller_il": "medium", "total_candidates": N,
  "scored_targets": N,
  "targets": [{ ...ComServer.to_dict(), "privesc_score": 0.0-1.0,
    "has_attack_useful_methods": true, "high_value_methods": [...] }] }
```

## Risk/Scoring Model

### Risk Tiers

Computed per access context from server properties (identity, permissions, elevation).

| Tier | Criteria |
|------|----------|
| critical | SYSTEM service reachable from medium-IL |
| high | Elevation/auto-elevation, permissive SDDL, remote activation |
| medium | Trusted marshaller, low service protection, low-IL access |
| low | Default; no privilege boundary crossings |

### Privilege Escalation Score (find_com_privesc.py)

| Factor | Weight | Condition |
|--------|--------|-----------|
| SYSTEM identity | +0.30 | `runs_as_system` |
| Out-of-process | +0.15 | `is_out_of_process` |
| Elevation capable | +0.15 | `can_elevate` or `auto_elevation` |
| Permissive launch | +0.10 | `has_permissive_launch` |
| Permissive access | +0.10 | `has_permissive_access` |
| Remote activation | +0.05 | `supports_remote_activation` |
| Trusted marshaller | +0.05 | `trusted_marshaller` |
| High-value methods | +0.10 | Ratio of methods matching attack-useful patterns |

Servers exposing only IUnknown trivial methods (QI/AddRef/Release) score 0.

## Error Handling

| Condition | Behavior |
|-----------|----------|
| COM index not loaded | `emit_error()` with `NOT_FOUND`; suggests checking `com.data_root` |
| Missing access context | Loads available contexts; logs warning for missing ones |
| Module not found in index | Returns empty server list (no error) |
| CLSID not found | Returns empty server list |
| No interfaces on server | Server metadata returned; methods list empty |
| Pseudo-IDL absent | Omitted silently from output |
