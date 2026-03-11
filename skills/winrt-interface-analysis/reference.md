# WinRT Interface Analysis -- Technical Reference

## Data Model

### WinrtServer Record

| Field | Type | Description |
|-------|------|-------------|
| `name` | str | Activation class name (e.g. Windows.Internal.Data.Activities.ActivityImageManager) |
| `hosting_binary` | str | Binary filename hosting this server |
| `activation_type` | str | InProcess, OutOfProcess, etc. |
| `trust_level` | str | BaseTrust, PartialTrust, FullTrust |
| `server_identity` | str? | Server process identity (e.g. LocalSystem) |
| `service_name` | str? | Windows service name (if service-hosted) |
| `runs_as_system` | bool | Server runs as LocalSystem |
| `is_out_of_process` | bool | Out-of-process activation |
| `has_permissive_sddl` | bool | SDDL grants wide access |
| `is_remote_activatable` | bool | Supports remote activation |
| `is_base_trust` | bool | BaseTrust level (lowest restriction) |
| `access_contexts` | set | Which access contexts include this server |
| `interfaces` | list[WinrtInterface] | Interfaces exposed by this server |
| `interface_count` | int | Number of interfaces |
| `method_count` | int | Total methods across all interfaces |
| `best_risk_tier` | str | Highest risk tier across all access contexts |

### WinrtInterface / WinrtMethod

| Field | Type | Description |
|-------|------|-------------|
| `name` | str | Interface name |
| `guid` | str? | Interface GUID |
| `methods` | list[WinrtMethod] | Methods on this interface |
| `pseudo_idl` | list[str]? | Pseudo-IDL definition lines |
| `method.short_name` | str | Unqualified method name |
| `method.binary_name` | str | Full mangled/binary name |
| `method.interface_name` | str | Parent interface name |

### Access Contexts

| Context Key | Caller IL | Server Privilege |
|-------------|-----------|-----------------|
| `high_il_all` | high | elevated + regular |
| `high_il_privileged` | high | SYSTEM/high only |
| `medium_il_all` | medium | elevated + regular |
| `medium_il_privileged` | medium | SYSTEM/high only |

## Output Schemas

### resolve_winrt_server.py

```json
{ "status": "ok", "module": "TaskFlowDataEngine.dll",
  "server_count": N, "total_methods": N,
  "servers": [{ ...WinrtServer.to_dict(), "risk_tier": "..." }] }
```

### map_winrt_surface.py

```json
{ "status": "ok", "scope": "<module|system_wide>", "total_servers": N,
  "by_tier": { "critical": N, "high": N, "medium": N, "low": N },
  "servers": [{ ...WinrtServer.to_dict() }] }
```

### enumerate_winrt_methods.py

```json
{ "status": "ok", "target": "<module_or_class>", "scope": "module|class",
  "total_interfaces": N, "total_methods": N,
  "interfaces": [{ ...WinrtInterface.to_dict(), "server_name": "..." }] }
```

### classify_winrt_entrypoints.py

```json
{ "status": "ok", "scope": "<module|system_wide>", "total_methods": N,
  "by_category": { "authentication": N, "file_io": N, ... },
  "categories": { "<category>": [{ "method": "...", "short_name": "...",
    "server_name": "...", "binary": "...", "risk_tier": "..." }] } }
```

### audit_winrt_security.py

```json
{ "status": "ok", "module": "...", "db_path": "...",
  "finding_count": N,
  "findings": [{ "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "server": "...", "finding": "...", "detail": "..." }] }
```

### find_winrt_privesc.py

```json
{ "status": "ok", "caller_il": "medium",
  "total_candidates": N, "scored_targets": N,
  "targets": [{ ...WinrtServer.to_dict(), "privesc_score": 0.0-1.0,
    "high_value_methods": [{ ...WinrtMethod.to_dict() }] }] }
```

## Risk Tier Definitions

Computed per access context from server properties.

| Tier | Criteria |
|------|----------|
| critical | SYSTEM server reachable from medium-IL with permissive SDDL |
| high | SYSTEM identity, out-of-process, or BaseTrust with wide access |
| medium | Partial trust, moderate method count, or non-SYSTEM OOP |
| low | Default; in-process, FullTrust, no privilege boundary |

## Privilege Escalation Score (find_winrt_privesc.py)

| Factor | Weight | Condition |
|--------|--------|-----------|
| SYSTEM identity | +0.30 | `runs_as_system` |
| Out-of-process | +0.15 | `is_out_of_process` |
| Permissive SDDL | +0.10 | `has_permissive_sddl` |
| Remote activatable | +0.05 | `is_remote_activatable` |
| BaseTrust | +0.05 | `is_base_trust` |
| Method surface | +0.10 | `min(method_count / 20, 1.0)` |
| High-value methods | +0.20 | Ratio of methods matching attack patterns |
| Context breadth | +0.05 | `min(access_contexts / 4, 1.0)` |

High-value patterns: launch, execute, create, write, delete, set, put, install, update, register, config, policy, shutdown, reboot, crypt, impersonat, token, credential, elevat.

## Error Handling

| Condition | Behavior |
|-----------|----------|
| WinRT index not loaded | `emit_error()` with `NOT_FOUND`; suggests checking `winrt.data_root` |
| Missing access context | Loads available contexts; logs warning for missing ones |
| Module not found in index | Returns empty server list |
| Analysis DB unavailable (audit) | Falls back to metadata-only audit |
| Pseudo-IDL absent | Omitted silently from output |
| Class name not found | Returns empty server list |
