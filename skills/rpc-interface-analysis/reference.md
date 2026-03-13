# RPC Interface Analysis -- Technical Reference

## Data Model

### RpcInterface Record

| Field | Type | Description |
|-------|------|-------------|
| `interface_id` | str | Interface UUID |
| `interface_version` | str | Major.minor version string |
| `binary_name` | str | Hosting binary filename |
| `risk_tier` | str | critical, high, medium, or low |
| `protocols` | set[str] | Transport protocols (ncacn_np, ncalrpc, ncacn_ip_tcp, etc.) |
| `endpoints` | list[str] | Registered endpoint strings |
| `service_name` | str? | Windows service name |
| `service_display_name` | str? | Human-readable service name |
| `is_service_running` | bool | Whether the host service is running |
| `is_client` | bool | Whether this is a client-side interface |
| `procedure_count` | int | Number of RPC procedures |
| `procedure_names` | list[str] | Procedure name list |
| `has_complex_types` | bool | Whether NDR complex types are present |
| `complex_types` | list[str] | NDR type names |

### Procedure Signature (from C# stubs)

| Field | Type | Description |
|-------|------|-------------|
| `opnum` | int | Operation number |
| `name` | str | Procedure name |
| `return_type` | str | Return type (e.g. int, void) |
| `parameters` | list | Parameter list with direction, NDR type, and name |
| `parameter.direction` | str | In, Out, or InOut |
| `parameter.ndr_type` | str | NDR wire type |
| `parameter.name` | str | Parameter name |

### Procedure Classification

Semantic categories assigned by `rpc_procedure_classifier`:

| Category | Pattern Examples |
|----------|-----------------|
| authentication | Auth, Login, Credential, Token |
| file_io | File, Read, Write, Open, Create |
| process | Process, Launch, Execute, Spawn |
| registry | Registry, RegKey |
| network | Network, Socket, Connect |
| crypto | Crypt, Encrypt, Hash, Sign |
| system_management | Update, Install, Config, Policy |
| data_access | Get, Set, Query, Enum, List |
| event | Event, Notify, Callback |

### Blast-Radius Model

Co-hosted interfaces share a process; compromising one exposes all siblings.

| Field | Type | Description |
|-------|------|-------------|
| `found` | bool | Whether the interface was located |
| `service_name` | str | Shared service name |
| `sibling_count` | int | Number of co-hosted interfaces |
| `total_procedures` | int | Total procedures across siblings |
| `combined_protocols` | list[str] | Union of all sibling protocols |
| `siblings` | list[dict] | Interface UUID and procedure count per sibling |

## Output Schemas

### resolve_rpc_interface.py

```json
{ "status": "ok", "module": "appinfo.dll",
  "interface_count": N, "total_procedures": N,
  "interfaces": [{ ...RpcInterface.to_dict(),
    "stub_signatures": [{ "opnum": N, "name": "...", "return_type": "...",
      "parameters": [{ "direction": "In", "ndr_type": "...", "name": "..." }] }] }],
  "all_procedures": ["proc1", "proc2", ...] }
```

### resolve_rpc_interface.py --workspace

```json
{ "status": "ok",
  "workspace_modules": ["mod1.dll", "mod2.dll", ...],
  "rpc": { "<module>": { "interface_count": N,
    "interfaces": [{ "uuid": "...", "version": "...", "procedure_count": N,
      "procedure_names": [...], "risk_tier": "...", "is_remote_reachable": bool,
      "service_name": "...", "pipe_names": [...] }] } },
  "summary": { "total_workspace_modules": N, "rpc_modules": N } }
```

The module list key is **`workspace_modules`** (not `modules`).

### map_rpc_surface.py

```json
{ "status": "ok", "scope": "<module|system_wide>",
  "total_interfaces": N,
  "by_tier": { "critical": N, "high": N, "medium": N, "low": N },
  "interfaces": [{ ...RpcInterface.to_dict(),
    "blast_radius": { "found": true, "sibling_count": N, ... } }] }
```

### audit_rpc_security.py

```json
{ "status": "ok", "module": "...", "db_path": "...",
  "finding_count": N,
  "findings": [{ "severity": "...", "category": "...",
    "function_name": "...", "detail": "..." }] }
```

### trace_rpc_chain.py

```json
{ "status": "ok", "function": "...",
  "chain": [{ "function": "...", "calls": ["..."], "dangerous_sinks": ["..."] }],
  "dangerous_sink_count": N }
```

### find_rpc_clients.py

```json
{ "status": "ok", "interface_uuid": "...",
  "server_modules": ["..."], "client_modules": ["..."],
  "stub_available": true }
```

### rpc_topology.py

```json
{ "status": "ok", "scope": "<module|system_wide>",
  "nodes": [{ "module": "...", "service": "...", "interfaces": N }],
  "edges": [{ "client": "...", "server": "...", "interface_uuid": "...", "protocol": "..." }],
  "node_count": N, "edge_count": N }
```

## Risk Tier Definitions

| Tier | Criteria |
|------|----------|
| critical | Network-accessible (ncacn_ip_tcp/ncacn_http), running service, high procedure count |
| high | Named-pipe accessible (ncacn_np), running service, or >10 procedures |
| medium | ALPC-only (ncalrpc), moderate procedure count, or stopped service |
| low | No endpoints, client-only, or minimal procedure surface |

Risk tier is a property of `RpcInterface`, computed from protocols, service state, and procedure count.

## Error Handling

| Condition | Behavior |
|-----------|----------|
| RPC index not loaded | `emit_error()` with `NOT_FOUND`; suggests checking `rpc.enabled` |
| Module not found in index | Returns empty interface list |
| Stub directory missing | Stub signatures unavailable; proceeds without them |
| DB path invalid (audit/trace) | `emit_error()` with `NOT_FOUND` |
| Interface UUID not found | Returns empty result |
| Procedure classification miss | Falls back to "other" category |
