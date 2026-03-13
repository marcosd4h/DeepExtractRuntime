---
name: rpc-interface-analysis
description: >
  Analyze RPC interfaces in Windows binaries using ground-truth extraction data,
  C# client stub signatures, and procedure semantic classification. Use when the
  user asks about RPC interfaces, RPC attack surface, RPC security, RPC
  procedures, blast-radius, RPC topology, parameter types, or needs to audit
  RPC handlers.
cacheable: false
depends_on: []
---

# RPC Interface Analysis

## Purpose

Query and analyze RPC (Remote Procedure Call) interfaces registered in Windows
system binaries.  Uses a pre-built index of NtApiDotNet-extracted RPC data that
maps every binary to its interfaces, procedure names, endpoint protocols,
service associations, and NDR complex types.  Optionally enriches with C#
client stub parameter signatures and procedure semantic classification.

## When to Use

- Enumerate RPC interfaces in a module or system-wide
- Map the RPC attack surface ranked by risk tier
- Audit RPC handler security (missing impersonation, missing auth)
- Trace RPC handler data flow to dangerous sinks
- Analyze blast-radius of co-hosted interfaces in shared processes
- View typed parameter signatures from C# client stubs
- Build client-server topology graphs

## When NOT to Use

- General function explanation -- use **re-analyst**
- COM interface reconstruction -- use **com-interface-reconstruction**
- Non-RPC attack surface mapping -- use **map-attack-surface**

## Data Sources

- **RPC index** (`helpers/rpc_index.py`): Singleton loaded from
  `config/assets/rpc_data/rpc_servers.json` (binary-keyed; contains
  interface metadata, endpoints, file info, and procedure lists per binary).
- **C# client stubs** (`config/assets/rpc_data/rpc_clients_26200_7840/*.cs`): 414
  auto-generated client stubs with typed procedure signatures.
- **Per-module analysis DB**: Decompiled code for RPC handler functions.

## Scripts

### `resolve_rpc_interface.py` (Start Here)

List all RPC interfaces for a module with full metadata and optional stub
signatures. Use `--workspace` to discover which workspace modules implement
RPC interfaces.

```bash
python .agent/skills/rpc-interface-analysis/scripts/resolve_rpc_interface.py appinfo.dll
python .agent/skills/rpc-interface-analysis/scripts/resolve_rpc_interface.py appinfo.dll --json
python .agent/skills/rpc-interface-analysis/scripts/resolve_rpc_interface.py spoolsv.exe --with-stubs --json
python .agent/skills/rpc-interface-analysis/scripts/resolve_rpc_interface.py --workspace --json
```

### `map_rpc_surface.py`

Risk-ranked RPC attack surface, per module or system-wide.  Includes optional
blast-radius analysis. Use `--system-wide` to rank the full RPC index. This
script does **not** support `--workspace` -- to discover which workspace modules
implement RPC interfaces, use `resolve_rpc_interface.py --workspace` above.

```bash
python .agent/skills/rpc-interface-analysis/scripts/map_rpc_surface.py appinfo.dll --json
python .agent/skills/rpc-interface-analysis/scripts/map_rpc_surface.py --system-wide --top 20
python .agent/skills/rpc-interface-analysis/scripts/map_rpc_surface.py --system-wide --with-blast-radius --json
```

### `audit_rpc_security.py`

RPC-specific security audit combining index data with decompiled code.

```bash
python .agent/skills/rpc-interface-analysis/scripts/audit_rpc_security.py <db_path> --json
```

### `trace_rpc_chain.py`

Trace an RPC handler's data flow from NDR dispatch to dangerous sinks.

```bash
python .agent/skills/rpc-interface-analysis/scripts/trace_rpc_chain.py <db_path> --function <func_name> --json
```

### `find_rpc_clients.py`

Find all modules that implement or consume a given RPC interface UUID.
Falls back to C# stub data when no runtime clients are present.

```bash
python .agent/skills/rpc-interface-analysis/scripts/find_rpc_clients.py <interface_uuid> --json
```

### `rpc_topology.py`

Build a system-wide or per-module RPC client-server topology graph combining
pipe name extraction, ALPC endpoints, stub metadata, and service grouping.

```bash
python .agent/skills/rpc-interface-analysis/scripts/rpc_topology.py --json
python .agent/skills/rpc-interface-analysis/scripts/rpc_topology.py spoolsv.exe --json
python .agent/skills/rpc-interface-analysis/scripts/rpc_topology.py --top 20 --json
```

## Direct Helper Module Access

- `helpers.rpc_index.get_rpc_index()` -- cached singleton RPC index
- `helpers.rpc_index.RpcIndex.compute_blast_radius(uuid)` -- co-hosted interfaces
- `helpers.rpc_index.RpcIndex.cross_reference_strings(strings)` -- string-to-RPC matching
- `helpers.rpc_index.RpcIndex.get_procedure_signatures(uuid)` -- stub signatures
- `helpers.rpc_stub_parser.parse_stub_file(path)` -- parse a single stub
- `helpers.rpc_procedure_classifier.classify_procedure(name)` -- semantic classification

## Workflows

### Module RPC Enumeration

1. Run `resolve_rpc_interface.py <module>` to list all interfaces.
2. Run `map_rpc_surface.py <module>` to rank by risk.

### RPC Security Audit

1. Run `resolve_rpc_interface.py <module>` for interface context.
2. Run `audit_rpc_security.py <db_path>` to check security patterns.
3. Run `trace_rpc_chain.py <db_path> --function <handler>` for high-risk handlers.

### System-Wide Surface

1. Run `map_rpc_surface.py --system-wide --top 30` for global ranking.

### Blast-Radius Analysis

1. Run `map_rpc_surface.py --system-wide --with-blast-radius --json` for
   co-hosted interface impact across all services.

### Client-Server Topology

1. Run `rpc_topology.py --json` for the full system topology.

## Integration with Other Skills

| Task | Recommended Skill |
|------|------------------|
| Decompiled code for RPC handlers | decompiled-code-extractor |
| Entry point ranking including RPC | map-attack-surface |
| Cross-module call graph with RPC edges | callgraph-tracer |
| Taint analysis through RPC handlers | taint-analysis |

## Performance

| Operation | Typical Time | Notes |
|-----------|-------------|-------|
| RPC index load | ~1-2s | Cached after first load |
| Stub directory parse (414 files) | ~3-5s | Only when `load_stubs` is true |
| Per-module interface resolve | <100ms | Index lookup |
| System-wide surface ranking | <200ms | Full index scan |
| Blast-radius computation | <50ms | Per-UUID service/module lookup |

## Error Handling

- If the RPC index is not loaded (files missing or `rpc.enabled` is false),
  scripts degrade gracefully with an informative message.
- Module-specific commands require either a module name or DB path.
- Stub queries return empty results when stubs are not loaded.
