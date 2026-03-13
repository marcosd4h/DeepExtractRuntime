# RPC Analysis

## Overview

Analyze RPC interfaces in Windows binaries using ground-truth NtApiDotNet extraction data. Enumerates interfaces, maps the RPC attack surface, audits security properties, and traces handler call chains.

The text after `/rpc` is the **module name** and optional **subcommand** (e.g., `/rpc appinfo.dll`, `/rpc surface`, `/rpc audit appinfo.dll`).

### Subcommands

| Subcommand | Usage | Purpose |
|------------|-------|---------|
| *(default)* | `/rpc <module>` | Enumerate all RPC interfaces, procedures, endpoints |
| `workspace` | `/rpc workspace` | Discover which workspace modules implement RPC interfaces |
| `surface` | `/rpc surface [module]` | Risk-ranked RPC attack surface (module or system-wide) |
| `audit` | `/rpc audit <module>` | RPC-specific security audit |
| `trace` | `/rpc trace <module> <function>` | Trace RPC handler data flow to sinks |
| `clients` | `/rpc clients <uuid>` | Find modules implementing/consuming a UUID |
| `topology` | `/rpc topology [module]` | System-wide or per-module RPC client-server topology |
| `blast-radius` | `/rpc blast-radius <module or uuid>` | Show co-hosted interface impact analysis |
| `stubs` | `/rpc stubs <uuid>` | Show C# stub parameter signatures for an interface |

## IMPORTANT: Execution Model

**This is an execute-immediately command. Do NOT present anything for user confirmation.** Run the requested analysis and present the report directly.

## Execution Context

> **IMPORTANT**: Skill script invocations like `python .agent/skills/.../script.py` can be run from the workspace root because those scripts manage their own path setup.

## Steps

### Step 0: Preflight Validation

Parse the subcommand and arguments:
- No subcommand + module name -> enumerate interfaces (default)
- `surface` + optional module -> attack surface ranking
- `audit` + module -> security audit (requires DB path)
- `trace` + module + function -> handler chain trace (requires DB path)
- `clients` + UUID -> find modules for interface
- `topology` + optional module -> RPC client-server topology (system-wide or per-module)
- `blast-radius` + module or UUID -> co-hosted interface impact analysis
- `stubs` + UUID -> C# stub parameter signatures for interface

For `audit` and `trace` subcommands, resolve the module name to its analysis DB path using `helpers.command_validation.validate_command_args("rpc", {"module": "<module>"})`.

### Step 1: `/rpc workspace` -- Workspace Discovery

Show which workspace modules implement RPC interfaces with UUIDs, risk tiers, and procedure counts:

```bash
python .agent/skills/rpc-interface-analysis/scripts/resolve_rpc_interface.py --workspace --json
```

Use this as a discovery step before drilling into a specific module. Only `resolve_rpc_interface.py` supports `--workspace`; do NOT use `--workspace` on `map_rpc_surface.py` (use `--system-wide` there instead).

### Step 2: `/rpc <module>` -- Enumerate Interfaces

Use the **rpc-interface-analysis** skill:

```bash
python .agent/skills/rpc-interface-analysis/scripts/resolve_rpc_interface.py <module> --json
```

Present: interface UUIDs, versions, endpoints, protocols, service names, procedure names, risk tiers.

### Step 2: `/rpc surface [module]` -- Attack Surface Ranking

Use the **rpc-interface-analysis** skill:

```bash
# Per-module
python .agent/skills/rpc-interface-analysis/scripts/map_rpc_surface.py <module> --json

# System-wide
python .agent/skills/rpc-interface-analysis/scripts/map_rpc_surface.py --system-wide --top 30 --json
```

Present: ranked interfaces by risk tier (critical > high > medium > low), procedure counts, service associations. Highlight remote-reachable and named-pipe interfaces.

### Step 3: `/rpc audit <module>` -- Security Audit

Requires the module's analysis DB. Run in sequence:

1. Resolve the module DB path.
2. Run interface enumeration for context:

```bash
python .agent/skills/rpc-interface-analysis/scripts/resolve_rpc_interface.py <module> --json
```

3. Run the security audit:

```bash
python .agent/skills/rpc-interface-analysis/scripts/audit_rpc_security.py <db_path> --json
```

Present: security findings ranked by severity -- missing impersonation, missing revert, remote interfaces without auth, complex type risks, elevation handlers without identity checks. For each finding, include the interface UUID, risk tier, and remediation guidance.

When generating Mermaid attack surface diagrams for `ncalrpc`-only services, label the attacker node as "Medium-IL Caller (standard user process)" -- not "Low-IL / Medium-IL". LRPC endpoints are not accessible to Low Integrity or AppContainer processes without explicit DACL grants.

### Step 4: `/rpc trace <module> <function>` -- Handler Chain Trace

Requires the module's analysis DB. Run:

```bash
python .agent/skills/rpc-interface-analysis/scripts/trace_rpc_chain.py <db_path> --function <func_name> --json
```

Present: RPC context (interface UUID, opnum, protocol, service), call chain with depths, dangerous sinks reachable, depth to first sink. Include a Mermaid call-chain diagram for the top path.

### Step 5: `/rpc clients <uuid>` -- Find Interface Consumers

```bash
python .agent/skills/rpc-interface-analysis/scripts/find_rpc_clients.py <uuid> --json
```

Present: server implementations and client consumers, grouped by module, with service and protocol details.

### Step 6: `/rpc topology [module]` -- RPC Client-Server Topology

Use the **rpc-interface-analysis** skill:

```bash
# System-wide
python .agent/skills/rpc-interface-analysis/scripts/rpc_topology.py --json

# Per-module
python .agent/skills/rpc-interface-analysis/scripts/rpc_topology.py <module> --json
```

Present: topology entries (interface UUID, risk tier, procedure count, server/client binaries, services, protocols, pipe names, ALPC endpoints, TCP ports). Group by service where helpful.

### Step 7: `/rpc blast-radius <module or uuid>` -- Co-Hosted Interface Impact

**For module**: Resolve interfaces first, then call `compute_blast_radius` for each via inline Python:

```python
from helpers.rpc_index import get_rpc_index
idx = get_rpc_index()
ifaces = idx.get_interfaces_for_module("<module>")
for iface in ifaces:
    result = idx.compute_blast_radius(iface.interface_id)
    # format and present result
```

**For UUID**: Call directly via inline Python:

```python
from helpers.rpc_index import get_rpc_index
idx = get_rpc_index()
result = idx.compute_blast_radius("<uuid>")
# format and present result
```

Present: target interface info, sibling interfaces (co-hosted in same service/binary), aggregate procedure count, combined protocol set, risk escalation notes.

### Step 8: `/rpc stubs <uuid>` -- C# Stub Parameter Signatures

Use inline Python to call the RPC index:

```python
from helpers.rpc_index import get_rpc_index
idx = get_rpc_index()
sigs = idx.get_procedure_signatures("<uuid>")
# format: for each sig, use sig.to_dict() or present name, opnum, parameters (name, ndr_type, direction)
```

Present: procedure name, opnum, parameter list (name, ndr_type, direction, risk_score). Note if stubs are not loaded.

## Output Format

Present results as a structured report in chat with:
- Summary statistics (interface count, risk distribution, procedure count)
- Formatted tables for ranked data
- Mermaid diagrams for topology/chains where helpful
- Actionable recommendations for high-risk findings

## Skills Used

- **rpc-interface-analysis**: All scripts (resolve, map, audit, trace, find, rpc_topology); blast-radius and stubs use inline Python with `helpers.rpc_index`
- **decompiled-code-extractor**: Module DB resolution (for audit/trace)
- **map-attack-surface**: Cross-reference with entry point data (optional enrichment)

## Error Handling

- If the RPC index is not loaded, report the issue and suggest checking `config/assets/` and `rpc.enabled` in `config/defaults.json`.
- If a module has no RPC interfaces, say so clearly.
- For `audit` and `trace`, the analysis DB must be available; guide the user to resolve if missing.
