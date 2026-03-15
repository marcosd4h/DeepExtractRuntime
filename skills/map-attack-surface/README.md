# Attack Surface Mapper

Answer: **"Where can an attacker enter this binary?"**

Discovers, classifies, and ranks every entry point in a Windows PE binary -- from obvious DLL exports to hidden COM vtable methods, RPC stubs, callback registrations, and socket dispatchers. Each entry point is ranked by attack value using callgraph reachability to dangerous operations.

## Quick Start

```bash
# 1. Find the module DB
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll

# 2. Discover all entry points
python .agent/skills/map-attack-surface/scripts/discover_entrypoints.py extracted_dbs/appinfo_dll_e98d25a9e8.db

# 3. Rank by attack value
python .agent/skills/map-attack-surface/scripts/rank_entrypoints.py extracted_dbs/appinfo_dll_e98d25a9e8.db --top 15

# 4. Generate CRS-compatible JSON
python .agent/skills/map-attack-surface/scripts/generate_entrypoints_json.py extracted_dbs/appinfo_dll_e98d25a9e8.db -o entrypoints.json
```

## What It Detects (21 Entry Point Types)

| Category | Types |
|----------|-------|
| **Explicit** | DLL exports, ordinal-only exports, forwarded exports, main/DllMain/ServiceMain, TLS callbacks |
| **Interface** | COM vtable methods, WinRT/WRL methods, COM class factories |
| **Protocol** | RPC server stubs, named pipe handlers, ALPC/LPC dispatchers, TCP/UDP socket handlers |
| **Callback** | CreateThread/SetTimer/RegisterClassEx targets (60+ APIs), window procedures, service handlers, hook procedures, exception handlers |

## Scripts

| Script | Purpose |
|--------|---------|
| `discover_entrypoints.py` | Scan a module for all entry point types |
| `rank_entrypoints.py` | Rank by attack value using callgraph reachability |
| `generate_entrypoints_json.py` | Output CRS-compatible entrypoints.json |

## Example Output

```
==========================================================================================
ATTACK SURFACE RANKING: 20 entry points
==========================================================================================

Rank   Score  DangerOps  Reachable  ParamRisk  Type                       Function
----  ------  ---------  ---------  ---------  -------------------------  ----------------
#1     87.0%         22        140      0.72  SERVICE_MAIN               ServiceMain
#2     77.3%         19        125      0.50  COM_CLASS_FACTORY          ReplaceDSMAIfPresent
#3     58.5%         17        115      0.20  COM_CLASS_FACTORY          TryActivateContract...

------------------------------------------------------------------------------------------
  #1  ServiceMain
------------------------------------------------------------------------------------------
  Attack Score:   [#################...] (87.0%)
  Type:           SERVICE_MAIN (explicit_entry_point)
  Signature:      void __fastcall ServiceMain(unsigned int, unsigned __int16 **)
  Reachable:      140 internal functions
  Dangerous ops:  22 reachable danger sinks
  Nearest danger: depth 0
  Danger APIs:    CreateFileW, RegOpenKeyExW, RpcServerRegisterIfEx, ...
  Tainted args:
    - arg1 (unsigned __int16 **): COM interface - TAINT
```

## Ranking Algorithm

Composite score (0.0--1.0) with five weighted factors:

| Factor | Weight | Description |
|--------|--------|-------------|
| Dangerous operations reachable | 30% | BFS callgraph to dangerous API sinks (memcpy, CreateProcess, ...) |
| Parameter risk | 25% | Buffer/string pointers > handles > flags |
| Proximity to danger | 15% | Inverse depth to first dangerous operation |
| Reachability breadth | 15% | Number of internal functions reachable |
| Entry type inherent risk | 15% | RPC/pipe/socket > COM > exports |

## Tested Results

| Module | Entry Points | Top Target | Score | Reachable | Danger Sinks |
|--------|-------------|------------|-------|-----------|-------------|
| appinfo.dll | 91 | `ServiceMain` | 87% | 140 | 22 |
| cmd.exe | 26 | `main` | 91% | 314 | 121 |
| coredpus.dll | 189 | `CWapDPU::ProcessData` | 88% | 188 | 17 |

## Files

```
map-attack-surface/
├── SKILL.md              # Agent skill instructions (read by Cursor)
├── reference.md          # Entry point taxonomy, scoring algorithm, JSON schema
├── README.md             # This file
└── scripts/
    ├── _common.py                   # Shared: type enums, 60+ callback APIs, 170+ danger sinks,
    │                                #   parameter risk scorer, callgraph reachability engine
    ├── discover_entrypoints.py      # Scan module DB for all entry point types
    ├── rank_entrypoints.py          # Rank by attack value using callgraph BFS
    └── generate_entrypoints_json.py # Output CRS-compatible entrypoints.json
```

## Dependencies

- Python 3.10+
- `.agent/helpers/` module (workspace root) -- provides `open_individual_analysis_db`, `open_analyzed_files_db`
- SQLite analysis databases from DeepExtractIDA

## Related Skills

- [security-dossier](../security-dossier/SKILL.md) -- Deep security context for individual functions
- [callgraph-tracer](../callgraph-tracer/SKILL.md) -- Trace call chains across modules
- [classify-functions](../classify-functions/SKILL.md) -- Classify all functions by purpose
- [com-interface-reconstruction](../com-interface-reconstruction/SKILL.md) -- Reconstruct COM interfaces
- [verify-decompiled](../verify-decompiled/SKILL.md) -- Verify decompiler accuracy
