# RE Report Generator

Answer: **"What IS this binary, what does it do, and where should I focus?"**

Generates synthesized reverse engineering reports from DeepExtractIDA analysis databases. Unlike raw `file_info.md` data dumps, this skill cross-correlates data, computes derived metrics, and produces actionable guidance -- the report you'd write manually after hours with the binary, generated in seconds.

## Quick Start

```bash
# 1. Find the module DB
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll

# 2. Generate a full report
python .agent/skills/generate-re-report/scripts/generate_report.py extracted_dbs/appinfo_dll_e98d25a9e8.db

# 3. Quick triage (brief mode)
python .agent/skills/generate-re-report/scripts/generate_report.py extracted_dbs/appinfo_dll_e98d25a9e8.db --summary

# 4. Save alongside module files
python .agent/skills/generate-re-report/scripts/generate_report.py extracted_dbs/appinfo_dll_e98d25a9e8.db -o extracted_code/appinfo_dll/re_report.md
```

## What It Produces (10-Section Report)

| Section | What It Answers |
|---------|----------------|
| **1. Executive Summary** | Identity, capabilities, scale, compiler, symbol quality |
| **2. Provenance & Build** | Rich header decode, PDB path analysis, .NET status |
| **3. Binary Structure** | DLL characteristics, section anomalies |
| **4. External Interface** | Imports categorized by capability, exports, delay-loads |
| **5. Internal Architecture** | Class hierarchy, symbol quality, component structure |
| **6. Complexity Hotspots** | Top functions by loops, xrefs, globals, size |
| **7. String Intelligence** | File paths, registry keys, URLs, GUIDs, ETW providers |
| **8. Cross-Reference Topology** | Entry reachability, dead code, SCCs, bottlenecks |
| **9. Anomalies** | TLS callbacks, decompiler failures, huge functions |
| **10. Recommendations** | Priority functions, skill suggestions, entry coverage |

## Scripts

| Script | Purpose |
|--------|---------|
| `generate_report.py` | Main orchestrator -- runs all analyses, assembles report |
| `analyze_imports.py` | Categorize imports/exports by API capability type |
| `analyze_complexity.py` | Rank functions by loops, xrefs, globals, size |
| `analyze_topology.py` | Call graph metrics: reachability, dead code, SCCs |
| `analyze_strings.py` | Categorize and index all string literals |
| `analyze_decompilation_quality.py` | Decompilation quality metrics (coverage, failure rate, artifact density) |

## Usage

```bash
# Full report to stdout
python .agent/skills/generate-re-report/scripts/generate_report.py <db_path>

# Brief mode (sections 1, 3, 4, 10 only)
python .agent/skills/generate-re-report/scripts/generate_report.py <db_path> --summary

# Control ranked table sizes
python .agent/skills/generate-re-report/scripts/generate_report.py <db_path> --top 20

# JSON output (all raw analysis data)
python .agent/skills/generate-re-report/scripts/generate_report.py <db_path> --json

# Write to file
python .agent/skills/generate-re-report/scripts/generate_report.py <db_path> -o report.md

# Individual analyzers
python .agent/skills/generate-re-report/scripts/analyze_imports.py <db_path> --exports --include-delay-load
python .agent/skills/generate-re-report/scripts/analyze_complexity.py <db_path> --top 20
python .agent/skills/generate-re-report/scripts/analyze_topology.py <db_path> --json
python .agent/skills/generate-re-report/scripts/analyze_strings.py <db_path> --category registry_key
```

## Example Output

```
# Reverse Engineering Report

## 1. Executive Summary

**appinfo.dll** v10.0.26100.7462 by Microsoft Corporation
_Application Information Service_

**Primary capabilities**: sync, security, process thread, string manipulation, registry
**Scale**: 1,173 functions (720 class methods + 453 standalone functions)
**PDB**: `appinfo.pdb`
**Exports/Entries**: 5
**Imports**: 391 functions from 79 modules

## 4. External Interface (Import/Export Analysis)

| Category | Import Count | Key APIs |
|---|---|---|
| sync | 24 | AcquireSRWLockExclusive, CreateEventExW, ... |
| security | 22 | CheckTokenMembership, OpenProcessToken, ... |
| process_thread | 12 | CreateProcessAsUserW, CreateThread, ... |
| registry | 9 | RegOpenKeyExW, RegCreateKeyExW, ... |
| crypto | 0 | (none) |

## 10. Recommended Focus Areas

### Priority Functions
1. **AiLaunchProcess** -- complex (13 loops, cyclomatic 103); hub (5 in, 107 out)
2. **RAiLaunchAdminProcess** -- complex (8 loops, cyclomatic 35); hub (3 in, 87 out)
3. **AipLaunchProcessWithIdentityHelper** -- complex (4 loops); large (1733 instructions)

### Skill Integration Suggestions
- **batch-lift**: 720 class methods -- consider batch-lifting entire classes
- **callgraph-tracer**: Entry ServiceMain reaches 144 functions
```

## API Taxonomy

The import categorizer covers ~500 Win32/NT API prefixes across 15 categories:

`file_io`, `registry`, `network`, `process_thread`, `crypto`, `security`, `com_ole`, `rpc`, `memory`, `ui_shell`, `sync`, `string_manipulation`, `error_handling`, `service`, `telemetry`, `debug_diagnostics`

Defined in `helpers/api_taxonomy.py:API_TAXONOMY`, the canonical source shared by all skills.

## Tested Results

| Module | Functions | Report Lines | Time | Key Finding |
|--------|-----------|-------------|------|-------------|
| cmd.exe | 817 | 444 | ~4s | 7 recursive clusters, `SearchForExecutable` most complex (26 loops) |
| appinfo.dll | 1,173 | 548 | ~4s | 720 class methods, 213 dead code candidates, `AiLaunchProcess` top priority |
| coredpus.dll | 1,080 | 623 | ~4s | 915 class methods, 407 dead code, `CWapDPU::ProcessData` most complex |

## Files

```
generate-re-report/
├── SKILL.md              # Agent skill instructions (read by Cursor)
├── reference.md          # Report section definitions, API taxonomy, algorithms
├── README.md             # This file
└── scripts/
    ├── _common.py              # Shared: ~500 API taxonomy, string patterns,
    │                           #   Rich header decoder, asm metrics, helpers
    ├── generate_report.py      # Main orchestrator -- assembles 10-section report
    ├── analyze_imports.py      # Categorize imports/exports by API capability
    ├── analyze_complexity.py   # Rank functions by loops, xrefs, globals, size
    ├── analyze_topology.py     # Call graph: reachability, SCCs, dead code, bottlenecks
    ├── analyze_strings.py      # Categorize all string literals across module
    └── analyze_decompilation_quality.py  # Decompilation quality metrics
```

## Dependencies

- Python 3.10+
- `.agent/helpers/` module (workspace root) -- provides `open_individual_analysis_db`, `open_analyzed_files_db`
- SQLite analysis databases from DeepExtractIDA

## Related Skills

- [classify-functions](../classify-functions/SKILL.md) -- Classify all functions by purpose
- [callgraph-tracer](../callgraph-tracer/SKILL.md) -- Trace call chains across modules
- [batch-lift](../batch-lift/SKILL.md) -- Lift related function groups together
- [security-dossier](../security-dossier/SKILL.md) -- Deep security context per function
- [map-attack-surface](../map-attack-surface/SKILL.md) -- Map module-wide attack surface
