---
name: generate-re-report
description: Generate comprehensive reverse engineering reports from DeepExtractIDA analysis databases, synthesizing binary identity, security posture, import/export capabilities, internal architecture, complexity hotspots, string intelligence, call graph topology, anomalies, and prioritized focus recommendations. Use when the user asks to generate a report, summarize a binary, understand what a module does, get an overview of an extracted module, triage a binary for analysis, or asks about the capabilities or architecture of an analyzed PE binary.
---

# Generate RE Report

## Purpose

Generate synthesized reverse engineering reports from DeepExtractIDA analysis databases. Unlike raw data dumps (`file_info.md`/`file_info.json`), this skill **cross-correlates data**, **computes derived metrics**, and produces **actionable guidance** -- the report you'd write manually after hours with the binary, generated in seconds.

**This is per-module analysis.** Each report covers one binary. The report is a living document that can be regenerated as analysis progresses.

## Data Sources

Reports are generated from **individual analysis databases** (`extracted_dbs/{module}_{hash}.db`). These contain per-function data (assembly, decompiled code, xrefs, strings, loops, globals, stack frames, analysis errors) plus binary-level metadata (imports, exports, sections, security features, Rich header, TLS callbacks, load config).

### Finding a Module DB

Reuse the decompiled-code-extractor skill's `find_module_db.py`:

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py --list
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll
```

### Quick Cross-Dimensional Search

To search across function names, signatures, strings, APIs, classes, and exports in one call:

```bash
python .agent/helpers/unified_search.py <db_path> --query "SearchTerm"
python .agent/helpers/unified_search.py <db_path> --query "SearchTerm" --json
```

## Utility Scripts

Pre-built scripts in `scripts/` handle all analysis and report generation. Run from the workspace root.

### generate_report.py -- Full Report (Start Here)

The main orchestrator. Runs all sub-analyses and assembles a 10-section markdown report.

```bash
# Full report to stdout
python .agent/skills/generate-re-report/scripts/generate_report.py <db_path>

# Write to file
python .agent/skills/generate-re-report/scripts/generate_report.py <db_path> --output re_report.md

# Write to module's extracted_code directory
python .agent/skills/generate-re-report/scripts/generate_report.py <db_path> --output extracted_code/appinfo_dll/re_report.md

# Brief mode (sections 1, 3, 4, 10 only -- fast overview)
python .agent/skills/generate-re-report/scripts/generate_report.py <db_path> --summary

# Control table sizes (default: top 10)
python .agent/skills/generate-re-report/scripts/generate_report.py <db_path> --top 20

# JSON output (all raw analysis data)
python .agent/skills/generate-re-report/scripts/generate_report.py <db_path> --json
```

### analyze_imports.py -- Import Capability Categorization

Categorize imports by API capability:

```bash
python .agent/skills/generate-re-report/scripts/analyze_imports.py <db_path>
python .agent/skills/generate-re-report/scripts/analyze_imports.py <db_path> --json
python .agent/skills/generate-re-report/scripts/analyze_imports.py <db_path> --exports --include-delay-load
```

### analyze_complexity.py -- Function Complexity Ranking

Rank functions by multiple metrics:

```bash
python .agent/skills/generate-re-report/scripts/analyze_complexity.py <db_path>
python .agent/skills/generate-re-report/scripts/analyze_complexity.py <db_path> --json --top 20
```

### analyze_topology.py -- Call Graph Metrics

Compute call graph metrics:

```bash
python .agent/skills/generate-re-report/scripts/analyze_topology.py <db_path>
python .agent/skills/generate-re-report/scripts/analyze_topology.py <db_path> --json
```

### analyze_strings.py -- String Literal Categorization

Categorize all string literals:

```bash
python .agent/skills/generate-re-report/scripts/analyze_strings.py <db_path>
python .agent/skills/generate-re-report/scripts/analyze_strings.py <db_path> --json --top 20
python .agent/skills/generate-re-report/scripts/analyze_strings.py <db_path> --category file_path
```

### analyze_decompilation_quality.py -- Decompilation Quality Metrics

Decompilation quality analysis. Scans `analysis_errors` across all functions: success rates, error category breakdown, problematic functions by severity, and confidence tiers (high/medium/low quality decompilation).

```bash
python .agent/skills/generate-re-report/scripts/analyze_decompilation_quality.py <db_path>
python .agent/skills/generate-re-report/scripts/analyze_decompilation_quality.py <db_path> --json
python .agent/skills/generate-re-report/scripts/analyze_decompilation_quality.py <db_path> --no-cache
```

## Report Sections

### 1. Executive Summary

One-paragraph overview: binary identity, primary capabilities (from import categories), scale (function/class counts), compiler info (Rich header), PDB path, symbol quality.

### 2. Provenance & Build Environment

Rich header decode (MSVC compiler version, linker, object file counts), PDB path analysis (source tree structure, developer machine hints), compilation timestamp vs file modification date, .NET status.

### 3. Security Posture

ASLR/DEP/CFG/SEH status, DLL characteristics, section permission anomalies (W+X), stack canary coverage percentage across all functions, load config guard data.

### 4. External Interface (Import/Export Analysis)

Imports categorized by capability (file I/O, registry, network, process/thread, crypto, security, COM, RPC, memory, sync, UI, telemetry, etc.). Exports with categories. Delay-loaded imports called out separately. Built-in taxonomy covers ~500 Win32/NT APIs across 15 categories.

### 5. Internal Architecture

Class hierarchy from mangled names, symbol quality (named vs `sub_XXXX`), class method counts.

### 6. Complexity Hotspots

Ranked tables: top by loop complexity, by xref count (hub functions), by global state access, by assembly size. Function distribution by size/type/complexity. Stack canary coverage. Functions with analysis errors.

### 7. String Intelligence

All strings categorized: file paths, registry keys, URLs, RPC endpoints, named pipes, ETW providers, GUIDs, error messages, format strings, debug strings. Each linked back to referencing functions.

### 8. Cross-Reference Topology

Call graph metrics: entry point reachability (coverage per export), dead code candidates, leaf functions, recursive groups (SCCs), bottleneck functions, max call depth from entries.

### 9. Notable Patterns & Anomalies

TLS callbacks, decompiler failures, unusually large functions (>500 asm lines), heavy global state writers.

### 10. Recommended Focus Areas

Synthesized priority list: top functions by combined complexity/connectivity/size, skill integration suggestions (which other skills to use and on what), entry points by code coverage, functions needing assembly verification.

## Workflows

### Workflow 1: "Generate a report for this module"

```
Report Generation:
- [ ] Step 1: Find the module DB
- [ ] Step 2: Generate the report
- [ ] Step 3: Review and save
```

**Step 1**: Find the DB

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll
```

**Step 2**: Generate

```bash
python .agent/skills/generate-re-report/scripts/generate_report.py extracted_dbs/appinfo_dll_e98d25a9e8.db
```

**Step 3**: Save alongside existing module files

```bash
python .agent/skills/generate-re-report/scripts/generate_report.py extracted_dbs/appinfo_dll_e98d25a9e8.db \
  --output extracted_code/appinfo_dll/re_report.md
```

### Workflow 2: "Quick triage of an unknown binary"

```bash
# Brief summary -- just the essential sections
python .agent/skills/generate-re-report/scripts/generate_report.py <db_path> --summary
```

### Workflow 3: "What APIs does this binary use?"

```bash
python .agent/skills/generate-re-report/scripts/analyze_imports.py <db_path> --exports --include-delay-load
```

### Workflow 4: "Find the most complex/interesting functions"

```bash
python .agent/skills/generate-re-report/scripts/analyze_complexity.py <db_path> --top 20
```

### Workflow 5: "What strings does this binary reference?"

```bash
# All strings categorized
python .agent/skills/generate-re-report/scripts/analyze_strings.py <db_path>

# Just file paths
python .agent/skills/generate-re-report/scripts/analyze_strings.py <db_path> --category file_path

# Just registry keys
python .agent/skills/generate-re-report/scripts/analyze_strings.py <db_path> --category registry_key
```

### Workflow 6: "JSON for downstream processing"

```bash
# Full JSON with all analysis data
python .agent/skills/generate-re-report/scripts/generate_report.py <db_path> --json > analysis.json
```

## Integration with Other Skills

| Task | Recommended Skill |
|------|-------------------|
| Deep-dive into interesting functions from report | security-dossier |
| Trace call chains for reported hotspots | callgraph-tracer |
| Map attack surface using report findings | map-attack-surface |
| Classify functions for focused follow-up | classify-functions |
| Generate deep research prompts from report areas | deep-research-prompt |

## API Taxonomy

The import categorizer uses a canonical taxonomy of ~500 Win32/NT API prefixes across 15 categories. Defined in `helpers/api_taxonomy.py:API_TAXONOMY` and shared by all skills. Categories: `file_io`, `registry`, `network`, `process_thread`, `crypto`, `security`, `com_ole`, `rpc`, `memory`, `ui_shell`, `sync`, `string_manipulation`, `error_handling`, `service`, `telemetry`, `debug_diagnostics`.

The taxonomy is importable by any skill via `from helpers.api_taxonomy import API_TAXONOMY, classify_api`.

## Direct Helper Module Access

For custom queries not covered by scripts:

```python
from helpers import open_individual_analysis_db

with open_individual_analysis_db("extracted_dbs/module_hash.db") as db:
    fi = db.get_file_info()
    print(fi.parsed_security_features)
    print(fi.parsed_imports)
```

## Performance

| Operation | Typical Time | Notes |
|-----------|-------------|-------|
| Analyze imports | ~3-5s | Classifies all imported APIs |
| Analyze strings | ~3-5s | Categorizes all string literals |
| Analyze complexity | ~5-10s | Assembly metrics for all functions |
| Analyze topology | ~5-10s | Call graph statistics |
| Generate full report | ~30-60s | Runs all analysis scripts sequentially |

## Additional Resources

- For detailed report section definitions, see [reference.md](reference.md)
- For DB schema and JSON field formats, see [data_format_reference.md](../../docs/data_format_reference.md)
- For file_info.json schema, see [file_info_format_reference.md](../../docs/file_info_format_reference.md)
- For code analysis skill, see [analyze-ida-decompiled](../analyze-ida-decompiled/SKILL.md)
- For function classification, see [classify-functions](../classify-functions/SKILL.md)
- For call graph tracing, see [callgraph-tracer](../callgraph-tracer/SKILL.md)
- For code lifting, see [code-lifting](../code-lifting/SKILL.md)
