# import-export-resolver

Resolve PE-level import and export relationships across all analyzed
modules in a DeepExtractIDA workspace.

## Scripts

### query_function.py

Find which modules export a given function and which modules import it.

```bash
# Find exporters and importers (default: both directions)
python .agent/skills/import-export-resolver/scripts/query_function.py --function CreateProcessW

# Exports only, JSON output
python .agent/skills/import-export-resolver/scripts/query_function.py --function CreateProcessW --direction export --json

# Imports only
python .agent/skills/import-export-resolver/scripts/query_function.py --function HeapAlloc --direction import --json

# Custom tracking DB
python .agent/skills/import-export-resolver/scripts/query_function.py path/to/analyzed_files.db --function NtCreateFile --json
```

**JSON output structure:**

```json
{
  "status": "ok",
  "function": "CreateProcessW",
  "direction": "both",
  "exporters": [
    {"module": "kernel32.dll", "name": "CreateProcessW", "ordinal": 123, "is_forwarded": false}
  ],
  "importers": [
    {"importing_module": "appinfo.dll", "source_module": "kernel32.dll", "is_delay_loaded": false}
  ],
  "_meta": {"tracking_db": "...", "generated": "..."}
}
```

### build_index.py

Build and cache the cross-module PE import/export index. Other scripts
use the index automatically; run this directly to see statistics.

```bash
# Human-readable summary
python .agent/skills/import-export-resolver/scripts/build_index.py

# JSON output
python .agent/skills/import-export-resolver/scripts/build_index.py --json

# Force rebuild (bypass cache)
python .agent/skills/import-export-resolver/scripts/build_index.py --no-cache
```

### module_deps.py

Build module dependency graphs from PE import tables.

```bash
# Full dependency graph
python .agent/skills/import-export-resolver/scripts/module_deps.py --json

# Single module's dependencies (what it imports from)
python .agent/skills/import-export-resolver/scripts/module_deps.py --module appinfo.dll --json

# Reverse: who depends on this module
python .agent/skills/import-export-resolver/scripts/module_deps.py --module ntdll.dll --consumers --json

# Mermaid diagram output
python .agent/skills/import-export-resolver/scripts/module_deps.py --diagram
```

### resolve_forwarders.py

Follow forwarded export chains across DLLs.

```bash
# Single forwarder chain
python .agent/skills/import-export-resolver/scripts/resolve_forwarders.py --module kernel32.dll --function HeapAlloc

# All forwarded exports in a module
python .agent/skills/import-export-resolver/scripts/resolve_forwarders.py --module kernel32.dll --all --json
```
