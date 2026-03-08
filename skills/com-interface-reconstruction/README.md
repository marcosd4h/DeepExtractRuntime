# COM / WRL Interface Reconstruction

Reconstruct COM interface definitions and WRL class hierarchies from IDA Pro decompiled Windows PE binaries.

Answers: **"What COM interfaces does this binary implement, and how are they structured?"**

## Quick Start

```bash
# 1. Find the module DB
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll

# 2. Scan for all COM interfaces
python .agent/skills/com-interface-reconstruction/scripts/scan_com_interfaces.py extracted_dbs/appinfo_dll_e98d25a9e8.db

# 3. Decode WRL template instantiations
python .agent/skills/com-interface-reconstruction/scripts/decode_wrl_templates.py extracted_dbs/appinfo_dll_e98d25a9e8.db

# 4. Map which interfaces each class implements
python .agent/skills/com-interface-reconstruction/scripts/map_class_interfaces.py extracted_dbs/appinfo_dll_e98d25a9e8.db

# 5. Generate IDL-like descriptions
python .agent/skills/com-interface-reconstruction/scripts/generate_idl.py extracted_dbs/appinfo_dll_e98d25a9e8.db
```

## What It Detects

| Source | What It Extracts |
|--------|-----------------|
| **VTable contexts** | Method tables from IDA vtable slot analysis (with COM confidence scoring) |
| **QI/AddRef/Release** | IUnknown implementations identifying COM classes |
| **WRL templates** | RuntimeClassFlags, interface lists, FtmBase, weak ref support from mangled names |
| **ComPtr usage** | Which interfaces are used as smart pointers at call sites |
| **COM APIs** | CoCreateInstance, DllGetClassObject, and other COM infrastructure calls |
| **Decompiled code** | GUID comparisons in QueryInterface dispatch, IID references |

## Scripts

| Script | Purpose |
|--------|---------|
| `scan_com_interfaces.py` | Discover QI/AddRef/Release implementations, vtable layouts, COM API usage |
| `decode_wrl_templates.py` | Parse `Microsoft::WRL::*` template parameters for class hierarchies |
| `map_class_interfaces.py` | Merge all evidence into class-to-interface mappings |
| `generate_idl.py` | Produce IDL-syntax interface descriptions from vtable analysis |

All scripts support `--json` for programmatic output.

## Example Output

### scan_com_interfaces.py

```
================================================================================
  COM INTERFACE SCAN: coredpus.dll
================================================================================

  Functions scanned:        1080
  WRL functions:            24
  QI implementations:       11
  Unique COM classes:       16
  COM vtables:              126

  COM CLASSES (from QI/AddRef/Release):
    CClassFactory          QI=1 AddRef=1 Release=1
    CDomNode               QI=1 AddRef=1 Release=1
    CSyncMLDPU             QI=2 AddRef=1 Release=2
    CWapDPUHelper          QI=1 AddRef=1 Release=1

  COM VTABLE INTERFACES -- MEDIUM confidence:

    Class: CSyncMLDPU
    Base:  IUnknown
    Slots: 5
      [0] 0x00: QueryInterface
      [1] 0x08: Initialize
      [2] 0x10: ProcessData
      [3] 0x18: GetResultsData
      [4] 0x20: UnenrollForVail
```

### map_class_interfaces.py --class CWapDPUHelper

```
  CLASS: CWapDPUHelper
    QI function IDs:      [767]
    AddRef function IDs:  [753]
    Release function IDs: [769]
    Other methods:        18 function(s)

    INTERFACES (1):
      IUnknown                                     [inherent]

    VTABLE METHODS (14):
      [0] 0x00: QueryInterface
      [1] 0x08: HasV2Node
      [2] 0x10: AddV2Node
      [3] 0x18: DeleteV2Node
      [4] 0x20: ExecV2Node
      [5] 0x28: SetV2NodeValue
      [6] 0x30: QueryV2Node
      [7] 0x38: ProcessNode
      ...
```

### generate_idl.py

```idl
// Reconstructed COM Interfaces from: coredpus.dll

[uuid(unknown)]
interface ISyncMLDPU : IUnknown
{
    // Slot 0 (0x00)
    HRESULT QueryInterface();
    // Slot 1 (0x08)
    HRESULT Initialize(CSyncMLDPU *this, struct tagSyncMLDPUInit *);
    // Slot 2 (0x10)
    HRESULT ProcessData(CSyncMLDPU *this, struct tagSyncMLDPUParams *);
    // Slot 3 (0x18)
    HRESULT GetResultsData(CSyncMLDPU *this, struct tagSyncMLDPUResults *);
    // Slot 4 (0x20)
    HRESULT UnenrollForVail();
};
```

## Tested Results

| Module | Functions | QI Impls | COM Classes | COM VTables | WRL Classes | ComPtr Interfaces |
|--------|-----------|----------|-------------|-------------|-------------|-------------------|
| appinfo.dll | 1173 | 6 | 7 | 33 | 3 | 1 |
| cmd.exe | 817 | 2 | 5 | 3 | 1 | 1 |
| coredpus.dll | 1080 | 11 | 16 | 126 | 1 | 5 |

## Files

```
com-interface-reconstruction/
├── SKILL.md              # Agent skill instructions (read by Cursor)
├── reference.md          # COM/WRL technical reference (vtable layouts, QI patterns, mangled names)
├── README.md             # This file
└── scripts/
    ├── _common.py                # Shared: COM constants, WRL template parsing, vtable classification,
    │                             #   mangled name decoder, GUID detection, well-known IID resolution
    ├── scan_com_interfaces.py    # Scan module DB for QI/AddRef/Release, vtable layouts, COM APIs
    ├── decode_wrl_templates.py   # Decode RuntimeClassImpl/ComPtr/FtmBase from mangled names
    ├── map_class_interfaces.py   # Merge WRL + QI + vtable evidence into class-to-interface map
    └── generate_idl.py           # Produce IDL-syntax interface descriptions
```

## Dependencies

- Python 3.10+
- `.agent/helpers/` module (workspace root) -- provides `open_individual_analysis_db`, `open_analyzed_files_db`
- SQLite analysis databases from DeepExtractIDA

## Related Skills

- [reconstruct-types](../reconstruct-types/SKILL.md) -- Reconstruct struct/class field layouts
- [classify-functions](../classify-functions/SKILL.md) -- Classify all functions by purpose
- [code-lifting](../code-lifting/SKILL.md) -- Lift functions into clean code
- [callgraph-tracer](../callgraph-tracer/SKILL.md) -- Trace call chains across modules
- [map-attack-surface](../map-attack-surface/SKILL.md) -- Map module-wide attack surface
- [security-dossier](../security-dossier/SKILL.md) -- Deep security context for individual functions
