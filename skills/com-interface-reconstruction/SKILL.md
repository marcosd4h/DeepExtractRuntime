---
name: com-interface-reconstruction
description: Reconstruct COM and WRL interface definitions from IDA Pro decompiled Windows PE binaries by analyzing vtable slots, QueryInterface/AddRef/Release patterns, mangled names, and WRL template instantiations. Use when the user asks to reconstruct COM interfaces, find COM classes, decode WRL templates, map CLSIDs, generate IDL descriptions, identify QueryInterface patterns, analyze vtable layouts as COM interfaces, or understand COM class hierarchies in extracted modules.
---

# COM / WRL Interface Reconstruction

## Purpose

Reconstruct complete COM interface and WRL class definitions from DeepExtractIDA analysis databases. Windows binaries are heavily COM-based; this skill extracts structured COM metadata from:

- **VTable slot analysis** -- map vtable layouts to COM interface method tables
- **QueryInterface/AddRef/Release patterns** -- identify IUnknown implementations
- **Mangled name decoding** -- extract full C++ type info from MSVC mangled names
- **WRL template instantiation decoding** -- parse `Microsoft::WRL::*` template parameters to recover interface lists, RuntimeClassFlags, and class hierarchies
- **Decompiled code pattern matching** -- find QI dispatch tables, CLSID registrations, and class factory patterns

Output is structured COM metadata: interfaces with method slots, class-to-interface maps, WRL template breakdowns, and IDL-like descriptions.

**This is NOT security analysis.** The goal is faithful COM structure reconstruction.

## Data Sources

### SQLite Databases (primary)

Individual analysis DBs in `extracted_dbs/` provide per-function data:

| Field                                  | COM Relevance                                                              |
| -------------------------------------- | -------------------------------------------------------------------------- |
| `mangled_name`                         | Full C++ type info: WRL templates, interface names, class names            |
| `vtable_contexts`                      | Reconstructed class skeletons with virtual method slots                    |
| `function_name` / `function_signature` | Demangled names showing COM patterns                                       |
| `outbound_xrefs`                       | VTable call info (`is_vtable_call`, `vtable_info`), CoCreateInstance calls |
| `simple_outbound_xrefs`                | Simplified callee info for API usage detection                             |
| `decompiled_code`                      | QI dispatch logic, GUID comparisons, class factory implementations         |
| `string_literals`                      | GUID strings, interface name strings                                       |

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

Pre-built scripts in `scripts/` handle all COM extraction. Run from the workspace root.

### scan_com_interfaces.py -- Discover All COM Interfaces (Start Here)

Scan a module for all COM-related structures:

```bash
# Full COM scan -- interfaces, QI patterns, vtable layouts
python .agent/skills/com-interface-reconstruction/scripts/scan_com_interfaces.py <db_path>

# JSON output for programmatic use
python .agent/skills/com-interface-reconstruction/scripts/scan_com_interfaces.py <db_path> --json

# Filter to functions with vtable contexts only
python .agent/skills/com-interface-reconstruction/scripts/scan_com_interfaces.py <db_path> --vtable-only
```

Output: COM interface inventory, QI/AddRef/Release implementations, vtable-derived method tables, and COM API usage summary.

### decode_wrl_templates.py -- Decode WRL Template Instantiations

Parse `Microsoft::WRL::*` template parameters from mangled names:

```bash
# Decode all WRL templates in a module
python .agent/skills/com-interface-reconstruction/scripts/decode_wrl_templates.py <db_path>

# JSON output
python .agent/skills/com-interface-reconstruction/scripts/decode_wrl_templates.py <db_path> --json

# Filter to specific WRL type (RuntimeClass, ComPtr, etc.)
python .agent/skills/com-interface-reconstruction/scripts/decode_wrl_templates.py <db_path> --type RuntimeClass
```

Output: decoded WRL class hierarchies, interface lists per RuntimeClass, RuntimeClassFlags, ComPtr usage, weak reference support.

### map_class_interfaces.py -- Map Interfaces to Classes

Build a class-to-interface mapping from QI logic, WRL metadata, and vtable analysis:

```bash
# Map all classes to their interfaces
python .agent/skills/com-interface-reconstruction/scripts/map_class_interfaces.py <db_path>

# JSON output
python .agent/skills/com-interface-reconstruction/scripts/map_class_interfaces.py <db_path> --json

# Focus on a specific class
python .agent/skills/com-interface-reconstruction/scripts/map_class_interfaces.py <db_path> --class CAppInfoService
```

Output: per-class interface lists, evidence sources (QI, WRL, vtable), base interfaces, aggregation.

### generate_idl.py -- Generate IDL-Like Descriptions

Produce IDL-like interface descriptions from reconstructed COM metadata:

```bash
# Generate IDL for all discovered interfaces
python .agent/skills/com-interface-reconstruction/scripts/generate_idl.py <db_path>

# Write to file
python .agent/skills/com-interface-reconstruction/scripts/generate_idl.py <db_path> --output interfaces.idl

# Filter to specific interface
python .agent/skills/com-interface-reconstruction/scripts/generate_idl.py <db_path> --interface IAppInfoService
```

Output: IDL-syntax interface blocks with method signatures, parameter types, HRESULT returns, and vtable slot comments.

## Workflows

```
COM Reconstruction Progress:
- [ ] Step 1: Orient -- find module DB, get module overview
- [ ] Step 2: Scan -- discover all COM interfaces and vtable layouts
- [ ] Step 3: Decode WRL -- parse WRL template instantiations
- [ ] Step 4: Map -- build class-to-interface mappings
- [ ] Step 5: Generate -- produce IDL-like descriptions
- [ ] Step 6: Refine -- cross-reference with decompiled code for details
```

**Step 1**: Orient

Find the module DB and understand scope:

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll
python .agent/skills/classify-functions/scripts/triage_summary.py <db_path>
```

Check the triage for `com_rpc` category count to gauge COM density.

**Step 2**: Scan COM Interfaces

Run the main scanner:

```bash
python .agent/skills/com-interface-reconstruction/scripts/scan_com_interfaces.py <db_path>
```

Review output for:

- **IUnknown implementations** -- classes implementing QI/AddRef/Release
- **VTable-derived interfaces** -- method tables extracted from vtable contexts
- **COM API usage** -- CoCreateInstance, CoInitialize, etc.

**Step 3**: Decode WRL Templates

```bash
python .agent/skills/com-interface-reconstruction/scripts/decode_wrl_templates.py <db_path>
```

WRL templates encode rich type info in mangled names:

- `RuntimeClassImpl<Flags, ...Interfaces>` -- reveals which interfaces a class implements
- `ComPtr<IFoo>` -- reveals interface usage at call sites
- `FtmBase` -- indicates free-threaded marshalling support
- `RuntimeClassFlags<N>` -- 1=WinRt, 2=ClassicCom, 3=WinRtClassicComMix

**Step 4**: Map Interfaces to Classes

```bash
python .agent/skills/com-interface-reconstruction/scripts/map_class_interfaces.py <db_path>
```

Evidence sources merged:

1. **WRL templates** (highest confidence) -- interface lists from RuntimeClassImpl parameters
2. **QI dispatch code** -- GUID comparisons in QueryInterface implementations
3. **VTable contexts** -- method slot analysis
4. **Mangled name patterns** -- `@ClassName@@` patterns linking methods to classes

**Step 5**: Generate IDL

```bash
python .agent/skills/com-interface-reconstruction/scripts/generate_idl.py <db_path> --output reconstructed.idl
```

**Step 6**: Refine

Use decompiled code to fill in details:

- Read QueryInterface implementations to discover additional interfaces via GUID comparisons
- Examine class factories (`DllGetClassObject`, `IClassFactory::CreateInstance`) for CLSID mappings
- Cross-reference with imports for COM API usage patterns
- Use the [reconstruct-types](../reconstruct-types/SKILL.md) skill for struct field analysis of COM objects

## Direct Helper Module Access

For custom queries:

```python
from helpers import open_individual_analysis_db

with open_individual_analysis_db("extracted_dbs/module_hash.db") as db:
    # Find all QI implementations
    qi_funcs = db.search_functions(name_contains="QueryInterface")
    # Find WRL classes
    wrl_funcs = db.search_functions(name_contains="RuntimeClassImpl")
    # Custom vtable query
    rows = db.execute_query("""
        SELECT function_name, vtable_contexts FROM functions
        WHERE vtable_contexts IS NOT NULL AND vtable_contexts NOT LIKE '[]%'
    """)
```

**Library tagging**: `filter_by_library(load_function_index(module), library='WRL')` identifies WRL infrastructure vs application COM classes.

## COM VTable Layout Reference

Standard IUnknown vtable (all COM interfaces inherit this):

| Slot | Offset | Method           | Signature                                 |
| ---- | ------ | ---------------- | ----------------------------------------- |
| 0    | +0x00  | `QueryInterface` | `HRESULT (REFIID riid, void **ppvObject)` |
| 1    | +0x08  | `AddRef`         | `ULONG ()`                                |
| 2    | +0x10  | `Release`        | `ULONG ()`                                |
| 3+   | +0x18+ | Custom methods   | Interface-specific                        |

IDispatch extends IUnknown:

| Slot | Offset | Method             |
| ---- | ------ | ------------------ |
| 3    | +0x18  | `GetTypeInfoCount` |
| 4    | +0x20  | `GetTypeInfo`      |
| 5    | +0x28  | `GetIDsOfNames`    |
| 6    | +0x30  | `Invoke`           |

## WRL RuntimeClassFlags Reference

| Value | Meaning              | COM Characteristics                       |
| ----- | -------------------- | ----------------------------------------- |
| 1     | `WinRt`              | Windows Runtime class, IInspectable-based |
| 2     | `ClassicCom`         | Classic COM, IUnknown-based               |
| 3     | `WinRtClassicComMix` | Hybrid: WinRT + classic COM interfaces    |

## Microsoft Mangled Name Patterns for COM

| Pattern                   | Meaning                    | Example                                               |
| ------------------------- | -------------------------- | ----------------------------------------------------- |
| `??_7Class@@6B@`          | VFTable symbol             | `??_7CMyService@@6BIMyService@@@`                     |
| `??0Class@@`              | Constructor                | `??0CAppInfoService@@QEAA@XZ`                         |
| `?QueryInterface@Class@@` | QI implementation          | `?QueryInterface@CMyClass@@UEAAJAEBU_GUID@@PEAPEAX@Z` |
| `?AddRef@Class@@`         | AddRef                     | `?AddRef@CMyClass@@UEAAKXZ`                           |
| `?Release@Class@@`        | Release                    | `?Release@CMyClass@@UEAAKXZ`                          |
| `RuntimeClassImpl<...>`   | WRL class implementation   | Encodes flags + interface list                        |
| `ComPtr<IFoo>`            | Smart pointer to interface | Reveals interface usage                               |
| `FillArrayWithIid`        | IID enumeration helper     | Lists supported IIDs                                  |

## Integration with Other Skills

| Task | Recommended Skill |
|------|-------------------|
| Cross-reference with ground-truth COM extraction data | com-interface-analysis |
| Reconstruct struct layouts for COM classes | reconstruct-types |
| Trace call chains through COM vtable methods | callgraph-tracer |
| Map COM entry points as attack surface | map-attack-surface |
| Build security dossier for COM methods | security-dossier |
| Lift COM class methods to clean code | code-lifting / batch-lift |

## Performance

| Operation | Typical Time | Notes |
|-----------|-------------|-------|
| Scan COM interfaces | ~5-10s | Full module vtable scan |
| Decode WRL templates | ~2-3s | Mangled name parsing |
| Map class interfaces | ~3-5s | Cross-references vtables and QI |
| Generate IDL | ~1-2s | After interface scan |

## Additional Resources

- For detailed COM/WRL technical reference, see [reference.md](reference.md)
- For type reconstruction (struct fields), see [reconstruct-types](../reconstruct-types/SKILL.md)
- For function classification, see [classify-functions](../classify-functions/SKILL.md)
- For code lifting, see [code-lifting](../code-lifting/SKILL.md)
- For DB schema and JSON formats, see [data_format_reference.md](../../docs/data_format_reference.md)
