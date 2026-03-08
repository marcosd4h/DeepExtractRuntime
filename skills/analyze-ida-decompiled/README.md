# Analyze IDA Decompiled Code

Answer: **"What does this function do, how do I find it, and what is this binary?"**

The foundational navigation and comprehension skill for DeepExtractIDA extraction outputs. Unlike every other skill in this ecosystem (which provides Python scripts), this is a pure **knowledge skill** -- it teaches the AI agent how to read, navigate, cross-reference, and understand decompiled C/C++ code and PE metadata produced by DeepExtractIDA from Windows binaries. It operates entirely through Cursor's built-in tools (Read, Grep, Glob) guided by the structured knowledge in its SKILL.md.

## Quick Start

No scripts to run. The agent uses its own tools guided by this skill's workflow:

```
1. Orient   -- Read file_info.json for module identity, scope, and security posture
2. Discover -- Search function_summary or grep grouped .cpp files for the target function
3. Analyze  -- Parse the comment header, read the body, map struct accesses, identify APIs
4. Xref     -- Trace call chains: search function_summary, then imports, then sub_XXXX addresses
5. Context  -- Ground analysis using security_features, entry_points, exports, rich_header
```

### Example: Find and analyze a function

```
User: "How does AiCheckSecureApplicationDirectory work?"

Agent workflow:
  1. Read extracted_code/appinfo_dll/file_info.json
  2. Search function_summary.standalone_functions -> found
  3. Grep appinfo_dll_standalone_group_*.cpp for "// Function Name: AiCheckSecure..."
  4. Read the function body in appinfo_dll_standalone_group_9.cpp
  5. Cross-reference CreateFileW in file_info.json imports for correct signature
  6. Report: validates directory is in a secure location by resolving NT paths
```

## What It Teaches

This skill encodes five areas of knowledge that the agent needs to work with DeepExtractIDA output:

### 1. Extraction Layout Knowledge

| Artifact                  | Location                                 | Purpose                                               |
| ------------------------- | ---------------------------------------- | ----------------------------------------------------- |
| Module metadata (machine) | `extracted_code/{module}/file_info.json` | Primary lookup for all programmatic queries           |
| Module metadata (human)   | `extracted_code/{module}/file_info.md`   | Same data, Markdown formatted for reading             |
| Class method code         | `{module}_{ClassName}_group_{N}.cpp`     | Methods of a class, split ~250-300 lines per file     |
| Standalone function code  | `{module}_standalone_group_{N}.cpp`      | Non-class functions, alphabetically packed            |
| Analysis database         | `extracted_dbs/{module}_{hash}.db`       | SQLite with full analysis data (used by other skills) |
| Batch summary             | `extraction_report.json`                 | Batch run overview                                    |

Module naming: `{stem}_{extension}` -- e.g., `appinfo.dll` becomes `appinfo_dll`.

### 2. Comment Header Format

Every function in grouped `.cpp` files is preceded by a structured header block:

```cpp
// Function Name: AiCheckSecureApplicationDirectory
// Mangled Name: ?AiCheckSecureApplicationDirectory@@YAJPEBGPEAUCSecurityDescriptor@@PEAH@Z
// Function Signature (Extended): __int64 __fastcall AiCheckSecureApplicationDirectory(...)
// Function Signature: long AiCheckSecureApplicationDirectory(ushort const *,...)
```

The Extended signature line appears only when it differs from the base signature. The mangled name encodes C++ types and can be used to determine the original class hierarchy, parameter types, and return type.

### 3. IDA Naming Pattern Dictionary

The skill encodes a comprehensive lookup table for IDA's auto-generated names:

| Pattern                                  | Meaning                                                   |
| ---------------------------------------- | --------------------------------------------------------- |
| `a1`, `a2`, ...                          | Function parameters (positional)                          |
| `v1`, `v2`, ...                          | Auto-named local variables                                |
| `sub_XXXX`                               | Unnamed function at address XXXX                          |
| `off_XXXX` / `dword_XXXX` / `qword_XXXX` | Pointer / 4-byte / 8-byte global at XXXX                  |
| `word_XXXX` / `byte_XXXX` / `unk_XXXX`   | 2-byte / 1-byte / unknown-typed data                      |
| `loc_XXXX` / `LABEL_N`                   | Code label / decompiler goto target                       |
| `_DWORD`, `_QWORD`, `_WORD`, `_BYTE`     | IDA sized-access type casts                               |
| `LODWORD(x)` / `HIDWORD(x)`              | Low / high 32 bits of 64-bit value                        |
| `__fastcall`                             | x64 calling convention (rcx, rdx, r8, r9)                 |
| `__imp_Func` / `_imp_Func`               | Import thunk for Func                                     |
| `wil::*`                                 | Windows Implementation Library (telemetry, feature flags) |
| `Microsoft::WRL::*`                      | COM Windows Runtime Library                               |

### 4. file_info.json Schema Knowledge

The skill maps all 13 sections of `file_info.json` and teaches when to use each:

| Section               | Use For                                                               |
| --------------------- | --------------------------------------------------------------------- |
| `basic_file_info`     | File identity: path, size, MD5/SHA256, analysis timestamp             |
| `pe_version_info`     | Product context: company, product, version, description               |
| `pe_metadata`         | Build details: compilation timestamp, PDB path, .NET status           |
| `entry_points`        | Module entry points with confidence and detection method              |
| `imports`             | All imported DLLs/functions (includes delay-load, API-set resolution) |
| `exports`             | Exported symbols with ordinals and forwarder info                     |
| `sections`            | PE section table (names, addresses, sizes, permissions)               |
| `security_features`   | ASLR, DEP, CFG, SEH status                                            |
| `dll_characteristics` | Raw and decoded DllCharacteristics flags                              |
| `rich_header`         | Compiler/linker toolchain metadata                                    |
| `tls_callbacks`       | TLS callbacks with threat analysis                                    |
| `load_config`         | SEH/CFG guard tables                                                  |
| `function_summary`    | Complete categorized function index (class methods + standalone)      |

Import entries include API-set resolution (`api-ms-win-...` resolved to `kernel32.dll`) and delay-load labeling.

### 5. Common Analysis Patterns

**Struct field access** -- when decompiled code uses casts:

```cpp
v5 = *((_QWORD *)a1 + 14);   // byte offset 14*8 = 112
*(_DWORD *)a2 = 45;           // writing int at offset 0
if ( *((_BYTE *)a1 + 32) )    // byte at offset 32
```

Collecting all accesses to the same type across functions reconstructs struct layouts.

**COM/WRL vtable calls:**

```cpp
result = (*((__int64 (__fastcall **)(_QWORD, _QWORD, _QWORD))(*a1) + 0))(a1, riid, ppvObject);
// => a1->lpVtbl->QueryInterface(a1, riid, ppvObject)
// vtable[0] = QueryInterface, [1] = AddRef, [2] = Release
```

**HRESULT error handling:**

```cpp
v3 = SomeWin32Call(...);
if ( v3 < 0 )              // FAILED(hr)
    goto cleanup;
```

## Example Sessions

The skill ships with 6 worked examples in [examples.md](examples.md) using real `appinfo.dll` data:

| Example                    | Question                                                      | Technique                                                                 |
| -------------------------- | ------------------------------------------------------------- | ------------------------------------------------------------------------- |
| 1. Orient in a module      | "What is appinfo.dll?"                                        | Read `file_info.json` metadata + `function_summary`                       |
| 2. Analyze a function      | "How does AiCheckSecureApplicationDirectory work?"            | Locate via function_summary, read grouped file, trace logic, resolve APIs |
| 3. Class method            | "What does LUATelemetry::AppXSyncActivity::StartActivity do?" | Search class group files, decode WIL activity patterns                    |
| 4. Entry point tracing     | "What happens when the service starts?"                       | Check `entry_points`, find ServiceMain, follow call chain                 |
| 5. Security API audit      | "What security-sensitive APIs does this use?"                 | Scan `imports` for notable API categories                                 |
| 6. Grouped file navigation | "How do I find a function in grouped files?"                  | Alphabetical ordering + `// Function Name:` header search                 |

## What Makes This Skill Different

| Property             | analyze-ida-decompiled                    | All other skills (13)  |
| -------------------- | ----------------------------------------- | ---------------------- |
| **Type**             | Knowledge / navigation                    | Automation / tooling   |
| **Has scripts/**     | No                                        | Yes (Python scripts)   |
| **Has reference.md** | Yes                                       | Most do                |
| **Operates via**     | Agent's built-in tools (Read, Grep, Glob) | Python scripts + agent |
| **Primary output**   | Natural language analysis                 | Structured text/JSON   |
| **Files**            | 2 (SKILL.md + examples.md)                | 4-8 typically          |

This is the only skill that teaches **how to read** the extraction output. Every other skill **operates on** it programmatically. This makes it the prerequisite literacy layer for the entire ecosystem.

## Ecosystem Role

This skill is referenced by **10 of 13** other skills, making it the most-referenced skill in the DeepExtractIDA ecosystem:

```
                            analyze-ida-decompiled
                                    |
        +-----------+-------+-------+-------+-----------+
        |           |       |       |       |           |
   code-lifting     |  classify  callgraph  |    deep-research
        |           |       |       |       |           |
   batch-lift  reconstruct  |  data-flow  verify-decompiled
                    |       |       |
              state-machine |  generate-re-report
                            |
                    com-interface
                            |
                   security-dossier
                            |
                   map-attack-surface
```

**Skills that reference this one:**

| Skill                   | How it uses analyze-ida-decompiled                |
| ----------------------- | ------------------------------------------------- |
| code-lifting            | Complementary code analysis                       |
| batch-lift              | Understanding decompiled code and module metadata |
| reconstruct-types       | Navigate and understand decompiled code           |
| classify-functions      | Code analysis context                             |
| callgraph-tracer        | Code analysis skill                               |
| data-flow-tracer        | Code analysis and navigation                      |
| state-machine-extractor | Navigate and understand decompiled code           |
| verify-decompiled       | Navigate and understand decompiled code           |
| generate-re-report      | Code analysis skill                               |
| deep-research-prompt    | Gather module metadata and function summaries     |

## Files

```
analyze-ida-decompiled/
├── SKILL.md       # Agent skill instructions -- full knowledge base
│                  #   (extraction layout, file_info.json schema, IDA naming
│                  #   patterns, 5-step analysis workflow, common patterns)
├── examples.md    # 6 worked analysis examples using real appinfo.dll data
└── README.md      # This file
```

Referenced documentation (outside this skill):

```
.agent/docs/
├── file_info_format_reference.md   # Full file_info.json/file_info.md schema
└── data_format_reference.md        # SQLite database schema, JSON field formats
```

## Dependencies

- Cursor IDE with built-in tools (Read, Grep, Glob)
- DeepExtractIDA extraction output (`extracted_code/` and/or `extracted_dbs/`)
- No Python scripts, no external packages

## Related Skills

- [code-lifting](../code-lifting/SKILL.md) -- Lift functions into clean, readable code
- [batch-lift](../batch-lift/SKILL.md) -- Lift related function groups together with shared context
- [verify-decompiled](../verify-decompiled/SKILL.md) -- Verify decompiler accuracy against assembly
- [reconstruct-types](../reconstruct-types/SKILL.md) -- Reconstruct struct/class definitions from memory access
- [classify-functions](../classify-functions/SKILL.md) -- Categorize functions by purpose and interest score
- [callgraph-tracer](../callgraph-tracer/SKILL.md) -- Trace call chains across modules
- [data-flow-tracer](../data-flow-tracer/SKILL.md) -- Trace parameter and data flow
- [generate-re-report](../generate-re-report/SKILL.md) -- Generate comprehensive RE reports
- [deep-research-prompt](../deep-research-prompt/SKILL.md) -- Generate deep research prompts
- [security-dossier](../security-dossier/SKILL.md) -- Security context dossier per function
- [map-attack-surface](../map-attack-surface/SKILL.md) -- Map module-wide attack surface
- [state-machine-extractor](../state-machine-extractor/SKILL.md) -- Extract dispatch tables and state machines
- [com-interface-reconstruction](../com-interface-reconstruction/SKILL.md) -- Reconstruct COM/WRL interfaces
