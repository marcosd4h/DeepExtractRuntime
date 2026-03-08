# Security Context Dossier

One-command deep context gathering for security auditing of decompiled Windows PE functions.

## Quick Start

```bash
# 1. Find the module DB
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll

# 2. Build a dossier
python .agent/skills/security-dossier/scripts/build_dossier.py extracted_dbs/appinfo_dll_e98d25a9e8.db AiCheckSecureApplicationDirectory
```

## What It Does

Before manually auditing a decompiled function, you need to understand its security landscape. `build_dossier.py` gathers everything in one shot:

| Section | What It Answers |
|---------|----------------|
| **Identity** | What is this function? Name, signature, class, mangled name |
| **Attack Reachability** | Can an attacker reach it? Is it exported? Path from entry points? |
| **Data Exposure** | Can untrusted data flow here? Which exports feed into it? |
| **Dangerous Operations** | What sensitive APIs does it call? What about its callees? |
| **Resource Patterns** | Locks held? Memory allocated? Global state mutated? |
| **Complexity** | How complex is it? Loop count, cyclomatic complexity, stack size |
| **Neighbors** | What else is nearby? Class methods, callers, callees |
| **Module Security** | ASLR, DEP, CFG, SEH enabled? |

## Usage

```bash
# By function name
python .agent/skills/security-dossier/scripts/build_dossier.py <db_path> <function_name>

# By function ID
python .agent/skills/security-dossier/scripts/build_dossier.py <db_path> --id <function_id>

# Search for functions
python .agent/skills/security-dossier/scripts/build_dossier.py <db_path> --search <pattern>

# JSON output
python .agent/skills/security-dossier/scripts/build_dossier.py <db_path> <function_name> --json

# Deeper callee analysis (check callees' callees)
python .agent/skills/security-dossier/scripts/build_dossier.py <db_path> <function_name> --callee-depth 2
```

## Example Output

```
################################################################################
  SECURITY CONTEXT DOSSIER
  Function: BatLoop
  Module:   cmd.exe
################################################################################

==== 2. ATTACK REACHABILITY ====================================================
  Is Exported:          No
  Externally Reachable: YES
  Direct Callers:       1
    <- BatProc [internal, ID=88]
  Transitive Callers:   21 (within 10 hops)

  Shortest Path from Entry (6 hops):
    mainCRTStartup -> __scrt_common_main_seh -> main -> Dispatch -> ECWork -> BatProc -> BatLoop

==== 4. DANGEROUS OPERATIONS ===================================================
  Direct Dangerous APIs (1):
    ! memset
  Callee Dangerous APIs (depth 1):
    Dispatch: memset
    dupstr: HeapAlloc
    mkstr: HeapAlloc

==== 6. COMPLEXITY ASSESSMENT ==================================================
  Assembly Instructions:      242
  Branch Count:               49
  Loop Count:                 5
  Max Cyclomatic Complexity:  27
  Stack Frame:
    Local Vars Size:    0x290 (656 bytes)
    Has Canary:         Yes
```

## Key Indicators to Watch

| Indicator | Risk |
|-----------|------|
| **Externally Reachable = YES** | Attacker can invoke this function |
| **Direct Dangerous APIs** | Immediate dangerous behavior |
| **memory_unsafe callees** | Buffer overflow potential |
| **command_execution callees** | Command injection potential |
| **Receives External Data = YES** | Untrusted input flows here |
| **Global Writes + Reachable** | Attacker-controlled state mutation |
| **No Canary + Large Stack** | Stack buffer overflow risk |
| **Cyclomatic Complexity > 10** | Complex flow, higher bug probability |

## Files

```
security-dossier/
├── SKILL.md              # Agent skill instructions (read by Cursor)
├── reference.md          # Technical reference (API categories, JSON schema)
├── README.md             # This file
└── scripts/
    ├── _common.py        # Shared utilities (security API taxonomy, call graph, asm metrics)
    └── build_dossier.py  # Main script -- builds the complete dossier
```

## Dependencies

- Python 3.10+
- `.agent/helpers/` module (workspace root) -- provides `open_individual_analysis_db`, `open_analyzed_files_db`
- SQLite analysis databases from DeepExtractIDA

## Security API Categories

Outbound calls are classified into 10 security-relevant categories:

- `memory_unsafe` -- strcpy, sprintf, gets, etc.
- `command_execution` -- CreateProcess*, ShellExecute*, WinExec
- `code_injection` -- WriteProcessMemory, VirtualAllocEx, CreateRemoteThread
- `privilege` -- AdjustTokenPrivileges, Impersonate*, OpenProcessToken
- `file_write` -- CreateFile*, WriteFile, DeleteFile
- `registry_write` -- RegSetValue*, RegCreateKey*, RegDeleteKey*
- `network` -- connect, send, recv, WinHttp*, InternetOpen
- `crypto` -- BCrypt{Encrypt,Decrypt}, Crypt{Encrypt,Decrypt}
- `sync` -- EnterCriticalSection, AcquireSRWLock, WaitForSingleObject
- `memory_alloc` -- VirtualAlloc, VirtualProtect, HeapAlloc, MapViewOfFile

## Related Skills

- [code-lifting](../code-lifting/SKILL.md) -- Lift functions into clean, readable code
- [callgraph-tracer](../callgraph-tracer/SKILL.md) -- Trace call chains across modules
- [data-flow-tracer](../data-flow-tracer/SKILL.md) -- Trace parameter and data flow
- [classify-functions](../classify-functions/SKILL.md) -- Classify all functions by purpose
- [verify-decompiled](../verify-decompiled/SKILL.md) -- Verify decompiler accuracy
- [map-attack-surface](../map-attack-surface/SKILL.md) -- Map module-wide attack surface
