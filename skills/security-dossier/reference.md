# Security Dossier -- Technical Reference

## Security API Categories

The dossier classifies outbound API calls into security-relevant categories using prefix matching (strips `__imp_`, `_imp_`, `j_`, `cs:` prefixes first):

| Category            | API Prefixes                                                                                                            | Risk Context                    |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| `memory_unsafe`     | strcpy, strcat, sprintf, vsprintf, gets, scanf, wcscpy, wcscat, wsprintf, lstrcpy, lstrcat                              | Buffer overflow potential       |
| `command_execution` | CreateProcess*, ShellExecute*, WinExec, system                                                                          | Arbitrary command execution     |
| `code_injection`    | WriteProcessMemory, VirtualAllocEx, CreateRemoteThread, QueueUserAPC, NtWriteVirtualMemory, SetWindowsHookEx            | Code injection vectors          |
| `privilege`         | AdjustTokenPrivileges, Impersonate\*, OpenProcessToken, OpenThreadToken, DuplicateTokenEx                               | Privilege escalation            |
| `file_write`        | CreateFile\*, WriteFile, DeleteFile, MoveFile, CopyFile                                                                 | File system modification        |
| `registry_write`    | RegSetValue*, RegCreateKey*, RegDeleteKey*, RegDeleteValue*                                                             | Registry modification           |
| `network`           | connect, send, recv, WSA*, Internet*, WinHttp\*, URLDownloadToFile                                                      | Network communication           |
| `crypto`            | BCrypt{Encrypt,Decrypt,GenRandom}, Crypt{Encrypt,Decrypt,GenRandom}                                                     | Cryptographic operations        |
| `sync`              | EnterCriticalSection, LeaveCriticalSection, AcquireSRWLock, ReleaseSRWLock, WaitForSingleObject, WaitForMultipleObjects | Synchronization / deadlock risk |
| `memory_alloc`      | VirtualAlloc, VirtualFree, VirtualProtect, HeapAlloc, HeapFree, MapViewOfFile                                           | Memory management               |

## Output Formats

### Text Output (default)

Structured sections with headers and indented fields. Designed for terminal reading.

### JSON Output (`--json`)

Complete dossier as a JSON object:

```json
{
  "identity": {
    "function_id": 42,
    "function_name": "FuncName",
    "function_signature": "...",
    "function_signature_extended": "...",
    "mangled_name": "?...",
    "class_name": "ClassName or null",
    "has_decompiled": true,
    "has_assembly": true,
    "module_name": "module.dll",
    "module_description": "..."
  },
  "reachability": {
    "is_exported": false,
    "export_info": null,
    "is_entry_point": false,
    "direct_callers": [
      { "name": "...", "id": 10, "module": "", "is_internal": true }
    ],
    "direct_caller_count": 3,
    "transitive_caller_count": 15,
    "reachable_from_exports": ["ExportA"],
    "reachable_from_entry_points": ["DllMain"],
    "shortest_path_from_entry": ["DllMain", "FuncA", "FuncName"],
    "externally_reachable": true,
    "ipc_context": {
      "is_rpc_handler": false,
      "is_com_method": false,
      "is_winrt_method": false,
      "reachable_from_rpc": [],
      "reachable_from_com": [],
      "reachable_from_winrt": [],
      "rpc_interface_id": "uuid or null",
      "rpc_endpoints": [],
      "com_clsid": "guid or null",
      "com_can_elevate": false,
      "winrt_class_name": "string or null",
      "winrt_activation_type": "string or null"
    }
  },
  "data_exposure": {
    "export_callers_count": 1,
    "export_callers": ["ExportA"],
    "data_paths": [
      { "source": "ExportA", "source_export": "ExportA", "entry_type": "export", "path": ["ExportA", "FuncName"], "hops": 1 }
    ],
    "parameter_count": 3,
    "param_risk_score": 0.0,
    "param_risk_reasons": [],
    "external_callers_count": 1,
    "external_callers": ["ExportA"],
    "receives_external_data": true
  },
  "dangerous_operations": {
    "dangerous_apis_direct": ["strcpy"],
    "dangerous_api_count": 1,
    "security_relevant_callees": { "command_execution": ["CreateProcessW"] },
    "callee_dangerous_apis": { "HelperFunc": ["memcpy"] },
    "total_callees": 12,
    "indirect_calls": [
      { "target": "vfunc_name", "is_indirect": true, "is_vtable": false, "vtable_info": null, "confidence": 80 }
    ],
    "indirect_call_count": 1
  },
  "resource_patterns": {
    "sync_operations": ["EnterCriticalSection", "LeaveCriticalSection"],
    "memory_operations": ["VirtualAlloc"],
    "file_operations": [],
    "global_accesses_total": 5,
    "global_reads": 3,
    "global_writes": 2,
    "globals": [
      { "name": "g_Flag", "address": "0x1234", "access_type": "Write" }
    ],
    "has_sync": true,
    "has_memory_ops": true,
    "has_global_writes": true
  },
  "complexity": {
    "instruction_count": 245,
    "call_count": 12,
    "branch_count": 34,
    "ret_count": 1,
    "has_syscall": false,
    "loop_count": 3,
    "max_cyclomatic_complexity": 7,
    "total_loop_instructions": 80,
    "has_infinite_loop": false,
    "local_vars_size": 288,
    "args_size": 40,
    "saved_regs_size": 8,
    "has_exception_handler": false,
    "frame_pointer_present": false,
    "string_count": 5,
    "strings_sample": ["Error: %s", "\\Registry\\Machine\\SOFTWARE\\..."],
    "string_categories": { "url": ["http://..."], "registry_key": ["HKLM\\..."] }
  },
  "neighboring_context": {
    "class_name": "ClassName",
    "class_methods": [
      { "name": "ClassName::Method1", "id": 43, "has_decompiled": true }
    ],
    "class_method_count": 5,
    "vtable_classes": ["ClassName"],
    "direct_callees": [
      {
        "name": "CreateProcessW",
        "id": null,
        "module": "kernel32.dll",
        "is_internal": false
      }
    ],
    "direct_callee_count": 12,
    "direct_callers": [
      { "name": "CallerFunc", "id": 10, "module": "", "is_internal": true }
    ],
    "direct_caller_count": 3
  },
  "data_quality": {
    "has_issues": false,
    "analysis_errors": [],
    "error_count": 0
  }
}
```

## Interpretation Guide

### High-Risk Indicators

| Indicator                             | Meaning                                                   | Priority |
| ------------------------------------- | --------------------------------------------------------- | -------- |
| Externally Reachable = YES            | Attacker can invoke this function from outside the module | High     |
| Exported + dangerous APIs             | Direct attack surface with sensitive operations           | Critical |
| memory_unsafe APIs                    | Buffer overflow vectors                                   | Critical |
| command_execution APIs                | Command injection potential                               | Critical |
| code_injection APIs                   | Process injection capability                              | Critical |
| privilege APIs                        | Privilege escalation surface                              | High     |
| Global writes + external reachability | Attacker-controlled state mutation                        | High     |
| High cyclomatic complexity (>10)      | Complex control flow, higher bug probability              | Medium   |
| Sync operations                       | Potential deadlock or race conditions                     | Medium   |
| `has_syscall = true`                  | Direct syscall detected -- potential security hook evasion | High     |
| `param_risk_score >= 0.8`             | High-risk parameters (buffers, strings)                   | High     |
| `ipc_context.is_rpc_handler = YES`    | Confirmed RPC handler from ground-truth data              | Critical |
| `ipc_context.is_com_method = YES`     | Confirmed COM vtable method from ground-truth data        | High     |
| `indirect_call_count > 0`             | Unresolved indirect/vtable calls present                  | Medium   |
| `data_quality.has_issues = true`      | Extraction-time errors may affect analysis accuracy       | Medium   |

### Reachability Triage

- **Direct Export**: Function IS the export -- immediate attack surface, highest priority
- **Reachable from Export (1-2 hops)**: Close to the attack surface, high priority
- **Reachable from Export (3+ hops)**: Indirect, lower priority but still auditable
- **Not externally reachable**: Internal helper -- lower priority unless called broadly

## Helper Module API

For custom queries beyond the dossier script:

```python
from helpers import open_individual_analysis_db

with open_individual_analysis_db("extracted_dbs/module.db") as db:
    func = db.get_function_by_name("FuncName")[0]

    # Parsed JSON fields
    func.parsed_dangerous_api_calls    # list of API name strings
    func.parsed_simple_outbound_xrefs  # list of xref dicts
    func.parsed_simple_inbound_xrefs   # list of xref dicts
    func.parsed_global_var_accesses    # list of {address, name, access_type}
    func.parsed_loop_analysis          # {loops: [...], loop_count: N}
    func.parsed_stack_frame            # {local_vars_size, ...}

    # File-level data
    file_info = db.get_file_info()
    file_info.parsed_exports           # list of export dicts
```

See [data_format_reference.md](../../docs/data_format_reference.md) for full field documentation.
