# Taint Vulnerability Patterns for AI-Driven Analysis

Reference patterns for AI-driven taint analysis of IDA Pro decompiled Windows PE
binaries. Each pattern describes a vulnerability class where attacker-controlled
data flows unsanitized to a dangerous sink. Use these during taint tracing to
identify vulnerable data-flow shapes.

---

## 1. Unchecked Buffer Size Propagation

**Name**: Unchecked Buffer Size Propagation

**Description**: An RPC or network parameter specifying a buffer length is used
directly as the size argument to `memcpy`, `memmove`, or similar copy operation
without validation against the actual destination buffer capacity. The tainted
size flows from the entry point to the copy sink with no intervening bounds check.

**Decompiled Code Example**:

```c
__int64 __fastcall NetrShareSetInfo(
    handle_t binding,
    unsigned int level,
    __int64 info_buf,
    unsigned int info_size)    // attacker-controlled from RPC
{
  char *dest;
  dest = (char *)HeapAlloc(hHeap, 0, 0x100);
  if ( dest )
    memcpy(dest, (const void *)info_buf, info_size);  // tainted size, no check
  return 0;
}
```

**What to Look For**:
- Same parameter (or derived value) used as both source pointer and size in copy
- No comparison of size against allocation size or buffer capacity before copy
- RPC/COM/export parameters flowing to `memcpy` / `memmove` / `RtlCopyMemory` third argument

**Common Mitigations**:
- Explicit bounds check: `if (info_size > 0x100) return ERROR_INVALID_PARAMETER`
- Safe wrappers: `memcpy_s`, `RtlCopyMemory` with pre-validated size
- Use of `UIntMult` or similar to cap size before allocation

---

## 2. Registry Value to File Path

**Name**: Registry Value to File Path

**Description**: A value read from the registry (e.g., via `RegQueryValueExW`) is
used as or concatenated into a file path passed to `CreateFileW`, `CreateFile2`,
or `NtCreateFile` without path canonicalization, traversal checks, or whitelist
validation. Attacker-controlled registry keys or values enable path traversal or
arbitrary file access.

**Decompiled Code Example**:

```c
void __fastcall LoadConfigFromRegistry()
{
  wchar_t path_buf[260];
  DWORD size = sizeof(path_buf);
  if ( RegQueryValueExW(hKey, L"ConfigPath", 0, 0, (LPBYTE)path_buf, &size) == 0 )
  {
    HANDLE hFile = CreateFileW(path_buf, GENERIC_READ, FILE_SHARE_READ, 0,
                               OPEN_EXISTING, 0, 0);  // tainted path, no sanitization
    if ( hFile != INVALID_HANDLE_VALUE )
      ReadConfig(hFile);
  }
}
```

**What to Look For**:
- `RegQueryValueEx*` output used in `CreateFile*`, `Path*` APIs, or string concatenation
- No `PathCchCanonicalize`, `GetFullPathName`, or traversal sequence checks (`..\\`)
- Registry value directly passed to file-opening APIs

**Common Mitigations**:
- Path canonicalization before use
- Whitelist of allowed prefixes or base directories
- Validation that the resolved path is under an allowed root

---

## 3. RPC Parameter to Privileged Operation

**Name**: RPC Parameter to Privileged Operation

**Description**: An RPC handler parameter (e.g., a pointer, DACL, or security
descriptor) flows to a privileged security API such as `SetSecurityInfo`,
`SetNamedSecurityInfo`, or `SetKernelObjectSecurity` without re-validation at the
trust boundary. The RPC interface is attacker-reachable; the security operation
runs in a privileged context.

**Decompiled Code Example**:

```c
NET_API_STATUS __fastcall NetrShareSetSecurity(
    handle_t binding,
    LPCWSTR share_name,
    SECURITY_INFORMATION sec_info,
    __int64 security_descriptor)  // attacker-controlled from RPC
{
  HANDLE hShare = OpenShareHandle(share_name);
  if ( !hShare ) return NERR_InvalidDevice;
  SetSecurityInfo(hShare, SE_LMSHARE, sec_info, 0, 0, (PACL)security_descriptor, 0);
  return NERR_Success;
}
```

**What to Look For**:
- RPC/COM parameters reaching `SetSecurityInfo`, `SetNamedSecurityInfo`, `SetKernelObjectSecurity`
- No integrity or format validation of the security descriptor before use
- Trust boundary crossing (low-trust RPC caller -> high-trust system service)

**Common Mitigations**:
- Validate security descriptor format and ACL structure before applying
- Limit which `SECURITY_INFORMATION` flags are accepted
- Use kernel or trusted helper to validate rather than applying raw client data

---

## 4. COM Activation with Tainted CLSID

**Name**: COM Activation with Tainted CLSID

**Description**: A CLSID or class name that is attacker-influenced (from RPC,
file, registry, or other untrusted source) is passed to `CoCreateInstance`,
`CoGetClassObject`, or equivalent without validation against an allowlist. An
attacker can redirect activation to a malicious COM server.

**Decompiled Code Example**:

```c
HRESULT __fastcall CreateHelperByClsid(__int64 clsid_ptr)  // from RPC / config
{
  CLSID clsid;
  memcpy(&clsid, clsid_ptr, 16);  // tainted CLSID
  return CoCreateInstance(&clsid, 0, CLSCTX_LOCAL_SERVER, &IID_IClassFactory,
                          (void **)&pFactory);  // no allowlist check
}
```

**What to Look For**:
- CLSID or ProgID derived from untrusted input before `CoCreateInstance` / `CoGetClassObject`
- No comparison against a fixed allowlist of permitted CLSIDs
- CLSID coming from struct/parameter that traces to RPC, file, or registry

**Common Mitigations**:
- Hardcoded allowlist of CLSIDs; reject any that do not match
- Mapping from validated input (e.g., enum) to known CLSID
- Restriction of activation context (e.g., in-process only, specific servers)

---

## 5. Tainted Array Index

**Name**: Tainted Array Index

**Description**: A user-supplied or otherwise attacker-controlled value is used
as an array index or structure field offset without bounds checking. This can
lead to out-of-bounds read/write, information disclosure, or controlled
memory corruption depending on how the indexed value is used.

**Decompiled Code Example**:

```c
__int64 __fastcall GetHandlerByIndex(unsigned int index, __int64 handlers)
{
  if ( !handlers ) return 0;
  return *(__int64 *)(handlers + 8 * index);  // index unbounded; no count check
}

void __fastcall DispatchRequest(unsigned int opcode, __int64 args)
{
  void (*handler)(__int64) = GetHandlerByIndex(opcode, g_handler_table);  // tainted index
  if ( handler )
    handler(args);
}
```

**What to Look For**:
- Parameter used in `array[index]`, `*(base + index * size)`, or vtable slot indexing
- No comparison of index against array length or max valid value
- RPC/export parameters flowing to index calculations

**Common Mitigations**:
- Explicit bounds check: `if (index >= count) return error`
- Use of `__analysis_assume`-style annotations (not sufficient alone)
- Sanitization to known enum or capped range before use

---

## 6. Return Value Cross-Trust Propagation

**Name**: Return Value Cross-Trust Propagation

**Description**: A return value from a lower-trust module (e.g., user-mode
DLL, RPC stub, or IPC layer) is used unsanitized in a higher-trust context.
The callee may be coerced or compromised to return attacker-controlled data,
which is then trusted by the caller and passed to a dangerous sink.

**Decompiled Code Example**:

```c
void __fastcall ProcessClientRequest(__int64 client_ctx)
{
  __int64 path = GetClientPath(client_ctx);   // from user-mode RPC; may be tainted
  DWORD attr = GetFileAttributesW(path);      // path used without validation
  if ( attr != INVALID_FILE_ATTRIBUTES )
    ApplyPolicy(path, attr);                  // tainted path in privileged path
}
```

**What to Look For**:
- Call to module across trust boundary (user->kernel, RPC client->server, different IL)
- Return value used immediately in file/registry/security APIs without validation
- Assumption that callee "must" return safe data without explicit contract

**Common Mitigations**:
- Re-validate all data crossing trust boundaries (path canonicalization, format checks)
- Use of hardened parsing and allowlists on the trusted side
- Cryptographic or integrity checks when returning sensitive data from low-trust code

---

## 7. Named Pipe Impersonation Gap

**Name**: Named Pipe Impersonation Gap

**Description**: After impersonating a client over a named pipe (e.g., via
`ImpersonateNamedPipeClient`), the server performs operations using tainted
data (path, token attributes, etc.) while still impersonating, but fails to
call `RevertToSelf` (or equivalent) before a critical operation, or performs
a privileged action on tainted data after reverting. This can lead to
confused deputy or privilege misuse.

**Decompiled Code Example**:

```c
void __fastcall HandlePipeRequest(HANDLE hPipe)
{
  if ( !ImpersonateNamedPipeClient(hPipe) ) return;
  wchar_t path[260];
  ReadFromPipe(hPipe, path, sizeof(path));    // tainted path from client
  ProcessFile(path);                          // processes while impersonating
  // Missing: RevertToSelf() before or after?
  DoPrivilegedCleanup(path);                  // path still tainted; may run as self
  RevertToSelf();                             // reverted too late
}
```

**What to Look For**:
- `ImpersonateNamedPipeClient` / `ImpersonateLoggedOnUser` paired with file/registry/process ops on tainted data
- No `RevertToSelf` between impersonation and privileged operation, or reversion after tainted use
- Tainted data (path, handles) used in security-sensitive calls during or after impersonation

**Common Mitigations**:
- Call `RevertToSelf` before any privileged operation on tainted data
- Validate and canonicalize all client-provided paths before use
- Restrict what operations run while impersonating

---

## 8. Integer Overflow in Size Calculation

**Name**: Integer Overflow in Size Calculation

**Description**: Attacker-controlled size or count participates in arithmetic
(multiplication, addition) before the result is passed to an allocator or
copy operation. If the arithmetic overflows, the resulting size is smaller
than intended, leading to undersized allocation and subsequent overflow when
the original (unchecked) count or size is used for copying or indexing.

**Decompiled Code Example**:

```c
__int64 __fastcall AllocAndCopyItems(__int64 items, unsigned int count)
{
  unsigned int alloc_size = count * 0x28;     // tainted count; can overflow
  void *buf = HeapAlloc(hHeap, 0, alloc_size);
  if ( !buf ) return E_OUTOFMEMORY;
  for ( i = 0; i < count; ++i )
    memcpy((char *)buf + i * 0x28, *(const void **)(items + 8 * i), 0x28);
  return 0;
}
```

**What to Look For**:
- Multiplication or addition of tainted size/count before `HeapAlloc` / `LocalAlloc` / `malloc`
- Loop bound or copy size using original tainted value while allocation uses computed size
- No `UIntMult`, `SizeTAdd`, or overflow-checked arithmetic

**Common Mitigations**:
- `UIntMult`, `UIntAdd`, `SizeTAdd` from the safe integer library
- Explicit overflow check before allocation
- Separate validation of count and element size before computing total size

---

## Summary

When tracing taint, prioritize paths where:

- Attacker-controlled parameters reach **size arguments** of memcpy/HeapAlloc
- Registry/file/network data reaches **path arguments** of CreateFile/security APIs
- **Cross-trust** data flows (RPC -> privileged ops, low-IL return values)
- **Impersonation** scope overlaps with tainted data use
- **Arithmetic** on tainted sizes before allocation or indexing

Always verify against assembly when the decompiled code suggests one of these patterns; see `decompiler_pitfalls.md` for common Hex-Rays misreadings.
