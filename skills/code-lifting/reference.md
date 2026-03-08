# Code Lifting Reference

## Contents

- IDA Naming Patterns
- Assembly-to-C++ Quick Reference
- Common Patterns (COM/WRL, unique_ptr, HRESULT, Locks, SEH, Memory, Callbacks)

## IDA Naming Patterns

| Pattern                                  | Meaning                                   |
| ---------------------------------------- | ----------------------------------------- |
| `a1`, `a2`                               | Parameters (positional order)             |
| `v1`, `v2`                               | Auto-named local variables                |
| `sub_XXXX`                               | Unnamed function at address XXXX          |
| `off_XXXX` / `dword_XXXX` / `qword_XXXX` | Data at address XXXX                      |
| `LODWORD(x)` / `HIDWORD(x)`              | Low/high 32 bits of 64-bit value          |
| `__fastcall`                             | x64 calling convention (rcx, rdx, r8, r9) |
| `__imp_Func`                             | Import thunk for `Func`                   |
| `LABEL_N`                                | Decompiler-generated goto target          |
| `_DWORD`, `_QWORD`, `_BYTE`              | IDA sized-access type casts               |
| `wil::*` / `Microsoft::WRL::*`           | WIL telemetry / COM WRL support           |

## Assembly-to-C++ Quick Reference

| Assembly                     | C++ Equivalent                                        |
| ---------------------------- | ----------------------------------------------------- |
| `mov eax, [rcx+20h]`         | `val = *(DWORD*)(ptr + 0x20)`                         |
| `mov rax, [rcx+20h]`         | `val = *(QWORD*)(ptr + 0x20)`                         |
| `lea rax, [rcx+offset]`      | `addr = basePtr + offset`                             |
| `movzx eax, byte ptr [rcx]`  | `val = (BYTE)*(ptr)` -- zero-extend to DWORD          |
| `movsx eax, byte ptr [rcx]`  | `val = (signed char)*(ptr)` -- sign-extend to DWORD   |
| `movzx eax, word ptr [rcx]`  | `val = (WORD)*(ptr)` -- zero-extend 16-bit            |
| `movsx rax, dword ptr [rcx]` | `val = (INT64)(INT32)*(ptr)` -- sign-extend 32->64    |
| `cmp [rcx+10h], 0`           | `if (*(DWORD*)(ptr + 0x10) == 0)`                     |
| `call qword ptr [rax+8]`     | `(*(func_ptr*)(vtable + 0x8))()` -- virtual call      |
| `test eax, eax` / `jz`       | `if (result == 0)`                                    |
| `xor eax, eax`               | `return 0` or `result = 0`                            |
| `rep movsb`                  | `memcpy(rdi, rsi, rcx)` -- byte-granular copy         |
| `rep stosd`                  | `memset(rdi, eax, rcx*4)` -- DWORD-granular fill      |
| `bsr eax, ecx`               | bit scan reverse (find highest set bit)               |
| `bsf eax, ecx`               | bit scan forward (find lowest set bit)                |
| `lock cmpxchg [rcx], edx`    | `InterlockedCompareExchange(ptr, edx, eax)` -- atomic |

## Common Patterns

### COM/WRL Virtual Calls

```cpp
// IDA:  (*((__int64 (__fastcall **)(_QWORD, _QWORD, _QWORD))(*a1) + 0))(a1, riid, ppv);
// Lifted: vtable offset 0 = QueryInterface, 1 = AddRef, 2 = Release
result = pUnknown->lpVtbl->QueryInterface(pUnknown, &riid, &ppvObject);
```

### unique_ptr Move Semantics

```cpp
// IDA: v5 = *a2; *a2 = 0; a1[1] = v5;
// Lifted: move ownership from source to destination, null out source
this->strategy1 = std::move(source1);
```

### HRESULT Error Chains

```cpp
// IDA: if ( v3 < 0 ) goto cleanup;
// Lifted: use FAILED() macro, preserve goto-cleanup when it represents real single-exit cleanup
HRESULT hr = CoCreateInstance(&clsid, NULL, CLSCTX_INPROC_SERVER, &iid, (void **)&pService);
if (FAILED(hr))
    return hr;

hr = pService->Connect(NULL, NULL, NULL, NULL);
if (FAILED(hr))
    goto cleanup;

// ... more operations that share the same cleanup label ...

cleanup:
    pService->Release();
    return hr;
```

### Lock Pair Reconstruction

```cpp
// IDA: EnterCriticalSection(a1 + 0x40); ... LeaveCriticalSection(a1 + 0x40);
// Lifted: ensure lock release appears on ALL exit paths (early return, goto, normal return)
EnterCriticalSection(&manager->lock);  // +0x40

IHandler *handler = manager->activeHandler;  // +0x20
if (!handler) {
    LeaveCriticalSection(&manager->lock);  // release on early exit
    return E_FAIL;
}

HRESULT hr = handler->ProcessRequest(request);
LeaveCriticalSection(&manager->lock);  // release on normal exit
return hr;
```

### SEH Exception Handling

```cpp
// IDA: __try { ... } __finally { ... }
// Lifted: preserve exact structure -- do not simplify into if/else
EnterCriticalSection(&globalLock);
__try {
    result = PerformOperation(context);
}
__finally {
    // __finally ensures lock release even if PerformOperation throws
    LeaveCriticalSection(&globalLock);
}
```

### Memory Lifecycle (Alloc / Use / Free)

```cpp
// IDA: v3 = HeapAlloc(...); ... HeapFree(0, 0, v3);
// Lifted: name after purpose, comment lifecycle
WIDGET *widget = (WIDGET *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WIDGET));
if (!widget)
    return E_OUTOFMEMORY;

// ... use widget ...

HeapFree(GetProcessHeap(), 0, widget);  // ownership ends here
```

### Function Pointer / Callback Dispatch

```cpp
// IDA: (*(void (__fastcall **)(_QWORD, _QWORD))(*(_QWORD *)a1 + 0x48))(a1, a2);
// Lifted: decode vtable offset to named method
pHandler->OnComplete(context);  // vtable slot 9, offset +0x48
```
