# Analyze IDA Decompiled -- Reference

## IDA Hex-Rays Type Cast Reference

| Cast | Size | C Equivalent |
|------|------|-------------|
| `_BYTE` | 1 byte | `uint8_t` / `char` |
| `_WORD` | 2 bytes | `uint16_t` / `short` |
| `_DWORD` | 4 bytes | `uint32_t` / `int` |
| `_QWORD` | 8 bytes | `uint64_t` / `__int64` |
| `_OWORD` | 16 bytes | `__int128` / SSE register |
| `LOBYTE(x)` | low byte of x | `(uint8_t)(x)` |
| `HIBYTE(x)` | high byte of x | `(uint8_t)((x) >> 8)` |
| `LOWORD(x)` | low 16 bits of x | `(uint16_t)(x)` |
| `HIWORD(x)` | high 16 bits of x | `(uint16_t)((x) >> 16)` |
| `LODWORD(x)` | low 32 bits of 64-bit x | `(uint32_t)(x)` |
| `HIDWORD(x)` | high 32 bits of 64-bit x | `(uint32_t)((x) >> 32)` |
| `BYTE1(x)` | 2nd byte | `(uint8_t)((x) >> 8)` |
| `BYTE2(x)` | 3rd byte | `(uint8_t)((x) >> 16)` |
| `BYTE3(x)` | 4th byte | `(uint8_t)((x) >> 24)` |

## Struct Field Offset Calculation

When IDA shows pointer arithmetic like `*(TYPE*)(base + offset)`:

```
*((_QWORD *)a1 + N)  -> byte offset = N * 8   (QWORD = 8 bytes)
*((_DWORD *)a1 + N)  -> byte offset = N * 4   (DWORD = 4 bytes)
*((_WORD *)a1 + N)   -> byte offset = N * 2   (WORD = 2 bytes)
*((_BYTE *)a1 + N)   -> byte offset = N * 1   (BYTE = 1 byte)
```

Mixed casts to the same base pointer reveal different fields of the same struct:

```cpp
*((_QWORD *)a1 + 0)   // offset 0x00: QWORD field (likely vtable pointer)
*((_DWORD *)a1 + 4)   // offset 0x10: DWORD field
*((_BYTE *)a1 + 24)   // offset 0x18: BYTE field (flag or status)
```

## COM VTable Slot Reference

Standard COM IUnknown vtable layout:

| Slot | Offset | Method |
|------|--------|--------|
| 0 | +0x00 | QueryInterface |
| 1 | +0x08 | AddRef |
| 2 | +0x10 | Release |

IDispatch extends IUnknown:

| Slot | Offset | Method |
|------|--------|--------|
| 3 | +0x18 | GetTypeInfoCount |
| 4 | +0x20 | GetTypeInfo |
| 5 | +0x28 | GetIDsOfNames |
| 6 | +0x30 | Invoke |

## x64 Calling Convention (Microsoft __fastcall)

| Parameter | Register | Stack |
|-----------|----------|-------|
| 1st integer/pointer | RCX | -- |
| 2nd integer/pointer | RDX | -- |
| 3rd integer/pointer | R8 | -- |
| 4th integer/pointer | R9 | -- |
| 5th+ | -- | RSP+0x28, RSP+0x30, ... |
| 1st float/double | XMM0 | -- |
| 2nd float/double | XMM1 | -- |
| 3rd float/double | XMM2 | -- |
| 4th float/double | XMM3 | -- |
| Return value | RAX (integer) / XMM0 (float) | -- |

Shadow space: 32 bytes (RSP+0x08 through RSP+0x20) reserved by caller.

## HRESULT Error Handling Patterns

```cpp
// Standard FAILED() check
hr = SomeFunction(...);
if ( hr < 0 )           // FAILED(hr) -- negative HRESULT means failure
    goto cleanup;

// SUCCEEDED() check
if ( hr >= 0 )          // SUCCEEDED(hr)
    DoMoreWork();

// Common HRESULT values
// S_OK = 0x00000000
// S_FALSE = 0x00000001
// E_FAIL = 0x80004005
// E_INVALIDARG = 0x80070057
// E_OUTOFMEMORY = 0x8007000E
// E_NOINTERFACE = 0x80004002
// E_ACCESSDENIED = 0x80070005
```

## Library Tag Reference

Functions in `function_index.json` have a `library` field:

| Tag | Meaning | Action |
|-----|---------|--------|
| `null` | Application code | Analyze -- this is the interesting code |
| `WIL` | Windows Implementation Library | Skip -- telemetry, error helpers, feature flags |
| `STL` | C++ Standard Library | Skip -- std::string, std::vector, etc. |
| `WRL` | Windows Runtime Library | Context -- COM infrastructure, may reveal interfaces |
| `CRT` | C Runtime | Skip -- malloc, memcpy wrappers |
| `ETW/TraceLogging` | Event Tracing for Windows | Skip -- telemetry instrumentation |

## file_info.json Section Cross-Reference

| Analysis Question | file_info.json Section |
|------------------|----------------------|
| What binary is this? | `basic_file_info` |
| Who built it? | `pe_version_info`, `rich_header` |
| What APIs does it call? | `imports` |
| What does it export? | `exports` |
| Is ASLR/DEP/CFG enabled? | `security_features` |
| What classes exist? | `function_summary.class_methods` |
| How many functions total? | `function_summary.total_functions` |
| Are there TLS callbacks? | `tls_callbacks` |
| What PE sections exist? | `sections` |
