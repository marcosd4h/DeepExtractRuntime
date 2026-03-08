# COM / WRL Interface Reconstruction -- Technical Reference

Detailed reference for COM interface reconstruction from decompiled binaries.

---

## COM Fundamentals in Decompiled Code

### IUnknown Virtual Method Table

Every COM interface inherits from IUnknown. In decompiled code, vtable calls appear as:

```cpp
// QueryInterface (vtable slot 0, offset +0x00)
result = (*((__int64 (__fastcall **)(__int64, const GUID *, void **))(*a1) + 0))(a1, &riid, &ppv);

// AddRef (vtable slot 1, offset +0x08)
(*((__int64 (__fastcall **)(__int64))(*a1) + 1))(a1);

// Release (vtable slot 2, offset +0x10)
(*((__int64 (__fastcall **)(__int64))(*a1) + 2))(a1);
```

Pattern: `(*a1)` dereferences the vtable pointer at offset 0 of the object. `+ N` indexes into the vtable. Each slot is 8 bytes on x64.

### QueryInterface Dispatch Patterns

QI implementations typically compare the requested IID against known interface GUIDs:

```cpp
// Pattern 1: Sequential GUID comparison
HRESULT __fastcall CMyClass::QueryInterface(CMyClass *this, const GUID *riid, void **ppvObj)
{
    if (IsEqualGUID(riid, &IID_IUnknown) || IsEqualGUID(riid, &IID_IMyInterface))
    {
        *ppvObj = this;
        this->AddRef();
        return S_OK;
    }
    *ppvObj = NULL;
    return E_NOINTERFACE;
}

// Pattern 2: Decompiled GUID comparison (common in IDA output)
if ( *riid == 0x00000000 && *(riid + 4) == 0x0000 && *(riid + 6) == 0x0000
     && *(BYTE *)(riid + 8) == 0xC0 && ... )
    // This is IID_IUnknown = {00000000-0000-0000-C000-000000000046}

// Pattern 3: Delegating QI (WRL pattern)
HRESULT QueryInterface(REFIID riid, void **ppv) {
    return RuntimeClassImpl::QueryInterface(riid, ppv);
}
```

### AddRef/Release Patterns

```cpp
// Typical AddRef -- interlocked increment
ULONG __fastcall CMyClass::AddRef(CMyClass *this) {
    return _InterlockedIncrement((volatile LONG *)&this->m_refCount);
}

// Typical Release -- interlocked decrement + destroy on zero
ULONG __fastcall CMyClass::Release(CMyClass *this) {
    ULONG ref = _InterlockedDecrement((volatile LONG *)&this->m_refCount);
    if (ref == 0)
        this->Release_destructor(1);   // or: operator delete(this)
    return ref;
}
```

Reference count field is typically at offset +0x08 or +0x10 (after vtable pointer(s)).

---

## WRL Template Decoding

### Template Structure in Mangled Names

WRL encodes class structure in deeply nested C++ templates. The mangled name contains:

```
Microsoft::WRL::Details::RuntimeClassImpl<
    Microsoft::WRL::RuntimeClassFlags<N>,  // N=1(WinRt), 2(ClassicCom), 3(Mix)
    1,                                      // Weak reference support (1=yes, 0=no)
    1,                                      // IInspectable support
    0,                                      // Reserved
    Interface1,                             // First implemented interface
    Interface2,                             // Second implemented interface
    ...
    Microsoft::WRL::FtmBase                 // Free-threaded marshalling (if present)
>
```

### RuntimeClassFlags Values

| Value | Name | Base Interface | Description |
|-------|------|----------------|-------------|
| 1 | `WinRt` | IInspectable | Windows Runtime class |
| 2 | `ClassicCom` | IUnknown | Classic COM class |
| 3 | `WinRtClassicComMix` | Both | Hybrid class |

### Key WRL Types

| Type | Purpose | Information Encoded |
|------|---------|---------------------|
| `RuntimeClassImpl<Flags, ...Interfaces>` | Class implementation | Interface list, flags |
| `RuntimeClass<Flags, ...Interfaces>` | Public class type | Same as RuntimeClassImpl |
| `ComPtr<IFoo>` | Smart pointer | Interface usage at call site |
| `WeakReferenceImpl` | Weak reference support | Target class supports weak refs |
| `FtmBase` | Free-threaded marshalling | Class is apartment-agile |
| `ImplementsHelper<Flags, N, ...Ifaces>` | Interface enumeration | Recursive interface list |
| `RuntimeClassBaseT<N>` | Base class helpers | `AsIID`, `GetImplementedIIDS` |
| `HStringReference` | WinRT string wrapper | WinRT string usage |

### Extracting Interfaces from RuntimeClassImpl

From a mangled name like:
```
RuntimeClassImpl<RuntimeClassFlags<2>, 1, 0, 0, IAsyncOperationCompletedHandler<T>, FtmBase>
```

Extract:
1. **Flags**: `RuntimeClassFlags<2>` = ClassicCom
2. **Weak ref support**: `1` (yes)
3. **IInspectable**: `0` (no)
4. **Interfaces**: `IAsyncOperationCompletedHandler<T>`, plus `FtmBase` (marshalling mixin)

### FillArrayWithIid Functions

WRL generates `FillArrayWithIid` methods that enumerate supported IIDs. The `ImplementsHelper` chain reveals the full interface tree:

```
ImplementsHelper<RuntimeClassFlags<3>, 0, IFoo, IWeakReferenceSource, FtmBase>::FillArrayWithIid
ImplementsHelper<RuntimeClassFlags<3>, 1, IWeakReferenceSource, FtmBase>::FillArrayWithIid
```

The position index (0, 1, ...) shows the iteration order. Interface at position 0 is the primary interface.

---

## VTable Context Analysis

### vtable_contexts JSON Format

```json
[
  {
    "extraction_type": "detailed_vtable_analysis",
    "reconstructed_classes": [
      "class ClassName {\npublic:\n    virtual Method1();\n    virtual Method2();\n};"
    ],
    "source_ea": "0x180012345"
  }
]
```

### Mapping VTable Slots to COM Methods

Given a reconstructed vtable:
```
Slot 0: QueryInterface    → IUnknown (always)
Slot 1: AddRef            → IUnknown
Slot 2: Release           → IUnknown
Slot 3+: Custom methods   → Specific interface
```

For IInspectable-based (WinRT):
```
Slot 0-2: IUnknown methods
Slot 3: GetIids           → IInspectable
Slot 4: GetRuntimeClassName → IInspectable
Slot 5: GetTrustLevel     → IInspectable
Slot 6+: Custom methods   → Specific interface
```

### Multiple VTable Pointers

COM classes implementing multiple interfaces have multiple vtable pointers at different offsets in the object. The primary vtable is at offset 0. Secondary vtables use `adjustor{N}` thunks (visible in function names like `QueryInterface'adjustor{8}'`), where N is the byte offset of the secondary vtable pointer.

---

## Class Factory Detection

### DllGetClassObject Pattern

```cpp
HRESULT __stdcall DllGetClassObject(const CLSID *rclsid, const IID *riid, void **ppv)
{
    // Compare rclsid against known CLSIDs
    if (IsEqualCLSID(rclsid, &CLSID_MyClass))
        return CMyClassFactory::CreateInstance(riid, ppv);
    return CLASS_E_CLASSNOTAVAILABLE;
}
```

### IClassFactory Pattern

```cpp
HRESULT CMyClassFactory::CreateInstance(IUnknown *pUnkOuter, REFIID riid, void **ppv)
{
    CMyClass *obj = new CMyClass();
    if (!obj) return E_OUTOFMEMORY;
    HRESULT hr = obj->QueryInterface(riid, ppv);
    obj->Release();
    return hr;
}
```

---

## Database Queries for COM Reconstruction

### Find All QI Implementations

```sql
SELECT function_id, function_name, mangled_name, function_signature
FROM functions
WHERE (function_name LIKE '%QueryInterface%'
    OR function_name LIKE '%AddRef%'
    OR function_name LIKE '%Release%')
  AND mangled_name IS NOT NULL
ORDER BY function_name;
```

### Find All WRL Functions

```sql
SELECT function_name, mangled_name
FROM functions
WHERE function_name LIKE '%Microsoft::WRL%'
ORDER BY function_name;
```

### Find VTable Symbols

```sql
SELECT function_name, mangled_name
FROM functions
WHERE mangled_name LIKE '??_7%'  -- VFTable symbols
ORDER BY function_name;
```

### Find Functions with VTable Call Xrefs

```sql
SELECT function_name, outbound_xrefs
FROM functions
WHERE outbound_xrefs LIKE '%is_vtable_call%'
  AND outbound_xrefs LIKE '%true%'
LIMIT 20;
```

### Find COM API Callers

```sql
SELECT function_name, simple_outbound_xrefs
FROM functions
WHERE simple_outbound_xrefs LIKE '%CoCreateInstance%'
   OR simple_outbound_xrefs LIKE '%CoInitialize%'
   OR simple_outbound_xrefs LIKE '%DllGetClassObject%'
   OR simple_outbound_xrefs LIKE '%RegisterClassObject%';
```

---

## Script Output Formats

### scan_com_interfaces.py --json

```json
{
  "module": "appinfo.dll",
  "com_summary": {
    "total_com_classes": 5,
    "total_interfaces_found": 12,
    "qi_implementations": 6,
    "addref_implementations": 4,
    "release_implementations": 8,
    "wrl_classes": 3,
    "vtable_functions": 114,
    "com_api_callers": 2
  },
  "qi_implementations": [
    {
      "function_id": 892,
      "function_name": "...::QueryInterface",
      "class_name": "RuntimeClassImpl<...>",
      "mangled_name": "?QueryInterface@...",
      "has_adjustor": false
    }
  ],
  "vtable_interfaces": [
    {
      "source_function_id": 42,
      "class_name": "CAppInfoService",
      "methods": ["QueryInterface", "AddRef", "Release", "Initialize", "GetInfo"],
      "slot_count": 5,
      "is_iunknown_based": true
    }
  ]
}
```

### decode_wrl_templates.py --json

```json
{
  "module": "appinfo.dll",
  "wrl_classes": [
    {
      "class_name": "FTMEventDelegate",
      "runtime_class_flags": 2,
      "flags_meaning": "ClassicCom",
      "weak_reference_support": true,
      "iinspectable_support": false,
      "interfaces": [
        "IAsyncOperationCompletedHandler<UserSelectionResult*>"
      ],
      "has_ftm_base": true,
      "source_functions": [889, 890, 891]
    }
  ],
  "comptr_usage": [
    {"interface": "IUnknown", "function_ids": [42]},
    {"interface": "IActivationFactory", "function_ids": [100, 101]}
  ]
}
```

### map_class_interfaces.py --json

```json
{
  "module": "appinfo.dll",
  "class_interface_map": {
    "FTMEventDelegate": {
      "interfaces": ["IAsyncOperationCompletedHandler<...>", "IUnknown", "IMarshal"],
      "evidence": {
        "IAsyncOperationCompletedHandler<...>": ["wrl_template", "qi_dispatch"],
        "IUnknown": ["inherent"],
        "IMarshal": ["ftm_base"]
      },
      "runtime_class_flags": 2,
      "supports_weak_ref": true,
      "has_ftm": true
    }
  }
}
```

### generate_idl.py output

```idl
// Reconstructed from: appinfo.dll
// Auto-generated -- slot offsets from vtable analysis

[uuid(unknown)]
interface IAppInfoService : IUnknown
{
    // Slot 3 (+0x18)
    HRESULT Initialize();

    // Slot 4 (+0x20)
    HRESULT GetInfo([in] LPCWSTR appPath, [out] AppInfo **ppInfo);

    // Slot 5 (+0x28)
    HRESULT Shutdown();
};
```

---

## Known Limitations

1. **GUID values**: CLSIDs/IIDs often appear as inline constants in decompiled code rather than named symbols. The scanner detects GUID-like patterns but cannot always resolve them to well-known IID names.
2. **Incomplete vtable reconstruction**: IDA may not fully resolve all vtable slots, especially for classes with multiple inheritance.
3. **Adjustor thunks**: Secondary vtable thunks indicate multi-interface classes but may not always be paired correctly.
4. **WRL template depth**: Deeply nested WRL templates may have mangled names truncated by IDA or the DB.
5. **COM aggregation**: Inner/outer unknown patterns require manual analysis of CreateInstance implementations.
