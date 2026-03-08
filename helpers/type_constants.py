"""IDA type size mappings and C type translation tables.

Consolidates ``TYPE_SIZES``, ``IDA_TO_C_TYPE``, and ``SIZE_TO_C_TYPE``
dictionaries that were previously duplicated across ``batch-lift``,
``reconstruct-types``, ``type-reconstructor``, and ``code-lifter``.
"""

from __future__ import annotations

# IDA type name -> byte size
TYPE_SIZES: dict[str, int] = {
    "_BYTE": 1, "BYTE": 1, "char": 1, "unsigned char": 1, "bool": 1,
    "_BOOL": 1, "__int8": 1, "unsigned __int8": 1,
    "_WORD": 2, "WORD": 2, "short": 2, "unsigned short": 2,
    "__int16": 2, "unsigned __int16": 2,
    "_DWORD": 4, "DWORD": 4, "int": 4, "unsigned int": 4,
    "LONG": 4, "__int32": 4, "unsigned __int32": 4, "HRESULT": 4,
    "_QWORD": 8, "QWORD": 8, "__int64": 8, "unsigned __int64": 8,
}

# IDA type name -> C standard type (for header generation)
IDA_TO_C_TYPE: dict[str, str] = {
    "_BYTE": "uint8_t", "BYTE": "uint8_t", "char": "char",
    "bool": "bool", "_BOOL": "bool",
    "_WORD": "uint16_t", "WORD": "uint16_t", "short": "int16_t",
    "_DWORD": "uint32_t", "DWORD": "uint32_t", "int": "int32_t",
    "LONG": "LONG", "HRESULT": "HRESULT",
    "_QWORD": "uint64_t", "QWORD": "uint64_t",
    "__int64": "int64_t", "unsigned __int64": "uint64_t",
}

# Field byte-size -> default C type
SIZE_TO_C_TYPE: dict[int, str] = {
    1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t",
}
