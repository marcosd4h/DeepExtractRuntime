"""Parameter surface metadata for function signatures.

Extracts factual parameter characteristics (buffer pointers, handles, COM
interfaces, size parameters, buffer+size pairs) from C-style function
signatures.  Returns structured metadata -- no numeric risk score.
Consumers interpret the facts in context.

Extracted from the map-attack-surface skill for reuse across skills.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from helpers.decompiled_parser import split_arguments

__all__ = [
    "PARAM_TYPE_PATTERNS",
    "BUFFER_SIZE_PAIR_PATTERNS",
    "describe_parameter_surface",
]

PARAM_TYPE_PATTERNS: list[tuple[str, str]] = [
    (r"(?:void|PVOID|LPVOID|char|BYTE|PBYTE|LPBYTE)\s*\*", "buffer_pointer"),
    (r"(?:wchar_t|WCHAR|LPWSTR|PWSTR|OLECHAR)\s*\*", "string_pointer"),
    (r"(?:LPSTR|LPCSTR|PSTR|PCSTR|char\s+const)\s*\*?", "string_pointer"),
    (r"(?:LPCWSTR|PCWSTR|wchar_t\s+const)\s*\*?", "string_pointer"),
    (r"(?:BSTR|VARIANT|SAFEARRAY)", "string_pointer"),
    (r"(?:DWORD|ULONG|SIZE_T|size_t|unsigned|int)\b", "size_or_int"),
    (r"(?:HANDLE|HKEY|HMODULE|HINSTANCE|SOCKET|HWND)", "handle"),
    (r"(?:IUnknown|IDispatch|I[A-Z]\w+)\s*\*", "com_interface"),
    (r"(?:REFIID|REFCLSID|GUID|IID)", "guid"),
    (r"(?:struct|SECURITY_ATTRIBUTES|OVERLAPPED)\s*\*", "struct_pointer"),
    (r"(?:FLAGS|ULONG|DWORD)\b.*(?:flags|options|mode)", "flags"),
]

BUFFER_SIZE_PAIR_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?:void|char|BYTE|wchar_t|WCHAR)\s*\*.*,\s*(?:DWORD|ULONG|SIZE_T|size_t|unsigned|int)\b", re.I),
    re.compile(r"(?:LPVOID|PVOID|LPBYTE|PBYTE)\s.*,\s*(?:DWORD|ULONG|SIZE_T|size_t|unsigned)\b", re.I),
    re.compile(r"(?:LPWSTR|LPSTR|PWSTR|PSTR)\s.*,\s*(?:DWORD|ULONG|SIZE_T|int|unsigned)\b", re.I),
]


def describe_parameter_surface(signature: Optional[str]) -> dict[str, Any]:
    """Extract factual parameter characteristics from a function signature.

    Returns structured metadata -- no numeric risk score.
    Consumers interpret the facts in context.
    """
    empty: dict[str, Any] = {
        "param_count": 0,
        "has_buffer_pointer": False,
        "has_string_pointer": False,
        "has_size_param": False,
        "has_buffer_size_pair": False,
        "has_handle": False,
        "has_com_interface": False,
        "has_struct_pointer": False,
        "has_flags_param": False,
        "pointer_param_count": 0,
        "characteristics": [],
    }
    if not signature:
        return empty

    has_pair = any(pat.search(signature) for pat in BUFFER_SIZE_PAIR_PATTERNS)

    paren_match = re.search(r"\(([^)]*)\)", signature)
    if not paren_match:
        result = dict(empty)
        if has_pair:
            result["has_buffer_size_pair"] = True
            result["characteristics"] = ["buffer+size pair"]
        return result

    param_str = paren_match.group(1)
    if not param_str.strip() or param_str.strip().lower() in ("void", ""):
        return empty

    params = split_arguments(param_str)

    categories_seen: set[str] = set()
    pointer_count = 0

    for param in params:
        for pattern, category in PARAM_TYPE_PATTERNS:
            if re.search(pattern, param, re.I):
                categories_seen.add(category)
                if category in ("buffer_pointer", "string_pointer",
                                "com_interface", "struct_pointer"):
                    pointer_count += 1
                break

    characteristics: list[str] = []
    if has_pair:
        characteristics.append("buffer+size pair")
    if "buffer_pointer" in categories_seen:
        characteristics.append("buffer pointer")
    if "string_pointer" in categories_seen:
        characteristics.append("string pointer")
    if "com_interface" in categories_seen:
        characteristics.append("COM interface pointer")
    if "handle" in categories_seen:
        characteristics.append("handle parameter")
    if "struct_pointer" in categories_seen:
        characteristics.append("struct pointer")
    if "flags" in categories_seen:
        characteristics.append("flags/options parameter")

    return {
        "param_count": len(params),
        "has_buffer_pointer": "buffer_pointer" in categories_seen,
        "has_string_pointer": "string_pointer" in categories_seen,
        "has_size_param": "size_or_int" in categories_seen,
        "has_buffer_size_pair": has_pair,
        "has_handle": "handle" in categories_seen,
        "has_com_interface": "com_interface" in categories_seen,
        "has_struct_pointer": "struct_pointer" in categories_seen,
        "has_flags_param": "flags" in categories_seen,
        "pointer_param_count": pointer_count,
        "characteristics": characteristics,
    }
