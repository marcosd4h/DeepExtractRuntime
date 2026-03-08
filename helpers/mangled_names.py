"""Microsoft C++ mangled name parsing.

Consolidates ``parse_class_from_mangled()`` which was duplicated across
``batch-lift``, ``reconstruct-types``, and ``code-lifter`` with diverging
implementations.  The canonical version here is the most complete variant
(from ``reconstruct-types``), handling full namespace resolution, access
level detection, and virtual method classification.
"""

from __future__ import annotations

from typing import Any, Optional


def parse_class_from_mangled(mangled: str) -> Optional[dict[str, Any]]:
    """Extract class/method info from a Microsoft C++ mangled name.

    Returns dict with keys:
        class_name, full_qualified_name, namespaces, role,
        method_name (if role=='method'), access (if detectable), mangled
    Returns None for non-C++ or unparseable names.
    """
    if not mangled or not mangled.startswith("?"):
        return None

    is_ctor = mangled.startswith("??0")
    is_dtor = mangled.startswith("??1")
    is_vdel = mangled.startswith("??_G")
    is_vftable = mangled.startswith("??_7")

    # Determine prefix length and skip prefix
    if is_vftable:
        rest = mangled[4:]
    elif is_ctor or is_dtor:
        rest = mangled[3:]
    elif is_vdel:
        rest = mangled[4:]
    else:
        rest = mangled[1:]

    parts = rest.split("@")
    try:
        end = parts.index("")
    except ValueError:
        return None

    if is_vftable:
        if end < 1:
            return None
        class_name = parts[0]
        namespaces = list(reversed(parts[1:end]))
        full_name = "::".join(namespaces + [class_name]) if namespaces else class_name
        return {
            "class_name": class_name, "full_qualified_name": full_name,
            "namespaces": namespaces, "role": "vftable", "mangled": mangled,
        }

    if is_ctor or is_dtor or is_vdel:
        if end < 1:
            return None
        class_name = parts[0]
        namespaces = list(reversed(parts[1:end]))
        full_name = "::".join(namespaces + [class_name]) if namespaces else class_name
        role = "constructor" if is_ctor else ("destructor" if is_dtor else "vdel_destructor")
        return {
            "class_name": class_name, "full_qualified_name": full_name,
            "namespaces": namespaces, "role": role, "mangled": mangled,
        }

    # Regular method: ?Method@Class@Namespace@@encoding...
    if end < 2:
        return None

    method_name = parts[0]
    class_name = parts[1]
    namespaces = list(reversed(parts[2:end]))
    full_name = "::".join(namespaces + [class_name]) if namespaces else class_name

    # Detect access/virtual from encoding after @@
    access = "unknown"
    after_sep = mangled.split("@@")[1] if "@@" in mangled else ""
    if after_sep[:4] in ("UEAA", "UEBA", "UEAH"):
        access = "public_virtual"
    elif after_sep[:3] in ("UEA",):
        access = "public_virtual"
    elif after_sep[:4] in ("QEAA", "QEBA"):
        access = "public"
    elif after_sep[:3] in ("QEA",):
        access = "public"
    elif after_sep[:4] in ("AEAA", "AEBA"):
        access = "private"
    elif after_sep[:4] in ("IEAA", "IEBA"):
        access = "protected"

    return {
        "class_name": class_name, "full_qualified_name": full_name,
        "namespaces": namespaces, "role": "method", "method_name": method_name,
        "access": access, "mangled": mangled,
    }
