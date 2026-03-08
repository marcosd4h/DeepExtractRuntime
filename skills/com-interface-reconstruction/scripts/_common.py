"""Shared utilities for COM/WRL interface reconstruction scripts.

Provides workspace root resolution, WRL template parsing, COM pattern detection,
GUID parsing, mangled name analysis for COM types, and vtable slot mapping.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

_AGENT_DIR = str(Path(__file__).resolve().parents[3])
if _AGENT_DIR not in sys.path:
    sys.path.insert(0, _AGENT_DIR)

from skills._shared import bootstrap, make_db_resolvers

WORKSPACE_ROOT = bootstrap(__file__)

from helpers import parse_json_safe  # noqa: E402

# ---------------------------------------------------------------------------
# COM constants
# ---------------------------------------------------------------------------

# Standard IUnknown vtable layout (slot -> method name)
IUNKNOWN_SLOTS: dict[int, str] = {0: "QueryInterface", 1: "AddRef", 2: "Release"}

# IInspectable extends IUnknown (WinRT)
IINSPECTABLE_SLOTS: dict[int, str] = {
    **IUNKNOWN_SLOTS,
    3: "GetIids",
    4: "GetRuntimeClassName",
    5: "GetTrustLevel",
}

# IDispatch extends IUnknown
IDISPATCH_SLOTS: dict[int, str] = {
    **IUNKNOWN_SLOTS,
    3: "QueryInterface",
    4: "GetTypeInfoCount",
    5: "GetTypeInfo",
    6: "GetIDsOfNames",
    7: "Invoke",
}

# IClassFactory extends IUnknown
ICLASSFACTORY_SLOTS: dict[int, str] = {
    **IUNKNOWN_SLOTS,
    3: "CreateInstance",
    4: "LockServer",
}

# RuntimeClassFlags meanings
RUNTIME_CLASS_FLAGS: dict[int, str] = {
    1: "WinRt",
    2: "ClassicCom",
    3: "WinRtClassicComMix",
}

# Well-known COM APIs to detect in outbound xrefs
COM_API_NAMES: set[str] = {
    "CoCreateInstance", "CoCreateInstanceEx", "CoGetClassObject",
    "CoInitialize", "CoInitializeEx", "CoUninitialize",
    "CoRegisterClassObject", "CoRevokeClassObject",
    "CoMarshalInterface", "CoUnmarshalInterface",
    "CoGetInterfaceAndReleaseStream", "CoMarshalInterThreadInterfaceInStream",
    "DllGetClassObject", "DllCanUnloadNow", "DllRegisterServer",
    "OleInitialize", "OleUninitialize",
    "RegisterDragDrop", "RevokeDragDrop",
    "CLSIDFromProgID", "CLSIDFromString", "ProgIDFromCLSID",
    "StringFromGUID2", "StringFromCLSID", "StringFromIID",
    "IIDFromString",
}

# QI/AddRef/Release method names
QI_METHOD_NAMES: set[str] = {"QueryInterface"}
ADDREF_METHOD_NAMES: set[str] = {"AddRef"}
RELEASE_METHOD_NAMES: set[str] = {"Release"}
IUNKNOWN_METHOD_NAMES: set[str] = QI_METHOD_NAMES | ADDREF_METHOD_NAMES | RELEASE_METHOD_NAMES


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class COMInterface:
    """A reconstructed COM interface."""
    name: str
    methods: list[dict[str, Any]] = field(default_factory=list)
    base_interface: str = "IUnknown"
    slot_count: int = 0
    source_function_ids: list[int] = field(default_factory=list)
    source: str = ""  # "vtable", "wrl", "qi", "mangled"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "methods": self.methods,
            "base_interface": self.base_interface,
            "slot_count": self.slot_count,
            "source_function_ids": self.source_function_ids,
            "source": self.source,
        }


@dataclass
class WRLClassInfo:
    """Decoded WRL RuntimeClass/RuntimeClassImpl info."""
    class_name: str
    full_name: str = ""
    runtime_class_flags: int = 0
    flags_meaning: str = ""
    weak_reference_support: bool = False
    iinspectable_support: bool = False
    interfaces: list[str] = field(default_factory=list)
    has_ftm_base: bool = False
    source_functions: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "class_name": self.class_name,
            "full_name": self.full_name,
            "runtime_class_flags": self.runtime_class_flags,
            "flags_meaning": self.flags_meaning,
            "weak_reference_support": self.weak_reference_support,
            "iinspectable_support": self.iinspectable_support,
            "interfaces": self.interfaces,
            "has_ftm_base": self.has_ftm_base,
            "source_functions": self.source_functions,
        }


@dataclass
class QIImplementation:
    """A detected QueryInterface/AddRef/Release implementation."""
    function_id: int
    function_name: str
    mangled_name: str = ""
    class_name: str = ""
    method_type: str = ""  # "QueryInterface", "AddRef", "Release"
    has_adjustor: bool = False
    adjustor_offset: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "function_id": self.function_id,
            "function_name": self.function_name,
            "mangled_name": self.mangled_name,
            "class_name": self.class_name,
            "method_type": self.method_type,
            "has_adjustor": self.has_adjustor,
            "adjustor_offset": self.adjustor_offset,
        }


@dataclass
class COMClassInfo:
    """Aggregated COM class information."""
    class_name: str
    interfaces: list[str] = field(default_factory=list)
    evidence: dict[str, list[str]] = field(default_factory=dict)
    runtime_class_flags: Optional[int] = None
    supports_weak_ref: bool = False
    has_ftm: bool = False
    qi_function_ids: list[int] = field(default_factory=list)
    addref_function_ids: list[int] = field(default_factory=list)
    release_function_ids: list[int] = field(default_factory=list)
    other_method_ids: list[int] = field(default_factory=list)
    vtable_methods: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "class_name": self.class_name,
            "interfaces": self.interfaces,
            "evidence": self.evidence,
            "runtime_class_flags": self.runtime_class_flags,
            "supports_weak_ref": self.supports_weak_ref,
            "has_ftm": self.has_ftm,
            "qi_function_ids": self.qi_function_ids,
            "addref_function_ids": self.addref_function_ids,
            "release_function_ids": self.release_function_ids,
            "other_method_ids": self.other_method_ids,
            "vtable_methods": self.vtable_methods,
        }


# ---------------------------------------------------------------------------
# Mangled name parsing for COM/WRL
# ---------------------------------------------------------------------------

def _clean_template_name(name: str) -> str:
    """Clean MSVC template mangling prefix from a class name.

    MSVC encodes template instantiations as ?$TemplateName in mangled names.
    Strip the ?$ prefix to get a readable name.
    """
    if name.startswith("?$"):
        return name[2:]
    return name


def parse_com_class_from_mangled(mangled: str) -> Optional[dict[str, Any]]:
    """Extract COM class/method info from a Microsoft C++ mangled name.

    Returns dict with keys: class_name, method_name, namespaces, role, is_wrl,
                            has_adjustor, adjustor_offset, mangled
    Returns None for non-C++ or unparseable names.
    """
    if not mangled or not mangled.startswith("?"):
        return None

    # Detect adjustor thunks
    has_adjustor = False
    adjustor_offset = 0
    adj_match = re.search(r"`adjustor\{(\d+)\}'", mangled)
    if adj_match:
        has_adjustor = True
        adjustor_offset = int(adj_match.group(1))

    # Determine role from prefix
    is_ctor = mangled.startswith("??0")
    is_dtor = mangled.startswith("??1")
    is_vdel = mangled.startswith("??_G")
    is_vftable = mangled.startswith("??_7")

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

    is_wrl = "WRL" in mangled and "Microsoft" in mangled

    if is_vftable:
        if end < 1:
            return None
        class_name = _clean_template_name(parts[0])
        namespaces = list(reversed([_clean_template_name(p) for p in parts[1:end]]))
        return {
            "class_name": class_name,
            "namespaces": namespaces,
            "role": "vftable",
            "method_name": None,
            "is_wrl": is_wrl,
            "has_adjustor": has_adjustor,
            "adjustor_offset": adjustor_offset,
            "mangled": mangled,
        }

    if is_ctor or is_dtor or is_vdel:
        if end < 1:
            return None
        class_name = _clean_template_name(parts[0])
        namespaces = list(reversed([_clean_template_name(p) for p in parts[1:end]]))
        role = "constructor" if is_ctor else ("destructor" if is_dtor else "vdel_destructor")
        return {
            "class_name": class_name,
            "namespaces": namespaces,
            "role": role,
            "method_name": class_name if is_ctor else f"~{class_name}",
            "is_wrl": is_wrl,
            "has_adjustor": has_adjustor,
            "adjustor_offset": adjustor_offset,
            "mangled": mangled,
        }

    # Regular method
    if end < 2:
        return None

    method_name = _clean_template_name(parts[0])
    class_name = _clean_template_name(parts[1])
    namespaces = list(reversed([_clean_template_name(p) for p in parts[2:end]]))

    return {
        "class_name": class_name,
        "namespaces": namespaces,
        "role": "method",
        "method_name": method_name,
        "is_wrl": is_wrl,
        "has_adjustor": has_adjustor,
        "adjustor_offset": adjustor_offset,
        "mangled": mangled,
    }


def is_qi_method(function_name: str) -> bool:
    """Check if a function name is a QueryInterface implementation."""
    return any(n in function_name for n in QI_METHOD_NAMES)


def is_addref_method(function_name: str) -> bool:
    """Check if a function name is an AddRef implementation."""
    return any(n in function_name for n in ADDREF_METHOD_NAMES)


def is_release_method(function_name: str) -> bool:
    """Check if a function name is a Release implementation."""
    # Be careful not to match "InternalRelease" as just Release
    return "Release" in function_name and "Internal" not in function_name


def classify_iunknown_method(function_name: str) -> Optional[str]:
    """Classify a function as QI, AddRef, or Release. Returns None if not IUnknown."""
    if is_qi_method(function_name):
        return "QueryInterface"
    if is_addref_method(function_name):
        return "AddRef"
    if is_release_method(function_name):
        return "Release"
    return None


# ---------------------------------------------------------------------------
# WRL template parsing
# ---------------------------------------------------------------------------

def decode_wrl_runtime_class(function_name: str, mangled_name: str = "") -> Optional[WRLClassInfo]:
    """Decode WRL RuntimeClassImpl or RuntimeClass template parameters.

    Extracts RuntimeClassFlags, interface list, weak ref support, and FtmBase presence
    from the function name (demangled) or mangled name.
    """
    # Look for RuntimeClassImpl or RuntimeClass in the function name
    rci_match = re.search(
        r'RuntimeClassImpl<[^>]*RuntimeClassFlags<(\d)>[^,]*,\s*(\d),\s*(\d),\s*(\d),\s*(.+?)>',
        function_name
    )
    if not rci_match:
        # Try RuntimeClass (public type, same template args)
        rci_match = re.search(
            r'RuntimeClass<[^>]*RuntimeClassFlags<(\d)>[^,]*,\s*(.+?)>',
            function_name
        )
        if rci_match:
            flags_val = int(rci_match.group(1))
            rest = rci_match.group(2)
            weak_ref = False
            iinspectable = False
        else:
            return None
    else:
        flags_val = int(rci_match.group(1))
        weak_ref = rci_match.group(2) == "1"
        iinspectable = rci_match.group(3) == "1"
        rest = rci_match.group(5)

    # Parse the interface list from 'rest'
    interfaces = _split_template_args(rest)

    has_ftm = False
    filtered_interfaces = []
    for iface in interfaces:
        iface = iface.strip()
        if not iface:
            continue
        if "FtmBase" in iface:
            has_ftm = True
            continue
        # Skip WRL internal types
        if iface.startswith("Microsoft::WRL::") and "Implements" in iface:
            continue
        filtered_interfaces.append(iface)

    # Try to extract the concrete class name
    class_name = _extract_concrete_class(function_name)

    return WRLClassInfo(
        class_name=class_name or "Unknown",
        full_name=function_name,
        runtime_class_flags=flags_val,
        flags_meaning=RUNTIME_CLASS_FLAGS.get(flags_val, f"Unknown({flags_val})"),
        weak_reference_support=weak_ref,
        iinspectable_support=iinspectable,
        interfaces=filtered_interfaces,
        has_ftm_base=has_ftm,
    )


def _split_template_args(text: str) -> list[str]:
    """Split a comma-separated template argument list respecting nested <> brackets."""
    depth = 0
    current = []
    results = []
    for ch in text:
        if ch == '<':
            depth += 1
            current.append(ch)
        elif ch == '>':
            depth -= 1
            current.append(ch)
        elif ch == ',' and depth == 0:
            results.append(''.join(current).strip())
            current = []
        else:
            current.append(ch)
    remaining = ''.join(current).strip()
    if remaining:
        results.append(remaining)
    return results


def _extract_concrete_class(function_name: str) -> Optional[str]:
    """Try to extract the concrete (non-WRL) class name from a WRL function name.

    Strategies (in order):
    1. Make<ConcreteClass, ...> or MakeAndInitialize<ConcreteClass, ...>
    2. Named inner classes (FTMEventDelegate, etc.)
    3. First non-WRL interface in template args as class label
    """
    # Strategy 1: Make<ConcreteClass, ...> pattern
    make_match = re.search(r'Make(?:AndInitialize)?<([^,<>]+)', function_name)
    if make_match:
        name = make_match.group(1).strip()
        return name.split("::")[-1]

    # Strategy 2: Named inner classes in local scope
    named_match = re.search(
        r"'::(\w+Delegate|\w+Context|\w+Handler|\w+Factory|\w+Callback)\b",
        function_name
    )
    if named_match:
        return named_match.group(1)

    return None


def _label_from_interfaces(interfaces: list[str]) -> str:
    """Generate a human-readable class label from its interface list.

    Used as fallback when the concrete class name cannot be extracted.
    Returns the short name of the first non-trivial interface.
    """
    for iface in interfaces:
        short = iface.split("::")[-1]
        # Skip trivial interfaces
        if short in ("IUnknown", "IInspectable", "FtmBase", "IWeakReference",
                     "IWeakReferenceSource", "IMarshal"):
            continue
        # Simplify template args for display
        bracket = short.find("<")
        if bracket > 0:
            short = short[:bracket] + "Impl"
        return short
    # Fallback: use first interface
    if interfaces:
        short = interfaces[0].split("::")[-1]
        bracket = short.find("<")
        if bracket > 0:
            short = short[:bracket] + "Impl"
        return short
    return "Unknown"


def decode_comptr_usage(function_name: str) -> Optional[str]:
    """Extract the interface from ComPtr<IFoo> in a function name."""
    match = re.search(r'ComPtr<([^>]+)>', function_name)
    if match:
        return match.group(1).strip()
    return None


# ---------------------------------------------------------------------------
# VTable context parsing
# ---------------------------------------------------------------------------

def parse_vtable_methods(vtable_skeleton: str) -> list[dict[str, Any]]:
    """Parse a vtable reconstructed_class skeleton string into method list.

    Input format (from IDA vtable analysis):
        class ClassName {
        public:
            virtual MethodName1() = 0;
            virtual MethodName2() = 0;
        };

    Returns list of dicts with slot, offset_hex, method_name.
    """
    methods = []
    slot = 0
    for line in vtable_skeleton.splitlines():
        line = line.strip()
        if line.startswith("virtual "):
            # Extract method name -- remove "virtual ", trailing "= 0;", etc.
            method_text = line.removeprefix("virtual ").strip()
            method_text = re.sub(r'\s*=\s*0\s*;?\s*$', '', method_text)
            method_text = method_text.rstrip(';').strip()
            # Try to extract just the name (may have return type + params)
            # Simple heuristic: last word-like part before '(' or end
            name_match = re.search(r'(\w+)\s*\(', method_text)
            method_name = name_match.group(1) if name_match else method_text
            methods.append({
                "slot": slot,
                "offset_hex": f"0x{slot * 8:02X}",
                "method_name": method_name,
                "raw_signature": method_text,
            })
            slot += 1
    return methods


def classify_vtable_as_com(methods: list[dict[str, Any]], class_name: str = "") -> dict[str, Any]:
    """Determine if a vtable represents a COM interface based on method patterns.

    Handles both complete vtables (QI/AddRef/Release at slots 0-2) and partial
    vtables reconstructed by IDA (may show only a few slots). Also checks the
    class name for COM/WRL indicators.

    Returns dict with: is_com, base_interface, custom_method_start_slot, confidence.
    """
    if not methods:
        return {"is_com": False, "base_interface": None, "custom_method_start_slot": 0, "confidence": "none"}

    names = [m["method_name"] for m in methods]
    raw_sigs = [m.get("raw_signature", "") for m in methods]

    # --- High confidence: Full IUnknown signature at slots 0-2 ---
    if len(names) >= 3:
        is_iunknown = (
            "QueryInterface" in names[0]
            and "AddRef" in names[1]
            and "Release" in names[2]
        )
        if is_iunknown:
            # Check IInspectable base (WinRT)
            is_iinspectable = (
                len(names) >= 6
                and "GetIids" in names[3]
                and "GetRuntimeClassName" in names[4]
                and "GetTrustLevel" in names[5]
            )
            if is_iinspectable:
                return {"is_com": True, "base_interface": "IInspectable",
                        "custom_method_start_slot": 6, "confidence": "high"}
            return {"is_com": True, "base_interface": "IUnknown",
                    "custom_method_start_slot": 3, "confidence": "high"}

    # --- Medium confidence: Partial vtable with COM method names anywhere ---
    has_qi = any("QueryInterface" in n for n in names)
    has_addref = any("AddRef" in n for n in names)
    has_release = any("Release" in n for n in names)

    if has_qi or (has_addref and has_release):
        return {"is_com": True, "base_interface": "IUnknown",
                "custom_method_start_slot": 0, "confidence": "medium"}

    # --- Low confidence: Class name implies COM/WRL ---
    com_indicators = (
        "Microsoft::WRL" in class_name
        or "RuntimeClassImpl" in class_name
        or "FtmBase" in class_name
        or class_name.startswith("I") and len(class_name) > 1 and class_name[1].isupper()
    )
    if com_indicators:
        return {"is_com": True, "base_interface": "IUnknown",
                "custom_method_start_slot": 0, "confidence": "low"}

    return {"is_com": False, "base_interface": None,
            "custom_method_start_slot": 0, "confidence": "none"}


# ---------------------------------------------------------------------------
# GUID pattern detection
# ---------------------------------------------------------------------------

# Standard GUID pattern in code: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
GUID_RE = re.compile(
    r'\{?([0-9A-Fa-f]{8})-([0-9A-Fa-f]{4})-([0-9A-Fa-f]{4})-'
    r'([0-9A-Fa-f]{4})-([0-9A-Fa-f]{12})\}?'
)


def find_guids_in_text(text: str) -> list[str]:
    """Find all GUID-like patterns in a text string."""
    return [m.group(0) for m in GUID_RE.finditer(text)]


# Well-known IIDs for recognition
WELL_KNOWN_IIDS: dict[str, str] = {
    "{00000000-0000-0000-C000-000000000046}": "IID_IUnknown",
    "{00000001-0000-0000-C000-000000000046}": "IID_IClassFactory",
    "{00000003-0000-0000-C000-000000000046}": "IID_IMarshal",
    "{AF86E2E0-B12D-4c6a-9C5A-D7AA65101E90}": "IID_IInspectable",
    "{00020400-0000-0000-C000-000000000046}": "IID_IDispatch",
    "{0000010C-0000-0000-C000-000000000046}": "IID_IPersist",
    "{00000109-0000-0000-C000-000000000046}": "IID_IPersistStream",
    "{0000010B-0000-0000-C000-000000000046}": "IID_IPersistFile",
    "{00000037-0000-0000-C000-000000000046}": "IID_IWeakReference",
    "{00000038-0000-0000-C000-000000000046}": "IID_IWeakReferenceSource",
}


def resolve_guid_name(guid_str: str) -> Optional[str]:
    """Resolve a GUID string to a well-known IID name if possible."""
    normalized = guid_str.upper()
    if not normalized.startswith("{"):
        normalized = "{" + normalized + "}"
    return WELL_KNOWN_IIDS.get(normalized)


# ---------------------------------------------------------------------------
# DB path resolution (bound to this skill's WORKSPACE_ROOT)
# ---------------------------------------------------------------------------
resolve_db_path, resolve_tracking_db = make_db_resolvers(WORKSPACE_ROOT)


__all__ = [
    "ADDREF_METHOD_NAMES",
    "classify_iunknown_method",
    "classify_vtable_as_com",
    "COM_API_NAMES",
    "COMClassInfo",
    "COMInterface",
    "decode_comptr_usage",
    "decode_wrl_runtime_class",
    "find_guids_in_text",
    "GUID_RE",
    "ICLASSFACTORY_SLOTS",
    "IDISPATCH_SLOTS",
    "IINSPECTABLE_SLOTS",
    "IUNKNOWN_METHOD_NAMES",
    "IUNKNOWN_SLOTS",
    "is_addref_method",
    "is_qi_method",
    "is_release_method",
    "parse_com_class_from_mangled",
    "parse_json_safe",
    "parse_vtable_methods",
    "QIImplementation",
    "QI_METHOD_NAMES",
    "RELEASE_METHOD_NAMES",
    "resolve_db_path",
    "resolve_guid_name",
    "resolve_tracking_db",
    "RUNTIME_CLASS_FLAGS",
    "WELL_KNOWN_IIDS",
    "WRLClassInfo",
    "WORKSPACE_ROOT",
]
