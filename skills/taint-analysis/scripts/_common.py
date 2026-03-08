"""Shared utilities for the taint-analysis skill.

Provides workspace bootstrapping, parameter inference from IDA signatures,
tainted parameter resolution, severity scoring helpers, cross-module taint
context, trust boundary classification, COM vtable resolution, and RPC
boundary detection.
"""

from __future__ import annotations

import re
import sys
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

_AGENT_DIR = str(Path(__file__).resolve().parents[3])
if _AGENT_DIR not in sys.path:
    sys.path.insert(0, _AGENT_DIR)

from skills._shared import bootstrap, make_db_resolvers

WORKSPACE_ROOT = bootstrap(__file__)
resolve_db_path, resolve_tracking_db = make_db_resolvers(WORKSPACE_ROOT)

from helpers import (  # noqa: E402
    emit_error,
    parse_json_safe,
    load_function_index_for_db,
    open_individual_analysis_db,
    resolve_function,
    validate_function_id,
)
from helpers.api_taxonomy import (  # noqa: E402
    SECURITY_API_CATEGORIES,
    classify_api_security,
    get_dangerous_api_set,
    is_in_dangerous_apis_json,
)
from helpers.callgraph import CallGraph  # noqa: E402
from helpers.import_export_index import ImportExportIndex  # noqa: E402
from helpers.decompiled_parser import (  # noqa: E402
    extract_function_calls,
    find_param_in_calls,
)
from helpers.def_use_chain import (  # noqa: E402
    TaintResult as DefUseTaintResult,
    analyze_taint as analyze_def_use_taint,
)
from helpers.errors import db_error_handler  # noqa: E402
from helpers.guard_classifier import Guard, classify_guard, find_guards_between  # noqa: E402
from helpers.json_output import emit_json  # noqa: E402
from helpers.cache import get_cached, cache_result  # noqa: E402
from helpers.script_runner import run_skill_script, get_workspace_args  # noqa: E402
from helpers.calling_conventions import param_name_for  # noqa: E402
from helpers.asm_patterns import strip_import_prefix, IDA_PARAM_RE as _PARAM_RE  # noqa: E402
from skills._shared.finding_base import severity_label as _finding_severity_label  # noqa: E402

# ---------------------------------------------------------------------------
# Extended sink detection (supplements helpers.api_taxonomy)
# ---------------------------------------------------------------------------
# Maps lowercase API prefixes to taint-specific sink categories.
# classify_sink() checks helpers.classify_api_security() first, then falls
# back to this table.  Entries are case-insensitive prefix matches.

EXTENDED_SINK_PREFIXES: dict[str, list[str]] = {
    "command_execution": [
        "terminateprocess", "exitprocess", "exitthread",
        "ntterminateprocess", "ntterminatethread",
        "ntsuspendprocess", "ntsuspendthread",
        "ntresumeprocess", "ntresumethread",
        "ntcreateprocess", "ntcreatethread", "ntcreateuserprocess",
        "rtlcreateuserthread", "rtlcreateuserprocess", "createuserprocess",
        "createthread", "resumethread", "suspendthread",
        "ntassignprocesstojobobject", "ntterminatejobobject", "ntcreatejobobject",
        "runshellcommand", "initiateshutdown", "initiatesystemshutdown",
        "lockworkstation", "exitwindows",
    ],
    "code_injection": [
        "ntwritevirtualmemory", "ntqueueapcthread", "ntqueueapcthreadex",
        "setthreadcontext", "getthreadcontext",
        "ntsetinformationthread", "ntsetinformationprocess",
        "wow64setthreadcontext",
        "callwindowproc", "sendmessage", "postmessage",
        "sendmessagetimeout", "sendnotifymessage",
        "unhookwindowshookex",
    ],
    "memory_unsafe": [
        "memcpy", "memmove", "memset", "copymemory",
        "rtlcopymemory", "rtlmovememory",
        "strncpy", "strncat", "wcsncpy",
        "fgets", "fwrite",
        "swprintf", "vswprintf", "vsprintf",
        "alloca", "_alloca", "_getts",
        "multibytetowidechar",
    ],
    "privilege": [
        "ntcreatetoken", "ntduplicatetoken", "ntduplicateobject",
        "ntsetinformationtoken", "ntimpersonateanonymoustoken",
        "duplicatehandle", "setthreadtoken", "impersonateself",
        "rtladjustprivilege",
        "rtlcreateacl", "rtladdaccessallowedace", "rtladdaccessdeniedace",
        "rtladdaccessallowedobjectace", "rtladdaccessdeniedobjectace",
        "rtladdmandatoryace", "rtladdcompoundace",
        "rtldeleteace", "rtlsetinformationacl",
        "rtlsetprocessiscritical",
        "setnamedsecurityinfo", "setfilesecurity",
        "setkernelobjectsecurity", "ntsetsecurityobject",
        "ntsetinformationobject",
        "coinitializesecurity",
    ],
    "code_loading": [
        "ldrloaddll", "loadregtypelib", "loadtypelib",
        "ntloaddriver", "ntunloaddriver", "loaddriver", "zwunloaddriver",
    ],
    "file_write": [
        "createhardlink", "ntcreatesymboliclinkobject",
        "ntcreatefile", "ntdeletefile", "ntdeletekey",
        "ntsetinformationfile", "ntseteafile", "zwsetinformationfile",
        "setfileinformationbyhandle", "setdispositioninformationfile",
        "setrenameinformationfile",
        "createfilemapping", "openfilemapping",
        "replacefile", "movefiletransacted",
        "removedirectory", "createdirectory", "mkdir", "rmdir",
        "remove", "rename",
        "shfileoperation",
    ],
    "registry_write": [
        "regcreatekeyex", "regopenkeyex", "regopencurrentuser",
        "regopenuserclassesroot",
        "ntcreatekey", "ntdeletevaluekey", "ntrenamekey",
        "ntsavekey", "ntlockregistrykey", "ntunloadkey", "ntcompresskey",
        "zwsetvaluekey",
        "rtlwriteregistryvalue",
        "shregsetvalue", "shsetvalue",
        "deletevalue", "deletekeyvalue", "createkey", "regsetkey",
    ],
    "network": [
        "socket", "listen", "bind", "accept",
        "httpsendrequestex", "httpsendrequest",
        "internetconnect", "internetreadfile", "internetwritefile",
        "internetopenurl", "winhttpreaddata",
        "urldownloadtofile",
        "wsasocket", "wsastartup",
        "wnetuseconnection",
        "ndr64asyncclientcall", "ndrasyncclientcall", "ndrclientcall",
    ],
    "memory_alloc": [
        "malloc", "calloc", "realloc", "alloca", "_alloca",
        "heapcreate", "heaprealloc",
        "globalalloc", "globalrealloc",
        "localalloc", "localrealloc",
        "mapviewoffile3", "mapviewoffileex", "mapviewoffilenuma",
        "ntmapviewofsection", "ntprotectvirtualmemory",
        "virtualprotectex", "virtualfreeex",
        "flushviewoffile", "ntunmapviewofsection",
    ],
    "named_pipe": [
        "createnamedpipe", "connectnamedpipe", "callnamedpipe",
        "peeknamedpipe", "waitnamedpipe",
        "ntcreatenamedpipefile",
    ],
    "device_io": [
        "deviceiocontrol", "ntdeviceiocontrolfile", "ntfscontrolfile",
    ],
    "process_enum": [
        "enumprocesses", "enumprocessmodules",
        "createtoolhelp32snapshot",
        "getprocessimagefilename", "queryfullprocessimagename",
        "readprocessmemory", "openprocess", "openthread",
        "ntopenprocess", "ntopenthread",
        "minidumpwritedump",
    ],
    "service_control": [
        "startservice", "controlservice", "deleteservice",
        "changeserviceconfig", "createservice",
    ],
    "debug_control": [
        "isdebuggerpresent", "outputdebugstring",
        "ntdebugactiveprocess", "ntcreatedebugobject",
        "ntsystemdebugcontrol", "ntremoveprocessdebug",
        "ntsetinformationdebugobject",
        "ntraiseharderror",
    ],
    "com_marshaling": [
        "comarshalinterface", "counmarshalinterface",
        "coallowunmarshalerclsid",
        "cocreateinstance", "cocreateinstanceex", "cocreateinstancefromapp",
        "cogetclassobject", "cogetobject",
        "cogetstandardmarshal", "cogetstdmarshalex",
        "oleload", "oleloadfromstream", "olesave", "olesavetostream",
        "olecreate", "olecreateex", "olecreatefromdata", "olecreatefromfile",
        "olecreatelink", "olecreatelinkfromdata", "olegetclipboard",
        "stgcreatestorage", "stgcreatestorageex", "stgopenstorage",
        "stgcreatepropsetstg", "stgcreatepropstg",
        "initvariantfromdispatch", "initvariantfromunknown",
    ],
    "alpc_ipc": [
        "ntalpccreateport", "ntcreateport", "ntconnectport",
        "ntsecureconnectport", "ntlistenport",
        "ntcreatemailslotfile",
    ],
    "dde": [
        "ddeinitialize", "ddeinitalizea", "ddeconnect",
        "ddecreatedatahandle", "ddeaccessdata", "ddeadddata",
        "ddegetdata", "ddenameservice", "ddecallback",
    ],
    "wow64": [
        "wow64disablewow64fsredirection", "wow64revertwow64fsredirection",
    ],
    "ntrace_etw": [
        "nttracecontrol",
    ],
}

# Severity weights for all categories (original + extended)
SINK_SEVERITY: dict[str, float] = {
    "command_execution": 1.0,
    "code_injection": 0.95,
    "memory_unsafe": 0.9,
    "privilege": 0.85,
    "code_loading": 0.8,
    "named_pipe": 0.75,
    "device_io": 0.75,
    "alpc_ipc": 0.75,
    "file_write": 0.7,
    "registry_write": 0.7,
    "service_control": 0.7,
    "anti_forensics": 0.7,
    "com_marshaling": 0.65,
    "dde": 0.65,
    "uncategorized_dangerous": 0.65,
    "network": 0.6,
    "debug_control": 0.55,
    "memory_alloc": 0.5,
    "sync": 0.5,
    "shell_storage": 0.5,
    "process_enum": 0.4,
    "crypto": 0.4,
    "wow64": 0.35,
    "reconnaissance": 0.35,
    "ntrace_etw": 0.3,
}

# Build a flat lowercase-prefix -> category lookup, sorted longest first
_EXTENDED_LOOKUP: list[tuple[str, str]] = []
for _cat, _pfxs in EXTENDED_SINK_PREFIXES.items():
    for _p in _pfxs:
        _EXTENDED_LOOKUP.append((_p.lower(), _cat))
_EXTENDED_LOOKUP.sort(key=lambda x: -len(x[0]))


def classify_sink(api_name: str) -> Optional[str]:
    """Classify an API as a taint sink.

    Resolution order:
    1. ``classify_api_security()`` taxonomy prefix match or JSON
       auto-classify (specific categories only).
    2. Extended prefix table (taint-specific lowercase prefixes).
    3. ``dangerous_apis.json`` membership as ``uncategorized_dangerous``.

    If step 1 returns ``"uncategorized_dangerous"``, step 2 still runs so
    the more specific extended-prefix category wins when available.
    """
    cat = classify_api_security(api_name)
    if cat and cat != "uncategorized_dangerous":
        return cat

    clean = strip_import_prefix(api_name)
    lower = clean.lower()
    for prefix, category in _EXTENDED_LOOKUP:
        if lower.startswith(prefix):
            return category

    # Return the catch-all from classify_api_security if it matched
    if cat:
        return cat

    if is_in_dangerous_apis_json(clean):
        return "uncategorized_dangerous"
    return None

SOURCE_SEVERITY: dict[str, float] = {
    "parameter": 1.0,
    "param_dereference": 0.9,
    "global": 0.7,
    "call_result": 0.5,
    "local_variable": 0.3,
    "string_literal": 0.1,
    "constant": 0.0,
}

# APIs whose return values carry attacker-controlled data.  When a
# call_result source matches one of these prefixes, treat its severity
# as 0.9 (same as param_dereference) rather than the default 0.5.
UNTRUSTED_INPUT_APIS: tuple[str, ...] = (
    "recv", "recvfrom", "WSARecv",
    "ReadFile", "NtReadFile",
    "InternetReadFile", "WinHttpReadData", "HttpQueryInfo",
    "RegQueryValue", "RegGetValue", "NtQueryValueKey",
    "GetEnvironmentVariable",
    "GetWindowText", "PeekMessage", "GetMessage",
    "fgets", "fread",
)

SEVERITY_BANDS: list[tuple[float, str]] = [
    (0.8, "CRITICAL"),
    (0.6, "HIGH"),
    (0.3, "MEDIUM"),
    (0.0, "LOW"),
]


def severity_label(score: float) -> str:
    return _finding_severity_label(score, bands=SEVERITY_BANDS)


def compute_finding_score(
    sink_category: str,
    path_hops: int,
    non_tainted_guard_count: int = 0,
) -> float:
    """Compute a composite severity score for a taint finding."""
    import math

    sink_w = SINK_SEVERITY.get(sink_category, 0.3)
    path_penalty = 1.0 / math.sqrt(max(path_hops, 1))
    guard_penalty = max(0.0, 1.0 - 0.15 * non_tainted_guard_count)
    return round(min(1.0, sink_w * path_penalty * guard_penalty), 3)


# ---------------------------------------------------------------------------
# Parameter inference
# ---------------------------------------------------------------------------



def infer_param_count(signature: str, code: str) -> int:
    """Count function parameters from the IDA signature or decompiled body.

    IDA names parameters ``a1``, ``a2``, ... in the function body.  The
    signature often lists them as ``(__int64 a1, unsigned int a2, ...)``.
    We take the maximum index found in either source.
    """
    max_idx = 0
    for m in _PARAM_RE.finditer(signature):
        max_idx = max(max_idx, int(m.group(1)))
    for m in _PARAM_RE.finditer(code):
        max_idx = max(max_idx, int(m.group(1)))
    return max_idx


def resolve_tainted_params(
    params_arg: Optional[str],
    signature: str,
    code: str,
) -> list[int]:
    """Return the list of 1-based parameter numbers to trace.

    If *params_arg* is provided (comma-separated ints), parse it.
    Otherwise infer all parameters from the function data.
    """
    if params_arg:
        return sorted(set(int(p.strip()) for p in params_arg.split(",") if p.strip().isdigit()))
    count = infer_param_count(signature, code)
    if count < 1:
        count = 1
    return list(range(1, count + 1))


# ---------------------------------------------------------------------------
# Function resolution helper
# ---------------------------------------------------------------------------

def get_function(db_path: str, function_name: str = None, function_id: int = None) -> Optional[dict]:
    """Load a function record from the analysis DB (with detailed xrefs)."""
    from helpers.batch_operations import load_function_record
    return load_function_record(
        db_path,
        function_name=function_name,
        function_id=function_id,
        include_detailed_xrefs=True,
    )


# ---------------------------------------------------------------------------
# Logic-effect detection patterns
# ---------------------------------------------------------------------------

def detect_logic_effects(code: str, tainted_var: str) -> list[dict]:
    """Scan decompiled code for ways *tainted_var* affects internal logic."""
    effects: list[dict] = []
    pat = re.compile(rf"\b{re.escape(tainted_var)}\b")

    for i, line in enumerate(code.splitlines(), 1):
        stripped = line.strip()
        if not pat.search(stripped):
            continue

        if re.match(r"\s*(if|while)\s*\(", stripped):
            effects.append({"type": "branch_steering", "line": i, "text": stripped})

        if re.search(rf"\[.*{re.escape(tainted_var)}.*\]", stripped):
            effects.append({"type": "array_index", "line": i, "text": stripped})

        if re.match(r"\s*for\s*\(", stripped) and pat.search(stripped):
            effects.append({"type": "loop_bound", "line": i, "text": stripped})

        if re.match(r"\s*return\b", stripped):
            effects.append({"type": "returned", "line": i, "text": stripped})

        # Size argument to allocation / memcpy-family
        for alloc_fn in ("HeapAlloc", "VirtualAlloc", "malloc", "calloc",
                         "LocalAlloc", "GlobalAlloc", "RtlAllocateHeap",
                         "memcpy", "memmove", "memset", "RtlCopyMemory"):
            if alloc_fn in stripped and pat.search(stripped):
                effects.append({"type": "size_argument", "line": i, "text": stripped})
                break

    # Deduplicate by (type, line)
    seen: set[tuple[str, int]] = set()
    unique: list[dict] = []
    for e in effects:
        key = (e["type"], e["line"])
        if key not in seen:
            seen.add(key)
            unique.append(e)
    return unique


# ---------------------------------------------------------------------------
# Cross-module taint context
# ---------------------------------------------------------------------------

TRUST_LEVELS = (
    "user_process", "system_service", "com_server",
    "rpc_server", "rpc_server_remote", "rpc_server_named_pipe", "rpc_server_local",
    "kernel_adjacent",
)

TRUST_LEVEL_RANK: dict[str, int] = {
    "user_process": 0,
    "rpc_server_remote": 1,
    "rpc_server_named_pipe": 1,
    "com_server": 1,
    "rpc_server": 2,
    "rpc_server_local": 2,
    "system_service": 3,
    "kernel_adjacent": 4,
}

# Severity multiplier when taint crosses into a higher trust domain
TRUST_ESCALATION_MULTIPLIER = 1.25


@dataclass
class TaintContext:
    """Portable context that travels with taint through cross-module hops.

    Accumulates call stack, guards, trust transitions, and parameter
    mappings so that downstream consumers can reconstruct the full
    cross-module attack chain.
    """

    call_stack: list[dict] = field(default_factory=list)
    accumulated_guards: list[dict] = field(default_factory=list)
    trust_transitions: list[dict] = field(default_factory=list)
    param_map: dict[int, int] = field(default_factory=dict)
    return_taint: bool = False
    boundary_types: list[str] = field(default_factory=list)

    def push_frame(
        self,
        module: str,
        function: str,
        param: int,
        trust_level: str,
    ) -> None:
        self.call_stack.append({
            "module": module,
            "function": function,
            "param": param,
            "trust_level": trust_level,
        })

    def add_guards(self, guards: list[dict]) -> None:
        self.accumulated_guards.extend(guards)

    def add_trust_transition(
        self,
        from_module: str,
        to_module: str,
        from_trust: str,
        to_trust: str,
        boundary_type: str = "dll_import",
    ) -> None:
        transition_kind = classify_trust_transition(from_trust, to_trust)
        self.trust_transitions.append({
            "from_module": from_module,
            "to_module": to_module,
            "from_trust": from_trust,
            "to_trust": to_trust,
            "boundary_type": boundary_type,
            "transition": transition_kind,
        })
        self.boundary_types.append(boundary_type)

    def to_dict(self) -> dict:
        return {
            "call_stack": list(self.call_stack),
            "accumulated_guards": list(self.accumulated_guards),
            "trust_transitions": list(self.trust_transitions),
            "param_map": dict(self.param_map),
            "return_taint": self.return_taint,
            "boundary_types": list(self.boundary_types),
        }

    def clone(self) -> "TaintContext":
        return TaintContext(
            call_stack=list(self.call_stack),
            accumulated_guards=list(self.accumulated_guards),
            trust_transitions=list(self.trust_transitions),
            param_map=dict(self.param_map),
            return_taint=self.return_taint,
            boundary_types=list(self.boundary_types),
        )


# ---------------------------------------------------------------------------
# Trust boundary classification
# ---------------------------------------------------------------------------

_TRUST_CACHE: OrderedDict[str, str] = OrderedDict()
_TRUST_CACHE_MAX_SIZE = 256


def clear_trust_cache() -> None:
    """Clear the module trust classification cache."""
    _TRUST_CACHE.clear()


def _refine_rpc_trust(module_name: str, fallback: str = "rpc_server") -> str:
    """Use the RPC index to determine the most specific RPC trust level."""
    try:
        from helpers.rpc_index import get_rpc_index
        idx = get_rpc_index()
        if idx.loaded and module_name:
            ifaces = idx.get_interfaces_for_module(module_name)
            if ifaces:
                if any(i.is_remote_reachable for i in ifaces):
                    return "rpc_server_remote"
                if any(i.is_named_pipe for i in ifaces):
                    return "rpc_server_named_pipe"
                return "rpc_server_local"
    except Exception:
        pass
    return fallback


def classify_module_trust(db_path: str) -> str:
    """Classify a module's trust level from its exports/imports.

    Uses an LRU-bounded cache keyed by *db_path* to avoid repeated DB opens.
    """
    if db_path in _TRUST_CACHE:
        _TRUST_CACHE.move_to_end(db_path)
        return _TRUST_CACHE[db_path]

    trust = "user_process"
    try:
        with open_individual_analysis_db(db_path) as db:
            fi = db.get_file_info()
            if not fi:
                _TRUST_CACHE[db_path] = trust
                return trust

            exports_raw = parse_json_safe(fi.exports) or []
            imports_raw = parse_json_safe(fi.imports) or []

            export_names = set()
            for exp in exports_raw:
                if isinstance(exp, dict):
                    export_names.add((exp.get("name") or "").lower())
                elif isinstance(exp, str):
                    export_names.add(exp.lower())

            import_names = set()
            for imp in imports_raw:
                if isinstance(imp, dict):
                    for fn in imp.get("functions", []):
                        name = fn.get("name", "") if isinstance(fn, dict) else str(fn)
                        import_names.add(name.lower())
                elif isinstance(imp, str):
                    import_names.add(imp.lower())

            if {"dllgetclassobject", "dllregisterserver"} & export_names:
                trust = "com_server"
            elif any(n.startswith("rpcserverregisterif") for n in import_names):
                trust = _refine_rpc_trust(fi.file_name or "", trust)
            elif {"servicemain"} & export_names or any(
                "startservicectrldispatcher" in n for n in import_names
            ):
                trust = "system_service"
            elif sum(1 for n in import_names if "ntdeviceiocontrolfile" in n) >= 2:
                trust = "kernel_adjacent"

    except Exception:
        pass

    _TRUST_CACHE[db_path] = trust
    if len(_TRUST_CACHE) > _TRUST_CACHE_MAX_SIZE:
        _TRUST_CACHE.popitem(last=False)
    return trust


def classify_trust_transition(from_trust: str, to_trust: str) -> str:
    """Classify a trust boundary crossing."""
    from_rank = TRUST_LEVEL_RANK.get(from_trust, 0)
    to_rank = TRUST_LEVEL_RANK.get(to_trust, 0)
    if to_rank > from_rank:
        return "privilege_escalation"
    if to_rank < from_rank:
        return "trust_reduction"
    return "same_trust"


# ---------------------------------------------------------------------------
# COM vtable call resolution
# ---------------------------------------------------------------------------

def resolve_vtable_callees(
    func: dict,
    db_path: str,
) -> list[dict]:
    """Resolve COM vtable dispatch calls to concrete implementations.

    Scans the *detailed* outbound xrefs for ``is_vtable_call`` entries,
    then attempts to resolve each via:
    1. The vtable method name embedded by IDA in the xref
    2. Cross-referencing ``vtable_info`` with the COM class-interface map

    Returns a list of dicts with ``callee_name``, ``vtable_address``,
    ``method_offset``, ``boundary_type`` ("com_vtable").
    """
    detailed = func.get("detailed_outbound_xrefs") or []
    results: list[dict] = []

    for xref in detailed:
        if not isinstance(xref, dict):
            continue
        if not xref.get("is_vtable_call"):
            continue

        vt_info = xref.get("vtable_info") or {}
        callee_name = xref.get("function_name") or xref.get("target_name", "")
        vtable_addr = vt_info.get("vtable_address")
        method_offset = vt_info.get("method_offset")

        if not callee_name:
            continue

        results.append({
            "callee_name": callee_name,
            "vtable_address": vtable_addr,
            "method_offset": method_offset,
            "boundary_type": "com_vtable",
            "module_name": xref.get("module_name", ""),
            "function_id": xref.get("function_id"),
        })

    return results


# ---------------------------------------------------------------------------
# RPC boundary detection
# ---------------------------------------------------------------------------

_RPC_STUB_PREFIXES = (
    "ndrclientcall",
    "ndr64asyncclientcall",
    "ndrasyncclientcall",
    "ndr64clientcall",
    "ndrclientcall2",
    "ndrclientcall3",
    "ndrclientcall4",
    "ndrsendasyncserverresponse",
)


def detect_rpc_boundaries(call_usages: list[dict]) -> list[dict]:
    """Identify RPC stub invocations in a function's call usages.

    Returns annotated entries for each NdrClientCall-family call found,
    which represent cross-process/cross-machine taint boundaries.
    """
    rpc_calls: list[dict] = []
    for cu in call_usages:
        name = cu.get("function_name", "")
        clean = strip_import_prefix(name)
        if clean.lower() in _RPC_STUB_PREFIXES or any(
            clean.lower().startswith(p) for p in _RPC_STUB_PREFIXES
        ):
            rpc_calls.append({
                "function_name": name,
                "boundary_type": "rpc",
                "arg_position": cu.get("arg_position"),
                "line_number": cu.get("line_number"),
                "line": cu.get("line", ""),
            })
    return rpc_calls


# ---------------------------------------------------------------------------
# Return-value taint detection
# ---------------------------------------------------------------------------

_RETURN_ASSIGN_RE = re.compile(
    r"(\bv\d+|\b\w+)\s*=\s*(\w+)\s*\(",
)


def detect_return_taint(callee_trace_result: dict) -> bool:
    """Check whether any tainted parameter reaches a return statement
    in the callee, indicating taint flows back via the return value."""
    effects = callee_trace_result.get("logic_effects", {})
    if isinstance(effects, dict):
        for _pname, effect_list in effects.items():
            if isinstance(effect_list, list):
                for e in effect_list:
                    if isinstance(e, dict) and e.get("type") == "returned":
                        return True
    findings = callee_trace_result.get("findings", [])
    for f in findings:
        path = f.get("path", [])
        for step in path:
            if isinstance(step, str) and "return" in step.lower():
                return True
    return False


def find_return_assignment_targets(
    code: str,
    callee_name: str,
) -> list[str]:
    """Find variable names that receive the return value of *callee_name*.

    Scans for patterns like ``v5 = callee_name(...)`` and returns the
    list of assignment target variable names.
    """
    targets: list[str] = []
    for line in code.splitlines():
        stripped = line.strip()
        if callee_name not in stripped:
            continue
        m = _RETURN_ASSIGN_RE.search(stripped)
        if m and m.group(2) == callee_name:
            targets.append(m.group(1))
    return targets


__all__ = [
    "CallGraph",
    "EXTENDED_SINK_PREFIXES",
    "Guard",
    "SECURITY_API_CATEGORIES",
    "SINK_SEVERITY",
    "SOURCE_SEVERITY",
    "TRUST_ESCALATION_MULTIPLIER",
    "TRUST_LEVEL_RANK",
    "TRUST_LEVELS",
    "TaintContext",
    "WORKSPACE_ROOT",
    "cache_result",
    "classify_api_security",
    "classify_guard",
    "classify_module_trust",
    "classify_sink",
    "classify_trust_transition",
    "clear_trust_cache",
    "compute_finding_score",
    "db_error_handler",
    "detect_logic_effects",
    "detect_return_taint",
    "detect_rpc_boundaries",
    "emit_error",
    "emit_json",
    "extract_function_calls",
    "find_guards_between",
    "find_param_in_calls",
    "find_return_assignment_targets",
    "get_cached",
    "get_dangerous_api_set",
    "get_function",
    "get_workspace_args",
    "infer_param_count",
    "param_name_for",
    "parse_json_safe",
    "resolve_db_path",
    "resolve_tainted_params",
    "resolve_tracking_db",
    "resolve_vtable_callees",
    "run_skill_script",
    "severity_label",
    "validate_function_id",
    "DefUseTaintResult",
    "analyze_def_use_taint",
]
