#!/usr/bin/env python3
"""Discover all entry points in a module analysis DB.

Scans for: explicit entry points (PE header), exports, COM vtable methods,
RPC handlers, WinRT methods, callbacks, window procedures, service handlers,
TLS callbacks, IPC dispatchers, socket handlers, and more.

Usage:
    python discover_entrypoints.py <db_path>
    python discover_entrypoints.py <db_path> --json
    python discover_entrypoints.py <db_path> --type COM_METHOD
    python discover_entrypoints.py <db_path> --type EXPORT_DLL --type RPC_HANDLER

Examples:
    python discover_entrypoints.py extracted_dbs/appinfo_dll_e98d25a9e8.db
    python discover_entrypoints.py extracted_dbs/cmd_exe_6d109a3a00.db --json
    python discover_entrypoints.py extracted_dbs/appinfo_dll_e98d25a9e8.db --type SERVICE_MAIN --type RPC_HANDLER

Output:
    Categorized list of all discovered entry points with type, signature,
    detection source, and parameter risk scores.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

# Resolve workspace root
_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))

from _common import (
    CALLBACK_REGISTRATION_APIS,
    COM_SERVER_APIS,
    ALPC_APIS,
    NAMED_PIPE_APIS,
    RPC_SERVER_APIS,
    SERVICE_APIS,
    SERVICE_DISPATCHER_APIS,
    SERVICE_HANDLER_APIS,
    SOCKET_APIS,
    _classify_entry_name,
    EntryPoint,
    EntryPointType,
    parse_json_safe,
    resolve_db_path,
    describe_parameter_surface,
)
from helpers import get_function_id, load_function_index_for_db, open_individual_analysis_db, search_index
from helpers.cache import get_cached, cache_result
from helpers.errors import db_error_handler, safe_parse_args
from helpers.json_output import emit_json_list
from helpers.rpc_index import get_rpc_index
from helpers.com_index import get_com_index
from helpers.winrt_index import get_winrt_index


# ===========================================================================
# Cache serialization helpers
# ===========================================================================

def _entrypoints_to_cacheable(entries: list[EntryPoint]) -> list[dict]:
    """Serialize EntryPoint objects for the cache."""
    return [ep.to_dict() for ep in entries]


def _entrypoints_from_cached(data: list[dict]) -> list[EntryPoint]:
    """Reconstruct EntryPoint objects from cached dict list."""
    results: list[EntryPoint] = []
    for d in data:
        type_name = d.get("entry_type", d.get("type_label", "EXPORT_DLL"))
        try:
            etype = EntryPointType[type_name]
        except KeyError:
            etype = EntryPointType.EXPORT_DLL
        ep = EntryPoint(
            function_name=d.get("function_name", ""),
            function_id=d.get("function_id"),
            entry_type=etype,
            type_label=d.get("type_label", ""),
            category=d.get("category", ""),
            detection_source=d.get("detection_source", ""),
            signature=d.get("signature", ""),
            mangled_name=d.get("mangled_name", ""),
            address=d.get("address", ""),
            ordinal=d.get("ordinal"),
            param_surface=d.get("param_surface", {}),
            reachable_count=d.get("reachable_count", 0),
            dangerous_ops_reachable=d.get("dangerous_ops_reachable", 0),
            dangerous_ops_list=d.get("dangerous_ops_list", []),
            depth_to_first_danger=d.get("depth_to_first_danger"),
            reachable_functions=d.get("reachable_functions", []),
            rpc_interface_id=d.get("rpc_interface_id", ""),
            rpc_opnum=d.get("rpc_opnum"),
            rpc_protocol=d.get("rpc_protocol", ""),
            rpc_service=d.get("rpc_service", ""),
            rpc_risk_tier=d.get("rpc_risk_tier", ""),
            com_clsid=d.get("com_clsid", ""),
            com_interface_name=d.get("com_interface_name", ""),
            com_service=d.get("com_service", ""),
            com_risk_tier=d.get("com_risk_tier", ""),
            com_can_elevate=d.get("com_can_elevate", False),
            com_access_contexts=d.get("com_access_contexts", ""),
            winrt_class_name=d.get("winrt_class_name", ""),
            winrt_interface_name=d.get("winrt_interface_name", ""),
            winrt_activation_type=d.get("winrt_activation_type", ""),
            winrt_risk_tier=d.get("winrt_risk_tier", ""),
            winrt_access_contexts=d.get("winrt_access_contexts", ""),
            attack_score=d.get("attack_score", 0.0),
            attack_rank=d.get("attack_rank", 0),
            tainted_args=d.get("tainted_args", []),
            notes=d.get("notes", []),
        )
        results.append(ep)
    return results


# ===========================================================================
# Discovery Functions
# ===========================================================================

def discover_explicit_entry_points(db, function_index: dict | None = None) -> list[EntryPoint]:
    """Extract entry points from file_info.entry_point (IDA detection)."""
    results: list[EntryPoint] = []
    raw = db.get_file_info_field("entry_point")
    entries = parse_json_safe(raw)
    if not entries or not isinstance(entries, list):
        return results

    for ep in entries:
        if not isinstance(ep, dict):
            continue
        name = ep.get("function_name", ep.get("entry_name", ""))
        if not name:
            continue

        # Classify type from name
        etype = _classify_entry_name(name)
        entry = EntryPoint(
            function_name=_clean_name(name),
            entry_type=etype,
            type_label=etype.name,
            category="explicit_entry_point",
            detection_source=f"file_info.entry_point ({ep.get('detection_method', 'unknown')})",
            signature=ep.get("function_signature_extended", ""),
            mangled_name=ep.get("mangled_name", ""),
            address=ep.get("address", ""),
            ordinal=ep.get("ordinal"),
        )
        # Resolve function_id
        clean_name = _clean_name(name)
        resolved_func = None
        if function_index:
            idx_entry = function_index.get(clean_name)
            if idx_entry is None:
                matches = search_index(function_index, clean_name)
                if matches:
                    _, idx_entry = next(iter(matches.items()))
            if idx_entry:
                entry.function_id = get_function_id(idx_entry)
                if entry.function_id is not None and not entry.signature:
                    resolved_func = db.get_function_by_id(entry.function_id)
        if resolved_func is None and entry.function_id is None:
            funcs = db.get_function_by_name(clean_name)
            resolved_func = funcs[0] if funcs else None
            if resolved_func:
                entry.function_id = resolved_func.function_id
        if resolved_func and not entry.signature:
            entry.signature = resolved_func.function_signature_extended or resolved_func.function_signature or ""
        # Score parameters
        entry.param_surface = describe_parameter_surface(entry.signature)
        results.append(entry)

    return results


def discover_exports(db, function_index: dict | None = None) -> list[EntryPoint]:
    """Extract all exports from file_info.exports."""
    results: list[EntryPoint] = []
    raw = db.get_file_info_field("exports")
    exports = parse_json_safe(raw)
    if not exports or not isinstance(exports, list):
        return results

    for exp in exports:
        if not isinstance(exp, dict):
            continue
        name = exp.get("function_name", exp.get("raw_name", ""))
        if not name:
            continue

        # Determine export subtype
        is_forwarded = exp.get("is_forwarded", False)
        is_ordinal_only = not name or name.startswith("Ordinal_") or (exp.get("raw_name", "") == "")

        if is_forwarded:
            etype = EntryPointType.FORWARDED_EXPORT
            category = "forwarded_export"
        elif is_ordinal_only:
            etype = EntryPointType.EXPORT_ORDINAL_ONLY
            category = "ordinal_only_export"
        else:
            # Check if it's a known special type
            etype = _classify_entry_name(name)
            if etype == EntryPointType.EXPORT_DLL:
                # Check COM class factory exports
                if _matches_com_factory(name):
                    etype = EntryPointType.COM_CLASS_FACTORY
                    category = "com_class_factory_export"
                else:
                    category = "dll_export"
            else:
                category = f"{etype.name.lower()}_export"

        entry = EntryPoint(
            function_name=name,
            entry_type=etype,
            type_label=etype.name,
            category=category,
            detection_source="file_info.exports",
            signature=exp.get("function_signature_extended", ""),
            mangled_name=exp.get("mangled_name", ""),
            address=exp.get("address", ""),
            ordinal=exp.get("ordinal"),
        )
        # Resolve function_id and get better signature
        resolved_func = None
        if function_index:
            idx_entry = function_index.get(name)
            if idx_entry:
                entry.function_id = get_function_id(idx_entry)
                if entry.function_id is not None and not entry.signature:
                    resolved_func = db.get_function_by_id(entry.function_id)
        if resolved_func is None and entry.function_id is None:
            funcs = db.get_function_by_name(name)
            resolved_func = funcs[0] if funcs else None
            if resolved_func:
                entry.function_id = resolved_func.function_id
        if resolved_func and not entry.signature:
            entry.signature = resolved_func.function_signature_extended or resolved_func.function_signature or ""

        entry.param_surface = describe_parameter_surface(entry.signature)
        if is_forwarded:
            entry.notes.append(f"Forwarded to: {exp.get('forwarded_to', 'unknown')}")
        results.append(entry)

    return results


def discover_tls_callbacks(db, function_index: dict | None = None) -> list[EntryPoint]:
    """Extract TLS callbacks from file_info.tls_callbacks."""
    results: list[EntryPoint] = []
    raw = db.get_file_info_field("tls_callbacks")
    callbacks = parse_json_safe(raw)
    if not callbacks or not isinstance(callbacks, list):
        return results

    for cb in callbacks:
        if not isinstance(cb, dict):
            continue
        name = cb.get("function_name", cb.get("demangled_name", ""))
        if not name:
            name = f"tls_callback_{cb.get('index', '?')}"

        entry = EntryPoint(
            function_name=name,
            entry_type=EntryPointType.TLS_CALLBACK,
            type_label="TLS_CALLBACK",
            category="tls_callback",
            detection_source="file_info.tls_callbacks",
            address=cb.get("address", ""),
            mangled_name=cb.get("mangled_name", ""),
        )

        threat = cb.get("threat_level", "MINIMAL")
        entry.notes.append(f"Threat level: {threat} (score: {cb.get('threat_score', 0)})")
        if cb.get("has_anti_debug"):
            entry.notes.append("Contains anti-debug patterns")
        if cb.get("has_crypto_constants"):
            entry.notes.append("Contains crypto constants")

        resolved_func = None
        if function_index:
            idx_entry = function_index.get(name)
            if idx_entry:
                entry.function_id = get_function_id(idx_entry)
                if entry.function_id is not None:
                    resolved_func = db.get_function_by_id(entry.function_id)
        if resolved_func is None and entry.function_id is None:
            funcs = db.get_function_by_name(name)
            resolved_func = funcs[0] if funcs else None
            if resolved_func:
                entry.function_id = resolved_func.function_id
        if resolved_func:
            entry.signature = resolved_func.function_signature_extended or resolved_func.function_signature or ""

        entry.param_surface = describe_parameter_surface(entry.signature)
        results.append(entry)

    return results


def discover_com_vtable_methods(db, all_funcs: list | None = None) -> list[EntryPoint]:
    """Find COM/WRL vtable methods from vtable_contexts across all functions."""
    results: list[EntryPoint] = []
    seen_names: set[str] = set()

    if all_funcs is None:
        all_funcs = db.get_all_functions()
    for func in all_funcs:
        vtc = parse_json_safe(func.vtable_contexts)
        if not vtc or not isinstance(vtc, list):
            continue

        for ctx in vtc:
            if not isinstance(ctx, dict):
                continue
            classes = ctx.get("reconstructed_classes", [])
            if not classes:
                continue

            for class_str in classes:
                if not isinstance(class_str, str):
                    continue

                # Parse vtable class skeleton for method names
                is_winrt = "Microsoft::WRL" in class_str or "Windows::Foundation" in class_str
                is_com = ("IUnknown" in class_str or "QueryInterface" in class_str
                          or "AddRef" in class_str or "Release" in class_str
                          or re.search(r"\bI[A-Z]\w+\b", class_str))

                if not is_com and not is_winrt:
                    continue

                # The function itself is referenced by this vtable
                name = func.function_name
                if not name or name in seen_names:
                    continue
                seen_names.add(name)

                etype = EntryPointType.WINRT_METHOD if is_winrt else EntryPointType.COM_METHOD
                entry = EntryPoint(
                    function_name=name,
                    function_id=func.function_id,
                    entry_type=etype,
                    type_label=etype.name,
                    category="winrt_vtable_method" if is_winrt else "com_vtable_method",
                    detection_source="vtable_contexts",
                    signature=func.function_signature_extended or func.function_signature or "",
                    mangled_name=func.mangled_name or "",
                )
                entry.notes.append(f"VTable class: {class_str[:120]}")
                entry.param_surface = describe_parameter_surface(entry.signature)
                results.append(entry)

    return results


def discover_callback_registrations(db, all_funcs: list | None = None) -> list[EntryPoint]:
    """Find functions registered as callbacks via API calls.

    Scans outbound_xrefs of ALL functions looking for calls to callback-registering
    APIs (CreateThread, SetTimer, RegisterClassEx, etc.). Uses inbound_xrefs of
    candidate callbacks to confirm they are referenced by the registering function.

    Conservative: only flags functions that have limited callers (<=5) and match
    callback-like signatures (function pointers, LPTHREAD_START_ROUTINE, etc.) or
    whose names suggest callback/handler/proc roles.
    """
    results: list[EntryPoint] = []
    seen_names: set[str] = set()

    if all_funcs is None:
        all_funcs = db.get_all_functions()
    name_to_func = {}
    for func in all_funcs:
        if func.function_name:
            name_to_func[func.function_name] = func

    # Callback name heuristics (likely callback if name contains these)
    _CALLBACK_NAME_HINTS = re.compile(
        r"(?:Callback|Handler|Proc|Thread|Worker|Timer|Notify|OnEvent|OnTimer|"
        r"CtrlHandler|ServiceHandler|WndProc|DlgProc|Hook|ApcRoutine|IoCompletion|"
        r"AcceptProc|RecvCallback)",
        re.I,
    )

    for func in all_funcs:
        outbound = parse_json_safe(func.simple_outbound_xrefs)
        if not outbound or not isinstance(outbound, list):
            continue

        # Collect callback-registering API calls in this function
        registration_apis: list[tuple[str, dict]] = []
        internal_callees: list[dict] = []

        for xref in outbound:
            if not isinstance(xref, dict):
                continue
            callee_name = xref.get("function_name", "")
            clean = re.sub(r"^(?:__imp_|_imp_|__imp__|j_)", "", callee_name)

            api_info = CALLBACK_REGISTRATION_APIS.get(clean)
            if not api_info:
                for api_key, api_val in CALLBACK_REGISTRATION_APIS.items():
                    if clean.startswith(api_key):
                        api_info = api_val
                        break
            if api_info:
                registration_apis.append((clean, api_info))
            elif xref.get("function_id") is not None and callee_name in name_to_func:
                internal_callees.append(xref)

        if not registration_apis:
            continue

        # For each internal callee, check if it looks like a callback
        for inner_xref in internal_callees:
            inner_name = inner_xref.get("function_name", "")
            if not inner_name or inner_name in seen_names:
                continue

            inner_func = name_to_func.get(inner_name)
            if not inner_func:
                continue

            # Heuristic: callback functions typically have few callers (1-5)
            inbound = parse_json_safe(inner_func.simple_inbound_xrefs)
            caller_count = len(inbound) if inbound and isinstance(inbound, list) else 0
            if caller_count > 5:
                continue  # Too many callers -- probably a utility function

            # Check name hints or signature hints
            name_looks_like_callback = bool(_CALLBACK_NAME_HINTS.search(inner_name))

            sig = inner_func.function_signature_extended or inner_func.function_signature or ""
            sig_looks_like_callback = bool(re.search(
                r"(?:LPTHREAD_START_ROUTINE|TIMERPROC|WNDPROC|DLGPROC|"
                r"PTP_\w+_CALLBACK|WAITORTIMERCALLBACK|PIO_APC_ROUTINE|"
                r"LPOVERLAPPED_COMPLETION_ROUTINE|HANDLER_FUNCTION_EX|"
                r"PHANDLER_ROUTINE)",
                sig, re.I,
            ))

            # Accept if name or signature suggests callback, or if very few callers (1-2)
            if not name_looks_like_callback and not sig_looks_like_callback and caller_count > 2:
                continue

            # Use the most specific registration API category
            best_api, best_info = registration_apis[0]
            cat = best_info["category"]
            etype = _callback_category_to_type(cat)
            seen_names.add(inner_name)

            entry = EntryPoint(
                function_name=inner_name,
                function_id=inner_xref.get("function_id"),
                entry_type=etype,
                type_label=etype.name,
                category=cat,
                detection_source=f"callback registration via {best_api} in {func.function_name}",
                signature=sig,
            )
            entry.param_surface = describe_parameter_surface(sig)
            entry.notes.append(f"Registered by {func.function_name} via {best_api}()")
            if caller_count <= 2:
                entry.notes.append(f"Low caller count ({caller_count}) supports callback hypothesis")
            results.append(entry)

    return results


def discover_by_naming_patterns(db, all_funcs: list | None = None) -> list[EntryPoint]:
    """Find entry points by function name patterns (RPC stubs, WndProc, etc.).

    Regex-based name patterns have been removed. Classification is done by
    structured data sources (RPC/COM/WinRT indexes, file_info.json exports).
    Returns empty list to preserve pipeline compatibility.
    """
    return []


def discover_by_api_usage(db, all_funcs: list | None = None) -> list[EntryPoint]:
    """Find entry points by the APIs a function calls (RPC server, pipes, sockets, etc.)."""
    results: list[EntryPoint] = []
    seen_names: set[str] = set()

    if all_funcs is None:
        all_funcs = db.get_all_functions()
    for func in all_funcs:
        name = func.function_name
        if not name or name in seen_names:
            continue

        outbound = parse_json_safe(func.simple_outbound_xrefs)
        if not outbound or not isinstance(outbound, list):
            continue

        called_apis: set[str] = set()
        for xref in outbound:
            if not isinstance(xref, dict):
                continue
            api = xref.get("function_name", "")
            clean = re.sub(r"^(?:__imp_|_imp_|__imp__|j_)", "", api)
            called_apis.add(clean)

        # Check for RPC server patterns
        rpc_matches = called_apis & RPC_SERVER_APIS
        if rpc_matches:
            seen_names.add(name)
            entry = EntryPoint(
                function_name=name,
                function_id=func.function_id,
                entry_type=EntryPointType.RPC_HANDLER,
                type_label="RPC_HANDLER",
                category="rpc_server_function",
                detection_source=f"calls RPC server APIs: {', '.join(sorted(rpc_matches)[:5])}",
                signature=func.function_signature_extended or func.function_signature or "",
                mangled_name=func.mangled_name or "",
            )
            entry.param_surface = describe_parameter_surface(entry.signature)
            results.append(entry)
            continue

        # Check for named pipe server patterns
        pipe_matches = called_apis & NAMED_PIPE_APIS
        if pipe_matches:
            seen_names.add(name)
            entry = EntryPoint(
                function_name=name,
                function_id=func.function_id,
                entry_type=EntryPointType.NAMED_PIPE_HANDLER,
                type_label="NAMED_PIPE_HANDLER",
                category="named_pipe_server",
                detection_source=f"calls pipe APIs: {', '.join(sorted(pipe_matches)[:5])}",
                signature=func.function_signature_extended or func.function_signature or "",
                mangled_name=func.mangled_name or "",
            )
            entry.param_surface = describe_parameter_surface(entry.signature)
            results.append(entry)
            continue

        # Check for ALPC/LPC patterns
        alpc_matches = called_apis & ALPC_APIS
        if alpc_matches:
            seen_names.add(name)
            entry = EntryPoint(
                function_name=name,
                function_id=func.function_id,
                entry_type=EntryPointType.IPC_DISPATCHER,
                type_label="IPC_DISPATCHER",
                category="alpc_ipc_handler",
                detection_source=f"calls ALPC APIs: {', '.join(sorted(alpc_matches)[:5])}",
                signature=func.function_signature_extended or func.function_signature or "",
                mangled_name=func.mangled_name or "",
            )
            entry.param_surface = describe_parameter_surface(entry.signature)
            results.append(entry)
            continue

        # Check for socket/network server patterns
        socket_matches = called_apis & SOCKET_APIS
        if len(socket_matches) >= 2:  # Need multiple socket APIs to be a handler
            seen_names.add(name)
            entry = EntryPoint(
                function_name=name,
                function_id=func.function_id,
                entry_type=EntryPointType.TCP_UDP_HANDLER,
                type_label="TCP_UDP_HANDLER",
                category="socket_handler",
                detection_source=f"calls socket APIs: {', '.join(sorted(socket_matches)[:5])}",
                signature=func.function_signature_extended or func.function_signature or "",
                mangled_name=func.mangled_name or "",
            )
            entry.param_surface = describe_parameter_surface(entry.signature)
            results.append(entry)
            continue

        # Check for COM server patterns
        com_matches = called_apis & COM_SERVER_APIS
        if com_matches:
            seen_names.add(name)
            entry = EntryPoint(
                function_name=name,
                function_id=func.function_id,
                entry_type=EntryPointType.COM_CLASS_FACTORY,
                type_label="COM_CLASS_FACTORY",
                category="com_server_function",
                detection_source=f"calls COM server APIs: {', '.join(sorted(com_matches)[:5])}",
                signature=func.function_signature_extended or func.function_signature or "",
                mangled_name=func.mangled_name or "",
            )
            entry.param_surface = describe_parameter_surface(entry.signature)
            results.append(entry)
            continue

        # Check for service dispatcher APIs (-> SERVICE_MAIN)
        svc_disp_matches = called_apis & SERVICE_DISPATCHER_APIS
        if svc_disp_matches:
            seen_names.add(name)
            entry = EntryPoint(
                function_name=name,
                function_id=func.function_id,
                entry_type=EntryPointType.SERVICE_MAIN,
                type_label="SERVICE_MAIN",
                category="service_dispatcher",
                detection_source=f"calls service dispatcher APIs: {', '.join(sorted(svc_disp_matches)[:5])}",
                signature=func.function_signature_extended or func.function_signature or "",
                mangled_name=func.mangled_name or "",
            )
            entry.param_surface = describe_parameter_surface(entry.signature)
            results.append(entry)
            continue

        # Check for service handler registration APIs (-> SERVICE_CTRL_HANDLER)
        svc_handler_matches = called_apis & SERVICE_HANDLER_APIS
        if svc_handler_matches:
            seen_names.add(name)
            entry = EntryPoint(
                function_name=name,
                function_id=func.function_id,
                entry_type=EntryPointType.SERVICE_CTRL_HANDLER,
                type_label="SERVICE_CTRL_HANDLER",
                category="service_handler_registration",
                detection_source=f"calls service handler APIs: {', '.join(sorted(svc_handler_matches)[:5])}",
                signature=func.function_signature_extended or func.function_signature or "",
                mangled_name=func.mangled_name or "",
            )
            entry.param_surface = describe_parameter_surface(entry.signature)
            results.append(entry)

    return results


def discover_by_string_patterns(db, all_funcs: list | None = None) -> list[EntryPoint]:
    """Find entry points by string literals (pipe names, RPC protocols, etc.).

    Regex-based string patterns have been removed. Classification is done by
    structured data sources (RPC/COM/WinRT indexes). Returns empty list to
    preserve pipeline compatibility.
    """
    return []


# ===========================================================================
# RPC Index-Based Discovery
# ===========================================================================

def discover_from_rpc_index(
    db, module_name: str, function_index: dict | None = None,
) -> list[EntryPoint]:
    """Discover RPC entry points using the ground-truth RPC index.

    Returns definitive RPC handlers with interface UUID, opnum, protocol,
    and service context attached.  These take priority over heuristic detection.
    """
    results: list[EntryPoint] = []
    idx = get_rpc_index()
    if not idx.loaded:
        return results

    mod_name = module_name
    if not mod_name:
        return results

    procedures = idx.get_procedures_for_module(mod_name)
    if not procedures:
        return results

    for func_name in procedures:
        iface = idx.get_interface_for_procedure(mod_name, func_name)
        opnum = idx.procedure_to_opnum(mod_name, func_name)

        protocol = ""
        rpc_service = ""
        rpc_risk_tier = ""
        rpc_iface_id = ""
        if iface:
            rpc_iface_id = iface.interface_id
            rpc_service = iface.service_name or ""
            rpc_risk_tier = iface.risk_tier
            protocol = ",".join(sorted(iface.protocols)) if iface.protocols else "ncalrpc"

        sig = ""
        func_id = None
        if function_index:
            idx_entry = function_index.get(func_name)
            if idx_entry:
                func_id = get_function_id(idx_entry)
        if func_id is None:
            funcs = db.get_function_by_name(func_name)
            if funcs:
                func_id = funcs[0].function_id
                sig = funcs[0].function_signature_extended or funcs[0].function_signature or ""

        if func_id is not None and not sig:
            resolved = db.get_function_by_id(func_id)
            if resolved:
                sig = resolved.function_signature_extended or resolved.function_signature or ""

        ep = EntryPoint(
            function_name=func_name,
            function_id=func_id,
            entry_type=EntryPointType.RPC_HANDLER,
            type_label="RPC_HANDLER",
            category="rpc_index_confirmed",
            detection_source=f"rpc_index (interface {rpc_iface_id}, opnum {opnum})",
            signature=sig,
            rpc_interface_id=rpc_iface_id,
            rpc_opnum=opnum,
            rpc_protocol=protocol,
            rpc_service=rpc_service,
            rpc_risk_tier=rpc_risk_tier,
        )
        ep.param_surface = describe_parameter_surface(sig)
        if rpc_service:
            ep.notes.append(f"Windows service: {rpc_service}")
        if iface and iface.has_complex_types:
            ep.notes.append(f"Complex NDR types (serialization surface)")
        results.append(ep)

    return results


def _enrich_existing_with_rpc_index(
    entries: list[EntryPoint], module_name: str,
) -> None:
    """Enrich existing RPC_HANDLER entries with index metadata and
    downgrade false-positive heuristic matches."""
    idx = get_rpc_index()
    if not idx.loaded or not module_name:
        return

    confirmed_procs = set(idx.get_procedures_for_module(module_name))
    if not confirmed_procs:
        return

    for ep in entries:
        if ep.entry_type != EntryPointType.RPC_HANDLER:
            continue
        if ep.rpc_interface_id:
            continue  # Already enriched from index discovery

        if ep.function_name in confirmed_procs:
            iface = idx.get_interface_for_procedure(module_name, ep.function_name)
            if iface:
                ep.rpc_interface_id = iface.interface_id
                ep.rpc_opnum = idx.procedure_to_opnum(module_name, ep.function_name)
                ep.rpc_protocol = ",".join(sorted(iface.protocols)) if iface.protocols else "ncalrpc"
                ep.rpc_service = iface.service_name or ""
                ep.rpc_risk_tier = iface.risk_tier
                ep.notes.append("Confirmed by RPC index")
        else:
            ep.notes.append("Heuristic RPC detection (not confirmed by RPC index)")


# ===========================================================================
# COM Index-Based Discovery
# ===========================================================================

def discover_from_com_index(
    db, module_name: str, function_index: dict | None = None,
) -> list[EntryPoint]:
    """Discover COM entry points using the ground-truth COM index."""
    results: list[EntryPoint] = []
    idx = get_com_index()
    if not idx.loaded or not module_name:
        return results

    procedures = idx.get_procedures_for_module(module_name)
    if not procedures:
        return results

    servers = idx.get_servers_for_module(module_name)
    server_map: dict[str, Any] = {}
    for srv in servers:
        for m in srv.methods_flat:
            server_map[m.name] = srv
            server_map[m.short_name] = srv

    for func_name in procedures:
        sig = ""
        func_id = None
        if function_index:
            idx_entry = function_index.get(func_name)
            if idx_entry:
                func_id = get_function_id(idx_entry)
        if func_id is None:
            funcs = db.get_function_by_name(func_name)
            if funcs:
                func_id = funcs[0].function_id
                sig = funcs[0].function_signature_extended or funcs[0].function_signature or ""

        if func_id is not None and not sig:
            resolved = db.get_function_by_id(func_id)
            if resolved:
                sig = resolved.function_signature_extended or resolved.function_signature or ""

        srv = server_map.get(func_name)
        com_clsid = srv.clsid if srv else ""
        com_service = (srv.service_name or "") if srv else ""
        com_risk_tier = srv.best_risk_tier if srv else ""
        com_can_elevate = bool(srv and (getattr(srv, "can_elevate", False) or getattr(srv, "auto_elevate", False)))
        com_access_ctxs = ",".join(sorted(str(c) for c in srv.access_contexts)) if srv else ""
        com_iface = ""
        if srv:
            for m in srv.methods_flat:
                if m.name == func_name or m.short_name == func_name:
                    com_iface = getattr(m, "interface_name", "") or ""
                    break

        ep = EntryPoint(
            function_name=func_name,
            function_id=func_id,
            entry_type=EntryPointType.COM_METHOD,
            type_label="COM_METHOD",
            category="com_index_confirmed",
            detection_source=f"com_index (CLSID {com_clsid})",
            signature=sig,
            com_clsid=com_clsid,
            com_interface_name=com_iface,
            com_service=com_service,
            com_risk_tier=com_risk_tier,
            com_can_elevate=com_can_elevate,
            com_access_contexts=com_access_ctxs,
        )
        ep.param_surface = describe_parameter_surface(sig)
        if com_service:
            ep.notes.append(f"Windows service: {com_service}")
        if com_can_elevate:
            ep.notes.append("COM server supports elevation (UAC bypass surface)")
        results.append(ep)

    return results


def _enrich_existing_with_com_index(
    entries: list[EntryPoint], module_name: str,
) -> None:
    """Use is_com_procedure() to identify and enrich COM handlers."""
    idx = get_com_index()
    if not idx.loaded or not module_name:
        return

    confirmed_procs = set(idx.get_procedures_for_module(module_name))
    if not confirmed_procs:
        return

    servers = idx.get_servers_for_module(module_name)
    server_map: dict[str, Any] = {}
    for srv in servers:
        for m in srv.methods_flat:
            server_map[m.name] = srv
            server_map[m.short_name] = srv

    for ep in entries:
        if ep.com_clsid:
            continue

        if ep.function_name in confirmed_procs or idx.is_com_procedure(module_name, ep.function_name):
            srv = server_map.get(ep.function_name)
            if srv:
                ep.com_clsid = srv.clsid
                ep.com_service = srv.service_name or ""
                ep.com_risk_tier = srv.best_risk_tier
                ep.com_can_elevate = bool(getattr(srv, "can_elevate", False) or getattr(srv, "auto_elevate", False))
                ep.com_access_contexts = ",".join(sorted(str(c) for c in srv.access_contexts))
                for m in srv.methods_flat:
                    if m.name == ep.function_name or m.short_name == ep.function_name:
                        ep.com_interface_name = getattr(m, "interface_name", "") or ""
                        break

            if ep.entry_type in (EntryPointType.COM_METHOD, EntryPointType.COM_CLASS_FACTORY):
                ep.notes.append("Confirmed by COM index")
            else:
                ep.entry_type = EntryPointType.COM_METHOD
                ep.type_label = "COM_METHOD"
                ep.notes.append("Identified as COM handler by COM index")
        elif ep.entry_type in (EntryPointType.COM_METHOD, EntryPointType.COM_CLASS_FACTORY):
            ep.notes.append("Heuristic COM detection (not confirmed by COM index)")


# ===========================================================================
# WinRT Index-Based Discovery
# ===========================================================================

def discover_from_winrt_index(
    db, module_name: str, function_index: dict | None = None,
) -> list[EntryPoint]:
    """Discover WinRT entry points using the ground-truth WinRT index."""
    results: list[EntryPoint] = []
    idx = get_winrt_index()
    if not idx.loaded or not module_name:
        return results

    procedures = idx.get_procedures_for_module(module_name)
    if not procedures:
        return results

    servers = idx.get_servers_for_module(module_name)
    server_map: dict[str, Any] = {}
    for srv in servers:
        for m in srv.methods_flat:
            server_map[m.name] = srv
            server_map[m.short_name] = srv

    for func_name in procedures:
        sig = ""
        func_id = None
        if function_index:
            idx_entry = function_index.get(func_name)
            if idx_entry:
                func_id = get_function_id(idx_entry)
        if func_id is None:
            funcs = db.get_function_by_name(func_name)
            if funcs:
                func_id = funcs[0].function_id
                sig = funcs[0].function_signature_extended or funcs[0].function_signature or ""

        if func_id is not None and not sig:
            resolved = db.get_function_by_id(func_id)
            if resolved:
                sig = resolved.function_signature_extended or resolved.function_signature or ""

        srv = server_map.get(func_name)
        winrt_class = srv.name if srv else ""
        winrt_activation = (getattr(srv, "activation_type", "") or "") if srv else ""
        winrt_risk_tier = srv.best_risk_tier if srv else ""
        winrt_access_ctxs = ",".join(sorted(str(c) for c in srv.access_contexts)) if srv else ""
        winrt_iface = ""
        if srv:
            for m in srv.methods_flat:
                if m.name == func_name or m.short_name == func_name:
                    winrt_iface = getattr(m, "interface_name", "") or ""
                    break

        ep = EntryPoint(
            function_name=func_name,
            function_id=func_id,
            entry_type=EntryPointType.WINRT_METHOD,
            type_label="WINRT_METHOD",
            category="winrt_index_confirmed",
            detection_source=f"winrt_index (class {winrt_class})",
            signature=sig,
            winrt_class_name=winrt_class,
            winrt_interface_name=winrt_iface,
            winrt_activation_type=winrt_activation,
            winrt_risk_tier=winrt_risk_tier,
            winrt_access_contexts=winrt_access_ctxs,
        )
        ep.param_surface = describe_parameter_surface(sig)
        results.append(ep)

    return results


def _enrich_existing_with_winrt_index(
    entries: list[EntryPoint], module_name: str,
) -> None:
    """Use is_winrt_procedure() to identify and enrich WinRT handlers."""
    idx = get_winrt_index()
    if not idx.loaded or not module_name:
        return

    confirmed_procs = set(idx.get_procedures_for_module(module_name))
    if not confirmed_procs:
        return

    servers = idx.get_servers_for_module(module_name)
    server_map: dict[str, Any] = {}
    for srv in servers:
        for m in srv.methods_flat:
            server_map[m.name] = srv
            server_map[m.short_name] = srv

    for ep in entries:
        if ep.winrt_class_name:
            continue

        if ep.function_name in confirmed_procs or idx.is_winrt_procedure(module_name, ep.function_name):
            srv = server_map.get(ep.function_name)
            if srv:
                ep.winrt_class_name = srv.name
                ep.winrt_activation_type = getattr(srv, "activation_type", "") or ""
                ep.winrt_risk_tier = srv.best_risk_tier
                ep.winrt_access_contexts = ",".join(sorted(str(c) for c in srv.access_contexts))
                for m in srv.methods_flat:
                    if m.name == ep.function_name or m.short_name == ep.function_name:
                        ep.winrt_interface_name = getattr(m, "interface_name", "") or ""
                        break

            if ep.entry_type == EntryPointType.WINRT_METHOD:
                ep.notes.append("Confirmed by WinRT index")
            else:
                ep.entry_type = EntryPointType.WINRT_METHOD
                ep.type_label = "WINRT_METHOD"
                ep.notes.append("Identified as WinRT handler by WinRT index")
        elif ep.entry_type == EntryPointType.WINRT_METHOD:
            ep.notes.append("Heuristic WinRT detection (not confirmed by WinRT index)")


# ===========================================================================
# Discovery Orchestrator
# ===========================================================================

def discover_all(db_path: str, *, no_cache: bool = False) -> list[EntryPoint]:
    """Run all discovery methods and return deduplicated entry points.

    Priority: explicit entry points > exports > all other detection methods.
    When duplicates found, the higher-priority detection is kept but notes are merged.
    """
    if not no_cache:
        cached = get_cached(db_path, "discover_entrypoints")
        if cached is not None:
            return _entrypoints_from_cached(cached)

    with db_error_handler(db_path, "discovering entry points"):
        with open_individual_analysis_db(db_path) as db:
            function_index = load_function_index_for_db(db_path)
            all_funcs = db.get_all_functions()

            # Resolve module name for RPC index lookup
            module_name = ""
            fi = db.get_file_info()
            if fi:
                module_name = fi.file_name or ""

            # Phase 0: Ground-truth RPC handlers from RPC index (highest confidence)
            rpc_index_entries = discover_from_rpc_index(
                db, module_name, function_index=function_index,
            )

            # Phase 0b: Ground-truth COM handlers from COM index
            com_index_entries = discover_from_com_index(
                db, module_name, function_index=function_index,
            )

            # Phase 0c: Ground-truth WinRT handlers from WinRT index
            winrt_index_entries = discover_from_winrt_index(
                db, module_name, function_index=function_index,
            )

            # Phase 1: Explicit sources (highest confidence)
            explicit = discover_explicit_entry_points(db, function_index=function_index)
            exports = discover_exports(db, function_index=function_index)
            tls = discover_tls_callbacks(db, function_index=function_index)

            # Phase 2: Heuristic discovery (reuse pre-fetched function list)
            com_vtable = discover_com_vtable_methods(db, all_funcs=all_funcs)
            callbacks = discover_callback_registrations(db, all_funcs=all_funcs)
            name_patterns = discover_by_naming_patterns(db, all_funcs=all_funcs)
            api_usage = discover_by_api_usage(db, all_funcs=all_funcs)
            string_patterns = discover_by_string_patterns(db, all_funcs=all_funcs)

    # Merge with deduplication -- RPC index entries come first (highest priority)
    all_entries = (
        rpc_index_entries + com_index_entries + winrt_index_entries +
        explicit + exports + tls + com_vtable +
        callbacks + name_patterns + api_usage + string_patterns
    )
    deduped = _deduplicate(all_entries)

    # Enrich any heuristic entries with index metadata
    _enrich_existing_with_rpc_index(deduped, module_name)
    _enrich_existing_with_com_index(deduped, module_name)
    _enrich_existing_with_winrt_index(deduped, module_name)

    cache_result(db_path, "discover_entrypoints", _entrypoints_to_cacheable(deduped))
    return deduped


def _deduplicate(entries: list[EntryPoint]) -> list[EntryPoint]:
    """Deduplicate by function_name, keeping highest-priority entry."""
    seen: dict[str, EntryPoint] = {}
    for ep in entries:
        key = ep.function_name
        if key not in seen:
            seen[key] = ep
        else:
            existing = seen[key]
            # Merge notes and keep the one with more specific type
            existing.notes.extend(ep.notes)
            if ep.detection_source not in existing.detection_source:
                existing.notes.append(f"Also detected via: {ep.detection_source}")
    return list(seen.values())


# ===========================================================================
# Helpers
# ===========================================================================

def _clean_name(name: str) -> str:
    """Remove trailing parameter list from function names like 'Foo(int, int)'."""
    paren = name.find("(")
    if paren > 0:
        return name[:paren].strip()
    return name.strip()


def _matches_com_factory(name: str) -> bool:
    """Check if a function name matches COM class factory exports."""
    return bool(re.match(
        r"^Dll(?:GetClassObject|CanUnloadNow|RegisterServer|UnregisterServer)$",
        name, re.I
    ))


def _callback_category_to_type(category: str) -> EntryPointType:
    """Map callback API category to EntryPointType."""
    mapping = {
        "thread_callback": EntryPointType.CALLBACK_REGISTRATION,
        "fiber_callback": EntryPointType.CALLBACK_REGISTRATION,
        "timer_callback": EntryPointType.SCHEDULED_CALLBACK,
        "threadpool_callback": EntryPointType.SCHEDULED_CALLBACK,
        "window_proc": EntryPointType.WINDOW_PROC,
        "dialog_proc": EntryPointType.WINDOW_PROC,
        "apc_callback": EntryPointType.SCHEDULED_CALLBACK,
        "hook_procedure": EntryPointType.HOOK_PROCEDURE,
        "enum_callback": EntryPointType.CALLBACK_REGISTRATION,
        "exception_handler": EntryPointType.EXCEPTION_HANDLER,
        "service_handler": EntryPointType.SERVICE_CTRL_HANDLER,
        "io_completion": EntryPointType.CALLBACK_REGISTRATION,
        "socket_callback": EntryPointType.TCP_UDP_HANDLER,
    }
    return mapping.get(category, EntryPointType.CALLBACK_REGISTRATION)


# ===========================================================================
# Output Formatting
# ===========================================================================

def _build_compact_summary(entries: list[EntryPoint]) -> dict:
    """Build a domain-specific compact summary for workspace handoff.

    This becomes the content of summary.json (via the ``_summary`` opt-in
    mechanism in helpers.workspace.summarize_json_payload), replacing the
    auto-generated structural metadata that would otherwise only carry key
    names and counts.  Downstream triage steps can read this small file
    instead of loading the full (potentially large) results.json.
    """
    by_type: dict[str, int] = {}
    interfaces: list[str] = []
    seen_ifaces: set[str] = set()

    for ep in entries:
        key = ep.type_label or ep.entry_type.name
        by_type[key] = by_type.get(key, 0) + 1
        for iface_id in (ep.rpc_interface_id, ep.com_clsid):
            if iface_id and iface_id not in seen_ifaces:
                seen_ifaces.add(iface_id)
                interfaces.append(iface_id)

    top_entries = sorted(entries, key=lambda e: e.param_surface.get("pointer_param_count", 0), reverse=True)[:10]
    return {
        "total": len(entries),
        "by_type": by_type,
        "interfaces": interfaces,
        "top10_by_param_surface": [
            {
                "name": e.function_name,
                "type": e.type_label,
                "param_surface": e.param_surface,
                "rpc_opnum": e.rpc_opnum,
                "interface_id": e.rpc_interface_id or e.com_clsid or "",
                "signature": (e.signature or "")[:120],
            }
            for e in top_entries
        ],
    }


def print_results(entries: list[EntryPoint], as_json: bool = False) -> None:
    """Print discovered entry points."""
    if as_json:
        emit_json_list(
            "entrypoints",
            [ep.to_dict() for ep in entries],
            extra={"_summary": _build_compact_summary(entries)},
        )
        return

    # Group by type
    by_type: dict[str, list[EntryPoint]] = {}
    for ep in entries:
        key = ep.type_label or ep.entry_type.name
        by_type.setdefault(key, []).append(ep)

    total = len(entries)
    print(f"{'=' * 80}")
    print(f"ATTACK SURFACE DISCOVERY: {total} entry points found")
    print(f"{'=' * 80}\n")

    # Summary table
    print(f"{'Type':<30} {'Count':>6}")
    print(f"{'-' * 30} {'-' * 6}")
    for type_name in sorted(by_type.keys()):
        print(f"{type_name:<30} {len(by_type[type_name]):>6}")
    print(f"{'-' * 30} {'-' * 6}")
    print(f"{'TOTAL':<30} {total:>6}\n")

    # Detailed listing per type
    for type_name in sorted(by_type.keys()):
        eps = by_type[type_name]
        print(f"\n{'-' * 80}")
        print(f"  {type_name} ({len(eps)} entries)")
        print(f"{'-' * 80}")
        for ep in eps:
            chars = ep.param_surface.get("characteristics", [])
            print(f"  {ep.function_name}")
            if ep.signature:
                print(f"    Signature: {ep.signature[:100]}")
            print(f"    Source:    {ep.detection_source}")
            print(f"    Params:    {ep.param_surface.get('param_count', 0)} params" +
                  (f" ({', '.join(chars)})" if chars else ""))
            if ep.notes:
                for note in ep.notes[:3]:
                    print(f"    Note:      {note[:100]}")
            print()


# ===========================================================================
# Main
# ===========================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Discover all entry points in a module analysis DB.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("db_path", help="Path to individual analysis DB")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument(
        "--type", dest="types", action="append", default=[],
        help="Filter to specific entry point types (repeatable). Use type names like EXPORT_DLL, COM_METHOD, etc.",
    )
    parser.add_argument("--no-cache", action="store_true", help="Bypass result cache")
    args = safe_parse_args(parser)

    db_path = resolve_db_path(args.db_path)
    with db_error_handler(db_path, "entry point discovery"):
        entries = discover_all(db_path, no_cache=args.no_cache)

    if args.types:
        allowed = {t.upper() for t in args.types}
        entries = [ep for ep in entries if ep.entry_type.name in allowed or ep.type_label in allowed]

    # Sort by pointer_param_count descending
    entries.sort(key=lambda ep: ep.param_surface.get("pointer_param_count", 0), reverse=True)

    print_results(entries, as_json=args.json)


if __name__ == "__main__":
    main()
