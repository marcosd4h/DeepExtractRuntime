#!/usr/bin/env python3
"""Rank discovered entry points by attack value using callgraph reachability.

For each entry point, computes:
  - Number of reachable internal functions (callgraph BFS)
  - Number of dangerous operations reachable (dangerous API sinks)
  - Depth to first dangerous operation
  - Parameter type risk (buffer+size pairs > handles > flags)
  - Composite attack score

Usage:
    python rank_entrypoints.py <db_path>
    python rank_entrypoints.py <db_path> --json
    python rank_entrypoints.py <db_path> --top 20
    python rank_entrypoints.py <db_path> --depth 8 --min-score 0.3

Examples:
    python rank_entrypoints.py extracted_dbs/appinfo_dll_e98d25a9e8.db
    python rank_entrypoints.py extracted_dbs/appinfo_dll_e98d25a9e8.db --json --top 10
    python rank_entrypoints.py extracted_dbs/cmd_exe_6d109a3a00.db --depth 12

Output:
    Prioritized list of entry points ranked by attack score, with reachability
    statistics and recommended tainted arguments.
"""

from __future__ import annotations

import argparse
import re
from collections import Counter
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))

from _common import (
    DANGEROUS_SINK_APIS,
    EntryPoint,
    EntryPointType,
    build_adjacency,
    collect_dangerous_apis_map,
    compute_reachability,
    find_dangerous_ops_reachable,
    parse_json_safe,
    score_parameter_risk,
    _classify_entry_name,
)
from discover_entrypoints import discover_all
from helpers import open_individual_analysis_db
from helpers.cache import get_cached
from helpers.com_index import get_com_index
from helpers.cross_module_graph import CrossModuleGraph
from helpers.db_paths import resolve_tracking_db_auto
from helpers.errors import db_error_handler, log_warning, safe_parse_args
from helpers.json_output import emit_json_list
from helpers.rpc_index import get_rpc_index
from helpers.winrt_index import get_winrt_index


# ===========================================================================
# Ranking Engine
# ===========================================================================

_ROLE_TO_ENTRY_TYPES: dict[str, set[EntryPointType]] = {
    "rpc_server": {EntryPointType.RPC_HANDLER},
    "com_server": {EntryPointType.COM_METHOD, EntryPointType.COM_CLASS_FACTORY},
    "winrt_server": {EntryPointType.WINRT_METHOD},
    "service": {EntryPointType.SERVICE_MAIN, EntryPointType.SERVICE_CTRL_HANDLER},
    "pipe_server": {EntryPointType.NAMED_PIPE_HANDLER},
    "network_server": {EntryPointType.TCP_UDP_HANDLER},
    "ipc_server": {EntryPointType.IPC_DISPATCHER},
    "driver": {EntryPointType.DRIVER_DISPATCH},
}


def _detect_module_roles(
    entries: list[EntryPoint],
    module_name: str,
) -> set[str]:
    """Detect all roles a module serves using ground-truth indices and entry points."""
    roles: set[str] = set()

    rpc_idx = get_rpc_index()
    if rpc_idx.loaded and rpc_idx.get_procedures_for_module(module_name):
        roles.add("rpc_server")

    com_idx = get_com_index()
    if com_idx.loaded and com_idx.get_servers_for_module(module_name):
        roles.add("com_server")

    winrt_idx = get_winrt_index()
    if winrt_idx.loaded and winrt_idx.get_servers_for_module(module_name):
        roles.add("winrt_server")

    types = {ep.entry_type for ep in entries}
    if EntryPointType.SERVICE_MAIN in types or EntryPointType.SERVICE_CTRL_HANDLER in types:
        roles.add("service")
    if EntryPointType.NAMED_PIPE_HANDLER in types:
        roles.add("pipe_server")
    if EntryPointType.TCP_UDP_HANDLER in types:
        roles.add("network_server")
    if EntryPointType.IPC_DISPATCHER in types:
        roles.add("ipc_server")
    if EntryPointType.DRIVER_DISPATCH in types:
        roles.add("driver")

    return roles


def _infer_module_trust(entries: list[EntryPoint]) -> str:
    """Infer module privilege context from discovered entry point types."""
    types = {ep.entry_type for ep in entries}
    if EntryPointType.SERVICE_MAIN in types or EntryPointType.SERVICE_CTRL_HANDLER in types:
        return "system_service"
    if EntryPointType.RPC_HANDLER in types:
        return "rpc_server"
    if EntryPointType.DRIVER_DISPATCH in types:
        return "kernel_adjacent"
    if any(ep.com_can_elevate for ep in entries):
        return "system_service"
    return ""


def rank_entrypoints(
    db_path: str,
    max_depth: int = 10,
    *,
    no_cache: bool = False,
) -> list[EntryPoint]:
    """Discover and rank all entry points for a module.

    Steps:
    1. Run full discovery scan
    2. Build callgraph adjacency from DB
    3. For each entry point, compute reachability via BFS
    4. Count dangerous operations reachable
    5. Score parameters
    6. Detect module roles and trust level
    7. Count cross-module callers (if tracking DB available)
    8. Compute composite attack score (with role + cross-module boosts)
    9. Enrich with upstream classification data
    10. Sort and assign ranks
    """
    entries = discover_all(db_path, no_cache=no_cache)
    if not entries:
        return []

    cached_classification = get_cached(db_path, "classify_module")

    with db_error_handler(db_path, "ranking entry points"):
        with open_individual_analysis_db(db_path) as db:
            adjacency = build_adjacency(db)
            dangerous_map = collect_dangerous_apis_map(db)

            func_by_name: dict[str, int] = {}
            for func in db.get_all_functions():
                if func.function_name:
                    func_by_name[func.function_name] = func.function_id

            module_name = ""
            file_info = db.get_file_info()
            if file_info:
                module_name = file_info.file_name or ""

    for ep in entries:
        reachable = compute_reachability(adjacency, ep.function_name, max_depth=max_depth)
        ep.reachable_count = len(reachable) - 1

        danger_count, danger_apis, min_depth = find_dangerous_ops_reachable(
            adjacency, reachable, dangerous_map
        )
        ep.dangerous_ops_reachable = danger_count
        ep.dangerous_ops_list = danger_apis
        ep.depth_to_first_danger = min_depth

        ep.reachable_functions = sorted(
            [name for name, depth in reachable.items() if name != ep.function_name],
            key=lambda n: reachable[n],
        )[:50]

        ep.tainted_args = _infer_tainted_args(ep)

    module_trust = _infer_module_trust(entries)
    module_roles = _detect_module_roles(entries, module_name) if module_name else set()

    cross_module_callers = (
        _count_cross_module_callers(module_name, {ep.function_name for ep in entries})
        if module_name else {}
    )

    _compute_composite_scores(
        entries,
        module_trust=module_trust,
        module_roles=module_roles,
        cross_module_callers=cross_module_callers,
    )

    if cached_classification and isinstance(cached_classification, dict):
        by_name = {}
        for func_data in cached_classification.get("functions", []):
            if isinstance(func_data, dict):
                by_name[func_data.get("function_name", "")] = func_data
        for ep in entries:
            cls_data = by_name.get(ep.function_name)
            if cls_data:
                cat = cls_data.get("primary_category", "")
                interest = cls_data.get("interest_score", 0)
                if cat:
                    ep.notes.append(f"classified: {cat} (interest {interest}/10)")

    entries.sort(key=lambda ep: ep.attack_score, reverse=True)
    for i, ep in enumerate(entries, 1):
        ep.attack_rank = i

    return entries


def _compute_composite_scores(
    entries: list[EntryPoint],
    *,
    module_trust: str = "",
    module_roles: set[str] | None = None,
    cross_module_callers: dict[str, int] | None = None,
) -> None:
    """Compute composite attack score for all entries.

    Score components (0-1 each, weighted):
      - param_risk (0.25): Parameter type risk
      - danger_reachability (0.30): Dangerous operations reachable (normalized)
      - danger_proximity (0.15): How close the first danger is (inverse depth)
      - reach_breadth (0.15): How many functions are reachable (normalized)
      - type_bonus (0.15): Entry point type inherent risk

    Additive boosts (clamped to [0, 1.0] total):
      - role_match (0.08): Entry type matches one of the module's detected roles
      - cross_module (0-0.15): Called by other modules (0.05 per caller, capped)
    """
    if not entries:
        return

    max_danger = max((ep.dangerous_ops_reachable for ep in entries), default=1) or 1
    max_reach = max((ep.reachable_count for ep in entries), default=1) or 1

    for ep in entries:
        param_score = ep.param_risk_score
        danger_score = min(ep.dangerous_ops_reachable / max_danger, 1.0)

        if ep.depth_to_first_danger is not None:
            proximity = 1.0 / (1.0 + ep.depth_to_first_danger)
        else:
            proximity = 0.0

        reach_score = min(ep.reachable_count / max_reach, 1.0)

        rpc_bonus = _rpc_protocol_bonus(ep)
        com_bonus = _com_privilege_bonus(ep)
        winrt_bonus = _winrt_privilege_bonus(ep)
        type_bonus = max(rpc_bonus, com_bonus, winrt_bonus) or _type_risk_bonus(ep.entry_type, module_trust)

        ep.attack_score = (
            param_score * 0.25 +
            danger_score * 0.30 +
            proximity * 0.15 +
            reach_score * 0.15 +
            type_bonus * 0.15
        )

        if module_roles:
            role_match = any(
                ep.entry_type in _ROLE_TO_ENTRY_TYPES.get(role, set())
                for role in module_roles
            )
            if role_match:
                ep.attack_score += 0.08
                ep.notes.append(f"role boost: module serves as {', '.join(sorted(module_roles))}")

        if cross_module_callers:
            caller_count = cross_module_callers.get(ep.function_name, 0)
            if caller_count > 0:
                xmod_boost = min(caller_count * 0.05, 0.15)
                ep.attack_score += xmod_boost
                ep.notes.append(f"cross-module: called by {caller_count} other module(s)")

        ep.attack_score = min(ep.attack_score, 1.0)


_RPC_PROTOCOL_RISK: dict[str, float] = {
    "ncacn_ip_tcp": 0.95,
    "ncacn_http": 0.95,
    "ncacn_np": 0.85,
}


def _rpc_protocol_bonus(ep: EntryPoint) -> float:
    """Protocol-aware risk bonus for RPC handlers.

    Returns a refined risk score based on the actual transport protocol
    from the RPC index, falling back to the default if no index data.
    """
    if ep.entry_type != EntryPointType.RPC_HANDLER:
        return 0.0

    if not ep.rpc_protocol:
        return 0.9  # Heuristic-only, no index data

    protocols = {p.strip() for p in ep.rpc_protocol.split(",")}

    best = 0.0
    for proto, score in _RPC_PROTOCOL_RISK.items():
        if proto in protocols:
            best = max(best, score)

    if best == 0.0:
        # ncalrpc only
        if ep.rpc_service:
            best = 0.75
        else:
            best = 0.60

    if ep.rpc_risk_tier == "critical":
        best = max(best, 0.95)

    return best


def _com_privilege_bonus(ep: EntryPoint) -> float:
    """Privilege-aware risk bonus for COM entry points."""
    if ep.entry_type not in (EntryPointType.COM_METHOD, EntryPointType.COM_CLASS_FACTORY):
        return 0.0

    if not ep.com_clsid:
        return 0.0

    if ep.com_risk_tier == "critical":
        return 0.95
    if ep.com_can_elevate:
        return 0.90
    if ep.com_risk_tier == "high" or ep.com_service:
        return 0.80
    return 0.75


def _winrt_privilege_bonus(ep: EntryPoint) -> float:
    """Privilege-aware risk bonus for WinRT entry points."""
    if ep.entry_type != EntryPointType.WINRT_METHOD:
        return 0.0

    if not ep.winrt_class_name:
        return 0.0

    if ep.winrt_risk_tier == "critical":
        return 0.90
    if ep.winrt_risk_tier == "high":
        return 0.80
    return 0.70


def _type_risk_bonus(etype: EntryPointType, module_trust: str = "") -> float:
    """Inherent risk bonus by entry point type.

    When the module runs in a privileged trust context (system_service,
    rpc_server, kernel_adjacent), DLL exports and forwarded exports
    receive a boost since they become privilege-boundary entry points.
    """
    bonuses = {
        EntryPointType.RPC_HANDLER: 0.9,
        EntryPointType.NAMED_PIPE_HANDLER: 0.85,
        EntryPointType.TCP_UDP_HANDLER: 0.85,
        EntryPointType.IPC_DISPATCHER: 0.8,
        EntryPointType.COM_METHOD: 0.7,
        EntryPointType.WINRT_METHOD: 0.65,
        EntryPointType.COM_CLASS_FACTORY: 0.7,
        EntryPointType.WINDOW_PROC: 0.6,
        EntryPointType.SERVICE_MAIN: 0.6,
        EntryPointType.SERVICE_CTRL_HANDLER: 0.55,
        EntryPointType.CALLBACK_REGISTRATION: 0.5,
        EntryPointType.SCHEDULED_CALLBACK: 0.5,
        EntryPointType.HOOK_PROCEDURE: 0.65,
        EntryPointType.TLS_CALLBACK: 0.6,
        EntryPointType.EXCEPTION_HANDLER: 0.4,
        EntryPointType.DLLMAIN: 0.5,
        EntryPointType.MAIN_ENTRY: 0.5,
        EntryPointType.DRIVER_DISPATCH: 0.9,
        EntryPointType.EXPORT_DLL: 0.3,
        EntryPointType.EXPORT_ORDINAL_ONLY: 0.35,
        EntryPointType.FORWARDED_EXPORT: 0.3,
    }
    base = bonuses.get(etype, 0.3)

    privileged_contexts = {"system_service", "rpc_server", "kernel_adjacent"}
    if module_trust in privileged_contexts:
        if etype in (EntryPointType.EXPORT_DLL, EntryPointType.EXPORT_ORDINAL_ONLY,
                     EntryPointType.FORWARDED_EXPORT):
            base = max(base, 0.7)

    return base


def _count_cross_module_callers(
    module_name: str,
    entry_names: set[str],
) -> dict[str, int]:
    """Count how many other modules import/call each entry point.

    Uses CrossModuleGraph built from the tracking DB.  Returns an empty
    dict if the tracking DB is unavailable or any error occurs.
    """
    try:
        tracking_db = resolve_tracking_db_auto()
        if not tracking_db:
            return {}

        with CrossModuleGraph.from_tracking_db(tracking_db, modules=[module_name]) as cmg:
            mod_key = module_name.lower()
            callers: dict[str, int] = {}

            dep_map = cmg.module_dependency_map()
            importing_modules = [m for m, deps in dep_map.items() if mod_key in deps]

            for other_mod in importing_modules:
                graph = cmg.get_module_graph(other_mod)
                if graph is None:
                    continue
                seen_in_module: set[str] = set()
                for _caller, ext_calls in graph.external_calls.items():
                    for callee_name, target_module in ext_calls:
                        if (target_module.lower() == mod_key
                                and callee_name in entry_names
                                and callee_name not in seen_in_module):
                            seen_in_module.add(callee_name)
                            callers[callee_name] = callers.get(callee_name, 0) + 1

            return callers
    except Exception as exc:
        log_warning(f"Cross-module caller analysis failed: {exc}", "DB_ERROR")
        return {}


def _infer_tainted_args(ep: EntryPoint) -> list[str]:
    """Infer which arguments should be considered tainted from the signature."""
    tainted: list[str] = []
    if not ep.signature:
        return tainted

    paren_match = re.search(r"\(([^)]*)\)", ep.signature)
    if not paren_match:
        return tainted

    param_str = paren_match.group(1)
    if not param_str.strip() or param_str.strip().lower() == "void":
        return tainted

    params = [p.strip() for p in param_str.split(",") if p.strip()]
    for i, param in enumerate(params):
        if re.search(r"(?:void|char|BYTE|wchar_t|WCHAR)\s*\*", param, re.I):
            tainted.append(f"arg{i} ({param[:40]}): buffer pointer - TAINT")
        elif re.search(r"\bBSTR\b", param, re.I):
            tainted.append(f"arg{i} ({param[:40]}): BSTR (OLECHAR*) - TAINT")
        elif re.search(r"(?:LPWSTR|LPSTR|PWSTR|PSTR|LPCWSTR|LPCSTR|PCWSTR|PCSTR)", param, re.I):
            tainted.append(f"arg{i} ({param[:40]}): string pointer - TAINT")
        elif re.search(r"(?:LPVOID|PVOID|LPBYTE|PBYTE)", param, re.I):
            tainted.append(f"arg{i} ({param[:40]}): raw buffer - TAINT")
        elif re.search(r"(?:IUnknown|IDispatch|I[A-Z]\w+)\s*\*", param, re.I):
            tainted.append(f"arg{i} ({param[:40]}): COM interface - TAINT")
        elif re.search(r"(?:VARIANT|SAFEARRAY)", param, re.I):
            tainted.append(f"arg{i} ({param[:40]}): variant/array - TAINT")
        elif re.search(r"(?:REFIID|REFCLSID|GUID|IID)\b", param, re.I):
            tainted.append(f"arg{i} ({param[:40]}): GUID/IID - PARTIAL_TAINT")
        elif re.search(r"(?:SECURITY_ATTRIBUTES|OVERLAPPED|struct)\s*\*", param, re.I):
            tainted.append(f"arg{i} ({param[:40]}): struct pointer - PARTIAL_TAINT")
        elif re.search(r"(?:HANDLE|HKEY|HMODULE|HINSTANCE|HWND|SOCKET)\b", param, re.I):
            tainted.append(f"arg{i} ({param[:40]}): handle - PARTIAL_TAINT")
        elif re.search(r"(?:DWORD|ULONG|SIZE_T|size_t|unsigned)\b", param, re.I):
            if i > 0 and any("buffer" in t or "string" in t or "raw buffer" in t or "BSTR" in t for t in tainted):
                tainted.append(f"arg{i} ({param[:40]}): size/length - TAINT (controls buffer bounds)")
            elif re.search(r"(?:size|len|count|cb[A-Z]|cch[A-Z]|dw(?:Size|Length|Count|Bytes))\b", param, re.I):
                tainted.append(f"arg{i} ({param[:40]}): size/length - TAINT (name suggests size)")

    return tainted


# ===========================================================================
# Output Formatting
# ===========================================================================

def print_ranked(entries: list[EntryPoint], as_json: bool = False, top_n: int = 0) -> None:
    """Print ranked entry points."""
    if top_n > 0:
        entries = entries[:top_n]

    if as_json:
        emit_json_list("ranked", [ep.to_dict() for ep in entries])
        return

    print(f"{'=' * 90}")
    print(f"ATTACK SURFACE RANKING: {len(entries)} entry points")
    print(f"{'=' * 90}\n")

    # Summary header
    print(f"{'Rank':>4}  {'Score':>6}  {'DangerOps':>9}  {'Reachable':>9}  {'ParamRisk':>9}  {'Type':<25}  Function")
    print(f"{'-' * 4}  {'-' * 6}  {'-' * 9}  {'-' * 9}  {'-' * 9}  {'-' * 25}  {'-' * 40}")

    for ep in entries:
        score_pct = f"{ep.attack_score * 100:.1f}%"
        print(
            f"#{ep.attack_rank:<3}  {score_pct:>6}  "
            f"{ep.dangerous_ops_reachable:>9}  "
            f"{ep.reachable_count:>9}  "
            f"{ep.param_risk_score:>8.2f}  "
            f"{ep.type_label:<25}  "
            f"{ep.function_name}"
        )

    # Detailed top entries
    detail_count = min(len(entries), top_n if top_n > 0 else 15)
    if detail_count > 0:
        print(f"\n\n{'=' * 90}")
        print(f"DETAILED ANALYSIS (top {detail_count})")
        print(f"{'=' * 90}")

    for ep in entries[:detail_count]:
        print(f"\n{'-' * 90}")
        print(f"  #{ep.attack_rank}  {ep.function_name}")
        print(f"{'-' * 90}")
        print(f"  Attack Score:   {_score_bar(ep.attack_score)} ({ep.attack_score * 100:.1f}%)")
        print(f"  Type:           {ep.type_label} ({ep.category})")
        print(f"  Source:         {ep.detection_source}")
        if ep.signature:
            print(f"  Signature:      {ep.signature[:120]}")
        print(f"  Reachable:      {ep.reachable_count} internal functions")
        print(f"  Dangerous ops:  {ep.dangerous_ops_reachable} reachable danger sinks")
        if ep.depth_to_first_danger is not None:
            print(f"  Nearest danger: depth {ep.depth_to_first_danger}")
        if ep.dangerous_ops_list:
            print(f"  Danger APIs:    {', '.join(ep.dangerous_ops_list[:10])}")
        print(f"  Param risk:     {ep.param_risk_score:.2f}")
        if ep.param_risk_reasons:
            print(f"  Risk factors:   {'; '.join(ep.param_risk_reasons)}")
        if ep.tainted_args:
            print(f"  Tainted args:")
            for ta in ep.tainted_args[:8]:
                print(f"    - {ta}")
        if ep.notes:
            print(f"  Notes:")
            for note in ep.notes[:5]:
                print(f"    - {note[:100]}")


def _score_bar(score: float) -> str:
    """Visual score bar."""
    filled = int(score * 20)
    return "[" + "#" * filled + "." * (20 - filled) + "]"


# ===========================================================================
# Main
# ===========================================================================

def rank_single_function(
    db_path: str,
    function_name: str,
    max_depth: int = 10,
    *,
    no_cache: bool = False,
) -> list[EntryPoint]:
    """Analyze a specific function as if it were an entry point.

    Looks up the function by name in the DB, constructs a synthetic EntryPoint,
    then runs the full reachability and scoring pipeline on it.  Works for any
    internal function regardless of whether auto-discovery would have found it.
    """
    from helpers.errors import emit_error, ErrorCode

    with db_error_handler(db_path, f"looking up function '{function_name}'"):
        with open_individual_analysis_db(db_path) as db:
            funcs = db.get_function_by_name(function_name)
            if not funcs:
                emit_error(f"Function not found in DB: {function_name}", ErrorCode.NOT_FOUND)

            func = funcs[0]
            sig = func.function_signature_extended or func.function_signature or ""

            etype = _classify_entry_name(function_name)
            # If name-pattern matching fell back to EXPORT_DLL, consult the
            # RPC ground-truth index before giving up.
            file_info = db.get_file_info()
            module_name = (file_info.file_name if file_info else "") or ""
            rpc_idx = get_rpc_index()
            if etype == EntryPointType.EXPORT_DLL:
                if rpc_idx.loaded and module_name and rpc_idx.is_rpc_procedure(module_name, function_name):
                    etype = EntryPointType.RPC_HANDLER

            ep = EntryPoint(
                function_name=function_name,
                function_id=func.function_id,
                entry_type=etype,
                type_label=etype.name if etype != EntryPointType.EXPORT_DLL else "INTERNAL_FUNCTION",
                category="user_specified",
                detection_source="--function flag (user-specified)",
                signature=sig,
                mangled_name=func.mangled_name or "",
            )
            ep.param_risk_score, ep.param_risk_reasons = score_parameter_risk(sig)
            ep.notes.append("User-specified function (not auto-discovered as entry point)")

            # Enrich RPC fields from the index for any confirmed RPC handler.
            if etype == EntryPointType.RPC_HANDLER and rpc_idx.loaded and module_name:
                iface = rpc_idx.get_interface_for_procedure(module_name, function_name)
                if iface:
                    ep.rpc_interface_id = iface.interface_id or ""
                    ep.rpc_opnum = rpc_idx.procedure_to_opnum(module_name, function_name)
                    ep.rpc_service = getattr(iface, "service_name", "") or ""
                    ep.rpc_risk_tier = getattr(iface, "risk_tier", "") or ""
                    endpoints = getattr(iface, "endpoints", [])
                    if endpoints:
                        ep.rpc_protocol = endpoints[0]

            adjacency = build_adjacency(db)
            dangerous_map = collect_dangerous_apis_map(db)

    reachable = compute_reachability(adjacency, function_name, max_depth=max_depth)
    ep.reachable_count = len(reachable) - 1

    danger_count, danger_apis, min_depth = find_dangerous_ops_reachable(
        adjacency, reachable, dangerous_map
    )
    ep.dangerous_ops_reachable = danger_count
    ep.dangerous_ops_list = danger_apis
    ep.depth_to_first_danger = min_depth

    ep.reachable_functions = sorted(
        [name for name, depth in reachable.items() if name != function_name],
        key=lambda n: reachable[n],
    )[:50]

    ep.tainted_args = _infer_tainted_args(ep)

    _compute_composite_scores([ep])
    ep.attack_rank = 1

    return [ep]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Rank entry points by attack value using callgraph reachability.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("db_path", help="Path to individual analysis DB")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--top", type=int, default=0, help="Show only top N entries")
    parser.add_argument("--depth", type=int, default=10, help="Max callgraph BFS depth (default: 10)")
    parser.add_argument("--min-score", type=float, default=0.0, help="Minimum attack score threshold")
    parser.add_argument(
        "--function", metavar="FUNCTION_NAME",
        help="Analyze a specific function by name (bypasses discovery; works for any internal function)",
    )
    parser.add_argument("--no-cache", action="store_true", help="Bypass result cache")
    args = safe_parse_args(parser)

    if args.function:
        entries = rank_single_function(args.db_path, args.function, max_depth=args.depth, no_cache=args.no_cache)
    else:
        with db_error_handler(args.db_path, "entry point ranking"):
            entries = rank_entrypoints(args.db_path, max_depth=args.depth, no_cache=args.no_cache)
        if args.min_score > 0:
            entries = [ep for ep in entries if ep.attack_score >= args.min_score]

    print_ranked(entries, as_json=args.json, top_n=args.top)


if __name__ == "__main__":
    main()
