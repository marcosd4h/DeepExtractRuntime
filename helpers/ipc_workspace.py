"""Workspace IPC server discovery -- intersect extracted modules with COM/RPC/WinRT indexes.

Determines which modules in the current workspace implement COM servers,
RPC interfaces, or WinRT activation servers by cross-referencing the
workspace module list against the system-wide IPC indexes.

Typical usage::

    from helpers.ipc_workspace import discover_workspace_ipc_servers

    result = discover_workspace_ipc_servers()                   # all IPC types
    result = discover_workspace_ipc_servers(ipc_types=["com"])  # COM only
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

from .errors import log_warning

_log = logging.getLogger(__name__)

_WORKSPACE_ROOT = Path(__file__).resolve().parents[1]
_EXTRACTED_CODE_DIR = _WORKSPACE_ROOT / "extracted_code"

ALL_IPC_TYPES = ("com", "rpc", "winrt")


def _resolve_module_filename(folder_name: str) -> Optional[str]:
    """Map a workspace folder name to its canonical PE filename.

    Reads ``file_info.json`` from the module folder to get the authoritative
    ``file_name`` (e.g. ``srvsvc.dll``).  Falls back to heuristic reversal
    of the folder naming convention when the JSON is absent.
    """
    fi_path = _EXTRACTED_CODE_DIR / folder_name / "file_info.json"
    if fi_path.is_file():
        try:
            with open(fi_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            bfi = data.get("basic_file_info", {})
            name = bfi.get("file_name", "")
            if name:
                return name
        except (json.JSONDecodeError, OSError):
            pass

    # Heuristic fallback: reverse the folder convention.
    # Known extensions are replaced at the end: _dll -> .dll, _exe -> .exe, etc.
    for ext in (".dll", ".exe", ".sys", ".drv", ".ocx", ".cpl"):
        suffix = "_" + ext.lstrip(".")
        if folder_name.lower().endswith(suffix):
            stem = folder_name[: len(folder_name) - len(suffix)]
            return f"{stem}{ext}"
    return None


def _get_workspace_modules() -> dict[str, str]:
    """Return ``{canonical_filename: folder_name}`` for all workspace modules."""
    from .function_index import list_extracted_modules

    result: dict[str, str] = {}
    for folder in list_extracted_modules():
        filename = _resolve_module_filename(folder)
        if filename:
            result[filename] = folder
    return result


def _summarize_com_server(server: Any) -> dict[str, Any]:
    """Build a compact summary dict for a single ComServer."""
    return {
        "clsid": server.clsid,
        "name": server.name,
        "server_type": server.server_type,
        "access_contexts": sorted(str(ctx) for ctx in server.access_contexts),
        "runs_as_system": server.runs_as_system,
        "can_elevate": server.can_elevate,
        "is_service": server.is_service,
        "service_name": server.service_name or None,
        "interface_count": len(server.interfaces),
        "method_count": server.method_count,
    }


def _summarize_rpc_interface(iface: Any) -> dict[str, Any]:
    """Build a compact summary dict for a single RpcInterface."""
    return {
        "uuid": iface.interface_id,
        "version": iface.interface_version,
        "procedure_count": iface.procedure_count,
        "procedure_names": list(iface.procedure_names),
        "risk_tier": iface.risk_tier,
        "is_remote_reachable": iface.is_remote_reachable,
        "service_name": iface.service_name or None,
        "pipe_names": iface.pipe_names,
    }


def _summarize_winrt_server(server: Any) -> dict[str, Any]:
    """Build a compact summary dict for a single WinrtServer."""
    return {
        "class_name": server.name,
        "activation_type": server.activation_type,
        "access_contexts": sorted(str(ctx) for ctx in server.access_contexts),
        "trust_level": server.trust_level,
        "runs_as_system": server.runs_as_system,
        "service_name": server.service_name or None,
        "interface_count": server.interface_count,
        "method_count": server.method_count,
    }


def discover_workspace_ipc_servers(
    ipc_types: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Intersect workspace modules with COM/RPC/WinRT indexes.

    Args:
        ipc_types: Which IPC types to check. ``None`` means all three.
                   Valid values: ``"com"``, ``"rpc"``, ``"winrt"``.

    Returns:
        A dict with per-type results keyed by module filename, plus a
        summary with counts.
    """
    types_to_check = set(ipc_types or ALL_IPC_TYPES)
    invalid = types_to_check - set(ALL_IPC_TYPES)
    if invalid:
        raise ValueError(f"Unknown IPC types: {invalid}")

    ws_modules = _get_workspace_modules()
    filenames = list(ws_modules.keys())

    result: dict[str, Any] = {
        "workspace_modules": sorted(filenames),
    }
    summary: dict[str, int] = {
        "total_workspace_modules": len(filenames),
    }

    if "com" in types_to_check:
        com_data = _discover_com(filenames)
        result["com"] = com_data
        summary["com_modules"] = len(com_data)

    if "rpc" in types_to_check:
        rpc_data = _discover_rpc(filenames)
        result["rpc"] = rpc_data
        summary["rpc_modules"] = len(rpc_data)

    if "winrt" in types_to_check:
        winrt_data = _discover_winrt(filenames)
        result["winrt"] = winrt_data
        summary["winrt_modules"] = len(winrt_data)

    result["summary"] = summary
    return result


def _discover_com(filenames: list[str]) -> dict[str, Any]:
    """Check which filenames have COM servers."""
    try:
        from .com_index import get_com_index
        idx = get_com_index()
        if not idx.loaded:
            log_warning("COM index not loaded; skipping COM discovery", "NO_DATA")
            return {}
    except Exception as exc:
        log_warning(f"COM index unavailable: {exc}", "NO_DATA")
        return {}

    matches: dict[str, Any] = {}
    for fname in filenames:
        servers = idx.get_servers_for_module(fname)
        if servers:
            matches[fname] = {
                "server_count": len(servers),
                "servers": [_summarize_com_server(s) for s in servers],
            }
    return matches


def _discover_rpc(filenames: list[str]) -> dict[str, Any]:
    """Check which filenames have RPC interfaces."""
    try:
        from .rpc_index import get_rpc_index
        idx = get_rpc_index()
        if not idx.loaded:
            log_warning("RPC index not loaded; skipping RPC discovery", "NO_DATA")
            return {}
    except Exception as exc:
        log_warning(f"RPC index unavailable: {exc}", "NO_DATA")
        return {}

    matches: dict[str, Any] = {}
    for fname in filenames:
        ifaces = idx.get_interfaces_for_module(fname)
        if ifaces:
            matches[fname] = {
                "interface_count": len(ifaces),
                "interfaces": [_summarize_rpc_interface(i) for i in ifaces],
            }
    return matches


def _discover_winrt(filenames: list[str]) -> dict[str, Any]:
    """Check which filenames have WinRT servers."""
    try:
        from .winrt_index import get_winrt_index
        idx = get_winrt_index()
        if not idx.loaded:
            log_warning("WinRT index not loaded; skipping WinRT discovery", "NO_DATA")
            return {}
    except Exception as exc:
        log_warning(f"WinRT index unavailable: {exc}", "NO_DATA")
        return {}

    matches: dict[str, Any] = {}
    for fname in filenames:
        servers = idx.get_servers_for_module(fname)
        if servers:
            matches[fname] = {
                "server_count": len(servers),
                "servers": [_summarize_winrt_server(s) for s in servers],
            }
    return matches
