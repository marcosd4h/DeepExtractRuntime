#!/usr/bin/env python3
"""Discover which workspace modules implement COM, RPC, or WinRT servers.

Cross-references the extracted modules in this workspace against the
system-wide IPC indexes and reports which modules are IPC servers,
with per-server access context and security metadata.

Usage::

    # All IPC types (default)
    python discover_workspace_ipc.py --json

    # Specific IPC types
    python discover_workspace_ipc.py --type com --json
    python discover_workspace_ipc.py --type rpc --type winrt --json

    # Human-readable table (no --json)
    python discover_workspace_ipc.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))

from _common import WORKSPACE_ROOT  # noqa: E402

from helpers.errors import safe_parse_args, emit_error  # noqa: E402
from helpers.json_output import emit_json  # noqa: E402
from helpers.progress import status_message  # noqa: E402
from helpers.ipc_workspace import discover_workspace_ipc_servers, ALL_IPC_TYPES  # noqa: E402


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Discover workspace modules that implement COM/RPC/WinRT servers.",
    )
    parser.add_argument(
        "--type",
        dest="ipc_types",
        action="append",
        choices=list(ALL_IPC_TYPES),
        help="IPC type(s) to check (repeatable). Default: all.",
    )
    parser.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Emit structured JSON output.",
    )
    return parser


def _print_table(result: dict) -> None:
    """Print a human-readable summary table."""
    summary = result.get("summary", {})
    total = summary.get("total_workspace_modules", 0)
    print(f"\n=== Workspace IPC Server Discovery ({total} modules scanned) ===\n")

    for ipc_type in ALL_IPC_TYPES:
        if ipc_type not in result:
            continue

        data = result[ipc_type]
        count = summary.get(f"{ipc_type}_modules", 0)
        label = {"com": "COM Servers", "rpc": "RPC Interfaces", "winrt": "WinRT Servers"}[ipc_type]
        print(f"--- {label} ({count} module(s)) ---")

        if not data:
            print("  (none)\n")
            continue

        for module, info in sorted(data.items()):
            if ipc_type == "com":
                srv_count = info["server_count"]
                print(f"  {module}: {srv_count} server(s)")
                for srv in info["servers"]:
                    ctxs = ", ".join(srv["access_contexts"])
                    flags = []
                    if srv["runs_as_system"]:
                        flags.append("SYSTEM")
                    if srv["can_elevate"]:
                        flags.append("elevate")
                    if srv["is_service"]:
                        flags.append("service")
                    flag_str = f" [{', '.join(flags)}]" if flags else ""
                    print(f"    {srv['clsid']} {srv['name'] or '(unnamed)'}{flag_str}")
                    print(f"      type={srv['server_type']}  ifaces={srv['interface_count']}  methods={srv['method_count']}")
                    print(f"      contexts: {ctxs}")

            elif ipc_type == "rpc":
                iface_count = info["interface_count"]
                print(f"  {module}: {iface_count} interface(s)")
                for iface in info["interfaces"]:
                    remote = " [REMOTE]" if iface["is_remote_reachable"] else ""
                    pipes = f" pipes={iface['pipe_names']}" if iface["pipe_names"] else ""
                    print(f"    {iface['uuid']} v{iface['version']}  risk={iface['risk_tier']}{remote}{pipes}")
                    print(f"      {iface['procedure_count']} procedure(s): {', '.join(iface['procedure_names'][:5])}", end="")
                    if iface["procedure_count"] > 5:
                        print(f" ... (+{iface['procedure_count'] - 5} more)", end="")
                    print()

            elif ipc_type == "winrt":
                srv_count = info["server_count"]
                print(f"  {module}: {srv_count} server(s)")
                for srv in info["servers"]:
                    ctxs = ", ".join(srv["access_contexts"])
                    flags = []
                    if srv["runs_as_system"]:
                        flags.append("SYSTEM")
                    flag_str = f" [{', '.join(flags)}]" if flags else ""
                    print(f"    {srv['class_name']}{flag_str}")
                    print(f"      activation={srv['activation_type']}  trust={srv['trust_level']}  ifaces={srv['interface_count']}  methods={srv['method_count']}")
                    print(f"      contexts: {ctxs}")

        print()

    if all(not result.get(t) for t in ALL_IPC_TYPES if t in result):
        print("No workspace modules implement COM, RPC, or WinRT servers.\n")


def main() -> None:
    parser = _build_parser()
    args = safe_parse_args(parser)

    ipc_types = args.ipc_types or None
    type_label = ", ".join(ipc_types) if ipc_types else "all"
    status_message(f"Discovering workspace IPC servers ({type_label})...")

    result = discover_workspace_ipc_servers(ipc_types=ipc_types)

    if args.as_json:
        emit_json(result)
    else:
        _print_table(result)


if __name__ == "__main__":
    main()
