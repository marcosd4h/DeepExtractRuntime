"""Inspect and diagnose IPC index state -- COM, RPC, WinRT.

Standalone diagnostic tool for verifying index correctness, checking
module attribution, counting edge injection results, and detecting
generic-host misattribution (svchost.exe, dllhost.exe).

Usage::

    # Summary of all three indexes
    python .agent/helpers/ipc_index_inspect.py --summary

    # COM index details
    python .agent/helpers/ipc_index_inspect.py --com

    # Procedures attributed to a specific module
    python .agent/helpers/ipc_index_inspect.py --com --module svchost.exe

    # Cross-module edge injection counts (loads all workspace DBs)
    python .agent/helpers/ipc_index_inspect.py --edges

    # Check for generic-host misattribution
    python .agent/helpers/ipc_index_inspect.py --check-hosts

    # JSON output
    python .agent/helpers/ipc_index_inspect.py --summary --json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from helpers.errors import safe_parse_args
from helpers.json_output import emit_json

_GENERIC_HOSTS = {
    "svchost.exe", "dllhost.exe", "rundll32.exe",
    "taskhostw.exe", "sihost.exe",
}


def _index_summary(idx_type: str, idx) -> dict:
    """Build a summary dict for an IPC index."""
    if not idx.loaded:
        return {"type": idx_type, "loaded": False}

    result: dict = {
        "type": idx_type,
        "loaded": True,
        "module_count": idx.module_count,
    }
    if hasattr(idx, "server_count"):
        result["server_count"] = idx.server_count
    if hasattr(idx, "interface_count"):
        result["interface_count"] = idx.interface_count
    if hasattr(idx, "total_methods"):
        result["total_methods"] = idx.total_methods
    if hasattr(idx, "_procedures_by_module"):
        result["procedure_modules"] = len(idx._procedures_by_module)
        result["total_procedures"] = sum(
            len(v) for v in idx._procedures_by_module.values()
        )
    return result


def _module_detail(idx, module_name: str) -> dict:
    """Get server and procedure details for a specific module."""
    servers = idx.get_servers_for_module(module_name)
    procs = idx.get_procedures_for_module(module_name)
    return {
        "module": module_name,
        "server_count": len(servers),
        "procedure_count": len(procs),
        "servers": [
            getattr(s, "clsid", None) or getattr(s, "name", "?")
            for s in servers
        ],
        "procedures_sample": procs[:20],
    }


def _iter_entries(idx):
    """Yield (hosting_binary, label) for all index entries."""
    if hasattr(idx, "_servers"):
        for srv in idx._servers:
            label = getattr(srv, "clsid", None) or getattr(srv, "name", "?")
            yield (srv.hosting_binary or ""), label
    elif hasattr(idx, "_interfaces"):
        for iface in idx._interfaces:
            yield (iface.binary_name or ""), iface.interface_id


def _top_modules(idx, top_n: int = 15) -> list[dict]:
    """Return top modules by server/interface count."""
    from collections import Counter
    counts = Counter()
    for hosting, _label in _iter_entries(idx):
        h = hosting.lower()
        if h:
            counts[h] += 1
    return [
        {"module": mod, "count": count}
        for mod, count in counts.most_common(top_n)
    ]


def _check_generic_hosts(idx, idx_type: str) -> list[dict]:
    """Check for generic host process misattribution."""
    findings = []
    for hosting, label in _iter_entries(idx):
        h = hosting.lower()
        if h in _GENERIC_HOSTS:
            findings.append({
                "type": idx_type,
                "hosting_binary": h,
                "server": label,
            })

    if hasattr(idx, "_procedures_by_module"):
        for mod_key, procs in idx._procedures_by_module.items():
            if mod_key in _GENERIC_HOSTS:
                findings.append({
                    "type": idx_type,
                    "hosting_binary": mod_key,
                    "issue": "procedures_indexed_under_host",
                    "procedure_count": len(procs),
                })
    return findings


def _get_edge_counts() -> dict[str, int]:
    """Load cross-module graph and return IPC edge injection counts."""
    from helpers.cross_module_graph import CrossModuleGraph
    from helpers.db_paths import resolve_tracking_db

    tracking_db = resolve_tracking_db(Path.cwd())
    graph = CrossModuleGraph.from_tracking_db(tracking_db=tracking_db)
    counts = graph.inject_all_ipc_edges()
    graph.close()
    return counts


def cmd_summary(as_json: bool) -> None:
    from helpers.com_index import get_com_index
    from helpers.rpc_index import get_rpc_index
    from helpers.winrt_index import get_winrt_index

    summaries = [
        _index_summary("com", get_com_index()),
        _index_summary("rpc", get_rpc_index()),
        _index_summary("winrt", get_winrt_index()),
    ]

    if as_json:
        emit_json({"indexes": summaries})
    else:
        for s in summaries:
            print(f"\n=== {s['type'].upper()} Index ===")
            if not s.get("loaded"):
                print("  Not loaded")
                continue
            for k, v in s.items():
                if k not in ("type", "loaded"):
                    print(f"  {k}: {v}")


def cmd_index_detail(idx_type: str, module: str | None, as_json: bool) -> None:
    loaders = {
        "com": lambda: __import__("helpers.com_index", fromlist=["get_com_index"]).get_com_index(),
        "rpc": lambda: __import__("helpers.rpc_index", fromlist=["get_rpc_index"]).get_rpc_index(),
        "winrt": lambda: __import__("helpers.winrt_index", fromlist=["get_winrt_index"]).get_winrt_index(),
    }
    idx = loaders[idx_type]()

    if module:
        detail = _module_detail(idx, module)
        if as_json:
            emit_json(detail)
        else:
            print(f"\n=== {idx_type.upper()} -- {module} ===")
            print(f"  Servers: {detail['server_count']}")
            print(f"  Procedures: {detail['procedure_count']}")
            if detail["servers"]:
                for s in detail["servers"][:10]:
                    print(f"    {s}")
            if detail["procedures_sample"]:
                print(f"  Procedures (first 20):")
                for p in detail["procedures_sample"]:
                    print(f"    {p}")
    else:
        summary = _index_summary(idx_type, idx)
        top = _top_modules(idx)
        if as_json:
            emit_json({**summary, "top_modules": top})
        else:
            print(f"\n=== {idx_type.upper()} Index ===")
            for k, v in summary.items():
                if k not in ("type",):
                    print(f"  {k}: {v}")
            print(f"\n  Top modules by server count:")
            for entry in top:
                print(f"    {entry['module']}: {entry['server_count']}")


def cmd_edges(as_json: bool) -> None:
    from helpers.progress import status_message
    status_message("Loading cross-module graph and injecting IPC edges...")
    counts = _get_edge_counts()
    if as_json:
        emit_json({"edge_counts": counts})
    else:
        print("\n=== IPC Edge Injection ===")
        for ipc_type, count in counts.items():
            print(f"  {ipc_type.upper()}: {count}")
        print(f"  Total: {sum(counts.values())}")


def cmd_check_hosts(as_json: bool) -> None:
    from helpers.com_index import get_com_index
    from helpers.rpc_index import get_rpc_index
    from helpers.winrt_index import get_winrt_index

    findings = []
    findings.extend(_check_generic_hosts(get_com_index(), "com"))
    findings.extend(_check_generic_hosts(get_winrt_index(), "winrt"))

    if as_json:
        emit_json({
            "generic_host_findings": len(findings),
            "findings": findings,
        })
    else:
        if not findings:
            print("No generic-host misattribution found.")
        else:
            print(f"\n{len(findings)} generic-host attribution(s) found:")
            for f in findings:
                print(f"  [{f['type']}] {f['hosting_binary']}: {f.get('server', f.get('issue', '?'))}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Inspect and diagnose IPC index state",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--summary", action="store_true", help="Show summary of all indexes")
    parser.add_argument("--com", action="store_true", help="COM index details")
    parser.add_argument("--rpc", action="store_true", help="RPC index details")
    parser.add_argument("--winrt", action="store_true", help="WinRT index details")
    parser.add_argument("--module", metavar="NAME", help="Show details for a specific module")
    parser.add_argument("--edges", action="store_true", help="Show IPC edge injection counts")
    parser.add_argument("--check-hosts", action="store_true", help="Check for generic-host misattribution")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = safe_parse_args(parser)

    ran = False
    if args.summary:
        cmd_summary(args.json)
        ran = True
    if args.com:
        cmd_index_detail("com", args.module, args.json)
        ran = True
    if args.rpc:
        cmd_index_detail("rpc", args.module, args.json)
        ran = True
    if args.winrt:
        cmd_index_detail("winrt", args.module, args.json)
        ran = True
    if args.edges:
        cmd_edges(args.json)
        ran = True
    if args.check_hosts:
        cmd_check_hosts(args.json)
        ran = True

    if not ran:
        cmd_summary(args.json)


if __name__ == "__main__":
    main()
