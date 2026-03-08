#!/usr/bin/env python3
"""Build PE-level module dependency graphs from import tables.

Usage:
    python .agent/skills/import-export-resolver/scripts/module_deps.py --json
    python .agent/skills/import-export-resolver/scripts/module_deps.py --module appinfo.dll --json
    python .agent/skills/import-export-resolver/scripts/module_deps.py --module ntdll.dll --consumers --json
    python .agent/skills/import-export-resolver/scripts/module_deps.py --diagram
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))

from _common import (
    ImportExportIndex,
    emit_error,
    emit_json,
    resolve_tracking_db,
    status_message,
)
from helpers.errors import safe_parse_args


def analyze_deps(
    tracking_db: str | None,
    *,
    module: str | None = None,
    consumers: bool = False,
    no_cache: bool = False,
) -> dict:
    """Build dependency information from PE import tables."""
    resolved = tracking_db or resolve_tracking_db()
    if resolved is None:
        emit_error(
            "No tracking database found. Run find_module_db.py --list "
            "to verify available modules.",
            "NOT_FOUND",
        )

    status_message("Building PE-level dependency graph...")
    with ImportExportIndex(str(resolved), no_cache=no_cache) as idx:
        if module and consumers:
            raw = idx.module_consumers(module)
            result = {
                "status": "ok",
                "mode": "consumers",
                "target_module": module,
                "consumers": {
                    mod: sorted(set(funcs)) for mod, funcs in raw.items()
                },
                "consumer_count": len(raw),
            }
        elif module:
            raw = idx.module_suppliers(module)
            result = {
                "status": "ok",
                "mode": "suppliers",
                "target_module": module,
                "suppliers": {
                    src: sorted(set(funcs)) for src, funcs in raw.items()
                },
                "supplier_count": len(raw),
            }
        else:
            graph = idx.dependency_graph()
            result = {
                "status": "ok",
                "mode": "full_graph",
                "graph": {
                    mod: sorted(deps) for mod, deps in graph.items()
                },
                "module_count": len(graph),
                "edge_count": sum(len(d) for d in graph.values()),
            }

    result["_meta"] = {
        "tracking_db": str(resolved),
        "generated": datetime.now(timezone.utc).isoformat(),
    }
    return result


def format_text(data: dict) -> str:
    """Human-readable output."""
    lines = []
    mode = data.get("mode", "full_graph")

    if mode == "consumers":
        target = data.get("target_module", "?")
        consumers = data.get("consumers", {})
        lines.append(f"## Modules importing from `{target}` ({len(consumers)})\n")
        for mod, funcs in sorted(consumers.items()):
            lines.append(f"- **{mod}** ({len(funcs)} functions)")
            for f in funcs[:10]:
                lines.append(f"  - `{f}`")
            if len(funcs) > 10:
                lines.append(f"  - _... and {len(funcs) - 10} more_")

    elif mode == "suppliers":
        target = data.get("target_module", "?")
        suppliers = data.get("suppliers", {})
        lines.append(f"## `{target}` imports from ({len(suppliers)} modules)\n")
        for src, funcs in sorted(suppliers.items()):
            lines.append(f"- **{src}** ({len(funcs)} functions)")
            for f in funcs[:10]:
                lines.append(f"  - `{f}`")
            if len(funcs) > 10:
                lines.append(f"  - _... and {len(funcs) - 10} more_")

    else:
        graph = data.get("graph", {})
        lines.append(
            f"## PE Module Dependency Graph "
            f"({data.get('module_count', 0)} modules, "
            f"{data.get('edge_count', 0)} edges)\n"
        )
        for mod, deps in sorted(graph.items()):
            lines.append(f"- **{mod}** -> {', '.join(sorted(deps))}")

    return "\n".join(lines)


def format_diagram(data: dict) -> str:
    """Mermaid diagram output."""
    lines = ["```mermaid", "flowchart LR"]

    if data.get("mode") == "full_graph":
        graph = data.get("graph", {})
    elif data.get("mode") == "suppliers":
        target = data.get("target_module", "unknown")
        graph = {target: set(data.get("suppliers", {}).keys())}
    elif data.get("mode") == "consumers":
        target = data.get("target_module", "unknown")
        graph = {
            mod: {target} for mod in data.get("consumers", {}).keys()
        }
    else:
        graph = {}

    node_ids: dict[str, str] = {}
    counter = 0
    for mod in sorted(
        set(graph.keys()) | {d for deps in graph.values() for d in deps}
    ):
        node_id = f"m{counter}"
        node_ids[mod] = node_id
        safe_label = mod.replace('"', "'")
        lines.append(f'    {node_id}["{safe_label}"]')
        counter += 1

    for mod, deps in sorted(graph.items()):
        src_id = node_ids.get(mod, mod)
        for dep in sorted(deps):
            dst_id = node_ids.get(dep, dep)
            lines.append(f"    {src_id} --> {dst_id}")

    lines.append("```")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PE-level module dependency graph from import tables"
    )
    parser.add_argument(
        "tracking_db_path",
        nargs="?",
        default=None,
        help="Path to analyzed_files.db (auto-detected if omitted)",
    )
    parser.add_argument(
        "--module", help="Focus on a specific module"
    )
    parser.add_argument(
        "--consumers",
        action="store_true",
        help="Show modules that import FROM --module (reverse deps)",
    )
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument(
        "--diagram", action="store_true", help="Output Mermaid diagram"
    )
    parser.add_argument(
        "--no-cache", action="store_true", help="Bypass result cache"
    )
    args = safe_parse_args(parser)

    if args.consumers and not args.module:
        parser.error("--consumers requires --module")

    result = analyze_deps(
        args.tracking_db_path,
        module=args.module,
        consumers=args.consumers,
        no_cache=args.no_cache,
    )

    if args.json:
        emit_json(result)
    elif args.diagram:
        print(format_diagram(result))
    else:
        print(format_text(result))


if __name__ == "__main__":
    main()
