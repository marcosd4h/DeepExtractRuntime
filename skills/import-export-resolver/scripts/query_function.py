#!/usr/bin/env python3
"""Resolve which modules export and/or import a given function.

Usage:
    python .agent/skills/import-export-resolver/scripts/query_function.py --function CreateProcessW
    python .agent/skills/import-export-resolver/scripts/query_function.py --function HeapAlloc --direction export --json
    python .agent/skills/import-export-resolver/scripts/query_function.py path/to/analyzed_files.db --function NtCreateFile --json
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


def query_function(
    tracking_db: str | None,
    function_name: str,
    direction: str = "both",
    *,
    no_cache: bool = False,
) -> dict:
    """Find exporters and importers for *function_name*."""
    resolved = tracking_db or resolve_tracking_db()
    if resolved is None:
        emit_error(
            "No tracking database found. Run find_module_db.py --list "
            "to verify available modules.",
            "NOT_FOUND",
        )

    status_message(f"Resolving '{function_name}' across all modules...")
    with ImportExportIndex(str(resolved), no_cache=no_cache) as idx:
        exporters = []
        importers = []

        if direction in ("export", "both"):
            for exp in idx.who_exports(function_name):
                exporters.append(exp.to_dict())

        if direction in ("import", "both"):
            for imp in idx.who_imports(function_name):
                importers.append(imp.to_dict())

    result: dict = {
        "status": "ok",
        "function": function_name,
        "direction": direction,
    }
    if direction in ("export", "both"):
        result["exporters"] = exporters
    if direction in ("import", "both"):
        result["importers"] = importers
    result["_meta"] = {
        "tracking_db": str(resolved),
        "generated": datetime.now(timezone.utc).isoformat(),
    }
    return result


def format_text(data: dict) -> str:
    """Human-readable output."""
    lines = [f"## Resolution for `{data['function']}`\n"]
    direction = data.get("direction", "both")

    exporters = data.get("exporters", [])
    if direction in ("export", "both"):
        lines.append(f"### Exporters ({len(exporters)})\n")
        if exporters:
            for exp in exporters:
                fwd = ""
                if exp.get("is_forwarded"):
                    fwd = f" -> {exp.get('forwarded_to', '?')}"
                lines.append(
                    f"- **{exp['module']}** ordinal={exp.get('ordinal', '?')}{fwd}"
                )
        else:
            lines.append("_No modules export this function._")
        lines.append("")

    importers = data.get("importers", [])
    if direction in ("import", "both"):
        lines.append(f"### Importers ({len(importers)})\n")
        if importers:
            for imp in importers:
                delay = " (delay-loaded)" if imp.get("is_delay_loaded") else ""
                lines.append(
                    f"- **{imp['importing_module']}** from "
                    f"`{imp['source_module']}`{delay}"
                )
        else:
            lines.append("_No modules import this function._")
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Resolve which modules export/import a function"
    )
    parser.add_argument(
        "tracking_db_path",
        nargs="?",
        default=None,
        help="Path to analyzed_files.db (auto-detected if omitted)",
    )
    parser.add_argument(
        "--function",
        required=True,
        help="Function name to resolve",
    )
    parser.add_argument(
        "--direction",
        choices=["export", "import", "both"],
        default="both",
        help="Search direction (default: both)",
    )
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument(
        "--no-cache", action="store_true", help="Bypass result cache"
    )
    args = safe_parse_args(parser)

    result = query_function(
        args.tracking_db_path, args.function, args.direction,
        no_cache=args.no_cache,
    )

    if args.json:
        emit_json(result)
    else:
        print(format_text(result))


if __name__ == "__main__":
    main()
