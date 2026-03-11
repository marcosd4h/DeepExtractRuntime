#!/usr/bin/env python3
"""Follow forwarded PE export chains across DLLs.

Usage:
    python .agent/skills/import-export-resolver/scripts/resolve_forwarders.py --module kernel32.dll --function HeapAlloc
    python .agent/skills/import-export-resolver/scripts/resolve_forwarders.py --module kernel32.dll --all --json
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
from helpers.errors import ErrorCode, emit_error, safe_parse_args


def resolve_forwarders(
    tracking_db: str | None,
    *,
    module: str | None = None,
    function: str | None = None,
    all_forwarded: bool = False,
    no_cache: bool = False,
) -> dict:
    """Follow forwarded export chains."""
    resolved = tracking_db or resolve_tracking_db()
    if resolved is None:
        emit_error(
            "No tracking database found. Run find_module_db.py --list "
            "to verify available modules.",
            "NOT_FOUND",
        )

    with ImportExportIndex(str(resolved), no_cache=no_cache) as idx:
        if function and module:
            status_message(
                f"Resolving forwarder chain: {module}!{function}"
            )
            chain = idx.resolve_forwarder_chain(module, function)
            chain_dicts = [
                {"module": m, "function": f} for m, f in chain
            ]
            result = {
                "status": "ok",
                "mode": "single",
                "start_module": module,
                "start_function": function,
                "chain": chain_dicts,
                "chain_length": len(chain),
            }

        elif all_forwarded and module:
            status_message(
                f"Finding all forwarded exports in {module}..."
            )
            exports = idx.module_export_list(module)
            chains = []
            for exp in exports:
                if exp.is_forwarded and exp.forwarded_to:
                    chain = idx.resolve_forwarder_chain(module, exp.name)
                    chains.append({
                        "export": exp.name,
                        "forwarded_to": exp.forwarded_to,
                        "chain": [
                            {"module": m, "function": f}
                            for m, f in chain
                        ],
                    })
            result = {
                "status": "ok",
                "mode": "all_forwarded",
                "module": module,
                "forwarded_exports": chains,
                "forwarded_count": len(chains),
            }
        else:
            emit_error(
                "Provide --module and --function, or --module and --all.",
                "INVALID_ARGS",
            )
            return {}  # unreachable; emit_error exits

    result["_meta"] = {
        "tracking_db": str(resolved),
        "generated": datetime.now(timezone.utc).isoformat(),
    }
    return result


def format_text(data: dict) -> str:
    """Human-readable output."""
    lines = []
    mode = data.get("mode", "single")

    if mode == "single":
        chain = data.get("chain", [])
        lines.append(
            f"## Forwarder chain for "
            f"`{data.get('start_module')}!{data.get('start_function')}`\n"
        )
        for i, hop in enumerate(chain):
            prefix = "  " * i
            arrow = "-> " if i > 0 else ""
            lines.append(f"{prefix}{arrow}**{hop['module']}**!`{hop['function']}`")
        if len(chain) <= 1:
            lines.append("\n_Not a forwarded export (chain length 1)._")

    elif mode == "all_forwarded":
        module = data.get("module", "?")
        chains = data.get("forwarded_exports", [])
        lines.append(
            f"## Forwarded exports in `{module}` ({len(chains)})\n"
        )
        for entry in chains:
            chain = entry.get("chain", [])
            chain_str = " -> ".join(
                f"{h['module']}!{h['function']}" for h in chain
            )
            lines.append(f"- `{entry['export']}`: {chain_str}")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Follow forwarded PE export chains across DLLs"
    )
    parser.add_argument(
        "tracking_db_path",
        nargs="?",
        default=None,
        help="Path to analyzed_files.db (auto-detected if omitted)",
    )
    parser.add_argument("--module", help="Source module name")
    parser.add_argument("--function", help="Export function name")
    parser.add_argument(
        "--all",
        dest="all_forwarded",
        action="store_true",
        help="Show all forwarded exports in --module",
    )
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument(
        "--no-cache", action="store_true", help="Bypass result cache"
    )
    args = safe_parse_args(parser)

    if not args.module:
        emit_error("--module is required", ErrorCode.INVALID_ARGS)
    if not args.function and not args.all_forwarded:
        emit_error("Provide --function or --all", ErrorCode.INVALID_ARGS)

    result = resolve_forwarders(
        args.tracking_db_path,
        module=args.module,
        function=args.function,
        all_forwarded=args.all_forwarded,
        no_cache=args.no_cache,
    )

    if args.json:
        emit_json(result)
    else:
        print(format_text(result))


if __name__ == "__main__":
    main()
