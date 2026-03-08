#!/usr/bin/env python3
"""Build and display the cross-module PE import/export index.

Usage:
    python .agent/skills/import-export-resolver/scripts/build_index.py
    python .agent/skills/import-export-resolver/scripts/build_index.py --json
    python .agent/skills/import-export-resolver/scripts/build_index.py path/to/analyzed_files.db --no-cache
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
    cache_result,
    emit_error,
    emit_json,
    get_cached,
    resolve_tracking_db,
    status_message,
)
from helpers.errors import safe_parse_args


def build_index(tracking_db: str | None, *, no_cache: bool = False) -> dict:
    """Build the import/export index and return summary stats."""
    resolved = tracking_db or resolve_tracking_db()
    if resolved is None:
        emit_error(
            "No tracking database found. Run find_module_db.py --list "
            "to verify available modules.",
            "NOT_FOUND",
        )

    if not no_cache:
        cached = get_cached(str(resolved), "import_export_index")
        if cached is not None:
            return cached

    status_message("Building cross-module import/export index...")
    with ImportExportIndex(str(resolved), no_cache=no_cache) as idx:
        result = idx.summary()

    result["status"] = "ok"
    result["_meta"] = {
        "tracking_db": str(resolved),
        "generated": datetime.now(timezone.utc).isoformat(),
    }

    cache_result(str(resolved), "import_export_index", result)
    return result


def format_text(data: dict) -> str:
    """Human-readable summary."""
    lines = ["## PE Import/Export Index Summary\n"]
    lines.append(f"Modules indexed:       {data.get('module_count', 0)}")
    lines.append(f"Total exports:         {data.get('total_exports', 0)}")
    lines.append(f"Total imports:         {data.get('total_imports', 0)}")
    lines.append(f"Forwarded exports:     {data.get('forwarded_count', 0)}")
    lines.append(f"Unique export names:   {data.get('unique_export_names', 0)}")
    lines.append(f"Unique import names:   {data.get('unique_import_names', 0)}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build cross-module PE import/export index"
    )
    parser.add_argument(
        "tracking_db_path",
        nargs="?",
        default=None,
        help="Path to analyzed_files.db (auto-detected if omitted)",
    )
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument(
        "--no-cache", action="store_true", help="Bypass result cache"
    )
    args = safe_parse_args(parser)

    result = build_index(args.tracking_db_path, no_cache=args.no_cache)

    if args.json:
        emit_json(result)
    else:
        print(format_text(result))


if __name__ == "__main__":
    main()
