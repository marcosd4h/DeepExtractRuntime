#!/usr/bin/env python3
"""Semantic classification of COM method names.

Categorizes methods into functional areas (data access, authentication,
system management, file I/O, etc.) to characterize the attack surface.

Usage:
    python classify_com_entrypoints.py wuapi.dll --json
    python classify_com_entrypoints.py --system-wide --json
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))

from _common import ComMethod, emit_json, parse_context, require_com_index
from helpers.errors import safe_parse_args

_CATEGORY_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("authentication", re.compile(r"(?i)(auth|login|credential|token|identity|impersonat)")),
    ("crypto", re.compile(r"(?i)(crypt|encrypt|decrypt|hash|sign|verify|cert)")),
    ("file_io", re.compile(r"(?i)(file|folder|directory|path|stream|storage|read|write|open|create|delete)(?!.*async)")),
    ("network", re.compile(r"(?i)(network|socket|http|url|connect|download|upload|remote)")),
    ("process", re.compile(r"(?i)(process|launch|execute|run|spawn|shutdown|reboot)")),
    ("registry", re.compile(r"(?i)(registry|regkey|hkey)")),
    ("system_management", re.compile(r"(?i)(system|update|install|config|setting|policy|timezone|power)")),
    ("elevation", re.compile(r"(?i)(elevat|admin|privilege|uac|consent)")),
    ("marshalling", re.compile(r"(?i)(marshal|unmarshal|proxy|stub|interface)")),
    ("data_access", re.compile(r"(?i)(get_|put_|set_|query|enum|list|find|search|exists|tryget|add|remove)")),
    ("event", re.compile(r"(?i)(add_|remove_|event|changed|notify|callback)")),
    ("async_operation", re.compile(r"(?i)(async|await|operation|task)")),
]


def classify_method(method: ComMethod) -> str:
    """Return the semantic category for a COM method name."""
    name = method.short_name
    for category, pattern in _CATEGORY_PATTERNS:
        if pattern.search(name):
            return category
    return "other"


def main() -> None:
    parser = argparse.ArgumentParser(description="Classify COM entry points.")
    parser.add_argument("module", nargs="?", help="Module name")
    parser.add_argument("--system-wide", action="store_true", help="Classify all modules")
    parser.add_argument("--context", help="Filter by access context")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = safe_parse_args(parser)

    idx = require_com_index()
    ctx = parse_context(args.context)

    if args.module and not args.system_wide:
        servers = idx.get_servers_for_module(args.module)
    elif ctx and ctx.is_privileged_server:
        servers = idx.get_privileged_surface(ctx.caller_il)
    else:
        servers = list(idx._servers)

    categories: dict[str, list[dict]] = {}
    for srv in servers:
        for method in srv.methods_flat:
            cat = classify_method(method)
            categories.setdefault(cat, []).append({
                "method": method.name,
                "short_name": method.short_name,
                "server_name": srv.name,
                "clsid": srv.clsid,
                "binary": method.binary_name,
                "risk_tier": srv.best_risk_tier,
            })

    if args.json:
        summary = {cat: len(items) for cat, items in sorted(categories.items())}
        emit_json({
            "scope": args.module or "system_wide",
            "total_methods": sum(len(v) for v in categories.values()),
            "by_category": summary,
            "categories": {
                cat: items for cat, items in sorted(categories.items())
            },
        })
        return

    scope = args.module or "SYSTEM-WIDE"
    total = sum(len(v) for v in categories.values())
    print(f"{'=' * 70}")
    print(f"COM ENTRY POINT CLASSIFICATION: {scope} ({total} methods)")
    print(f"{'=' * 70}")
    print()

    for cat in sorted(categories.keys(), key=lambda c: -len(categories[c])):
        items = categories[cat]
        print(f"  {cat.upper()} ({len(items)} methods)")
        for item in items[:5]:
            print(f"    - {item['short_name']}  [{item['server_name']}]  ({item['risk_tier']})")
        if len(items) > 5:
            print(f"    ... and {len(items) - 5} more")
        print()


if __name__ == "__main__":
    main()
