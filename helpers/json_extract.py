"""Extract specific keys or search within large JSON files.

Standalone script for rule-compliant JSON field extraction from
agent-tools output files or workspace results.  Replaces inline
``python -c`` post-processing that the guardrails prohibit.

Usage::

    # Direct key lookup (top-level)
    python .agent/helpers/json_extract.py <file> <key>

    # Dotted path lookup
    python .agent/helpers/json_extract.py <file> "module.security_posture.cfg"

    # Substring search across all top-level keys
    python .agent/helpers/json_extract.py <file> --grep "18006336C"

    # List top-level keys only (structure preview)
    python .agent/helpers/json_extract.py <file> --keys
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _deep_get(obj: Any, path: str) -> Any:
    """Traverse *obj* by dotted *path*, returning the nested value or raising KeyError."""
    parts = path.split(".")
    current = obj
    for part in parts:
        if isinstance(current, dict):
            current = current[part]
        elif isinstance(current, list) and part.isdigit():
            current = current[int(part)]
        else:
            raise KeyError(part)
    return current


def _grep_keys(obj: dict, needle: str) -> dict:
    """Return top-level entries whose key contains *needle* (case-insensitive)."""
    needle_lower = needle.lower()
    return {k: v for k, v in obj.items() if needle_lower in k.lower()}


def _emit(data: Any) -> None:
    json.dump(data, sys.stdout, indent=2, default=str, ensure_ascii=False)
    sys.stdout.write("\n")


def _emit_error(message: str, code: str = "PARSE_ERROR") -> None:
    json.dump({"error": message, "code": code}, sys.stderr, ensure_ascii=False)
    sys.stderr.write("\n")
    sys.exit(1)


def main() -> None:
    from helpers.errors import safe_parse_args

    parser = argparse.ArgumentParser(
        description="Extract specific keys or search within a JSON file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("file", help="Path to the JSON file to query")
    parser.add_argument("key", nargs="?", default=None, help="Key or dotted path to extract (e.g. 'module.name')")
    parser.add_argument("--grep", dest="grep_pattern", help="Substring search across top-level keys")
    parser.add_argument("--keys", action="store_true", help="List top-level keys only")
    args = safe_parse_args(parser)

    filepath = Path(args.file)
    if not filepath.is_file():
        _emit_error(f"File not found: {args.file}")

    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        _emit_error(f"Invalid JSON: {exc}")

    if args.keys:
        if isinstance(data, dict):
            _emit({"key_count": len(data), "keys": sorted(data.keys())})
        elif isinstance(data, list):
            _emit({"type": "array", "length": len(data)})
        else:
            _emit({"type": type(data).__name__, "value_preview": str(data)[:200]})
        return

    if args.grep_pattern:
        if not isinstance(data, dict):
            _emit_error("--grep requires a JSON object (dict) at the top level")
        matches = _grep_keys(data, args.grep_pattern)
        if not matches:
            _emit_error(f"No keys matching '{args.grep_pattern}' in {len(data)} top-level entries")
        _emit({"match_count": len(matches), "matches": matches})
        return

    if args.key:
        try:
            value = _deep_get(data, args.key)
        except (KeyError, IndexError, TypeError):
            _emit_error(f"Key path '{args.key}' not found")
        _emit(value)
        return

    parser.print_help()
    sys.exit(1)


if __name__ == "__main__":
    main()
