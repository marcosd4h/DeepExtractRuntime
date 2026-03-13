"""Extract specific keys or search within large JSON files.

Standalone script for rule-compliant JSON field extraction from
agent-tools output files or workspace results.  Replaces inline
``python -c`` post-processing that the guardrails prohibit.

Handles mixed-stream files produced by the Cursor Shell tool, where
stderr status/warning lines (e.g. ``[status] ...``) are captured
alongside the stdout JSON payload.

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


def _looks_mangled_win_path(path_str: str) -> bool:
    """Detect paths where bash stripped backslashes (e.g. ``C:Usersteto...``)."""
    if len(path_str) < 4:
        return False
    if path_str[1] != ":":
        return False
    rest = path_str[2:]
    return "/" not in rest and "\\" not in rest and len(rest) > 3


def _emit_error(message: str, code: str = "PARSE_ERROR") -> None:
    json.dump({"error": message, "code": code}, sys.stderr, ensure_ascii=False)
    sys.stderr.write("\n")
    sys.exit(1)


def _load_json_robust(filepath: Path) -> Any:
    """Load JSON from a file that may contain non-JSON prefix/suffix lines.

    The Cursor Shell tool captures both stdout and stderr into the same
    agent-tools output file.  Scripts emit ``[status]``/``[warning]``
    messages to stderr and JSON to stdout, so the captured file often has
    non-JSON lines before (and occasionally after) the actual payload.

    Strategy:
      1. Fast path -- ``json.loads(text)`` on the raw file.
      2. Slow path -- find the first ``{`` at the start of a line and
         use ``raw_decode`` from that offset, which tolerates trailing
         non-JSON content.
    """
    text = filepath.read_text(encoding="utf-8")

    # Fast path: file is pure JSON
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Slow path: skip non-JSON prefix lines, find the first top-level {
    offset = 0
    for line in text.splitlines(keepends=True):
        stripped = line.lstrip()
        if stripped.startswith("{"):
            try:
                obj, _ = json.JSONDecoder().raw_decode(text, offset + (len(line) - len(stripped)))
                return obj
            except json.JSONDecodeError:
                pass
        offset += len(line)

    raise json.JSONDecodeError(
        "No valid JSON object found (file may contain non-JSON stderr lines "
        "that could not be skipped)",
        text,
        0,
    )


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
        hint = ""
        if _looks_mangled_win_path(args.file):
            hint = (
                " (path looks mangled -- backslashes were likely stripped by bash; "
                "wrap the path in double quotes or use forward slashes)"
            )
        _emit_error(f"File not found: {args.file}{hint}")

    try:
        data = _load_json_robust(filepath)
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
            _emit_error(f"No keys matching '{args.grep_pattern}' in {len(data)} top-level entries", code="NOT_FOUND")
        _emit({"match_count": len(matches), "matches": matches})
        return

    if args.key:
        try:
            value = _deep_get(data, args.key)
        except (KeyError, IndexError, TypeError):
            available = sorted(data.keys()) if isinstance(data, dict) else []
            hint = f"; available top-level keys: {available}" if available else ""
            _emit_error(f"Key path '{args.key}' not found{hint}", code="NOT_FOUND")
        _emit(value)
        return

    parser.print_help()
    sys.exit(1)


if __name__ == "__main__":
    main()
