"""Detect format string vulnerabilities in decompiled functions.

Scans for: calls to FORMAT_APIS where the format string argument is not a
constant string literal, and uses def-use chain analysis to check whether
the non-constant format string flows from a tainted parameter.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))

from _common import (
    FORMAT_APIS,
    MemCorruptionFinding,
    SCANNER_DEFAULT_TOP_N,
    analyze_taint,
    build_export_names,
    build_meta,
    cache_result,
    compute_memcorrupt_score,
    emit_error,
    discover_calls_with_xrefs,
    emit_json,
    extract_function_calls,
    extract_param_names,
    get_cached,
    get_format_arg_position,
    is_format_api,
    load_all_functions_slim,
    load_function_record,
    resolve_db_path,
    status_message,
    validate_function_id,
)
from helpers.errors import ErrorCode, safe_parse_args


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

RE_STRING_LITERAL = re.compile(
    r"""
    ^"[^"]*"$           # Simple double-quoted string
    |^L"[^"]*"$         # Wide string literal
    |^u"[^"]*"$         # Unicode string literal
    |^a[A-Z]\w*$        # IDA string constant reference (aErrorS, etc.)
    """,
    re.VERBOSE,
)

RE_VAR = re.compile(r"\b(a\d+|v\d+)\b")


def _is_constant_format(arg_expr: str) -> bool:
    """Check if a format argument is a constant string literal."""
    stripped = arg_expr.strip()

    if stripped.startswith('"') and stripped.endswith('"'):
        return True
    if stripped.startswith('L"') and stripped.endswith('"'):
        return True

    # IDA often generates string references like aFormatString or off_xxx
    if re.match(r"^a[A-Z]\w*$", stripped):
        return True
    if re.match(r"^off_[0-9A-Fa-f]+$", stripped):
        return True

    # Cast to string pointer with constant: (const char *)"..."
    if re.search(r'"\s*$', stripped) and '"' in stripped:
        return True

    return False


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def detect_format_strings(func: dict[str, Any]) -> list[MemCorruptionFinding]:
    """Detect format string vulnerabilities in a single function."""
    findings: list[MemCorruptionFinding] = []
    code = func.get("decompiled_code", "")
    sig = func.get("function_signature", "")
    fname = func["function_name"]
    fid = func["function_id"]

    if not code:
        return findings

    params = extract_param_names(sig)
    initial_tainted = {f"a{p}" for p in params}
    taint_result = analyze_taint(code, initial_tainted)
    tainted_vars = taint_result.tainted_vars

    xrefs = func.get("outbound_xrefs", [])
    calls = discover_calls_with_xrefs(code, xrefs) if xrefs else extract_function_calls(code)

    for call in calls:
        api = call["function_name"]
        if not is_format_api(api):
            continue

        fmt_pos = get_format_arg_position(api)
        args = call.get("arguments", [])

        if fmt_pos >= len(args):
            continue

        fmt_arg = args[fmt_pos].strip()

        if _is_constant_format(fmt_arg):
            continue

        fmt_vars = set(RE_VAR.findall(fmt_arg))
        tainted_fmt_vars = fmt_vars & tainted_vars

        if tainted_fmt_vars:
            severity_boost = "tainted parameter"
            findings.append(MemCorruptionFinding(
                category="format_string",
                function_name=fname,
                function_id=fid,
                summary=f"{api}() with tainted format string from "
                        f"{', '.join(sorted(tainted_fmt_vars))}",
                dangerous_api=api,
                dangerous_api_category="format",
                size_source=fmt_arg,
                evidence_lines=[call["line"]],
                extra={
                    "format_arg": fmt_arg,
                    "format_arg_position": fmt_pos,
                    "tainted_fmt_vars": sorted(tainted_fmt_vars),
                    "taint_source": "parameter",
                    "line_number": call["line_number"],
                },
            ))
        elif fmt_vars:
            findings.append(MemCorruptionFinding(
                category="format_string",
                function_name=fname,
                function_id=fid,
                summary=f"{api}() with non-constant format string '{fmt_arg}' "
                        f"(variable, not confirmed tainted)",
                dangerous_api=api,
                dangerous_api_category="format",
                size_source=fmt_arg,
                evidence_lines=[call["line"]],
                extra={
                    "format_arg": fmt_arg,
                    "format_arg_position": fmt_pos,
                    "format_vars": sorted(fmt_vars),
                    "taint_source": "unknown",
                    "line_number": call["line_number"],
                },
            ))
        else:
            findings.append(MemCorruptionFinding(
                category="format_string",
                function_name=fname,
                function_id=fid,
                summary=f"{api}() with non-constant format expression '{fmt_arg}'",
                dangerous_api=api,
                dangerous_api_category="format",
                size_source=fmt_arg,
                evidence_lines=[call["line"]],
                extra={
                    "format_arg": fmt_arg,
                    "format_arg_position": fmt_pos,
                    "taint_source": "expression",
                    "line_number": call["line_number"],
                },
            ))

    return findings


# ---------------------------------------------------------------------------
# Single function scan
# ---------------------------------------------------------------------------

def scan_single_function(db_path: str, function_id: int) -> list[MemCorruptionFinding]:
    """Scan a single function for format string vulnerabilities."""
    rec = load_function_record(db_path, function_id=function_id)
    if not rec or not rec["decompiled_code"]:
        return []
    return detect_format_strings(rec)


# ---------------------------------------------------------------------------
# Module-wide scan
# ---------------------------------------------------------------------------

def scan_module(
    db_path: str,
    top_n: int = 100,
    no_cache: bool = False,
) -> dict:
    """Scan all functions for format string vulnerabilities."""
    if not no_cache:
        cached = get_cached(db_path, "memcorrupt_format")
        if cached is not None:
            return cached

    status_message("Loading functions for format string scan...")
    functions = load_all_functions_slim(db_path)
    if not functions:
        return {"status": "ok", "findings": [], "summary": {"total": 0}}

    export_names = build_export_names(db_path)
    all_findings: list[MemCorruptionFinding] = []

    status_message(f"Scanning {len(functions)} functions for format string issues...")

    for func in functions:
        fname = func["function_name"]
        is_exported = fname in export_names

        for f in detect_format_strings(func):
            f.score, f.severity = compute_memcorrupt_score(
                f.category,
                is_exported=is_exported,
                is_entry_reachable=True,
            )
            all_findings.append(f)

    all_findings.sort(key=lambda f: f.score, reverse=True)
    top_findings = all_findings[:top_n]

    result = {
        "status": "ok",
        "_meta": build_meta(db_path, scanner="format_strings", top_n=top_n),
        "findings": [f.to_dict() for f in top_findings],
        "summary": {
            "total": len(all_findings),
            "returned": len(top_findings),
            "by_category": {},
        },
    }
    for f in all_findings:
        result["summary"]["by_category"][f.category] = (
            result["summary"]["by_category"].get(f.category, 0) + 1
        )

    if not no_cache:
        cache_result(db_path, "memcorrupt_format", result)

    return result


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def print_text(data: dict) -> None:
    summary = data.get("summary", {})
    findings = data.get("findings", [])
    print(f"=== Format String Scan: {summary.get('total', 0)} findings ===\n")
    for cat, count in sorted(summary.get("by_category", {}).items()):
        print(f"  {cat}: {count}")
    print()
    for i, f in enumerate(findings, 1):
        print(f"  [{i}] [{f['severity']}] {f['score']:.2f}  {f['function_name']}")
        print(f"      Category: {f['category']}")
        print(f"      {f['summary']}")
        if f.get("dangerous_api"):
            print(f"      API: {f['dangerous_api']}")
        extra = f.get("extra", {})
        if extra.get("format_arg"):
            print(f"      Format arg: {extra['format_arg']}")
        if extra.get("taint_source"):
            print(f"      Taint source: {extra['taint_source']}")
        print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Detect format string vulnerabilities in decompiled functions"
    )
    parser.add_argument("db_path", help="Path to the individual analysis database")
    fn_group = parser.add_mutually_exclusive_group()
    fn_group.add_argument("--function", "--name", dest="function_name", metavar="NAME",
                          help="Scan a single function by name")
    fn_group.add_argument("--id", type=int, dest="function_id",
                          help="Scan a single function by ID")
    parser.add_argument("--top", type=int, default=SCANNER_DEFAULT_TOP_N,
                        help="Return top N findings (default: 30)")
    parser.add_argument("--json", action="store_true", help="JSON output mode")
    parser.add_argument("--no-cache", action="store_true", help="Bypass cache")
    args = safe_parse_args(parser)

    db_path = resolve_db_path(args.db_path)

    if args.function_name and args.function_id is None:
        rec = load_function_record(db_path, function_name=args.function_name)
        if rec is None:
            emit_error(f"Function '{args.function_name}' not found", ErrorCode.NOT_FOUND)
        args.function_id = rec["function_id"]

    if args.function_id is not None:
        args.function_id = validate_function_id(args.function_id)
        findings = scan_single_function(db_path, args.function_id)
        for f in findings:
            f.score, f.severity = compute_memcorrupt_score(f.category)
        result = {
            "status": "ok",
            "_meta": build_meta(db_path, scanner="format_strings", mode="single"),
            "findings": [f.to_dict() for f in findings],
            "summary": {"total": len(findings)},
        }
    else:
        result = scan_module(db_path, top_n=args.top, no_cache=args.no_cache)

    if args.json:
        emit_json(result)
    else:
        print_text(result)


if __name__ == "__main__":
    main()
