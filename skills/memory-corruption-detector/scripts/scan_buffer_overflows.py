"""Detect buffer overflow vulnerabilities in decompiled functions.

Scans for: bounded copy APIs (memcpy, memmove, etc.) with tainted/unchecked
size arguments, unbounded copy APIs (strcpy, strcat, etc.) used on tainted
sources, and stack buffer writes with unchecked tainted sizes.
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
    COPY_APIS,
    MemCorruptionFinding,
    RE_STACK_BUFFER,
    SCANNER_DEFAULT_TOP_N,
    UNBOUNDED_COPY_APIS,
    _is_size_capped,
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
    is_copy_api,
    is_safe_bounded_copy_api,
    is_unbounded_copy_api,
    load_all_functions_slim,
    load_function_record,
    matches_api_list,
    resolve_db_path,
    status_message,
    validate_function_id,
)
from helpers.errors import ErrorCode, safe_parse_args


# ---------------------------------------------------------------------------
# Detection routines
# ---------------------------------------------------------------------------

def _check_bounded_copy(
    call: dict,
    code: str,
    params: set[str],
    fname: str,
    fid: int,
    asm: str,
) -> MemCorruptionFinding | None:
    """Check a bounded copy API (memcpy/memmove/etc.) for tainted size."""
    args = call.get("arguments", [])
    if len(args) < 3:
        return None

    size_arg = args[2].strip()
    taint_result = analyze_taint(code, {f"a{p}" for p in params})
    tainted_vars = taint_result.tainted_vars

    size_vars = set(re.findall(r"\b(a\d+|v\d+)\b", size_arg))
    tainted_size_vars = size_vars & tainted_vars

    if not tainted_size_vars:
        return None

    if _is_size_capped(size_arg, code, call.get("line_number", 0)):
        return None

    dst_arg = args[0].strip()
    is_stack = bool(RE_STACK_BUFFER.search(asm)) if asm else False
    category = "stack_overflow" if is_stack else "heap_overflow"

    return MemCorruptionFinding(
        category=category,
        function_name=fname,
        function_id=fid,
        summary=f"{call['function_name']}() with tainted size from "
                f"{', '.join(sorted(tainted_size_vars))}; "
                f"dst={'stack buffer' if is_stack else dst_arg}",
        dangerous_api=call["function_name"],
        dangerous_api_category="copy",
        size_source=size_arg,
        evidence_lines=[call["line"]],
        extra={
            "dst_arg": dst_arg,
            "size_arg": size_arg,
            "tainted_size_vars": sorted(tainted_size_vars),
            "is_stack_dst": is_stack,
            "line_number": call["line_number"],
        },
    )


def _check_unbounded_copy(
    call: dict,
    code: str,
    params: set[str],
    fname: str,
    fid: int,
    asm: str,
) -> MemCorruptionFinding | None:
    """Check an unbounded copy API (strcpy/strcat/etc.) for tainted source."""
    args = call.get("arguments", [])
    if len(args) < 2:
        return None

    src_arg = args[1].strip()
    taint_result = analyze_taint(code, {f"a{p}" for p in params})
    tainted_vars = taint_result.tainted_vars

    src_vars = set(re.findall(r"\b(a\d+|v\d+)\b", src_arg))
    tainted_src_vars = src_vars & tainted_vars

    is_stack = bool(RE_STACK_BUFFER.search(asm)) if asm else False
    category = "stack_overflow" if is_stack else "heap_overflow"

    if tainted_src_vars:
        return MemCorruptionFinding(
            category=category,
            function_name=fname,
            function_id=fid,
            summary=f"Unbounded {call['function_name']}() with tainted source "
                    f"from {', '.join(sorted(tainted_src_vars))}",
            dangerous_api=call["function_name"],
            dangerous_api_category="unbounded_copy",
            size_source="unbounded",
            evidence_lines=[call["line"]],
            extra={
                "dst_arg": args[0].strip(),
                "src_arg": src_arg,
                "tainted_src_vars": sorted(tainted_src_vars),
                "is_stack_dst": is_stack,
                "line_number": call["line_number"],
            },
        )

    # Even without tainted source, unbounded copy into stack buffer is risky
    if is_stack:
        return MemCorruptionFinding(
            category="stack_overflow",
            function_name=fname,
            function_id=fid,
            summary=f"Unbounded {call['function_name']}() into stack buffer",
            severity="MEDIUM",
            dangerous_api=call["function_name"],
            dangerous_api_category="unbounded_copy",
            size_source="unbounded",
            evidence_lines=[call["line"]],
            extra={
                "dst_arg": args[0].strip(),
                "src_arg": src_arg,
                "is_stack_dst": True,
                "line_number": call["line_number"],
            },
        )

    return None


def detect_buffer_overflows(func: dict[str, Any]) -> list[MemCorruptionFinding]:
    """Detect buffer overflow patterns in a single function record."""
    findings: list[MemCorruptionFinding] = []
    code = func.get("decompiled_code", "")
    asm = func.get("assembly_code", "")
    sig = func.get("function_signature", "")
    fname = func["function_name"]
    fid = func["function_id"]

    if not code:
        return findings

    params = extract_param_names(sig)
    xrefs = func.get("outbound_xrefs", [])
    calls = discover_calls_with_xrefs(code, xrefs) if xrefs else extract_function_calls(code)

    for call in calls:
        api = call["function_name"]

        if is_safe_bounded_copy_api(api):
            continue

        if is_copy_api(api):
            finding = _check_bounded_copy(call, code, params, fname, fid, asm)
            if finding:
                findings.append(finding)

        elif is_unbounded_copy_api(api):
            finding = _check_unbounded_copy(call, code, params, fname, fid, asm)
            if finding:
                findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# Single function scan
# ---------------------------------------------------------------------------

def scan_single_function(db_path: str, function_id: int) -> list[MemCorruptionFinding]:
    """Scan a single function for buffer overflow patterns."""
    rec = load_function_record(db_path, function_id=function_id)
    if not rec or not rec["decompiled_code"]:
        return []
    return detect_buffer_overflows(rec)


# ---------------------------------------------------------------------------
# Module-wide scan
# ---------------------------------------------------------------------------

def scan_module(
    db_path: str,
    top_n: int = 100,
    no_cache: bool = False,
) -> dict:
    """Scan all functions for buffer overflow vulnerabilities."""
    if not no_cache:
        cached = get_cached(db_path, "memcorrupt_buffer")
        if cached is not None:
            return cached

    status_message("Loading functions for buffer overflow scan...")
    functions = load_all_functions_slim(db_path)
    if not functions:
        return {"status": "ok", "findings": [], "summary": {"total": 0}}

    export_names = build_export_names(db_path)
    all_findings: list[MemCorruptionFinding] = []

    status_message(f"Scanning {len(functions)} functions for buffer overflow patterns...")

    for func in functions:
        fname = func["function_name"]
        is_exported = fname in export_names

        for f in detect_buffer_overflows(func):
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
        "_meta": build_meta(db_path, scanner="buffer_overflows", top_n=top_n),
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
        cache_result(db_path, "memcorrupt_buffer", result)

    return result


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def print_text(data: dict) -> None:
    summary = data.get("summary", {})
    findings = data.get("findings", [])
    print(f"=== Buffer Overflow Scan: {summary.get('total', 0)} findings ===\n")
    for cat, count in sorted(summary.get("by_category", {}).items()):
        print(f"  {cat}: {count}")
    print()
    for i, f in enumerate(findings, 1):
        print(f"  [{i}] [{f['severity']}] {f['score']:.2f}  {f['function_name']}")
        print(f"      Category: {f['category']}")
        print(f"      {f['summary']}")
        if f.get("dangerous_api"):
            print(f"      API: {f['dangerous_api']}")
        if f.get("size_source"):
            print(f"      Size source: {f['size_source']}")
        print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Detect buffer overflow vulnerabilities in decompiled functions"
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
            "_meta": build_meta(db_path, scanner="buffer_overflows", mode="single"),
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
