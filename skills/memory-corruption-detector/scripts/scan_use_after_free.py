"""Detect use-after-free and double-free vulnerabilities.

Scans for: memory use after deallocation via FREE_APIS, double-free of the
same pointer, and freed pointers that are not nulled after free.  Uses
def-use chain analysis to track freed variable usage.
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
    FREE_APIS,
    ALLOC_APIS,
    MemCorruptionFinding,
    SCANNER_DEFAULT_TOP_N,
    build_export_names,
    build_meta,
    cache_result,
    compute_memcorrupt_score,
    emit_error,
    discover_calls_with_xrefs,
    emit_json,
    extract_function_calls,
    get_cached,
    is_alloc_api,
    is_free_api,
    load_all_functions_slim,
    load_function_record,
    resolve_db_path,
    status_message,
    validate_function_id,
)
from helpers.errors import safe_parse_args


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

RE_VAR = re.compile(r"\b(a\d+|v\d+)\b")
RE_NULL_ASSIGN = re.compile(r"\b(a\d+|v\d+)\s*=\s*(?:0|NULL|nullptr|0LL|0i64)\s*;")
RE_STRUCT_FIELD_NULL = re.compile(
    r"(?:this|self|\w+)\s*->\s*\w+\s*=\s*(?:0|NULL|nullptr|0LL|0i64)\s*;",
)


# ---------------------------------------------------------------------------
# Detection routines
# ---------------------------------------------------------------------------

def _extract_freed_var(call: dict) -> str | None:
    """Extract the pointer variable being freed from a free API call.

    For HeapFree/RtlFreeHeap the pointer is arg 2 (0-indexed),
    for free/LocalFree/GlobalFree/CoTaskMemFree/SysFreeString it is arg 0.
    """
    args = call.get("arguments", [])
    api = call["function_name"]

    clean = api
    for pfx in ("__imp_", "_imp_", "j_", "cs:"):
        if clean.startswith(pfx):
            clean = clean[len(pfx):]

    if clean.startswith(("HeapFree", "RtlFreeHeap")):
        if len(args) >= 3:
            m = RE_VAR.search(args[2])
            return m.group(1) if m else None
    elif clean.startswith("VirtualFree"):
        if len(args) >= 1:
            m = RE_VAR.search(args[0])
            return m.group(1) if m else None
    else:
        if args:
            m = RE_VAR.search(args[0])
            return m.group(1) if m else None

    return None


def _is_null_after_free(lines: list[str], free_line: int, freed_var: str) -> bool:
    """Check if the freed variable is nulled or safely reassigned after free.

    Searches up to 50 lines after the free call for:
    - Direct null assignment: ``var = NULL;``
    - Struct-field null assignment when *freed_var* appears in the LHS
    - Re-assignment via any allocator API (HeapAlloc, malloc, etc.)
    """
    search_end = min(free_line + 50, len(lines))
    for i in range(free_line, search_end):
        stripped = lines[i].strip()
        m = RE_NULL_ASSIGN.match(stripped)
        if m and m.group(1) == freed_var:
            return True
        if RE_STRUCT_FIELD_NULL.match(stripped) and freed_var in stripped:
            return True
        assign_match = re.match(rf"\s*{re.escape(freed_var)}\s*=", stripped)
        if assign_match:
            for alloc in ALLOC_APIS:
                if alloc in stripped:
                    return True
    return False


def _is_reallocated(lines: list[str], start_line: int, end_line: int, var: str) -> bool:
    """Check if a variable is reassigned via allocation between two lines."""
    for i in range(start_line, min(end_line, len(lines))):
        stripped = lines[i].strip()
        assign_match = re.match(rf"\s*{re.escape(var)}\s*=", stripped)
        if assign_match:
            for alloc in ALLOC_APIS:
                if alloc in stripped:
                    return True
            if "malloc" in stripped or "calloc" in stripped or "realloc" in stripped:
                return True
    return False


def detect_use_after_free(func: dict[str, Any]) -> list[MemCorruptionFinding]:
    """Detect use-after-free and double-free patterns in a single function."""
    findings: list[MemCorruptionFinding] = []
    code = func.get("decompiled_code", "")
    fname = func["function_name"]
    fid = func["function_id"]

    if not code:
        return findings

    xrefs = func.get("outbound_xrefs", [])
    calls = discover_calls_with_xrefs(code, xrefs) if xrefs else extract_function_calls(code)
    lines = code.splitlines()

    free_calls = [(c, _extract_freed_var(c)) for c in calls if is_free_api(c["function_name"])]
    free_calls = [(c, v) for c, v in free_calls if v is not None]

    if not free_calls:
        return findings

    freed_state: dict[str, list[dict]] = {}

    for call, freed_var in free_calls:
        free_line = call["line_number"]

        if freed_var in freed_state:
            prev_free = freed_state[freed_var][-1]
            prev_line = prev_free["line_number"]
            if not _is_reallocated(lines, prev_line, free_line - 1, freed_var):
                findings.append(MemCorruptionFinding(
                    category="double_free",
                    function_name=fname,
                    function_id=fid,
                    summary=f"Double free of '{freed_var}': first at line {prev_line}, "
                            f"again at line {free_line} via {call['function_name']}()",
                    dangerous_api=call["function_name"],
                    dangerous_api_category="free",
                    evidence_lines=[prev_free["line_text"], call["line"]],
                    extra={
                        "freed_var": freed_var,
                        "first_free_line": prev_line,
                        "second_free_line": free_line,
                        "free_api": call["function_name"],
                    },
                ))

        freed_state.setdefault(freed_var, []).append({
            "line_number": free_line,
            "line_text": call["line"],
            "api": call["function_name"],
        })

        is_nulled = _is_null_after_free(lines, free_line, freed_var)
        if is_nulled:
            continue

        for subsequent_call in calls:
            if subsequent_call["line_number"] <= free_line:
                continue
            if is_free_api(subsequent_call["function_name"]):
                continue

            sub_args = subsequent_call.get("arguments", [])
            args_text = " ".join(sub_args)
            if freed_var not in args_text:
                continue

            if _is_reallocated(lines, free_line, subsequent_call["line_number"] - 1, freed_var):
                continue

            findings.append(MemCorruptionFinding(
                category="use_after_free",
                function_name=fname,
                function_id=fid,
                summary=f"'{freed_var}' freed at line {free_line} via "
                        f"{call['function_name']}(), then used at line "
                        f"{subsequent_call['line_number']} in "
                        f"{subsequent_call['function_name']}()",
                dangerous_api=subsequent_call["function_name"],
                dangerous_api_category="use_after_free",
                evidence_lines=[call["line"], subsequent_call["line"]],
                extra={
                    "freed_var": freed_var,
                    "free_line": free_line,
                    "free_api": call["function_name"],
                    "use_line": subsequent_call["line_number"],
                    "use_api": subsequent_call["function_name"],
                    "nulled_after_free": False,
                },
            ))
            break

        for use_line_num in range(free_line, min(free_line + 20, len(lines))):
            stripped = lines[use_line_num].strip()
            if "(" in stripped:
                _parts = stripped.split("(")[0].strip().split()
                if _parts and is_free_api(_parts[-1]):
                    continue
            if RE_NULL_ASSIGN.match(stripped):
                break

            deref_patterns = [
                rf"\*\s*{re.escape(freed_var)}\b",
                rf"{re.escape(freed_var)}\s*->",
                rf"{re.escape(freed_var)}\s*\[",
            ]
            for pat in deref_patterns:
                if re.search(pat, stripped):
                    if _is_reallocated(lines, free_line, use_line_num, freed_var):
                        break
                    findings.append(MemCorruptionFinding(
                        category="use_after_free",
                        function_name=fname,
                        function_id=fid,
                        summary=f"'{freed_var}' freed at line {free_line}, "
                                f"dereferenced at line {use_line_num + 1}",
                        dangerous_api=call["function_name"],
                        dangerous_api_category="use_after_free",
                        evidence_lines=[call["line"], stripped],
                        extra={
                            "freed_var": freed_var,
                            "free_line": free_line,
                            "free_api": call["function_name"],
                            "deref_line": use_line_num + 1,
                            "deref_text": stripped,
                            "nulled_after_free": False,
                        },
                    ))
                    break

    return findings


# ---------------------------------------------------------------------------
# Single function scan
# ---------------------------------------------------------------------------

def scan_single_function(db_path: str, function_id: int) -> list[MemCorruptionFinding]:
    """Scan a single function for UAF/double-free patterns."""
    rec = load_function_record(db_path, function_id=function_id)
    if not rec or not rec["decompiled_code"]:
        return []
    return detect_use_after_free(rec)


# ---------------------------------------------------------------------------
# Module-wide scan
# ---------------------------------------------------------------------------

def scan_module(
    db_path: str,
    top_n: int = 100,
    no_cache: bool = False,
) -> dict:
    """Scan all functions for use-after-free and double-free vulnerabilities."""
    if not no_cache:
        cached = get_cached(db_path, "memcorrupt_uaf")
        if cached is not None:
            return cached

    status_message("Loading functions for UAF scan...")
    functions = load_all_functions_slim(db_path)
    if not functions:
        return {"status": "ok", "findings": [], "summary": {"total": 0}}

    export_names = build_export_names(db_path)
    all_findings: list[MemCorruptionFinding] = []

    status_message(f"Scanning {len(functions)} functions for UAF/double-free patterns...")

    for func in functions:
        fname = func["function_name"]
        is_exported = fname in export_names

        for f in detect_use_after_free(func):
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
        "_meta": build_meta(db_path, scanner="use_after_free", top_n=top_n),
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
        cache_result(db_path, "memcorrupt_uaf", result)

    return result


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def print_text(data: dict) -> None:
    summary = data.get("summary", {})
    findings = data.get("findings", [])
    print(f"=== Use-After-Free Scan: {summary.get('total', 0)} findings ===\n")
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
        if extra.get("freed_var"):
            print(f"      Freed var: {extra['freed_var']}")
        print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Detect use-after-free and double-free vulnerabilities"
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
            emit_error(f"Function '{args.function_name}' not found", "NOT_FOUND")
        args.function_id = rec["function_id"]

    if args.function_id is not None:
        args.function_id = validate_function_id(args.function_id)
        findings = scan_single_function(db_path, args.function_id)
        for f in findings:
            f.score, f.severity = compute_memcorrupt_score(f.category)
        result = {
            "status": "ok",
            "_meta": build_meta(db_path, scanner="use_after_free", mode="single"),
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
