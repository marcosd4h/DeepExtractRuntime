"""Detect integer overflow and truncation vulnerabilities.

Scans for: integer arithmetic on tainted parameters before allocation calls,
integer truncation (larger to smaller type) before size-sensitive operations,
and multiplication/addition without subsequent overflow checks before
allocator invocations.
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
    ALLOC_APIS,
    COPY_APIS,
    MemCorruptionFinding,
    RE_MUL_INSN,
    RE_TRUNCATION_CAST,
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
    is_alloc_api,
    is_copy_api,
    load_all_functions_slim,
    load_function_record,
    matches_api_list,
    parse_def_use,
    propagate_taint,
    resolve_db_path,
    status_message,
    validate_function_id,
)
from helpers.errors import safe_parse_args


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

RE_ARITHMETIC = re.compile(
    r"\b(a\d+|v\d+)\s*[*+\-]\s*(a\d+|v\d+|\d+)",
)

RE_SHIFT_LEFT = re.compile(
    r"\b(a\d+|v\d+)\s*<<\s*(\d+|a\d+|v\d+)",
)

RE_OVERFLOW_CHECK = re.compile(
    r"""
    \bif\s*\(
    .*?
    (?:
        \b(?:a\d+|v\d+)\s*[<>]=?\s*(?:0x[fF]+|\d{5,}|MAXDWORD|UINT_MAX|SIZE_MAX|INT_MAX)
        |
        (?:FAILED|NT_ERROR|IS_ERROR)\s*\(
        |
        \b(?:a\d+|v\d+)\s*/\s*(?:a\d+|v\d+)\s*!=\s*(?:a\d+|v\d+)
        |
        UInt\w*(?:Add|Mult|Sub)\s*\(
        |
        SUCCEEDED\s*\(\s*UInt
        |
        Intsafe
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Detection routines
# ---------------------------------------------------------------------------

def _find_arithmetic_before_alloc(
    calls: list[dict],
    code: str,
    tainted_vars: set[str],
    lines: list[str],
) -> list[tuple[int, str, str, str]]:
    """Find arithmetic on tainted vars that flows to an allocation size arg.

    Returns list of (line_number, arith_expr, alloc_api, size_arg).
    """
    results: list[tuple[int, str, str, str]] = []

    alloc_calls = [c for c in calls if is_alloc_api(c["function_name"])]
    if not alloc_calls:
        return results

    for line_num, raw_line in enumerate(lines, 1):
        stripped = raw_line.strip()
        arith_match = RE_ARITHMETIC.search(stripped)
        shift_match = RE_SHIFT_LEFT.search(stripped)
        match = arith_match or shift_match
        if not match:
            continue

        involved = set(re.findall(r"\b(a\d+|v\d+)\b", match.group(0)))
        if not (involved & tainted_vars):
            continue

        assign_match = re.match(r"\s*(v\d+)\s*=", stripped)
        if not assign_match:
            continue
        result_var = assign_match.group(1)

        between_code = "\n".join(lines[line_num - 1:])
        if RE_OVERFLOW_CHECK.search(between_code.split(";", 3)[0] if ";" in between_code else between_code[:500]):
            continue

        for ac in alloc_calls:
            if ac["line_number"] <= line_num:
                continue
            ac_args = ac.get("arguments", [])
            for arg_expr in ac_args:
                if result_var in arg_expr:
                    results.append((
                        line_num,
                        match.group(0).strip(),
                        ac["function_name"],
                        arg_expr.strip(),
                    ))
                    break

    return results


def _find_truncation_before_size_use(
    calls: list[dict],
    code: str,
    tainted_vars: set[str],
    lines: list[str],
) -> list[tuple[int, str, str, str]]:
    """Find integer truncation casts before size-sensitive API calls.

    Returns list of (line_number, truncated_var, target_api, cast_expr).
    """
    results: list[tuple[int, str, str, str]] = []

    size_calls = [c for c in calls if is_alloc_api(c["function_name"]) or is_copy_api(c["function_name"])]
    if not size_calls:
        return results

    for line_num, raw_line in enumerate(lines, 1):
        stripped = raw_line.strip()
        cast_match = RE_TRUNCATION_CAST.search(stripped)
        if not cast_match:
            continue

        cast_end = cast_match.end()
        after_cast = stripped[cast_end:cast_end + 30]
        cast_vars = set(re.findall(r"\b(a\d+|v\d+)\b", after_cast))
        if not (cast_vars & tainted_vars):
            continue

        assign_match = re.match(r"\s*(v\d+)\s*=", stripped)
        truncated_var = assign_match.group(1) if assign_match else None

        for sc in size_calls:
            if sc["line_number"] <= line_num:
                continue
            sc_args = sc.get("arguments", [])
            for arg_expr in sc_args:
                if truncated_var and truncated_var in arg_expr:
                    results.append((
                        line_num,
                        truncated_var,
                        sc["function_name"],
                        stripped,
                    ))
                    break
                for cv in cast_vars & tainted_vars:
                    if cv in arg_expr:
                        results.append((
                            line_num,
                            cv,
                            sc["function_name"],
                            stripped,
                        ))
                        break

    return results


def _check_asm_mul_before_alloc(asm: str) -> list[dict[str, Any]]:
    """Check assembly for mul/imul instructions without overflow check before call to allocator."""
    if not asm:
        return []

    hits: list[dict[str, Any]] = []
    lines = asm.splitlines()

    for i, line in enumerate(lines):
        if not RE_MUL_INSN.search(line):
            continue

        has_overflow_check = False
        has_alloc_call = False
        alloc_target = ""

        for j in range(i + 1, min(i + 30, len(lines))):
            subsequent = lines[j].strip()
            if re.search(r"\bj[onc]\b", subsequent, re.IGNORECASE):
                has_overflow_check = True
                break
            call_match = re.search(r"\bcall\s+.*?(\w+)", subsequent, re.IGNORECASE)
            if call_match:
                target = call_match.group(1)
                if matches_api_list(target, ALLOC_APIS):
                    has_alloc_call = True
                    alloc_target = target
                break

        if has_alloc_call and not has_overflow_check:
            hits.append({
                "mul_line": i + 1,
                "mul_insn": line.strip(),
                "alloc_target": alloc_target,
            })

    return hits


def detect_integer_issues(func: dict[str, Any]) -> list[MemCorruptionFinding]:
    """Detect integer overflow/truncation patterns in a single function."""
    findings: list[MemCorruptionFinding] = []
    code = func.get("decompiled_code", "")
    asm = func.get("assembly_code", "")
    sig = func.get("function_signature", "")
    fname = func["function_name"]
    fid = func["function_id"]

    if not code:
        return findings

    params = extract_param_names(sig)
    initial_tainted = {f"a{p}" for p in params}
    defs, uses = parse_def_use(code)
    taint_result = propagate_taint(defs, uses, initial_tainted)
    tainted_vars = taint_result.tainted_vars

    xrefs = func.get("outbound_xrefs", [])
    calls = discover_calls_with_xrefs(code, xrefs) if xrefs else extract_function_calls(code)
    lines = code.splitlines()

    # Integer overflow: arithmetic on tainted vars before allocation
    for line_num, arith_expr, alloc_api, size_arg in _find_arithmetic_before_alloc(
        calls, code, tainted_vars, lines
    ):
        findings.append(MemCorruptionFinding(
            category="integer_overflow",
            function_name=fname,
            function_id=fid,
            summary=f"Tainted arithmetic '{arith_expr}' flows to "
                    f"{alloc_api}() size arg without overflow check",
            dangerous_api=alloc_api,
            dangerous_api_category="allocation",
            alloc_api=alloc_api,
            size_source=size_arg,
            evidence_lines=[lines[line_num - 1].strip() if line_num <= len(lines) else arith_expr],
            extra={
                "arithmetic_expr": arith_expr,
                "alloc_api": alloc_api,
                "size_arg": size_arg,
                "line_number": line_num,
            },
        ))

    # Integer truncation before size-sensitive use
    for line_num, trunc_var, target_api, cast_line in _find_truncation_before_size_use(
        calls, code, tainted_vars, lines
    ):
        findings.append(MemCorruptionFinding(
            category="integer_truncation",
            function_name=fname,
            function_id=fid,
            summary=f"Truncation of tainted '{trunc_var}' before "
                    f"{target_api}() size argument",
            dangerous_api=target_api,
            dangerous_api_category="truncation",
            size_source=trunc_var,
            evidence_lines=[cast_line],
            extra={
                "truncated_var": trunc_var,
                "target_api": target_api,
                "line_number": line_num,
            },
        ))

    # Assembly-level: mul/imul without overflow check before allocator
    for hit in _check_asm_mul_before_alloc(asm):
        findings.append(MemCorruptionFinding(
            category="integer_overflow",
            function_name=fname,
            function_id=fid,
            summary=f"Assembly mul/imul at line {hit['mul_line']} without "
                    f"overflow check before {hit['alloc_target']}()",
            dangerous_api=hit["alloc_target"],
            dangerous_api_category="allocation",
            alloc_api=hit["alloc_target"],
            evidence_lines=[hit["mul_insn"]],
            extra={
                "asm_mul_line": hit["mul_line"],
                "alloc_target": hit["alloc_target"],
                "source": "assembly",
            },
        ))

    return findings


# ---------------------------------------------------------------------------
# Single function scan
# ---------------------------------------------------------------------------

def scan_single_function(db_path: str, function_id: int) -> list[MemCorruptionFinding]:
    """Scan a single function for integer issues."""
    rec = load_function_record(db_path, function_id=function_id)
    if not rec or not rec["decompiled_code"]:
        return []
    return detect_integer_issues(rec)


# ---------------------------------------------------------------------------
# Module-wide scan
# ---------------------------------------------------------------------------

def scan_module(
    db_path: str,
    top_n: int = 100,
    no_cache: bool = False,
) -> dict:
    """Scan all functions for integer overflow/truncation vulnerabilities."""
    if not no_cache:
        cached = get_cached(db_path, "memcorrupt_integer")
        if cached is not None:
            return cached

    status_message("Loading functions for integer issue scan...")
    functions = load_all_functions_slim(db_path)
    if not functions:
        return {"status": "ok", "findings": [], "summary": {"total": 0}}

    export_names = build_export_names(db_path)
    all_findings: list[MemCorruptionFinding] = []

    status_message(f"Scanning {len(functions)} functions for integer issues...")

    for func in functions:
        fname = func["function_name"]
        is_exported = fname in export_names

        for f in detect_integer_issues(func):
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
        "_meta": build_meta(db_path, scanner="integer_issues", top_n=top_n),
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
        cache_result(db_path, "memcorrupt_integer", result)

    return result


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def print_text(data: dict) -> None:
    summary = data.get("summary", {})
    findings = data.get("findings", [])
    print(f"=== Integer Issue Scan: {summary.get('total', 0)} findings ===\n")
    for cat, count in sorted(summary.get("by_category", {}).items()):
        print(f"  {cat}: {count}")
    print()
    for i, f in enumerate(findings, 1):
        print(f"  [{i}] [{f['severity']}] {f['score']:.2f}  {f['function_name']}")
        print(f"      Category: {f['category']}")
        print(f"      {f['summary']}")
        if f.get("alloc_api"):
            print(f"      Alloc API: {f['alloc_api']}")
        if f.get("size_source"):
            print(f"      Size source: {f['size_source']}")
        print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Detect integer overflow/truncation vulnerabilities in decompiled functions"
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
            "_meta": build_meta(db_path, scanner="integer_issues", mode="single"),
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
