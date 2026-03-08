#!/usr/bin/env python3
"""Compare lifted code against original assembly + decompiled code from a DB.

This is the core verification script for the verifier subagent. It takes
the original assembly + decompiled code from the analysis database and the
lifted code (provided as a file or stdin), then runs systematic comparisons
to verify that the lifted code faithfully represents the original binary behavior.

Usage:
    python compare_lifted.py <db_path> <function_name> --lifted lifted_code.cpp
    python compare_lifted.py <db_path> --id <func_id> --lifted lifted_code.cpp
    python compare_lifted.py <db_path> <function_name> --lifted-stdin < lifted.cpp
    python compare_lifted.py <db_path> <function_name> --lifted lifted_code.cpp --json

Automated checks:
    1. Call count match -- call instructions in assembly vs function calls in lifted
    2. Branch count match -- conditional jumps in assembly vs if/else/switch in lifted
    3. Memory access extraction -- [base+offset] patterns verified against lifted code
    4. String literal usage -- every DB string_literal should appear in lifted code
    5. Return path analysis -- ret instructions vs return statements
    6. API name preservation -- every __imp_XXX in assembly appears as XXX(...) in lifted
    7. Global variable access -- every global read/write in assembly is present in lifted

Output:
    Verification report with pass/fail per check, discrepancy details, and
    overall confidence score. Use --json for machine-readable output.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Import shared utilities (also sets up workspace root and paths)
from _common import (
    WORKSPACE_ROOT,
    ComparisonResult,
    CheckResult,
    LiftedCodeStats,
    AsmStats,
    parse_assembly,
    parse_decompiled,
    parse_lifted_code,
    parse_json_safe,
    extract_api_calls_from_assembly,
    extract_memory_offsets_from_assembly,
    resolve_db_path,
    is_decompilation_failure,
)

sys.path.insert(0, str(WORKSPACE_ROOT / ".agent"))
from helpers import (
    emit_error,
    load_function_index_for_db,
    open_individual_analysis_db,
    resolve_function,
)
from helpers.errors import ErrorCode, db_error_handler, safe_parse_args
from helpers.json_output import emit_json
from helpers.script_runner import get_workspace_args
from helpers.validation import validate_function_id


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_call_count(asm_stats: AsmStats, lifted_stats: LiftedCodeStats) -> CheckResult:
    """Compare call instruction count in assembly vs function calls in lifted code."""
    asm_calls = asm_stats.call_count
    lifted_calls = lifted_stats.total_call_sites

    # Allow tolerance: lifted code may inline small helpers or use macros
    diff = abs(asm_calls - lifted_calls)
    tolerance = max(2, int(asm_calls * 0.2))  # 20% or 2, whichever is larger

    passed = diff <= tolerance
    discrepancies = []

    if asm_calls > lifted_calls + tolerance:
        discrepancies.append(
            f"Assembly has {asm_calls} call instructions but lifted code has only "
            f"{lifted_calls} call sites -- {asm_calls - lifted_calls} calls may be missing"
        )
    elif lifted_calls > asm_calls + tolerance:
        discrepancies.append(
            f"Lifted code has {lifted_calls} call sites but assembly only has "
            f"{asm_calls} call instructions -- lifted code may have extra calls"
        )

    severity = "INFO" if passed else ("CRITICAL" if diff > asm_calls * 0.5 else "FAIL")

    return CheckResult(
        name="call_count_match",
        passed=passed,
        expected=asm_calls,
        actual=lifted_calls,
        details=(
            f"Assembly call instructions: {asm_calls}\n"
            f"Lifted code call sites: {lifted_calls} ({lifted_stats.call_count} unique)\n"
            f"Tolerance: {tolerance}"
        ),
        severity=severity,
        discrepancies=discrepancies,
    )


def check_branch_count(asm_stats: AsmStats, lifted_stats: LiftedCodeStats) -> CheckResult:
    """Compare conditional branch count in assembly vs branch points in lifted code."""
    asm_branches = asm_stats.branch_count
    lifted_branches = lifted_stats.total_branch_points

    # Generous tolerance -- branch counting is inherently imprecise
    diff = abs(asm_branches - lifted_branches)
    tolerance = max(3, int(asm_branches * 0.3))

    passed = diff <= tolerance
    discrepancies = []

    if asm_branches > lifted_branches + tolerance:
        discrepancies.append(
            f"Assembly has {asm_branches} branches but lifted code has only "
            f"{lifted_branches} branch points -- {asm_branches - lifted_branches} "
            f"branches may be missing (potential collapsed NULL guards or error checks)"
        )
    elif lifted_branches > asm_branches + tolerance:
        discrepancies.append(
            f"Lifted code has {lifted_branches} branch points but assembly only has "
            f"{asm_branches} branches -- lifted code may have added extra conditions"
        )

    severity = "INFO" if passed else (
        "CRITICAL" if diff > max(8, asm_branches * 0.5) else "FAIL"
    )

    return CheckResult(
        name="branch_count_match",
        passed=passed,
        expected=asm_branches,
        actual=lifted_branches,
        details=(
            f"Assembly branches: {asm_branches} "
            f"(signed={asm_stats.signed_branch_count}, "
            f"unsigned={asm_stats.unsigned_branch_count}, "
            f"neutral={asm_stats.neutral_branch_count})\n"
            f"Lifted branch points: {lifted_branches} "
            f"(if={lifted_stats.if_count}, while={lifted_stats.while_count}, "
            f"for={lifted_stats.for_count}, &&/||={lifted_stats.and_or_ops}, "
            f"ternary={lifted_stats.ternary_ops}, case={lifted_stats.case_count}, "
            f"goto={lifted_stats.goto_count})\n"
            f"Tolerance: {tolerance}"
        ),
        severity=severity,
        discrepancies=discrepancies,
    )


def check_string_literal_usage(
    db_string_literals: list[str],
    lifted_code: str,
) -> CheckResult:
    """Verify that every string literal from the DB appears in lifted code."""
    if not db_string_literals:
        return CheckResult(
            name="string_literal_usage",
            passed=True,
            expected=0,
            actual=0,
            details="No string literals in DB for this function.",
            severity="INFO",
        )

    missing: list[str] = []
    present: list[str] = []
    lifted_lower = lifted_code.lower()

    for s in db_string_literals:
        if not s or not s.strip():
            continue
        # Check if the string (or a significant substring) appears in lifted code
        # Use case-insensitive matching for robustness
        s_stripped = s.strip()
        if len(s_stripped) <= 2:
            # Very short strings are unreliable for matching
            continue
        if s_stripped.lower() in lifted_lower:
            present.append(s_stripped)
        else:
            # Try escaped version (common for paths with backslashes)
            escaped = s_stripped.replace("\\", "\\\\")
            if escaped.lower() in lifted_lower:
                present.append(s_stripped)
            else:
                missing.append(s_stripped)

    total_meaningful = len(present) + len(missing)
    if total_meaningful == 0:
        return CheckResult(
            name="string_literal_usage",
            passed=True,
            expected=0,
            actual=0,
            details="No meaningful string literals to check.",
            severity="INFO",
        )

    passed = len(missing) == 0
    discrepancies = []
    if missing:
        for s in missing[:10]:
            truncated = s[:80] + "..." if len(s) > 80 else s
            discrepancies.append(f"Missing string: \"{truncated}\"")
        if len(missing) > 10:
            discrepancies.append(f"... and {len(missing) - 10} more missing strings")

    severity = "INFO" if passed else (
        "FAIL" if len(missing) > len(present) else "WARNING"
    )

    return CheckResult(
        name="string_literal_usage",
        passed=passed,
        expected=total_meaningful,
        actual=len(present),
        details=(
            f"DB string literals (meaningful): {total_meaningful}\n"
            f"Found in lifted code: {len(present)}\n"
            f"Missing from lifted code: {len(missing)}"
        ),
        severity=severity,
        discrepancies=discrepancies,
    )


def check_return_paths(asm_stats: AsmStats, lifted_stats: LiftedCodeStats) -> CheckResult:
    """Compare ret instruction count vs return statement count."""
    asm_rets = asm_stats.ret_count
    lifted_returns = lifted_stats.return_count

    # In x64, there's typically 1 ret instruction (or a few for error paths).
    # Lifted code may have multiple return statements that all converge to
    # the same ret instruction. So lifted returns >= asm rets is normal.
    # The concern is if asm has MORE rets than lifted returns (missing paths).
    passed = lifted_returns >= asm_rets or abs(asm_rets - lifted_returns) <= 1
    discrepancies = []

    if asm_rets > lifted_returns + 1:
        discrepancies.append(
            f"Assembly has {asm_rets} ret instructions but lifted code has only "
            f"{lifted_returns} return statements -- some return paths may be missing"
        )

    severity = "INFO" if passed else "WARNING"

    return CheckResult(
        name="return_path_analysis",
        passed=passed,
        expected=asm_rets,
        actual=lifted_returns,
        details=(
            f"Assembly ret instructions: {asm_rets}\n"
            f"Lifted return statements: {lifted_returns}"
        ),
        severity=severity,
        discrepancies=discrepancies,
    )


def check_api_name_preservation(
    assembly_code: str,
    lifted_stats: LiftedCodeStats,
    lifted_code: str,
) -> CheckResult:
    """Verify every __imp_XXX in assembly appears as XXX(...) in lifted code."""
    asm_apis = extract_api_calls_from_assembly(assembly_code)

    if not asm_apis:
        return CheckResult(
            name="api_name_preservation",
            passed=True,
            expected=0,
            actual=0,
            details="No API calls detected in assembly.",
            severity="INFO",
        )

    lifted_funcs_lower = {f.lower() for f in lifted_stats.called_functions}
    lifted_code_lower = lifted_code.lower()

    missing: list[str] = []
    present: list[str] = []

    for api in asm_apis:
        # Skip sub_XXXX (internal unnamed functions) and loc_XXXX
        if api.startswith("sub_") or api.startswith("loc_"):
            continue

        api_lower = api.lower()
        if api_lower in lifted_funcs_lower:
            present.append(api)
        elif api_lower in lifted_code_lower:
            # Found as text even if not detected as a call
            present.append(api)
        else:
            missing.append(api)

    total = len(present) + len(missing)
    if total == 0:
        return CheckResult(
            name="api_name_preservation",
            passed=True,
            expected=0,
            actual=0,
            details="No named API calls to verify.",
            severity="INFO",
        )

    passed = len(missing) == 0
    discrepancies = []
    if missing:
        for api in missing[:15]:
            discrepancies.append(f"Missing API: {api}()")
        if len(missing) > 15:
            discrepancies.append(f"... and {len(missing) - 15} more missing APIs")

    severity = "INFO" if passed else (
        "CRITICAL" if len(missing) > total * 0.3 else "FAIL"
    )

    return CheckResult(
        name="api_name_preservation",
        passed=passed,
        expected=total,
        actual=len(present),
        details=(
            f"Named API calls in assembly: {total}\n"
            f"Found in lifted code: {len(present)}\n"
            f"Missing from lifted code: {len(missing)}"
        ),
        severity=severity,
        discrepancies=discrepancies,
    )


def check_global_variable_access(
    global_var_accesses_json: str | None,
    lifted_code: str,
) -> CheckResult:
    """Verify every global variable read/write from DB appears in lifted code."""
    globals_data = parse_json_safe(global_var_accesses_json)

    if not globals_data or not isinstance(globals_data, list):
        return CheckResult(
            name="global_variable_access",
            passed=True,
            expected=0,
            actual=0,
            details="No global variable accesses recorded in DB.",
            severity="INFO",
        )

    lifted_lower = lifted_code.lower()
    missing: list[str] = []
    present: list[str] = []

    for gvar in globals_data:
        name = gvar.get("name", "")
        access_type = gvar.get("access_type", "")
        if not name:
            continue

        if name.lower() in lifted_lower:
            present.append(f"{name} ({access_type})")
        else:
            missing.append(f"{name} ({access_type})")

    total = len(present) + len(missing)
    if total == 0:
        return CheckResult(
            name="global_variable_access",
            passed=True,
            expected=0,
            actual=0,
            details="No meaningful global accesses to check.",
            severity="INFO",
        )

    passed = len(missing) == 0
    discrepancies = []
    if missing:
        for g in missing[:10]:
            discrepancies.append(f"Missing global: {g}")
        if len(missing) > 10:
            discrepancies.append(f"... and {len(missing) - 10} more missing globals")

    severity = "INFO" if passed else "WARNING"

    return CheckResult(
        name="global_variable_access",
        passed=passed,
        expected=total,
        actual=len(present),
        details=(
            f"Global variable accesses in DB: {total}\n"
            f"Found in lifted code: {len(present)}\n"
            f"Missing from lifted code: {len(missing)}"
        ),
        severity=severity,
        discrepancies=discrepancies,
    )


def check_memory_access_coverage(
    assembly_code: str,
    lifted_code: str,
) -> CheckResult:
    """Extract [base+offset] patterns from assembly and check coverage in lifted code.

    This is a heuristic check: we verify that the offsets mentioned in assembly
    appear somewhere in the lifted code (as struct field comments, offset annotations,
    or in pointer arithmetic).
    """
    mem_accesses = extract_memory_offsets_from_assembly(assembly_code)

    if not mem_accesses:
        return CheckResult(
            name="memory_access_coverage",
            passed=True,
            expected=0,
            actual=0,
            details="No significant memory access patterns found in assembly.",
            severity="INFO",
        )

    # Deduplicate by offset
    unique_offsets: dict[str, dict] = {}
    for acc in mem_accesses:
        key = acc["offset_hex"]
        if key not in unique_offsets:
            unique_offsets[key] = acc

    lifted_lower = lifted_code.lower()

    found: list[str] = []
    not_found: list[str] = []

    for off_hex, acc in unique_offsets.items():
        # Check if offset appears in lifted code (in comments, pointer math, etc.)
        # Try multiple representations: 0x70, 0x070, +112, etc.
        off_dec = acc["offset_decimal"]
        off_hex_lower = off_hex.lower()
        off_hex_nox = off_hex_lower.replace("0x", "")

        found_this = False
        for pattern in [off_hex_lower, off_hex_nox, str(off_dec)]:
            if pattern in lifted_lower:
                found_this = True
                break

        if found_this:
            found.append(f"{off_hex} (size={acc['size']}B)")
        else:
            not_found.append(f"{off_hex} (size={acc['size']}B, asm: {acc['line'][:60]})")

    total = len(found) + len(not_found)
    # This is a soft check -- lifted code may use struct names instead of offsets
    passed = len(not_found) <= total * 0.5
    discrepancies = []
    if not_found:
        for nf in not_found[:10]:
            discrepancies.append(f"Offset not found in lifted: {nf}")
        if len(not_found) > 10:
            discrepancies.append(f"... and {len(not_found) - 10} more")

    severity = "INFO" if passed else "WARNING"

    return CheckResult(
        name="memory_access_coverage",
        passed=passed,
        expected=total,
        actual=len(found),
        details=(
            f"Unique memory offsets in assembly: {total}\n"
            f"Found in lifted code: {len(found)}\n"
            f"Not found: {len(not_found)}\n"
            f"Note: Not finding offsets may be OK if lifted code uses struct field names"
        ),
        severity=severity,
        discrepancies=discrepancies,
    )


# ---------------------------------------------------------------------------
# Main comparison logic
# ---------------------------------------------------------------------------

def compare_lifted(
    db_path: str,
    function_name: str | None = None,
    function_id: int | None = None,
    lifted_code: str = "",
    output_json: bool = False,
) -> ComparisonResult | None:
    """Run all verification checks comparing lifted code against original."""
    function_index = load_function_index_for_db(db_path)
    with open_individual_analysis_db(db_path) as db:
        func, err = resolve_function(
            db, name=function_name, function_id=function_id,
            function_index=function_index,
        )
        if err:
            if "Multiple matches" in err:
                emit_error(f"[{Path(db_path).stem}] {err}", ErrorCode.AMBIGUOUS)
            emit_error(f"[{Path(db_path).stem}] {err}", ErrorCode.NOT_FOUND)

        assert func is not None

        # Parse original data
        has_asm = bool(func.assembly_code and func.assembly_code.strip())
        if not has_asm:
            emit_error("No assembly code available for function.", ErrorCode.NO_DATA)

        _, asm_stats = parse_assembly(func.assembly_code or "")
        lifted_stats = parse_lifted_code(lifted_code)

        # Parse DB string literals
        db_strings = parse_json_safe(func.string_literals)
        if not isinstance(db_strings, list):
            db_strings = []

        # Build comparison result
        result = ComparisonResult(
            function_name=func.function_name or "(unnamed)",
            function_id=func.function_id,
        )

        # Run all checks
        result.add_check(check_call_count(asm_stats, lifted_stats))
        result.add_check(check_branch_count(asm_stats, lifted_stats))
        result.add_check(check_string_literal_usage(db_strings, lifted_code))
        result.add_check(check_return_paths(asm_stats, lifted_stats))
        result.add_check(check_api_name_preservation(
            func.assembly_code or "", lifted_stats, lifted_code
        ))
        result.add_check(check_global_variable_access(
            func.global_var_accesses, lifted_code
        ))
        result.add_check(check_memory_access_coverage(
            func.assembly_code or "", lifted_code
        ))

        # Compute verdict
        result.compute_verdict()

        # Output
        if output_json:
            out = result.to_dict()
            # Include original data for context
            out["original_function_signature"] = func.function_signature
            out["original_mangled_name"] = func.mangled_name
            out["asm_instruction_count"] = asm_stats.instruction_count
            out["lifted_line_count"] = lifted_stats.line_count
            emit_json(out)
        else:
            _print_human_report(result, func, asm_stats, lifted_stats, db_path)

        return result


def _print_human_report(
    result: ComparisonResult,
    func,
    asm_stats: AsmStats,
    lifted_stats: LiftedCodeStats,
    db_path: str,
) -> None:
    """Print human-readable comparison report."""
    verdict_marker = {
        "PASS": "[PASS]",
        "FAIL": "[FAIL]",
        "WARN": "[WARN]",
        "UNKNOWN": "[????]",
    }

    print(f"{'#' * 80}")
    print(f"  LIFTED CODE VERIFICATION REPORT")
    print(f"  Function: {result.function_name}")
    print(f"  ID: {result.function_id}")
    print(f"  DB: {db_path}")
    print(f"{'#' * 80}")
    print()

    # Overall verdict
    marker = verdict_marker.get(result.verdict, "[????]")
    print(f"VERDICT: {marker} {result.verdict}")
    print(f"Confidence: {result.overall_confidence:.1%}")
    print(f"Checks: {result.passed_count}/{result.total_checks} passed")
    print()

    # Summary stats
    print(f"Summary:")
    print(f"  Assembly instructions: {asm_stats.instruction_count}")
    print(f"  Lifted code lines:    {lifted_stats.line_count}")
    print(f"  Signature: {func.function_signature or '(none)'}")
    if func.mangled_name:
        print(f"  Mangled:   {func.mangled_name}")
    print()

    # Check results
    print(f"{'=' * 80}")
    print(f"  CHECK RESULTS")
    print(f"{'=' * 80}")
    print()

    for check in result.checks:
        status = "PASS" if check.passed else check.severity
        icon = "+" if check.passed else "X"
        print(f"[{icon}] {check.name}: {status}")
        print(f"    Expected: {check.expected}  |  Actual: {check.actual}")
        if check.details:
            for line in check.details.splitlines():
                print(f"    {line}")
        if check.discrepancies:
            print(f"    Discrepancies:")
            for d in check.discrepancies:
                print(f"      - {d}")
        print()

    # API calls comparison
    asm_apis = extract_api_calls_from_assembly(func.assembly_code or "")
    if asm_apis:
        print(f"{'=' * 80}")
        print(f"  API CALLS IN ASSEMBLY (for manual verification)")
        print(f"{'=' * 80}")
        for api in asm_apis:
            in_lifted = "YES" if api.lower() in " ".join(lifted_stats.called_functions).lower() else "---"
            print(f"  [{in_lifted:>3}] {api}")
        print()

    # Lifted code functions called
    if lifted_stats.called_functions:
        print(f"{'=' * 80}")
        print(f"  FUNCTIONS CALLED IN LIFTED CODE")
        print(f"{'=' * 80}")
        for fn in lifted_stats.called_functions:
            print(f"  {fn}")
        print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare lifted code against original assembly from analysis DB.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("db_path", help="Path to the individual analysis DB")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("function_name", nargs="?", help="Function name to compare")
    group.add_argument("--id", type=int, dest="function_id", help="Function ID to compare")

    lifted_group = parser.add_mutually_exclusive_group(required=True)
    lifted_group.add_argument("--lifted", dest="lifted_file", help="Path to lifted code file")
    lifted_group.add_argument("--lifted-stdin", action="store_true", help="Read lifted code from stdin")

    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = safe_parse_args(parser)

    # Force JSON output when workspace mode is active so bootstrap captures
    # structured data instead of human-readable text.
    force_json = args.json or bool(get_workspace_args(args)["workspace_dir"])

    # Resolve DB path
    db_path = resolve_db_path(args.db_path)

    # Read lifted code
    if args.lifted_stdin:
        lifted_code = sys.stdin.read()
    elif args.lifted_file:
        lifted_path = Path(args.lifted_file)
        if not lifted_path.is_absolute():
            lifted_path = Path(WORKSPACE_ROOT) / args.lifted_file
        if not lifted_path.exists():
            emit_error(f"Lifted code file not found: {lifted_path}", ErrorCode.NOT_FOUND)
        lifted_code = lifted_path.read_text(encoding="utf-8")
    else:
        parser.error("Provide --lifted or --lifted-stdin")
        return

    if not lifted_code.strip():
        emit_error("Lifted code is empty.", ErrorCode.NO_DATA)

    # Validate function specifier
    if args.function_id is None and args.function_name is None:
        parser.error("Provide a function name or --id")

    if args.function_id is not None:
        args.function_id = validate_function_id(args.function_id)

    with db_error_handler(db_path, "lifted code comparison"):
        compare_lifted(
            db_path=db_path,
            function_name=args.function_name,
            function_id=args.function_id,
            lifted_code=lifted_code,
            output_json=force_json,
        )


if __name__ == "__main__":
    main()
