#!/usr/bin/env python3
"""Verify decompiler accuracy for a single function by comparing assembly vs decompiled code.

Usage:
    python verify_function.py <db_path> <function_name>
    python verify_function.py <db_path> --id <function_id>
    python verify_function.py <db_path> --search <pattern>
    python verify_function.py <db_path> <function_name> --json

Examples:
    python verify_function.py extracted_dbs/appinfo_dll_e98d25a9e8.db AiCheckSecureApplicationDirectory
    python verify_function.py extracted_dbs/cmd_exe_6d109a3a00.db --id 42
    python verify_function.py extracted_dbs/cmd_exe_6d109a3a00.db --search "BatLoop"

Output:
    1. Assembly statistics (instruction/call/branch counts, memory access sizes)
    2. Decompiled code statistics (if/goto counts, type casts, artifacts)
    3. Automated heuristic findings with severity and suggested fixes
    4. Full decompiled code and assembly code for agent-driven deep comparison

    The automated checks are HEURISTIC -- they flag potential issues for the
    agent to investigate. The agent performs the definitive comparison using the
    full assembly and decompiled code.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Import shared utilities (also sets up workspace root and helpers path)
from _common import (
    SCRIPT_DIR,
    WORKSPACE_ROOT,
    SEVERITY_LABELS,
    AsmStats,
    DecompStats,
    VerificationResult,
    emit_error,
    is_decompilation_failure,
    parse_assembly,
    parse_decompiled,
    resolve_db_path,
    run_heuristic_checks,
)

from helpers.json_output import emit_json
from helpers import (
    load_function_index_for_db,
    open_individual_analysis_db,
    resolve_function,
    search_functions_by_pattern,
    validate_function_id,
)
from helpers.errors import ErrorCode, db_error_handler, safe_parse_args


def _print_section(title: str, content: str | None, max_lines: int = 0) -> None:
    print(f"\n{'=' * 80}")
    print(f"  {title}")
    print(f"{'=' * 80}")
    if content is None or content.strip() == "":
        print("(none)")
        return
    if max_lines > 0:
        lines = content.splitlines()
        if len(lines) > max_lines:
            for line in lines[:max_lines]:
                print(line)
            print(f"\n... ({len(lines) - max_lines} more lines, {len(lines)} total)")
            return
    print(content)


def _format_asm_stats(stats: AsmStats) -> str:
    lines = [
        f"  Instructions:      {stats.instruction_count}",
        f"  Calls:             {stats.call_count}",
        f"  Branches:          {stats.branch_count} (signed={stats.signed_branch_count}, unsigned={stats.unsigned_branch_count}, neutral={stats.neutral_branch_count})",
        f"  Returns:           {stats.ret_count}",
        f"  test instructions: {stats.test_count}",
        f"  cmp instructions:  {stats.cmp_count}",
        f"  lea instructions:  {stats.lea_count}",
        f"  NULL check pairs:  {stats.null_check_patterns} (test reg,reg + jz/jnz)",
        f"  Memory accesses:   BYTE={stats.byte_accesses}, WORD={stats.word_accesses}, DWORD={stats.dword_accesses}, QWORD={stats.qword_accesses}",
        f"  Memory reads:      {stats.memory_reads}",
        f"  Memory writes:     {stats.memory_writes}",
    ]
    return "\n".join(lines)


def _format_decomp_stats(stats: DecompStats) -> str:
    lines = [
        f"  Lines:             {stats.line_count}",
        f"  Return type:       {stats.return_type or '(unknown)'}",
        f"  if-statements:     {stats.if_count}",
        f"  gotos:             {stats.goto_count}",
        f"  while/for loops:   {stats.while_count + stats.for_count}",
        f"  &&/|| operators:   {stats.short_circuit_ops}",
        f"  Ternary (? :):     {stats.ternary_ops}",
        f"  switch/case:       {stats.switch_count} switch, {stats.case_count} case/default labels",
        f"  Call sites (total): {stats.total_call_sites}  ({stats.call_count} unique functions)",
        f"  Type casts:        _BYTE={stats.byte_casts}, _WORD={stats.word_casts}, _DWORD={stats.dword_casts}, _QWORD={stats.qword_casts}",
        f"  Signed comparisons: {stats.signed_comparisons}",
        f"  Unsigned casts:    {stats.unsigned_casts}",
        f"  Artifacts:         do/while(0)={stats.do_while_0_count}, LOBYTE={stats.lobyte_count}, HI/LODWORD={stats.hidword_lodword_count}",
    ]
    if stats.called_functions:
        fns = ", ".join(stats.called_functions[:20])
        if len(stats.called_functions) > 20:
            fns += f" ... (+{len(stats.called_functions) - 20} more)"
        lines.append(f"  Called functions:   {fns}")
    return "\n".join(lines)


def _format_issue(idx: int, issue) -> str:
    sev = SEVERITY_LABELS[issue.severity]
    lines = [
        f"[{sev}] #{idx}: {issue.summary}",
    ]
    if issue.details:
        for detail_line in issue.details.splitlines():
            lines.append(f"  {detail_line}")
    if issue.decompiled_evidence:
        lines.append(f"  Decompiled: {issue.decompiled_evidence}")
    if issue.assembly_evidence:
        lines.append(f"  Assembly:   {issue.assembly_evidence}")
    if issue.suggested_fix:
        lines.append(f"  Fix:        {issue.suggested_fix}")
    if issue.line_hint > 0:
        lines.append(f"  Line hint:  ~line {issue.line_hint}")
    return "\n".join(lines)


def search_functions(db_path: str, pattern: str, *, as_json: bool = False) -> None:
    """Search for functions matching a pattern."""
    function_index = load_function_index_for_db(db_path)
    with db_error_handler(db_path, "searching functions for verification"):
        with open_individual_analysis_db(db_path) as db:
            results = [
                func for func in search_functions_by_pattern(
                    db,
                    pattern,
                    function_index=function_index,
                )
                if func.decompiled_code
            ]

            if not results:
                if as_json:
                    emit_json({"match_count": 0, "matches": [], "pattern": pattern})
                else:
                    print(f"No functions matching '{pattern}' with decompiled code found.")
                return

            if as_json:
                matches = [
                    {
                        "function_id": func.function_id,
                        "function_name": func.function_name,
                        "has_assembly": bool(func.assembly_code),
                        "signature": func.function_signature or "",
                    }
                    for func in results
                ]
                emit_json({"match_count": len(matches), "matches": matches, "pattern": pattern})
                return

            print(f"Found {len(results)} function(s) matching '{pattern}':\n")
            print(f"{'ID':>6}  {'Function Name':<50}  {'Has ASM':>7}  {'Signature'}")
            print(f"{'-' * 6}  {'-' * 50}  {'-' * 7}  {'-' * 60}")
            for func in results:
                name = func.function_name or "(unnamed)"
                has_asm = "YES" if func.assembly_code else "NO"
                sig = func.function_signature or ""
                if len(sig) > 60:
                    sig = sig[:57] + "..."
                print(f"{func.function_id:>6}  {name:<50}  {has_asm:>7}  {sig}")
            print(f"\nUse --id <ID> to verify a specific function.")


def verify_function(
    db_path: str,
    function_name: str | None = None,
    function_id: int | None = None,
    output_json: bool = False,
) -> None:
    """Verify decompiler accuracy for a single function."""
    function_index = load_function_index_for_db(db_path)
    with db_error_handler(db_path, "verifying function decompilation"):
        with open_individual_analysis_db(db_path) as db:
            func, err = resolve_function(
                db, name=function_name, function_id=function_id,
                function_index=function_index,
            )
        if err:
            if "Multiple matches" in err and output_json:
                emit_error(f"[{Path(db_path).stem}] {err}", ErrorCode.AMBIGUOUS)
            if "Multiple matches" in err:
                print(err)
                return
            emit_error(f"[{Path(db_path).stem}] {err}", ErrorCode.NOT_FOUND)

        assert func is not None

        # Parse assembly and decompiled code
        instructions, asm_stats = parse_assembly(func.assembly_code or "")
        decomp_stats = parse_decompiled(func.decompiled_code or "")

        index_entry = function_index.get(func.function_name or "") if function_index else None
        if index_entry is not None:
            has_asm = bool(index_entry.get("has_assembly", False))
            has_decomp = bool(index_entry.get("has_decompiled", False))
        else:
            has_asm = bool(func.assembly_code and func.assembly_code.strip())
            has_decomp = bool(
                func.decompiled_code
                and func.decompiled_code.strip()
                and not is_decompilation_failure(func.decompiled_code)
            )

        # Run heuristic checks (only if both assembly and decompiled are available)
        issues = []
        if has_asm and has_decomp:
            issues = run_heuristic_checks(
                asm_stats,
                decomp_stats,
                mangled_name=func.mangled_name,
                function_signature=func.function_signature,
                function_signature_extended=func.function_signature_extended,
                assembly_code=func.assembly_code,
                decompiled_code=func.decompiled_code,
            )

        # Build result
        result = VerificationResult(
            function_id=func.function_id,
            function_name=func.function_name or "(unnamed)",
            has_decompiled=has_decomp,
            has_assembly=has_asm,
            asm_stats=asm_stats,
            decomp_stats=decomp_stats,
        )
        for issue in issues:
            result.add_issue(issue)

        if output_json:
            out = result.to_dict()
            out["decompiled_code"] = func.decompiled_code
            out["assembly_code"] = func.assembly_code
            out["function_signature"] = func.function_signature
            out["function_signature_extended"] = func.function_signature_extended
            out["mangled_name"] = func.mangled_name
            emit_json(out)
            return

        # Human-readable output
        print(f"{'#' * 80}")
        print(f"  DECOMPILER ACCURACY VERIFICATION")
        print(f"  Function: {func.function_name}")
        print(f"  ID: {func.function_id}")
        print(f"  DB: {db_path}")
        print(f"{'#' * 80}")

        # Signatures
        _print_section("FUNCTION SIGNATURE", func.function_signature)
        if func.function_signature_extended and func.function_signature_extended != func.function_signature:
            _print_section("EXTENDED SIGNATURE", func.function_signature_extended)
        if func.mangled_name:
            _print_section("MANGLED NAME", func.mangled_name)

        # Stats
        if has_asm:
            _print_section("ASSEMBLY STATISTICS", _format_asm_stats(asm_stats))
        else:
            _print_section("ASSEMBLY STATISTICS", "(no assembly code available)")

        if has_decomp:
            _print_section("DECOMPILED CODE STATISTICS", _format_decomp_stats(decomp_stats))
        else:
            _print_section("DECOMPILED CODE STATISTICS", "(no decompiled code available)")

        # Heuristic findings
        if not has_asm or not has_decomp:
            _print_section(
                "AUTOMATED HEURISTIC FINDINGS",
                "SKIPPED: Both assembly and decompiled code are required for verification.\n"
                + (f"  Assembly available: {has_asm}\n  Decompiled available: {has_decomp}"),
            )
        elif issues:
            severity_summary = (
                f"Total issues found: {result.total_issues}  "
                f"({result.critical_count} critical, {result.high_count} high, "
                f"{result.moderate_count} moderate, {result.low_count} low)"
            )
            findings = [severity_summary, ""]
            for idx, issue in enumerate(issues, 1):
                findings.append(_format_issue(idx, issue))
                findings.append("")
            _print_section("AUTOMATED HEURISTIC FINDINGS", "\n".join(findings))
        else:
            _print_section(
                "AUTOMATED HEURISTIC FINDINGS",
                "No issues detected by automated heuristics.\n"
                "NOTE: Automated checks are heuristic. The agent should still compare\n"
                "assembly vs decompiled code for issues the heuristics cannot detect,\n"
                "especially collapsed multi-step operations and missing NULL guards.",
            )

        # Agent instructions
        _print_section(
            "AGENT VERIFICATION INSTRUCTIONS",
            "The automated checks above flag potential issues. For a complete verification,\n"
            "compare the assembly code (ground truth) against the decompiled code below.\n\n"
            "Focus on these areas that automated heuristics cannot fully detect:\n"
            "  1. COLLAPSED OPERATIONS: Assembly has load + test + branch + call, but\n"
            "     decompiled shows just the call -- a NULL guard is hidden\n"
            "  2. WRONG OFFSETS: Decompiler's pointer arithmetic scaling may not match\n"
            "     assembly byte offsets (e.g., +N*8 vs +N in assembly)\n"
            "  3. LOST VOLATILE READS: Consecutive identical memory reads in assembly\n"
            "     that appear as a single read in decompiled code\n"
            "  4. SPECIFIC ACCESS SIZE ERRORS: Individual mov eax,[...] = DWORD vs\n"
            "     decompiled _QWORD cast at the same offset\n\n"
            "For each issue found, produce:\n"
            "  - Category and severity\n"
            "  - The decompiled line(s) affected\n"
            "  - The assembly evidence\n"
            "  - The corrected decompiled line(s)",
        )

        # Full decompiled code
        _print_section("DECOMPILED CODE (to be verified and corrected)", func.decompiled_code)

        # Full assembly code
        _print_section("ASSEMBLY CODE (ground truth)", func.assembly_code)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify decompiler accuracy by comparing assembly vs decompiled code.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("db_path", help="Path to the individual analysis DB")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--function", "--name", dest="function_name", metavar="NAME",
                       help="Function name to verify")
    group.add_argument("--id", "--function-id", type=int, dest="function_id", help="Function ID to verify")
    group.add_argument("--search", dest="search_pattern", help="Search for functions matching a pattern")
    parser.add_argument("function_name_pos", nargs="?", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = safe_parse_args(parser)
    if args.function_name_pos and not args.function_name:
        args.function_name = args.function_name_pos

    if args.function_id is not None:
        args.function_id = validate_function_id(args.function_id)

    db_path = resolve_db_path(args.db_path)

    if args.search_pattern:
        search_functions(db_path, args.search_pattern, as_json=args.json)
    elif args.function_id is not None:
        verify_function(db_path, function_id=args.function_id, output_json=args.json)
    elif args.function_name:
        verify_function(db_path, function_name=args.function_name, output_json=args.json)
    else:
        parser.error("Provide a function name, --id, or --search")


if __name__ == "__main__":
    main()
