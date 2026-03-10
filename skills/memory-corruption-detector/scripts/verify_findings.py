"""Independent verification layer for memory corruption findings.

Operates with fresh eyes: takes findings JSON as input, re-reads raw
decompiled code and assembly from the DB, and independently confirms or
rejects each finding.  Assigns confidence levels and collects assembly
evidence for confirmed findings.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))

from _common import (
    ALLOC_APIS,
    CONFIDENCE_SCORES,
    COPY_APIS,
    FORMAT_APIS,
    FREE_APIS,
    RE_CALL_INSN,
    RE_MUL_INSN,
    RE_STACK_BUFFER,
    UNBOUNDED_COPY_APIS,
    VerificationResult,
    build_meta,
    check_feasibility,
    collect_constraints,
    compute_memcorrupt_score,
    discover_calls_with_xrefs,
    emit_error,
    emit_json,
    extract_function_calls,
    find_guards_between,
    is_alloc_api,
    is_copy_api,
    is_format_api,
    is_free_api,
    is_unbounded_copy_api,
    load_function_record,
    matches_api_list,
    resolve_db_path,
    status_message,
)


# ---------------------------------------------------------------------------
# Per-category verification routines
# ---------------------------------------------------------------------------

def _verify_heap_overflow(finding: dict, func: dict) -> VerificationResult:
    """Verify that a copy API call with tainted size truly exists."""
    code = func.get("decompiled_code", "")
    asm = func.get("assembly_code", "")
    dangerous_api = finding.get("dangerous_api", "")
    xrefs = func.get("outbound_xrefs", [])

    calls = discover_calls_with_xrefs(code, xrefs) if xrefs else extract_function_calls(code)
    target_calls = [c for c in calls if c["function_name"] == dangerous_api]

    if not target_calls:
        return VerificationResult(
            finding=finding,
            confidence="FALSE_POSITIVE",
            confidence_score=0.0,
            reasoning=f"Copy API '{dangerous_api}' not found in current code",
        )

    evidence: list[str] = []
    if asm:
        for line in asm.splitlines():
            if dangerous_api.lower() in line.lower() or "call" in line.lower():
                clean = line.strip()
                if dangerous_api.lower() in clean.lower():
                    evidence.append(clean)
                    break

    size_source = finding.get("size_source", "")
    extra = finding.get("extra", {})
    tainted_vars = extra.get("tainted_size_vars", [])

    if tainted_vars:
        for tv in tainted_vars:
            pattern = re.compile(rf"\b{re.escape(tv)}\b")
            found_in_args = False
            for tc in target_calls:
                for arg in tc.get("arguments", []):
                    if pattern.search(arg):
                        found_in_args = True
                        break
            if not found_in_args:
                return VerificationResult(
                    finding=finding,
                    confidence="UNCERTAIN",
                    confidence_score=0.3,
                    reasoning=f"Tainted var '{tv}' not found in {dangerous_api}() args on re-read",
                )

    return VerificationResult(
        finding=finding,
        confidence="CONFIRMED",
        confidence_score=1.0,
        reasoning=f"{dangerous_api}() with tainted size confirmed in decompiled code",
        assembly_evidence=evidence,
    )


def _verify_stack_overflow(finding: dict, func: dict) -> VerificationResult:
    """Verify stack buffer overflow pattern."""
    code = func.get("decompiled_code", "")
    asm = func.get("assembly_code", "")
    dangerous_api = finding.get("dangerous_api", "")
    xrefs = func.get("outbound_xrefs", [])

    calls = discover_calls_with_xrefs(code, xrefs) if xrefs else extract_function_calls(code)
    target_calls = [c for c in calls if c["function_name"] == dangerous_api]

    if not target_calls:
        return VerificationResult(
            finding=finding,
            confidence="FALSE_POSITIVE",
            confidence_score=0.0,
            reasoning=f"Copy API '{dangerous_api}' not found in current code",
        )

    has_stack_ref = bool(RE_STACK_BUFFER.search(asm)) if asm else False
    if not has_stack_ref:
        return VerificationResult(
            finding=finding,
            confidence="UNCERTAIN",
            confidence_score=0.3,
            reasoning="Stack buffer reference not confirmed in assembly",
            mitigating_factors=["Could not verify stack destination in assembly"],
        )

    evidence: list[str] = []
    if asm:
        for line in asm.splitlines():
            if RE_STACK_BUFFER.search(line):
                evidence.append(line.strip())
                if len(evidence) >= 2:
                    break

    return VerificationResult(
        finding=finding,
        confidence="CONFIRMED",
        confidence_score=1.0,
        reasoning=f"{dangerous_api}() writing to stack buffer confirmed",
        assembly_evidence=evidence,
    )


def _verify_integer_overflow(finding: dict, func: dict) -> VerificationResult:
    """Verify integer overflow before allocation."""
    code = func.get("decompiled_code", "")
    asm = func.get("assembly_code", "")
    extra = finding.get("extra", {})

    if extra.get("source") == "assembly":
        if not asm:
            return VerificationResult(
                finding=finding,
                confidence="UNCERTAIN",
                confidence_score=0.3,
                reasoning="No assembly available for verification",
            )

        mul_line = extra.get("asm_mul_line", 0)
        lines = asm.splitlines()
        if mul_line > 0 and mul_line <= len(lines):
            insn = lines[mul_line - 1].strip()
            if RE_MUL_INSN.search(insn):
                for j in range(mul_line, min(mul_line + 20, len(lines))):
                    if re.search(r"\bj[onc]\b", lines[j], re.IGNORECASE):
                        return VerificationResult(
                            finding=finding,
                            confidence="FALSE_POSITIVE",
                            confidence_score=0.0,
                            reasoning="Overflow check (conditional jump) found after mul",
                            mitigating_factors=["jo/jno/jc after multiplication"],
                        )

                return VerificationResult(
                    finding=finding,
                    confidence="CONFIRMED",
                    confidence_score=1.0,
                    reasoning=f"mul/imul without overflow check confirmed at line {mul_line}",
                    assembly_evidence=[insn],
                )

        return VerificationResult(
            finding=finding,
            confidence="UNCERTAIN",
            confidence_score=0.3,
            reasoning="Could not locate mul instruction at reported line",
        )

    arith_expr = extra.get("arithmetic_expr", "")
    alloc_api = finding.get("alloc_api") or finding.get("dangerous_api", "")

    if not arith_expr:
        return VerificationResult(
            finding=finding,
            confidence="UNCERTAIN",
            confidence_score=0.3,
            reasoning="No arithmetic expression recorded in finding",
        )

    xrefs = func.get("outbound_xrefs", [])
    calls = discover_calls_with_xrefs(code, xrefs) if xrefs else extract_function_calls(code)
    alloc_calls = [c for c in calls if c["function_name"] == alloc_api]

    if not alloc_calls:
        return VerificationResult(
            finding=finding,
            confidence="FALSE_POSITIVE",
            confidence_score=0.0,
            reasoning=f"Alloc API '{alloc_api}' not found in re-read code",
        )

    safe_patterns = [
        r"\bUInt\w*(?:Add|Mult|Sub)\b",
        r"\bIntsafe\b",
        r"\bSIZE_T_MAX\b",
        r"\bSafe\w*(?:Add|Mult)\b",
    ]
    for pat in safe_patterns:
        if re.search(pat, code, re.IGNORECASE):
            return VerificationResult(
                finding=finding,
                confidence="FALSE_POSITIVE",
                confidence_score=0.0,
                reasoning="Safe integer arithmetic API detected in function",
                mitigating_factors=["Uses safe integer arithmetic helpers"],
            )

    return VerificationResult(
        finding=finding,
        confidence="CONFIRMED",
        confidence_score=1.0,
        reasoning=f"Arithmetic '{arith_expr}' flows to {alloc_api}() without overflow check",
    )


def _verify_integer_truncation(finding: dict, func: dict) -> VerificationResult:
    """Verify integer truncation before size-sensitive API."""
    code = func.get("decompiled_code", "")
    extra = finding.get("extra", {})
    trunc_var = extra.get("truncated_var", "")
    target_api = extra.get("target_api", "")

    if not code or not trunc_var:
        return VerificationResult(
            finding=finding,
            confidence="UNCERTAIN",
            confidence_score=0.3,
            reasoning="Insufficient data for truncation verification",
        )

    from _common import RE_TRUNCATION_CAST
    if not RE_TRUNCATION_CAST.search(code):
        return VerificationResult(
            finding=finding,
            confidence="FALSE_POSITIVE",
            confidence_score=0.0,
            reasoning="Truncation cast not found in re-read code",
        )

    xrefs = func.get("outbound_xrefs", [])
    calls = discover_calls_with_xrefs(code, xrefs) if xrefs else extract_function_calls(code)
    target_calls = [c for c in calls if c["function_name"] == target_api]
    if not target_calls:
        return VerificationResult(
            finding=finding,
            confidence="FALSE_POSITIVE",
            confidence_score=0.0,
            reasoning=f"Target API '{target_api}' not found in re-read code",
        )

    return VerificationResult(
        finding=finding,
        confidence="LIKELY",
        confidence_score=0.7,
        reasoning=f"Truncation cast and {target_api}() both present; "
                  f"data flow confirmation is heuristic",
    )


def _verify_use_after_free(finding: dict, func: dict) -> VerificationResult:
    """Verify use-after-free pattern in code and assembly."""
    code = func.get("decompiled_code", "")
    asm = func.get("assembly_code", "")
    extra = finding.get("extra", {})
    freed_var = extra.get("freed_var", "")
    free_api = extra.get("free_api", "")

    if not code or not freed_var:
        return VerificationResult(
            finding=finding,
            confidence="UNCERTAIN",
            confidence_score=0.3,
            reasoning="No code or freed variable for verification",
        )

    xrefs = func.get("outbound_xrefs", [])
    calls = discover_calls_with_xrefs(code, xrefs) if xrefs else extract_function_calls(code)
    free_calls = [c for c in calls if c["function_name"] == free_api]

    if not free_calls:
        return VerificationResult(
            finding=finding,
            confidence="FALSE_POSITIVE",
            confidence_score=0.0,
            reasoning=f"Free API '{free_api}' not found in re-read code",
        )

    free_line = free_calls[0]["line_number"]
    lines = code.splitlines()

    null_pattern = re.compile(
        rf"\b{re.escape(freed_var)}\s*=\s*(?:0|NULL|nullptr|0LL|0i64)\s*;"
    )
    for i in range(free_line, min(free_line + 5, len(lines))):
        if null_pattern.search(lines[i]):
            return VerificationResult(
                finding=finding,
                confidence="FALSE_POSITIVE",
                confidence_score=0.0,
                reasoning=f"'{freed_var}' is nulled at line {i + 1} after free",
                mitigating_factors=[f"Null assignment after free at line {i + 1}"],
            )

    use_pattern = re.compile(
        rf"(?:\*\s*{re.escape(freed_var)}\b|{re.escape(freed_var)}\s*->|{re.escape(freed_var)}\s*\[)"
    )
    use_in_call = re.compile(rf"\b{re.escape(freed_var)}\b")

    found_use = False
    evidence: list[str] = []
    for i in range(free_line, len(lines)):
        stripped = lines[i].strip()
        if use_pattern.search(stripped):
            found_use = True
            evidence.append(stripped)
            break
        post_calls = [c for c in calls if c["line_number"] == i + 1 and c["function_name"] != free_api]
        for pc in post_calls:
            args_text = " ".join(pc.get("arguments", []))
            if use_in_call.search(args_text):
                found_use = True
                evidence.append(pc["line"])
                break
        if found_use:
            break

    if not found_use:
        return VerificationResult(
            finding=finding,
            confidence="FALSE_POSITIVE",
            confidence_score=0.0,
            reasoning=f"No use of '{freed_var}' found after free on re-read",
        )

    return VerificationResult(
        finding=finding,
        confidence="CONFIRMED",
        confidence_score=1.0,
        reasoning=f"Use of '{freed_var}' after {free_api}() confirmed",
        assembly_evidence=evidence,
    )


def _verify_double_free(finding: dict, func: dict) -> VerificationResult:
    """Verify double-free pattern."""
    code = func.get("decompiled_code", "")
    extra = finding.get("extra", {})
    freed_var = extra.get("freed_var", "")
    free_api = extra.get("free_api", "")

    if not code or not freed_var:
        return VerificationResult(
            finding=finding,
            confidence="UNCERTAIN",
            confidence_score=0.3,
            reasoning="No code or freed variable for verification",
        )

    xrefs = func.get("outbound_xrefs", [])
    calls = discover_calls_with_xrefs(code, xrefs) if xrefs else extract_function_calls(code)
    free_calls = [c for c in calls if is_free_api(c["function_name"])]

    freed_var_frees = []
    for fc in free_calls:
        args = fc.get("arguments", [])
        args_text = " ".join(args)
        if freed_var in args_text:
            freed_var_frees.append(fc)

    if len(freed_var_frees) < 2:
        return VerificationResult(
            finding=finding,
            confidence="FALSE_POSITIVE",
            confidence_score=0.0,
            reasoning=f"Only {len(freed_var_frees)} free call(s) for '{freed_var}' found",
        )

    first = freed_var_frees[0]
    second = freed_var_frees[1]
    lines = code.splitlines()

    realloc_pattern = re.compile(
        rf"\b{re.escape(freed_var)}\s*=\s*.*(?:{'|'.join(re.escape(a) for a in ALLOC_APIS)})"
    )
    between = "\n".join(lines[first["line_number"]:second["line_number"] - 1])
    if realloc_pattern.search(between):
        return VerificationResult(
            finding=finding,
            confidence="FALSE_POSITIVE",
            confidence_score=0.0,
            reasoning=f"'{freed_var}' is reallocated between the two free calls",
            mitigating_factors=["Reallocation between frees"],
        )

    return VerificationResult(
        finding=finding,
        confidence="CONFIRMED",
        confidence_score=1.0,
        reasoning=f"Double free of '{freed_var}' at lines "
                  f"{first['line_number']} and {second['line_number']} confirmed",
        assembly_evidence=[first["line"], second["line"]],
    )


def _verify_format_string(finding: dict, func: dict) -> VerificationResult:
    """Verify format string vulnerability."""
    code = func.get("decompiled_code", "")
    asm = func.get("assembly_code", "")
    dangerous_api = finding.get("dangerous_api", "")
    extra = finding.get("extra", {})
    fmt_arg = extra.get("format_arg", "")
    xrefs = func.get("outbound_xrefs", [])

    calls = discover_calls_with_xrefs(code, xrefs) if xrefs else extract_function_calls(code)
    target_calls = [c for c in calls if c["function_name"] == dangerous_api]

    if not target_calls:
        return VerificationResult(
            finding=finding,
            confidence="FALSE_POSITIVE",
            confidence_score=0.0,
            reasoning=f"Format API '{dangerous_api}' not found in current code",
        )

    evidence: list[str] = []
    if asm:
        for line in asm.splitlines():
            if dangerous_api.lower() in line.lower():
                evidence.append(line.strip())
                break

    taint_source = extra.get("taint_source", "unknown")
    if taint_source == "parameter":
        return VerificationResult(
            finding=finding,
            confidence="CONFIRMED",
            confidence_score=1.0,
            reasoning=f"{dangerous_api}() with parameter-derived format string confirmed",
            assembly_evidence=evidence,
        )

    if taint_source == "unknown":
        return VerificationResult(
            finding=finding,
            confidence="LIKELY",
            confidence_score=0.7,
            reasoning=f"{dangerous_api}() with variable format string; "
                      f"taint source not fully confirmed",
            assembly_evidence=evidence,
        )

    return VerificationResult(
        finding=finding,
        confidence="UNCERTAIN",
        confidence_score=0.3,
        reasoning=f"{dangerous_api}() with non-constant format from expression",
        assembly_evidence=evidence,
    )


def _verify_generic(finding: dict, func: dict) -> VerificationResult:
    """Generic verification for categories without specialized routines."""
    from skills._shared.verify_base import verify_generic
    return verify_generic(finding, func)


# ---------------------------------------------------------------------------
# Independent cross-representation verifiers
# ---------------------------------------------------------------------------

_PARAM_REGS = frozenset({"rcx", "rdx", "r8", "r9", "ecx", "edx", "r8d", "r9d"})


def _verify_heap_overflow_asm_independent(finding: dict, func: dict) -> VerificationResult:
    """Independently verify heap/stack overflow via assembly when detection used decompiled C.

    Looks for the copy API call instruction in assembly, then traces the size
    register backward to check if it originates from a parameter register.
    """
    asm = func.get("assembly_code", "")
    dangerous_api = finding.get("dangerous_api", "")

    if not asm or not dangerous_api:
        return VerificationResult(
            finding=finding,
            confidence="UNCERTAIN",
            confidence_score=0.3,
            reasoning="No assembly or dangerous API name available for independent verification",
        )

    lines = asm.splitlines()
    call_idx = None
    for i, line in enumerate(lines):
        if RE_CALL_INSN.search(line) and dangerous_api.lower() in line.lower():
            call_idx = i
            break

    if call_idx is None:
        return VerificationResult(
            finding=finding,
            confidence="UNCERTAIN",
            confidence_score=0.3,
            reasoning=f"Call to '{dangerous_api}' not found in assembly",
        )

    evidence = [lines[call_idx].strip()]

    param_reg_used = False
    lookback = max(0, call_idx - 20)
    for j in range(lookback, call_idx):
        stripped = lines[j].strip().lower()
        for reg in _PARAM_REGS:
            if re.search(rf"\b{reg}\b", stripped):
                param_reg_used = True
                evidence.append(lines[j].strip())
                break
        if param_reg_used:
            break

    if param_reg_used:
        return VerificationResult(
            finding=finding,
            confidence="CONFIRMED",
            confidence_score=1.0,
            reasoning=f"Assembly confirms {dangerous_api}() call with size "
                      f"derived from parameter register",
            assembly_evidence=evidence,
        )

    return VerificationResult(
        finding=finding,
        confidence="LIKELY",
        confidence_score=0.7,
        reasoning=f"Assembly confirms {dangerous_api}() call but could not "
                  f"trace size to parameter register",
        assembly_evidence=evidence,
    )


def _verify_uaf_asm_independent(finding: dict, func: dict) -> VerificationResult:
    """Independently verify UAF via assembly when detection used decompiled C.

    Checks assembly for the free call, identifies the register holding the freed
    pointer, then looks for subsequent use of that same register without
    intervening reassignment.
    """
    asm = func.get("assembly_code", "")
    extra = finding.get("extra", {})
    free_api = extra.get("free_api", "")

    if not asm or not free_api:
        return VerificationResult(
            finding=finding,
            confidence="UNCERTAIN",
            confidence_score=0.3,
            reasoning="No assembly or free API name for independent verification",
        )

    lines = asm.splitlines()
    free_idx = None
    for i, line in enumerate(lines):
        if RE_CALL_INSN.search(line) and free_api.lower() in line.lower():
            free_idx = i
            break

    if free_idx is None:
        return VerificationResult(
            finding=finding,
            confidence="UNCERTAIN",
            confidence_score=0.3,
            reasoning=f"Free call '{free_api}' not found in assembly",
        )

    evidence = [lines[free_idx].strip()]

    freed_reg = None
    for j in range(max(0, free_idx - 5), free_idx):
        stripped = lines[j].strip().lower()
        m = re.search(r"mov\s+(?:rcx|ecx)\s*,\s*(\w+)", stripped)
        if m:
            freed_reg = m.group(1)
            break

    if not freed_reg:
        return VerificationResult(
            finding=finding,
            confidence="LIKELY",
            confidence_score=0.7,
            reasoning=f"Assembly confirms {free_api}() call but freed register "
                      f"could not be identified",
            assembly_evidence=evidence,
        )

    re_use = re.compile(rf"\b{re.escape(freed_reg)}\b", re.IGNORECASE)
    re_reassign = re.compile(
        rf"(?:mov|lea)\s+{re.escape(freed_reg)}\s*,",
        re.IGNORECASE,
    )

    lookahead = min(free_idx + 40, len(lines))
    for j in range(free_idx + 1, lookahead):
        stripped = lines[j].strip()
        if re_reassign.search(stripped):
            break
        if re_use.search(stripped) and not RE_CALL_INSN.search(stripped):
            evidence.append(stripped)
            return VerificationResult(
                finding=finding,
                confidence="CONFIRMED",
                confidence_score=1.0,
                reasoning=f"Assembly confirms use of register '{freed_reg}' "
                          f"after {free_api}() without reassignment",
                assembly_evidence=evidence,
            )

    return VerificationResult(
        finding=finding,
        confidence="LIKELY",
        confidence_score=0.7,
        reasoning=f"Assembly confirms {free_api}() call; post-free use of "
                  f"'{freed_reg}' not conclusively found in assembly",
        assembly_evidence=evidence,
    )


INDEPENDENT_VERIFIERS: dict[str, Any] = {
    "heap_overflow": _verify_heap_overflow_asm_independent,
    "stack_overflow": _verify_heap_overflow_asm_independent,
    "use_after_free": _verify_uaf_asm_independent,
}


CATEGORY_VERIFIERS = {
    "heap_overflow": _verify_heap_overflow,
    "stack_overflow": _verify_stack_overflow,
    "integer_overflow": _verify_integer_overflow,
    "integer_truncation": _verify_integer_truncation,
    "use_after_free": _verify_use_after_free,
    "double_free": _verify_double_free,
    "format_string": _verify_format_string,
    "uninitialized_size": _verify_generic,
}


# ---------------------------------------------------------------------------
# Main verification pipeline
# ---------------------------------------------------------------------------

def _check_path_feasibility(finding: dict, func: dict) -> bool | None:
    """Check whether guards between function entry and the dangerous call are satisfiable.

    Returns True if feasible / unknown, False if provably infeasible,
    None if no guards to check.
    """
    code = func.get("decompiled_code", "")
    if not code:
        return None
    dangerous_api = finding.get("dangerous_api", "")
    if not dangerous_api:
        return None
    try:
        xrefs = func.get("outbound_xrefs", [])
        calls = discover_calls_with_xrefs(code, xrefs) if xrefs else extract_function_calls(code)
        target = [c for c in calls if c["function_name"] == dangerous_api]
        if not target:
            return None
        sink_line = target[0]["line_number"]
        guards = find_guards_between(code, 1, sink_line, set())
        if not guards:
            return None
        guard_dicts = [
            {"guard_type": g.guard_type, "condition": g.condition_text,
             "attacker_controllable": g.attacker_controllable,
             "bypass_difficulty": g.bypass_difficulty}
            for g in guards
        ]
        constraint_set = collect_constraints(guard_dicts)
        if not constraint_set.constraints:
            return None
        result = check_feasibility(constraint_set)
        return result.feasible is not False
    except (ValueError, KeyError, TypeError, AttributeError):
        return None


def main() -> None:
    from skills._shared.verify_base import run_verify_main

    run_verify_main(
        description="Independently verify memory corruption findings",
        verifier_name="memcorrupt_verify",
        category_verifiers=CATEGORY_VERIFIERS,
        independent_verifiers=INDEPENDENT_VERIFIERS,
        check_feasibility=_check_path_feasibility,
        resolve_db_path=resolve_db_path,
        load_function_record=load_function_record,
        status_message=status_message,
        emit_error=emit_error,
        emit_json=emit_json,
        build_meta=build_meta,
    )


if __name__ == "__main__":
    main()
