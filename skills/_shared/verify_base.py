"""Shared verification pipeline for vulnerability findings.

Provides the common scaffolding used by both logic-vulnerability-detector
and memory-corruption-detector ``verify_findings.py`` scripts.  Each scanner
supplies its own category-specific verifiers and feasibility function; the
loop, scoring, output formatting, and CLI plumbing live here.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable

from helpers.errors import ErrorCode, ScriptError

from .finding_base import CONFIDENCE_SCORES, VerificationResult


def verify_generic(finding: dict, func: dict) -> VerificationResult:
    """Generic verification for categories without specialized routines."""
    code = func.get("decompiled_code", "")
    if not code:
        return VerificationResult(
            finding=finding,
            confidence="UNCERTAIN",
            confidence_score=0.3,
            reasoning="No decompiled code available for verification",
        )

    return VerificationResult(
        finding=finding,
        confidence="LIKELY",
        confidence_score=0.7,
        reasoning="Pattern present but no specialized verification implemented",
    )


def verify_findings(
    findings: list[dict],
    db_path: str,
    category_verifiers: dict[str, Callable],
    check_feasibility: Callable[[dict, dict], bool | None],
    *,
    load_function_record: Callable,
    status_message: Callable,
    independent_verifiers: dict[str, Callable] | None = None,
    verification_mode: str = "independent",
) -> list[VerificationResult]:
    """Run the verification loop over *findings*.

    Parameters
    ----------
    category_verifiers:
        ``{category_name: verifier_fn(finding, func) -> VerificationResult}``
    check_feasibility:
        ``(finding, func) -> bool | None`` — True/None = feasible,
        False = infeasible.
    load_function_record:
        Callable that loads a function record dict from the DB.
    status_message:
        Callable that emits progress messages to stderr.
    independent_verifiers:
        ``{category_name: independent_fn(finding, func) -> VerificationResult}``
        Cross-representation verifiers that use a *different* representation
        than the detector (e.g. assembly when detection used decompiled C).
        Used when *verification_mode* is ``"independent"``.
    verification_mode:
        ``"independent"`` (default) uses cross-representation verifiers where
        available, falling back to same-representation verifiers.
        ``"replicate"`` uses only the original same-representation verifiers.
    """
    if independent_verifiers is None:
        independent_verifiers = {}

    results: list[VerificationResult] = []
    func_cache: dict[int, dict] = {}
    func_errors: dict[int, ScriptError] = {}

    for i, finding in enumerate(findings):
        fid = finding.get("function_id")
        if fid and fid not in func_cache and fid not in func_errors:
            try:
                rec = load_function_record(db_path, function_id=fid)
            except ScriptError as exc:
                func_errors[fid] = exc
            else:
                if rec:
                    func_cache[fid] = rec

        if fid and fid in func_errors:
            load_error = func_errors[fid]
            status_message(
                f"Verifying finding {i + 1}/{len(findings)}: "
                f"{finding.get('category', '')} in {finding.get('function_name', '?')}"
            )
            finding_with_error = dict(finding)
            finding_with_error["infrastructure_error"] = {
                "code": load_error.code,
                "message": str(load_error),
            }
            vr = VerificationResult(
                finding=finding_with_error,
                confidence="UNCERTAIN",
                confidence_score=0.3,
                reasoning=(
                    "Verification skipped due to infrastructure error while "
                    f"loading function context: {load_error}"
                ),
                mitigating_factors=[
                    f"Infrastructure error prevented verification ({load_error.code})"
                ],
            )
            old_score = finding.get("score", 0.0)
            conf_multiplier = CONFIDENCE_SCORES.get(vr.confidence, 0.3)
            vr.verified_score = round(old_score * conf_multiplier, 3)
            results.append(vr)
            continue

        func = func_cache.get(fid, {})
        category = finding.get("category", "")

        if verification_mode == "independent" and category in independent_verifiers:
            verifier = independent_verifiers[category]
        else:
            verifier = category_verifiers.get(category, verify_generic)

        status_message(f"Verifying finding {i + 1}/{len(findings)}: "
                       f"{category} in {finding.get('function_name', '?')}")

        vr = verifier(finding, func)

        feasible = check_feasibility(finding, func)
        if feasible is False and vr.confidence not in ("FALSE_POSITIVE", "UNLIKELY"):
            vr.confidence = "FALSE_POSITIVE"
            vr.confidence_score = 0.0
            vr.reasoning += " [guard constraints provably unsatisfiable]"
            vr.mitigating_factors.append("Path infeasible per constraint analysis")

        old_score = finding.get("score", 0.0)
        conf_multiplier = CONFIDENCE_SCORES.get(vr.confidence, 0.3)
        vr.verified_score = round(old_score * conf_multiplier, 3)

        results.append(vr)

    return results


def print_text(results: list[dict]) -> None:
    """Human-readable verification output."""
    confirmed = [r for r in results if r["confidence"] == "CONFIRMED"]
    likely = [r for r in results if r["confidence"] == "LIKELY"]
    uncertain = [r for r in results if r["confidence"] == "UNCERTAIN"]
    fp = [r for r in results if r["confidence"] in ("FALSE_POSITIVE", "UNLIKELY")]

    print(f"=== Verification Results: {len(results)} findings ===")
    print(f"  CONFIRMED: {len(confirmed)}  LIKELY: {len(likely)}  "
          f"UNCERTAIN: {len(uncertain)}  FALSE_POSITIVE: {len(fp)}\n")

    for r in sorted(results, key=lambda x: x["verified_score"], reverse=True):
        f = r["finding"]
        print(f"  [{r['confidence']}] {r['verified_score']:.2f}  "
              f"{f.get('function_name', '?')} -- {f.get('category', '?')}")
        print(f"    Reasoning: {r['reasoning']}")
        if r.get("mitigating_factors"):
            print(f"    Mitigating: {', '.join(r['mitigating_factors'])}")
        if r.get("assembly_evidence"):
            for ev in r["assembly_evidence"][:2]:
                print(f"    ASM: {ev}")
        print()


def run_verify_main(
    *,
    description: str,
    verifier_name: str,
    category_verifiers: dict[str, Callable],
    check_feasibility: Callable[[dict, dict], bool | None],
    resolve_db_path: Callable,
    load_function_record: Callable,
    status_message: Callable,
    emit_error: Callable,
    emit_json: Callable,
    build_meta: Callable,
    independent_verifiers: dict[str, Callable] | None = None,
) -> None:
    """Shared ``main()`` implementation for verify_findings scripts."""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--findings", required=True,
                        help="Path to findings JSON file")
    parser.add_argument("--db-path", required=True,
                        help="Path to the analysis database")
    parser.add_argument("--json", action="store_true", help="JSON output mode")
    parser.add_argument(
        "--verification-mode",
        choices=["independent", "replicate"],
        default="independent",
        help="Verification strategy: 'independent' uses cross-representation "
             "verifiers (default), 'replicate' uses same-representation only",
    )
    args = parser.parse_args()

    db_path = resolve_db_path(args.db_path)
    findings_path = Path(args.findings)
    if not findings_path.exists():
        emit_error(f"Findings file not found: {args.findings}", ErrorCode.NOT_FOUND)

    try:
        with open(findings_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        emit_error(
            f"Malformed JSON in findings file {findings_path}: {exc}",
            ErrorCode.PARSE_ERROR,
        )

    if isinstance(data, dict):
        findings_list = data.get("findings", [])
    elif isinstance(data, list):
        findings_list = data
    else:
        emit_error("Findings file must contain a dict or list", ErrorCode.PARSE_ERROR)

    verification_mode = getattr(args, "verification_mode", "independent")
    status_message(f"Verifying {len(findings_list)} findings "
                   f"(mode={verification_mode})...")
    results = verify_findings(
        findings_list,
        db_path,
        category_verifiers,
        check_feasibility,
        load_function_record=load_function_record,
        status_message=status_message,
        independent_verifiers=independent_verifiers,
        verification_mode=verification_mode,
    )

    result_data = {
        "status": "ok",
        "_meta": build_meta(db_path, verifier=verifier_name,
                            verification_mode=verification_mode),
        "verified_findings": [r.to_dict() for r in results],
        "summary": {
            "total_input": len(findings_list),
            "confirmed": sum(1 for r in results if r.confidence == "CONFIRMED"),
            "likely": sum(1 for r in results if r.confidence == "LIKELY"),
            "uncertain": sum(1 for r in results if r.confidence == "UNCERTAIN"),
            "false_positive": sum(1 for r in results
                                  if r.confidence in ("FALSE_POSITIVE", "UNLIKELY")),
        },
    }

    if args.json:
        emit_json(result_data)
    else:
        print_text(result_data["verified_findings"])
