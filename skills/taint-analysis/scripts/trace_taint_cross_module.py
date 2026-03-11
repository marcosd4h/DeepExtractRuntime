#!/usr/bin/env python3
"""Cross-module taint orchestrator.

Traces tainted parameters from a function in one module across DLL
boundaries into other analyzed modules, maintaining:

- **Full parameter mapping** across each boundary crossing
- **Guard/bypass accumulation** through the entire chain
- **Trust boundary analysis** (privilege escalation detection)
- **COM vtable call resolution** for indirect COM dispatch
- **RPC boundary detection** for cross-process taint chains
- **Return-value back-propagation** when tainted data flows back

Groups findings by module boundary crossing and annotates each with
the accumulated taint context.

Usage:
    python trace_taint_cross_module.py <db_path> <function_name>
    python trace_taint_cross_module.py <db_path> --id <fid> --params 1,3 --cross-depth 2
    python trace_taint_cross_module.py <db_path> <function_name> --json
    python trace_taint_cross_module.py <db_path> <function_name> --no-trust-analysis
    python trace_taint_cross_module.py <db_path> <function_name> --no-com-resolve
    python trace_taint_cross_module.py <db_path> --from-entrypoints --top 5 --json
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

from _common import (
    TRUST_LEVEL_RANK,
    TaintContext,
    WORKSPACE_ROOT,
    classify_module_trust,
    classify_trust_transition,
    emit_error,
    emit_json,
    get_function,
    param_name_for,
    resolve_db_path,
    resolve_tainted_params,
    run_skill_script,
    severity_label,
    validate_function_id,
)
from helpers.errors import emit_error, ErrorCode, safe_parse_args
from trace_taint_forward import trace_forward


def trace_cross_module(
    db_path: str,
    function_name: str | None = None,
    function_id: int | None = None,
    params_arg: str | None = None,
    depth: int = 2,
    cross_depth: int = 2,
    trust_analysis: bool = True,
    com_resolve: bool = True,
) -> dict:
    """Run cross-module taint analysis with full context preservation.

    Performs a forward taint trace with cross-module resolution enabled,
    then restructures the results to highlight module-boundary crossings,
    trust escalations, COM/RPC boundaries, and accumulated guard chains.
    """
    func = get_function(db_path, function_name=function_name, function_id=function_id)
    if not func:
        target = function_name or f"ID={function_id}"
        emit_error(f"Function '{target}' not found", ErrorCode.NOT_FOUND)

    sig = func.get("function_signature", "") or ""
    code = func.get("decompiled_code", "") or ""
    params = resolve_tainted_params(params_arg, sig, code)

    source_trust = classify_module_trust(db_path) if trust_analysis else "user_process"

    ctx = TaintContext()
    ctx.push_frame(
        module=func.get("module_name", "?"),
        function=func.get("function_name", "?"),
        param=params[0] if params else 0,
        trust_level=source_trust,
    )
    ctx.param_map = {p: p for p in params}

    result = trace_forward(
        db_path=db_path,
        function_id=func["function_id"],
        params=params,
        depth=depth,
        cross_module=True,
        cross_depth=cross_depth,
        taint_context=ctx,
        com_resolve=com_resolve,
    )

    if result.get("status") != "ok":
        return result

    findings = result.get("findings", [])
    local_findings = [f for f in findings if not f.get("cross_module_source")]
    cross_findings = [f for f in findings if f.get("cross_module_source")]

    by_boundary: dict[str, list[dict]] = defaultdict(list)
    for f in cross_findings:
        src = f["cross_module_source"]
        bt = src.get("boundary_type", "dll_import")
        key = f"{src['from_module']} -[{bt}]-> {src['to_module']}"
        by_boundary[key].append(f)

    modules_reached: set[str] = set()
    for f in cross_findings:
        modules_reached.add(f["cross_module_source"]["to_module"])

    # Trust analysis summary
    trust_info: dict = {}
    if trust_analysis:
        transitions = ctx.trust_transitions
        escalations = [t for t in transitions if t.get("transition") == "privilege_escalation"]
        trust_info = {
            "source_module_trust": source_trust,
            "transitions": transitions,
            "escalation_count": len(escalations),
            "escalation_details": escalations,
            "highest_target_trust": max(
                (TRUST_LEVEL_RANK.get(t.get("to_trust", "user_process"), 0) for t in transitions),
                default=0,
            ),
        }

    # Boundary type breakdown
    boundary_type_counts: dict[str, int] = defaultdict(int)
    for f in cross_findings:
        bt = f.get("cross_module_source", {}).get("boundary_type", "dll_import")
        boundary_type_counts[bt] += 1

    # Return-value taint info
    return_taint_info = result.get("cross_module", {}).get("return_taint_vars", [])

    output = {
        "status": "ok",
        "function": result["function"],
        "tainted_params": params,
        "depth": depth,
        "cross_depth": cross_depth,
        "local_findings": local_findings,
        "cross_module_findings": cross_findings,
        "boundary_groups": {k: v for k, v in by_boundary.items()},
        "logic_effects": result.get("logic_effects", {}),
        "taint_context": ctx.to_dict(),
        "trust_analysis": trust_info,
        "summary": {
            "total_sinks": len(findings),
            "local_sinks": len(local_findings),
            "cross_module_sinks": len(cross_findings),
            "modules_reached": sorted(modules_reached),
            "module_boundaries_crossed": len(by_boundary),
            "boundary_type_counts": dict(boundary_type_counts),
            "trust_escalations": trust_info.get("escalation_count", 0),
            "return_taint_vars": return_taint_info,
            "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in findings if f["severity"] == "LOW"),
        },
    }

    return output


def _extract_tainted_param_indices(tainted_args: list[str]) -> str | None:
    """Parse ``tainted_args`` from rank_entrypoints into a ``--params`` string.

    Each entry looks like ``"arg0 (LPWSTR ...): string pointer - TAINT"``.
    Returns a comma-separated 1-based param string (e.g. ``"1,3"``), or
    ``None`` when no indices can be extracted (caller falls back to all).
    """
    indices: list[int] = []
    for item in tainted_args:
        m = re.match(r"arg(\d+)\b", item)
        if m:
            indices.append(int(m.group(1)) + 1)
    return ",".join(str(i) for i in sorted(set(indices))) if indices else None


def trace_from_entrypoints(
    db_path: str,
    *,
    top: int = 5,
    min_score: float = 0.0,
    depth: int = 2,
    cross_depth: int = 2,
    trust_analysis: bool = True,
    com_resolve: bool = True,
) -> dict:
    """Discover ranked entry points, then run cross-module taint on each.

    Uses ``rank_entrypoints.py`` (via subprocess) to discover and rank the
    module's entry points, then calls :func:`trace_cross_module` in-process
    for each qualifying entry point.  Returns an aggregated report.
    """
    ranking = run_skill_script(
        "map-attack-surface", "rank_entrypoints.py", [db_path], json_output=True,
        timeout=300,
    )
    if not ranking["success"]:
        return {
            "status": "error",
            "error": f"rank_entrypoints failed: {ranking.get('error', 'unknown')}",
        }

    ranked: list[dict] = (ranking.get("json_data") or {}).get("ranked", [])
    if not ranked:
        return {"status": "ok", "mode": "from_entrypoints",
                "entry_points_analyzed": 0, "entry_points_skipped": 0,
                "results": [], "aggregate": _empty_aggregate()}

    candidates = ranked[:top] if top > 0 else ranked
    if min_score > 0:
        candidates = [ep for ep in candidates if (ep.get("attack_score") or 0) >= min_score]

    results: list[dict] = []
    skipped = 0
    for ep in candidates:
        fid = ep.get("function_id")
        if fid is None:
            skipped += 1
            continue
        params_arg = _extract_tainted_param_indices(ep.get("tainted_args") or [])
        try:
            taint_result = trace_cross_module(
                db_path=db_path,
                function_id=int(fid),
                params_arg=params_arg,
                depth=depth,
                cross_depth=cross_depth,
                trust_analysis=trust_analysis,
                com_resolve=com_resolve,
            )
        except Exception as exc:
            print(f"[WARN] Taint failed for {ep.get('function_name', '?')}: {exc}",
                  file=sys.stderr)
            taint_result = {"status": "error", "error": str(exc)}
        results.append({
            "entry_point": {
                "function_name": ep.get("function_name", "?"),
                "function_id": fid,
                "attack_score": ep.get("attack_score", 0),
                "attack_rank": ep.get("attack_rank", 0),
                "entry_type": ep.get("entry_type", ""),
            },
            "taint_result": taint_result,
        })

    aggregate = _build_aggregate(results)
    return {
        "status": "ok",
        "mode": "from_entrypoints",
        "entry_points_analyzed": len(results),
        "entry_points_skipped": skipped,
        "results": results,
        "aggregate": aggregate,
    }


def _empty_aggregate() -> dict:
    return {
        "total_sinks": 0, "cross_module_sinks": 0, "trust_escalations": 0,
        "modules_reached": [], "critical": 0, "high": 0, "medium": 0, "low": 0,
    }


def _build_aggregate(results: list[dict]) -> dict:
    total = xmod = trust_esc = crit = high = med = low = 0
    modules: set[str] = set()
    for r in results:
        summary = r.get("taint_result", {}).get("summary", {})
        total += summary.get("total_sinks", 0)
        xmod += summary.get("cross_module_sinks", 0)
        trust_esc += summary.get("trust_escalations", 0)
        crit += summary.get("critical", 0)
        high += summary.get("high", 0)
        med += summary.get("medium", 0)
        low += summary.get("low", 0)
        modules.update(summary.get("modules_reached", []))
    return {
        "total_sinks": total, "cross_module_sinks": xmod,
        "trust_escalations": trust_esc, "modules_reached": sorted(modules),
        "critical": crit, "high": high, "medium": med, "low": low,
    }


def _print_entrypoints_result(result: dict) -> None:
    if result.get("status") != "ok":
        print(f"[ERROR] {result.get('error', 'unknown')}")
        return

    analyzed = result.get("entry_points_analyzed", 0)
    skipped = result.get("entry_points_skipped", 0)
    print(f"\n{'=' * 78}")
    print(f"Cross-Module Taint from Entry Points")
    print(f"{'=' * 78}")
    print(f"Analyzed: {analyzed} | Skipped (no function_id): {skipped}")

    for item in result.get("results", []):
        ep = item.get("entry_point", {})
        tr = item.get("taint_result", {})
        score_pct = f"{ep.get('attack_score', 0) * 100:.1f}%"

        print(f"\n{'-' * 78}")
        print(f"  #{ep.get('attack_rank', '?')}  {ep.get('function_name', '?')}  "
              f"[{ep.get('entry_type', '?')}]  score={score_pct}")
        print(f"{'-' * 78}")

        if tr.get("status") != "ok":
            print(f"  Taint result: {tr.get('status', 'error')} -- "
                  f"{tr.get('error', tr.get('target', '?'))}")
            continue

        summary = tr.get("summary", {})
        print(f"  Sinks: {summary.get('total_sinks', 0)} "
              f"({summary.get('local_sinks', 0)} local, "
              f"{summary.get('cross_module_sinks', 0)} cross-module)")
        print(f"  CRITICAL={summary.get('critical', 0)} "
              f"HIGH={summary.get('high', 0)} "
              f"MEDIUM={summary.get('medium', 0)} "
              f"LOW={summary.get('low', 0)}")

        reached = summary.get("modules_reached", [])
        if reached:
            print(f"  Modules reached: {', '.join(reached)}")
        if summary.get("trust_escalations", 0):
            print(f"  Trust escalations: {summary['trust_escalations']}")

    agg = result.get("aggregate", {})
    print(f"\n{'=' * 78}")
    print(f"AGGREGATE SUMMARY")
    print(f"{'=' * 78}")
    print(f"Total sinks: {agg.get('total_sinks', 0)} "
          f"({agg.get('cross_module_sinks', 0)} cross-module)")
    print(f"CRITICAL={agg.get('critical', 0)} HIGH={agg.get('high', 0)} "
          f"MEDIUM={agg.get('medium', 0)} LOW={agg.get('low', 0)}")
    reached = agg.get("modules_reached", [])
    if reached:
        print(f"Modules reached: {', '.join(reached)}")
    if agg.get("trust_escalations", 0):
        print(f"Trust escalations: {agg['trust_escalations']}")


def _print_result(result: dict) -> None:
    status = result.get("status", "")

    func = result.get("function", {})
    params = result.get("tainted_params", [])
    pnames = ", ".join(param_name_for(p) for p in params)
    print(f"\n{'=' * 78}")
    print(f"Cross-Module Taint: {func.get('function_name', '?')}")
    print(f"{'=' * 78}")
    print(f"Module: {func.get('module_name', '?')}")
    print(f"Signature: {func.get('function_signature', '?')}")
    print(f"Tainted params: {pnames}")
    print(f"Depth: {result.get('depth')} | Cross-module hops: {result.get('cross_depth')}")

    # Trust analysis
    trust = result.get("trust_analysis", {})
    if trust:
        src_trust = trust.get("source_module_trust", "?")
        esc_count = trust.get("escalation_count", 0)
        print(f"\nTrust level: {src_trust}")
        if esc_count > 0:
            print(f"*** {esc_count} PRIVILEGE ESCALATION BOUNDARY(S) DETECTED ***")
            for esc in trust.get("escalation_details", []):
                print(f"    {esc['from_module']} ({esc['from_trust']}) -> "
                      f"{esc['to_module']} ({esc['to_trust']}) [{esc['boundary_type']}]")

    summary = result.get("summary", {})
    print(f"\nModules reached: {', '.join(summary.get('modules_reached', [])) or 'none'}")
    print(f"Boundary crossings: {summary.get('module_boundaries_crossed', 0)}")

    bt_counts = summary.get("boundary_type_counts", {})
    if bt_counts:
        parts = [f"{k}={v}" for k, v in bt_counts.items()]
        print(f"Boundary types: {', '.join(parts)}")

    ret_vars = summary.get("return_taint_vars", [])
    if ret_vars:
        print(f"Return-tainted variables: {', '.join(ret_vars)}")

    local = result.get("local_findings", [])
    if local:
        print(f"\n--- Local Findings ({len(local)}) ---\n")
        for i, f in enumerate(local, 1):
            print(f"[{i}] {f['severity']} ({f['score']:.2f}) -- "
                  f"{f['param_name']} reaches {f['sink']} ({f['sink_category']})")
            print(f"    Path: {' -> '.join(f['path'])}")

    groups = result.get("boundary_groups", {})
    if groups:
        print(f"\n--- Cross-Module Findings ---\n")
        for boundary, bfindings in groups.items():
            print(f"  [{boundary}] ({len(bfindings)} findings)")
            for i, f in enumerate(bfindings, 1):
                escalated = " [ESCALATED]" if f.get("trust_escalated") else ""
                print(f"    [{i}] {f['severity']} ({f['score']:.2f}){escalated} -- "
                      f"{f['param_name']} reaches {f['sink']} ({f['sink_category']})")
                print(f"        Path: {' -> '.join(f['path'])}")

                cms = f.get("cross_module_source", {})
                pm = cms.get("param_mapping", {})
                if pm:
                    mappings = ", ".join(f"a{k}->a{v}" for k, v in pm.items())
                    print(f"        Param mapping: {mappings}")

                guards = f.get("guards", [])
                if guards:
                    for g in guards:
                        ctrl = "YES" if g["attacker_controllable"] else "NO"
                        print(f"        Guard: [{g['guard_type'].upper()}] "
                              f"controllable={ctrl} difficulty={g['bypass_difficulty']}")

                ctx = f.get("taint_context", {})
                acc_guards = ctx.get("accumulated_guards", [])
                if acc_guards:
                    unique_types = set(g.get("guard_type", "?") for g in acc_guards)
                    print(f"        Accumulated guards across chain: {len(acc_guards)} "
                          f"(types: {', '.join(sorted(unique_types))})")
            print()

    print(f"\n--- Summary ---")
    print(f"Total: {summary.get('total_sinks', 0)} sinks "
          f"({summary.get('local_sinks', 0)} local, "
          f"{summary.get('cross_module_sinks', 0)} cross-module)")
    print(f"CRITICAL={summary.get('critical', 0)} HIGH={summary.get('high', 0)} "
          f"MEDIUM={summary.get('medium', 0)} LOW={summary.get('low', 0)}")
    if summary.get("trust_escalations", 0):
        print(f"Trust escalations: {summary['trust_escalations']}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cross-module taint analysis: trace tainted inputs across DLL boundaries.",
    )
    parser.add_argument("db_path", help="Path to the starting module analysis DB")
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument("--function", "--name", dest="function_name", metavar="NAME",
                              help="Function name")
    target_group.add_argument("--id", "--function-id", type=int, dest="function_id")
    parser.add_argument("function_name_pos", nargs="?", default=None, help=argparse.SUPPRESS)
    target_group.add_argument(
        "--from-entrypoints", action="store_true",
        help="Auto-discover and rank entry points, then taint-trace the top N",
    )
    parser.add_argument("--params", default=None,
                        help="Comma-separated param numbers (1-based); omit for all")
    parser.add_argument("--depth", type=int, default=2,
                        help="Max intra-module recursion depth (default: 2)")
    parser.add_argument("--cross-depth", type=int, default=2,
                        help="Max cross-module hops (default: 2)")
    parser.add_argument("--top", type=int, default=5,
                        help="Number of top entry points to analyze (default: 5; "
                             "used with --from-entrypoints)")
    parser.add_argument("--min-score", type=float, default=0.0,
                        help="Minimum attack score threshold (default: 0.0; "
                             "used with --from-entrypoints)")
    parser.add_argument("--no-trust-analysis", action="store_true",
                        help="Disable trust boundary classification")
    parser.add_argument("--no-com-resolve", action="store_true",
                        help="Disable COM vtable call resolution")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--no-cache", action="store_true")
    args = safe_parse_args(parser)
    if args.function_name_pos and not args.function_name:
        args.function_name = args.function_name_pos

    db_path = resolve_db_path(args.db_path)

    if args.from_entrypoints:
        result = trace_from_entrypoints(
            db_path=db_path,
            top=args.top,
            min_score=args.min_score,
            depth=args.depth,
            cross_depth=args.cross_depth,
            trust_analysis=not args.no_trust_analysis,
            com_resolve=not args.no_com_resolve,
        )
        if args.json:
            emit_json(result)
        else:
            _print_entrypoints_result(result)
        return

    if not args.function_name and args.function_id is None:
        emit_error("Provide a function name, --id, or --from-entrypoints", ErrorCode.INVALID_ARGS)
    if args.function_id is not None:
        args.function_id = validate_function_id(args.function_id)

    result = trace_cross_module(
        db_path=db_path,
        function_name=args.function_name,
        function_id=args.function_id,
        params_arg=args.params,
        depth=args.depth,
        cross_depth=args.cross_depth,
        trust_analysis=not args.no_trust_analysis,
        com_resolve=not args.no_com_resolve,
    )

    if args.json:
        emit_json(result)
    else:
        _print_result(result)


if __name__ == "__main__":
    main()
