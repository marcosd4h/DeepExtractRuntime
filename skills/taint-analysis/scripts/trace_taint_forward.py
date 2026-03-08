#!/usr/bin/env python3
"""Forward taint propagation: trace tainted parameters to dangerous sinks.

Wraps data-flow-tracer ``forward_trace.py`` via subprocess, then enriches
the results with:
  - Sink detection via ``classify_api_security()``
  - Guard/bypass analysis via ``find_guards_between()``
  - Logic-effect detection (branch steering, OOB, DoS, state pollution)
  - Severity scoring per finding

Usage:
    python trace_taint_forward.py <db_path> <function_name> --params 1,3
    python trace_taint_forward.py <db_path> --id <fid> --params 1 --depth 3
    python trace_taint_forward.py <db_path> <function_name> --json
"""

from __future__ import annotations

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from _common import (
    TRUST_ESCALATION_MULTIPLIER,
    TaintContext,
    WORKSPACE_ROOT,
    analyze_def_use_taint,
    cache_result,
    classify_module_trust,
    classify_sink,
    compute_finding_score,
    detect_logic_effects,
    detect_return_taint,
    detect_rpc_boundaries,
    emit_error,
    emit_json,
    find_guards_between,
    find_return_assignment_targets,
    get_cached,
    get_function,
    get_workspace_args,
    param_name_for,
    resolve_db_path,
    resolve_tainted_params,
    resolve_vtable_callees,
    run_skill_script,
    severity_label,
    validate_function_id,
)
from helpers.errors import emit_error, ErrorCode, safe_parse_args

# ---------------------------------------------------------------------------
# Core forward taint analysis
# ---------------------------------------------------------------------------

def _walk_findings(
    trace_result: dict,
    path_so_far: list[str],
    func_data: dict,
    tainted_var: str,
    all_tainted: set[str],
) -> list[dict]:
    """Recursively walk a forward_trace result tree collecting sink findings."""
    findings: list[dict] = []
    status = trace_result.get("status", "")
    if status not in ("ok",):
        return findings

    func_info = trace_result.get("function", {})
    fname = func_info.get("function_name", "?")
    pnum = trace_result.get("param_number", 0)
    pname = trace_result.get("param_name", f"a{pnum}")

    current_path = path_so_far + [f"{fname}.{pname}"]

    # Track local tainted aliases within this function scope
    local_tainted = set(all_tainted)
    local_tainted.add(pname)

    code = func_data.get("decompiled_code", "") if func_data else ""

    # Expand tainted set using def-use chain analysis for better precision
    if code and local_tainted:
        try:
            du_result = analyze_def_use_taint(code, local_tainted)
            local_tainted = local_tainted | du_result.tainted_vars
        except Exception:
            pass  # graceful degradation: fall back to original tainted set

    for cu in trace_result.get("call_usages", []):
        callee = cu.get("function_name", "")
        callee_clean = callee
        for pfx in ("__imp_", "_imp_", "j_", "cs:"):
            if callee_clean.startswith(pfx):
                callee_clean = callee_clean[len(pfx):]

        sec_cat = classify_sink(callee)
        if sec_cat and sec_cat not in ("sync",):
            sink_path = current_path + [f"{callee}.arg{cu['arg_position'] + 1}"]
            hops = len(sink_path) - 1
            source_line = 1
            sink_line = cu.get("line_number", len(code.splitlines()))

            guards = []
            if code:
                guards = find_guards_between(code, source_line, sink_line, local_tainted)
            non_tainted_guards = sum(1 for g in guards if not g.attacker_controllable)

            score = compute_finding_score(sec_cat, hops, non_tainted_guards)
            findings.append({
                "param": pnum,
                "param_name": pname,
                "sink": callee,
                "sink_category": sec_cat,
                "severity": severity_label(score),
                "score": score,
                "path": sink_path,
                "path_hops": hops,
                "sink_line": cu.get("line_number"),
                "sink_expression": cu.get("line", ""),
                "arg_position": cu["arg_position"] + 1,
                "guards": [g.to_dict() for g in guards],
            })

    # Recurse into callee traces
    for sub in trace_result.get("callee_traces", []):
        sub_func = sub.get("function", {})
        sub_fname = sub_func.get("function_name", "?")
        sub_pnum = sub.get("param_number", 0)
        sub_pname = sub.get("param_name", f"a{sub_pnum}")
        sub_path = current_path + [f"{sub_fname}.{sub_pname}"]
        child_findings = _walk_findings(sub, sub_path[:-1], None, sub_pname, all_tainted)
        findings.extend(child_findings)

    return findings


def _build_callee_param_map(
    func: dict,
    callee_name: str,
    all_tainted: set[str],
) -> list[int]:
    """Determine which parameters of *callee_name* receive tainted data.

    For each tainted variable, uses ``find_param_in_calls`` to find all
    call sites where that variable is passed as an argument, then filters
    for calls whose target is *callee_name*.  Returns a sorted list of
    1-based parameter numbers in the callee that receive tainted data.
    """
    from _common import find_param_in_calls as _find

    code = func.get("decompiled_code", "") or ""
    if not code:
        return []

    # Expand tainted set through def-use chains before checking call sites
    expanded_tainted = set(all_tainted)
    try:
        du_result = analyze_def_use_taint(code, all_tainted)
        expanded_tainted = expanded_tainted | du_result.tainted_vars
    except Exception:
        pass

    mapped: set[int] = set()
    for tv in expanded_tainted:
        if not tv:
            continue
        usages = _find(code, tv)
        for cu in usages:
            if cu.get("function_name", "") == callee_name:
                mapped.add(cu["arg_position"] + 1)

    if not mapped:
        outbound = func.get("outbound_xrefs", [])
        for xref in outbound:
            if isinstance(xref, dict) and xref.get("function_name") == callee_name:
                mapped.add(1)
                break

    return sorted(mapped) if mapped else []


def _trace_cross_module_callees(
    db_path: str,
    func: dict,
    params: list[int],
    cross_depth: int,
    all_tainted: set[str],
    visited_modules: set[str] | None = None,
    taint_context: TaintContext | None = None,
    raw_traces: dict[int, dict] | None = None,
    com_resolve: bool = True,
) -> tuple[list[dict], list[str]]:
    """Resolve external callees to other analyzed modules and recurse.

    Enhanced version with:
    - Specific parameter mapping (not ``params=None``)
    - TaintContext threading (call stack, guards, trust transitions)
    - COM vtable call resolution
    - RPC boundary detection
    - Return-value back-propagation

    Returns ``(cross_findings, return_tainted_vars)`` where
    *return_tainted_vars* are caller-side variable names that received
    tainted return values from cross-module callees.
    """
    if cross_depth <= 0:
        return [], []
    if visited_modules is None:
        visited_modules = set()

    current_module = func.get("module_name", "")
    visited_modules.add(current_module.lower())

    try:
        from helpers.cross_module_graph import ModuleResolver
    except ImportError:
        return [], []

    cross_findings: list[dict] = []
    return_tainted_vars: list[str] = []

    # Collect normal external xrefs
    outbound = func.get("outbound_xrefs", [])
    if isinstance(outbound, str):
        from helpers import parse_json_safe
        outbound = parse_json_safe(outbound) or []

    external_xrefs = [
        x for x in outbound
        if isinstance(x, dict) and x.get("module_name")
    ]

    # Collect COM vtable callees (when enabled)
    vtable_callees: list[dict] = []
    if com_resolve:
        vtable_callees = resolve_vtable_callees(func, db_path)
    vtable_xrefs = [
        {"function_name": vc["callee_name"], "module_name": vc.get("module_name", "")}
        for vc in vtable_callees
        if vc.get("module_name")
    ]
    vtable_names = {vc["callee_name"] for vc in vtable_callees}

    # Detect RPC boundaries in the caller's code
    caller_code = func.get("decompiled_code", "") or ""
    from _common import find_param_in_calls as _fpc
    caller_call_usages = []
    for tv in all_tainted:
        caller_call_usages.extend(_fpc(caller_code, tv))
    rpc_boundaries = detect_rpc_boundaries(caller_call_usages)
    rpc_callee_names = {r["function_name"] for r in rpc_boundaries}

    all_xrefs = external_xrefs + vtable_xrefs
    if not all_xrefs:
        return [], []

    source_trust = classify_module_trust(db_path) if taint_context else "user_process"

    with ModuleResolver() as resolver:
        resolved = resolver.batch_resolve_xrefs(all_xrefs)

        # Prepare all callee tasks
        callee_tasks: list[tuple[dict, str, list[int] | None, str, TaintContext | None]] = []
        for info in resolved.values():
            if info is None:
                continue

            callee_name = info.get("function_name", "")
            target_db = info.get("db_path", "")
            target_module = info.get("module", "")
            if not callee_name or not target_db or not info.get("has_decompiled"):
                continue
            if target_module.lower() in visited_modules:
                continue

            mapped_params = _build_callee_param_map(func, callee_name, all_tainted)
            if not mapped_params:
                mapped_params = None

            boundary_type = "dll_import"
            if callee_name in vtable_names:
                boundary_type = "com_vtable"
            elif callee_name in rpc_callee_names:
                boundary_type = "rpc"

            child_ctx: TaintContext | None = None
            if taint_context is not None:
                child_ctx = taint_context.clone()
                target_trust = classify_module_trust(target_db)
                child_ctx.push_frame(
                    module=current_module,
                    function=func.get("function_name", "?"),
                    param=mapped_params[0] if mapped_params else 0,
                    trust_level=source_trust,
                )
                child_ctx.add_trust_transition(
                    from_module=current_module,
                    to_module=target_module,
                    from_trust=source_trust,
                    to_trust=target_trust,
                    boundary_type=boundary_type,
                )
                if mapped_params:
                    child_ctx.param_map = {
                        orig: mapped
                        for orig, mapped in zip(params[:len(mapped_params)], mapped_params)
                    }

            callee_tasks.append((info, boundary_type, mapped_params, target_db, child_ctx))

        def _trace_one_callee(
            task: tuple[dict, str, list[int] | None, str, TaintContext | None],
        ) -> tuple[dict, str, list[int] | None, str, TaintContext | None, dict]:
            info, boundary_type, mapped_params, target_db, child_ctx = task
            callee_name = info.get("function_name", "")
            recurse = cross_depth > 1
            sub_result = trace_forward(
                db_path=target_db,
                function_name=callee_name,
                params=mapped_params,
                depth=1,
                cross_module=recurse,
                cross_depth=cross_depth - 1 if recurse else 0,
                taint_context=child_ctx,
            )
            return info, boundary_type, mapped_params, target_db, child_ctx, sub_result

        def _process_callee_result(
            info: dict,
            boundary_type: str,
            mapped_params: list[int] | None,
            target_db: str,
            child_ctx: TaintContext | None,
            sub_result: dict,
        ) -> None:
            if sub_result.get("status") != "ok":
                return

            callee_name = info.get("function_name", "")
            target_module = info.get("module", "")

            if detect_return_taint(sub_result):
                ret_targets = find_return_assignment_targets(caller_code, callee_name)
                return_tainted_vars.extend(ret_targets)
                if child_ctx is not None:
                    child_ctx.return_taint = True

            trust_mult = 1.0
            if taint_context is not None:
                target_trust = classify_module_trust(target_db)
                from _common import classify_trust_transition as _ctt
                if _ctt(source_trust, target_trust) == "privilege_escalation":
                    trust_mult = TRUST_ESCALATION_MULTIPLIER

            for finding in sub_result.get("findings", []):
                finding["cross_module_source"] = {
                    "from_module": current_module,
                    "from_function": func.get("function_name", "?"),
                    "to_module": target_module,
                    "to_function": callee_name,
                    "boundary_type": boundary_type,
                    "param_mapping": (
                        {str(p): mp for p, mp in zip(params[:len(mapped_params)], mapped_params)}
                        if mapped_params else {}
                    ),
                }
                if child_ctx is not None:
                    finding["taint_context"] = child_ctx.to_dict()
                finding["path"] = [
                    f"{func.get('function_name', '?')} -[{boundary_type}]-> [{target_module}]",
                ] + finding.get("path", [])

                if trust_mult > 1.0:
                    finding["score"] = round(min(1.0, finding["score"] * trust_mult), 3)
                    finding["severity"] = severity_label(finding["score"])
                    finding["trust_escalated"] = True

                cross_findings.append(finding)

        if len(callee_tasks) > 1:
            with ThreadPoolExecutor(max_workers=min(len(callee_tasks), 4)) as pool:
                futures = {pool.submit(_trace_one_callee, t): t for t in callee_tasks}
                for fut in as_completed(futures):
                    info, boundary_type, mapped_params, target_db, child_ctx, sub_result = fut.result()
                    _process_callee_result(info, boundary_type, mapped_params, target_db, child_ctx, sub_result)
        else:
            for task in callee_tasks:
                info, boundary_type, mapped_params, target_db, child_ctx, sub_result = _trace_one_callee(task)
                _process_callee_result(info, boundary_type, mapped_params, target_db, child_ctx, sub_result)

    return cross_findings, return_tainted_vars


def trace_forward(
    db_path: str,
    function_name: str | None = None,
    function_id: int | None = None,
    params: list[int] | None = None,
    depth: int = 2,
    json_output: bool = False,
    cross_module: bool = False,
    cross_depth: int = 1,
    no_cache: bool = False,
    taint_context: TaintContext | None = None,
    com_resolve: bool = True,
) -> dict:
    """Run forward taint analysis for the given function and parameters.

    Parameters
    ----------
    cross_module : bool
        When True, resolve external callees to other analyzed modules
        via the tracking DB and recurse the taint trace into them.
    cross_depth : int
        Maximum number of cross-module hops (default 1).
    no_cache : bool
        Skip cache lookup when True.
    taint_context : TaintContext, optional
        Cross-module context that accumulates call stack, guards, and
        trust transitions.  Created automatically by the cross-module
        orchestrator; pass ``None`` for standalone usage.
    com_resolve : bool
        When True (default), resolve COM vtable dispatch calls to
        concrete implementations during cross-module tracing.
    """
    func = get_function(db_path, function_name=function_name, function_id=function_id)
    if not func:
        target = function_name or f"ID={function_id}"
        emit_error(f"Function '{target}' not found in {Path(db_path).name}", ErrorCode.NOT_FOUND)

    cache_params = {
        "fid": func["function_id"],
        "depth": depth,
        "cross": cross_module,
        "cd": cross_depth if cross_module else 0,
    }
    if not no_cache and not cross_module and taint_context is None:
        cached = get_cached(db_path, "taint_forward", params=cache_params)
        if cached is not None:
            return cached

    sig = func.get("function_signature", "") or ""
    code = func.get("decompiled_code", "") or ""

    if params is None:
        params = resolve_tainted_params(None, sig, code)

    all_tainted: set[str] = {param_name_for(p) for p in params}

    all_findings: list[dict] = []
    all_effects: dict[int, list[dict]] = {}
    raw_traces: dict[int, dict] = {}

    def _trace_one_param(pnum: int) -> tuple[int, dict | None]:
        pname = param_name_for(pnum)
        script_args = [db_path]
        if function_id is not None:
            script_args += ["--id", str(func["function_id"])]
        else:
            script_args.append(func["function_name"])
        script_args += ["--param", str(pnum), "--depth", str(depth)]

        result = run_skill_script(
            "data-flow-tracer",
            "forward_trace.py",
            script_args,
            json_output=True,
            timeout=90,
        )

        trace_data = result.get("json_data")
        if not trace_data or not result.get("success"):
            return pnum, None
        return pnum, trace_data

    if len(params) > 1:
        with ThreadPoolExecutor(max_workers=min(len(params), 4)) as pool:
            futures = {pool.submit(_trace_one_param, p): p for p in params}
            for fut in as_completed(futures):
                pnum, trace_data = fut.result()
                if trace_data is None:
                    continue
                raw_traces[pnum] = trace_data
                pname = param_name_for(pnum)
                all_findings.extend(_walk_findings(trace_data, [], func, pname, all_tainted))
                effects = detect_logic_effects(code, pname)
                if effects:
                    all_effects[pnum] = effects
    else:
        for pnum in params:
            pnum, trace_data = _trace_one_param(pnum)
            if trace_data is None:
                continue
            raw_traces[pnum] = trace_data
            pname = param_name_for(pnum)
            all_findings.extend(_walk_findings(trace_data, [], func, pname, all_tainted))
            effects = detect_logic_effects(code, pname)
            if effects:
                all_effects[pnum] = effects

    if cross_module:
        cross_findings, return_vars = _trace_cross_module_callees(
            db_path, func, params, cross_depth, all_tainted,
            taint_context=taint_context,
            raw_traces=raw_traces,
            com_resolve=com_resolve,
        )
        all_findings.extend(cross_findings)

        # Return-value back-propagation: if a cross-module callee returned
        # tainted data, scan the caller for additional sinks reachable from
        # the assignment target variables.
        if return_vars:
            extended_tainted = all_tainted | set(return_vars)
            for rv in return_vars:
                rv_effects = detect_logic_effects(code, rv)
                if rv_effects:
                    all_effects.setdefault(-1, []).extend(rv_effects)
                for pnum_trace, trace_data in raw_traces.items():
                    rv_findings = _walk_findings(
                        trace_data, [], func, rv, extended_tainted,
                    )
                    for f in rv_findings:
                        f["return_taint_origin"] = True
                    all_findings.extend(rv_findings)

        # Accumulate local guards into taint context
        if taint_context is not None and code:
            local_guards = find_guards_between(code, 1, len(code.splitlines()), all_tainted)
            taint_context.add_guards([g.to_dict() for g in local_guards])

    all_findings.sort(key=lambda f: -f["score"])

    output = {
        "status": "ok",
        "function": {
            "function_id": func["function_id"],
            "function_name": func["function_name"],
            "function_signature": func["function_signature"],
            "module_name": func["module_name"],
            "db": Path(db_path).name,
        },
        "tainted_params": params,
        "depth": depth,
        "findings": all_findings,
        "logic_effects": {
            param_name_for(k): v for k, v in all_effects.items()
        },
        "summary": {
            "total_sinks": len(all_findings),
            "critical": sum(1 for f in all_findings if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in all_findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in all_findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in all_findings if f["severity"] == "LOW"),
            "params_with_effects": len(all_effects),
        },
    }

    if cross_module:
        cross_count = sum(
            1 for f in all_findings if f.get("cross_module_source")
        )
        boundary_types = set()
        trust_escalations = 0
        for f in all_findings:
            cms = f.get("cross_module_source", {})
            if cms.get("boundary_type"):
                boundary_types.add(cms["boundary_type"])
            if f.get("trust_escalated"):
                trust_escalations += 1
        output["cross_module"] = {
            "enabled": True,
            "cross_depth": cross_depth,
            "cross_module_findings": cross_count,
            "boundary_types": sorted(boundary_types),
            "trust_escalations": trust_escalations,
            "return_taint_vars": return_vars if return_vars else [],
        }
        if taint_context is not None:
            output["taint_context"] = taint_context.to_dict()

    if not cross_module and taint_context is None:
        cache_result(db_path, "taint_forward", output, params=cache_params)

    return output


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Forward taint propagation: trace tainted parameters to dangerous sinks.",
    )
    parser.add_argument("db_path", help="Path to the module analysis DB")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--function", "--name", dest="function_name", metavar="NAME",
                       help="Function name")
    group.add_argument("--id", "--function-id", type=int, dest="function_id")
    parser.add_argument("function_name_pos", nargs="?", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--params", default=None, help="Comma-separated param numbers (1-based); omit for all")
    parser.add_argument("--depth", type=int, default=2, help="Max recursion depth (default: 2)")
    parser.add_argument("--cross-module", action="store_true",
                        help="Resolve external callees to other analyzed modules and recurse")
    parser.add_argument("--cross-depth", type=int, default=1,
                        help="Max cross-module hops (default: 1)")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--no-cache", action="store_true")
    args = safe_parse_args(parser)
    if args.function_name_pos and not args.function_name:
        args.function_name = args.function_name_pos

    if not args.function_name and args.function_id is None:
        parser.error("Provide a function name or --id")
    if args.function_id is not None:
        args.function_id = validate_function_id(args.function_id)

    db_path = resolve_db_path(args.db_path)
    params = None
    if args.params:
        params = [int(p.strip()) for p in args.params.split(",") if p.strip().isdigit()]

    result = trace_forward(
        db_path=db_path,
        function_name=args.function_name,
        function_id=args.function_id,
        params=params,
        depth=args.depth,
        cross_module=args.cross_module,
        cross_depth=args.cross_depth,
    )

    if args.json:
        emit_json(result)
    else:
        _print_result(result)


def _print_result(result: dict) -> None:
    status = result.get("status", "")

    func = result.get("function", {})
    params = result.get("tainted_params", [])
    pnames = ", ".join(param_name_for(p) for p in params)
    print(f"\n{'=' * 78}")
    print(f"Forward Taint: {func.get('function_name', '?')}")
    print(f"{'=' * 78}")
    print(f"Module: {func.get('module_name', '?')}")
    print(f"Signature: {func.get('function_signature', '?')}")
    print(f"Tainted params: {pnames}")
    print(f"Depth: {result.get('depth', '?')}")

    findings = result.get("findings", [])
    if not findings:
        print("\nNo dangerous sinks reached by tainted data.")
    else:
        print(f"\n--- {len(findings)} Finding(s) ---\n")
        for i, f in enumerate(findings, 1):
            print(f"[{i}] {f['severity']} ({f['score']:.2f}) -- {f['param_name']} reaches {f['sink']} ({f['sink_category']})")
            print(f"    Path: {' -> '.join(f['path'])}")
            if f.get("guards"):
                print(f"    Guards to bypass ({len(f['guards'])}):")
                for g in f["guards"]:
                    ctrl = "YES" if g["attacker_controllable"] else "NO"
                    print(f"      [{g['guard_type'].upper()}] {g['condition']} at L{g['line_number']}  (attacker-controllable: {ctrl}, difficulty: {g['bypass_difficulty']})")
            print()

    effects = result.get("logic_effects", {})
    if effects:
        print("--- Logic Effects ---\n")
        for pname, elist in effects.items():
            for e in elist:
                print(f"  {pname}: {e['type'].upper()} at L{e['line']} -- {e['text'][:100]}")
        print()

    summary = result.get("summary", {})
    print(f"Summary: {summary.get('total_sinks', 0)} sinks | "
          f"CRITICAL={summary.get('critical', 0)} HIGH={summary.get('high', 0)} "
          f"MEDIUM={summary.get('medium', 0)} LOW={summary.get('low', 0)} | "
          f"{summary.get('params_with_effects', 0)} params with logic effects")


if __name__ == "__main__":
    main()
