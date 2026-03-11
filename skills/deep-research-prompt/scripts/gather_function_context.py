#!/usr/bin/env python3
"""Gather comprehensive context for a single function from analysis DBs.

Extracts classification, call graph, data flow, strings, COM patterns,
dispatch tables, and cross-module resolution into a single context bundle
for research prompt generation.

Usage:
    python gather_function_context.py <db_path> <function_name>
    python gather_function_context.py <db_path> --id <function_id>
    python gather_function_context.py <db_path> <function_name> --cross-module --depth 3
    python gather_function_context.py <db_path> <function_name> --with-code --json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

from _common import (
    WORKSPACE_ROOT,
    categorize_string_full,
    categorize_strings,
    classify_api,
    classify_function,
    emit_error,
    is_callable_xref,
    is_external_xref,
    is_internal_xref,
    parse_json_safe,
    resolve_db_path,
    resolve_tracking_db,
    truncate,
)

from helpers import (
    load_function_index_for_db,
    open_analyzed_files_db,
    open_individual_analysis_db,
    resolve_function,
)
from helpers.cache import get_cached, cache_result
from helpers.errors import db_error_handler, safe_parse_args
from helpers.errors import ErrorCode  # noqa: E402
from helpers.json_output import emit_json


# ---------------------------------------------------------------------------
# Context gathering
# ---------------------------------------------------------------------------

def gather_function_identity(func) -> dict:
    """Extract function identity fields."""
    return {
        "function_name": func.function_name or "",
        "function_id": func.function_id,
        "function_signature": func.function_signature or "",
        "function_signature_extended": func.function_signature_extended or "",
        "mangled_name": func.mangled_name or "",
    }


def gather_classification(func) -> dict:
    """Classify the function using the classify-functions skill."""
    if classify_function is None:
        return {"primary_category": "unknown", "interest_score": 0, "error": "classify-functions skill not available"}

    result = classify_function(func)
    return {
        "primary_category": result.primary_category,
        "secondary_categories": result.secondary_categories,
        "interest_score": result.interest_score,
        "scores": {k: round(v, 1) for k, v in result.scores.items() if v > 0},
        "signals": {k: v for k, v in result.signals.items() if v},
        "asm_metrics": {
            "instruction_count": result.asm_metrics.instruction_count if result.asm_metrics else 0,
            "call_count": result.asm_metrics.call_count if result.asm_metrics else 0,
            "branch_count": result.asm_metrics.branch_count if result.asm_metrics else 0,
            "is_leaf": result.asm_metrics.is_leaf if result.asm_metrics else True,
            "is_tiny": result.asm_metrics.is_tiny if result.asm_metrics else True,
            "has_syscall": result.asm_metrics.has_syscall if result.asm_metrics else False,
        },
        "loop_count": result.loop_count,
        "has_decompiled": result.has_decompiled,
        "api_count": result.api_count,
        "string_count": result.string_count,
        "dangerous_api_count": result.dangerous_api_count,
    }


def gather_call_graph(func, db, depth: int = 3) -> dict:
    """Extract call graph information from outbound/inbound xrefs."""
    outbound = parse_json_safe(func.simple_outbound_xrefs) or []
    inbound = parse_json_safe(func.simple_inbound_xrefs) or []

    internal_callees = []
    external_callees = []
    api_by_category = defaultdict(list)

    for xref in outbound:
        if not isinstance(xref, dict):
            continue
        if not is_callable_xref(xref):
            continue

        api_name = xref.get("function_name", "?")
        module = xref.get("module_name", "")
        fid = xref.get("function_id")

        # Classify the API
        cat = classify_api(api_name)
        if cat:
            api_by_category[cat].append(api_name)

        if is_internal_xref(xref):
            internal_callees.append({
                "name": api_name,
                "id": fid,
                "category": cat or "uncategorized",
            })
        elif is_external_xref(xref):
            external_callees.append({
                "name": api_name,
                "module": module,
                "category": cat or "uncategorized",
            })

    # Callers
    callers = []
    for xref in inbound:
        if not isinstance(xref, dict):
            continue
        if not is_callable_xref(xref):
            continue
        callers.append({
            "name": xref.get("function_name", "?"),
            "id": xref.get("function_id"),
            "module": xref.get("module_name", ""),
        })

    # Build a simple reachability estimate using internal callees recursively
    reachable_ids = set()
    _collect_reachable(db, func.function_id, depth, reachable_ids, set())

    return {
        "internal_callees": internal_callees,
        "external_callees": external_callees,
        "callers": callers,
        "api_by_category": dict(api_by_category),
        "reachable_count": len(reachable_ids),
        "max_depth": depth,
        "internal_callee_count": len(internal_callees),
        "external_callee_count": len(external_callees),
        "caller_count": len(callers),
    }


def _collect_reachable(db, func_id: int, max_depth: int, visited: set, stack: set):
    """BFS to collect reachable internal function IDs with batch fetching."""
    from collections import deque

    if func_id in visited or max_depth <= 0:
        return

    queue: deque[tuple[int, int]] = deque([(func_id, max_depth)])
    visited.add(func_id)

    while queue:
        current_id, remaining_depth = queue.popleft()
        if remaining_depth <= 0:
            continue

        func = db.get_function_by_id(current_id)
        if func is None:
            continue

        outbound = parse_json_safe(func.simple_outbound_xrefs) or []
        candidate_ids: list[int] = []
        for xref in outbound:
            if not isinstance(xref, dict):
                continue
            callee_id = xref.get("function_id")
            if callee_id is not None and is_callable_xref(xref) and callee_id not in visited:
                candidate_ids.append(callee_id)
                visited.add(callee_id)

        if candidate_ids:
            # Batch-fetch to validate existence, then enqueue
            fetched_ids = {f.function_id for f in db.get_functions_by_ids(candidate_ids)}
            for cid in candidate_ids:
                if cid in fetched_ids:
                    queue.append((cid, remaining_depth - 1))


def gather_cross_module(external_callees: list[dict]) -> list[dict]:
    """Resolve external callees to analyzed module DBs."""
    tracking_db_path = resolve_tracking_db()
    if not tracking_db_path:
        return [dict(c, resolvable=False, target_db=None) for c in external_callees]

    resolved = []
    try:
        with open_analyzed_files_db(tracking_db_path) as tracking_db:
            for callee in external_callees:
                module_name = callee.get("module", "")
                if not module_name or module_name in ("internal", "static_library", "data", "vtable"):
                    resolved.append(dict(callee, resolvable=False, target_db=None))
                    continue

                # Search for the module in the tracking DB
                records = tracking_db.get_by_file_name(module_name)
                if records:
                    r = records[0]
                    if r.status == "COMPLETE" and r.analysis_db_path:
                        abs_path = WORKSPACE_ROOT / r.analysis_db_path
                        resolved.append(dict(callee, resolvable=True, target_db=str(abs_path)))
                    else:
                        resolved.append(dict(callee, resolvable=False, target_db=None))
                else:
                    resolved.append(dict(callee, resolvable=False, target_db=None))
    except Exception:
        return [dict(c, resolvable=False, target_db=None) for c in external_callees]

    return resolved


def gather_data_flow(func) -> dict:
    """Extract data flow summary: parameter usage, global state, return patterns."""
    outbound = parse_json_safe(func.simple_outbound_xrefs) or []
    globals_accessed = parse_json_safe(func.global_var_accesses) or []

    # Map API calls from outbound
    api_calls = []
    for xref in outbound:
        if not isinstance(xref, dict) or not is_callable_xref(xref):
            continue
        api_calls.append(xref.get("function_name", "?"))

    # Global state
    globals_list = []
    if isinstance(globals_accessed, list):
        for g in globals_accessed:
            if isinstance(g, dict):
                globals_list.append({
                    "name": g.get("name", "?"),
                    "address": g.get("address", "?"),
                    "access_type": g.get("access_type", "?"),
                })

    return {
        "api_calls": api_calls,
        "globals_accessed": globals_list,
        "global_read_count": sum(1 for g in globals_list if g["access_type"] == "Read"),
        "global_write_count": sum(1 for g in globals_list if g["access_type"] == "Write"),
    }


def gather_strings(func) -> dict:
    """Extract and categorize string literals with security descriptions."""
    strings = parse_json_safe(func.string_literals) or []
    if not isinstance(strings, list):
        strings = []

    valid_strings = [s for s in strings if isinstance(s, str) and s.strip()]
    categorized = categorize_strings(valid_strings)

    security_strings: list[dict] = []
    for s in valid_strings:
        result = categorize_string_full(s)
        if result is not None:
            cat, desc = result
            if cat not in ("other", "error_message", "debug_trace"):
                security_strings.append({"string": s, "category": cat, "description": desc})

    security_strings.sort(key=lambda x: x["category"])

    return {
        "categorized": categorized,
        "security_relevant": security_strings[:30],
        "security_relevant_count": len(security_strings),
        "total_count": len(valid_strings),
        "all_strings": valid_strings[:50],
    }


def gather_dangerous_apis(func) -> list[str]:
    """Extract dangerous API calls."""
    dangerous = parse_json_safe(func.dangerous_api_calls) or []
    if isinstance(dangerous, list):
        return [str(d) for d in dangerous if isinstance(d, str)]
    return []


def gather_patterns(func) -> dict:
    """Detect dispatch tables, state machines, COM interfaces."""
    decompiled = func.decompiled_code or ""
    vtable_contexts = parse_json_safe(func.vtable_contexts) or []

    # Dispatch/switch detection
    has_switch = "switch" in decompiled.lower() if decompiled else False
    switch_count = decompiled.lower().count("case ") if decompiled else 0

    # COM detection from vtable contexts and function name
    has_com = False
    com_interfaces = []
    if isinstance(vtable_contexts, list) and vtable_contexts:
        has_com = True
        for ctx in vtable_contexts:
            if isinstance(ctx, dict):
                classes = ctx.get("reconstructed_classes", [])
                if isinstance(classes, list):
                    com_interfaces.extend(classes)

    # Also check function name for COM patterns
    fname = func.function_name or ""
    mangled = func.mangled_name or ""
    if "QueryInterface" in fname or "AddRef" in fname or "Release" in fname:
        has_com = True
    if "RuntimeClassImpl" in mangled or "ComPtr" in mangled:
        has_com = True

    # Loop-based state machine hint
    loop_analysis = parse_json_safe(func.loop_analysis)
    has_loops = False
    if isinstance(loop_analysis, dict):
        loop_count = loop_analysis.get("loop_count", 0) or 0
        has_loops = loop_count > 0

    has_state_machine = has_switch and has_loops

    return {
        "has_dispatch_table": has_switch and switch_count >= 3,
        "dispatch_case_count": switch_count,
        "has_state_machine": has_state_machine,
        "has_com_interfaces": has_com,
        "com_interfaces": com_interfaces[:10],
        "has_vtable_contexts": bool(vtable_contexts),
    }


def gather_module_info(db) -> dict:
    """Extract module-level metadata."""
    try:
        fi = db.get_file_info()
        if fi is None:
            return {}
        return {
            "file_name": fi.file_name or "",
            "file_description": fi.file_description or "",
            "company_name": fi.company_name or "",
            "file_version": fi.file_version or "",
            "product_name": fi.product_name or "",
            "internal_name": fi.internal_name or "",
        }
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def gather_full_context(
    db_path: str,
    func,
    db,
    depth: int = 3,
    cross_module: bool = False,
    with_code: bool = False,
    with_taint: bool = False,
) -> dict:
    """Gather full context for a function.

    Returns a dict with all gathered data, suitable for JSON serialization
    or direct use by generate_research_prompt.py.
    """
    context = {
        "db_path": db_path,
        "target": gather_function_identity(func),
        "module": gather_module_info(db),
        "classification": gather_classification(func),
        "call_graph": gather_call_graph(func, db, depth),
        "data_flow": gather_data_flow(func),
        "strings": gather_strings(func),
        "dangerous_apis": gather_dangerous_apis(func),
        "patterns": gather_patterns(func),
    }

    # Cross-module resolution
    if cross_module:
        external = context["call_graph"]["external_callees"]
        context["cross_module"] = gather_cross_module(external)
        context["cross_module_summary"] = {
            "total_external": len(external),
            "resolvable": sum(1 for c in context["cross_module"] if c.get("resolvable")),
            "unresolvable": sum(1 for c in context["cross_module"] if not c.get("resolvable")),
        }

    if with_taint:
        try:
            from helpers.script_runner import run_skill_script
            fid = func.function_id
            taint_result = run_skill_script(
                "taint-analysis", "taint_function.py",
                [db_path, "--id", str(fid), "--depth", "2", "--json"],
                json_output=True, timeout=120,
            )
            taint_data = taint_result.get("json_data", {})
            if taint_data and taint_data.get("status") == "ok":
                findings = taint_data.get("forward_findings", taint_data.get("findings", []))
                context["taint"] = {
                    "total_sinks": len(findings),
                    "critical": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
                    "high": sum(1 for f in findings if f.get("severity") == "HIGH"),
                    "top_findings": findings[:5],
                }
        except Exception:
            pass

    # Include decompiled code and assembly excerpt
    if with_code:
        context["decompiled_code"] = func.decompiled_code or "(not available)"
        asm = func.assembly_code or ""
        # Truncate assembly to first 200 lines for prompt context
        asm_lines = asm.splitlines()
        if len(asm_lines) > 200:
            context["assembly_excerpt"] = "\n".join(asm_lines[:200]) + f"\n... ({len(asm_lines) - 200} more lines)"
        else:
            context["assembly_excerpt"] = asm

    return context


# ---------------------------------------------------------------------------
# Formatted text output
# ---------------------------------------------------------------------------

def print_context(context: dict) -> None:
    """Print gathered context in human-readable format."""
    target = context["target"]
    module = context.get("module", {})
    cls = context["classification"]
    cg = context["call_graph"]
    df = context["data_flow"]
    strings = context["strings"]
    dangerous = context["dangerous_apis"]
    patterns = context["patterns"]

    def _header(title: str):
        print(f"\n{'=' * 70}")
        print(f"  {title}")
        print(f"{'=' * 70}")

    print(f"{'#' * 70}")
    print(f"  DEEP FUNCTION CONTEXT: {target['function_name']}")
    print(f"  Module: {module.get('file_name', '?')} ({module.get('file_description', '')})")
    print(f"  DB: {context['db_path']}")
    print(f"{'#' * 70}")

    # Identity
    _header("1. FUNCTION IDENTITY")
    print(f"  Name:       {target['function_name']}")
    print(f"  ID:         {target['function_id']}")
    print(f"  Signature:  {target['function_signature']}")
    if target['function_signature_extended'] and target['function_signature_extended'] != target['function_signature']:
        print(f"  Extended:   {target['function_signature_extended']}")
    print(f"  Mangled:    {target['mangled_name']}")

    # Classification
    _header("2. CLASSIFICATION")
    print(f"  Category:     {cls['primary_category']}")
    if cls.get('secondary_categories'):
        print(f"  Secondary:    {', '.join(cls['secondary_categories'])}")
    print(f"  Interest:     {cls['interest_score']}/10")
    asm_m = cls.get("asm_metrics", {})
    print(f"  Assembly:     {asm_m.get('instruction_count', 0)} instr, {asm_m.get('call_count', 0)} calls, {asm_m.get('branch_count', 0)} branches")
    print(f"  Loops:        {cls.get('loop_count', 0)}")
    print(f"  APIs called:  {cls.get('api_count', 0)}")
    print(f"  Strings:      {cls.get('string_count', 0)}")
    print(f"  Dangerous:    {cls.get('dangerous_api_count', 0)}")

    if cls.get("signals"):
        print("\n  Classification signals:")
        for cat, sigs in sorted(cls["signals"].items()):
            if sigs:
                for sig in sigs:
                    print(f"    [{cat}] {sig}")

    # Call graph
    _header("3. CALL GRAPH")
    print(f"  Internal callees:  {cg['internal_callee_count']}")
    print(f"  External callees:  {cg['external_callee_count']}")
    print(f"  Callers:           {cg['caller_count']}")
    print(f"  Reachable (depth {cg['max_depth']}): {cg['reachable_count']} functions")

    if cg["internal_callees"]:
        print("\n  Internal callees:")
        for c in cg["internal_callees"][:20]:
            print(f"    -> {c['name']} [{c['category']}] (ID={c['id']})")
        if len(cg["internal_callees"]) > 20:
            print(f"    ... and {len(cg['internal_callees']) - 20} more")

    if cg["external_callees"]:
        print("\n  External callees:")
        for c in cg["external_callees"][:20]:
            print(f"    -> {c['name']} [{c['category']}] (module: {c['module']})")
        if len(cg["external_callees"]) > 20:
            print(f"    ... and {len(cg['external_callees']) - 20} more")

    if cg.get("api_by_category"):
        print("\n  API calls by category:")
        for cat, apis in sorted(cg["api_by_category"].items(), key=lambda x: -len(x[1])):
            print(f"    {cat}: {', '.join(apis[:5])}{' ...' if len(apis) > 5 else ''}")

    if cg["callers"]:
        print("\n  Called by:")
        for c in cg["callers"][:10]:
            src = f" (module: {c['module']})" if c.get("module") else ""
            print(f"    <- {c['name']}{src}")

    # Cross-module resolution
    if "cross_module" in context:
        _header("4. CROSS-MODULE RESOLUTION")
        summary = context.get("cross_module_summary", {})
        print(f"  Total external calls:  {summary.get('total_external', 0)}")
        print(f"  Resolvable:            {summary.get('resolvable', 0)}")
        print(f"  Unresolvable:          {summary.get('unresolvable', 0)}")

        resolvable = [c for c in context["cross_module"] if c.get("resolvable")]
        if resolvable:
            print("\n  Resolvable external calls:")
            for c in resolvable:
                print(f"    -> {c['name']} (module: {c['module']}) => DB: {c['target_db']}")

        unresolvable = [c for c in context["cross_module"] if not c.get("resolvable")]
        if unresolvable:
            print("\n  Unresolvable external calls (module not analyzed):")
            modules = sorted(set(c["module"] for c in unresolvable if c.get("module")))
            for m in modules:
                funcs = [c["name"] for c in unresolvable if c.get("module") == m]
                print(f"    {m}: {', '.join(funcs[:5])}{' ...' if len(funcs) > 5 else ''}")

    # Data flow
    section_num = 5 if "cross_module" in context else 4
    _header(f"{section_num}. DATA FLOW")
    print(f"  Global reads:   {df['global_read_count']}")
    print(f"  Global writes:  {df['global_write_count']}")
    if df["globals_accessed"]:
        print("\n  Global variables accessed:")
        for g in df["globals_accessed"][:15]:
            print(f"    {g['access_type']:>5}  {g['name']} @ {g['address']}")

    # Strings
    section_num += 1
    _header(f"{section_num}. STRING INTELLIGENCE ({strings['total_count']} strings)")
    if strings["categorized"]:
        for cat, items in sorted(strings["categorized"].items()):
            print(f"\n  [{cat}] ({len(items)} strings)")
            for s in items[:5]:
                print(f"    \"{truncate(s, 100)}\"")
            if len(items) > 5:
                print(f"    ... and {len(items) - 5} more")

    # Dangerous APIs
    if dangerous:
        section_num += 1
        _header(f"{section_num}. DANGEROUS APIs ({len(dangerous)})")
        for api in dangerous:
            print(f"    ! {api}")

    # Patterns
    section_num += 1
    _header(f"{section_num}. STRUCTURAL PATTERNS")
    if patterns["has_dispatch_table"]:
        print(f"  Dispatch table: YES ({patterns['dispatch_case_count']} cases)")
    if patterns["has_state_machine"]:
        print(f"  State machine:  YES (dispatch inside loop)")
    if patterns["has_com_interfaces"]:
        print(f"  COM interfaces: YES")
        for iface in patterns["com_interfaces"][:5]:
            iface_str = str(iface)
            print(f"    {truncate(iface_str, 100)}")
    if patterns["has_vtable_contexts"]:
        print(f"  VTable contexts present: YES")
    if not any([patterns["has_dispatch_table"], patterns["has_state_machine"],
                patterns["has_com_interfaces"], patterns["has_vtable_contexts"]]):
        print("  No special structural patterns detected.")

    # Decompiled code
    if "decompiled_code" in context:
        section_num += 1
        _header(f"{section_num}. DECOMPILED CODE")
        code = context["decompiled_code"]
        lines = code.splitlines()
        if len(lines) > 100:
            for line in lines[:100]:
                print(f"  {line}")
            print(f"  ... ({len(lines) - 100} more lines)")
        else:
            for line in lines:
                print(f"  {line}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Gather comprehensive context for a function from analysis DBs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("db_path", help="Path to the individual analysis DB")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--function", "--name", dest="function_name", metavar="NAME",
                       help="Function name to analyze")
    group.add_argument("--id", "--function-id", type=int, dest="function_id", help="Function ID")
    parser.add_argument("function_name_pos", nargs="?", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--depth", type=int, default=3, help="Call graph depth (default: 3)")
    parser.add_argument("--cross-module", action="store_true", help="Resolve external calls to analyzed modules")
    parser.add_argument("--with-code", action="store_true", help="Include decompiled code in output")
    parser.add_argument("--with-taint", action="store_true", help="Include taint analysis results for security-focused research")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = safe_parse_args(parser)
    if args.function_name_pos and not args.function_name:
        args.function_name = args.function_name_pos

    db_path = resolve_db_path(args.db_path)
    function_index = load_function_index_for_db(db_path)

    with db_error_handler(db_path, "gathering function context"):
        with open_individual_analysis_db(db_path) as db:
            if not args.function_name and args.function_id is None:
                emit_error("Provide a function name or --id", ErrorCode.INVALID_ARGS)

            func, err = resolve_function(
                db,
                name=args.function_name,
                function_id=args.function_id,
                function_index=function_index,
            )
            if err:
                if "Multiple matches" in err:
                    print(err)
                    return
                emit_error(f"[{Path(db_path).stem}] {err}", ErrorCode.NOT_FOUND)

            cache_params = {"fid": func.function_id, "depth": args.depth, "xmod": args.cross_module, "code": args.with_code, "taint": args.with_taint}
            cached = get_cached(db_path, "gather_function_context", params=cache_params)
            if cached is not None:
                context = cached
            else:
                context = gather_full_context(
                    db_path=db_path,
                    func=func,
                    db=db,
                    depth=args.depth,
                    cross_module=args.cross_module,
                    with_code=args.with_code,
                    with_taint=args.with_taint,
                )
                cache_result(db_path, "gather_function_context", context, params=cache_params)

    if args.json:
        emit_json(context, ensure_ascii=True, default=str)
    else:
        print_context(context)


if __name__ == "__main__":
    main()
