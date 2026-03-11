#!/usr/bin/env python3
"""Extract the dispatch table (case -> handler mapping) from a function.

Combines decompiled switch/case parsing, if-chain detection, and jump table
target resolution from outbound xrefs to build a unified dispatch table.

Usage:
    python extract_dispatch_table.py <db_path> <function_name>
    python extract_dispatch_table.py <db_path> --id <function_id>
    python extract_dispatch_table.py <db_path> --search <pattern>
    python extract_dispatch_table.py <db_path> <function_name> --json

Examples:
    python .agent/skills/state-machine-extractor/scripts/extract_dispatch_table.py extracted_dbs/cmd_exe_6d109a3a00.db Dispatch
    python .agent/skills/state-machine-extractor/scripts/extract_dispatch_table.py extracted_dbs/cmd_exe_6d109a3a00.db --id 42 --json
    python .agent/skills/state-machine-extractor/scripts/extract_dispatch_table.py extracted_dbs/cmd_exe_6d109a3a00.db --search "Dispatch"

Output:
    Full dispatch table with case values mapped to handler functions, including
    source (switch/if-chain/jump-table), string labels, and confidence.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from _common import (
    CaseEntry,
    DispatchTable,
    WORKSPACE_ROOT,
    classify_outbound_xrefs,
    detect_asm_switch_patterns,
    emit_error,
    extract_case_handlers,
    extract_jump_table_targets,
    format_int,
    parse_if_chain,
    parse_json_safe,
    parse_string_compare_chain,
    parse_switch_cases,
    resolve_db_path,
    RE_FUNCTION_CALL,
)

from helpers import (
    FunctionRecord,
    load_function_index_for_db,
    open_individual_analysis_db,
    resolve_function,
    search_functions_by_pattern,
    validate_function_id,
)
from helpers.cache import get_cached, cache_result
from helpers.errors import emit_error, ErrorCode, db_error_handler, safe_parse_args
from helpers.json_output import emit_json, emit_json_list


def build_dispatch_table(func: FunctionRecord, db) -> list[DispatchTable]:
    """Build dispatch table(s) from a function's decompiled code and xrefs.

    Returns a list of DispatchTable objects (one per switch/if-chain found).
    """
    tables = []
    decompiled = func.decompiled_code or ""
    func_name = func.function_name or f"sub_{func.function_id}"

    # Gather string literals for label mapping
    strings = parse_json_safe(func.string_literals) or []
    string_set = set(strings) if isinstance(strings, list) else set()

    # Get outbound xrefs for handler resolution
    simple_xrefs = parse_json_safe(func.simple_outbound_xrefs) or []
    detailed_xrefs = parse_json_safe(func.outbound_xrefs) or []

    # Build a name -> xref map for handler resolution
    xref_by_name: dict[str, dict] = {}
    for xref in simple_xrefs:
        fname = xref.get("function_name")
        if fname:
            xref_by_name[fname] = xref

    # 1. Parse switch/case statements
    switches = parse_switch_cases(decompiled)
    for sw in switches:
        table = DispatchTable(
            function_name=func_name,
            function_id=func.function_id,
            switch_variable=sw["switch_variable"],
            has_default=sw["has_default"],
            source_type="switch",
            total_cases=len(sw["cases"]),
        )

        # Extract handler calls per case
        case_handlers = extract_case_handlers(sw["body_text"])

        for case_val in sw["cases"]:
            entry = CaseEntry(
                case_value=case_val,
                case_value_hex=format_int(case_val),
                source="decompiled",
            )

            # Map case to handler function
            handlers = case_handlers.get(case_val, [])
            if handlers:
                # Use the first non-trivial call as the handler
                primary = _pick_primary_handler(handlers, xref_by_name)
                if primary:
                    entry.handler_name = primary
                    xref = xref_by_name.get(primary, {})
                    entry.handler_id = xref.get("function_id")
                    entry.is_internal = xref.get("function_id") is not None
                    entry.handler_module = xref.get("module_name")

            # Try to find a string label for this case value
            label = _find_label_for_case(case_val, strings, decompiled, sw["body_text"])
            if label:
                entry.label = label
                table.string_labels[case_val] = label

            table.cases.append(entry)

        tables.append(table)

    # 2. Parse if-else chains (only if no switch found for the same variable)
    switch_vars = {sw["switch_variable"] for sw in switches}
    if_chains = parse_if_chain(decompiled, min_branches=3)
    for chain in if_chains:
        if chain["variable"] in switch_vars:
            continue  # Already covered by switch

        table = DispatchTable(
            function_name=func_name,
            function_id=func.function_id,
            switch_variable=chain["variable"],
            source_type="if_chain",
            total_cases=len(chain["comparisons"]),
        )

        for comp in chain["comparisons"]:
            case_val = comp["value"]
            entry = CaseEntry(
                case_value=case_val,
                case_value_hex=format_int(case_val),
                source="if_chain",
                confidence=80.0,
            )

            # Try to find the handler in the if block following this comparison
            pos = comp["start_pos"]
            # Get the block after the if condition
            block_end = decompiled.find("\n}", pos)
            if block_end == -1:
                block_end = min(pos + 500, len(decompiled))
            block = decompiled[pos:block_end]

            calls = []
            for call_match in RE_FUNCTION_CALL.finditer(block):
                fname = call_match.group(1)
                if fname in xref_by_name:
                    calls.append(fname)

            primary = _pick_primary_handler(calls, xref_by_name) if calls else None
            if primary:
                entry.handler_name = primary
                xref = xref_by_name.get(primary, {})
                entry.handler_id = xref.get("function_id")
                entry.is_internal = xref.get("function_id") is not None
                entry.handler_module = xref.get("module_name")

            # Label
            label = _find_label_for_case(case_val, strings, decompiled, block)
            if label:
                entry.label = label
                table.string_labels[case_val] = label

            table.cases.append(entry)

        tables.append(table)

    # 2b. Parse string-compare dispatch chains
    str_chains = parse_string_compare_chain(decompiled, min_branches=3)
    for chain in str_chains:
        table = DispatchTable(
            function_name=func_name,
            function_id=func.function_id,
            switch_variable=chain["variable"],
            source_type="string_compare",
            total_cases=len(chain["keywords"]),
            has_default=True,  # string-compare chains always have an implicit fallthrough
        )

        for ordinal, kw_info in enumerate(chain["keywords"]):
            keyword = kw_info["keyword"]
            entry = CaseEntry(
                case_value=ordinal,
                case_value_hex=keyword,
                case_label=keyword,
                label=keyword,
                source="string_compare",
                confidence=90.0,
            )

            pos = kw_info["start_pos"]
            block_end = decompiled.find("\n}", pos)
            if block_end == -1:
                block_end = min(pos + 500, len(decompiled))
            block = decompiled[pos:block_end]

            calls = []
            for call_match in RE_FUNCTION_CALL.finditer(block):
                fname = call_match.group(1)
                if fname in xref_by_name:
                    calls.append(fname)

            primary = _pick_primary_handler(calls, xref_by_name) if calls else None
            if primary:
                entry.handler_name = primary
                xref = xref_by_name.get(primary, {})
                entry.handler_id = xref.get("function_id")
                entry.is_internal = xref.get("function_id") is not None
                entry.handler_module = xref.get("module_name")

            table.string_labels[ordinal] = keyword
            table.cases.append(entry)

        tables.append(table)

    # 3. Jump table targets (if no switch/if-chain/string-compare found)
    if not tables and detailed_xrefs:
        jt_targets = extract_jump_table_targets(detailed_xrefs)
        if jt_targets:
            table = DispatchTable(
                function_name=func_name,
                function_id=func.function_id,
                source_type="jump_table",
                total_cases=len(jt_targets),
            )

            for i, target in enumerate(jt_targets):
                entry = CaseEntry(
                    case_value=i,
                    case_value_hex=format_int(i),
                    handler_name=target["function_name"],
                    source="jump_table",
                    confidence=target.get("confidence", 50.0),
                )

                # Resolve handler info
                if target["function_name"] and target["function_name"] in xref_by_name:
                    xref = xref_by_name[target["function_name"]]
                    entry.handler_id = xref.get("function_id")
                    entry.is_internal = xref.get("function_id") is not None
                    entry.handler_module = xref.get("module_name")

                table.cases.append(entry)

            tables.append(table)

    return tables


def _pick_primary_handler(calls: list[str], xref_map: dict[str, dict]) -> Optional[str]:
    """Pick the most likely handler from a list of function calls.

    Prefers internal functions over APIs, named functions over sub_ names.
    """
    if not calls:
        return None

    # Rank: internal named > internal sub_ > external
    scored = []
    for name in calls:
        xref = xref_map.get(name, {})
        fid = xref.get("function_id")
        ftype = xref.get("function_type", 0)
        is_internal = fid is not None
        is_named = not name.startswith("sub_")
        score = 0
        if is_internal and is_named:
            score = 3
        elif is_internal:
            score = 2
        elif is_named and ftype != 4:  # not data
            score = 1
        scored.append((score, name))

    scored.sort(key=lambda x: x[0], reverse=True)
    return scored[0][1] if scored else calls[0]


def _find_label_for_case(
    case_val: int,
    string_list: list,
    full_code: str,
    case_block: str,
) -> Optional[str]:
    """Try to find a string label associated with a case value.

    Checks for string literals near the case in the decompiled code.
    """
    if not isinstance(string_list, list):
        return None

    # Look for string references in the case block
    for s in string_list:
        if not isinstance(s, str) or len(s) < 2 or len(s) > 200:
            continue
        # Check if string appears in the case block text
        if s in case_block:
            return s

    return None


def _tables_to_cacheable(tables: list[DispatchTable]) -> list[dict]:
    """Serialize DispatchTable list to JSON-safe dicts for caching."""
    output = []
    for table in tables:
        t = {
            "function_name": table.function_name,
            "function_id": table.function_id,
            "switch_variable": table.switch_variable,
            "source_type": table.source_type,
            "total_cases": table.total_cases,
            "has_default": table.has_default,
            "default_handler": table.default_handler,
            "cases": [
                {
                    "case_value": c.case_value,
                    "case_value_hex": c.case_value_hex,
                    "handler_name": c.handler_name,
                    "handler_id": c.handler_id,
                    "is_internal": c.is_internal,
                    "handler_module": c.handler_module,
                    "label": c.label,
                    "case_label": c.case_label,
                    "source": c.source,
                    "confidence": c.confidence,
                }
                for c in table.cases
            ],
            "string_labels": {str(k): v for k, v in table.string_labels.items()},
        }
        output.append(t)
    return output


def _table_from_cached(d: dict) -> DispatchTable:
    """Reconstruct a DispatchTable from a cached dict."""
    table = DispatchTable(
        function_name=d["function_name"],
        function_id=d["function_id"],
        switch_variable=d.get("switch_variable"),
        has_default=d.get("has_default", False),
        default_handler=d.get("default_handler"),
        total_cases=d.get("total_cases", 0),
        source_type=d.get("source_type", "switch"),
        string_labels={int(k): v for k, v in d.get("string_labels", {}).items()},
    )
    for c in d.get("cases", []):
        table.cases.append(CaseEntry(
            case_value=c["case_value"],
            case_value_hex=c.get("case_value_hex", ""),
            handler_name=c.get("handler_name"),
            handler_id=c.get("handler_id"),
            is_internal=c.get("is_internal", False),
            handler_module=c.get("handler_module"),
            label=c.get("label"),
            case_label=c.get("case_label"),
            source=c.get("source", "decompiled"),
            confidence=c.get("confidence", 100.0),
        ))
    return table


def print_dispatch_table(tables: list[DispatchTable], func: FunctionRecord, as_json: bool = False) -> None:
    if as_json:
        output = []
        for table in tables:
            t = {
                "function_name": table.function_name,
                "function_id": table.function_id,
                "switch_variable": table.switch_variable,
                "source_type": table.source_type,
                "total_cases": table.total_cases,
                "has_default": table.has_default,
                "cases": [
                    {
                        "case_value": c.case_value,
                        "case_value_hex": c.case_value_hex,
                        "handler_name": c.handler_name,
                        "handler_id": c.handler_id,
                        "is_internal": c.is_internal,
                        "handler_module": c.handler_module,
                        "label": c.label,
                        "case_label": c.case_label,
                        "source": c.source,
                        "confidence": c.confidence,
                    }
                    for c in table.cases
                ],
                "string_labels": table.string_labels,
            }
            output.append(t)
        emit_json_list("tables", output)
        return

    if not tables:
        print(f"No dispatch tables found in {func.function_name or func.function_id}.")
        return

    func_name = func.function_name or f"sub_{func.function_id}"
    sig = func.function_signature or ""

    print(f"\n{'#' * 80}")
    print(f"  DISPATCH TABLE EXTRACTION")
    print(f"  Function: {func_name}")
    print(f"  ID: {func.function_id}")
    if sig:
        print(f"  Signature: {sig}")
    print(f"  Tables found: {len(tables)}")
    print(f"{'#' * 80}")

    for i, table in enumerate(tables):
        print(f"\n{'=' * 80}")
        header = f"  Table {i + 1}: "
        if table.source_type == "string_compare":
            header += f"str-cmp({table.switch_variable})"
        elif table.switch_variable:
            header += f"switch({table.switch_variable})"
        else:
            header += f"{table.source_type}"
        header += f"  [{table.total_cases} cases"
        if table.has_default:
            header += " + default"
        header += "]"
        print(header)
        print(f"  Source: {table.source_type}")
        print(f"{'=' * 80}\n")

        is_str_cmp = table.source_type == "string_compare"
        case_col = "Keyword" if is_str_cmp else "Case"
        print(f"  {case_col:>20}  {'Handler':<40}  {'ID':>6}  {'Int':>3}  {'Label'}")
        print(f"  {'-' * 20}  {'-' * 40}  {'-' * 6}  {'-' * 3}  {'-' * 30}")

        for case in table.cases:
            handler = case.handler_name or "(unknown)"
            if len(handler) > 40:
                handler = handler[:37] + "..."
            hid = str(case.handler_id) if case.handler_id is not None else "-"
            internal = "Y" if case.is_internal else "N"
            label = case.label or ""
            if len(label) > 30:
                label = label[:27] + "..."
            case_display = f'"{case.case_label}"' if case.case_label else case.case_value_hex
            if len(case_display) > 20:
                case_display = case_display[:17] + "..."
            print(f"  {case_display:>20}  {handler:<40}  {hid:>6}  {internal:>3}  {label}")

        if table.has_default:
            dh = table.default_handler or "(fallthrough)"
            print(f"  {'default':>10}  {dh:<40}")

    # Summary
    total = sum(t.total_cases for t in tables)
    resolved = sum(1 for t in tables for c in t.cases if c.handler_name)
    labeled = sum(1 for t in tables for c in t.cases if c.label)
    internal = sum(1 for t in tables for c in t.cases if c.is_internal)

    print(f"\n{'=' * 80}")
    print(f"  Summary:")
    print(f"    Total cases:     {total}")
    print(f"    Handlers found:  {resolved} ({resolved * 100 // max(total, 1)}%)")
    print(f"    Internal funcs:  {internal}")
    print(f"    String labels:   {labeled}")
    print(f"{'=' * 80}")


def search_functions(db_path: str, pattern: str, *, as_json: bool = False) -> None:
    function_index = load_function_index_for_db(db_path)
    with db_error_handler(db_path, "searching functions"):
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
                        "signature": func.function_signature or "",
                    }
                    for func in results
                ]
                emit_json({"match_count": len(matches), "matches": matches, "pattern": pattern})
                return

            print(f"Found {len(results)} function(s) matching '{pattern}':\n")
            print(f"{'ID':>6}  {'Function Name':<50}  {'Signature'}")
            print(f"{'-' * 6}  {'-' * 50}  {'-' * 60}")
            for func in results:
                name = func.function_name or "(unnamed)"
                sig = func.function_signature or ""
                if len(sig) > 60:
                    sig = sig[:57] + "..."
                print(f"{func.function_id:>6}  {name:<50}  {sig}")
            print(f"\nUse function name or --id <ID> to extract the dispatch table.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract dispatch table (case -> handler) from a function.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("db_path", help="Path to the individual analysis DB")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--function", "--name", dest="function_name", metavar="NAME",
                       help="Function name to analyze")
    group.add_argument("--id", "--function-id", type=int, dest="function_id", help="Function ID")
    group.add_argument("--search", dest="search_pattern", help="Search for functions matching a pattern")
    parser.add_argument("function_name_pos", nargs="?", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--no-cache", action="store_true", help="Bypass cache and force fresh analysis")
    args = safe_parse_args(parser)
    if args.function_name_pos and not args.function_name:
        args.function_name = args.function_name_pos

    if args.function_id is not None:
        args.function_id = validate_function_id(args.function_id)

    db_path = resolve_db_path(args.db_path)
    function_index = load_function_index_for_db(db_path)

    if args.search_pattern:
        search_functions(db_path, args.search_pattern, as_json=args.json)
        return

    with db_error_handler(db_path, "extracting dispatch table"):
        with open_individual_analysis_db(db_path) as db:
            if not args.function_name and args.function_id is None:
                emit_error("Provide a function name, --id, or --search", ErrorCode.INVALID_ARGS)

            func, err = resolve_function(
                db, name=args.function_name, function_id=args.function_id,
                function_index=function_index,
            )
            if err:
                if "Multiple matches" in err:
                    print(err)
                    return
                emit_error(f"[{Path(db_path).stem}] {err}", ErrorCode.NOT_FOUND)

            cache_params = {"function_id": func.function_id}
            if not args.no_cache:
                cached = get_cached(db_path, "dispatch_table", params=cache_params)
                if cached is not None:
                    if args.json:
                        emit_json_list("tables", cached)
                    else:
                        tables = [_table_from_cached(t) for t in cached]
                        print_dispatch_table(tables, func, as_json=False)
                    return

            tables = build_dispatch_table(func, db)
            cache_result(
                db_path,
                "dispatch_table",
                _tables_to_cacheable(tables),
                params=cache_params,
            )
            print_dispatch_table(tables, func, as_json=args.json)


if __name__ == "__main__":
    main()
