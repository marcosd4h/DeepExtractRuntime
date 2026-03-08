#!/usr/bin/env python3
"""Gather module-level context for area-focused research prompts.

Extracts module identity, category distribution, import/export capabilities,
top interesting functions, cross-module dependencies, string intelligence,
security posture, COM density, and architecture overview.

Usage:
    python gather_module_context.py <db_path>
    python gather_module_context.py <db_path> --categories security,crypto,process_thread
    python gather_module_context.py <db_path> --top 20
    python gather_module_context.py <db_path> --json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

from _common import (
    WORKSPACE_ROOT,
    categorize_strings,
    classify_api,
    classify_function,
    is_callable_xref,
    is_external_xref,
    parse_json_safe,
    resolve_db_path,
    resolve_tracking_db,
    truncate,
)

from helpers import open_individual_analysis_db, open_analyzed_files_db, load_function_index_for_db, compute_stats
from helpers.errors import ErrorCode, db_error_handler, emit_error, log_error, safe_parse_args
from helpers.json_output import emit_json


# ---------------------------------------------------------------------------
# Module context gathering
# ---------------------------------------------------------------------------

def gather_module_identity(db) -> dict:
    """Extract module-level metadata from file_info table."""
    try:
        fi = db.get_file_info()
        if fi is None:
            return {}

        security = parse_json_safe(fi.security_features) or {}
        dll_chars = parse_json_safe(fi.dll_characteristics) or {}

        return {
            "file_name": fi.file_name or "",
            "file_description": fi.file_description or "",
            "company_name": fi.company_name or "",
            "file_version": fi.file_version or "",
            "product_name": fi.product_name or "",
            "internal_name": fi.internal_name or "",
            "pdb_path": fi.pdb_path or "",
            "time_date_stamp": fi.time_date_stamp_str or "",
            "is_net_assembly": fi.is_net_assembly or False,
            "security_posture": {
                "aslr": security.get("aslr", {}).get("enabled", False) if isinstance(security.get("aslr"), dict) else bool(security.get("aslr")),
                "dep": security.get("dep", {}).get("enabled", False) if isinstance(security.get("dep"), dict) else bool(security.get("dep")),
                "cfg": security.get("cfg", {}).get("enabled", False) if isinstance(security.get("cfg"), dict) else bool(security.get("cfg")),
                "seh": security.get("seh", {}).get("enabled", False) if isinstance(security.get("seh"), dict) else bool(security.get("seh")),
            },
        }
    except Exception as e:
        log_error(str(e), ErrorCode.DB_ERROR)
        return {}


def gather_import_capabilities(db) -> dict:
    """Categorize imports by capability area."""
    try:
        fi = db.get_file_info()
        if fi is None:
            return {}

        imports = parse_json_safe(fi.imports) or []
        capabilities = defaultdict(list)
        all_apis = []

        for mod_entry in imports:
            if not isinstance(mod_entry, dict):
                continue
            module_name = mod_entry.get("module_name", "")
            functions = mod_entry.get("functions", [])
            for func in functions:
                if not isinstance(func, dict):
                    continue
                api_name = func.get("function_name", "")
                if not api_name:
                    continue
                all_apis.append(api_name)
                cat = classify_api(api_name)
                if cat:
                    capabilities[cat].append(api_name)

        return {
            "capabilities": dict(capabilities),
            "total_imports": len(all_apis),
            "categorized_count": sum(len(v) for v in capabilities.values()),
        }
    except Exception:
        return {}


def gather_export_summary(db) -> list[dict]:
    """Get exports with classification."""
    try:
        fi = db.get_file_info()
        if fi is None:
            return []

        exports = parse_json_safe(fi.exports) or []
        result = []
        for exp in exports:
            if not isinstance(exp, dict):
                continue
            name = exp.get("function_name", "") or exp.get("name", "")
            cat = classify_api(name)
            result.append({
                "name": name,
                "ordinal": exp.get("ordinal"),
                "category": cat or "uncategorized",
            })
        return result
    except Exception:
        return []


def gather_category_distribution(db, filter_categories: list[str] = None, db_path: str = None, all_funcs: list = None) -> dict:
    """Classify all functions and compute category distribution."""
    if classify_function is None:
        log_error("classify-functions skill not available", ErrorCode.NOT_FOUND)
        return {}

    functions = all_funcs if all_funcs is not None else db.get_all_functions()
    category_counts = Counter()
    top_functions = []

    for func in functions:
        result = classify_function(func)
        category_counts[result.primary_category] += 1

        if filter_categories and result.primary_category not in filter_categories:
            continue

        top_functions.append({
            "function_name": func.function_name or "",
            "function_id": func.function_id,
            "primary_category": result.primary_category,
            "secondary_categories": result.secondary_categories,
            "interest_score": result.interest_score,
            "dangerous_api_count": result.dangerous_api_count,
            "api_count": result.api_count,
            "loop_count": result.loop_count,
            "has_decompiled": result.has_decompiled,
            "asm_instruction_count": result.asm_metrics.instruction_count if result.asm_metrics else 0,
        })

    # Sort by interest score descending
    top_functions.sort(key=lambda x: (-x["interest_score"], x["function_name"]))

    # Compute library distribution from function_index if available
    library_distribution = {}
    if db_path:
        function_index = load_function_index_for_db(db_path)
        if function_index:
            library_distribution = compute_stats(function_index)

    return {
        "category_counts": dict(category_counts),
        "total_functions": len(functions),
        "all_classified": top_functions,
        "library_distribution": library_distribution,
    }


def gather_cross_module_deps(db, all_funcs: list = None) -> dict:
    """Map cross-module dependencies from all functions."""
    functions = all_funcs if all_funcs is not None else db.get_all_functions()
    module_deps = Counter()

    for func in functions:
        outbound = parse_json_safe(func.simple_outbound_xrefs) or []
        for xref in outbound:
            if not isinstance(xref, dict):
                continue
            if is_external_xref(xref):
                module = xref.get("module_name", "")
                if module and module not in ("data", "vtable", "internal", "static_library", ""):
                    module_deps[module] += 1

    return dict(module_deps.most_common(30))


def gather_string_summary(db, all_funcs: list = None) -> dict:
    """Aggregate string categorization across all functions."""
    functions = all_funcs if all_funcs is not None else db.get_all_functions()
    all_categorized = defaultdict(set)

    for func in functions:
        strings = parse_json_safe(func.string_literals) or []
        if isinstance(strings, list):
            cats = categorize_strings([s for s in strings if isinstance(s, str)])
            for cat, items in cats.items():
                all_categorized[cat].update(items)

    return {cat: sorted(list(items))[:20] for cat, items in all_categorized.items()}


def gather_com_density(db, all_funcs: list = None) -> dict:
    """Detect COM class density in the module."""
    functions = all_funcs if all_funcs is not None else db.get_all_functions()
    com_classes = set()
    com_function_count = 0

    for func in functions:
        fname = func.function_name or ""
        mangled = func.mangled_name or ""
        is_com = False

        if "QueryInterface" in fname or "AddRef" in fname or "Release" in fname:
            is_com = True
        if "RuntimeClassImpl" in mangled or "ComPtr" in mangled:
            is_com = True

        vtable = parse_json_safe(func.vtable_contexts) or []
        if isinstance(vtable, list) and vtable:
            is_com = True

        if is_com:
            com_function_count += 1
            # Try to extract class name from mangled name
            if "@" in mangled:
                parts = mangled.split("@")
                if len(parts) >= 2 and parts[1]:
                    com_classes.add(parts[1])

    return {
        "com_function_count": com_function_count,
        "com_classes": sorted(list(com_classes))[:30],
    }


def gather_architecture(db, library_names: set = None, all_funcs: list = None) -> dict:
    """Extract architecture overview: classes, naming quality, complexity."""
    functions = all_funcs if all_funcs is not None else db.get_all_functions()
    class_methods = defaultdict(int)
    named_count = 0
    unnamed_count = 0
    total_complexity = 0
    complexity_count = 0

    for func in functions:
        fname = func.function_name or ""
        mangled = func.mangled_name or ""

        # Skip library-tagged functions from class listing
        if library_names and fname in library_names:
            continue

        if fname.startswith("sub_"):
            unnamed_count += 1
        else:
            named_count += 1

        # Extract class name from mangled
        if "@" in mangled and mangled.startswith("?"):
            parts = mangled.split("@")
            if len(parts) >= 2 and parts[1] and not parts[1].startswith("?"):
                class_methods[parts[1]] += 1

        # Complexity
        loop_analysis = parse_json_safe(func.loop_analysis)
        if isinstance(loop_analysis, dict):
            loops = loop_analysis.get("loops", [])
            if isinstance(loops, list):
                for loop in loops:
                    if isinstance(loop, dict):
                        c = loop.get("cyclomatic_complexity", 0) or 0
                        total_complexity += c
                        complexity_count += 1

    total = named_count + unnamed_count
    classes = [{"name": name, "method_count": count}
               for name, count in sorted(class_methods.items(), key=lambda x: -x[1])]

    return {
        "classes": classes[:30],
        "total_classes": len(class_methods),
        "named_function_count": named_count,
        "unnamed_function_count": unnamed_count,
        "named_function_pct": round(named_count / total * 100, 1) if total > 0 else 0,
        "avg_cyclomatic_complexity": round(total_complexity / complexity_count, 1) if complexity_count > 0 else 0,
    }


# ---------------------------------------------------------------------------
# Full module context
# ---------------------------------------------------------------------------

def gather_full_module_context(
    db_path: str,
    db,
    filter_categories: list[str] = None,
    top_n: int = 15,
) -> dict:
    """Gather comprehensive module-level context."""
    all_funcs = db.get_all_functions()

    identity = gather_module_identity(db)
    dist = gather_category_distribution(db, filter_categories, db_path=db_path, all_funcs=all_funcs)
    imports = gather_import_capabilities(db)
    exports = gather_export_summary(db)
    cross_deps = gather_cross_module_deps(db, all_funcs=all_funcs)
    string_summary = gather_string_summary(db, all_funcs=all_funcs)
    com = gather_com_density(db, all_funcs=all_funcs)

    # Load function_index for library filtering in architecture view
    function_index = load_function_index_for_db(db_path)
    library_names = set()
    if function_index:
        library_names = {k for k, v in function_index.items() if v.get("library") is not None}
    arch = gather_architecture(db, library_names=library_names if library_names else None, all_funcs=all_funcs)

    # Trim top functions to requested count
    top_functions = dist.get("all_classified", [])[:top_n]

    return {
        "db_path": db_path,
        "module": identity,
        "category_distribution": dist.get("category_counts", {}),
        "total_functions": dist.get("total_functions", 0),
        "top_functions": top_functions,
        "import_capabilities": imports,
        "exports": exports[:30],
        "export_count": len(exports),
        "cross_module_deps": cross_deps,
        "string_summary": string_summary,
        "com_density": com,
        "architecture": arch,
    }


# ---------------------------------------------------------------------------
# Formatted output
# ---------------------------------------------------------------------------

def print_module_context(context: dict) -> None:
    """Print module context in human-readable format."""
    module = context.get("module", {})
    dist = context.get("category_distribution", {})
    top_funcs = context.get("top_functions", [])
    imports = context.get("import_capabilities", {})
    cross_deps = context.get("cross_module_deps", {})
    string_summary = context.get("string_summary", {})
    com = context.get("com_density", {})
    arch = context.get("architecture", {})

    def _header(title: str):
        print(f"\n{'=' * 70}")
        print(f"  {title}")
        print(f"{'=' * 70}")

    print(f"{'#' * 70}")
    print(f"  MODULE CONTEXT: {module.get('file_name', '?')}")
    print(f"  {module.get('file_description', '')}")
    print(f"  {module.get('company_name', '')} v{module.get('file_version', '?')}")
    print(f"  Functions: {context.get('total_functions', 0)}")
    print(f"{'#' * 70}")

    # Category distribution
    _header("1. CATEGORY DISTRIBUTION")
    if dist:
        for cat, count in sorted(dist.items(), key=lambda x: -x[1]):
            pct = count / context.get("total_functions", 1) * 100
            bar = "#" * int(pct / 2)
            print(f"  {cat:<25} {count:>5} ({pct:5.1f}%)  {bar}")

    # Security posture
    sec = module.get("security_posture", {})
    if sec:
        _header("2. SECURITY POSTURE")
        for feat, val in sec.items():
            status = "ENABLED" if val else "DISABLED"
            print(f"  {feat.upper():<8}: {status}")

    # Import capabilities
    if imports.get("capabilities"):
        _header("3. IMPORT CAPABILITIES")
        print(f"  Total imports: {imports.get('total_imports', 0)} (categorized: {imports.get('categorized_count', 0)})")
        for cat, apis in sorted(imports["capabilities"].items(), key=lambda x: -len(x[1])):
            shown = apis[:8]
            more = f" +{len(apis) - 8} more" if len(apis) > 8 else ""
            print(f"\n  [{cat}] ({len(apis)} APIs)")
            print(f"    {', '.join(shown)}{more}")

    # Top functions
    if top_funcs:
        _header(f"4. TOP {len(top_funcs)} MOST INTERESTING FUNCTIONS")
        print(f"  {'Rank':>4}  {'Score':>5}  {'Category':<22}  {'Dangerous':>9}  {'Function Name'}")
        print(f"  {'-' * 4}  {'-' * 5}  {'-' * 22}  {'-' * 9}  {'-' * 40}")
        for i, f in enumerate(top_funcs, 1):
            name = f["function_name"]
            if len(name) > 40:
                name = name[:37] + "..."
            print(f"  {i:>4}  {f['interest_score']:>5}  {f['primary_category']:<22}  {f['dangerous_api_count']:>9}  {name}")

    # Cross-module dependencies
    if cross_deps:
        _header("5. CROSS-MODULE DEPENDENCIES")
        for mod, count in sorted(cross_deps.items(), key=lambda x: -x[1]):
            print(f"  {mod:<35} {count:>5} calls")

    # String summary
    if string_summary:
        _header("6. STRING INTELLIGENCE SUMMARY")
        for cat, items in sorted(string_summary.items(), key=lambda x: -len(x[1])):
            print(f"\n  [{cat}] ({len(items)} unique)")
            for s in items[:3]:
                print(f"    \"{truncate(s, 80)}\"")
            if len(items) > 3:
                print(f"    ... and {len(items) - 3} more")

    # COM density
    if com.get("com_function_count", 0) > 0:
        _header("7. COM DENSITY")
        print(f"  COM-related functions: {com['com_function_count']}")
        if com.get("com_classes"):
            print(f"  COM classes: {', '.join(com['com_classes'][:10])}")

    # Architecture
    _header("8. ARCHITECTURE")
    print(f"  Total classes:       {arch.get('total_classes', 0)}")
    print(f"  Named functions:     {arch.get('named_function_count', 0)} ({arch.get('named_function_pct', 0)}%)")
    print(f"  Unnamed (sub_):      {arch.get('unnamed_function_count', 0)}")
    print(f"  Avg complexity:      {arch.get('avg_cyclomatic_complexity', 0)}")
    if arch.get("classes"):
        print(f"\n  Top classes by method count:")
        for cls in arch["classes"][:10]:
            print(f"    {cls['name']:<40} {cls['method_count']:>4} methods")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Gather module-level context for area-focused research prompts.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("db_path", help="Path to the individual analysis DB")
    parser.add_argument("--categories", help="Comma-separated list of categories to focus on")
    parser.add_argument("--top", type=int, default=15, help="Number of top functions to include (default: 15)")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = safe_parse_args(parser)

    db_path = resolve_db_path(args.db_path)
    filter_cats = args.categories.split(",") if args.categories else None

    with db_error_handler(db_path, "gathering module context"):
        with open_individual_analysis_db(db_path) as db:
            context = gather_full_module_context(
                db_path=db_path,
                db=db,
                filter_categories=filter_cats,
                top_n=args.top,
            )

    if args.json:
        emit_json(context, ensure_ascii=True, default=str)
    else:
        print_module_context(context)


if __name__ == "__main__":
    main()
