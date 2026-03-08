#!/usr/bin/env python3
"""Categorize module imports by API capability type.

Usage:
    python .agent/skills/generate-re-report/scripts/analyze_imports.py <db_path>
    python .agent/skills/generate-re-report/scripts/analyze_imports.py <db_path> --json
    python .agent/skills/generate-re-report/scripts/analyze_imports.py <db_path> --include-delay-load
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

# Ensure _common is importable
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (
    API_TAXONOMY,
    classify_api,
    open_analysis_db,
    parse_json_safe,
    resolve_db_path,
)
from helpers.cache import get_cached, cache_result
from helpers.errors import ErrorCode, db_error_handler, emit_error, safe_parse_args
from helpers.json_output import emit_json


def analyze_imports(db_path: str, *, no_cache: bool = False) -> dict:
    """Analyze and categorize all imports from a module's DB.

    Returns dict with keys:
        categories: {category: [{module, function, is_delay_loaded}]}
        uncategorized: [{module, function}]
        summary: {category: count}
        delay_loaded: [{module, function}]
        total_imports: int
        total_modules: int
        import_modules: [{module_name, function_count, is_delay_loaded, categories}]
    """
    if not no_cache:
        cached = get_cached(db_path, "analyze_imports")
        if cached is not None:
            return cached

    with db_error_handler(db_path, "analyzing imports"):
        with open_analysis_db(db_path) as db:
            fi = db.get_file_info()
            if not fi:
                emit_error("No file_info found in database", ErrorCode.NO_DATA)

            imports_data = parse_json_safe(fi.imports) or []

    categories: dict[str, list[dict]] = defaultdict(list)
    uncategorized: list[dict] = []
    delay_loaded: list[dict] = []
    module_info: list[dict] = []
    total_imports = 0

    for module_entry in imports_data:
        if not isinstance(module_entry, dict):
            continue

        mod_name = module_entry.get("module_name", module_entry.get("name", "unknown"))
        functions = module_entry.get("functions", [])
        if not isinstance(functions, list):
            continue

        mod_categories: dict[str, int] = defaultdict(int)
        mod_func_count = 0
        mod_delay = False

        for func in functions:
            if not isinstance(func, dict):
                continue
            fname = func.get("function_name", func.get("name", ""))
            if not fname:
                continue

            total_imports += 1
            mod_func_count += 1
            is_delay = func.get("is_delay_loaded", False)
            if is_delay:
                mod_delay = True
                delay_loaded.append({"module": mod_name, "function": fname})

            entry = {"module": mod_name, "function": fname, "is_delay_loaded": is_delay}
            cat = classify_api(fname)
            if cat:
                categories[cat].append(entry)
                mod_categories[cat] += 1
            else:
                uncategorized.append(entry)

        if mod_func_count > 0:
            module_info.append({
                "module_name": mod_name,
                "function_count": mod_func_count,
                "is_delay_loaded": mod_delay,
                "categories": dict(mod_categories),
            })

    # Build summary
    summary = {cat: len(funcs) for cat, funcs in categories.items()}
    summary = dict(sorted(summary.items(), key=lambda x: -x[1]))

    result = {
        "categories": {k: v for k, v in sorted(categories.items(), key=lambda x: -len(x[1]))},
        "uncategorized": uncategorized,
        "summary": summary,
        "delay_loaded": delay_loaded,
        "total_imports": total_imports,
        "total_modules": len(module_info),
        "import_modules": sorted(module_info, key=lambda x: -x["function_count"]),
    }

    cache_result(db_path, "analyze_imports", result)
    return result


def analyze_exports(db_path: str) -> dict:
    """Analyze exports from a module's DB.

    Returns dict with keys:
        exports: [{name, signature, ordinal, is_forwarded, forwarded_to, category}]
        forwarded: [{name, forwarded_to}]
        total: int
        categorized: {category: count}
    """
    with db_error_handler(db_path, "analyzing imports"):
        with open_analysis_db(db_path) as db:
            fi = db.get_file_info()
            if not fi:
                emit_error("No file_info found", ErrorCode.NO_DATA)

            exports_data = parse_json_safe(fi.exports) or []

    exports = []
    forwarded = []
    cat_counts: dict[str, int] = defaultdict(int)

    for exp in exports_data:
        if not isinstance(exp, dict):
            continue
        name = exp.get("function_name", exp.get("name", ""))
        sig = exp.get("function_signature_extended", "")
        ordinal = exp.get("ordinal", 0)
        is_fwd = exp.get("is_forwarded", False)
        fwd_to = exp.get("forwarded_to", None)

        cat = classify_api(name) if name else None
        entry = {
            "name": name,
            "signature": sig,
            "ordinal": ordinal,
            "is_forwarded": is_fwd,
            "forwarded_to": fwd_to,
            "category": cat,
        }
        exports.append(entry)
        if cat:
            cat_counts[cat] += 1
        if is_fwd:
            forwarded.append({"name": name, "forwarded_to": fwd_to})

    return {
        "exports": exports,
        "forwarded": forwarded,
        "total": len(exports),
        "categorized": dict(sorted(cat_counts.items(), key=lambda x: -x[1])),
    }


def format_import_report(result: dict, include_delay: bool = False) -> str:
    """Format import analysis as markdown."""
    lines = []
    lines.append("## Import Analysis by Capability\n")

    summary = result.get("summary", {})
    total = result.get("total_imports", 0)
    total_mods = result.get("total_modules", 0)

    lines.append(f"**{total} imports from {total_mods} modules**\n")

    if summary:
        lines.append("| Category | Import Count | Key APIs |")
        lines.append("|---|---|---|")
        categories = result.get("categories", {})
        for cat, count in summary.items():
            funcs = categories.get(cat, [])
            # Show up to 4 representative API names
            api_names = sorted(set(f["function"] for f in funcs[:20]))[:4]
            key_apis = ", ".join(api_names)
            lines.append(f"| {cat} | {count} | {key_apis} |")

        uncat_count = len(result.get("uncategorized", []))
        if uncat_count:
            lines.append(f"| _(uncategorized)_ | {uncat_count} | |")
        lines.append("")

    # Delay-loaded imports
    delay = result.get("delay_loaded", [])
    if delay and include_delay:
        lines.append(f"### Delay-Loaded Imports ({len(delay)})\n")
        lines.append("Delay-loaded imports are resolved on first invocation rather than at module load time.\n")
        for d in delay[:30]:
            lines.append(f"- `{d['module']}` -> `{d['function']}`")
        if len(delay) > 30:
            lines.append(f"- _... and {len(delay) - 30} more_")
        lines.append("")

    return "\n".join(lines)


def format_export_report(result: dict) -> str:
    """Format export analysis as markdown."""
    lines = []
    total = result.get("total", 0)
    forwarded = result.get("forwarded", [])

    lines.append(f"### Exports ({total} total, {len(forwarded)} forwarded)\n")

    categorized = result.get("categorized", {})
    if categorized:
        lines.append("| Category | Count |")
        lines.append("|---|---|")
        for cat, count in categorized.items():
            lines.append(f"| {cat} | {count} |")
        lines.append("")

    if forwarded:
        lines.append("**Forwarded exports:**\n")
        for f in forwarded[:20]:
            lines.append(f"- `{f['name']}` -> `{f['forwarded_to']}`")
        if len(forwarded) > 20:
            lines.append(f"- _... and {len(forwarded) - 20} more_")
        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Categorize module imports by API capability")
    parser.add_argument("db_path", help="Path to individual analysis DB")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--include-delay-load", action="store_true", help="Show delay-loaded import details")
    parser.add_argument("--exports", action="store_true", help="Also analyze exports")
    parser.add_argument("--no-cache", action="store_true", help="Bypass result cache")
    args = safe_parse_args(parser)

    import_result = analyze_imports(args.db_path, no_cache=args.no_cache)
    export_result = analyze_exports(args.db_path) if args.exports else None

    if args.json:
        output = {"imports": import_result}
        if export_result:
            output["exports"] = export_result
        emit_json(output, default=str)
    else:
        print(format_import_report(import_result, include_delay=args.include_delay_load))
        if export_result:
            print(format_export_report(export_result))


if __name__ == "__main__":
    main()
