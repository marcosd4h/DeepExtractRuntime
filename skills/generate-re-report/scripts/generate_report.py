#!/usr/bin/env python3
"""Generate a comprehensive reverse engineering report for a binary module.

Main orchestrator: runs all analyses and assembles a synthesized markdown report.

Usage:
    python .agent/skills/generate-re-report/scripts/generate_report.py <db_path>
    python .agent/skills/generate-re-report/scripts/generate_report.py <db_path> --output report.md
    python .agent/skills/generate-re-report/scripts/generate_report.py <db_path> --summary
    python .agent/skills/generate-re-report/scripts/generate_report.py <db_path> --top 20
    python .agent/skills/generate-re-report/scripts/generate_report.py <db_path> --json
"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
from collections import defaultdict
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (
    WORKSPACE_ROOT,
    classify_api,
    decode_rich_tool,
    fmt_count,
    fmt_pct,
    get_complexity_bucket,
    get_size_bucket,
    open_analysis_db,
    parse_json_safe,
    resolve_db_path,
    truncate_string,
)
from helpers.errors import ErrorCode, db_error_handler, emit_error, safe_parse_args
from helpers.json_output import emit_json

# Import sub-analyzers
from analyze_imports import analyze_imports, analyze_exports, format_import_report, format_export_report
from analyze_strings import analyze_strings, format_string_report
from analyze_complexity import analyze_complexity, format_complexity_report
from analyze_topology import analyze_topology, format_topology_report


# ---------------------------------------------------------------------------
# Section generators
# ---------------------------------------------------------------------------

def _section_executive_summary(fi, func_count: int, import_result: dict,
                                complexity_result: dict, topology_result: dict) -> str:
    """Section 1: Executive Summary."""
    lines = ["# Reverse Engineering Report\n"]
    lines.append("## 1. Executive Summary\n")

    # Binary identity
    name = fi.file_name or "Unknown"
    desc = fi.file_description or ""
    company = fi.company_name or ""
    version = fi.file_version or fi.product_version or ""
    product = fi.product_name or ""

    identity_parts = [f"**{name}**"]
    if version:
        identity_parts.append(f"v{version}")
    if company:
        identity_parts.append(f"by {company}")
    lines.append(" ".join(identity_parts))
    if desc:
        lines.append(f"  \n_{desc}_\n")
    else:
        lines.append("")

    # Purpose assessment from import categories
    import_summary = import_result.get("summary", {})
    top_capabilities = list(import_summary.keys())[:5]
    if top_capabilities:
        cap_str = ", ".join(c.replace("_", " ") for c in top_capabilities)
        lines.append(f"**Primary capabilities**: {cap_str}")

    # Scale
    type_dist = complexity_result.get("distributions", {}).get("type", {})
    class_count = type_dist.get("class_method", 0)
    standalone_count = type_dist.get("standalone", 0)
    lines.append(
        f"**Scale**: {fmt_count(func_count, 'function')} "
        f"({fmt_count(class_count, 'class method')} + "
        f"{fmt_count(standalone_count, 'standalone function')})"
    )

    # Build info
    rich = parse_json_safe(fi.rich_header)
    if isinstance(rich, dict) and rich.get("present"):
        tools = rich.get("tools", [])
        if tools:
            # Find the main compiler tool
            compiler_info = ""
            for t in tools:
                if isinstance(t, dict):
                    pid = t.get("product_id", 0)
                    if pid in (104, 105, 255, 256, 257, 258, 259, 260):  # Utc C/C++
                        build = t.get("build_number", 0)
                        compiler_info = decode_rich_tool(pid, build)
                        break
            if compiler_info:
                lines.append(f"**Compiler**: {compiler_info}")

    if fi.pdb_path:
        lines.append(f"**PDB**: `{fi.pdb_path}`")

    # Export/entry count
    lines.append(f"**Exports/Entries**: {topology_result.get('export_count', 0)}")

    total_imports = import_result.get("total_imports", 0)
    total_modules = import_result.get("total_modules", 0)
    lines.append(f"**Imports**: {total_imports} functions from {total_modules} modules")
    lines.append("")

    return "\n".join(lines)


def _section_provenance(fi) -> str:
    """Section 2: Provenance & Build Environment."""
    lines = ["## 2. Provenance & Build Environment\n"]

    # Timestamps
    if fi.time_date_stamp_str:
        lines.append(f"**Compilation timestamp**: {fi.time_date_stamp_str}")
    if fi.file_modified_date_str:
        lines.append(f"**File modified date**: {fi.file_modified_date_str}")

    # PDB path analysis
    if fi.pdb_path:
        lines.append(f"**PDB path**: `{fi.pdb_path}`")
        pdb = fi.pdb_path
        # Extract developer machine name and source tree
        if ":\\" in pdb or ":/" in pdb:
            parts = pdb.replace("/", "\\").split("\\")
            if len(parts) > 2:
                drive_tree = "\\".join(parts[:4])
                lines.append(f"  - Source tree root: `{drive_tree}\\...`")
                if "os\\src\\" in pdb.lower() or "minkernel" in pdb.lower():
                    lines.append("  - **Windows OS component** (OS source tree detected)")

    # Rich header decode
    rich = parse_json_safe(fi.rich_header)
    if isinstance(rich, dict) and rich.get("present"):
        lines.append("\n### Rich Header (Build Toolchain)\n")
        tools = rich.get("tools", [])
        total_objects = rich.get("total_objects", 0)
        unique_tools = rich.get("unique_tools", 0)
        lines.append(f"**{unique_tools} unique tools**, **{total_objects} total object files**\n")

        if tools:
            lines.append("| Tool | Build | Objects | Description |")
            lines.append("|---|---|---|---|")
            for t in tools:
                if isinstance(t, dict):
                    pid = t.get("product_id", 0)
                    build = t.get("build_number", 0)
                    count = t.get("object_count", 0)
                    desc = decode_rich_tool(pid, build)
                    tool_name = t.get("tool_name", f"[{pid}]")
                    lines.append(f"| {tool_name} | {build} | {count} | {desc} |")
            lines.append("")
    elif isinstance(rich, dict):
        lines.append("\n**Rich header**: Not present")

    # .NET status
    if fi.is_net_assembly:
        clr = parse_json_safe(fi.clr_metadata)
        lines.append("\n### .NET Assembly")
        if isinstance(clr, dict):
            major = clr.get("major_runtime_version", "?")
            minor = clr.get("minor_runtime_version", "?")
            lines.append(f"- CLR version: {major}.{minor}")
            if clr.get("flags"):
                lines.append(f"- Flags: `{clr['flags']}`")
    else:
        lines.append("\n**Runtime**: Native (not .NET)")

    lines.append("")
    return "\n".join(lines)


def _section_security(fi, canary_coverage: dict) -> str:
    """Section 3: Security Posture."""
    lines = ["## 3. Security Posture\n"]

    # Security features table
    sf = parse_json_safe(fi.security_features)
    if isinstance(sf, dict):
        lines.append("### Mitigation Status\n")
        lines.append("| Feature | Status |")
        lines.append("|---|---|")
        for feature, label in [
            ("aslr_enabled", "ASLR (Address Space Layout Randomization)"),
            ("dep_enabled", "DEP (Data Execution Prevention)"),
            ("cfg_enabled", "CFG (Control Flow Guard)"),
            ("seh_enabled", "SEH (Structured Exception Handling)"),
            ("code_integrity", "Code Integrity"),
            ("safeseh_present", "SafeSEH"),
        ]:
            val = sf.get(feature)
            if val is True:
                lines.append(f"| {label} | Enabled |")
            elif val is False:
                lines.append(f"| {label} | **Disabled** |")

        seh_handlers = sf.get("safeseh_handlers")
        if seh_handlers is not None:
            lines.append(f"| SafeSEH Handler Count | {seh_handlers} |")
        if sf.get("cfg_check_function_present"):
            lines.append(f"| CFG Check Function | Present |")
        lines.append("")

    # DLL Characteristics
    dll_chars = parse_json_safe(fi.dll_characteristics)
    if isinstance(dll_chars, dict):
        lines.append("### DLL Characteristics\n")
        active = [k for k, v in dll_chars.items() if v is True and k != "raw_value"]
        if active:
            lines.append("Active flags: " + ", ".join(f"`{f}`" for f in active))
        raw = dll_chars.get("raw_value")
        if raw:
            lines.append(f"  \nRaw value: `{raw}`")
        lines.append("")

    # Section permissions
    sections = parse_json_safe(fi.sections) or []
    if sections:
        anomalies = []
        for sec in sections:
            if isinstance(sec, dict):
                name = sec.get("name", "?")
                w = sec.get("writable", False)
                x = sec.get("executable", False)
                if w and x:
                    anomalies.append(f"`{name}` (writable + executable)")
                # Check non-standard section names
                standard = {".text", ".rdata", ".data", ".pdata", ".rsrc", ".reloc",
                            ".idata", ".edata", ".tls", ".bss", ".CRT", ".00cfg",
                            ".gfids", ".giats", ".didat", ".mrdata", ".retplne"}
                if name not in standard and not name.startswith("."):
                    anomalies.append(f"`{name}` (non-standard name)")

        if anomalies:
            lines.append("### Section Anomalies\n")
            for a in anomalies:
                lines.append(f"- {a}")
            lines.append("")

    # Stack canary coverage
    if canary_coverage.get("total", 0) > 0:
        lines.append("### Stack Canary Coverage\n")
        lines.append(
            f"**{canary_coverage['percentage']}** of functions have stack canaries "
            f"({canary_coverage['with_canary']}/{canary_coverage['total']})"
        )
        lines.append("")

    # Load config
    lc = parse_json_safe(fi.load_config)
    if isinstance(lc, dict) and lc.get("present"):
        lines.append("### Load Configuration\n")
        if lc.get("se_handler_count") is not None:
            lines.append(f"- SEH handler count: {lc['se_handler_count']}")
        if lc.get("guard_cf_check_function"):
            lines.append(f"- CFG check function: `{lc['guard_cf_check_function']}`")
        if lc.get("guard_flags"):
            lines.append(f"- Guard flags: `{lc['guard_flags']}`")
        lines.append("")

    return "\n".join(lines)


def _section_architecture(db_path: str, func_count: int) -> str:
    """Section 5: Internal Architecture."""
    lines = ["## 5. Internal Architecture\n"]

    with db_error_handler(db_path, "loading functions for architecture analysis"):
        with open_analysis_db(db_path) as db:
            all_funcs = db.get_all_functions()

    # Load function_index to skip library classes from hierarchy
    from _common import load_index_for_db
    function_index = load_index_for_db(db_path)
    library_names: set[str] = set()
    if function_index:
        library_names = {k for k, v in function_index.items() if v.get("library") is not None}

    # Class hierarchy from function names (excluding library boilerplate)
    classes: dict[str, list[str]] = defaultdict(list)
    standalone = []
    named_count = 0
    unnamed_count = 0

    for func in all_funcs:
        fname = func.function_name or ""
        if fname.startswith("sub_"):
            unnamed_count += 1
        else:
            named_count += 1

        # Skip library functions from class hierarchy
        if fname in library_names:
            continue

        if "::" in fname:
            parts = fname.split("::")
            class_name = parts[0]
            method_name = "::".join(parts[1:])
            classes[class_name].append(method_name)
        else:
            standalone.append(fname)

    # Symbol quality
    lines.append(f"### Symbol Quality\n")
    lines.append(f"- Named functions: {named_count} ({fmt_pct(named_count, func_count)})")
    lines.append(f"- Unnamed (`sub_XXXX`): {unnamed_count} ({fmt_pct(unnamed_count, func_count)})")
    lines.append("")

    # Class hierarchy
    if classes:
        sorted_classes = sorted(classes.items(), key=lambda x: -len(x[1]))
        lines.append(f"### Class Hierarchy ({len(classes)} classes)\n")
        for cls_name, methods in sorted_classes[:25]:
            lines.append(f"- **{cls_name}** ({len(methods)} methods)")
            for m in sorted(methods)[:8]:
                lines.append(f"  - {m}")
            if len(methods) > 8:
                lines.append(f"  - _... +{len(methods) - 8} more_")
        if len(sorted_classes) > 25:
            lines.append(f"\n_... and {len(sorted_classes) - 25} more classes_")
        lines.append("")

    return "\n".join(lines)


def _section_anomalies(fi, db_path: str, complexity_result: dict) -> str:
    """Section 9: Notable Patterns & Anomalies."""
    lines = ["## 9. Notable Patterns & Anomalies\n"]

    # TLS callbacks
    tls = parse_json_safe(fi.tls_callbacks) or []
    if tls:
        lines.append(f"### TLS Callbacks ({len(tls)})\n")
        for cb in tls[:5]:
            if isinstance(cb, dict):
                name = cb.get("function_name", cb.get("address", "?"))
                threat = cb.get("threat_level", "MINIMAL")
                score = cb.get("threat_score", 0)
                lines.append(f"- `{name}` -- threat: {threat} (score: {score})")
        lines.append("")

    # Decompiler failures (functions with analysis errors)
    with_errors = complexity_result.get("with_errors", [])
    if with_errors:
        lines.append(f"### Analysis Errors ({len(with_errors)} functions)\n")
        for e in with_errors[:10]:
            errors_str = "; ".join(str(err)[:60] for err in e["errors"][:2])
            lines.append(f"- `{e['name']}`: {errors_str}")
        if len(with_errors) > 10:
            lines.append(f"- _... and {len(with_errors) - 10} more_")
        lines.append("")

    # Very large functions
    by_size = complexity_result.get("by_size", [])
    huge_funcs = [f for f in by_size if f["instruction_count"] > 500]
    if huge_funcs:
        lines.append(f"### Unusually Large Functions ({len(huge_funcs)})\n")
        lines.append("Functions with >500 assembly instructions:\n")
        for f in huge_funcs[:10]:
            lines.append(f"- `{f['name']}`: {f['instruction_count']} instructions")
        lines.append("")

    # Functions with many global writers
    by_globals = complexity_result.get("by_global_state", [])
    heavy_writers = [g for g in by_globals if g["writes"] > 5]
    if heavy_writers:
        lines.append(f"### Heavy Global State Writers ({len(heavy_writers)})\n")
        for g in heavy_writers[:10]:
            lines.append(f"- `{g['name']}`: {g['writes']} writes, {g['reads']} reads")
        lines.append("")

    if not (tls or with_errors or huge_funcs or heavy_writers):
        lines.append("No notable anomalies detected.\n")

    return "\n".join(lines)


def _section_recommendations(import_result: dict, complexity_result: dict,
                              topology_result: dict, string_result: dict,
                              func_count: int) -> str:
    """Section 10: Recommended Focus Areas."""
    lines = ["## 10. Recommended Focus Areas\n"]

    # Top functions by combined metrics
    by_loops = complexity_result.get("by_loops", [])
    by_xrefs = complexity_result.get("by_xrefs", [])
    by_size = complexity_result.get("by_size", [])

    # Score each function: complexity + hub score + size
    func_scores: dict[str, float] = defaultdict(float)
    func_reasons: dict[str, list[str]] = defaultdict(list)

    for f in by_loops[:30]:
        func_scores[f["function_name"]] += f["loop_count"] * 2 + f["max_cyclomatic"]
        func_reasons[f["function_name"]].append(f"complex ({f['loop_count']} loops, cyclomatic {f['max_cyclomatic']})")

    for f in by_xrefs[:50]:
        func_scores[f["function_name"]] += f["hub_score"] * 0.5
        if f["hub_score"] > 20:
            func_reasons[f["function_name"]].append(f"hub ({f['inbound']} in, {f['outbound']} out)")

    for f in by_size[:30]:
        if f["instruction_count"] > 200:
            func_scores[f["function_name"]] += f["instruction_count"] * 0.01
            func_reasons[f["function_name"]].append(f"large ({f['instruction_count']} instructions)")

    top_funcs = sorted(func_scores.items(), key=lambda x: -x[1])[:10]

    if top_funcs:
        lines.append("### Priority Functions\n")
        lines.append("Ranked by combined complexity, connectivity, and size:\n")
        for i, (name, score) in enumerate(top_funcs, 1):
            reasons = "; ".join(func_reasons[name][:3])
            lines.append(f"{i}. **`{name}`** -- {reasons}")
        lines.append("")

    # Core classes (most methods)
    # We can approximate from complexity_result type distribution
    lines.append("### Skill Integration Suggestions\n")
    lines.append("Recommended follow-up analysis using additional skills:\n")

    # Check for complex dispatchers
    by_loops_names = {f["function_name"] for f in by_loops[:20] if f["loop_count"] >= 3}
    if by_loops_names:
        sample = list(by_loops_names)[:3]
        names_str = ", ".join(f"`{n}`" for n in sample)
        lines.append(f"- **state-machine-extractor**: Complex dispatch/loop functions detected ({names_str})")

    # Check for many class methods
    type_dist = complexity_result.get("distributions", {}).get("type", {})
    if type_dist.get("class_method", 0) > 20:
        lines.append(f"- **batch-lift**: {type_dist['class_method']} class methods -- "
                     "consider batch-lifting entire classes together")

    # Global state writers
    by_globals = complexity_result.get("by_global_state", [])
    if by_globals and by_globals[0]["total"] > 10:
        lines.append(f"- **data-flow-tracer**: High global state access count -- "
                     f"trace data flow through `{by_globals[0]['function_name']}` and related functions")

    # Entry point coverage
    entry_reach = topology_result.get("entry_reachability", [])
    if entry_reach:
        top_entry = entry_reach[0]
        lines.append(f"- **callgraph-tracer**: Entry `{top_entry['function_name']}` reaches "
                     f"{top_entry['reachable_count']} functions -- trace its call chain")

    # Dead code
    dead = topology_result.get("dead_code", [])
    if dead:
        lines.append(f"- **classify-functions**: {len(dead)} potential dead code functions -- "
                     "classify to determine analysis priority")

    lines.append("")

    # Entry points that cover most code
    if entry_reach:
        lines.append("### Entry Points by Coverage\n")
        lines.append("These exports/entries reach the most internal functions:\n")
        for e in entry_reach[:5]:
            lines.append(f"- `{e['name']}`: reaches {e['reachable_count']} functions ({e['reachable_pct']})")
        lines.append("")

    # Functions needing assembly verification
    with_errors = complexity_result.get("with_errors", [])
    if with_errors:
        lines.append("### Functions Needing Assembly Verification\n")
        lines.append("These functions have analysis errors; manual assembly review is recommended:\n")
        for e in with_errors[:5]:
            lines.append(f"- `{e['name']}`")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main report assembly
# ---------------------------------------------------------------------------

def generate_report(db_path: str, top_n: int = 10, summary_mode: bool = False,
                    *, no_cache: bool = False) -> str:
    """Generate the full RE report for a module.

    Args:
        db_path: Path to individual analysis DB
        top_n: Number of items in ranked tables
        summary_mode: If True, generate abbreviated report (sections 1, 3, 4, 10 only)
        no_cache: Bypass all sub-analyzer caches

    Returns:
        Complete markdown report string
    """
    resolved = resolve_db_path(db_path)

    # Load file info
    with db_error_handler(db_path, "loading module data for report"):
        with open_analysis_db(db_path) as db:
            fi = db.get_file_info()
            func_count = db.count_functions()

    if not fi:
        return "# Error\n\nNo file_info found in database."

    # Run all sub-analyses
    import_result = analyze_imports(db_path, no_cache=no_cache)
    export_result = analyze_exports(db_path)
    complexity_result = analyze_complexity(db_path, no_cache=no_cache)
    topology_result = analyze_topology(db_path, no_cache=no_cache)

    sections = []

    # Store db_path on fi for _section_executive_summary workaround
    # (fi is a frozen dataclass, so we pass db_path separately)

    # Section 1: Executive Summary
    sections.append(_section_executive_summary(fi, func_count, import_result,
                                                complexity_result, topology_result))

    if not summary_mode:
        # Section 2: Provenance & Build
        sections.append(_section_provenance(fi))

    # Section 3: Security Posture
    canary = complexity_result.get("canary_coverage", {})
    sections.append(_section_security(fi, canary))

    # Section 4: External Interface
    sections.append("## 4. External Interface (Import/Export Analysis)\n")
    sections.append(format_import_report(import_result, include_delay=True))
    sections.append(format_export_report(export_result))

    if not summary_mode:
        # Section 5: Internal Architecture
        sections.append(_section_architecture(db_path, func_count))

        # Section 6: Complexity Hotspots
        sections.append(format_complexity_report(complexity_result, top_n=top_n))

        # Section 7: String Intelligence
        string_result = analyze_strings(db_path, no_cache=no_cache)
        sections.append(format_string_report(string_result, top_n=top_n))

        # Section 8: Cross-Reference Topology
        sections.append(format_topology_report(topology_result, top_n=top_n))

        # Section 9: Notable Patterns & Anomalies
        sections.append(_section_anomalies(fi, db_path, complexity_result))
    else:
        string_result = {"categories": {}, "summary": {}}

    # Section 10: Recommended Focus Areas
    sections.append(_section_recommendations(import_result, complexity_result,
                                              topology_result, string_result, func_count))

    # Footer
    sections.append("---\n")
    sections.append(f"_Report generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} "
                   f"by generate-re-report skill_\n")
    sections.append(f"_Database: `{resolved}`_\n")

    return "\n".join(sections)


def generate_report_json(db_path: str, *, no_cache: bool = False) -> dict:
    """Generate a JSON report with all analysis data."""
    resolved = resolve_db_path(db_path)

    with db_error_handler(db_path, "loading module data for JSON report"):
        with open_analysis_db(db_path) as db:
            fi = db.get_file_info()
            func_count = db.count_functions()

    if not fi:
        emit_error("No file_info found in database", ErrorCode.NO_DATA)

    import_result = analyze_imports(db_path, no_cache=no_cache)
    export_result = analyze_exports(db_path)
    complexity_result = analyze_complexity(db_path, no_cache=no_cache)
    topology_result = analyze_topology(db_path, no_cache=no_cache)
    string_result = analyze_strings(db_path, no_cache=no_cache)

    return {
        "module": fi.file_name,
        "db_path": resolved,
        "generated_at": datetime.now().isoformat(),
        "function_count": func_count,
        "basic_info": {
            "file_name": fi.file_name,
            "file_description": fi.file_description,
            "company_name": fi.company_name,
            "file_version": fi.file_version,
            "product_name": fi.product_name,
            "pdb_path": fi.pdb_path,
            "is_net_assembly": fi.is_net_assembly,
            "compilation_timestamp": fi.time_date_stamp_str,
        },
        "security": {
            "features": parse_json_safe(fi.security_features),
            "dll_characteristics": parse_json_safe(fi.dll_characteristics),
            "load_config": parse_json_safe(fi.load_config),
            "canary_coverage": complexity_result.get("canary_coverage"),
        },
        "imports": import_result,
        "exports": export_result,
        "complexity": complexity_result,
        "topology": topology_result,
        "strings": string_result,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Generate a comprehensive RE report for a binary module"
    )
    parser.add_argument("db_path", help="Path to individual analysis DB")
    parser.add_argument("--output", "-o", type=str, default=None,
                        help="Write report to file (default: stdout)")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--summary", action="store_true",
                        help="Brief mode: sections 1, 3, 4, 10 only")
    parser.add_argument("--top", type=int, default=10,
                        help="Show top N in ranked tables (default: 10)")
    parser.add_argument("--no-cache", action="store_true",
                        help="Bypass all sub-analyzer caches")
    args = safe_parse_args(parser)

    if args.json:
        result = generate_report_json(args.db_path, no_cache=args.no_cache)
        if args.output:
            out_path = Path(args.output)
            if not out_path.is_absolute():
                out_path = WORKSPACE_ROOT / args.output
            out_path.parent.mkdir(parents=True, exist_ok=True)
            wrapped = {"status": "ok"}
            wrapped.update(result)
            out_path.write_text(json.dumps(wrapped, indent=2, default=str), encoding="utf-8")
            print(f"Report written to {out_path}", file=sys.stderr)
        else:
            emit_json(result, default=str)
    else:
        output = generate_report(args.db_path, top_n=args.top,
                                 summary_mode=args.summary, no_cache=args.no_cache)
        if args.output:
            out_path = Path(args.output)
            if not out_path.is_absolute():
                out_path = WORKSPACE_ROOT / args.output
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(output, encoding="utf-8")
            print(f"Report written to {out_path}", file=sys.stderr)
        else:
            print(output)


if __name__ == "__main__":
    main()
