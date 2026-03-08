#!/usr/bin/env python3
"""Build a comprehensive security context dossier for a function.

Gathers identity, attack reachability, untrusted data exposure, dangerous
operations, resource patterns, complexity assessment, and neighboring context
into a single structured report for pre-audit security review.

Usage:
    python build_dossier.py <db_path> <function_name>
    python build_dossier.py <db_path> --id <function_id>
    python build_dossier.py <db_path> --search <pattern>
    python build_dossier.py <db_path> <function_name> --json
    python build_dossier.py <db_path> <function_name> --callee-depth 2

Examples:
    python build_dossier.py extracted_dbs/appinfo_dll_e98d25a9e8.db AiCheckSecureApplicationDirectory
    python build_dossier.py extracted_dbs/cmd_exe_6d109a3a00.db --search "BatLoop"
    python build_dossier.py extracted_dbs/cmd_exe_6d109a3a00.db BatLoop --json

Output:
    A structured security dossier covering:
    1. Function Identity (name, signatures, class membership)
    2. Attack Reachability (exported? callers? path from entry points?)
    3. Untrusted Data Exposure (which callers are exports/entries?)
    4. Dangerous Operations (dangerous APIs, security-relevant callees by category)
    5. Resource Patterns (sync, memory, global state)
    6. Complexity Assessment (loops, branches, stack frame)
    7. Neighboring Context (class methods, call chain peers)
    8. Module Security Posture (ASLR, DEP, CFG, SEH)
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Optional

from _common import (
    WORKSPACE_ROOT,
    AsmMetrics,
    classify_api_security,
    emit_error,
    get_asm_metrics,
    has_real_decompiled,
    parse_json_safe,
    resolve_db_path,
)
from helpers.errors import ErrorCode, safe_parse_args
from helpers.cache import get_cached, cache_result
from helpers.callgraph import CallGraph
from helpers.json_output import emit_json

from helpers import (
    load_function_index_for_db,
    open_individual_analysis_db,
    resolve_function,
    search_functions_by_pattern,
    validate_function_id,
)
from helpers.errors import db_error_handler
from helpers.progress import status_message


# Thin wrappers preserving the original call signatures used in this module.

def find_function(db, name=None, fid=None, function_index=None):
    """Find a single function record. Returns (func, error_msg)."""
    return resolve_function(db, name=name, function_id=fid, function_index=function_index)


def search_functions(db, pattern, function_index=None):
    """Search for functions matching a pattern."""
    return search_functions_by_pattern(db, pattern, function_index=function_index)


# ---------------------------------------------------------------------------
# Dossier Builder
# ---------------------------------------------------------------------------

class DossierBuilder:
    """Builds a complete security context dossier for a single function."""

    def __init__(
        self,
        db_path: str,
        func,
        file_info,
        all_functions: list,
        callee_depth: int = 1,
    ) -> None:
        self.db_path = db_path
        self.func = func
        self.file_info = file_info
        self.all_functions = all_functions
        self.callee_depth = callee_depth

        # Build indexes
        self._func_by_id: dict[int, Any] = {}
        self._func_by_name: dict[str, list] = defaultdict(list)
        for f in all_functions:
            if f.function_name:
                self._func_by_id[f.function_id] = f
                self._func_by_name[f.function_name].append(f)

        # Build call graph
        self.graph = CallGraph.from_functions(all_functions)

        # Parse file-level data
        self.exports = _ensure_list(parse_json_safe(file_info.exports) if file_info else None)
        self.entry_points = _ensure_list(parse_json_safe(file_info.entry_point) if file_info else None)
        self.security_features = _ensure_dict(
            parse_json_safe(file_info.security_features) if file_info else None
        )

        # Parse function-level data
        self.fname = func.function_name or ""
        self.outbound = _ensure_list(parse_json_safe(func.simple_outbound_xrefs))
        self.inbound = _ensure_list(parse_json_safe(func.simple_inbound_xrefs))
        self.dangerous_apis = _ensure_list(parse_json_safe(func.dangerous_api_calls))
        self.globals_accessed = _ensure_list(parse_json_safe(func.global_var_accesses))
        self.strings = _ensure_list(parse_json_safe(func.string_literals))
        self.stack_frame = _ensure_dict(parse_json_safe(func.stack_frame))
        self.loop_analysis = _ensure_dict(parse_json_safe(func.loop_analysis))
        self.asm_metrics = get_asm_metrics(func.assembly_code)

        # Precompute export/entry name sets
        self._export_names: set[str] = set()
        for exp in self.exports:
            if isinstance(exp, dict):
                name = exp.get("function_name")
                if name:
                    self._export_names.add(name)

        self._entry_names: set[str] = set()
        for ep in self.entry_points:
            if isinstance(ep, dict):
                name = ep.get("function_name")
                if name:
                    self._entry_names.add(name)

        self._known_entries = self._export_names | self._entry_names

    def build(self) -> dict:
        """Build and return the complete dossier as a dict."""
        return {
            "identity": self._identity(),
            "reachability": self._reachability(),
            "data_exposure": self._data_exposure(),
            "dangerous_operations": self._dangerous_ops(),
            "resource_patterns": self._resources(),
            "complexity": self._complexity(),
            "neighboring_context": self._neighbors(),
            "module_security": self._module_security(),
        }

    # ---- Section builders ----

    def _identity(self) -> dict:
        class_name = None
        if "::" in self.fname:
            class_name = self.fname.rsplit("::", 1)[0]

        return {
            "function_id": self.func.function_id,
            "function_name": self.fname,
            "function_signature": self.func.function_signature,
            "function_signature_extended": self.func.function_signature_extended,
            "mangled_name": self.func.mangled_name,
            "class_name": class_name,
            "has_decompiled": has_real_decompiled(self.func.decompiled_code),
            "has_assembly": bool(self.func.assembly_code and self.func.assembly_code.strip()),
            "module_name": self.file_info.file_name if self.file_info else None,
            "module_description": self.file_info.file_description if self.file_info else None,
        }

    def _reachability(self) -> dict:
        is_exported = self.fname in self._export_names
        export_info = None
        if is_exported:
            for exp in self.exports:
                if isinstance(exp, dict) and exp.get("function_name") == self.fname:
                    export_info = {
                        "ordinal": exp.get("ordinal"),
                        "is_forwarded": exp.get("is_forwarded", False),
                    }
                    break

        is_entry = self.fname in self._entry_names

        # Direct callers (skip data/vtable refs -- not real callers)
        direct_callers = []
        for xref in self.inbound:
            if not isinstance(xref, dict):
                continue
            module = xref.get("module_name", "")
            ftype = xref.get("function_type", 0)
            if module in ("data", "vtable") or ftype in (4, 8):
                continue
            direct_callers.append({
                "name": xref.get("function_name", "?"),
                "id": xref.get("function_id"),
                "module": module,
                "is_internal": xref.get("function_id") is not None,
            })

        # Transitive callers (BFS upward)
        all_callers = self.graph.callers_of(self.fname, max_depth=10)
        transitive_count = max(0, len(all_callers) - 1)

        # Which callers are exports or entry points?
        reachable_exports = sorted(
            n for n in all_callers if n in self._export_names and n != self.fname
        )
        reachable_entries = sorted(
            n for n in all_callers if n in self._entry_names and n != self.fname
        )

        # Shortest path from any known entry to this function
        path_from_entry = self.graph.shortest_path_reverse(
            self.fname, self._known_entries, max_depth=10,
        )

        return {
            "is_exported": is_exported,
            "export_info": export_info,
            "is_entry_point": is_entry,
            "direct_callers": direct_callers,
            "direct_caller_count": len(direct_callers),
            "transitive_caller_count": transitive_count,
            "reachable_from_exports": reachable_exports,
            "reachable_from_entry_points": reachable_entries,
            "shortest_path_from_entry": path_from_entry,
            "externally_reachable": (
                is_exported or is_entry
                or bool(reachable_exports)
                or bool(reachable_entries)
            ),
        }

    def _data_exposure(self) -> dict:
        """Which export/entry callers can feed untrusted data to this function?"""
        callers = self.graph.callers_of(self.fname, max_depth=5)
        export_callers = [
            n for n in callers if n in self._export_names and n != self.fname
        ]

        data_paths = []
        for ec in export_callers[:5]:
            path = self.graph.shortest_path_reverse(self.fname, {ec}, max_depth=10)
            if path:
                data_paths.append({
                    "source_export": ec,
                    "path": path,
                    "hops": len(path) - 1,
                })

        # Rough parameter count from signature
        param_count = _count_params(
            self.func.function_signature_extended or self.func.function_signature
        )

        return {
            "export_callers_count": len(export_callers),
            "export_callers": export_callers,
            "data_paths": data_paths,
            "parameter_count": param_count,
            "receives_external_data": bool(export_callers) or self.fname in self._export_names,
        }

    def _dangerous_ops(self) -> dict:
        """Dangerous APIs in this function and its callees."""
        dangerous_direct = [a for a in self.dangerous_apis if isinstance(a, str)]

        # Classify outbound xrefs by security category
        security_callees: dict[str, list[str]] = defaultdict(list)
        all_callees: list[dict] = []
        for xref in self.outbound:
            if not isinstance(xref, dict):
                continue
            if xref.get("function_type", 0) in (4, 8):
                continue
            callee_name = xref.get("function_name", "")
            if not callee_name:
                continue

            all_callees.append({
                "name": callee_name,
                "module": xref.get("module_name", ""),
                "id": xref.get("function_id"),
                "is_internal": xref.get("function_id") is not None,
            })

            cat = classify_api_security(callee_name)
            if cat:
                security_callees[cat].append(callee_name)

        # Callee-depth analysis: gather dangerous APIs from internal callees
        callee_dangerous: dict[str, list[str]] = {}
        if self.callee_depth >= 1:
            for ci in all_callees:
                cid = ci.get("id")
                if cid is None:
                    continue
                callee_func = self._func_by_id.get(cid)
                if callee_func is None:
                    continue
                cdanger = _ensure_list(parse_json_safe(callee_func.dangerous_api_calls))
                if cdanger:
                    callee_dangerous[ci["name"]] = [a for a in cdanger if isinstance(a, str)]

                # Depth 2: also classify callee's outbound xrefs
                if self.callee_depth >= 2:
                    callee_out = _ensure_list(parse_json_safe(callee_func.simple_outbound_xrefs))
                    for cxref in callee_out:
                        if not isinstance(cxref, dict):
                            continue
                        if cxref.get("function_type", 0) in (4, 8):
                            continue
                        cname = cxref.get("function_name", "")
                        ccat = classify_api_security(cname)
                        if ccat:
                            security_callees[ccat].append(f"{ci['name']}->{cname}")

        # Deduplicate within each category
        for cat in security_callees:
            security_callees[cat] = sorted(set(security_callees[cat]))

        return {
            "dangerous_apis_direct": sorted(set(dangerous_direct)),
            "dangerous_api_count": len(set(dangerous_direct)),
            "security_relevant_callees": dict(security_callees),
            "callee_dangerous_apis": callee_dangerous,
            "total_callees": len(all_callees),
        }

    def _resources(self) -> dict:
        """Synchronization, memory, file ops, and global state access."""
        sync_ops: list[str] = []
        memory_ops: list[str] = []
        file_ops: list[str] = []
        for xref in self.outbound:
            if not isinstance(xref, dict):
                continue
            if xref.get("function_type", 0) in (4, 8):
                continue
            callee = xref.get("function_name", "")
            cat = classify_api_security(callee)
            if cat == "sync":
                sync_ops.append(callee)
            elif cat == "memory_alloc":
                memory_ops.append(callee)
            elif cat == "file_write":
                file_ops.append(callee)

        globals_list: list[dict] = []
        for g in self.globals_accessed:
            if isinstance(g, dict):
                globals_list.append({
                    "name": g.get("name", "?"),
                    "address": g.get("address", "?"),
                    "access_type": g.get("access_type", "?"),
                })
        reads = [g for g in globals_list if g["access_type"] == "Read"]
        writes = [g for g in globals_list if g["access_type"] == "Write"]

        return {
            "sync_operations": sorted(set(sync_ops)),
            "memory_operations": sorted(set(memory_ops)),
            "file_operations": sorted(set(file_ops)),
            "global_accesses_total": len(globals_list),
            "global_reads": len(reads),
            "global_writes": len(writes),
            "globals": globals_list[:50],
            "has_sync": bool(sync_ops),
            "has_memory_ops": bool(memory_ops),
            "has_global_writes": bool(writes),
        }

    def _complexity(self) -> dict:
        """Loop analysis, assembly metrics, stack frame."""
        loop_count = 0
        max_cyclomatic = 0
        total_loop_insns = 0
        has_infinite = False

        if self.loop_analysis:
            loop_count = self.loop_analysis.get("loop_count", 0) or 0
            loops = self.loop_analysis.get("loops", [])
            if isinstance(loops, list):
                for loop in loops:
                    if isinstance(loop, dict):
                        c = loop.get("cyclomatic_complexity", 0) or 0
                        if c > max_cyclomatic:
                            max_cyclomatic = c
                        total_loop_insns += loop.get("instruction_count", 0) or 0
                        if loop.get("is_infinite"):
                            has_infinite = True

        return {
            "instruction_count": self.asm_metrics.instruction_count,
            "call_count": self.asm_metrics.call_count,
            "branch_count": self.asm_metrics.branch_count,
            "ret_count": self.asm_metrics.ret_count,
            "loop_count": loop_count,
            "max_cyclomatic_complexity": max_cyclomatic,
            "total_loop_instructions": total_loop_insns,
            "has_infinite_loop": has_infinite,
            "local_vars_size": self.stack_frame.get("local_vars_size"),
            "args_size": self.stack_frame.get("args_size"),
            "saved_regs_size": self.stack_frame.get("saved_regs_size"),
            "has_canary": self.stack_frame.get("has_canary"),
            "has_exception_handler": self.stack_frame.get("exception_handler"),
            "frame_pointer_present": self.stack_frame.get("frame_pointer_present"),
            "string_count": len(self.strings),
            "strings_sample": self.strings[:15],
        }

    def _neighbors(self) -> dict:
        """Class methods and direct call chain peers."""
        class_name = None
        class_methods: list[dict] = []
        if "::" in self.fname:
            class_name = self.fname.rsplit("::", 1)[0]
            prefix = class_name + "::"
            for f in self.all_functions:
                if (
                    f.function_name
                    and f.function_name.startswith(prefix)
                    and f.function_name != self.fname
                ):
                    class_methods.append({
                        "name": f.function_name,
                        "id": f.function_id,
                        "has_decompiled": has_real_decompiled(f.decompiled_code),
                    })

        callees: list[dict] = []
        for xref in self.outbound:
            if not isinstance(xref, dict) or xref.get("function_type", 0) in (4, 8):
                continue
            callees.append({
                "name": xref.get("function_name", "?"),
                "id": xref.get("function_id"),
                "module": xref.get("module_name", ""),
                "is_internal": xref.get("function_id") is not None,
            })

        callers: list[dict] = []
        for xref in self.inbound:
            if not isinstance(xref, dict):
                continue
            module = xref.get("module_name", "")
            ftype = xref.get("function_type", 0)
            if module in ("data", "vtable") or ftype in (4, 8):
                continue
            callers.append({
                "name": xref.get("function_name", "?"),
                "id": xref.get("function_id"),
                "module": module,
                "is_internal": xref.get("function_id") is not None,
            })

        return {
            "class_name": class_name,
            "class_methods": class_methods,
            "class_method_count": len(class_methods),
            "direct_callees": callees,
            "direct_callee_count": len(callees),
            "direct_callers": callers,
            "direct_caller_count": len(callers),
        }

    def _module_security(self) -> dict:
        return {
            "aslr": self.security_features.get("aslr_enabled"),
            "dep": self.security_features.get("dep_enabled"),
            "cfg": self.security_features.get("cfg_enabled"),
            "seh": self.security_features.get("seh_enabled"),
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ensure_list(val: Any) -> list:
    return val if isinstance(val, list) else []


def _ensure_dict(val: Any) -> dict:
    return val if isinstance(val, dict) else {}


def _count_params(sig: Optional[str]) -> int:
    """Rough parameter count from a C-style function signature string."""
    if not sig or "(" not in sig:
        return 0
    try:
        inner = sig[sig.index("(") + 1:]
        if ")" in inner:
            inner = inner[:inner.index(")")]
        inner = inner.strip()
        if not inner or inner.lower() == "void":
            return 0
        return inner.count(",") + 1
    except Exception:
        return 0


def _hex_or_none(val: Any) -> str:
    if val is None:
        return "(unknown)"
    if isinstance(val, (int, float)):
        return f"0x{int(val):X} ({int(val)} bytes)"
    return str(val)


def _bool_str(val: Any) -> str:
    if val is None:
        return "(unknown)"
    return "Yes" if val else "No"


# ---------------------------------------------------------------------------
# Text Formatting
# ---------------------------------------------------------------------------

def format_text(dossier: dict, db_path: str) -> str:
    """Format the dossier as a human-readable text report."""
    lines: list[str] = []
    ident = dossier["identity"]
    reach = dossier["reachability"]
    exposure = dossier["data_exposure"]
    danger = dossier["dangerous_operations"]
    resources = dossier["resource_patterns"]
    complexity = dossier["complexity"]
    neighbors = dossier["neighboring_context"]
    mod_sec = dossier["module_security"]

    # Header
    lines.append("#" * 80)
    lines.append("  SECURITY CONTEXT DOSSIER")
    lines.append(f"  Function: {ident['function_name']}")
    lines.append(f"  Module:   {ident['module_name'] or '(unknown)'}")
    lines.append(f"  DB:       {Path(db_path).name}")
    lines.append("#" * 80)

    # 1. Identity
    _section(lines, "1. FUNCTION IDENTITY")
    lines.append(f"  Name:                {ident['function_name']}")
    lines.append(f"  Signature:           {ident['function_signature'] or '(none)'}")
    ext_sig = ident.get("function_signature_extended")
    if ext_sig and ext_sig != ident["function_signature"]:
        lines.append(f"  Extended Signature:  {ext_sig}")
    lines.append(f"  Mangled Name:        {ident['mangled_name'] or '(none)'}")
    lines.append(f"  Class:               {ident['class_name'] or '(standalone)'}")
    lines.append(f"  Has Decompiled Code: {'Yes' if ident['has_decompiled'] else 'No'}")
    lines.append(f"  Has Assembly:        {'Yes' if ident['has_assembly'] else 'No'}")
    if ident.get("module_description"):
        lines.append(f"  Module Description:  {ident['module_description']}")

    # 2. Reachability
    _section(lines, "2. ATTACK REACHABILITY")
    lines.append(f"  Is Exported:          {'YES' if reach['is_exported'] else 'No'}")
    lines.append(f"  Is Entry Point:       {'YES' if reach['is_entry_point'] else 'No'}")
    lines.append(f"  Externally Reachable: {'YES' if reach['externally_reachable'] else 'No'}")
    lines.append(f"  Direct Callers:       {reach['direct_caller_count']}")
    for c in reach["direct_callers"][:15]:
        tag = f"[internal, ID={c['id']}]" if c["is_internal"] else f"[external, {c['module']}]"
        lines.append(f"    <- {c['name']} {tag}")
    if reach["direct_caller_count"] > 15:
        lines.append(f"    ... and {reach['direct_caller_count'] - 15} more")
    lines.append(f"  Transitive Callers:   {reach['transitive_caller_count']} (within 10 hops)")
    if reach["reachable_from_exports"]:
        lines.append(f"\n  Reachable from Exports:")
        for name in reach["reachable_from_exports"][:10]:
            lines.append(f"    - {name}")
    if reach["reachable_from_entry_points"]:
        lines.append(f"\n  Reachable from Entry Points:")
        for name in reach["reachable_from_entry_points"][:10]:
            lines.append(f"    - {name}")
    if reach["shortest_path_from_entry"]:
        path = reach["shortest_path_from_entry"]
        lines.append(f"\n  Shortest Path from Entry ({len(path) - 1} hops):")
        lines.append(f"    {' -> '.join(path)}")

    # 3. Data Exposure
    _section(lines, "3. UNTRUSTED DATA EXPOSURE")
    lines.append(f"  Receives External Data: {'YES' if exposure['receives_external_data'] else 'No'}")
    lines.append(f"  Parameter Count:        {exposure['parameter_count']}")
    lines.append(f"  Export Callers:         {exposure['export_callers_count']}")
    for name in exposure.get("export_callers", [])[:10]:
        lines.append(f"    - {name}")
    if exposure["data_paths"]:
        lines.append(f"\n  Data Flow Paths from Exports:")
        for dp in exposure["data_paths"]:
            lines.append(f"    {dp['source_export']} -> ... -> {ident['function_name']} ({dp['hops']} hops)")
            lines.append(f"      Full: {' -> '.join(dp['path'])}")

    # 4. Dangerous Operations
    _section(lines, "4. DANGEROUS OPERATIONS")
    if danger["dangerous_apis_direct"]:
        lines.append(f"  Direct Dangerous APIs ({danger['dangerous_api_count']}):")
        for api in danger["dangerous_apis_direct"]:
            lines.append(f"    ! {api}")
    else:
        lines.append(f"  Direct Dangerous APIs: None")
    if danger["security_relevant_callees"]:
        lines.append(f"\n  Security-Relevant Callees (by category):")
        for cat, funcs in sorted(danger["security_relevant_callees"].items()):
            display = funcs[:10]
            suffix = f" ... +{len(funcs) - 10} more" if len(funcs) > 10 else ""
            lines.append(f"    [{cat}]: {', '.join(display)}{suffix}")
    if danger["callee_dangerous_apis"]:
        lines.append(f"\n  Callee Dangerous APIs (depth 1):")
        for cname, apis in sorted(danger["callee_dangerous_apis"].items()):
            lines.append(f"    {cname}: {', '.join(apis[:10])}")
    lines.append(f"\n  Total Callees: {danger['total_callees']}")

    # 5. Resources
    _section(lines, "5. RESOURCE PATTERNS")
    if resources["sync_operations"]:
        lines.append(f"  Synchronization:")
        for op in resources["sync_operations"]:
            lines.append(f"    - {op}")
    if resources["memory_operations"]:
        lines.append(f"  Memory Operations:")
        for op in resources["memory_operations"]:
            lines.append(f"    - {op}")
    if resources["file_operations"]:
        lines.append(f"  File Operations:")
        for op in resources["file_operations"]:
            lines.append(f"    - {op}")
    if not resources["sync_operations"] and not resources["memory_operations"] and not resources["file_operations"]:
        lines.append(f"  (no sync/memory/file operations detected)")
    lines.append(f"\n  Global Variable Accesses: {resources['global_accesses_total']}")
    lines.append(f"    Reads:  {resources['global_reads']}")
    lines.append(f"    Writes: {resources['global_writes']}")
    for g in resources.get("globals", [])[:20]:
        lines.append(f"    {g['access_type']:5s}  {g['name']} ({g['address']})")
    if resources["global_accesses_total"] > 20:
        lines.append(f"    ... and {resources['global_accesses_total'] - 20} more")

    # 6. Complexity
    _section(lines, "6. COMPLEXITY ASSESSMENT")
    lines.append(f"  Assembly Instructions:      {complexity['instruction_count']}")
    lines.append(f"  Call Count:                 {complexity['call_count']}")
    lines.append(f"  Branch Count:               {complexity['branch_count']}")
    lines.append(f"  Loop Count:                 {complexity['loop_count']}")
    lines.append(f"  Max Cyclomatic Complexity:  {complexity['max_cyclomatic_complexity']}")
    if complexity["has_infinite_loop"]:
        lines.append(f"  WARNING: Contains infinite loop")
    lines.append(f"  String Literals:            {complexity['string_count']}")
    if complexity.get("strings_sample"):
        for s in complexity["strings_sample"][:10]:
            display = s if len(s) <= 70 else s[:67] + "..."
            lines.append(f"    \"{display}\"")
        if complexity["string_count"] > 10:
            lines.append(f"    ... and {complexity['string_count'] - 10} more")
    lines.append(f"\n  Stack Frame:")
    lines.append(f"    Local Vars Size:    {_hex_or_none(complexity['local_vars_size'])}")
    lines.append(f"    Args Size:          {_hex_or_none(complexity['args_size'])}")
    lines.append(f"    Saved Regs:         {_hex_or_none(complexity['saved_regs_size'])}")
    lines.append(f"    Has Canary:         {_bool_str(complexity['has_canary'])}")
    lines.append(f"    Exception Handler:  {_bool_str(complexity['has_exception_handler'])}")

    # 7. Neighbors
    _section(lines, "7. NEIGHBORING CONTEXT")
    if neighbors["class_name"]:
        lines.append(f"  Class: {neighbors['class_name']} ({neighbors['class_method_count']} other methods)")
        for m in neighbors["class_methods"][:20]:
            dec = " [decompiled]" if m["has_decompiled"] else ""
            lines.append(f"    - {m['name']} (ID={m['id']}){dec}")
        if neighbors["class_method_count"] > 20:
            lines.append(f"    ... and {neighbors['class_method_count'] - 20} more")
    else:
        lines.append(f"  Class: (standalone function)")
    lines.append(f"\n  Direct Callees ({neighbors['direct_callee_count']}):")
    for c in neighbors["direct_callees"][:20]:
        tag = f"[internal, ID={c['id']}]" if c["is_internal"] else f"[{c['module']}]"
        lines.append(f"    -> {c['name']} {tag}")
    if neighbors["direct_callee_count"] > 20:
        lines.append(f"    ... and {neighbors['direct_callee_count'] - 20} more")

    # Module security footer
    _section(lines, "MODULE SECURITY POSTURE")
    lines.append(f"  ASLR: {_bool_str(mod_sec['aslr'])}")
    lines.append(f"  DEP:  {_bool_str(mod_sec['dep'])}")
    lines.append(f"  CFG:  {_bool_str(mod_sec['cfg'])}")
    lines.append(f"  SEH:  {_bool_str(mod_sec['seh'])}")

    # Footer
    lines.append(f"\n{'#' * 80}")
    lines.append(f"  END OF DOSSIER")
    lines.append(f"{'#' * 80}")

    return "\n".join(lines)


def _section(lines: list[str], title: str) -> None:
    lines.append(f"\n{'=' * 80}")
    lines.append(f"  {title}")
    lines.append(f"{'=' * 80}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build a security context dossier for a function.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("db_path", help="Path to the individual analysis DB")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--function", "--name", dest="function_name", metavar="NAME",
                       help="Function name")
    group.add_argument("--id", "--function-id", type=int, dest="function_id", help="Function ID")
    group.add_argument(
        "--search", dest="search_pattern",
        help="Search for functions matching a pattern",
    )
    parser.add_argument("function_name_pos", nargs="?", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--json", action="store_true", help="Output dossier as JSON")
    parser.add_argument(
        "--callee-depth", type=int, default=1,
        help="Depth for callee dangerous-API analysis (default: 1)",
    )
    parser.add_argument("--no-cache", action="store_true", help="Bypass result cache")
    args = safe_parse_args(parser)
    if args.function_name_pos and not args.function_name:
        args.function_name = args.function_name_pos

    if args.function_id is not None:
        args.function_id = validate_function_id(args.function_id)

    db_path = resolve_db_path(args.db_path)
    function_index = load_function_index_for_db(db_path)

    # Search mode
    if args.search_pattern:
        with db_error_handler(db_path, "searching functions for dossier"), \
                open_individual_analysis_db(db_path) as db:
            results = search_functions(db, args.search_pattern, function_index=function_index)
        if not results:
            if args.json:
                emit_json({"match_count": 0, "matches": [], "pattern": args.search_pattern})
                return
            emit_error(f"No functions matching '{args.search_pattern}' found.", ErrorCode.NOT_FOUND)
        if args.json:
            matches = [
                {
                    "function_id": func.function_id,
                    "function_name": func.function_name,
                    "signature": func.function_signature or "",
                }
                for func in results
            ]
            emit_json({"match_count": len(matches), "matches": matches, "pattern": args.search_pattern})
            return
        print(f"Found {len(results)} function(s) matching '{args.search_pattern}':\n")
        print(f"{'ID':>6}  {'Function Name':<50}  {'Signature'}")
        print(f"{'-' * 6}  {'-' * 50}  {'-' * 60}")
        for func in results[:30]:
            name = func.function_name or "(unnamed)"
            sig = func.function_signature or ""
            if len(sig) > 60:
                sig = sig[:57] + "..."
            print(f"{func.function_id:>6}  {name:<50}  {sig}")
        if len(results) > 30:
            print(f"\n... and {len(results) - 30} more")
        print(f"\nRun: python build_dossier.py {args.db_path} --id <ID>")
        return

    # Build mode
    status_message("Loading analysis database...")
    with db_error_handler(db_path, "building security dossier"), \
            open_individual_analysis_db(db_path) as db:
        func, err = find_function(
            db,
            name=args.function_name,
            fid=args.function_id,
            function_index=function_index,
        )
        if err:
            emit_error(f"[{Path(db_path).stem}] {err}", ErrorCode.NOT_FOUND)

        # Check cache before loading all functions (the expensive part)
        cache_params = {
            "function": func.function_name,
            "callee_depth": args.callee_depth,
        }
        if not args.no_cache:
            cached = get_cached(db_path, "security_dossier", params=cache_params)
            if cached is not None:
                if args.json:
                    emit_json(cached, default=str)
                else:
                    print(format_text(cached, db_path))
                return

        file_info = db.get_file_info()
        all_functions = db.get_all_functions()

    status_message(
        f"Building dossier for {func.function_name} "
        f"({len(all_functions)} functions in module)..."
    )

    builder = DossierBuilder(
        db_path=db_path,
        func=func,
        file_info=file_info,
        all_functions=all_functions,
        callee_depth=args.callee_depth,
    )
    dossier = builder.build()

    cache_result(db_path, "security_dossier", dossier, params=cache_params)

    if args.json:
        emit_json(dossier, default=str)
    else:
        print(format_text(dossier, db_path))


if __name__ == "__main__":
    main()
