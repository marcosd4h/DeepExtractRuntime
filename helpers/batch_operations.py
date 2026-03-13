"""Batch function loading and resolution utilities.

Higher-level primitives that compose the existing
:class:`IndividualAnalysisDB` batch methods to avoid the common
anti-pattern of calling ``get_function_by_id`` inside a loop.

Typical usage::

    from helpers.batch_operations import batch_extract_function_data

    with open_individual_analysis_db(db_path) as db:
        data = batch_extract_function_data(db, [10, 42, 99])
        for fid, info in data.items():
            process(info)
"""

from __future__ import annotations

from typing import Any, Optional, Union

from .individual_analysis_db import (
    FunctionRecord,
    IndividualAnalysisDB,
    parse_json_safe,
)


def _strip_keys(obj, keys):
    if isinstance(obj, dict):
        return {k: v for k, v in obj.items() if k not in keys}
    return obj


# ------------------------------------------------------------------
# Batch extract: full lifting-ready dicts for multiple functions
# ------------------------------------------------------------------

def batch_extract_function_data(
    db: IndividualAnalysisDB,
    function_ids: list[int],
) -> dict[int, dict[str, Any]]:
    """Load and parse lifting data for multiple functions in one query.

    Returns ``{function_id: parsed_dict}`` with the same fields produced
    by ``extract_function_data.py``'s ``_build_function_dict``:
    decompiled_code, assembly_code, xrefs, strings, stack_frame, etc.

    Missing IDs are silently omitted from the result.
    """
    if not function_ids:
        return {}

    records = db.get_functions_by_ids(function_ids)
    return {rec.function_id: _record_to_lifting_dict(rec) for rec in records}


def _record_to_lifting_dict(func: FunctionRecord) -> dict[str, Any]:
    """Convert a FunctionRecord into a flat, JSON-safe lifting dict."""
    return {
        "function_id": func.function_id,
        "function_name": func.function_name,
        "function_signature": func.function_signature,
        "function_signature_extended": func.function_signature_extended,
        "mangled_name": func.mangled_name,
        "decompiled_code": func.decompiled_code,
        "assembly_code": func.assembly_code,
        "string_literals": parse_json_safe(func.string_literals),
        "outbound_xrefs": parse_json_safe(func.simple_outbound_xrefs),
        "inbound_xrefs": parse_json_safe(func.simple_inbound_xrefs),
        "vtable_contexts": parse_json_safe(func.vtable_contexts),
        "global_var_accesses": parse_json_safe(func.global_var_accesses),
        "dangerous_api_calls": parse_json_safe(func.dangerous_api_calls),
        "stack_frame": _strip_keys(parse_json_safe(func.stack_frame), {"has_canary"}),
        "loop_analysis": parse_json_safe(func.loop_analysis),
    }


# ------------------------------------------------------------------
# Batch resolve: mixed names/IDs -> FunctionRecord
# ------------------------------------------------------------------

def batch_resolve_functions(
    db: IndividualAnalysisDB,
    identifiers: list[Union[str, int]],
) -> dict[Union[str, int], Optional[FunctionRecord]]:
    """Resolve a mixed list of function names and numeric IDs.

    Uses at most two DB queries (one ``get_functions_by_ids`` and one
    ``get_functions_by_names``) regardless of input size.

    Returns ``{identifier: FunctionRecord | None}`` preserving the
    original identifier as key.  ``None`` means the identifier could
    not be resolved.

    When a name matches multiple functions, the first match (by DB
    rowid order) is used and a warning is logged.  Callers that need
    precise disambiguation should use ``resolve_function()`` with
    ``--id`` instead.
    """
    if not identifiers:
        return {}

    ids: list[int] = []
    names: list[str] = []
    for ident in identifiers:
        if isinstance(ident, int):
            ids.append(ident)
        else:
            try:
                ids.append(int(ident))
            except (ValueError, TypeError):
                names.append(str(ident))

    result: dict[Union[str, int], Optional[FunctionRecord]] = {
        i: None for i in identifiers
    }

    if ids:
        by_id = {rec.function_id: rec for rec in db.get_functions_by_ids(ids)}
        for ident in identifiers:
            fid: Optional[int] = None
            if isinstance(ident, int):
                fid = ident
            else:
                try:
                    fid = int(ident)
                except (ValueError, TypeError):
                    pass
            if fid is not None and fid in by_id:
                result[ident] = by_id[fid]

    if names:
        from .errors import log_warning

        by_name = db.get_functions_by_names(names)
        for name in names:
            matches = by_name.get(name, [])
            if matches:
                result[name] = matches[0]
                if len(matches) > 1:
                    ids_preview = ", ".join(
                        str(m.function_id) for m in matches[:5]
                    )
                    log_warning(
                        f"Ambiguous name '{name}': {len(matches)} matches "
                        f"(IDs: {ids_preview}). Using first. "
                        f"Use --id for precise selection.",
                        "AMBIGUOUS",
                    )

    return result


# ------------------------------------------------------------------
# Batch xref resolution: collect outbound targets across functions
# ------------------------------------------------------------------

def load_function_record(
    db_path: str,
    function_name: str | None = None,
    function_id: int | None = None,
    *,
    include_detailed_xrefs: bool = False,
) -> dict[str, Any] | None:
    """Load a single function record as a flat dict from an analysis DB.

    Resolves via function index first, then falls back to DB lookup.
    Returns ``None`` only if the function cannot be found. Database and
    helper failures are raised as ``ScriptError`` so callers can surface
    infrastructure problems explicitly.

    When *include_detailed_xrefs* is True, the result also includes
    ``detailed_outbound_xrefs`` (parsed from ``outbound_xrefs``).

    This is the canonical implementation -- skill ``_common.py`` files
    should delegate here instead of duplicating the pattern.
    """
    from .errors import db_error_handler
    from .function_index import load_function_index_for_db
    from .function_resolver import resolve_function

    function_index = load_function_index_for_db(db_path)
    with db_error_handler(db_path, "loading function data", fatal=False):
        from .individual_analysis_db import open_individual_analysis_db
        from pathlib import Path

        with open_individual_analysis_db(db_path) as db:
            func, _err = resolve_function(
                db,
                name=function_name,
                function_id=function_id,
                function_index=function_index,
            )
            if not func:
                return None
            file_info = db.get_file_info()
            module_name = file_info.file_name if file_info else Path(db_path).stem

    result = {
        "function_id": func.function_id,
        "function_name": func.function_name,
        "function_signature": func.function_signature or "",
        "function_signature_extended": getattr(func, "function_signature_extended", None) or "",
        "decompiled_code": func.decompiled_code or "",
        "assembly_code": func.assembly_code or "",
        "module_name": module_name,
        "db_path": db_path,
        "outbound_xrefs": parse_json_safe(func.simple_outbound_xrefs) or [],
        "inbound_xrefs": parse_json_safe(func.simple_inbound_xrefs) or [],
        "global_var_accesses": parse_json_safe(func.global_var_accesses) or [],
        "string_literals": parse_json_safe(func.string_literals) or [],
    }
    if include_detailed_xrefs:
        result["detailed_outbound_xrefs"] = parse_json_safe(func.outbound_xrefs) or []
    return result


def load_all_functions_slim(db_path: str) -> list[dict[str, Any]]:
    """Load slim function records for module-wide scans.

    Returns only functions that have decompiled code, with fields:
    function_id, function_name, function_signature, decompiled_code,
    assembly_code, outbound_xrefs, inbound_xrefs, string_literals.

    Uses a targeted SELECT to avoid loading large unused columns.
    """
    from .errors import db_error_handler
    from .individual_analysis_db import open_individual_analysis_db

    records: list[dict[str, Any]] = []
    with db_error_handler(db_path, "loading all functions", fatal=False):
        with open_individual_analysis_db(db_path) as db:
            for row in db.get_decompiled_functions_slim():
                records.append({
                    "function_id": row["function_id"],
                    "function_name": row["function_name"],
                    "function_signature": row["function_signature"] or "",
                    "decompiled_code": row["decompiled_code"] or "",
                    "assembly_code": row["assembly_code"] or "",
                    "outbound_xrefs": parse_json_safe(row["simple_outbound_xrefs"]) or [],
                    "inbound_xrefs": parse_json_safe(row["simple_inbound_xrefs"]) or [],
                    "string_literals": parse_json_safe(row["string_literals"]) or [],
                })
    return records


DEFAULT_SEVERITY_BANDS: list[tuple[float, str]] = [
    (0.75, "CRITICAL"),
    (0.55, "HIGH"),
    (0.35, "MEDIUM"),
    (0.0, "LOW"),
]


def severity_label(
    score: float,
    bands: list[tuple[float, str]] | None = None,
) -> str:
    """Map a numeric score to a severity label using threshold bands.

    *bands* is a list of ``(threshold, label)`` tuples sorted descending
    by threshold.  The first band whose threshold is <= *score* wins.
    Defaults to CRITICAL/HIGH/MEDIUM/LOW at 0.75/0.55/0.35/0.0.
    """
    for threshold, label in (bands or DEFAULT_SEVERITY_BANDS):
        if score >= threshold:
            return label
    return "LOW"


# ------------------------------------------------------------------
# Batch xref resolution: collect outbound targets across functions
# ------------------------------------------------------------------

def batch_resolve_xref_targets(
    db: IndividualAnalysisDB,
    function_ids: list[int],
) -> dict[int, list[FunctionRecord]]:
    """For each source function, resolve internal outbound xref targets.

    1. Batch-loads the source functions.
    2. Collects all *internal* outbound xref target IDs (those with a
       non-null ``function_id`` in the xref entry).
    3. Batch-loads all target functions in one query.
    4. Returns ``{source_function_id: [target FunctionRecords]}``.

    External calls (those without a ``function_id``) are skipped.
    """
    if not function_ids:
        return {}

    sources = db.get_functions_by_ids(function_ids)
    source_map: dict[int, list[int]] = {}
    all_target_ids: set[int] = set()

    for func in sources:
        xrefs = parse_json_safe(func.simple_outbound_xrefs)
        if not isinstance(xrefs, list):
            source_map[func.function_id] = []
            continue
        target_ids = []
        for xref in xrefs:
            fid = xref.get("function_id") if isinstance(xref, dict) else None
            if fid is not None:
                target_ids.append(int(fid))
                all_target_ids.add(int(fid))
        source_map[func.function_id] = target_ids

    if not all_target_ids:
        return {fid: [] for fid in function_ids}

    targets_by_id = {
        rec.function_id: rec
        for rec in db.get_functions_by_ids(list(all_target_ids))
    }

    result: dict[int, list[FunctionRecord]] = {}
    for src_id in function_ids:
        target_ids = source_map.get(src_id, [])
        result[src_id] = [
            targets_by_id[tid] for tid in target_ids if tid in targets_by_id
        ]

    return result
