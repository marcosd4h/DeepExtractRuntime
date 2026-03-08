"""Unified function lookup and search.

Consolidates the index-exact -> index-partial -> DB-fallback pattern that
was previously duplicated across ~20 scripts in agents and skills.

Usage from any ``_common.py`` that already has ``sys.path`` configured::

    from helpers.function_resolver import resolve_function, search_functions_by_pattern

The resolver works with an **open** ``IndividualAnalysisDB`` instance so
callers retain full control over database lifecycle.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

from .function_index import get_function_id, search_index

if TYPE_CHECKING:
    from .individual_analysis_db import FunctionRecord, IndividualAnalysisDB


def resolve_function(
    db: IndividualAnalysisDB,
    *,
    name: Optional[str] = None,
    function_id: Optional[int] = None,
    function_index: Optional[dict[str, Any]] = None,
    allow_partial: bool = True,
    max_display: int = 20,
) -> tuple[Optional[FunctionRecord], Optional[str]]:
    """Unified function lookup: by ID, by name (exact/partial), with index fallback.

    Resolution order when *name* is provided:

    1. Exact match in *function_index* (O(1) dict lookup).
    2. Partial/substring match in *function_index* (if *allow_partial* is True).
    3. Exact name match via ``db.get_function_by_name()``.
    4. Substring match via ``db.search_functions(name_contains=...)``.

    When *function_id* is provided it takes priority and skips all name-based
    resolution.

    Args:
        db: An open ``IndividualAnalysisDB`` instance.
        name: Function name to search for.
        function_id: Direct function ID lookup (takes priority over *name*).
        function_index: Pre-loaded function_index dict (``{name: entry}``).
            Optional -- when absent, only DB-based lookup is performed.
        allow_partial: If ``True`` (default), attempt partial/substring
            matching in the function index.  Set to ``False`` to require
            exact matches only.
        max_display: Maximum number of matches to list in error messages
            when multiple functions match.

    Returns:
        ``(func, None)`` on success, or ``(None, error_message)`` on failure.
    """
    # --- By ID (fast path) ---------------------------------------------------
    if function_id is not None:
        func = db.get_function_by_id(function_id)
        if func is None:
            return None, f"No function with ID {function_id} found."
        return func, None

    # --- By name --------------------------------------------------------------
    if not name:
        return None, "Provide a function name or --id."

    # Step 1: Exact match in function_index
    if function_index:
        exact_entry = function_index.get(name)
        if exact_entry:
            fid = get_function_id(exact_entry)
            if fid is not None:
                func = db.get_function_by_id(fid)
                if func is not None:
                    return func, None

    # Step 2: Partial match in function_index
    if allow_partial and function_index:
        partial = search_index(function_index, name)
        if len(partial) == 1:
            _, entry = next(iter(partial.items()))
            fid = get_function_id(entry)
            if fid is not None:
                func = db.get_function_by_id(fid)
                if func is not None:
                    return func, None
        elif len(partial) > 1:
            lines = [f"Multiple matches for '{name}':"]
            for pname, entry in sorted(list(partial.items())[:max_display]):
                fid_val = get_function_id(entry)
                lines.append(f"  ID {fid_val if fid_val is not None else '?':>6}: {pname}")
            if len(partial) > max_display:
                lines.append(f"  ... and {len(partial) - max_display} more")
            lines.append("\nUse --id <ID> to select a specific function.")
            return None, "\n".join(lines)

    # Step 3: Exact name match via DB
    results = db.get_function_by_name(name)

    # Step 4: Substring match via DB
    if not results and allow_partial:
        results = db.search_functions(name_contains=name)

    if not results:
        return None, f"No function matching '{name}' found. Use --search to find available functions."

    if len(results) == 1:
        return results[0], None

    # Multiple DB matches
    lines = [f"Multiple matches for '{name}':"]
    for r in results[:max_display]:
        sig = r.function_signature or ""
        if len(sig) > 60:
            sig = sig[:57] + "..."
        lines.append(f"  ID {r.function_id:>6}: {r.function_name}  {sig}")
    if len(results) > max_display:
        lines.append(f"  ... and {len(results) - max_display} more")
    lines.append("\nUse --id <ID> to select a specific function.")
    return None, "\n".join(lines)


def search_functions_by_pattern(
    db: IndividualAnalysisDB,
    pattern: str,
    *,
    function_index: Optional[dict[str, Any]] = None,
) -> list:
    """Search for functions matching *pattern* via index then DB fallback.

    Resolution order:

    1. Substring search in *function_index*, resolved to full records via
       ``db.get_functions_by_ids()``.
    2. Fallback to DB-backed function-name and signature searches.

    Args:
        db: An open ``IndividualAnalysisDB`` instance.
        pattern: Search term (substring match).
        function_index: Pre-loaded function_index dict.  Optional.

    Returns:
        List of ``FunctionRecord`` objects (may be empty).
    """
    if function_index:
        matches = search_index(function_index, pattern)
        fids = [
            fid for entry in matches.values()
            if (fid := get_function_id(entry)) is not None
        ]
        if fids:
            resolved = db.get_functions_by_ids(fids)
            if resolved:
                return resolved

    # Without a function index, search both names and signatures and
    # deduplicate by function_id so name-only matches are not lost.
    results: list[FunctionRecord] = []
    seen_ids: set[int] = set()

    for func in db.search_functions(name_contains=pattern):
        if func.function_id not in seen_ids:
            results.append(func)
            seen_ids.add(func.function_id)

    for func in db.search_functions(signature_contains=pattern):
        if func.function_id not in seen_ids:
            results.append(func)
            seen_ids.add(func.function_id)

    return results
