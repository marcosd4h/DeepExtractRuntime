#!/usr/bin/env python3
"""Unified search across all analysis dimensions for a module DB.

Searches function names, signatures, string literals, API calls, dangerous
APIs, class names, and exports in a single invocation.  Supports substring
(default), regex, and fuzzy matching modes with relevance-ranked results.

Usage:
    python unified_search.py <db_path> --query <search_term>
    python unified_search.py <db_path> --query "CreateProcess"
    python unified_search.py <db_path> --query "CreateProcess" --json
    python unified_search.py <db_path> --query "registry" --limit 20
    python unified_search.py <db_path> --query "CheckToken" --dimensions name,api,string
    python unified_search.py <db_path> --query "^Ai.*Process$" --regex
    python unified_search.py <db_path> --query "CreateProces" --fuzzy
    python unified_search.py <db_path> --query "CreateProcess" --sort score

Examples:
    # Search everything for "CreateProcess"
    python unified_search.py extracted_dbs/appinfo_dll_f2bbf324a1.db --query "CreateProcess"

    # Regex: find functions matching a pattern
    python unified_search.py extracted_dbs/appinfo_dll_f2bbf324a1.db --query "^Ai.*Process$" --regex

    # Fuzzy: typo-tolerant search
    python unified_search.py extracted_dbs/appinfo_dll_f2bbf324a1.db --query "CreateProces" --fuzzy

    # Fuzzy with custom threshold (0.0-1.0, default 0.6)
    python unified_search.py extracted_dbs/appinfo_dll_f2bbf324a1.db --query "CretFle" --fuzzy --threshold 0.5

    # JSON output for programmatic consumption
    python unified_search.py extracted_dbs/cmd_exe_6d109a3a00.db --query "Bat" --json

    # Restrict to name and signature matches only
    python unified_search.py extracted_dbs/appinfo_dll_f2bbf324a1.db --query "Launch" --dimensions name,signature

    # Search across all modules (auto-discovers DBs)
    python unified_search.py --all --query "CreateProcess"

    # Sort by relevance score
    python unified_search.py extracted_dbs/appinfo_dll_f2bbf324a1.db --query "Process" --sort score

Modes:
    substring  - Case-insensitive substring match (default)
    regex      - Python regex via re.search()
    fuzzy      - Fuzzy matching via difflib.SequenceMatcher

Dimensions:
    name       - Function name match (via index + DB)
    signature  - Function signature match (DB)
    string     - String literal content match (DB JSON field)
    api        - Outbound API call name match (DB JSON field)
    dangerous  - Dangerous API call match (DB JSON field)
    class      - C++ class name from mangled names (DB)
    export     - Export name match (file_info table)

Output:
    Grouped results by match dimension with function ID, name, relevance
    score, and match context.  Summary counts per dimension.  With --json,
    emits a structured JSON object for direct consumption by other scripts.
"""

from __future__ import annotations

import argparse
import enum
import re
import sys
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Workspace bootstrap -- use the same pattern as other standalone scripts.
# helpers/ is one level below the runtime root.
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).resolve().parent
_RUNTIME_ROOT = _SCRIPT_DIR.parent
if str(_RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(_RUNTIME_ROOT))

from helpers.db_paths import _auto_workspace_root  # noqa: E402
_WORKSPACE_ROOT = _auto_workspace_root()

from helpers.errors import ErrorCode, log_warning  # noqa: E402
from helpers.json_output import emit_json  # noqa: E402
from helpers.progress import status_message  # noqa: E402
from helpers.individual_analysis_db import open_individual_analysis_db, parse_json_safe, escape_like, LIKE_ESCAPE  # noqa: E402
from helpers.function_index import (  # noqa: E402
    get_function_id,
    has_assembly,
    has_decompiled,
    load_function_index_for_db,
    search_index,
)

ALL_DIMENSIONS = ("name", "signature", "string", "api", "dangerous", "class", "export", "import")
DEFAULT_DIMENSIONS = ALL_DIMENSIONS
DEFAULT_FUZZY_THRESHOLD = 0.6


# ---------------------------------------------------------------------------
# Search mode enum
# ---------------------------------------------------------------------------

class MatchMode(enum.Enum):
    """Search matching strategy."""
    SUBSTRING = "substring"
    REGEX = "regex"
    FUZZY = "fuzzy"


# ---------------------------------------------------------------------------
# Match engine
# ---------------------------------------------------------------------------

_REGEX_SPECIAL = frozenset(r'\.[]{}()*+?|^$')


def _extract_literal_prefix(pattern: str) -> Optional[str]:
    """Return a literal safe for regex prefiltering, or ``None``.

    The returned string is used as a mandatory SQL ``LIKE`` prefilter before
    running the full regex in Python, so correctness matters more than
    aggressiveness.  Only plain-literal regexes (optionally wrapped in ``^``
    / ``$`` anchors and escaped literal punctuation) are eligible.
    """
    if not pattern:
        return None

    candidate = pattern
    if candidate.startswith("^"):
        candidate = candidate[1:]
    if candidate.endswith("$"):
        candidate = candidate[:-1]
    if not candidate:
        return None

    literal: list[str] = []
    i = 0
    while i < len(candidate):
        ch = candidate[i]
        if ch == "\\":
            if i + 1 >= len(candidate):
                return None
            next_ch = candidate[i + 1]
            if next_ch in _REGEX_SPECIAL or next_ch == "\\":
                literal.append(next_ch)
                i += 2
                continue
            return None
        if ch in _REGEX_SPECIAL:
            return None
        literal.append(ch)
        i += 1

    extracted = "".join(literal)
    if len(extracted) < 3:
        return None
    return extracted


def _match(text: str, query: str, mode: MatchMode, *,
           case_sensitive: bool = False,
           fuzzy_threshold: float = DEFAULT_FUZZY_THRESHOLD) -> tuple[bool, float]:
    """Return ``(matched, quality_score)`` for *text* against *query*.

    Quality scores reflect match precision:
      - exact match: 1.0
      - prefix match: 0.85
      - word-boundary match (at ``_`` or camelCase transition): 0.75
      - plain substring: 0.6
      - fuzzy: 0.3 + ratio * 0.25
    """
    if not text:
        return (False, 0.0)

    if mode == MatchMode.SUBSTRING:
        t = text if case_sensitive else text.lower()
        q = query if case_sensitive else query.lower()
        if t == q:
            return (True, 1.0)
        if t.startswith(q):
            return (True, 0.85)
        idx = t.find(q)
        if idx >= 0:
            if idx > 0 and (text[idx - 1] == '_' or
                            (text[idx - 1].islower() and text[idx].isupper())):
                return (True, 0.75)
            return (True, 0.6)
        return (False, 0.0)

    elif mode == MatchMode.REGEX:
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            m = re.search(query, text, flags)
        except re.error as exc:
            log_warning(f"Invalid regex in _match: '{query}': {exc}", ErrorCode.PARSE_ERROR)
            return (False, 0.0)
        if m:
            match_len = len(m.group())
            text_len = max(len(text), 1)
            if match_len == text_len:
                return (True, 1.0)
            ratio = match_len / text_len
            return (True, min(0.6 + ratio * 0.4, 0.99))
        return (False, 0.0)

    elif mode == MatchMode.FUZZY:
        t = text if case_sensitive else text.lower()
        q = query if case_sensitive else query.lower()
        if t == q:
            return (True, 1.0)
        if t.startswith(q):
            return (True, 0.85)
        if q in t:
            return (True, 0.6)
        ratio = SequenceMatcher(None, q, t).ratio()
        if ratio >= fuzzy_threshold:
            return (True, 0.3 + ratio * 0.25)
        return (False, 0.0)

    return (False, 0.0)


# ---------------------------------------------------------------------------
# Relevance scoring
# ---------------------------------------------------------------------------

def _score_result(match_quality: float, *,
                  is_app_code: bool = True,
                  has_decompiled_code: bool = False,
                  is_export: bool = False,
                  has_dangerous_apis: bool = False) -> float:
    """Compute composite relevance from match quality and context signals.

    Score range 0.0 - 1.0:
      - Match quality contributes 0 - 0.5 (50 % weight).
      - Context signals contribute up to 0.5:
          application code: +0.15, decompiled: +0.1, export: +0.1,
          dangerous APIs: +0.05.
    """
    score = match_quality * 0.5
    if is_app_code:
        score += 0.15
    if has_decompiled_code:
        score += 0.1
    if is_export:
        score += 0.1
    if has_dangerous_apis:
        score += 0.05
    return min(round(score, 4), 1.0)


def _build_json_prefilter(column: str, query: str, mode: MatchMode,
                          *, extra_excludes: str = "") -> tuple[str, tuple]:
    """Build a SQL WHERE clause for pre-filtering JSON text columns.

    Returns ``(where_clause, params)`` for use in ``execute_query``.
    For substring mode uses ``LIKE '%query%'``.  For regex mode tries to
    extract a literal for LIKE narrowing.  Fuzzy mode fetches all non-null
    rows (filtered in Python).
    """
    base = (
        f"{column} IS NOT NULL "
        f"AND {column} != '' "
        f"AND {column} NOT LIKE 'null%'"
    )
    if extra_excludes:
        base = f"{base} AND {extra_excludes}"

    if mode == MatchMode.SUBSTRING:
        return f"{base} AND {column} LIKE ? COLLATE NOCASE{LIKE_ESCAPE}", (f"%{escape_like(query)}%",)
    elif mode == MatchMode.REGEX:
        literal = _extract_literal_prefix(query)
        if literal:
            return f"{base} AND {column} LIKE ? COLLATE NOCASE{LIKE_ESCAPE}", (f"%{escape_like(literal)}%",)
        return base, ()
    else:
        prefix = query[:3] if len(query) >= 3 else query
        return (
            f"{base} AND {column} LIKE ? COLLATE NOCASE{LIKE_ESCAPE}",
            (f"%{escape_like(prefix)}%",),
        )


def _match_context_label(query: str, mode: MatchMode, dimension: str) -> str:
    """Build a human-readable match-context prefix."""
    if mode == MatchMode.REGEX:
        return f"{dimension} matches /{query}/"
    elif mode == MatchMode.FUZZY:
        return f"{dimension} ~= '{query}'"
    return f"{dimension} contains '{query}'"


# ---------------------------------------------------------------------------
# Search result container
# ---------------------------------------------------------------------------

class UnifiedSearchResults:
    """Accumulates, deduplicates, and ranks search results across dimensions."""

    def __init__(self, search_mode: str = "substring") -> None:
        self.results: dict[str, list[dict[str, Any]]] = {d: [] for d in ALL_DIMENSIONS}
        self._seen: dict[str, set[tuple[int, str]]] = {
            d: set() for d in ALL_DIMENSIONS
        }
        self.search_mode = search_mode

    @staticmethod
    def _result_key(function_id: int, function_name: str) -> tuple[int, str]:
        """Build a stable dedup key for resolved and unresolved matches."""
        if function_id >= 0:
            return (function_id, "")
        return (function_id, function_name.casefold())

    def add(self, dimension: str, function_id: int, function_name: str,
            match_context: str, *, relevance_score: float = 0.0,
            **extra: Any) -> None:
        key = self._result_key(function_id, function_name)
        if key in self._seen[dimension]:
            return
        self._seen[dimension].add(key)
        entry = {
            "function_id": function_id,
            "function_name": function_name,
            "match_context": match_context,
            "relevance_score": round(relevance_score, 4),
            **extra,
        }
        self.results[dimension].append(entry)

    def apply_multi_dimension_bonus(self) -> None:
        """Boost scores for functions appearing in multiple dimensions."""
        key_dim_count: dict[tuple[int, str], int] = {}
        for dim_keys in self._seen.values():
            for key in dim_keys:
                key_dim_count[key] = key_dim_count.get(key, 0) + 1
        for dim_results in self.results.values():
            for entry in dim_results:
                key = self._result_key(
                    entry["function_id"], entry.get("function_name", "")
                )
                dim_count = key_dim_count.get(key, 1)
                if dim_count > 1:
                    bonus = min(dim_count * 0.05, 0.15)
                    entry["relevance_score"] = min(
                        round(entry["relevance_score"] + bonus, 4), 1.0
                    )

    def sort_by_relevance(self) -> None:
        """Sort results within each dimension by relevance_score descending."""
        for dim in self.results:
            self.results[dim].sort(
                key=lambda e: (-e.get("relevance_score", 0.0),
                               e.get("function_name", ""))
            )

    def sort_by_name(self) -> None:
        """Sort results within each dimension alphabetically."""
        for dim in self.results:
            self.results[dim].sort(
                key=lambda e: e.get("function_name", "").lower()
            )

    def sort_by_id(self) -> None:
        """Sort results within each dimension by function_id."""
        for dim in self.results:
            self.results[dim].sort(key=lambda e: e.get("function_id", 0))

    def total_unique_functions(self) -> int:
        all_keys: set[tuple[int, str]] = set()
        for dim_keys in self._seen.values():
            all_keys |= dim_keys
        return len(all_keys)

    def dimension_counts(self) -> dict[str, int]:
        return {d: len(r) for d, r in self.results.items() if r}

    def has_results(self) -> bool:
        return any(r for r in self.results.values())

    def to_flat_list(self) -> list[dict[str, Any]]:
        """Deduplicated flat list of results across all dimensions.

        Each entry gets a ``dimension`` field.  When the same function_id
        appears in multiple dimensions only the highest-scored entry is kept.
        """
        best: dict[tuple[int, str], dict[str, Any]] = {}
        for dim, entries in self.results.items():
            for entry in entries:
                key = self._result_key(
                    entry.get("function_id", -1), entry.get("function_name", "")
                )
                tagged = {**entry, "dimension": dim}
                if key not in best:
                    best[key] = tagged
                elif entry.get("relevance_score", 0) > best[key].get("relevance_score", 0):
                    best[key] = tagged
        return sorted(best.values(),
                       key=lambda e: (-e.get("relevance_score", 0),
                                      e.get("function_name", "")))

    def to_dict(self) -> dict[str, Any]:
        return {
            "search_mode": self.search_mode,
            "total_unique_functions": self.total_unique_functions(),
            "dimension_counts": self.dimension_counts(),
            "results": {d: r for d, r in self.results.items() if r},
            "results_flat": self.to_flat_list(),
        }


# ---------------------------------------------------------------------------
# Search implementations per dimension
# ---------------------------------------------------------------------------

def _search_names(db, function_index: Optional[dict], query: str,
                  results: UnifiedSearchResults, limit: int,
                  mode: MatchMode = MatchMode.SUBSTRING,
                  fuzzy_threshold: float = DEFAULT_FUZZY_THRESHOLD) -> None:
    """Search function names via JSON index (fast) and DB fallback."""
    found_ids: set[int] = set()
    ctx = _match_context_label(query, mode, "name")

    if function_index:
        matches = search_index(function_index, query,
                               mode=mode.value,
                               fuzzy_threshold=fuzzy_threshold)
        for fname, entry in matches.items():
            fid = get_function_id(entry)
            if fid is None:
                continue
            _, mq = _match(fname, query, mode, fuzzy_threshold=fuzzy_threshold)
            is_app = entry.get("library") is None
            has_dec = has_decompiled(entry)
            score = _score_result(mq, is_app_code=is_app,
                                  has_decompiled_code=has_dec)
            results.add("name", fid, fname, ctx,
                         relevance_score=score,
                         has_decompiled=has_dec,
                         has_assembly=has_assembly(entry),
                         library=entry.get("library"))
            found_ids.add(fid)
            if len(found_ids) >= limit:
                return

    remaining = limit - len(found_ids)
    if remaining > 0:
        if mode == MatchMode.SUBSTRING:
            db_matches = db.search_functions(name_contains=query)
        elif mode == MatchMode.REGEX:
            literal = _extract_literal_prefix(query)
            if literal:
                db_matches = db.search_functions(name_contains=literal)
            else:
                db_matches = db.iter_functions(batch_size=500)
        else:
            db_matches = db.iter_functions(batch_size=500)

        for func in db_matches:
            if func.function_id in found_ids:
                continue
            fname = func.function_name or ""
            matched, mq = _match(fname, query, mode,
                                 fuzzy_threshold=fuzzy_threshold)
            if not matched:
                continue
            score = _score_result(mq,
                                  has_decompiled_code=bool(func.decompiled_code))
            results.add("name", func.function_id, fname or "(unnamed)", ctx,
                         relevance_score=score,
                         has_decompiled=bool(func.decompiled_code),
                         has_assembly=bool(func.assembly_code))
            found_ids.add(func.function_id)
            if len(found_ids) >= limit:
                return


def _search_signatures(db, query: str, results: UnifiedSearchResults, limit: int,
                       mode: MatchMode = MatchMode.SUBSTRING,
                       fuzzy_threshold: float = DEFAULT_FUZZY_THRESHOLD) -> None:
    """Search function signatures."""
    if mode == MatchMode.SUBSTRING:
        sql = ("SELECT function_id, function_name, function_signature "
               "FROM functions "
               "WHERE function_signature LIKE ? COLLATE NOCASE" + LIKE_ESCAPE)
        rows = db.execute_query(sql, (f"%{escape_like(query)}%",))
    elif mode == MatchMode.REGEX:
        literal = _extract_literal_prefix(query)
        if literal:
            sql = ("SELECT function_id, function_name, function_signature "
                   "FROM functions "
                   "WHERE function_signature LIKE ? COLLATE NOCASE" + LIKE_ESCAPE)
            rows = db.execute_query(sql, (f"%{escape_like(literal)}%",))
        else:
            sql = ("SELECT function_id, function_name, function_signature "
                   "FROM functions "
                   "WHERE function_signature IS NOT NULL")
            rows = db.execute_query(sql)
    else:
        sql = ("SELECT function_id, function_name, function_signature "
               "FROM functions "
               "WHERE function_signature IS NOT NULL")
        rows = db.execute_query(sql)

    count = 0
    for row in rows:
        if count >= limit:
            break
        sig = row["function_signature"] or ""
        matched, mq = _match(sig, query, mode, fuzzy_threshold=fuzzy_threshold)
        if not matched:
            continue
        score = _score_result(mq)
        results.add("signature", row["function_id"],
                     row["function_name"] or "(unnamed)",
                     _highlight_match(sig, query, mode),
                     relevance_score=score)
        count += 1


def _search_strings(db, query: str, results: UnifiedSearchResults, limit: int,
                    mode: MatchMode = MatchMode.SUBSTRING,
                    fuzzy_threshold: float = DEFAULT_FUZZY_THRESHOLD) -> None:
    """Search string literals embedded in functions.

    Uses a fast SQL pre-filter on the raw JSON text column, then parses
    matching rows to extract the specific strings.
    """
    where, params = _build_json_prefilter("string_literals", query, mode)
    sql = f"SELECT function_id, function_name, string_literals FROM functions WHERE {where}"
    rows = db.execute_query(sql, params)
    count = 0
    for row in rows:
        if count >= limit:
            break
        strings = parse_json_safe(row["string_literals"])
        if not strings or not isinstance(strings, list):
            continue
        matching = []
        best_mq = 0.0
        for s in strings:
            if not isinstance(s, str):
                continue
            hit, mq = _match(s, query, mode, fuzzy_threshold=fuzzy_threshold)
            if hit:
                matching.append(s)
                best_mq = max(best_mq, mq)
        if matching:
            preview = matching[0]
            if len(preview) > 80:
                preview = preview[:77] + "..."
            extra_count = f" (+{len(matching) - 1} more)" if len(matching) > 1 else ""
            score = _score_result(best_mq)
            results.add("string", row["function_id"],
                         row["function_name"] or "(unnamed)",
                         f'string: "{preview}"{extra_count}',
                         relevance_score=score)
            count += 1


def _search_apis(db, query: str, results: UnifiedSearchResults, limit: int,
                 mode: MatchMode = MatchMode.SUBSTRING,
                 fuzzy_threshold: float = DEFAULT_FUZZY_THRESHOLD) -> None:
    """Search outbound API calls by name.

    Pre-filters on the raw simple_outbound_xrefs JSON column, then parses
    to extract matching API names.
    """
    where, params = _build_json_prefilter("simple_outbound_xrefs", query, mode)
    sql = f"SELECT function_id, function_name, simple_outbound_xrefs FROM functions WHERE {where}"
    rows = db.execute_query(sql, params)
    count = 0
    for row in rows:
        if count >= limit:
            break
        xrefs = parse_json_safe(row["simple_outbound_xrefs"])
        if not xrefs or not isinstance(xrefs, list):
            continue
        matching_apis = []
        best_mq = 0.0
        for xref in xrefs:
            if not isinstance(xref, dict):
                continue
            api_name = xref.get("function_name", "")
            hit, mq = _match(api_name, query, mode,
                             fuzzy_threshold=fuzzy_threshold)
            if hit:
                module = xref.get("module_name", "")
                label = f"{api_name} (in {module})" if module else api_name
                matching_apis.append(label)
                best_mq = max(best_mq, mq)
        if matching_apis:
            preview = matching_apis[0]
            extra = f" (+{len(matching_apis) - 1} more)" if len(matching_apis) > 1 else ""
            score = _score_result(best_mq)
            results.add("api", row["function_id"],
                         row["function_name"] or "(unnamed)",
                         f"calls: {preview}{extra}",
                         relevance_score=score)
            count += 1


def _search_dangerous_apis(db, query: str, results: UnifiedSearchResults, limit: int,
                           mode: MatchMode = MatchMode.SUBSTRING,
                           fuzzy_threshold: float = DEFAULT_FUZZY_THRESHOLD) -> None:
    """Search dangerous API calls by name."""
    where, params = _build_json_prefilter(
        "dangerous_api_calls", query, mode,
        extra_excludes="dangerous_api_calls NOT LIKE '[]%'",
    )
    sql = f"SELECT function_id, function_name, dangerous_api_calls FROM functions WHERE {where}"
    rows = db.execute_query(sql, params)
    count = 0
    for row in rows:
        if count >= limit:
            break
        apis = parse_json_safe(row["dangerous_api_calls"])
        if not apis or not isinstance(apis, list):
            continue
        matching = []
        best_mq = 0.0
        for a in apis:
            if not isinstance(a, str):
                continue
            hit, mq = _match(a, query, mode, fuzzy_threshold=fuzzy_threshold)
            if hit:
                matching.append(a)
                best_mq = max(best_mq, mq)
        if matching:
            preview = ", ".join(matching[:3])
            extra = f" (+{len(matching) - 3} more)" if len(matching) > 3 else ""
            score = _score_result(best_mq, has_dangerous_apis=True)
            results.add("dangerous", row["function_id"],
                         row["function_name"] or "(unnamed)",
                         f"dangerous: {preview}{extra}",
                         relevance_score=score)
            count += 1


def _search_classes(db, query: str, results: UnifiedSearchResults, limit: int,
                    mode: MatchMode = MatchMode.SUBSTRING,
                    fuzzy_threshold: float = DEFAULT_FUZZY_THRESHOLD) -> None:
    """Search C++ class names from mangled names and vtable contexts.

    Matches against class names extracted from IDA mangled name prefixes
    (e.g., ??0ClassName@@) and vtable context class fields.
    """
    found_ids: set[int] = set()

    # Search mangled names for class patterns
    if mode == MatchMode.SUBSTRING:
        sql_mangled = (
            "SELECT function_id, function_name, mangled_name "
            "FROM functions "
            "WHERE mangled_name IS NOT NULL "
            "  AND mangled_name LIKE ? COLLATE NOCASE" + LIKE_ESCAPE)
        rows = db.execute_query(sql_mangled, (f"%{escape_like(query)}%",))
    elif mode == MatchMode.REGEX:
        literal = _extract_literal_prefix(query)
        if literal:
            sql_mangled = (
                "SELECT function_id, function_name, mangled_name "
                "FROM functions "
                "WHERE mangled_name IS NOT NULL "
                "  AND mangled_name LIKE ? COLLATE NOCASE" + LIKE_ESCAPE)
            rows = db.execute_query(sql_mangled, (f"%{escape_like(literal)}%",))
        else:
            sql_mangled = (
                "SELECT function_id, function_name, mangled_name "
                "FROM functions "
                "WHERE mangled_name IS NOT NULL")
            rows = db.execute_query(sql_mangled)
    else:
        sql_mangled = (
            "SELECT function_id, function_name, mangled_name "
            "FROM functions "
            "WHERE mangled_name IS NOT NULL")
        rows = db.execute_query(sql_mangled)

    for row in rows:
        if len(found_ids) >= limit:
            break
        mangled = row["mangled_name"] or ""
        class_name = _extract_class_from_mangled(mangled)
        if not class_name:
            continue
        hit, mq = _match(class_name, query, mode,
                         fuzzy_threshold=fuzzy_threshold)
        if hit:
            score = _score_result(mq)
            results.add("class", row["function_id"],
                         row["function_name"] or "(unnamed)",
                         f"class: {class_name} (mangled: {mangled[:60]})",
                         relevance_score=score)
            found_ids.add(row["function_id"])

    # Search vtable contexts for class names
    remaining = limit - len(found_ids)
    if remaining > 0:
        where, params = _build_json_prefilter("vtable_contexts", query, mode)
        sql_vtable = (
            f"SELECT function_id, function_name, vtable_contexts "
            f"FROM functions WHERE {where}"
        )
        rows = db.execute_query(sql_vtable, params)
        for row in rows:
            if row["function_id"] in found_ids:
                continue
            if len(found_ids) >= limit:
                break
            vtables = parse_json_safe(row["vtable_contexts"])
            if not vtables:
                continue
            class_names = _extract_classes_from_vtable(vtables, query, mode,
                                                      fuzzy_threshold)
            if class_names:
                preview = ", ".join(class_names[:3])
                best_mq = max(
                    _match(cn, query, mode, fuzzy_threshold=fuzzy_threshold)[1]
                    for cn in class_names
                )
                score = _score_result(best_mq)
                results.add("class", row["function_id"],
                             row["function_name"] or "(unnamed)",
                             f"vtable class: {preview}",
                             relevance_score=score)
                found_ids.add(row["function_id"])


def _search_exports(db, query: str, results: UnifiedSearchResults, limit: int,
                    mode: MatchMode = MatchMode.SUBSTRING,
                    fuzzy_threshold: float = DEFAULT_FUZZY_THRESHOLD) -> None:
    """Search export names from the file_info table."""
    file_info = db.get_file_info()
    if not file_info:
        return

    exports = parse_json_safe(file_info.exports)
    if not exports:
        return

    # Exports can be a list of dicts or a list of strings
    export_names: list[str] = []
    if isinstance(exports, list):
        for entry in exports:
            if isinstance(entry, dict):
                name = entry.get("name") or entry.get("function_name") or ""
                if name:
                    export_names.append(name)
            elif isinstance(entry, str):
                export_names.append(entry)
    elif isinstance(exports, dict):
        for key in exports:
            export_names.append(str(key))

    matched_exports: list[tuple[str, float]] = []
    for e in export_names:
        hit, mq = _match(e, query, mode, fuzzy_threshold=fuzzy_threshold)
        if hit:
            matched_exports.append((e, mq))
    if not matched_exports:
        return

    for export_name, mq in matched_exports[:limit]:
        score = _score_result(mq, is_export=True)
        func_matches = db.get_function_by_name(export_name)
        if func_matches:
            func = func_matches[0]
            results.add("export", func.function_id,
                         func.function_name or export_name,
                         f"export: {export_name}",
                         relevance_score=score)
        else:
            results.add("export", -1, export_name,
                         f"export: {export_name} (no function record)",
                         relevance_score=score)


def _search_imports(db, query: str, results: UnifiedSearchResults, limit: int,
                    mode: MatchMode = MatchMode.SUBSTRING,
                    fuzzy_threshold: float = DEFAULT_FUZZY_THRESHOLD) -> None:
    """Search imported function names from the file_info table."""
    file_info = db.get_file_info()
    if not file_info:
        return

    imports = parse_json_safe(file_info.imports)
    if not isinstance(imports, list):
        return

    matched: list[tuple[str, str, float]] = []
    for mod_entry in imports:
        if not isinstance(mod_entry, dict):
            continue
        src_module = mod_entry.get("module_name", mod_entry.get("name", ""))
        functions = mod_entry.get("functions", [])
        if not isinstance(functions, list):
            continue
        for func in functions:
            if not isinstance(func, dict):
                continue
            fname = func.get("function_name", func.get("name", ""))
            if not fname:
                continue
            hit, mq = _match(fname, query, mode, fuzzy_threshold=fuzzy_threshold)
            if hit:
                matched.append((fname, src_module, mq))

    for fname, src_module, mq in matched[:limit]:
        score = _score_result(mq, is_export=False) * 0.9
        func_matches = db.get_function_by_name(fname)
        if func_matches:
            func = func_matches[0]
            results.add("import", func.function_id,
                         func.function_name or fname,
                         f"import: {fname} from {src_module}",
                         relevance_score=score)
        else:
            results.add("import", -1, fname,
                         f"import: {fname} from {src_module}",
                         relevance_score=score)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _highlight_match(text: str, query: str,
                     mode: MatchMode = MatchMode.SUBSTRING,
                     max_len: int = 100) -> str:
    """Return a snippet of *text* around the first match of *query*."""
    if mode == MatchMode.REGEX:
        try:
            m = re.search(query, text, re.IGNORECASE)
            if m:
                start = max(0, m.start() - 20)
                end = min(len(text), m.end() + 40)
                snippet = text[start:end]
                if start > 0:
                    snippet = "..." + snippet
                if end < len(text):
                    snippet = snippet + "..."
                return snippet
        except re.error as exc:
            log_warning(f"Invalid regex in _highlight_match: '{query}': {exc}", ErrorCode.PARSE_ERROR)

    idx = text.lower().find(query.lower())
    if idx == -1:
        return text[:max_len] + ("..." if len(text) > max_len else "")
    start = max(0, idx - 20)
    end = min(len(text), idx + len(query) + 40)
    snippet = text[start:end]
    if start > 0:
        snippet = "..." + snippet
    if end < len(text):
        snippet = snippet + "..."
    return snippet


def _extract_class_from_mangled(mangled: str) -> Optional[str]:
    """Extract a class name from an IDA mangled name.

    Common patterns:
        ??0ClassName@@...    -> ClassName (constructor)
        ??1ClassName@@...    -> ClassName (destructor)
        ??_7ClassName@@6B@   -> ClassName (vftable)
        ?Method@ClassName@@  -> ClassName
    """
    if not mangled or not mangled.startswith("?"):
        return None

    # Constructor/destructor: ??0Name@@ or ??1Name@@
    if mangled.startswith("??0") or mangled.startswith("??1"):
        rest = mangled[3:]
        at_idx = rest.find("@@")
        if at_idx > 0:
            return rest[:at_idx]

    # Vftable: ??_7Name@@6B@
    if mangled.startswith("??_7"):
        rest = mangled[4:]
        at_idx = rest.find("@@")
        if at_idx > 0:
            return rest[:at_idx]

    # Method: ?Method@ClassName@@
    if mangled.startswith("?") and not mangled.startswith("??"):
        rest = mangled[1:]
        at_idx = rest.find("@")
        if at_idx > 0:
            rest2 = rest[at_idx + 1:]
            at2_idx = rest2.find("@@")
            if at2_idx > 0:
                return rest2[:at2_idx]

    return None


def _extract_classes_from_vtable(
    vtables: Any, query: str,
    mode: MatchMode = MatchMode.SUBSTRING,
    fuzzy_threshold: float = DEFAULT_FUZZY_THRESHOLD,
) -> list[str]:
    """Extract matching class names from parsed vtable_contexts JSON."""
    classes: list[str] = []

    def _check(class_name: str) -> None:
        if not class_name:
            return
        hit, _ = _match(class_name, query, mode,
                        fuzzy_threshold=fuzzy_threshold)
        if hit:
            classes.append(class_name)

    if isinstance(vtables, list):
        for vt in vtables:
            if isinstance(vt, dict):
                _check(vt.get("class_name") or vt.get("class") or "")
    elif isinstance(vtables, dict):
        _check(vtables.get("class_name") or vtables.get("class") or "")
    return classes


# ---------------------------------------------------------------------------
# Auto-discover all module DBs
# ---------------------------------------------------------------------------

def _discover_module_dbs() -> list[Path]:
    """Find all individual analysis DBs in the workspace."""
    from helpers.module_discovery import iter_module_dbs
    return [db.path for db in iter_module_dbs(_WORKSPACE_ROOT / "extracted_dbs")]


# ---------------------------------------------------------------------------
# Main search orchestrator
# ---------------------------------------------------------------------------

def run_search(
    db_path: str,
    query: str,
    dimensions: tuple[str, ...] = DEFAULT_DIMENSIONS,
    limit_per_dimension: int = 25,
    *,
    mode: MatchMode = MatchMode.SUBSTRING,
    fuzzy_threshold: float = DEFAULT_FUZZY_THRESHOLD,
    sort: str = "score",
) -> UnifiedSearchResults:
    """Run unified search across the specified dimensions.

    Args:
        db_path: Path to the individual analysis DB.
        query: Search term (interpreted according to *mode*).
        dimensions: Which dimensions to search.
        limit_per_dimension: Max results per dimension.
        mode: Matching strategy (substring / regex / fuzzy).
        fuzzy_threshold: Minimum similarity ratio for fuzzy mode (0.0-1.0).
        sort: Result ordering -- ``"score"``, ``"name"``, or ``"id"``.
    """
    results = UnifiedSearchResults(search_mode=mode.value)
    function_index = load_function_index_for_db(db_path)
    mk = dict(mode=mode, fuzzy_threshold=fuzzy_threshold)

    with open_individual_analysis_db(db_path) as db:
        if "name" in dimensions:
            _search_names(db, function_index, query, results,
                          limit_per_dimension, **mk)
        if "signature" in dimensions:
            _search_signatures(db, query, results,
                               limit_per_dimension, **mk)
        if "string" in dimensions:
            _search_strings(db, query, results,
                            limit_per_dimension, **mk)
        if "api" in dimensions:
            _search_apis(db, query, results,
                         limit_per_dimension, **mk)
        if "dangerous" in dimensions:
            _search_dangerous_apis(db, query, results,
                                   limit_per_dimension, **mk)
        if "class" in dimensions:
            _search_classes(db, query, results,
                           limit_per_dimension, **mk)
        if "export" in dimensions:
            _search_exports(db, query, results,
                            limit_per_dimension, **mk)
        if "import" in dimensions:
            _search_imports(db, query, results,
                            limit_per_dimension, **mk)

    results.apply_multi_dimension_bonus()
    if sort == "score":
        results.sort_by_relevance()
    elif sort == "name":
        results.sort_by_name()
    elif sort == "id":
        results.sort_by_id()

    return results


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

_DIMENSION_LABELS = {
    "name": "Function Name Matches",
    "signature": "Signature Matches",
    "string": "String Literal Matches",
    "api": "API Call Matches",
    "dangerous": "Dangerous API Matches",
    "class": "Class Name Matches",
    "export": "Export Matches",
    "import": "Import Matches",
}


def print_results(results: UnifiedSearchResults, query: str, db_path: str,
                  as_json: bool = False) -> None:
    """Print search results in human-readable or JSON format."""
    if as_json:
        output = results.to_dict()
        output["query"] = query
        output["db_path"] = db_path
        output["status"] = "ok"
        emit_json(output)
        return

    if not results.has_results():
        status_message(f"No results found for '{query}' in {Path(db_path).name}.")
        return

    counts = results.dimension_counts()
    total = results.total_unique_functions()
    mode_label = results.search_mode
    print(f"{'=' * 88}")
    print(f"  UNIFIED SEARCH: '{query}'  [mode: {mode_label}]")
    print(f"  DB: {Path(db_path).name}")
    print(f"  {total} unique function(s) across {len(counts)} dimension(s)")
    print(f"{'=' * 88}")

    for dim in ALL_DIMENSIONS:
        dim_results = results.results.get(dim, [])
        if not dim_results:
            continue
        label = _DIMENSION_LABELS.get(dim, dim)
        print(f"\n--- {label} ({len(dim_results)}) ---\n")
        print(f"  {'ID':>6}  {'Score':>5}  {'Function Name':<42}  {'Context'}")
        print(f"  {'-' * 6}  {'-' * 5}  {'-' * 42}  {'-' * 46}")
        for entry in dim_results:
            fid = entry["function_id"]
            fname = entry["function_name"] or "(unnamed)"
            context = entry["match_context"]
            score = entry.get("relevance_score", 0.0)
            if len(fname) > 42:
                fname = fname[:39] + "..."
            if len(context) > 46:
                context = context[:43] + "..."
            fid_str = str(fid) if fid >= 0 else "?"
            print(f"  {fid_str:>6}  {score:5.2f}  {fname:<42}  {context}")

    # Summary footer
    print(f"\n{'=' * 88}")
    print(f"  Summary: {total} unique function(s)  [mode: {mode_label}]")
    for dim, count in counts.items():
        label = _DIMENSION_LABELS.get(dim, dim)
        print(f"    {label}: {count}")
    print(f"{'=' * 88}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Unified search across all analysis dimensions for a module DB.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Modes: substring (default), regex, fuzzy\n"
            "Dimensions: name, signature, string, api, dangerous, class, export\n"
            "Default: all dimensions are searched.\n\n"
            "Examples:\n"
            "  python unified_search.py extracted_dbs/appinfo_dll_f2bbf324a1.db --query CreateProcess\n"
            '  python unified_search.py extracted_dbs/appinfo_dll_f2bbf324a1.db --query "^Ai.*Process$" --regex\n'
            "  python unified_search.py extracted_dbs/appinfo_dll_f2bbf324a1.db --query CreateProces --fuzzy\n"
            "  python unified_search.py extracted_dbs/cmd_exe_6d109a3a00.db --query Bat --json\n"
            "  python unified_search.py --all --query CreateProcess --dimensions name,api\n"
        ),
    )
    parser.add_argument("db_path", nargs="?", help="Path to the individual analysis DB")
    parser.add_argument("--query", "-q", required=True,
                        help="Search term (substring, regex pattern, or fuzzy target)")
    parser.add_argument("--all", action="store_true",
                        help="Search across all module DBs in extracted_dbs/")
    parser.add_argument("--limit-modules", type=int, default=0,
                        help="Max modules to search with --all (0 = use config default)")
    parser.add_argument("--dimensions", "-d",
                        help="Comma-separated list of dimensions to search (default: all)")
    parser.add_argument("--limit", type=int, default=25,
                        help="Max results per dimension (default: 25)")
    parser.add_argument("--json", action="store_true", help="Output as JSON")

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--mode", choices=["substring", "regex", "fuzzy"],
                            default="substring",
                            help="Match mode (default: substring)")
    mode_group.add_argument("--regex", action="store_true",
                            help="Shorthand for --mode regex")
    mode_group.add_argument("--fuzzy", action="store_true",
                            help="Shorthand for --mode fuzzy")

    parser.add_argument("--threshold", type=float, default=DEFAULT_FUZZY_THRESHOLD,
                        help=f"Fuzzy similarity threshold 0.0-1.0 (default: {DEFAULT_FUZZY_THRESHOLD})")
    parser.add_argument("--sort", choices=["score", "name", "id"],
                        default="score",
                        help="Sort order within each dimension (default: score)")
    args = parser.parse_args()

    if not args.db_path and not args.all:
        parser.error("Provide a db_path or use --all to search all modules")

    # Resolve match mode from --mode / --regex / --fuzzy
    if args.regex:
        mode = MatchMode.REGEX
    elif args.fuzzy:
        mode = MatchMode.FUZZY
    else:
        mode = MatchMode(args.mode)

    dimensions = DEFAULT_DIMENSIONS
    if args.dimensions:
        requested = tuple(d.strip().lower() for d in args.dimensions.split(","))
        invalid = [d for d in requested if d not in ALL_DIMENSIONS]
        if invalid:
            parser.error(f"Invalid dimensions: {', '.join(invalid)}. "
                         f"Valid: {', '.join(ALL_DIMENSIONS)}")
        dimensions = requested

    search_kwargs = dict(mode=mode, fuzzy_threshold=args.threshold,
                         sort=args.sort)

    if args.all:
        db_paths = _discover_module_dbs()
        if not db_paths:
            from helpers.errors import ErrorCode, emit_error
            emit_error("No analysis databases found in extracted_dbs/.", ErrorCode.NO_DATA)

        from helpers.config import get_config_value
        max_modules: int = getattr(args, "limit_modules", 0) or get_config_value(
            "scale.max_modules_search_all", 0
        )
        if search_kwargs.get("mode") == MatchMode.FUZZY and max_modules > 20:
            max_modules = 20
        if max_modules > 0 and len(db_paths) > max_modules:
            print(
                f"WARNING: {len(db_paths)} modules found, searching first "
                f"{max_modules} (use --limit-modules N to adjust).",
                file=sys.stderr,
            )
            db_paths = db_paths[:max_modules]

        from concurrent.futures import ThreadPoolExecutor, as_completed

        all_results: dict[str, Any] = {}

        def _search_one(db_p: Path):
            db_str = str(db_p)
            sr = run_search(db_str, args.query, dimensions, args.limit,
                            **search_kwargs)
            if sr.has_results():
                out = sr.to_dict()
                out["db_path"] = db_str
                return db_p.stem, out, sr
            return db_p.stem, None, sr

        found_any = False
        with ThreadPoolExecutor(max_workers=min(8, len(db_paths))) as pool:
            futures = {pool.submit(_search_one, p): p for p in db_paths}
            for fut in as_completed(futures):
                stem, out, sr = fut.result()
                if out is not None:
                    found_any = True
                    if args.json:
                        all_results[stem] = out
                    else:
                        print_results(sr, args.query, out["db_path"], as_json=False)
                        print()

        if args.json:
            combined = {
                "query": args.query,
                "search_mode": mode.value,
                "modules": all_results,
                "status": "ok",
            }
            emit_json(combined)
        elif not found_any:
            print(f"No results found for '{args.query}' across {len(db_paths)} module(s).")
        return

    # Single DB search
    db_path = args.db_path
    resolved = Path(db_path)
    if not resolved.is_absolute():
        resolved = _WORKSPACE_ROOT / db_path
    db_path = str(resolved)

    sr = run_search(db_path, args.query, dimensions, args.limit,
                    **search_kwargs)
    print_results(sr, args.query, db_path, as_json=args.json)


if __name__ == "__main__":
    main()
