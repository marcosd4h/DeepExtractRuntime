"""Read-only access to individual analysis databases."""

from __future__ import annotations


from pathlib import Path
import re
import sqlite3
import threading
from typing import Any, Iterable, Optional, Set
import warnings

from ..sql_utils import LIKE_ESCAPE, escape_like
from .records import FileInfoRecord, FunctionRecord, FunctionWithModuleInfo, Page

# Backward-compat aliases for internal use
_escape_like = escape_like
_LIKE_ESCAPE = LIKE_ESCAPE

_SQL_VAR_BATCH = 500


FILE_INFO_TABLE = "file_info"
FUNCTIONS_TABLE = "functions"
SCHEMA_VERSION_TABLE = "schema_version"
EXPECTED_SCHEMA_VERSION = 1

RECOMMENDED_FUNCTION_INDEXES: tuple[tuple[str, str], ...] = (
    (
        "idx_functions_name_nocase",
        "CREATE INDEX IF NOT EXISTS idx_functions_name_nocase "
        "ON functions(function_name COLLATE NOCASE)",
    ),
    (
        "idx_functions_signature_nocase",
        "CREATE INDEX IF NOT EXISTS idx_functions_signature_nocase "
        "ON functions(function_signature COLLATE NOCASE)",
    ),
    (
        "idx_functions_mangled_name_nocase",
        "CREATE INDEX IF NOT EXISTS idx_functions_mangled_name_nocase "
        "ON functions(mangled_name COLLATE NOCASE)",
    ),
)


_VALIDATED_PATHS: Set[str] = set()
_VALIDATED_PATHS_LOCK = threading.Lock()

# SQL keywords that mutate data or schema -- blocked for defense-in-depth
# even though the connection is opened read-only (URI ``?mode=ro``) and
# ``PRAGMA query_only = ON`` is set.
_UNSAFE_SQL_PATTERN: re.Pattern[str] = re.compile(
    r"\b(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|ATTACH|DETACH|REPLACE|REINDEX|VACUUM)\b",
    re.IGNORECASE,
)


def _validate_readonly_sql(sql: str) -> None:
    """Raise :class:`ValueError` if *sql* contains write/DDL keywords.

    This is a defense-in-depth check.  The database connection is
    already opened in read-only mode at the VFS level and with
    ``PRAGMA query_only = ON``, so writes would fail at the SQLite
    layer regardless.  This function catches dangerous statements
    earlier and with a clearer error message.
    """
    stripped = sql.strip()
    if not stripped:
        raise ValueError("Empty SQL statement")
    stripped = re.sub(r"/\*.*?\*/", " ", stripped, flags=re.DOTALL)
    stripped = re.sub(r"--[^\n]*", " ", stripped)
    stripped = re.sub(r"'[^']*'", "''", stripped)
    match = _UNSAFE_SQL_PATTERN.search(stripped)
    if match:
        raise ValueError(
            f"SQL contains disallowed keyword '{match.group()}'. "
            "This database is read-only; only SELECT/PRAGMA queries are permitted "
            "through the public API. Use parameterized queries for all user-supplied values."
        )


def reject_db_mutation(db_path: str | Path) -> dict[str, Any]:
    """Reject runtime attempts to mutate extraction databases."""
    resolved = Path(db_path).expanduser().resolve()
    raise RuntimeError(
        "Extraction analysis databases are read-only and must not be mutated "
        f"by runtime helpers: {resolved}. Run any indexing or maintenance "
        "steps in an explicitly offline workflow outside the DeepExtract runtime."
    )


ensure_performance_indexes = reject_db_mutation


class IndividualAnalysisDB:
    """Read-only access to a per-binary analysis database."""

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = self._resolve_db_path(db_path)
        self._conn: Optional[sqlite3.Connection] = None
        self._open_lock = threading.Lock()
        self._file_info_columns: set[str] | None = None

    def __enter__(self) -> "IndividualAnalysisDB":
        self._ensure_open()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __del__(self) -> None:
        if getattr(self, "_conn", None) is not None:
            warnings.warn(
                f"Unclosed IndividualAnalysisDB({self._db_path}). "
                "Use a 'with' block or call .close() explicitly.",
                ResourceWarning,
                stacklevel=2,
            )
            self.close()

    @property
    def db_path(self) -> Path:
        return self._db_path

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def get_file_info(self) -> Optional[FileInfoRecord]:
        query = f"SELECT * FROM {FILE_INFO_TABLE} LIMIT 1"
        return self._fetch_one_file_info(query, ())

    _file_info_columns_lock = threading.Lock()

    def _get_file_info_columns(self) -> set[str]:
        """Return the set of valid column names for the file_info table.

        Introspects via PRAGMA table_info on first call, then caches
        the result for the lifetime of this connection.
        """
        if self._file_info_columns is not None:
            return self._file_info_columns
        with self._file_info_columns_lock:
            if self._file_info_columns is not None:
                return self._file_info_columns
            self._ensure_open()
            assert self._conn is not None
            cursor = self._conn.execute(f"PRAGMA table_info({FILE_INFO_TABLE})")
            cols = {row[1] for row in cursor.fetchall()}
            self._file_info_columns = cols
            return cols

    def get_file_info_field(self, field_name: str) -> Any:
        allowed = self._get_file_info_columns()
        if field_name not in allowed:
            raise ValueError(f"Invalid file_info column: {field_name}")
        query = f"SELECT {field_name} FROM {FILE_INFO_TABLE} LIMIT 1"
        rows = self._fetch_rows(query, ())
        if not rows:
            return None
        return rows[0][0]

    def get_function_by_id(self, function_id: int) -> Optional[FunctionRecord]:
        query = f"SELECT * FROM {FUNCTIONS_TABLE} WHERE function_id = ?"
        return self._fetch_one_function(query, (function_id,))

    def get_function_by_name(self, name: str, case_insensitive: bool = True) -> list[FunctionRecord]:
        if case_insensitive:
            query = f"SELECT * FROM {FUNCTIONS_TABLE} WHERE function_name = ? COLLATE NOCASE"
        else:
            query = f"SELECT * FROM {FUNCTIONS_TABLE} WHERE function_name = ?"
        return self._fetch_all_functions(query, (name,))

    def get_function_by_mangled_name(self, name: str, case_insensitive: bool = True) -> list[FunctionRecord]:
        if case_insensitive:
            query = f"SELECT * FROM {FUNCTIONS_TABLE} WHERE mangled_name = ? COLLATE NOCASE"
        else:
            query = f"SELECT * FROM {FUNCTIONS_TABLE} WHERE mangled_name = ?"
        return self._fetch_all_functions(query, (name,))

    def search_functions_by_signature(
        self,
        pattern: str,
        case_insensitive: bool = True,
    ) -> list[FunctionRecord]:
        if case_insensitive:
            query = (
                f"SELECT * FROM {FUNCTIONS_TABLE} "
                "WHERE function_signature LIKE ? COLLATE NOCASE"
            )
        else:
            query = f"SELECT * FROM {FUNCTIONS_TABLE} WHERE function_signature LIKE ?"
        return self._fetch_all_functions(query, (pattern,))

    def get_all_functions(self, limit: Optional[int] = None, offset: Optional[int] = None) -> list[FunctionRecord]:
        query = f"SELECT * FROM {FUNCTIONS_TABLE} ORDER BY function_id"
        params: list[Any] = []
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
            if offset is not None:
                query += " OFFSET ?"
                params.append(offset)
        elif offset is not None:
            query += " LIMIT -1 OFFSET ?"
            params.append(offset)
        return self._fetch_all_functions(query, params)

    def count_functions(self) -> int:
        query = f"SELECT COUNT(*) AS count FROM {FUNCTIONS_TABLE}"
        rows = self._fetch_rows(query, ())
        if not rows:
            return 0
        return int(rows[0]["count"])

    def search_functions(
        self,
        name_contains: Optional[str] = None,
        signature_contains: Optional[str] = None,
        has_decompiled_code: Optional[bool] = None,
        has_dangerous_apis: Optional[bool] = None,
        case_insensitive: bool = True,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        order_by: str = "function_id",
        ascending: bool = True,
    ) -> list[FunctionRecord]:
        clauses: list[str] = []
        params: list[Any] = []
        allowed_order = {
            "function_id",
            "function_name",
            "function_signature",
            "mangled_name",
            "created_at",
        }
        if order_by not in allowed_order:
            raise ValueError(
                f"Invalid order_by column: {order_by!r}. "
                f"Allowed: {sorted(allowed_order)}"
            )

        if name_contains:
            if case_insensitive:
                clauses.append("function_name LIKE ? COLLATE NOCASE" + _LIKE_ESCAPE)
            else:
                clauses.append("function_name LIKE ?" + _LIKE_ESCAPE)
            params.append(f"%{_escape_like(name_contains)}%")
        if signature_contains:
            if case_insensitive:
                clauses.append("function_signature LIKE ? COLLATE NOCASE" + _LIKE_ESCAPE)
            else:
                clauses.append("function_signature LIKE ?" + _LIKE_ESCAPE)
            params.append(f"%{_escape_like(signature_contains)}%")
        if has_decompiled_code is True:
            clauses.append("decompiled_code IS NOT NULL AND decompiled_code != ''")
        elif has_decompiled_code is False:
            clauses.append("(decompiled_code IS NULL OR decompiled_code = '')")
        if has_dangerous_apis is True:
            clauses.append(
                "dangerous_api_calls IS NOT NULL AND dangerous_api_calls != '' "
                "AND dangerous_api_calls NOT LIKE '[]%' "
                "AND dangerous_api_calls NOT LIKE 'null%'"
            )
        elif has_dangerous_apis is False:
            clauses.append(
                "(dangerous_api_calls IS NULL OR dangerous_api_calls = '' "
                "OR dangerous_api_calls LIKE '[]%' OR dangerous_api_calls LIKE 'null%')"
            )

        query = f"SELECT * FROM {FUNCTIONS_TABLE}"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        direction = "ASC" if ascending else "DESC"
        query += f" ORDER BY {order_by} {direction}"
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
            if offset is not None:
                query += " OFFSET ?"
                params.append(offset)
        elif offset is not None:
            query += " LIMIT -1 OFFSET ?"
            params.append(offset)
        return self._fetch_all_functions(query, params)

    def iter_functions(
        self,
        *,
        batch_size: int = 500,
        start_offset: int = 0,
        order_by: str = "function_id",
        ascending: bool = True,
    ) -> Iterable[FunctionRecord]:
        """Stream functions in batches to avoid large full-table loads."""
        if batch_size < 1:
            raise ValueError("batch_size must be >= 1")
        offset = max(0, int(start_offset))
        while True:
            batch = self.search_functions(
                limit=batch_size,
                offset=offset,
                order_by=order_by,
                ascending=ascending,
            )
            if not batch:
                break
            for record in batch:
                yield record
            if len(batch) < batch_size:
                break
            offset += batch_size

    def get_function_names(self) -> list[str]:
        query = f"SELECT function_name FROM {FUNCTIONS_TABLE} WHERE function_name IS NOT NULL"
        rows = self._fetch_rows(query, ())
        return [row["function_name"] for row in rows]

    def get_outbound_xrefs_only(self) -> list[sqlite3.Row]:
        """Fetch only function_id and simple_outbound_xrefs for every function.

        Returns raw ``sqlite3.Row`` objects.  This is orders of magnitude
        faster than ``get_all_functions()`` because it skips the large
        decompiled_code, assembly_code, and all other JSON blob columns.
        Use this for dependency-graph construction that only needs xref data.
        """
        query = (
            f"SELECT function_id, simple_outbound_xrefs FROM {FUNCTIONS_TABLE} "
            "WHERE simple_outbound_xrefs IS NOT NULL "
            "AND simple_outbound_xrefs != '' "
            "AND simple_outbound_xrefs != '[]' "
            "ORDER BY function_id"
        )
        return self._fetch_rows(query, ())

    _SLIM_COLUMNS = (
        "function_id", "function_name", "function_signature",
        "decompiled_code", "assembly_code",
        "simple_outbound_xrefs", "simple_inbound_xrefs", "string_literals",
    )

    def get_decompiled_functions_slim(self) -> list[sqlite3.Row]:
        """Fetch only decompiled functions with a targeted column set.

        Returns raw ``sqlite3.Row`` objects with columns: function_id,
        function_name, function_signature, decompiled_code, assembly_code,
        simple_outbound_xrefs, simple_inbound_xrefs, string_literals.

        This avoids loading large unused columns (outbound_xrefs,
        inbound_xrefs, vtable_contexts, global_var_accesses, etc.)
        that can dominate memory for module-wide scans.
        """
        cols = ", ".join(self._SLIM_COLUMNS)
        query = (
            f"SELECT {cols} FROM {FUNCTIONS_TABLE} "
            "WHERE decompiled_code IS NOT NULL AND decompiled_code != '' "
            "ORDER BY function_id"
        )
        return self._fetch_rows(query, ())

    def search_by_json_field(
        self,
        field: str,
        value: str,
        case_insensitive: bool = True,
    ) -> list[FunctionRecord]:
        """Search functions where a JSON text column contains *value* via LIKE pre-filter.

        Only columns that store JSON text are allowed.  The query applies a
        SQL ``LIKE`` pre-filter on the raw column text and returns full
        ``FunctionRecord`` objects so callers can do precise post-filtering
        with ``parse_json_safe``.
        """
        allowed_json_fields = {
            "string_literals",
            "simple_outbound_xrefs",
            "simple_inbound_xrefs",
            "vtable_contexts",
            "dangerous_api_calls",
            "global_var_accesses",
            "loop_analysis",
            "stack_frame",
            "inbound_xrefs",
            "outbound_xrefs",
        }
        if field not in allowed_json_fields:
            raise ValueError(f"Invalid JSON field: {field}")
        collate = " COLLATE NOCASE" if case_insensitive else ""
        query = (
            f"SELECT * FROM {FUNCTIONS_TABLE} "
            f"WHERE {field} IS NOT NULL AND {field} != '' "
            f"AND {field} NOT LIKE 'null%' AND {field} NOT LIKE '[]%' "
            f"AND {field} LIKE ?{collate}{_LIKE_ESCAPE}"
        )
        return self._fetch_all_functions(query, (f"%{_escape_like(value)}%",))

    def get_functions_by_ids(self, ids: list[int]) -> list[FunctionRecord]:
        """Batch-load functions by ID list.

        Returns one ``FunctionRecord`` per matching ID.  Missing IDs are
        silently skipped.  Order follows the database rowid, not input order.

        Large lists are chunked to stay within SQLite's variable limit.
        """
        if not ids:
            return []
        if len(ids) <= _SQL_VAR_BATCH:
            placeholders = ",".join("?" for _ in ids)
            query = (
                f"SELECT * FROM {FUNCTIONS_TABLE} "
                f"WHERE function_id IN ({placeholders})"
            )
            return self._fetch_all_functions(query, ids)
        results: list[FunctionRecord] = []
        for i in range(0, len(ids), _SQL_VAR_BATCH):
            chunk = ids[i : i + _SQL_VAR_BATCH]
            placeholders = ",".join("?" for _ in chunk)
            query = (
                f"SELECT * FROM {FUNCTIONS_TABLE} "
                f"WHERE function_id IN ({placeholders})"
            )
            results.extend(self._fetch_all_functions(query, chunk))
        return results

    def get_functions_by_id_range(
        self, start_id: int, end_id: int
    ) -> list[FunctionRecord]:
        """Load functions whose ``function_id`` falls within *[start_id, end_id]*.

        Both bounds are inclusive.  Returns records ordered by ``function_id``.
        """
        query = (
            f"SELECT * FROM {FUNCTIONS_TABLE} "
            "WHERE function_id BETWEEN ? AND ? "
            "ORDER BY function_id"
        )
        return self._fetch_all_functions(query, (start_id, end_id))

    def get_functions_by_names(
        self,
        names: list[str],
        case_insensitive: bool = True,
    ) -> dict[str, list[FunctionRecord]]:
        """Batch-load functions by a list of names.

        Returns ``{name: [matching records]}`` with one entry per input name.
        Names that match no function still appear with an empty list.

        Large lists are chunked to stay within SQLite's variable limit.
        """
        if not names:
            return {}
        collate = " COLLATE NOCASE" if case_insensitive else ""
        all_records: list[FunctionRecord] = []
        for i in range(0, len(names), _SQL_VAR_BATCH):
            chunk = names[i : i + _SQL_VAR_BATCH]
            placeholders = ",".join("?" for _ in chunk)
            query = (
                f"SELECT * FROM {FUNCTIONS_TABLE} "
                f"WHERE function_name{collate} IN ({placeholders})"
            )
            all_records.extend(self._fetch_all_functions(query, chunk))
        result: dict[str, list[FunctionRecord]] = {n: [] for n in names}
        if case_insensitive:
            lower_to_originals: dict[str, list[str]] = {}
            for n in names:
                lower_to_originals.setdefault(n.lower(), []).append(n)
            for rec in all_records:
                fname = (rec.function_name or "").lower()
                for orig in lower_to_originals.get(fname, ()):
                    result[orig].append(rec)
        else:
            name_set = set(names)
            for rec in all_records:
                fname = rec.function_name or ""
                if fname in name_set:
                    result[fname].append(rec)
        return result

    # Primitive / keyword names that the decompiler's vtable reconstruction
    # produces as false-positive "class" names.
    _VTABLE_NOISE = frozenset({
        "void", "bool", "long", "unsigned", "char", "int", "short",
        "float", "double", "const", "class", "struct", "enum", "union",
        "signed", "wchar_t", "__int64", "__int32", "__int16", "__int8",
    })

    def get_vtable_classes(self) -> dict[str, list[int]]:
        """Extract class names from ``vtable_contexts`` across all functions.

        Returns a mapping of ``{class_name: [function_id, ...]}`` built by
        parsing every non-null ``vtable_contexts`` JSON blob.

        The method inspects both the legacy ``class_name`` / ``class`` keys
        and the current ``reconstructed_classes`` list of C++ declaration
        strings (``"class Foo::Bar { ... }"``).  Primitive type names
        produced by the decompiler (``void``, ``bool``, etc.) are filtered.
        """
        import re
        from .records import parse_json_safe

        _CLS_RE = re.compile(r"^(?:class|struct)\s+([\w:]+(?:::[\w:]+)*)")

        query = (
            f"SELECT function_id, vtable_contexts FROM {FUNCTIONS_TABLE} "
            "WHERE vtable_contexts IS NOT NULL AND vtable_contexts != '' "
            "AND vtable_contexts NOT LIKE 'null%'"
        )
        rows = self._fetch_rows(query, ())
        classes: dict[str, list[int]] = {}
        for row in rows:
            vtables = parse_json_safe(row["vtable_contexts"])
            if not vtables or not isinstance(vtables, list):
                continue
            for entry in vtables:
                if not isinstance(entry, dict):
                    continue
                # Legacy keys (class_name / class)
                cls = entry.get("class_name") or entry.get("class") or ""
                if cls and cls not in self._VTABLE_NOISE:
                    classes.setdefault(cls, []).append(row["function_id"])
                    continue
                # Current format: reconstructed_classes list
                for cls_text in entry.get("reconstructed_classes", []):
                    if not isinstance(cls_text, str):
                        continue
                    m = _CLS_RE.match(cls_text.strip())
                    if m:
                        name = m.group(1)
                        if name not in self._VTABLE_NOISE:
                            classes.setdefault(name, []).append(row["function_id"])
        return classes

    def get_dangerous_api_ranking(
        self, limit: int = 20
    ) -> list[tuple[FunctionRecord, int]]:
        """Return functions ranked by number of dangerous API calls (descending).

        Each result is a ``(FunctionRecord, api_count)`` tuple.  Uses
        ``json_array_length`` when the SQLite build supports it, otherwise
        falls back to Python-side counting.
        """
        from .records import parse_json_safe

        _HAS_DANGEROUS = (
            "dangerous_api_calls IS NOT NULL AND dangerous_api_calls != '' "
            "AND dangerous_api_calls NOT LIKE '[]%' "
            "AND dangerous_api_calls NOT LIKE 'null%'"
        )
        try:
            query = (
                f"SELECT *, json_array_length(dangerous_api_calls) AS api_cnt "
                f"FROM {FUNCTIONS_TABLE} "
                f"WHERE {_HAS_DANGEROUS} "
                "ORDER BY api_cnt DESC LIMIT ?"
            )
            rows = self._fetch_rows(query, (limit,))
            return [
                (self._row_to_function(row), int(row["api_cnt"]))
                for row in rows
            ]
        except RuntimeError as exc:
            if "json_array_length" not in str(exc).lower():
                raise
            query = (
                f"SELECT * FROM {FUNCTIONS_TABLE} WHERE {_HAS_DANGEROUS}"
            )
            records = self._fetch_all_functions(query, ())
            ranked: list[tuple[FunctionRecord, int]] = []
            for rec in records:
                apis = parse_json_safe(rec.dangerous_api_calls)
                cnt = len(apis) if isinstance(apis, list) else 0
                if cnt > 0:
                    ranked.append((rec, cnt))
            ranked.sort(key=lambda t: t[1], reverse=True)
            return ranked[:limit]

    def compute_stats(self) -> dict[str, Any]:
        """Return aggregated metrics from the functions table in a single query.

        Unlike ``function_index.compute_stats`` (which operates on the
        pre-built JSON index), this queries the database directly and
        returns authoritative counts.
        """
        query = (
            f"SELECT "
            f"COUNT(*) AS total_functions, "
            f"SUM(CASE WHEN decompiled_code IS NOT NULL "
            f"AND decompiled_code != '' THEN 1 ELSE 0 END) AS decompiled_count, "
            f"SUM(CASE WHEN dangerous_api_calls IS NOT NULL "
            f"AND dangerous_api_calls != '' "
            f"AND dangerous_api_calls NOT LIKE '[]%' "
            f"AND dangerous_api_calls NOT LIKE 'null%' THEN 1 ELSE 0 END) AS dangerous_api_count, "
            f"SUM(CASE WHEN vtable_contexts IS NOT NULL "
            f"AND vtable_contexts != '' "
            f"AND vtable_contexts NOT LIKE 'null%' THEN 1 ELSE 0 END) AS vtable_function_count, "
            f"SUM(CASE WHEN assembly_code IS NOT NULL "
            f"AND assembly_code != '' THEN 1 ELSE 0 END) AS has_assembly_count "
            f"FROM {FUNCTIONS_TABLE}"
        )
        rows = self._fetch_rows(query, ())
        if not rows:
            return {
                "total_functions": 0,
                "decompiled_count": 0,
                "dangerous_api_count": 0,
                "vtable_function_count": 0,
                "has_assembly_count": 0,
            }
        row = rows[0]
        return {
            "total_functions": int(row["total_functions"] or 0),
            "decompiled_count": int(row["decompiled_count"] or 0),
            "dangerous_api_count": int(row["dangerous_api_count"] or 0),
            "vtable_function_count": int(row["vtable_function_count"] or 0),
            "has_assembly_count": int(row["has_assembly_count"] or 0),
        }

    def get_functions_with_module_info(
        self,
        ids: Optional[list[int]] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> list[FunctionWithModuleInfo]:
        """JOIN functions with file_info in a single query.

        Returns ``FunctionWithModuleInfo`` records that combine each function
        with key module-level metadata (module name, description, version,
        company).  Since ``file_info`` always contains exactly one row the
        join is an implicit cross join.
        """
        query = (
            f"SELECT f.*, "
            f"fi.file_name AS _module_name, "
            f"fi.file_description AS _file_description, "
            f"fi.file_version AS _file_version, "
            f"fi.company_name AS _company_name "
            f"FROM {FUNCTIONS_TABLE} f, {FILE_INFO_TABLE} fi"
        )
        params_list: list[Any] = []
        if ids is not None:
            if not ids:
                return []
            placeholders = ",".join("?" for _ in ids)
            query += f" WHERE f.function_id IN ({placeholders})"
            params_list.extend(ids)
        query += " ORDER BY f.function_id"
        if limit is not None:
            query += " LIMIT ?"
            params_list.append(limit)
            if offset is not None:
                query += " OFFSET ?"
                params_list.append(offset)
        elif offset is not None:
            query += " LIMIT -1 OFFSET ?"
            params_list.append(offset)

        rows = self._fetch_rows(query, params_list)
        results: list[FunctionWithModuleInfo] = []
        for row in rows:
            func = self._row_to_function(row)
            results.append(FunctionWithModuleInfo(
                function=func,
                module_name=row["_module_name"],
                file_description=row["_file_description"],
                file_version=row["_file_version"],
                company_name=row["_company_name"],
            ))
        return results

    def get_functions_paginated(
        self,
        page: int = 1,
        page_size: int = 100,
        has_decompiled_code: Optional[bool] = None,
        has_dangerous_apis: Optional[bool] = None,
        name_contains: Optional[str] = None,
        order_by: str = "function_id",
        ascending: bool = True,
    ) -> "Page[FunctionRecord]":
        """Paginated function query with filters and sorting.

        Returns a ``Page`` of ``FunctionRecord`` objects including total
        count, page metadata, and navigation helpers.

        ``order_by`` is validated against an allowlist of column names.
        """
        _ALLOWED_ORDER = {
            "function_id",
            "function_name",
            "function_signature",
            "mangled_name",
            "created_at",
        }
        if order_by not in _ALLOWED_ORDER:
            raise ValueError(
                f"Invalid order_by column: {order_by!r}. "
                f"Allowed: {sorted(_ALLOWED_ORDER)}"
            )
        if page < 1:
            page = 1
        if page_size < 1:
            page_size = 100

        clauses: list[str] = []
        params: list[Any] = []
        if name_contains:
            clauses.append("function_name LIKE ? COLLATE NOCASE" + _LIKE_ESCAPE)
            params.append(f"%{_escape_like(name_contains)}%")
        if has_decompiled_code is True:
            clauses.append("decompiled_code IS NOT NULL AND decompiled_code != ''")
        elif has_decompiled_code is False:
            clauses.append("(decompiled_code IS NULL OR decompiled_code = '')")
        if has_dangerous_apis is True:
            clauses.append(
                "dangerous_api_calls IS NOT NULL AND dangerous_api_calls != '' "
                "AND dangerous_api_calls NOT LIKE '[]%' "
                "AND dangerous_api_calls NOT LIKE 'null%'"
            )
        elif has_dangerous_apis is False:
            clauses.append(
                "(dangerous_api_calls IS NULL OR dangerous_api_calls = '' "
                "OR dangerous_api_calls LIKE '[]%' OR dangerous_api_calls LIKE 'null%')"
            )

        where = ""
        if clauses:
            where = " WHERE " + " AND ".join(clauses)

        count_query = f"SELECT COUNT(*) AS c FROM {FUNCTIONS_TABLE}{where}"
        count_rows = self._fetch_rows(count_query, params)
        total = int(count_rows[0]["c"]) if count_rows else 0

        direction = "ASC" if ascending else "DESC"
        offset_val = (page - 1) * page_size
        data_query = (
            f"SELECT * FROM {FUNCTIONS_TABLE}{where} "
            f"ORDER BY {order_by} {direction} LIMIT ? OFFSET ?"
        )
        data_params = params + [page_size, offset_val]
        items = self._fetch_all_functions(data_query, data_params)

        return Page(items=items, total=total, page=page, page_size=page_size)

    def get_functions_by_vtable_class(self) -> dict[str, list[FunctionRecord]]:
        """Group functions by vtable class name, returning full records.

        Enhances :meth:`get_vtable_classes` by returning complete
        ``FunctionRecord`` objects instead of bare IDs, using a single
        batch fetch after collecting the ID-to-class mapping.
        """
        class_to_ids = self.get_vtable_classes()
        if not class_to_ids:
            return {}
        all_ids = list({fid for ids in class_to_ids.values() for fid in ids})
        func_map = {f.function_id: f for f in self.get_functions_by_ids(all_ids)}
        result: dict[str, list[FunctionRecord]] = {}
        for cls, ids in class_to_ids.items():
            funcs = [func_map[fid] for fid in ids if fid in func_map]
            if funcs:
                result[cls] = funcs
        return result

    def execute_query(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        """Execute a read-only SQL query with defense-in-depth validation.

        Raises :class:`ValueError` if the SQL contains write/DDL
        keywords (``INSERT``, ``UPDATE``, ``DELETE``, ``DROP``, etc.).
        The database connection is already read-only at the VFS and
        PRAGMA level, but this provides an earlier, clearer error.

        For unrestricted internal queries, use :meth:`_execute_query_raw`.
        For strict SELECT-only access, prefer :meth:`execute_safe_select`.
        """
        _validate_readonly_sql(sql)
        return self._fetch_rows(sql, params)

    def execute_safe_select(
        self, sql: str, params: Iterable[Any] = ()
    ) -> list[sqlite3.Row]:
        """Execute a SELECT-only query with strict validation.

        Raises :class:`ValueError` if the statement does not start with
        ``SELECT`` or contains disallowed write/DDL keywords.
        """
        stripped = sql.strip()
        if not stripped.upper().startswith("SELECT"):
            raise ValueError(
                "Only SELECT statements are allowed through execute_safe_select(). "
                f"Got: {stripped[:40]!r}..."
            )
        _validate_readonly_sql(stripped)
        return self._fetch_rows(sql, params)

    def _execute_query_raw(
        self, sql: str, params: Iterable[Any] = ()
    ) -> list[sqlite3.Row]:
        """Execute SQL without application-level validation (internal use).

        The connection-level protections (read-only URI mode and
        ``PRAGMA query_only = ON``) still apply.  Prefer
        :meth:`execute_query` or :meth:`execute_safe_select` for any
        caller-supplied SQL.
        """
        return self._fetch_rows(sql, params)

    def _ensure_open(self) -> None:
        if self._conn is not None:
            return
        with self._open_lock:
            if self._conn is not None:
                return
            uri = self._make_readonly_uri(self._db_path)
            try:
                self._conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
                self._conn.row_factory = sqlite3.Row
                self._conn.execute("PRAGMA query_only = ON")
                self._conn.execute("PRAGMA busy_timeout = 5000")
            except sqlite3.Error as e:
                self._conn = None
                raise RuntimeError(f"Failed to open analysis DB {self._db_path}: {e}") from e
            self._validate_schema_version()

    def _validate_schema_version(self) -> None:
        """Warn if the DB schema is newer than what this helper expects."""
        db_path_str = str(self._db_path)
        with _VALIDATED_PATHS_LOCK:
            if db_path_str in _VALIDATED_PATHS:
                return

        assert self._conn is not None
        try:
            row = self._conn.execute(
                f"SELECT MAX(version) FROM {SCHEMA_VERSION_TABLE}"
            ).fetchone()
        except sqlite3.OperationalError:
            with _VALIDATED_PATHS_LOCK:
                _VALIDATED_PATHS.add(db_path_str)
            return

        if row and row[0] is not None and int(row[0]) > EXPECTED_SCHEMA_VERSION:
            warnings.warn(
                f"DB schema version {row[0]} > expected {EXPECTED_SCHEMA_VERSION}. "
                "Some queries may not work correctly.",
                stacklevel=3,
            )
        with _VALIDATED_PATHS_LOCK:
            _VALIDATED_PATHS.add(db_path_str)

    def _fetch_rows(self, query: str, params: Iterable[Any]) -> list[sqlite3.Row]:
        self._ensure_open()
        assert self._conn is not None
        try:
            cursor = self._conn.execute(query, tuple(params))
            return cursor.fetchall()
        except sqlite3.Error as e:
            raise RuntimeError(f"Query failed on analysis DB {self._db_path}: {e}") from e

    def _fetch_one_file_info(self, query: str, params: Iterable[Any]) -> Optional[FileInfoRecord]:
        rows = self._fetch_rows(query, params)
        if not rows:
            return None
        return self._row_to_file_info(rows[0])

    def _fetch_one_function(self, query: str, params: Iterable[Any]) -> Optional[FunctionRecord]:
        rows = self._fetch_rows(query, params)
        if not rows:
            return None
        return self._row_to_function(rows[0])

    def _fetch_all_functions(self, query: str, params: Iterable[Any]) -> list[FunctionRecord]:
        rows = self._fetch_rows(query, params)
        return [self._row_to_function(row) for row in rows]

    @staticmethod
    def _row_to_file_info(row: sqlite3.Row) -> FileInfoRecord:
        return FileInfoRecord(
            file_path=row["file_path"],
            base_dir=row["base_dir"],
            file_name=row["file_name"],
            file_extension=row["file_extension"],
            file_size_bytes=row["file_size_bytes"],
            md5_hash=row["md5_hash"],
            sha256_hash=row["sha256_hash"],
            imports=row["imports"],
            exports=row["exports"],
            entry_point=row["entry_point"],
            file_version=row["file_version"],
            product_version=row["product_version"],
            company_name=row["company_name"],
            file_description=row["file_description"],
            internal_name=row["internal_name"],
            original_filename=row["original_filename"],
            legal_copyright=row["legal_copyright"],
            product_name=row["product_name"],
            time_date_stamp_str=row["time_date_stamp_str"],
            file_modified_date_str=row["file_modified_date_str"],
            sections=row["sections"],
            pdb_path=row["pdb_path"],
            rich_header=row["rich_header"],
            tls_callbacks=row["tls_callbacks"],
            is_net_assembly=row["is_net_assembly"],
            clr_metadata=row["clr_metadata"],
            idb_cache_path=row["idb_cache_path"],
            dll_characteristics=row["dll_characteristics"],
            security_features=row["security_features"],
            exception_info=row["exception_info"],
            load_config=row["load_config"],
            analysis_timestamp=row["analysis_timestamp"],
        )

    @staticmethod
    def _row_to_function(row: sqlite3.Row) -> FunctionRecord:
        return FunctionRecord(
            function_id=row["function_id"],
            function_signature=row["function_signature"],
            function_signature_extended=row["function_signature_extended"],
            mangled_name=row["mangled_name"],
            function_name=row["function_name"],
            assembly_code=row["assembly_code"],
            decompiled_code=row["decompiled_code"],
            inbound_xrefs=row["inbound_xrefs"],
            outbound_xrefs=row["outbound_xrefs"],
            simple_inbound_xrefs=row["simple_inbound_xrefs"],
            simple_outbound_xrefs=row["simple_outbound_xrefs"],
            vtable_contexts=row["vtable_contexts"],
            global_var_accesses=row["global_var_accesses"],
            dangerous_api_calls=row["dangerous_api_calls"],
            string_literals=row["string_literals"],
            stack_frame=row["stack_frame"],
            loop_analysis=row["loop_analysis"],
            analysis_errors=row["analysis_errors"],
            created_at=row["created_at"],
        )

    @staticmethod
    def _make_readonly_uri(db_path: Path) -> str:
        posix_path = db_path.as_posix()
        return f"file:{posix_path}?mode=ro"

    @staticmethod
    def _resolve_db_path(db_path: str | Path) -> Path:
        resolved = Path(db_path).expanduser().resolve()
        if not resolved.exists():
            raise FileNotFoundError(f"Database not found at {resolved}")
        return resolved


def open_individual_analysis_db(db_path: str | Path) -> IndividualAnalysisDB:
    return IndividualAnalysisDB(db_path=db_path)

