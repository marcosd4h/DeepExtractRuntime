"""Helper utilities for querying the analyzed_files tracking database."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import json
from pathlib import Path
import sqlite3
from typing import Any, Iterable, Optional
import warnings

from ..db_paths import resolve_db_path, workspace_root_from_tracking_db

_log = logging.getLogger(__name__)

from ..sql_utils import escape_like, LIKE_ESCAPE


ANALYZED_FILES_TABLE = "analyzed_files"
DEFAULT_DB_RELATIVE_PATH = Path("extracted_dbs") / "analyzed_files.db"


@dataclass(frozen=True)
class AnalyzedFileRecord:
    file_path: str
    base_dir: Optional[str]
    file_name: Optional[str]
    file_extension: Optional[str]
    md5_hash: Optional[str]
    sha256_hash: Optional[str]
    analysis_db_path: Optional[str]
    status: str
    analysis_flags: Optional[str]
    analysis_start_timestamp: Optional[str]
    analysis_completion_timestamp: Optional[str]

    @property
    def parsed_analysis_flags(self) -> Optional[dict[str, Any]]:
        if not self.analysis_flags:
            return None
        try:
            return json.loads(self.analysis_flags)
        except json.JSONDecodeError:
            return None


class CrossModuleXrefResult(list):
    """List-like cross-module xref results with skipped-module metadata."""

    def __init__(
        self,
        results: Iterable[dict[str, Any]] = (),
        skipped: Iterable[dict[str, str]] = (),
    ) -> None:
        super().__init__(results)
        self.skipped = list(skipped)

    @property
    def results(self) -> list[dict[str, Any]]:
        return list(self)

    @property
    def partial(self) -> bool:
        return bool(self.skipped)


class AnalyzedFilesDB:
    """Read-only access to the analyzed_files tracking database."""

    def __init__(self, db_path: Optional[str | Path] = None) -> None:
        self._db_path = self._resolve_db_path(db_path)
        self._conn: Optional[sqlite3.Connection] = None

    def __enter__(self) -> "AnalyzedFilesDB":
        self._ensure_open()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __del__(self) -> None:
        if getattr(self, "_conn", None) is not None:
            warnings.warn(
                f"Unclosed AnalyzedFilesDB({self._db_path}). "
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

    def get_all(self, limit: Optional[int] = None, offset: Optional[int] = None) -> list[AnalyzedFileRecord]:
        query = f"SELECT * FROM {ANALYZED_FILES_TABLE}"
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
        return self._fetch_all(query, params)

    def get_by_file_path(self, file_path: str) -> Optional[AnalyzedFileRecord]:
        query = f"SELECT * FROM {ANALYZED_FILES_TABLE} WHERE file_path = ?"
        return self._fetch_one(query, (file_path,))

    def get_by_status(self, status: str) -> list[AnalyzedFileRecord]:
        query = f"SELECT * FROM {ANALYZED_FILES_TABLE} WHERE status = ?"
        return self._fetch_all(query, (status.upper(),))

    def get_by_file_name(self, file_name: str, case_insensitive: bool = True) -> list[AnalyzedFileRecord]:
        if case_insensitive:
            query = f"SELECT * FROM {ANALYZED_FILES_TABLE} WHERE LOWER(file_name) = LOWER(?)"
        else:
            query = f"SELECT * FROM {ANALYZED_FILES_TABLE} WHERE file_name = ?"
        return self._fetch_all(query, (file_name,))

    def get_by_extension(self, extension: str, case_insensitive: bool = True) -> list[AnalyzedFileRecord]:
        normalized = self._normalize_extension(extension)
        if case_insensitive:
            query = f"SELECT * FROM {ANALYZED_FILES_TABLE} WHERE LOWER(file_extension) = LOWER(?)"
        else:
            query = f"SELECT * FROM {ANALYZED_FILES_TABLE} WHERE file_extension = ?"
        return self._fetch_all(query, (normalized,))

    def get_by_hash(self, hash_value: str, hash_type: str) -> list[AnalyzedFileRecord]:
        normalized = hash_type.strip().lower()
        if normalized == "md5":
            column = "md5_hash"
        elif normalized == "sha256":
            column = "sha256_hash"
        else:
            raise ValueError("hash_type must be 'md5' or 'sha256'")
        query = f"SELECT * FROM {ANALYZED_FILES_TABLE} WHERE {column} = ?"
        return self._fetch_all(query, (hash_value,))

    def count_by_status(self) -> dict[str, int]:
        query = f"SELECT status, COUNT(*) AS count FROM {ANALYZED_FILES_TABLE} GROUP BY status"
        rows = self._fetch_rows(query, ())
        return {row["status"]: int(row["count"]) for row in rows}

    def get_analysis_db_path(self, file_path: str) -> Optional[str]:
        record = self.get_by_file_path(file_path)
        if record is None:
            return None
        return record.analysis_db_path

    def list_statuses(self) -> list[str]:
        query = f"SELECT DISTINCT status FROM {ANALYZED_FILES_TABLE} ORDER BY status"
        rows = self._fetch_rows(query, ())
        return [row["status"] for row in rows]

    def get_complete(self) -> list[AnalyzedFileRecord]:
        return self.get_by_status("COMPLETE")

    def get_pending(self) -> list[AnalyzedFileRecord]:
        return self.get_by_status("PENDING")

    def get_analyzing(self) -> list[AnalyzedFileRecord]:
        return self.get_by_status("ANALYZING")

    def search(
        self,
        status: Optional[str] = None,
        extension: Optional[str] = None,
        name_contains: Optional[str] = None,
        case_insensitive: bool = True,
    ) -> list[AnalyzedFileRecord]:
        clauses: list[str] = []
        params: list[Any] = []

        if status:
            clauses.append("status = ?")
            params.append(status.upper())
        if extension:
            normalized = self._normalize_extension(extension)
            if case_insensitive:
                clauses.append("LOWER(file_extension) = LOWER(?)")
            else:
                clauses.append("file_extension = ?")
            params.append(normalized)
        if name_contains:
            if case_insensitive:
                clauses.append("LOWER(file_name) LIKE LOWER(?)" + LIKE_ESCAPE)
            else:
                clauses.append("file_name LIKE ?" + LIKE_ESCAPE)
            params.append(f"%{escape_like(name_contains)}%")

        query = f"SELECT * FROM {ANALYZED_FILES_TABLE}"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        return self._fetch_all(query, params)

    def get_by_filters(self, **filters: Any) -> list[AnalyzedFileRecord]:
        if not filters:
            return []
        allowed = {
            "file_path",
            "base_dir",
            "file_name",
            "file_extension",
            "md5_hash",
            "sha256_hash",
            "analysis_db_path",
            "status",
            "analysis_flags",
            "analysis_start_timestamp",
            "analysis_completion_timestamp",
        }
        invalid = [name for name in filters if name not in allowed]
        if invalid:
            raise ValueError(f"Invalid filter columns: {', '.join(sorted(invalid))}")
        clauses = " AND ".join(f"{name} = ?" for name in filters)
        query = f"SELECT * FROM {ANALYZED_FILES_TABLE} WHERE {clauses}"
        return self._fetch_all(query, list(filters.values()))

    def get_cross_module_xrefs(
        self,
        function_name: str,
        *,
        module_filter: Iterable[str] | None = None,
        max_modules: int | None = None,
    ) -> CrossModuleXrefResult:
        """Find references to *function_name* across analysed module DBs.

        Opens sibling individual analysis databases (resolved via each
        record's ``analysis_db_path``) and searches their outbound xrefs
        for calls matching *function_name* (case-insensitive substring).

        Uses a thread pool for parallel scanning of module databases.

        Parameters
        ----------
        module_filter:
            If given, only scan modules whose ``file_name`` (case-insensitive)
            is in this set.  Recommended when the workspace has many modules.
        max_modules:
            Maximum number of modules to scan.  Defaults to
            ``scale.max_modules_cross_scan`` config (0 = unlimited)
            when *module_filter* is not specified.

        Returns a list-like :class:`CrossModuleXrefResult`. The list items are
        dicts with keys: ``source_module``, ``source_function_id``,
        ``source_function_name``, ``target_function``, ``target_module``.
        When some sibling DBs could not be scanned, ``result.skipped``
        contains dicts with ``module_name`` and ``reason`` fields.
        """
        from ..individual_analysis_db import open_individual_analysis_db, parse_json_safe
        from ..config import get_config_value

        records = [r for r in self.get_complete() if r.analysis_db_path]
        if not records:
            return CrossModuleXrefResult()

        if module_filter is not None:
            allowed = {m.lower() for m in module_filter}
            records = [
                r for r in records
                if r.file_name and r.file_name.lower() in allowed
            ]

        if max_modules is None and module_filter is None:
            max_modules = get_config_value("scale.max_modules_cross_scan", 0)
        if max_modules is not None and max_modules > 0 and len(records) > max_modules:
            records = records[:max_modules]

        results: list[dict[str, Any]] = []
        skipped: list[dict[str, str]] = []
        workspace_root = workspace_root_from_tracking_db(self._db_path)

        def scan_module(
            rec: AnalyzedFileRecord,
        ) -> tuple[list[dict[str, Any]], dict[str, str] | None]:
            if not rec.analysis_db_path:
                return [], None
            db_path = Path(resolve_db_path(rec.analysis_db_path, workspace_root))
            if not db_path.exists():
                module_name = rec.file_name or rec.file_path
                reason = f"Analysis DB not found: {db_path}"
                _log.warning(
                    "Skipping module %s during cross-module search: %s",
                    module_name,
                    reason,
                )
                return [], {
                    "module_name": module_name,
                    "reason": reason,
                }

            module_results = []
            try:
                with open_individual_analysis_db(db_path) as mod_db:
                    matches = mod_db.search_by_json_field(
                        "simple_outbound_xrefs", function_name
                    )
                    for func in matches:
                        xrefs = parse_json_safe(func.simple_outbound_xrefs)
                        if not xrefs or not isinstance(xrefs, list):
                            continue
                        for xref in xrefs:
                            if isinstance(xref, dict):
                                name = xref.get("function_name", "")
                                if function_name.lower() in name.lower():
                                    module_results.append({
                                        "source_module": rec.file_name,
                                        "source_function_id": func.function_id,
                                        "source_function_name": func.function_name,
                                        "target_function": name,
                                        "target_module": xref.get("module_name", ""),
                                    })
            except (json.JSONDecodeError, OSError, RuntimeError, sqlite3.Error) as exc:
                module_name = rec.file_name or rec.file_path
                reason = str(exc)
                _log.warning(
                    "Skipping module %s during cross-module search: %s",
                    module_name,
                    reason,
                )
                return [], {
                    "module_name": module_name,
                    "reason": reason,
                }
            return module_results, None

        with ThreadPoolExecutor(max_workers=8) as executor:
            future_results = executor.map(scan_module, records)
            for res, skipped_module in future_results:
                results.extend(res)
                if skipped_module is not None:
                    skipped.append(skipped_module)

        return CrossModuleXrefResult(results, skipped)

    def _ensure_open(self) -> None:
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
            raise RuntimeError(f"Failed to open tracking DB {self._db_path}: {e}") from e

    def _fetch_all(self, query: str, params: Iterable[Any]) -> list[AnalyzedFileRecord]:
        rows = self._fetch_rows(query, params)
        return [self._row_to_record(row) for row in rows]

    def _fetch_one(self, query: str, params: Iterable[Any]) -> Optional[AnalyzedFileRecord]:
        rows = self._fetch_rows(query, params)
        if not rows:
            return None
        return self._row_to_record(rows[0])

    def _fetch_rows(self, query: str, params: Iterable[Any]) -> list[sqlite3.Row]:
        self._ensure_open()
        assert self._conn is not None
        try:
            cursor = self._conn.execute(query, tuple(params))
            return cursor.fetchall()
        except sqlite3.Error as e:
            raise RuntimeError(f"Query failed on tracking DB {self._db_path}: {e}") from e

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> AnalyzedFileRecord:
        return AnalyzedFileRecord(
            file_path=row["file_path"],
            base_dir=row["base_dir"],
            file_name=row["file_name"],
            file_extension=row["file_extension"],
            md5_hash=row["md5_hash"],
            sha256_hash=row["sha256_hash"],
            analysis_db_path=row["analysis_db_path"],
            status=row["status"],
            analysis_flags=row["analysis_flags"],
            analysis_start_timestamp=row["analysis_start_timestamp"],
            analysis_completion_timestamp=row["analysis_completion_timestamp"],
        )

    @staticmethod
    def _normalize_extension(extension: str) -> str:
        if extension and not extension.startswith("."):
            return f".{extension}"
        return extension

    @staticmethod
    def _make_readonly_uri(db_path: Path) -> str:
        posix_path = db_path.as_posix()
        return f"file:{posix_path}?mode=ro"

    @staticmethod
    def _resolve_db_path(db_path: Optional[str | Path]) -> Path:
        if db_path is not None:
            resolved = Path(db_path).expanduser().resolve()
            if not resolved.exists():
                raise FileNotFoundError(f"Database not found at {resolved}")
            return resolved

        from ..db_paths import resolve_tracking_db_auto

        auto_resolved = resolve_tracking_db_auto()
        if auto_resolved is not None:
            return Path(auto_resolved).resolve()

        module_root = Path(__file__).resolve().parents[2]
        candidate = module_root / DEFAULT_DB_RELATIVE_PATH
        if candidate.exists():
            return candidate

        cwd_candidate = Path.cwd() / DEFAULT_DB_RELATIVE_PATH
        if cwd_candidate.exists():
            return cwd_candidate

        raise FileNotFoundError(
            "analyzed_files.db not found. Provide db_path or place the database at "
            f"{DEFAULT_DB_RELATIVE_PATH} relative to the project root. "
            f"Checked: auto-detected workspace root, {candidate}, and {cwd_candidate}."
        )


def open_analyzed_files_db(db_path: Optional[str | Path] = None) -> AnalyzedFilesDB:
    return AnalyzedFilesDB(db_path=db_path)
