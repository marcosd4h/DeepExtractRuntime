"""DB schema validation and integrity checking.

Catches corruption, missing tables, and schema mismatches early --
before scripts crash with opaque ``OperationalError`` or ``KeyError``.

Usage::

    from helpers.validation import validate_analysis_db, quick_validate

    result = validate_analysis_db("extracted_dbs/appinfo_dll_f2bbf324a1.db")
    if not result:
        for err in result.errors:
            print(f"ERROR: {err}")
        sys.exit(1)

    # Fast hot-path check (file exists + opens + has functions table):
    if not quick_validate(db_path):
        emit_error(f"DB validation failed: {db_path}", "DB_ERROR")
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .db_paths import DB_NAME_RE, normalize_module_name, resolve_db_path, workspace_root_from_tracking_db


# Expected tables and columns for individual analysis DBs.
_ANALYSIS_REQUIRED_TABLES = {"functions", "file_info"}
_ANALYSIS_OPTIONAL_TABLES = {"schema_version"}

_FUNCTIONS_REQUIRED_COLUMNS = frozenset({
    "function_id",
    "function_signature",
    "function_signature_extended",
    "mangled_name",
    "function_name",
    "assembly_code",
    "decompiled_code",
    "inbound_xrefs",
    "outbound_xrefs",
    "simple_inbound_xrefs",
    "simple_outbound_xrefs",
    "vtable_contexts",
    "global_var_accesses",
    "dangerous_api_calls",
    "string_literals",
    "stack_frame",
    "loop_analysis",
    "analysis_errors",
    "created_at",
})

_FILE_INFO_REQUIRED_COLUMNS = frozenset({
    "file_path",
    "base_dir",
    "file_name",
    "file_extension",
    "file_size_bytes",
    "md5_hash",
    "sha256_hash",
    "imports",
    "exports",
    "entry_point",
    "file_version",
    "product_version",
    "company_name",
    "file_description",
    "internal_name",
    "original_filename",
    "legal_copyright",
    "product_name",
    "time_date_stamp_str",
    "file_modified_date_str",
    "sections",
    "pdb_path",
    "rich_header",
    "tls_callbacks",
    "is_net_assembly",
    "clr_metadata",
    "idb_cache_path",
    "dll_characteristics",
    "security_features",
    "exception_info",
    "load_config",
    "analysis_timestamp",
})

# Expected columns for the tracking DB.
_TRACKING_REQUIRED_COLUMNS = frozenset({
    "file_path",
    "file_name",
    "analysis_db_path",
    "status",
})

EXPECTED_SCHEMA_VERSION = 1


# ------------------------------------------------------------------
# ValidationResult
# ------------------------------------------------------------------

@dataclass
class ValidationResult:
    """Outcome of a validation check."""

    ok: bool = True
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.ok

    def add_error(self, msg: str) -> None:
        self.ok = False
        self.errors.append(msg)

    def add_warning(self, msg: str) -> None:
        self.warnings.append(msg)

    def merge(self, other: "ValidationResult") -> None:
        if not other.ok:
            self.ok = False
        self.errors.extend(other.errors)
        self.warnings.extend(other.warnings)


# ------------------------------------------------------------------
# Shared low-level checks
# ------------------------------------------------------------------

def _open_readonly(db_path: str) -> Optional[sqlite3.Connection]:
    """Open a SQLite DB in read-only mode, or return None on failure."""
    p = Path(db_path)
    uri = f"file:{p.as_posix()}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only = ON")
        return conn
    except sqlite3.Error:
        return None


def _get_tables(conn: sqlite3.Connection) -> set[str]:
    """List all table names in the database."""
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    return {row[0] for row in rows}


_ALLOWED_TABLES = frozenset({"functions", "file_info", "analyzed_files", "schema_version"})


def _get_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    """List all column names in *table*."""
    if table not in _ALLOWED_TABLES:
        raise ValueError(
            f"Invalid table name: {table!r}. Allowed: {sorted(_ALLOWED_TABLES)}"
        )
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {row["name"] for row in rows}


# ------------------------------------------------------------------
# Individual analysis DB validation
# ------------------------------------------------------------------

def validate_analysis_db(db_path: str, *, deep: bool = False) -> ValidationResult:
    """Validate an individual analysis database.

    Checks:
    - File exists and is a valid SQLite database
    - ``PRAGMA integrity_check`` passes (only when *deep=True*)
    - Required tables (``functions``, ``file_info``) exist
    - Required columns in ``functions`` are present
    - Schema version is compatible
    - At least one function row exists
    """
    result = ValidationResult()
    p = Path(db_path)

    if not p.exists():
        result.add_error(f"File does not exist: {db_path}")
        return result

    if p.stat().st_size == 0:
        result.add_error(f"File is empty (0 bytes): {db_path}")
        return result

    conn = _open_readonly(db_path)
    if conn is None:
        result.add_error(f"Cannot open as SQLite database: {db_path}")
        return result

    try:
        if deep:
            try:
                integrity = conn.execute("PRAGMA integrity_check").fetchone()
                if integrity and integrity[0] != "ok":
                    result.add_error(f"Integrity check failed: {integrity[0]}")
                    return result
            except sqlite3.Error as e:
                result.add_error(f"Integrity check error: {e}")
                return result

        # Table existence
        tables = _get_tables(conn)
        for required in _ANALYSIS_REQUIRED_TABLES:
            if required not in tables:
                result.add_error(f"Missing required table: {required}")

        if not result.ok:
            return result

        # Column checks on tables consumed by runtime helpers
        func_cols = _get_columns(conn, "functions")
        missing_cols = _FUNCTIONS_REQUIRED_COLUMNS - func_cols
        if missing_cols:
            result.add_error(
                f"Missing columns in 'functions' table: {sorted(missing_cols)}"
            )

        file_info_cols = _get_columns(conn, "file_info")
        missing_file_info_cols = _FILE_INFO_REQUIRED_COLUMNS - file_info_cols
        if missing_file_info_cols:
            result.add_error(
                "Missing columns in 'file_info' table: "
                f"{sorted(missing_file_info_cols)}"
            )

        # Schema version
        if "schema_version" in tables:
            try:
                row = conn.execute(
                    "SELECT MAX(version) FROM schema_version"
                ).fetchone()
                if row and row[0] is not None:
                    version = int(row[0])
                    if version > EXPECTED_SCHEMA_VERSION:
                        result.add_warning(
                            f"Schema version {version} > expected "
                            f"{EXPECTED_SCHEMA_VERSION} -- some queries "
                            "may behave unexpectedly"
                        )
            except sqlite3.Error:
                result.add_warning("Could not read schema_version table")
        else:
            result.add_warning("No schema_version table (older extraction?)")

        # At least one function
        try:
            count_row = conn.execute(
                "SELECT COUNT(*) FROM functions"
            ).fetchone()
            if count_row and count_row[0] == 0:
                result.add_warning("functions table is empty (0 rows)")
        except sqlite3.Error as e:
            result.add_error(f"Cannot query functions table: {e}")

    finally:
        conn.close()

    return result


# ------------------------------------------------------------------
# Tracking DB validation
# ------------------------------------------------------------------

def validate_tracking_db(db_path: str) -> ValidationResult:
    """Validate the ``analyzed_files.db`` tracking database.

    Checks:
    - File exists and opens as SQLite
    - ``analyzed_files`` table exists with required columns
    - All COMPLETE records point to existing DB files
    """
    result = ValidationResult()
    p = Path(db_path)

    if not p.exists():
        result.add_error(f"Tracking DB not found: {db_path}")
        return result

    conn = _open_readonly(db_path)
    if conn is None:
        result.add_error(f"Cannot open tracking DB: {db_path}")
        return result

    try:
        tables = _get_tables(conn)
        if "analyzed_files" not in tables:
            result.add_error("Missing required table: analyzed_files")
            return result

        cols = _get_columns(conn, "analyzed_files")
        missing = _TRACKING_REQUIRED_COLUMNS - cols
        if missing:
            result.add_error(
                f"Missing columns in 'analyzed_files': {sorted(missing)}"
            )
            return result

        # Check that COMPLETE records have valid DB paths
        workspace_root = workspace_root_from_tracking_db(p)
        rows = conn.execute(
            "SELECT file_name, analysis_db_path FROM analyzed_files "
            "WHERE status = 'COMPLETE'"
        ).fetchall()

        for row in rows:
            file_name = row["file_name"] or "(unnamed)"
            db_rel = row["analysis_db_path"]
            if not db_rel:
                result.add_warning(
                    f"COMPLETE record '{file_name}' has no analysis_db_path"
                )
                continue
            resolved_path = Path(resolve_db_path(db_rel, workspace_root))
            if not resolved_path.exists():
                result.add_error(
                    f"COMPLETE record '{file_name}' points to missing DB: "
                    f"{db_rel}"
                )

    finally:
        conn.close()

    return result


# ------------------------------------------------------------------
# Function index validation
# ------------------------------------------------------------------

def validate_function_index(index_path: str) -> ValidationResult:
    """Validate a function index JSON file.

    Checks:
    - Valid JSON
    - Top-level is a dict mapping function names to dicts
    - Entries contain expected keys (``function_id``, etc.)
    """
    result = ValidationResult()
    p = Path(index_path)

    if not p.exists():
        result.add_error(f"Index file not found: {index_path}")
        return result

    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        result.add_error(f"Invalid JSON: {e}")
        return result
    except OSError as e:
        result.add_error(f"Cannot read file: {e}")
        return result

    if not isinstance(data, dict):
        result.add_error(
            f"Expected top-level dict, got {type(data).__name__}"
        )
        return result

    if not data:
        result.add_warning("Function index is empty (0 entries)")
        return result

    # Validate every entry because downstream lookups can depend on any key.
    for name, entry in data.items():
        if not isinstance(entry, dict):
            result.add_error(
                f"Entry '{name}' is not a dict: {type(entry).__name__}"
            )
            break
        if "function_id" not in entry:
            result.add_warning(
                f"Entry '{name}' missing 'function_id' field"
            )

    return result


# ------------------------------------------------------------------
# Extraction–DB consistency checks
# ------------------------------------------------------------------

def validate_function_id_consistency(
    db_path: str,
    extraction_dir: str | Path,
) -> ValidationResult:
    """Validate function_id consistency between function_index.json and DB.

    Compares ``extracted_code/<module>/function_index.json`` with
    ``functions.function_id`` in the analysis DB. Matches entries by
    function name (or mangled name when function_name differs).

    Checks:
    - For each function in function_index.json: if present in DB, IDs must match
    - Reports mismatched IDs as errors
    - Warns on functions in index but not in DB (or vice versa)
    """
    result = ValidationResult()
    ext_dir = Path(extraction_dir)
    index_path = ext_dir / "function_index.json"

    if not index_path.exists():
        result.add_error(f"Function index not found: {index_path}")
        return result

    try:
        with open(index_path, "r", encoding="utf-8") as f:
            index_data = json.load(f)
    except json.JSONDecodeError as e:
        result.add_error(f"Invalid function_index.json: {e}")
        return result
    except OSError as e:
        result.add_error(f"Cannot read function_index.json: {e}")
        return result

    if not isinstance(index_data, dict):
        result.add_error(
            f"Expected function_index.json to be a dict, got {type(index_data).__name__}"
        )
        return result

    conn = _open_readonly(db_path)
    if conn is None:
        result.add_error(f"Cannot open database: {db_path}")
        return result

    try:
        tables = _get_tables(conn)
        if "functions" not in tables:
            result.add_error("Database has no 'functions' table")
            return result

        rows = conn.execute(
            "SELECT function_id, function_name, mangled_name FROM functions"
        ).fetchall()

        db_by_name: dict[str, int] = {}
        db_by_mangled: dict[str, int] = {}
        for row in rows:
            fid = row["function_id"]
            name = row["function_name"]
            mangled = row["mangled_name"]
            if name:
                db_by_name[name] = fid
            if mangled:
                db_by_mangled[mangled] = fid

        mismatches: list[str] = []
        in_index_not_db: list[str] = []
        for key, entry in index_data.items():
            if not isinstance(entry, dict):
                continue
            json_id = entry.get("function_id")
            if json_id is None:
                continue
            db_id = db_by_name.get(key) or db_by_mangled.get(key)
            if db_id is None:
                in_index_not_db.append(key)
            elif db_id != json_id:
                mismatches.append(
                    f"'{key}': function_index.json has {json_id}, DB has {db_id}"
                )

        for msg in mismatches:
            result.add_error(f"Function ID mismatch: {msg}")

        if in_index_not_db:
            sample = in_index_not_db[:5]
            extra = f" (and {len(in_index_not_db) - 5} more)" if len(in_index_not_db) > 5 else ""
            result.add_warning(
                f"Functions in function_index.json but not in DB: {sample}{extra}"
            )

        in_db_not_index: list[str] = []
        seen_missing: set[str] = set()
        for row in rows:
            name = row["function_name"]
            mangled = row["mangled_name"]
            if (name and name in index_data) or (mangled and mangled in index_data):
                continue
            display_name = name or mangled or f"<function_id {row['function_id']}>"
            if display_name not in seen_missing:
                in_db_not_index.append(display_name)
                seen_missing.add(display_name)
        if in_db_not_index:
            sample = in_db_not_index[:5]
            extra = f" (and {len(in_db_not_index) - 5} more)" if len(in_db_not_index) > 5 else ""
            result.add_warning(
                f"Functions in DB but not in function_index.json: {sample}{extra}"
            )

    finally:
        conn.close()

    return result


def validate_file_info_consistency(
    db_path: str,
    extraction_dir: str | Path,
) -> ValidationResult:
    """Validate file identity consistency between file_info.json and DB.

    Compares ``extracted_code/<module>/file_info.json`` with the
    ``file_info`` table in the analysis DB. Checks filename, hash, and
    version fields where available.

    Checks:
    - file_name (basic_file_info.file_name vs file_info.file_name)
    - md5_hash (basic_file_info.md5_hash vs file_info.md5_hash)
    - sha256_hash (basic_file_info.sha256_hash vs file_info.sha256_hash)
    - file_version (pe_version_info.file_version vs file_info.file_version)
    - product_version (pe_version_info.product_version vs file_info.product_version)
    """
    result = ValidationResult()
    ext_dir = Path(extraction_dir)
    file_info_path = ext_dir / "file_info.json"

    if not file_info_path.exists():
        result.add_error(f"file_info.json not found: {file_info_path}")
        return result

    try:
        with open(file_info_path, "r", encoding="utf-8") as f:
            json_info = json.load(f)
    except json.JSONDecodeError as e:
        result.add_error(f"Invalid file_info.json: {e}")
        return result
    except OSError as e:
        result.add_error(f"Cannot read file_info.json: {e}")
        return result

    conn = _open_readonly(db_path)
    if conn is None:
        result.add_error(f"Cannot open database: {db_path}")
        return result

    try:
        tables = _get_tables(conn)
        if "file_info" not in tables:
            result.add_error("Database has no 'file_info' table")
            return result

        row = conn.execute("SELECT * FROM file_info LIMIT 1").fetchone()
        if not row:
            result.add_warning("file_info table is empty")
            return result

        basic = json_info.get("basic_file_info") or {}
        version_info = json_info.get("pe_version_info") or {}

        json_file_name = basic.get("file_name")
        json_md5 = basic.get("md5_hash")
        json_sha256 = basic.get("sha256_hash")
        json_file_version = version_info.get("file_version")
        json_product_version = version_info.get("product_version")

        db_file_name = row["file_name"] if "file_name" in row else None
        db_md5 = row["md5_hash"] if "md5_hash" in row else None
        db_sha256 = row["sha256_hash"] if "sha256_hash" in row else None
        db_file_version = row["file_version"] if "file_version" in row else None
        db_product_version = (
            row["product_version"] if "product_version" in row else None
        )

        def _compare(
            field: str,
            json_val: str | None,
            db_val: str | None,
        ) -> None:
            if json_val is None and db_val is None:
                return
            if json_val is None or db_val is None:
                result.add_warning(
                    f"file_info.{field}: present in one source only "
                    f"(JSON={json_val!r}, DB={db_val!r})"
                )
                return
            if str(json_val).strip() != str(db_val).strip():
                result.add_error(
                    f"file_info.{field} mismatch: "
                    f"file_info.json has {json_val!r}, DB has {db_val!r}"
                )

        _compare("file_name", json_file_name, db_file_name)
        _compare("md5_hash", json_md5, db_md5)
        _compare("sha256_hash", json_sha256, db_sha256)
        _compare("file_version", json_file_version, db_file_version)
        _compare("product_version", json_product_version, db_product_version)

    finally:
        conn.close()

    return result


def validate_extraction_db_consistency(
    db_path: str,
    extraction_dir: str | Path,
) -> ValidationResult:
    """Run all extraction–DB consistency checks.

    Runs validate_function_id_consistency and validate_file_info_consistency,
    merging results.
    """
    result = ValidationResult()
    result.merge(validate_function_id_consistency(db_path, extraction_dir))
    result.merge(validate_file_info_consistency(db_path, extraction_dir))
    return result


# ------------------------------------------------------------------
# Quick validate (hot-path)
# ------------------------------------------------------------------

# ------------------------------------------------------------------
# Input validation helpers
# ------------------------------------------------------------------

def validate_function_id(value: int | str, arg_name: str = "--id") -> int:
    """Validate a function ID is a positive integer.

    Accepts int or string, returns validated int.
    Raises ScriptError with INVALID_ARGS if invalid.
    """
    from .errors import ErrorCode, ScriptError

    if isinstance(value, bool):
        raise ScriptError(
            f"{arg_name} must be an integer, got: {value!r}",
            ErrorCode.INVALID_ARGS,
        )

    if isinstance(value, float) and not value.is_integer():
        raise ScriptError(
            f"{arg_name} must be an integer, got: {value!r}",
            ErrorCode.INVALID_ARGS,
        )

    try:
        fid = int(value)
    except (TypeError, ValueError):
        raise ScriptError(
            f"{arg_name} must be an integer, got: {value!r}",
            ErrorCode.INVALID_ARGS,
        )
    if fid <= 0:
        raise ScriptError(
            f"{arg_name} must be a positive integer, got: {fid}",
            ErrorCode.INVALID_ARGS,
        )
    return fid


def validate_depth(value: int, *, max_depth: int = 10, arg_name: str = "--depth") -> int:
    """Validate a depth/recursion parameter is within safe bounds.

    Returns the clamped value. Raises ScriptError for negative values;
    silently clamps values above *max_depth* to prevent runaway recursion.
    """
    from .errors import ErrorCode, ScriptError

    if not isinstance(value, int):
        try:
            value = int(value)
        except (TypeError, ValueError):
            raise ScriptError(
                f"{arg_name} must be an integer, got: {value!r}",
                ErrorCode.INVALID_ARGS,
            )
    if value < 0:
        raise ScriptError(
            f"{arg_name} must be non-negative, got: {value}",
            ErrorCode.INVALID_ARGS,
        )
    return min(value, max_depth)


def validate_positive_int(
    value: int | str,
    arg_name: str,
    *,
    min_val: int = 1,
    max_val: Optional[int] = None,
) -> int:
    """Validate that *value* is an integer in [min_val, max_val].

    Returns the validated int.
    Raises ScriptError with INVALID_ARGS if invalid.
    """
    from .errors import ErrorCode, ScriptError

    try:
        ival = int(value)
    except (TypeError, ValueError):
        raise ScriptError(
            f"{arg_name} must be an integer, got: {value!r}",
            ErrorCode.INVALID_ARGS,
        )
    if ival < min_val:
        raise ScriptError(
            f"{arg_name} must be >= {min_val}, got: {ival}",
            ErrorCode.INVALID_ARGS,
        )
    if max_val is not None and ival > max_val:
        raise ScriptError(
            f"{arg_name} must be <= {max_val}, got: {ival}",
            ErrorCode.INVALID_ARGS,
        )
    return ival


# ------------------------------------------------------------------
# Quick validate (hot-path)
# ------------------------------------------------------------------

def quick_validate(db_path: str) -> bool:
    """Fast check: file exists, opens as SQLite, has a ``functions`` table.

    Suitable for hot paths where full validation is too expensive.
    Returns ``True`` if the DB looks usable, ``False`` otherwise.
    """
    p = Path(db_path)
    if not p.exists() or p.stat().st_size == 0:
        return False

    conn = _open_readonly(db_path)
    if conn is None:
        return False

    try:
        tables = _get_tables(conn)
        return "functions" in tables
    except sqlite3.Error:
        return False
    finally:
        conn.close()


# ------------------------------------------------------------------
# Workspace data preflight validation
# ------------------------------------------------------------------

@dataclass
class WorkspaceDataStatus:
    """Summary of available workspace data sources."""

    has_extracted_code: bool = False
    has_extracted_dbs: bool = False
    has_tracking_db: bool = False
    modules_with_code: list[str] = field(default_factory=list)
    modules_with_dbs: list[str] = field(default_factory=list)
    json_only_modules: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True if at least one data source is available."""
        return self.has_extracted_code or self.has_extracted_dbs

    @property
    def db_available(self) -> bool:
        """True if DB-backed analysis is possible."""
        return self.has_extracted_dbs and len(self.modules_with_dbs) > 0

    @property
    def json_only(self) -> bool:
        """True if only JSON files are available (no DBs)."""
        return self.has_extracted_code and not self.has_extracted_dbs

    def summary(self) -> str:
        """One-line summary of workspace data status."""
        if not self.ok:
            return "No extraction data found"
        parts = []
        if self.modules_with_dbs:
            parts.append(f"{len(self.modules_with_dbs)} module DB(s)")
        if self.json_only_modules:
            parts.append(f"{len(self.json_only_modules)} JSON-only module(s)")
        if self.has_tracking_db:
            parts.append("tracking DB")
        return ", ".join(parts) if parts else "No usable modules"


def validate_workspace_data(
    workspace_root: str | Path,
    *,
    sample_limit: int | None = None,
) -> WorkspaceDataStatus:
    """Pre-flight check for extraction data availability.

    Scans ``extracted_code/`` and ``extracted_dbs/`` to determine what
    data sources are available.  When *sample_limit* is set (or defaulted
    from ``scale.health_sample_count``), only a random sample of modules
    are checked for their JSON files -- this avoids O(N) I/O when the
    workspace has thousands of modules.  The full DB list is still
    obtained from the tracking DB when possible.

    Returns a :class:`WorkspaceDataStatus` describing the state so
    callers can decide whether to proceed, fall back to JSON-only mode,
    or emit a clear error.

    Usage::

        status = validate_workspace_data(workspace_root)
        if not status.ok:
            emit_error("No extraction data found. Run DeepExtractIDA first.", "NO_DATA")
        if status.json_only:
            log_warning("No analysis DBs found; some features unavailable.", "NO_DATA")
    """
    import random
    from .config import get_config_value

    root = Path(workspace_root)
    status = WorkspaceDataStatus()

    code_dir = root / "extracted_code"
    dbs_dir = root / "extracted_dbs"

    if sample_limit is None:
        sample_limit = get_config_value("scale.health_sample_count", 100)

    # --- Check extracted_code/ -----------------------------------------------
    from .module_discovery import iter_module_dirs, iter_module_dbs

    if code_dir.is_dir():
        status.has_extracted_code = True
        all_valid = iter_module_dirs(code_dir)
        all_dir_count = sum(1 for d in code_dir.iterdir() if d.is_dir())
        dirs_to_check = all_valid
        if sample_limit and len(all_valid) > sample_limit:
            dirs_to_check = random.sample(all_valid, sample_limit)

        for mod in dirs_to_check:
            status.modules_with_code.append(mod.name)

        if len(all_valid) > len(dirs_to_check):
            sampled_valid = len(status.modules_with_code)
            estimated_total = int(
                sampled_valid / max(len(dirs_to_check), 1) * len(all_valid)
            )
            status.warnings.append(
                f"Validated {len(dirs_to_check)}/{len(all_valid)} module "
                f"directories (sampled). ~{estimated_total} appear valid."
            )

        if not status.modules_with_code:
            status.warnings.append(
                "extracted_code/ exists but contains no valid module directories"
            )

    # --- Check extracted_dbs/ ------------------------------------------------
    if dbs_dir.is_dir():
        status.has_extracted_dbs = True
        tracking = dbs_dir / "analyzed_files.db"
        if tracking.exists():
            tracking_validation = validate_tracking_db(str(tracking))
            if tracking_validation.ok:
                status.has_tracking_db = True
                try:
                    from .analyzed_files_db import open_analyzed_files_db
                    with open_analyzed_files_db(tracking) as db:
                        for rec in db.get_complete():
                            if rec.analysis_db_path:
                                status.modules_with_dbs.append(
                                    Path(rec.analysis_db_path).stem
                                )
                except Exception as exc:
                    from .errors import log_warning
                    log_warning(
                        f"Failed to read tracking DB {tracking}: {exc}",
                        "DB_ERROR",
                    )
                    status.warnings.append(f"Tracking DB error: {exc}")
            else:
                status.warnings.extend(
                    f"Tracking DB validation error: {err}"
                    for err in tracking_validation.errors
                )
                status.warnings.extend(
                    f"Tracking DB validation warning: {warning}"
                    for warning in tracking_validation.warnings
                )

        if not status.modules_with_dbs:
            for db in iter_module_dbs(dbs_dir, include_empty=True):
                status.modules_with_dbs.append(Path(db.path).stem)
            if not status.modules_with_dbs and not status.has_tracking_db:
                status.warnings.append(
                    "extracted_dbs/ exists but contains no .db files"
                )
    else:
        if status.has_extracted_code:
            status.warnings.append(
                "extracted_dbs/ directory not found; DB-backed analysis "
                "unavailable. Only JSON-based operations will work."
            )

    # --- Identify JSON-only modules ------------------------------------------
    db_module_keys: set[str] = set()
    for stem in status.modules_with_dbs:
        match = DB_NAME_RE.match(f"{stem}.db")
        module_stem = match.group(1) if match else stem
        db_module_keys.add(_normalize_module_key(module_stem))

    for mod_name in status.modules_with_code:
        if _normalize_module_key(mod_name) not in db_module_keys:
            status.json_only_modules.append(mod_name)

    # --- Final diagnostics ---------------------------------------------------
    if not status.ok:
        status.errors.append(
            "No extraction data found. Ensure DeepExtractIDA has been run "
            "and output is in extracted_code/ and/or extracted_dbs/."
        )

    return status


def _normalize_module_key(name: str) -> str:
    """Normalize module names for robust exact matching across naming styles."""
    return normalize_module_name(name)
