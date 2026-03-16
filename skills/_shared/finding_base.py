"""Shared infrastructure for security-finding skills.

Consolidates dataclasses, data-loading wrappers, and API-matching
utilities used across ai-memory-corruption-scanner, ai-logic-scanner,
and ai-taint-scanner skill ``_common.py`` files.

Skills import from here and extend with category-specific constants::

    from skills._shared.finding_base import (
        VerificationResult,
        load_function_record,
        load_all_functions_slim,
        load_exports,
        build_meta,
        matches_api_list,
    )
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from helpers import (
    open_individual_analysis_db,
    parse_json_safe,
)
from helpers.batch_operations import (
    load_function_record as _base_load_function_record,
    load_all_functions_slim as _base_load_all_functions_slim,
)
from helpers.errors import db_error_handler, log_warning


# ---------------------------------------------------------------------------
# Shared dataclasses
# ---------------------------------------------------------------------------

@dataclass
class VerificationResult:
    """Result of independent verification for one finding."""

    finding: dict[str, Any]
    confidence: str  # CONFIRMED, LIKELY, UNCERTAIN, FALSE_POSITIVE
    confidence_score: float  # 0.0 - 1.0
    reasoning: str = ""
    assembly_evidence: list[str] = field(default_factory=list)
    mitigating_factors: list[str] = field(default_factory=list)
    verified_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Data-loading wrappers
# ---------------------------------------------------------------------------

def load_function_record(
    db_path: str,
    function_name: Optional[str] = None,
    function_id: Optional[int] = None,
) -> Optional[dict[str, Any]]:
    """Load a function record from the analysis DB."""
    return _base_load_function_record(
        db_path, function_name=function_name, function_id=function_id,
    )


def load_all_functions_slim(db_path: str) -> list[dict[str, Any]]:
    """Load slim function records for module-wide scans."""
    return _base_load_all_functions_slim(db_path)


def load_exports(db_path: str) -> list[dict[str, Any]]:
    """Load export list from file_info."""
    try:
        with db_error_handler(db_path, "loading exports", fatal=False):
            with open_individual_analysis_db(db_path) as db:
                fi = db.get_file_info()
                if fi and fi.exports:
                    exports = parse_json_safe(fi.exports)
                    if isinstance(exports, list):
                        return exports
    except Exception as exc:
        log_warning(f"Could not load exports from {db_path}: {exc}", "DB_ERROR")
    return []


def build_meta(db_path: str, skill_name: str, **extra: Any) -> dict[str, Any]:
    """Build a ``_meta`` block for JSON output."""
    return {
        "db": str(db_path),
        "generated": datetime.now(timezone.utc).isoformat(),
        "skill": skill_name,
        **extra,
    }


# ---------------------------------------------------------------------------
# API matching utility
# ---------------------------------------------------------------------------

from helpers.api_taxonomy import strip_import_prefix


def matches_api_list(api_name: str, api_list: tuple[str, ...]) -> bool:
    """Check if *api_name* starts with any prefix in *api_list*.

    Strips IDA import prefixes before matching.
    """
    clean = strip_import_prefix(api_name)
    for prefix in api_list:
        if clean.startswith(prefix):
            return True
    return False


def build_export_names(db_path: str) -> set[str]:
    """Collect exported function names from the analysis DB."""
    names: set[str] = set()
    for exp in load_exports(db_path):
        if isinstance(exp, dict):
            n = exp.get("name") or exp.get("function_name")
            if n:
                names.add(n)
        elif isinstance(exp, str):
            names.add(exp)
    return names


__all__ = [
    "VerificationResult",
    "build_export_names",
    "build_meta",
    "load_all_functions_slim",
    "load_exports",
    "load_function_record",
    "matches_api_list",
    "strip_import_prefix",
]
