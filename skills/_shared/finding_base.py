"""Shared infrastructure for security-finding skills.

Consolidates dataclasses, scoring models, data-loading wrappers, and
API-matching utilities duplicated across memory-corruption-detector,
logic-vulnerability-detector, and taint-analysis skill ``_common.py``
files.

Skills import from here and extend with category-specific constants::

    from skills._shared.finding_base import (
        VerificationResult,
        compute_finding_score,
        severity_label,
        load_function_record,
        load_all_functions_slim,
        load_exports,
        load_security_features,
        build_meta,
        matches_api_list,
    )
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from helpers import (
    open_individual_analysis_db,
    parse_json_safe,
)
from helpers.batch_operations import (
    severity_label as _base_severity_label,
    load_function_record as _base_load_function_record,
    load_all_functions_slim as _base_load_all_functions_slim,
    DEFAULT_SEVERITY_BANDS,
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
# Shared scoring constants
# ---------------------------------------------------------------------------

SCORE_WEIGHTS: dict[str, float] = {
    "impact_severity": 0.35,
    "trigger_complexity": 0.25,
    "verification_confidence": 0.20,
    "attack_reachability": 0.20,
}

CONFIDENCE_SCORES: dict[str, float] = {
    "CONFIRMED": 1.0,
    "LIKELY": 0.7,
    "UNCERTAIN": 0.3,
    "FALSE_POSITIVE": 0.0,
}

REACHABILITY_SCORES: dict[str, float] = {
    "exported": 1.0,
    "entry_point_reachable": 0.8,
    "indirect_reachable": 0.5,
    "internal_only": 0.2,
}


def severity_label(score: float, bands: list[tuple[float, str]] | None = None) -> str:
    """Map a numeric score to a severity label (CRITICAL/HIGH/MEDIUM/LOW).

    Pass custom *bands* to override the default thresholds.
    """
    return _base_severity_label(score, bands=bands)


def compute_finding_score(
    impact_severity: float,
    guard_count: int = 0,
    is_exported: bool = False,
    is_entry_reachable: bool = False,
    confidence: str = "LIKELY",
    path_hops: int = 1,
) -> tuple[float, str]:
    """Compute a unified vulnerability score (0-1) and severity label.

    Works for any finding type -- callers pass the category-specific
    ``impact_severity`` value from their own ``IMPACT_SEVERITY`` dict.
    """
    trigger = max(0.1, 1.0 - 0.12 * guard_count) / math.sqrt(max(path_hops, 1))
    conf_score = CONFIDENCE_SCORES.get(confidence, 0.3)

    if is_exported:
        reach = REACHABILITY_SCORES["exported"]
    elif is_entry_reachable:
        reach = REACHABILITY_SCORES["entry_point_reachable"]
    else:
        reach = REACHABILITY_SCORES["internal_only"]

    raw = (
        SCORE_WEIGHTS["impact_severity"] * impact_severity
        + SCORE_WEIGHTS["trigger_complexity"] * trigger
        + SCORE_WEIGHTS["verification_confidence"] * conf_score
        + SCORE_WEIGHTS["attack_reachability"] * reach
    )
    score = round(min(1.0, raw), 3)
    return score, severity_label(score)


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


def load_security_features(db_path: str) -> dict[str, Any]:
    """Load module security features from file_info."""
    try:
        with open_individual_analysis_db(db_path) as db:
            fi = db.get_file_info()
            if fi and fi.security_features:
                features = parse_json_safe(fi.security_features)
                if isinstance(features, dict):
                    return features
    except Exception as exc:
        log_warning(f"Could not load security features: {exc}", "DB_ERROR")
    return {}


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

from helpers.asm_patterns import strip_import_prefix


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
    "CONFIDENCE_SCORES",
    "REACHABILITY_SCORES",
    "SCORE_WEIGHTS",
    "VerificationResult",
    "build_export_names",
    "build_meta",
    "compute_finding_score",
    "load_all_functions_slim",
    "load_exports",
    "load_function_record",
    "load_security_features",  # cosmetic display-only; not used in scoring
    "matches_api_list",
    "severity_label",
    "strip_import_prefix",
]
