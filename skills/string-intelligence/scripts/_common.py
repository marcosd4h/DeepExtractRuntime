"""Shared utilities for string-intelligence skill."""

from __future__ import annotations

import sys
from pathlib import Path

_AGENT_DIR = str(Path(__file__).resolve().parents[3])
if _AGENT_DIR not in sys.path:
    sys.path.insert(0, _AGENT_DIR)

from skills._shared import bootstrap, make_db_resolvers
from skills._shared.skill_common import (  # noqa: F401
    open_individual_analysis_db,
    emit_error,
    parse_json_safe,
)

WORKSPACE_ROOT = bootstrap(__file__)
resolve_db_path, resolve_tracking_db = make_db_resolvers(WORKSPACE_ROOT)

from helpers.string_taxonomy import (  # noqa: E402
    STRING_TAXONOMY,
    CATEGORIES,
    CATEGORY_RISK,
    categorize_string,
    categorize_string_simple,
    categorize_strings,
)

__all__ = [
    "CATEGORIES",
    "CATEGORY_RISK",
    "STRING_TAXONOMY",
    "WORKSPACE_ROOT",
    "categorize_string",
    "categorize_string_simple",
    "categorize_strings",
    "emit_error",
    "open_individual_analysis_db",
    "parse_json_safe",
    "resolve_db_path",
    "resolve_tracking_db",
]
