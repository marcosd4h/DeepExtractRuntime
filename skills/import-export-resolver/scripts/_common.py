"""Shared utilities for import-export-resolver skill."""

from __future__ import annotations

import sys
from pathlib import Path

_AGENT_DIR = str(Path(__file__).resolve().parents[3])
if _AGENT_DIR not in sys.path:
    sys.path.insert(0, _AGENT_DIR)

from skills._shared import bootstrap, make_db_resolvers
from skills._shared.skill_common import (  # noqa: F401
    emit_error,
    emit_json,
    log_warning,
    open_individual_analysis_db,
    parse_json_safe,
    get_cached,
    cache_result,
    status_message,
    db_error_handler,
)

WORKSPACE_ROOT = bootstrap(__file__)
resolve_db_path, resolve_tracking_db = make_db_resolvers(WORKSPACE_ROOT)

from helpers.import_export_index import (  # noqa: E402
    ExportEntry,
    ImportEntry,
    ImportExportIndex,
)

__all__ = [
    "WORKSPACE_ROOT",
    "resolve_db_path",
    "resolve_tracking_db",
    "emit_error",
    "emit_json",
    "log_warning",
    "open_individual_analysis_db",
    "parse_json_safe",
    "get_cached",
    "cache_result",
    "status_message",
    "db_error_handler",
    "ExportEntry",
    "ImportEntry",
    "ImportExportIndex",
]
