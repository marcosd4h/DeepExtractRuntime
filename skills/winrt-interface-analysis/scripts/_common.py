"""Shared utilities for the winrt-interface-analysis skill."""

from __future__ import annotations

import sys
from pathlib import Path

_AGENT_DIR = str(Path(__file__).resolve().parents[3])
if _AGENT_DIR not in sys.path:
    sys.path.insert(0, _AGENT_DIR)

from skills._shared import bootstrap, make_db_resolvers

WORKSPACE_ROOT = bootstrap(__file__)
resolve_db_path, resolve_tracking_db = make_db_resolvers(WORKSPACE_ROOT)

from helpers import (  # noqa: E402
    emit_error,
    open_individual_analysis_db,
    parse_json_safe,
)
from helpers.errors import db_error_handler, ErrorCode  # noqa: E402
from helpers.json_output import emit_json, emit_json_list  # noqa: E402
from helpers.winrt_index import (  # noqa: E402
    WinrtAccessContext,
    WinrtIndex,
    WinrtInterface,
    WinrtMethod,
    WinrtServer,
    get_winrt_index,
)


def require_winrt_index() -> WinrtIndex:
    """Return the loaded WinRT index or exit with an error."""
    idx = get_winrt_index()
    if not idx.loaded:
        emit_error(
            "WinRT index not loaded. Check that config/assets/winrt_data/ "
            "contains the WinRT extraction data and winrt.enabled is true "
            "in config/defaults.json.",
            ErrorCode.NOT_FOUND,
        )
    return idx


CONTEXT_CHOICES = [str(c) for c in WinrtAccessContext]


def parse_context(value: str | None) -> WinrtAccessContext | None:
    """Parse an access context string into an enum, or None."""
    if not value:
        return None
    value_upper = value.upper().replace("-", "_")
    try:
        return WinrtAccessContext[value_upper]
    except KeyError:
        return None
