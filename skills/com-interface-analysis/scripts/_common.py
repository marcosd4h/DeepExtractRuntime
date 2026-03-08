"""Shared utilities for the com-interface-analysis skill."""

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
from helpers.com_index import (  # noqa: E402
    ComAccessContext,
    ComIndex,
    ComInterface,
    ComMethod,
    ComServer,
    get_com_index,
)


def require_com_index() -> ComIndex:
    """Return the loaded COM index or exit with an error."""
    idx = get_com_index()
    if not idx.loaded:
        emit_error(
            "COM index not loaded. Check that config/assets/com_data/ "
            "contains the COM extraction data and com.enabled is true "
            "in config/defaults.json.",
            ErrorCode.NOT_FOUND,
        )
    return idx


CONTEXT_CHOICES = [str(c) for c in ComAccessContext]

import re  # noqa: E402
CLSID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def is_clsid(value: str | None) -> bool:
    """Return True if *value* looks like a CLSID GUID."""
    if value is None:
        return False
    return bool(CLSID_RE.match(value))


def parse_context(value: str | None) -> ComAccessContext | None:
    """Parse an access context string into an enum, or None."""
    if not value:
        return None
    value_upper = value.upper().replace("-", "_")
    try:
        return ComAccessContext[value_upper]
    except KeyError:
        return None
