"""Shared utilities for the rpc-interface-analysis skill."""

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
from helpers.rpc_index import RpcIndex, RpcInterface, get_rpc_index  # noqa: E402


def require_rpc_index() -> RpcIndex:
    """Return the loaded RPC index or exit with an error."""
    idx = get_rpc_index()
    if not idx.loaded:
        emit_error(
            "RPC index not loaded. Check that config/assets/ contains the "
            "exported RPC data files and rpc.enabled is true in config/defaults.json.",
            ErrorCode.NOT_FOUND,
        )
    return idx
