"""Shared utilities for the ai-taint-scanner skill.

Provides workspace bootstrap, DB path resolution, and re-exports of helpers
used by the context-preparation and threat-model scripts.  This skill imports
taint-specific helpers (sink classification, trust boundary detection, COM
vtable resolution, RPC boundary identification, parameter inference) because
the context-preparation scripts enrich callgraph nodes with taint metadata
before handing off to the LLM agent.
"""

from __future__ import annotations

import sys
from pathlib import Path

_AGENT_DIR = str(Path(__file__).resolve().parents[3])
if _AGENT_DIR not in sys.path:
    sys.path.insert(0, _AGENT_DIR)

from skills._shared import bootstrap, make_db_resolvers

SCRIPT_DIR = Path(__file__).resolve().parent
WORKSPACE_ROOT = bootstrap(__file__)
resolve_db_path, resolve_tracking_db = make_db_resolvers(WORKSPACE_ROOT)

from helpers import (  # noqa: E402
    emit_error,
    load_function_index_for_db,
    open_individual_analysis_db,
    parse_json_safe,
)
from helpers.cross_module_graph import CrossModuleGraph, ModuleResolver  # noqa: E402
from helpers.errors import ErrorCode, db_error_handler, safe_parse_args  # noqa: E402
from helpers.function_index import (  # noqa: E402
    filter_application_functions,
    is_application_function,
    is_library_function,
)
from helpers.json_output import emit_json  # noqa: E402
from helpers.progress import status_message  # noqa: E402
from helpers.workspace import read_results, read_step_payload  # noqa: E402
from helpers.workspace_bootstrap import complete_step  # noqa: E402
from helpers.taint_helpers import (  # noqa: E402
    classify_sink,
    classify_module_trust,
    classify_trust_transition,
    TaintContext,
    TRUST_LEVEL_RANK,
    SINK_SEVERITY,
    resolve_vtable_callees,
    detect_rpc_boundaries,
    infer_param_count,
    resolve_tainted_params,
)

__all__ = [
    "CrossModuleGraph",
    "ErrorCode",
    "ModuleResolver",
    "SCRIPT_DIR",
    "SINK_SEVERITY",
    "TRUST_LEVEL_RANK",
    "TaintContext",
    "WORKSPACE_ROOT",
    "classify_module_trust",
    "classify_sink",
    "classify_trust_transition",
    "complete_step",
    "db_error_handler",
    "detect_rpc_boundaries",
    "emit_error",
    "emit_json",
    "filter_application_functions",
    "infer_param_count",
    "is_application_function",
    "is_library_function",
    "load_function_index_for_db",
    "open_individual_analysis_db",
    "parse_json_safe",
    "read_results",
    "read_step_payload",
    "resolve_db_path",
    "resolve_tainted_params",
    "resolve_tracking_db",
    "resolve_vtable_callees",
    "safe_parse_args",
    "status_message",
]
