"""Standard re-exports for skill _common.py files.

Consolidates the helpers that virtually every skill _common.py imports.
Skills with additional needs can import extra helpers alongside these.

Usage in a skill ``_common.py``::

    from skills._shared import bootstrap, make_db_resolvers
    from skills._shared.skill_common import *  # noqa: F401,F403

    WORKSPACE_ROOT = bootstrap(__file__)
    resolve_db_path, resolve_tracking_db = make_db_resolvers(WORKSPACE_ROOT)
"""

from __future__ import annotations

from helpers import (
    emit_error,
    emit_json,
    emit_json_list,
    log_warning,
    open_individual_analysis_db,
    parse_json_safe,
    resolve_function,
    search_functions_by_pattern,
    validate_function_id,
    validate_positive_int,
    load_function_index_for_db,
    get_cached,
    cache_result,
    status_message,
    db_error_handler,
    ScriptError,
)
from helpers.json_output import should_force_json
from helpers.script_runner import get_workspace_args, run_skill_script

__all__ = [
    "emit_error",
    "emit_json",
    "emit_json_list",
    "log_warning",
    "open_individual_analysis_db",
    "parse_json_safe",
    "resolve_function",
    "search_functions_by_pattern",
    "validate_function_id",
    "validate_positive_int",
    "load_function_index_for_db",
    "get_cached",
    "cache_result",
    "status_message",
    "db_error_handler",
    "ScriptError",
    "should_force_json",
    "get_workspace_args",
    "run_skill_script",
]
