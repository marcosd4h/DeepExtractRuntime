"""Shared utilities for deep-research-prompt skill.

Provides workspace root resolution, helpers import, JSON parsing, DB path
resolution, string categorization for prompts, and call graph classification
helpers.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Optional

_AGENT_DIR = str(Path(__file__).resolve().parents[3])
if _AGENT_DIR not in sys.path:
    sys.path.insert(0, _AGENT_DIR)

from skills._shared import bootstrap, make_db_resolvers
from skills._shared.skill_common import emit_error, parse_json_safe  # noqa: F401

WORKSPACE_ROOT = bootstrap(__file__)
resolve_db_path, resolve_tracking_db = make_db_resolvers(WORKSPACE_ROOT)

from helpers import load_skill_module  # noqa: E402
from helpers.api_taxonomy import classify_api  # noqa: E402

# ---------------------------------------------------------------------------
# Import classify_function from the classify-functions skill using load_skill_module
# to avoid module name collisions (both skills have _common.py).
# ---------------------------------------------------------------------------
try:
    _classify_mod = load_skill_module("classify-functions", "_common")
    classify_function = _classify_mod.classify_function
except (ImportError, FileNotFoundError):
    classify_function = None


# ---------------------------------------------------------------------------
# Xref helpers
# ---------------------------------------------------------------------------
# Sentinel module_name values that are NOT real cross-module calls
XREF_SKIP_MODULES = {"data", "vtable", ""}
# function_type values to skip (not actual function calls)
XREF_SKIP_FTYPES = {4, 8}  # FT_MEM=4, FT_VTB=8


def is_callable_xref(xref: dict) -> bool:
    """Return True if this xref represents a real function call (not data/vtable)."""
    ftype = xref.get("function_type", 0)
    if ftype in XREF_SKIP_FTYPES:
        return False
    module = xref.get("module_name", "")
    if module in XREF_SKIP_MODULES:
        return False
    return True


def is_internal_xref(xref: dict) -> bool:
    """Return True if this xref is an internal (same-module) call."""
    return xref.get("function_id") is not None and is_callable_xref(xref)


def is_external_xref(xref: dict) -> bool:
    """Return True if this xref is an external (cross-module) call."""
    return xref.get("function_id") is None and is_callable_xref(xref)


# ---------------------------------------------------------------------------
# String categorization for research prompts (canonical: helpers.string_taxonomy)
# ---------------------------------------------------------------------------
from helpers.string_taxonomy import (  # noqa: E402
    categorize_string_simple as categorize_string,
    categorize_string as categorize_string_full,
    categorize_strings,
)


# ---------------------------------------------------------------------------
# Truncation helpers
# ---------------------------------------------------------------------------
def truncate(s: str, max_len: int = 120) -> str:
    """Truncate a string to max_len, adding ... if needed."""
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."
