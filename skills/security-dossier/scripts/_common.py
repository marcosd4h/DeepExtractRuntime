"""Shared utilities for the security-dossier skill.

Provides workspace root resolution, JSON parsing, security-relevant API
classification, assembly metrics, and a lightweight call graph for reachability
analysis within a single module.
"""

from __future__ import annotations

import re
import sys
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_AGENT_DIR = str(Path(__file__).resolve().parents[3])
if _AGENT_DIR not in sys.path:
    sys.path.insert(0, _AGENT_DIR)

from skills._shared import bootstrap, make_db_resolvers
from skills._shared.skill_common import emit_error, parse_json_safe  # noqa: F401

WORKSPACE_ROOT = bootstrap(__file__)
resolve_db_path, resolve_tracking_db = make_db_resolvers(WORKSPACE_ROOT)

from helpers.api_taxonomy import SECURITY_API_CATEGORIES, classify_api_security  # noqa: E402
from helpers.callgraph import CallGraph  # noqa: E402
from helpers.asm_metrics import get_asm_metrics, AsmMetrics  # noqa: E402


def has_real_decompiled(code: Optional[str]) -> bool:
    """Check if decompiled_code is real output (not a failure placeholder)."""
    if not code or not code.strip():
        return False
    lower = code.strip().lower()
    return not (
        lower.startswith("decompiler not available")
        or lower.startswith("decompilation failed")
    )


# ---------------------------------------------------------------------------
# Call Graph (delegates to shared helpers.callgraph.CallGraph)
# ---------------------------------------------------------------------------
# MiniCallGraph is kept as an alias for backward compatibility.
# All call graph logic is now in helpers/callgraph.py.
MiniCallGraph = CallGraph


__all__ = [
    "AsmMetrics",
    "CallGraph",
    "classify_api_security",
    "emit_error",
    "get_asm_metrics",
    "has_real_decompiled",
    "MiniCallGraph",
    "parse_json_safe",
    "resolve_db_path",
    "resolve_tracking_db",
    "SECURITY_API_CATEGORIES",
    "WORKSPACE_ROOT",
]
