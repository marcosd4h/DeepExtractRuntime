"""Shared utilities for the memory-corruption-detector skill.

Provides workspace bootstrapping, memory-corruption finding dataclasses,
scoring model, API constant tuples for allocation/free/copy/format functions,
and helper re-exports used across all detection and verification scripts.
"""

from __future__ import annotations

import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

_AGENT_DIR = str(Path(__file__).resolve().parents[3])
if _AGENT_DIR not in sys.path:
    sys.path.insert(0, _AGENT_DIR)

from skills._shared import bootstrap, make_db_resolvers

WORKSPACE_ROOT = bootstrap(__file__)
resolve_db_path, resolve_tracking_db = make_db_resolvers(WORKSPACE_ROOT)

from helpers import (  # noqa: E402
    emit_error,
    load_function_index_for_db,
    open_individual_analysis_db,
    parse_json_safe,
    resolve_function,
    validate_function_id,
)
from helpers.api_taxonomy import classify_api_security, get_dangerous_api_set  # noqa: E402
from helpers.cache import cache_result, get_cached  # noqa: E402
from helpers.config import get_config_value  # noqa: E402
from helpers.callgraph import CallGraph  # noqa: E402
from helpers.decompiled_parser import discover_calls_with_xrefs, extract_function_calls, find_param_in_calls  # noqa: E402
from helpers.errors import db_error_handler, log_warning  # noqa: E402
from helpers.guard_classifier import (  # noqa: E402
    Guard,
    classify_guard,
    find_guards_between,
)
from helpers.constraint_collector import collect_constraints  # noqa: E402
from helpers.constraint_solver import check_feasibility  # noqa: E402
from helpers.json_output import emit_json  # noqa: E402
from helpers.progress import status_message  # noqa: E402
from helpers.def_use_chain import (  # noqa: E402
    TaintResult,
    VarDef,
    VarUse,
    analyze_taint,
    parse_def_use,
    propagate_taint,
)
from skills._shared.finding_base import (  # noqa: E402
    CONFIDENCE_SCORES,
    REACHABILITY_SCORES,
    SCORE_WEIGHTS,
    VerificationResult,
    build_export_names,
    build_meta as _build_meta,
    compute_finding_score,
    load_all_functions_slim,
    load_exports,
    load_function_record,
    matches_api_list,
    severity_label,
    strip_import_prefix,
)

SCANNER_DEFAULT_TOP_N = int(get_config_value("scoring.scanner_default_top_n", 100))


# ---------------------------------------------------------------------------
# Memory corruption finding categories
# ---------------------------------------------------------------------------

FINDING_CATEGORIES: dict[str, str] = {
    "heap_overflow": "Tainted size/length to memcpy/memmove/CopyMemory exceeds buffer capacity",
    "stack_overflow": "Stack buffer write with unchecked tainted size",
    "integer_overflow": "Integer arithmetic overflow before allocation or size check",
    "integer_truncation": "Integer truncation (e.g. DWORD to WORD) before size-sensitive operation",
    "use_after_free": "Memory use after deallocation on same path",
    "double_free": "Same pointer freed twice without intervening reallocation",
    "format_string": "Format function with non-constant format string from tainted source",
    "uninitialized_size": "Allocation with uninitialized or zero-checked size",
}

IMPACT_SEVERITY: dict[str, float] = {
    "heap_overflow": 1.0,
    "stack_overflow": 0.95,
    "integer_overflow": 0.9,
    "format_string": 0.85,
    "use_after_free": 0.8,
    "double_free": 0.8,
    "integer_truncation": 0.7,
    "uninitialized_size": 0.6,
}


# ---------------------------------------------------------------------------
# API constant tuples
# ---------------------------------------------------------------------------

ALLOC_APIS: tuple[str, ...] = (
    "HeapAlloc",
    "RtlAllocateHeap",
    "malloc",
    "calloc",
    "realloc",
    "VirtualAlloc",
    "LocalAlloc",
    "GlobalAlloc",
    "CoTaskMemAlloc",
    "SysAllocString",
    "ExAllocatePoolWithTag",
)

FREE_APIS: tuple[str, ...] = (
    "HeapFree",
    "RtlFreeHeap",
    "free",
    "VirtualFree",
    "LocalFree",
    "GlobalFree",
    "CoTaskMemFree",
    "SysFreeString",
)

COPY_APIS: tuple[str, ...] = (
    "memcpy",
    "memmove",
    "CopyMemory",
    "RtlCopyMemory",
    "RtlMoveMemory",
    "wmemcpy",
    "wmemmove",
    "strncpy",
    "wcsncpy",
    "lstrcpyn",
)

UNBOUNDED_COPY_APIS: tuple[str, ...] = (
    "strcpy",
    "wcscpy",
    "lstrcpy",
    "lstrcpyW",
    "lstrcpyA",
    "strcat",
    "wcscat",
    "lstrcat",
)

FORMAT_APIS: tuple[str, ...] = (
    "sprintf",
    "swprintf",
    "vsprintf",
    "vswprintf",
    "_snprintf",
    "_snwprintf",
    "wsprintf",
    "wvsprintf",
    "StringCchPrintf",
    "StringCbPrintf",
    "printf",
    "fprintf",
    "wprintf",
)

# Format string argument position per API (0-indexed).
# APIs not listed default to 0.
FORMAT_ARG_POSITION: dict[str, int] = {
    "sprintf": 1,
    "swprintf": 1,
    "vsprintf": 1,
    "vswprintf": 1,
    "_snprintf": 2,
    "_snwprintf": 2,
    "wsprintf": 1,
    "wvsprintf": 1,
    "StringCchPrintf": 2,
    "StringCbPrintf": 2,
    "fprintf": 1,
}


# ---------------------------------------------------------------------------
# Assembly patterns for memory operations
# ---------------------------------------------------------------------------

RE_STACK_BUFFER = re.compile(
    r"\[\s*(?:r|e)?(?:sp|bp)\s*[+\-]\s*\w+\s*\]",
    re.IGNORECASE,
)

RE_MUL_INSN = re.compile(
    r"\b(?:imul|mul)\b",
    re.IGNORECASE,
)

RE_TRUNCATION_CAST = re.compile(
    r"\(\s*(?:unsigned\s+)?(?:__int16|short|WORD|USHORT|BYTE|unsigned\s+char|char)\s*\)",
)

from helpers.asm_patterns import ASM_CALL_RE as RE_CALL_INSN, IDA_PARAM_RE as RE_IDA_PARAM  # noqa: E402


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class MemCorruptionFinding:
    """A single memory corruption vulnerability finding."""

    category: str
    function_name: str
    function_id: int
    summary: str
    severity: str = "MEDIUM"
    score: float = 0.0
    evidence_lines: list[str] = field(default_factory=list)
    dangerous_api: Optional[str] = None
    dangerous_api_category: Optional[str] = None
    alloc_api: Optional[str] = None
    size_source: Optional[str] = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Scoring model
# ---------------------------------------------------------------------------

def compute_memcorrupt_score(
    category: str,
    guard_count: int = 0,
    is_exported: bool = False,
    is_entry_reachable: bool = False,
    confidence: str = "LIKELY",
    path_hops: int = 1,
) -> tuple[float, str]:
    """Compute unified memory corruption vulnerability score (0-1) and rating label."""
    impact = IMPACT_SEVERITY.get(category, 0.5)
    return compute_finding_score(
        impact, guard_count, is_exported, is_entry_reachable, confidence, path_hops,
    )


# ---------------------------------------------------------------------------
# Function data loading (delegated to finding_base)
# ---------------------------------------------------------------------------

def build_meta(db_path: str, **extra: Any) -> dict[str, Any]:
    """Build a _meta block for JSON output."""
    return _build_meta(db_path, skill_name="memory-corruption-detector", **extra)


# ---------------------------------------------------------------------------
# Utility: check if an API name matches a pattern list
# ---------------------------------------------------------------------------


def is_alloc_api(api_name: str) -> bool:
    return matches_api_list(api_name, ALLOC_APIS)


def is_free_api(api_name: str) -> bool:
    return matches_api_list(api_name, FREE_APIS)


def is_copy_api(api_name: str) -> bool:
    return matches_api_list(api_name, COPY_APIS)


def is_unbounded_copy_api(api_name: str) -> bool:
    return matches_api_list(api_name, UNBOUNDED_COPY_APIS)


def is_format_api(api_name: str) -> bool:
    return matches_api_list(api_name, FORMAT_APIS)


def get_format_arg_position(api_name: str) -> int:
    """Return the 0-based position of the format string argument for a format API."""
    clean = strip_import_prefix(api_name)
    for name, pos in FORMAT_ARG_POSITION.items():
        if clean.startswith(name):
            return pos
    return 0


def extract_param_names(signature: str) -> set[str]:
    """Extract IDA parameter names (a1, a2, ...) from a function signature."""
    return set(RE_IDA_PARAM.findall(signature))


__all__ = [
    "ALLOC_APIS",
    "CallGraph",
    "CONFIDENCE_SCORES",
    "COPY_APIS",
    "FINDING_CATEGORIES",
    "FORMAT_APIS",
    "FORMAT_ARG_POSITION",
    "FREE_APIS",
    "Guard",
    "IMPACT_SEVERITY",
    "MemCorruptionFinding",
    "RE_CALL_INSN",
    "RE_IDA_PARAM",
    "RE_MUL_INSN",
    "RE_STACK_BUFFER",
    "RE_TRUNCATION_CAST",
    "REACHABILITY_SCORES",
    "SCORE_WEIGHTS",
    "TaintResult",
    "UNBOUNDED_COPY_APIS",
    "VarDef",
    "VarUse",
    "VerificationResult",
    "WORKSPACE_ROOT",
    "analyze_taint",
    "build_export_names",
    "build_meta",
    "cache_result",
    "classify_api_security",
    "classify_guard",
    "compute_memcorrupt_score",
    "db_error_handler",
    "emit_error",
    "emit_json",
    "discover_calls_with_xrefs",
    "extract_function_calls",
    "extract_param_names",
    "find_guards_between",
    "find_param_in_calls",
    "get_cached",
    "get_dangerous_api_set",
    "get_format_arg_position",
    "is_alloc_api",
    "is_copy_api",
    "is_format_api",
    "is_free_api",
    "is_unbounded_copy_api",
    "load_all_functions_slim",
    "load_exports",
    "load_function_record",
    "log_warning",
    "matches_api_list",
    "open_individual_analysis_db",
    "parse_def_use",
    "parse_json_safe",
    "propagate_taint",
    "resolve_db_path",
    "resolve_function",
    "resolve_tracking_db",
    "severity_label",
    "status_message",
    "validate_function_id",
]
