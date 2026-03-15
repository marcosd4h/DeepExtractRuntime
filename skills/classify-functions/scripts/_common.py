"""Shared utilities for function classification skill.

Provides API category definitions, naming pattern rules, string/assembly analysis,
and the core classification algorithm used by all skill scripts.
"""

from __future__ import annotations

import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_AGENT_DIR = str(Path(__file__).resolve().parents[3])
if _AGENT_DIR not in sys.path:
    sys.path.insert(0, _AGENT_DIR)

from skills._shared import bootstrap, make_db_resolvers

WORKSPACE_ROOT = bootstrap(__file__)
resolve_db_path, resolve_tracking_db = make_db_resolvers(WORKSPACE_ROOT)

from helpers import emit_error, parse_json_safe  # noqa: E402
from helpers.api_taxonomy import API_TAXONOMY, classify_api  # noqa: E402

NAME_RULES: list = []


# ---------------------------------------------------------------------------
# Classification result
# ---------------------------------------------------------------------------
CATEGORIES = [
    "initialization", "error_handling", "data_parsing", "com_ole", "rpc",
    "winrt", "ui_shell", "telemetry", "crypto", "resource_management",
    "dispatch_routing", "file_io", "registry", "network", "process_thread",
    "security", "sync", "memory", "service", "string_manipulation",
    "debug_diagnostics", "compiler_generated", "utility", "unknown",
]

# Categories considered low-interest (infrastructure noise)
LOW_INTEREST_CATEGORIES = {"telemetry", "compiler_generated"}


@dataclass
class ClassificationResult:
    """Classification output for a single function."""
    function_id: int
    function_name: str
    primary_category: str
    secondary_categories: list[str] = field(default_factory=list)
    scores: dict[str, float] = field(default_factory=dict)
    signals: dict[str, list[str]] = field(default_factory=dict)
    interest_score: int = 0
    has_decompiled: bool = False
    loop_count: int = 0
    api_count: int = 0
    string_count: int = 0
    dangerous_api_count: int = 0

    def to_dict(self) -> dict:
        return {
            "function_id": self.function_id,
            "function_name": self.function_name,
            "primary_category": self.primary_category,
            "secondary_categories": self.secondary_categories,
            "interest_score": self.interest_score,
            "scores": {k: round(v, 1) for k, v in self.scores.items() if v > 0},
            "signals": {k: v for k, v in self.signals.items() if v},
            "loop_count": self.loop_count,
            "api_count": self.api_count,
            "string_count": self.string_count,
            "dangerous_api_count": self.dangerous_api_count,
            "has_decompiled": self.has_decompiled,
        }


# ---------------------------------------------------------------------------
# Core classification algorithm
# ---------------------------------------------------------------------------
# Signal weights -- loaded from config with hardcoded fallbacks
def _load_weights() -> dict[str, float]:
    from helpers.config import get_config_value
    defaults = {
        "W_API": 5.0,
        "W_API_CAP": 25.0,
        "W_STRUCTURAL": 4.0,
        "W_LIBRARY": 12.0,
    }
    configured = get_config_value("classification.weights", {})
    return {k: configured.get(k, v) for k, v in defaults.items()}

_weights = _load_weights()
W_API = _weights["W_API"]
W_API_CAP = _weights["W_API_CAP"]
W_STRUCTURAL = _weights["W_STRUCTURAL"]
W_LIBRARY = _weights["W_LIBRARY"]


def _load_structural_thresholds() -> dict[str, int]:
    from helpers.config import get_config_value
    defaults = {
        "dispatch_min_branches": 15,
        "dispatch_min_calls": 5,
        "dispatch_max_loops": 1,
        "parsing_min_loops": 3,
        "parsing_min_complexity": 5,
        "utility_max_asm_instructions": 10,
        "utility_max_calls": 2,
        "leaf_max_instructions": 20,
    }
    return {
        k: get_config_value(f"classification.structural_thresholds.{k}", v)
        for k, v in defaults.items()
    }


_structural = _load_structural_thresholds()

# Library tag -> classification category mapping
_LIBRARY_TAG_CATEGORY: dict[str, str] = {
    "WIL": "telemetry",
    "ETW/TraceLogging": "telemetry",
    "CRT": "compiler_generated",
    "WRL": "com_ole",
    "STL": "utility",
}

# WIL/WRL functions that handle untrusted input or have security
# implications should not be dominated by the library tag.  We use a
# reduced weight (W_LIBRARY_REDUCED) when the function has dangerous
# API calls, allowing the API-based signals to compete.
_SECURITY_RELEVANT_LIBRARY_TAGS = frozenset({"WIL", "WRL"})


def classify_function(func, function_index: Optional[dict] = None) -> ClassificationResult:
    """Classify a single FunctionRecord into a purpose category.

    Args:
        func: A FunctionRecord from helpers.individual_analysis_db
        function_index: Optional function_index dict (from load_function_index or
            load_function_index_for_db). When provided, the library tag is used
            as a high-confidence classification signal (Step 0).

    Returns:
        ClassificationResult with primary category, scores, signals, and interest.
    """
    scores: dict[str, float] = defaultdict(float)
    signals: dict[str, list[str]] = defaultdict(list)

    fname = func.function_name or ""
    decompiled_from_db = bool(func.decompiled_code and func.decompiled_code.strip())

    # --- 0. Function index library tag (applied after dangerous API check) ---
    _library_tag: Optional[str] = None
    _index_entry: Optional[dict] = None
    if function_index is not None:
        mangled = func.mangled_name or ""
        _index_entry = function_index.get(fname) or function_index.get(mangled)
        if _index_entry and _index_entry.get("library"):
            _library_tag = _index_entry["library"]

    if _index_entry and "has_decompiled" in _index_entry:
        has_decompiled = bool(_index_entry.get("has_decompiled"))
    else:
        has_decompiled = decompiled_from_db

    # --- 1b. RPC index ground-truth classification ---
    try:
        from helpers.rpc_index import get_rpc_index as _get_rpc_idx
        _rpc_idx = _get_rpc_idx()
        if _rpc_idx.loaded and _rpc_idx._procedures_by_module:
            for _mod_procs in _rpc_idx._procedures_by_module.values():
                if fname in _mod_procs:
                    scores["rpc"] += 20.0  # IPC index ground-truth weight
                    signals["rpc"].append("rpc_index:confirmed_handler")
                    break
    except Exception:
        pass

    # --- 1c. COM index ground-truth classification ---
    try:
        from helpers.com_index import get_com_index as _get_com_idx
        _com_idx = _get_com_idx()
        if _com_idx.loaded and _com_idx._procedures_by_module:
            for _mod_procs in _com_idx._procedures_by_module.values():
                if fname in _mod_procs:
                    scores["com_ole"] += 20.0  # IPC index ground-truth weight
                    signals["com_ole"].append("com_index:confirmed_method")
                    break
    except Exception:
        pass

    # --- 1d. WinRT index ground-truth classification ---
    try:
        from helpers.winrt_index import get_winrt_index as _get_winrt_idx
        _winrt_idx = _get_winrt_idx()
        if _winrt_idx.loaded and _winrt_idx._procedures_by_module:
            for _mod_procs in _winrt_idx._procedures_by_module.values():
                if fname in _mod_procs:
                    scores["winrt"] += 20.0  # IPC index ground-truth weight
                    signals["winrt"].append("winrt_index:confirmed_method")
                    break
    except Exception:
        pass

    # --- 2. Definitive structural identity (demangled name) ---
    forced_category: Optional[str] = None
    if fname:
        if "::`vftable'" in fname:
            forced_category = "compiler_generated"
            signals["compiler_generated"].append("demangled:VFTable")
        elif "::`scalar deleting destructor'" in fname:
            forced_category = "resource_management"
            signals["resource_management"].append("demangled:Scalar deleting destructor")
        elif "::~" in fname:
            forced_category = "resource_management"
            signals["resource_management"].append("demangled:Destructor")
        elif "::" in fname:
            parts = fname.rsplit("::", 1)
            if len(parts) == 2 and parts[1] and parts[0].endswith(parts[1]):
                forced_category = "initialization"
                signals["initialization"].append("demangled:Constructor")

    # --- 3. API-based classification (from outbound xrefs) ---
    outbound = parse_json_safe(func.simple_outbound_xrefs) or []
    api_category_counts: dict[str, int] = defaultdict(int)
    api_count = 0
    for xref in outbound:
        if not isinstance(xref, dict):
            continue
        # Skip data/vtable refs
        ftype = xref.get("function_type", 0)
        if ftype in (4, 8):  # FT_MEM=4, FT_VTB=8
            continue
        api_name = xref.get("function_name", "")
        if not api_name:
            continue
        api_count += 1
        cat = classify_api(api_name)
        if cat:
            api_category_counts[cat] += 1

    for cat, count in api_category_counts.items():
        score = min(count * W_API, W_API_CAP)
        scores[cat] += score
        signals[cat].append(f"api:{count} call(s)")

    # --- 4. String count (for metadata only, no classification signal) ---
    string_literals = parse_json_safe(func.string_literals) or []
    string_count = len(string_literals) if isinstance(string_literals, list) else 0

    # --- 5. Structural classification ---
    loop_analysis = parse_json_safe(func.loop_analysis)
    loop_count = 0
    max_complexity = 0
    if isinstance(loop_analysis, dict):
        loop_count = loop_analysis.get("loop_count", 0) or 0
        loops = loop_analysis.get("loops", [])
        if isinstance(loops, list):
            for loop in loops:
                if isinstance(loop, dict):
                    c = loop.get("cyclomatic_complexity", 0) or 0
                    if c > max_complexity:
                        max_complexity = c

    # Algorithmic: many loops + high complexity
    if loop_count >= _structural["parsing_min_loops"] and max_complexity >= _structural["parsing_min_complexity"]:
        scores["data_parsing"] += W_STRUCTURAL
        signals["data_parsing"].append(f"structural:algorithmic ({loop_count} loops, complexity {max_complexity})")

    # --- 6. Dangerous API bonus ---
    dangerous = parse_json_safe(func.dangerous_api_calls) or []
    dangerous_count = len(dangerous) if isinstance(dangerous, list) else 0

    # --- 6b. Deferred library tag weight ---
    # Applied after dangerous API count is known so that WIL/WRL
    # functions with security-relevant APIs get a reduced weight,
    # allowing API-based signals to compete for primary category.
    if _library_tag is not None:
        cat = _LIBRARY_TAG_CATEGORY.get(_library_tag, "utility")
        if dangerous_count >= 3:
            weight = W_LIBRARY * 0.25
            signals[cat].append(f"function_index:library={_library_tag} (reduced: has dangerous APIs)")
        elif _library_tag in _SECURITY_RELEVANT_LIBRARY_TAGS and dangerous_count > 0:
            weight = W_LIBRARY * 0.25
            signals[cat].append(f"function_index:library={_library_tag} (reduced: has dangerous APIs)")
        else:
            weight = W_LIBRARY
            signals[cat].append(f"function_index:library={_library_tag}")
        scores[cat] += weight

    # --- 7. Select primary category ---
    if forced_category:
        primary = forced_category
        sorted_cats = sorted(scores.items(), key=lambda x: -x[1])
        secondary = [c for c, s in sorted_cats[:2] if s > 0 and c != primary]
    elif scores:
        sorted_cats = sorted(scores.items(), key=lambda x: -x[1])
        primary = sorted_cats[0][0]
        secondary = [c for c, s in sorted_cats[1:3] if s > 0]
    else:
        if fname.startswith("sub_"):
            primary = "unknown"
            signals["unknown"].append("unnamed function (sub_)")
        else:
            primary = "unknown"
            signals["unknown"].append("no classification signals")
        secondary = []

    # --- 8. Interest score ---
    # A function is a confirmed IPC entry point if the RPC/COM/WinRT index
    # explicitly identifies it as a handler or method.
    _is_ipc_entry = (
        "rpc_index:confirmed_handler" in signals.get("rpc", [])
        or "com_index:confirmed_method" in signals.get("com_ole", [])
        or "winrt_index:confirmed_method" in signals.get("winrt", [])
    )
    interest = _compute_interest(
        primary, dangerous_count, loop_count, max_complexity,
        string_count, api_count,
        has_decompiled,
        is_library_tagged=_library_tag is not None,
        is_ipc_entry=_is_ipc_entry,
    )

    return ClassificationResult(
        function_id=func.function_id,
        function_name=fname,
        primary_category=primary,
        secondary_categories=secondary,
        scores=dict(scores),
        signals=dict(signals),
        interest_score=interest,
        has_decompiled=has_decompiled,
        loop_count=loop_count,
        api_count=api_count,
        string_count=string_count,
        dangerous_api_count=dangerous_count,
    )


def _compute_interest(
    primary: str,
    dangerous_count: int,
    loop_count: int,
    max_complexity: int,
    string_count: int,
    api_count: int,
    has_decompiled: bool,
    is_library_tagged: bool = False,
    is_ipc_entry: bool = False,
) -> int:
    """Compute an interest score (0-10) to help researchers prioritize."""
    score = 0

    if dangerous_count > 0:
        score += min(dangerous_count, 3)

    if loop_count >= 2:
        score += 1
    if max_complexity >= 5:
        score += 1

    if string_count > 3:
        score += 1
    if has_decompiled:
        score += 1

    if is_library_tagged:
        penalty = 2 if dangerous_count > 0 else 5
        score = max(score - penalty, 0)
    elif primary in LOW_INTEREST_CATEGORIES:
        penalty = 1 if dangerous_count > 0 else 3
        score = max(score - penalty, 0)

    score = min(score, 10)

    if is_ipc_entry:
        score = max(score, 6)

    return score


__all__ = [
    "API_TAXONOMY",
    "CATEGORIES",
    "ClassificationResult",
    "classify_api",
    "classify_function",
    "emit_error",
    "LOW_INTEREST_CATEGORIES",
    "parse_json_safe",
    "resolve_db_path",
    "resolve_tracking_db",
    "W_API",
    "W_API_CAP",
    "W_LIBRARY",
    "W_STRUCTURAL",
    "WORKSPACE_ROOT",
]
