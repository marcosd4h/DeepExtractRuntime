"""Shared utilities for generate-re-report skill.

Provides:
- Workspace root resolution and helpers import
- Comprehensive Win32 API taxonomy (~500 APIs -> categories)
- Rich header MSVC version decoder
- Common data parsing and formatting helpers
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Optional

_AGENT_DIR = str(Path(__file__).resolve().parents[3])
if _AGENT_DIR not in sys.path:
    sys.path.insert(0, _AGENT_DIR)

from skills._shared import bootstrap, make_db_resolvers

WORKSPACE_ROOT = bootstrap(__file__)

from helpers import _resolve_module_db, parse_json_safe  # noqa: E402
from helpers.api_taxonomy import API_TAXONOMY, classify_api  # noqa: E402

# ---------------------------------------------------------------------------
# Rich Header MSVC Build Number -> Compiler Version
# ---------------------------------------------------------------------------
MSVC_VERSIONS: dict[int, str] = {
    # VS 2022 (v17.x)
    14_40: "VS 2022 17.10+",
    14_39: "VS 2022 17.9",
    14_38: "VS 2022 17.8",
    14_37: "VS 2022 17.7",
    14_36: "VS 2022 17.6",
    14_35: "VS 2022 17.5",
    14_34: "VS 2022 17.4",
    14_33: "VS 2022 17.3",
    14_32: "VS 2022 17.2",
    14_31: "VS 2022 17.1",
    14_30: "VS 2022 17.0",
    # VS 2019 (v16.x)
    14_29: "VS 2019 16.11",
    14_28: "VS 2019 16.9-16.10",
    14_27: "VS 2019 16.7-16.8",
    14_26: "VS 2019 16.6",
    14_25: "VS 2019 16.5",
    14_24: "VS 2019 16.4",
    14_23: "VS 2019 16.3",
    14_22: "VS 2019 16.2",
    14_21: "VS 2019 16.1",
    14_20: "VS 2019 16.0",
    # VS 2017 (v15.x)
    14_16: "VS 2017 15.9",
    14_15: "VS 2017 15.8",
    14_14: "VS 2017 15.7",
    14_13: "VS 2017 15.6",
    14_12: "VS 2017 15.5",
    14_11: "VS 2017 15.3-15.4",
    14_10: "VS 2017 15.0-15.2",
    # Older
    14_00: "VS 2015",
    12_00: "VS 2013",
    11_00: "VS 2012",
    10_00: "VS 2010",
    9_00: "VS 2008",
    8_00: "VS 2005",
}


def decode_rich_tool(product_id: int, build_number: int) -> str:
    """Decode a Rich header tool entry to a human-readable description."""
    # Product IDs: known categories
    tool_types = {
        0: "Unmarked objects",
        1: "Import (old)",
        2: "Linker",
        3: "CVTOMF",
        4: "Linker",
        5: "CVTRES",
        6: "MASM",
        7: "Utc C",
        8: "Utc C++",
        10: "Resource compiler",
        14: "Linker",
        40: "Utc C",
        41: "Utc C++",
        45: "Utc C",
        83: "Utc C",
        84: "Utc C++",
        93: "Utc C++",
        94: "Utc C",
        95: "Utc C++ (LTCG)",
        96: "Utc C (LTCG)",
        104: "Utc C",
        105: "Utc C++",
        255: "Utc C",
        256: "Utc C++",
        257: "Utc C",
        258: "Utc C++",
        259: "Utc C (LTCG)",
        260: "Utc C++ (LTCG)",
        261: "MASM (ML)",
    }
    tool_name = tool_types.get(product_id, f"Tool[{product_id}]")

    # Try to map build number to MSVC version
    major = build_number // 100
    minor_group = build_number // 10
    version = MSVC_VERSIONS.get(major * 100, MSVC_VERSIONS.get(minor_group * 10, ""))
    if version:
        return f"{tool_name} ({version}, build {build_number})"
    return f"{tool_name} (build {build_number})"


# ---------------------------------------------------------------------------
# DB/path resolution (bound to this skill's WORKSPACE_ROOT)
# ---------------------------------------------------------------------------
resolve_db_path, resolve_tracking_db = make_db_resolvers(WORKSPACE_ROOT)


def open_analysis_db(db_path: str):
    """Open an individual analysis DB using the helpers module."""
    from helpers import open_individual_analysis_db
    return open_individual_analysis_db(resolve_db_path(db_path))


def load_index_for_db(db_path: str) -> Optional[dict]:
    """Load the function_index for the module whose DB is at *db_path*.

    Returns the function_index dict or None if unavailable.
    """
    from helpers import load_function_index_for_db
    return load_function_index_for_db(resolve_db_path(db_path))


def build_app_name_set(db_path: str) -> Optional[set[str]]:
    """Build a set of application (non-library) function names for a module.

    Returns None if the function_index is not available.
    """
    from helpers import filter_by_library
    idx = load_index_for_db(db_path)
    if idx is None:
        return None
    return set(filter_by_library(idx, app_only=True).keys())


def get_library_tag_from_index(fname: str, function_index: Optional[dict]) -> Optional[str]:
    """Return the library tag for a function from the function_index, or None."""
    if function_index is None:
        return None
    entry = function_index.get(fname)
    if entry is None:
        return None
    return entry.get("library")


def open_tracking_db():
    """Open the analyzed_files tracking DB."""
    from helpers import open_analyzed_files_db
    return open_analyzed_files_db()


def find_module_db(module_name: str) -> Optional[str]:
    """Find the analysis DB path for a module name (e.g., 'appinfo.dll')."""
    return _resolve_module_db(module_name, WORKSPACE_ROOT)


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------
def fmt_count(n: int, singular: str, plural: Optional[str] = None) -> str:
    """Format a count with proper plural: '1 function' vs '5 functions'."""
    p = plural or (singular + "s")
    return f"{n:,} {singular if n == 1 else p}"


def fmt_pct(part: int, total: int) -> str:
    """Format a percentage: '87.3%'."""
    if total == 0:
        return "0.0%"
    return f"{100.0 * part / total:.1f}%"


def truncate_string(s: str, max_len: int = 80) -> str:
    """Truncate a string with ellipsis."""
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."


# ---------------------------------------------------------------------------
# Function size/complexity buckets
# ---------------------------------------------------------------------------
SIZE_BUCKETS = [
    ("tiny", 0, 10),
    ("small", 10, 50),
    ("medium", 50, 200),
    ("large", 200, 500),
    ("huge", 500, float("inf")),
]


def get_size_bucket(instruction_count: int) -> str:
    """Get the size bucket name for an instruction count."""
    for name, lo, hi in SIZE_BUCKETS:
        if lo <= instruction_count < hi:
            return name
    return "huge"


COMPLEXITY_BUCKETS = [
    ("simple", 0, 2),
    ("moderate", 2, 6),
    ("complex", 6, float("inf")),
]


def get_complexity_bucket(loop_count: int) -> str:
    """Get the complexity bucket name for a loop count."""
    for name, lo, hi in COMPLEXITY_BUCKETS:
        if lo <= loop_count < hi:
            return name
    return "complex"
