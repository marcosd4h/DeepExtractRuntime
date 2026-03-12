"""Shared utilities for function-index scripts.

Thin re-export layer: all core logic lives in helpers.function_index
so other skills can import directly via ``from helpers import ...``.
This module adds workspace root resolution for script sys.path setup.
"""

from __future__ import annotations

import sys
from pathlib import Path

# .agent must be on sys.path before skills._shared is importable
_AGENT_DIR = str(Path(__file__).resolve().parents[3])
if _AGENT_DIR not in sys.path:
    sys.path.insert(0, _AGENT_DIR)

from skills._shared import bootstrap

WORKSPACE_ROOT = bootstrap(__file__)

# Re-export everything from the helpers module so scripts can
# ``from _common import load_function_index, ...`` as before.
from helpers.function_index import (  # noqa: E402, F401
    EXTRACTED_CODE_DIR,
    FUNCTION_INDEX_FILENAME,
    LIBRARY_TAGS,
    build_id_map,
    compute_stats,
    filter_decompiled,
    filter_by_library,
    function_index_path,
    get_files,
    get_function_id,
    get_library_tag,
    get_primary_file,
    group_by_file,
    group_by_library,
    has_assembly,
    has_decompiled,
    is_application_function,
    is_library_function,
    list_extracted_modules,
    load_all_function_indexes,
    load_function_index,
    lookup_function,
    search_index,
    resolve_function_file,
    resolve_module_dir,
)
