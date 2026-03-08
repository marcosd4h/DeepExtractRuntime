"""Shared utilities for batch-lift scripts.

Provides workspace root resolution, JSON helpers, mangled name parsing,
struct access pattern scanning, and topological sort.
"""

from __future__ import annotations

import sys
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Optional

_AGENT_DIR = str(Path(__file__).resolve().parents[3])
if _AGENT_DIR not in sys.path:
    sys.path.insert(0, _AGENT_DIR)

from skills._shared import bootstrap, make_db_resolvers

WORKSPACE_ROOT = bootstrap(__file__)
resolve_db_path, resolve_tracking_db = make_db_resolvers(WORKSPACE_ROOT)

from helpers import emit_error, parse_json_safe  # noqa: E402
from helpers.type_constants import SIZE_TO_C_TYPE, TYPE_SIZES  # noqa: E402
from helpers.mangled_names import parse_class_from_mangled  # noqa: E402
from helpers.struct_scanner import (  # noqa: E402
    merge_struct_fields as _merge_struct_fields,
    scan_batch_struct_accesses,
)


# ---------------------------------------------------------------------------
# Struct access pattern scanning (decompiled code)
#
# NOTE: A more comprehensive implementation exists in
# reconstruct-types/scripts/scan_struct_fields.py (scan_decompiled_code)
# which handles hex offsets in Pattern 1, (char *) casts in Pattern 2,
# line-number tracking, and assembly-level verification.  The version here
# is kept for the lifting pipeline's simpler needs (merge_struct_fields,
# format_struct_definition).
# ---------------------------------------------------------------------------

def scan_struct_accesses(decompiled_code: str) -> list[dict[str, Any]]:
    """Scan decompiled code for struct field access patterns.

    Returns list of dicts: {base, offset, size, type_name, pattern}.
    """
    return scan_batch_struct_accesses(decompiled_code, TYPE_SIZES)


def merge_struct_fields(
    all_accesses: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Merge struct field accesses across multiple functions.

    Input: {base_type_or_param: [access_dicts_from_scan]}
    Output: {base_type: [merged_fields]} sorted by offset, with source functions noted.
    """
    return _merge_struct_fields(all_accesses, SIZE_TO_C_TYPE)


def format_struct_definition(name: str, fields: list[dict], func_count: int = 0) -> str:
    """Format a C struct definition from merged fields."""
    lines = []
    lines.append(f"/**")
    lines.append(f" * {name} -- Reconstructed from {func_count} function(s)")
    lines.append(f" * Field names are placeholders; rename during lifting.")
    lines.append(f" */")
    lines.append(f"struct {name} {{")

    prev_end = 0
    for field in fields:
        offset = field["offset"]
        size = field["size"]
        c_type = field["c_type"]

        # Add padding for gaps
        if offset > prev_end:
            gap = offset - prev_end
            lines.append(f"    uint8_t _unknown_{prev_end:02X}[0x{gap:X}];{' ' * max(1, 30 - len(f'uint8_t _unknown_{prev_end:02X}[0x{gap:X}]'))}// +0x{prev_end:02X} .. +0x{offset - 1:02X}")

        field_name = f"field_{offset:02X}"
        decl = f"    {c_type} {field_name};"
        comment = f"// +0x{offset:02X} ({size}B)"
        padding = max(1, 40 - len(decl))
        lines.append(f"{decl}{' ' * padding}{comment}")
        prev_end = offset + size

    lines.append(f"}};  // total known size >= 0x{prev_end:X} ({prev_end} bytes)")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Topological sort for dependency ordering
# ---------------------------------------------------------------------------


def topological_sort_functions(functions: list, id_set: set[int]) -> list[int]:
    """Sort function IDs so callees come before callers (bottom-up lift order).

    Uses Kahn's algorithm on caller->callee edges, then reverses.
    """
    graph: dict[int, list[int]] = defaultdict(list)
    in_degree: dict[int, int] = {fid: 0 for fid in id_set}

    for func in functions:
        outbound = parse_json_safe(func.simple_outbound_xrefs) or []
        for xref in outbound:
            if not isinstance(xref, dict):
                continue
            callee_id = xref.get("function_id")
            if callee_id is not None and callee_id in id_set and callee_id != func.function_id:
                graph[func.function_id].append(callee_id)
                in_degree[callee_id] += 1

    queue = deque(fid for fid in id_set if in_degree.get(fid, 0) == 0)
    result: list[int] = []
    while queue:
        fid = queue.popleft()
        result.append(fid)
        for callee_id in graph.get(fid, []):
            in_degree[callee_id] -= 1
            if in_degree[callee_id] == 0:
                queue.append(callee_id)

    # Append any remaining (cycles)
    remaining = [fid for fid in id_set if fid not in set(result)]
    result.extend(remaining)

    # Reverse: Kahn's on caller->callee gives callers first; we want callees first
    result.reverse()
    return result


__all__ = [
    "emit_error",
    "format_struct_definition",
    "merge_struct_fields",
    "parse_class_from_mangled",
    "parse_json_safe",
    "resolve_db_path",
    "resolve_tracking_db",
    "scan_batch_struct_accesses",
    "scan_struct_accesses",
    "SIZE_TO_C_TYPE",
    "topological_sort_functions",
    "TYPE_SIZES",
    "WORKSPACE_ROOT",
]
