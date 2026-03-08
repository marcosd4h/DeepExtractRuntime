"""Shared utilities for data-flow-tracer scripts.

Provides workspace root resolution, decompiled code parsing,
parameter tracking, and expression classification used across all scripts.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any, Optional

_AGENT_DIR = str(Path(__file__).resolve().parents[3])
if _AGENT_DIR not in sys.path:
    sys.path.insert(0, _AGENT_DIR)

from skills._shared import bootstrap, make_db_resolvers

WORKSPACE_ROOT = bootstrap(__file__)

from helpers import emit_error, parse_json_safe  # noqa: E402
from helpers.calling_conventions import (  # noqa: E402
    PARAM_REGISTERS,
    REGISTER_TO_PARAM,
    param_name_for,
)
from helpers.decompiled_parser import (  # noqa: E402
    discover_calls_with_xrefs as _discover_calls_with_xrefs,
    extract_balanced_parens as _extract_balanced_parens,
    extract_function_calls as _extract_function_calls,
    find_param_in_calls as _find_param_in_calls,
    split_arguments as _split_arguments,
)

# ---------------------------------------------------------------------------
# x64 calling convention (Microsoft fastcall)
# ---------------------------------------------------------------------------

# C keywords / IDA macros to skip during call extraction
_KEYWORDS = frozenset({
    "if", "while", "for", "switch", "return", "sizeof", "else",
    "do", "goto", "case", "break", "continue", "default",
    "LODWORD", "HIDWORD", "LOBYTE", "HIBYTE", "LOWORD", "HIWORD",
    "BYTE1", "BYTE2", "BYTE3", "BYTE4", "COERCE_FLOAT",
    "SHIDWORD", "SLODWORD",
})

# ---------------------------------------------------------------------------
# DB helpers (bound to this skill's WORKSPACE_ROOT)
# ---------------------------------------------------------------------------
resolve_db_path, resolve_tracking_db = make_db_resolvers(WORKSPACE_ROOT)


# ---------------------------------------------------------------------------
# Decompiled code parsing
# ---------------------------------------------------------------------------

def extract_balanced_parens(text: str, start: int = 0) -> Optional[str]:
    """Extract content inside balanced parentheses starting at position `start`.
    Returns content string (excluding outer parens) or None if unbalanced.
    """
    return _extract_balanced_parens(text, start)


def split_arguments(args_str: str) -> list[str]:
    """Split comma-separated arguments respecting nested parens/brackets."""
    return _split_arguments(args_str)


def extract_function_calls(code: str) -> list[dict]:
    """Extract function call sites from decompiled C code.

    Returns list of dicts with keys:
      function_name, line_number, line, arguments, result_var
    """
    return _extract_function_calls(code, keywords=_KEYWORDS)


def find_param_in_calls(code: str, param_name: str) -> list[dict]:
    """Find function calls where a parameter appears as an argument.

    Returns list of dicts:
      function_name, arg_position (0-based), arg_expression, line_number, line, is_direct
    """
    return _find_param_in_calls(code, param_name, keywords=_KEYWORDS)


def classify_expression(expr: str) -> dict:
    """Classify an expression as parameter, call_result, global, constant, etc."""
    expr = expr.strip()
    # Strip outer cast: (type)expr
    inner = re.sub(r"^\([^)]*\)\s*", "", expr)

    # IDA parameter: a1, a2 ...
    m = re.match(r"^a(\d+)$", inner)
    if m:
        return {"type": "parameter", "param_number": int(m.group(1))}

    # Function call result
    m = re.match(r"^([a-zA-Z_]\w*)\s*\(", inner)
    if m and m.group(1) not in _KEYWORDS:
        return {"type": "call_result", "function": m.group(1)}

    # Numeric constant
    if re.match(r"^-?(?:0[xX][0-9a-fA-F]+|\d+)[uUiIlL]*$", inner):
        return {"type": "constant", "value": inner}

    # NULL variants
    if inner in ("0", "NULL", "nullptr", "0LL", "0i64"):
        return {"type": "constant", "value": inner}

    # String literal
    if inner.startswith('"') or inner.startswith('L"') or inner.startswith("'"):
        return {"type": "string_literal", "value": inner}

    # IDA global variable (dword_XXXX, qword_XXXX, etc.)
    if re.match(r"^(?:dword|qword|word|byte|off|unk|stru)_[0-9A-Fa-f]+$", inner):
        return {"type": "global", "name": inner}

    # Local variable (v1, v2, ...)
    if re.match(r"^v\d+$", inner):
        return {"type": "local_variable", "name": inner}

    # Pointer dereference containing a parameter
    pm = re.search(r"\ba(\d+)\b", inner)
    if pm and ("*" in expr or "[" in expr):
        return {"type": "param_dereference", "param_number": int(pm.group(1)), "expression": expr}

    return {"type": "expression", "expression": expr}


def trace_variable_origin(code: str, var_name: str, max_depth: int = 5) -> list[dict]:
    """Trace where a variable gets its value from by following assignment chains.

    Returns list of origin dicts (from classify_expression) augmented with
    line_number, line, raw_expression, variable, and optional deeper_origin.
    """
    visited: set[str] = set()

    def _trace(name: str, depth: int) -> list[dict]:
        if depth > max_depth or name in visited:
            return []
        visited.add(name)
        origins: list[dict] = []
        for i, line in enumerate(code.splitlines(), 1):
            stripped = line.strip()
            m = re.match(
                rf".*?\b{re.escape(name)}\s*=[^=]\s*(.+?)\s*;", stripped
            )
            if m:
                expr = m.group(1).strip()
                classified = classify_expression(expr)
                classified["line_number"] = i
                classified["line"] = stripped
                classified["raw_expression"] = expr
                classified["variable"] = name
                if classified["type"] == "local_variable":
                    deeper = _trace(classified["name"], depth + 1)
                    if deeper:
                        classified["deeper_origin"] = deeper
                origins.append(classified)
        return origins

    return _trace(var_name, 0)


# ---------------------------------------------------------------------------
# Assembly analysis
# ---------------------------------------------------------------------------

def find_param_register_aliases(assembly: str, param_number: int) -> set[str]:
    """Track a parameter register through the function prologue.

    Returns all registers that hold the parameter value after register
    moves in the prologue area (~first 30 instructions).
    """
    if param_number < 1 or param_number > 4:
        return set()
    tracked = set(PARAM_REGISTERS[param_number])
    lines = assembly.splitlines()[:30]
    for line in lines:
        stripped = line.strip()
        m = re.match(r"mov\s+(\w+),\s*(\w+)", stripped, re.IGNORECASE)
        if m:
            dest, src = m.group(1).lower(), m.group(2).lower()
            if src in tracked:
                tracked.add(dest)
    return tracked


def find_assembly_calls(assembly: str) -> list[dict]:
    """Find all call instructions in assembly.

    Returns list of dicts: line_number, instruction, target
    """
    calls: list[dict] = []
    for i, line in enumerate(assembly.splitlines(), 1):
        stripped = line.strip()
        m = re.match(r"call\s+(.+)", stripped, re.IGNORECASE)
        if m:
            calls.append({
                "line_number": i,
                "instruction": stripped,
                "target": m.group(1).strip(),
            })
    return calls


def find_global_writes_in_assembly(assembly: str, tracked_regs: set[str]) -> list[dict]:
    """Find memory stores where source is a tracked register.

    Returns list of dicts: line_number, instruction, target_address
    """
    stores: list[dict] = []
    for i, line in enumerate(assembly.splitlines(), 1):
        stripped = line.strip()
        m = re.match(r"mov\s+\[([^\]]+)\],\s*(\w+)", stripped, re.IGNORECASE)
        if m:
            addr, src = m.group(1), m.group(2).lower()
            if src in tracked_regs:
                stores.append({
                    "line_number": i,
                    "instruction": stripped,
                    "target_address": addr,
                })
    return stores


__all__ = [
    "classify_expression",
    "emit_error",
    "extract_balanced_parens",
    "extract_function_calls",
    "find_assembly_calls",
    "find_global_writes_in_assembly",
    "find_param_in_calls",
    "find_param_register_aliases",
    "param_name_for",
    "PARAM_REGISTERS",
    "REGISTER_TO_PARAM",
    "parse_json_safe",
    "resolve_db_path",
    "resolve_tracking_db",
    "split_arguments",
    "trace_variable_origin",
    "WORKSPACE_ROOT",
]
