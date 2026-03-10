"""Shared utilities for state-machine-extractor scripts.

Provides workspace root resolution, switch/case regex patterns,
jump table helpers, and decompiled-code parsing used across all scripts.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

_AGENT_DIR = str(Path(__file__).resolve().parents[3])
if _AGENT_DIR not in sys.path:
    sys.path.insert(0, _AGENT_DIR)

from skills._shared import bootstrap, make_db_resolvers

WORKSPACE_ROOT = bootstrap(__file__)
resolve_db_path, resolve_tracking_db = make_db_resolvers(WORKSPACE_ROOT)

from helpers import emit_error, parse_json_safe  # noqa: E402


# ---------------------------------------------------------------------------
# Regex patterns for switch/case detection in decompiled code
# ---------------------------------------------------------------------------

# Matches: switch ( expression )
RE_SWITCH = re.compile(
    r'\bswitch\s*\(\s*(.+?)\s*\)',
    re.MULTILINE,
)

# Matches: case 0x1A: or case 42: or case -1: (with optional hex/decimal)
RE_CASE = re.compile(
    r'^\s*case\s+(-?(?:0[xX][0-9a-fA-F]+|\d+))\s*:',
    re.MULTILINE,
)

# Matches: default:
RE_DEFAULT = re.compile(r'^\s*default\s*:', re.MULTILINE)

# Large if-else chain detection: if ( var == CONST ) or if ( var == CONST )
# Matches comparisons like: if ( v5 == 3 ) or if ( a1 == 0x1A )
RE_IF_EQ_CONST = re.compile(
    r'\bif\s*\(\s*(\w+)\s*==\s*(-?(?:0[xX][0-9a-fA-F]+|\d+))\s*\)',
    re.MULTILINE,
)

# Matches function calls in case/branch bodies for handler extraction
RE_FUNCTION_CALL = re.compile(
    r'\b([a-zA-Z_]\w*)\s*\(',
)

# Matches: goto LABEL_N  (for tracking control flow in cases)
RE_GOTO = re.compile(r'\bgoto\s+(LABEL_\d+)\s*;')

# Matches return statements with values
RE_RETURN = re.compile(r'\breturn\s+(.+?)\s*;')


# ---------------------------------------------------------------------------
# String-compare dispatch detection
# ---------------------------------------------------------------------------

_STRING_CMP_FUNCTIONS = frozenset({
    "_wcsnicmp", "_o__wcsnicmp", "_wcsicmp", "_o__wcsicmp",
    "wcsncmp", "_wcsncmp", "wcscmp",
    "strcmp", "_stricmp", "strncmp", "_strnicmp",
    "_mbsicmp", "_o__mbsicmp",
    "_o_strcmp", "_o_strncmp", "_o_wcscmp", "_o_wcsncmp",
})

# Matches a call to a string-compare function with a string literal arg:
#   _wcsnicmp(ptr, L"keyword", 7)
#   _o__wcsnicmp(Str, L"eol=", 4)
#   strcmp(buf, "exit")
# Captures: (compare_func, first_arg, string_literal)
RE_STRING_CMP_CALL = re.compile(
    r'\b(' + '|'.join(re.escape(f) for f in sorted(_STRING_CMP_FUNCTIONS)) +
    r')\s*\(\s*'
    r'([^,]+?)'           # first arg (the pointer being compared)
    r'\s*,\s*'
    r'(?:L\s*)?'          # optional L prefix for wide strings
    r'"([^"]*)"'          # the string literal
    r'\s*(?:,\s*[^)]+)?'  # optional third arg (length)
    r'\s*\)',
)


# ---------------------------------------------------------------------------
# Dispatch table data structures
# ---------------------------------------------------------------------------

@dataclass
class CaseEntry:
    """A single case in a dispatch/switch table."""
    case_value: int
    case_value_hex: str
    handler_name: Optional[str] = None
    handler_id: Optional[int] = None
    is_internal: bool = False
    handler_module: Optional[str] = None
    label: Optional[str] = None  # string literal or name associated with this case
    case_label: Optional[str] = None  # keyword string for string-compare dispatch
    source: str = "decompiled"  # "decompiled", "jump_table", "if_chain", "string_compare"
    confidence: float = 100.0


@dataclass
class DispatchTable:
    """A reconstructed dispatch table from a function."""
    function_name: str
    function_id: int
    switch_variable: Optional[str] = None
    cases: list[CaseEntry] = field(default_factory=list)
    has_default: bool = False
    default_handler: Optional[str] = None
    total_cases: int = 0
    source_type: str = "switch"  # "switch", "if_chain", "jump_table", "mixed"
    string_labels: dict[int, str] = field(default_factory=dict)  # case_value -> label


@dataclass
class StateInfo:
    """A state in a reconstructed state machine."""
    state_id: int
    state_name: str
    handler_name: Optional[str] = None
    handler_id: Optional[int] = None
    is_terminal: bool = False
    is_initial: bool = False
    transitions: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class StateMachine:
    """A reconstructed state machine."""
    function_name: str
    function_id: int
    state_variable: Optional[str] = None
    states: list[StateInfo] = field(default_factory=list)
    loop_info: Optional[dict[str, Any]] = None
    dispatch_table: Optional[DispatchTable] = None


# ---------------------------------------------------------------------------
# Decompiled code parsing
# ---------------------------------------------------------------------------


def parse_switch_cases(decompiled: str) -> list[dict[str, Any]]:
    """Parse all switch statements from decompiled code.

    Returns list of dicts with keys:
        switch_variable, cases (list of case_value ints),
        has_default, start_pos, body_text
    """
    results = []
    for match in RE_SWITCH.finditer(decompiled):
        switch_var = match.group(1).strip()
        start = match.end()

        # Find the switch body by tracking braces
        body = _extract_brace_block(decompiled, start)
        if body is None:
            continue

        # Extract case values from body
        case_values = []
        for cm in RE_CASE.finditer(body):
            raw = cm.group(1)
            case_values.append(_parse_int(raw))

        has_default = bool(RE_DEFAULT.search(body))

        results.append({
            "switch_variable": switch_var,
            "cases": case_values,
            "has_default": has_default,
            "body_text": body,
            "start_pos": match.start(),
        })

    return results


def parse_if_chain(decompiled: str, min_branches: int = 4) -> list[dict[str, Any]]:
    """Detect if-else chains comparing the same variable against constants.

    Returns list of dicts with keys:
        variable, comparisons (list of {value, start_pos})
    Only returns chains with >= min_branches comparisons of the same variable.
    """
    # Collect all comparisons
    comparisons: dict[str, list[dict[str, Any]]] = {}
    for match in RE_IF_EQ_CONST.finditer(decompiled):
        var = match.group(1)
        val = _parse_int(match.group(2))
        if var not in comparisons:
            comparisons[var] = []
        comparisons[var].append({"value": val, "start_pos": match.start()})

    return [
        {"variable": var, "comparisons": comps}
        for var, comps in comparisons.items()
        if len(comps) >= min_branches
    ]


def parse_string_compare_chain(
    decompiled: str, min_branches: int = 3,
) -> list[dict[str, Any]]:
    """Detect if-chains dispatching on string-compare function results.

    Finds sequential calls to _wcsnicmp / strcmp / etc. where the same pointer
    is compared against different string literals, forming a keyword dispatcher.

    Returns list of dicts with keys:
        variable          -- the pointer argument being compared
        compare_function  -- primary compare function name (most frequent)
        keywords          -- list of {keyword, start_pos, compare_function}
    Only returns chains with >= min_branches distinct keyword comparisons.
    """
    matches: list[dict[str, Any]] = []
    for m in RE_STRING_CMP_CALL.finditer(decompiled):
        func_name = m.group(1)
        first_arg = m.group(2).strip()
        keyword = m.group(3)
        # Normalize the first-arg: strip casts like (unsigned int) and
        # outer parens so "Str" and "(wchar_t *)Str" collapse to "Str".
        bare_arg = re.sub(r'\([^)]*\)\s*', '', first_arg).strip()
        if not bare_arg:
            bare_arg = first_arg
        matches.append({
            "variable": bare_arg,
            "compare_function": func_name,
            "keyword": keyword,
            "start_pos": m.start(),
        })

    if not matches:
        return []

    # Group by variable name, preserving source order
    groups: dict[str, list[dict[str, Any]]] = {}
    for item in matches:
        var = item["variable"]
        groups.setdefault(var, []).append(item)

    results = []
    for var, items in groups.items():
        # Deduplicate keywords while preserving order
        seen: set[str] = set()
        unique_items: list[dict[str, Any]] = []
        for item in items:
            if item["keyword"] not in seen:
                seen.add(item["keyword"])
                unique_items.append(item)
        if len(unique_items) < min_branches:
            continue

        # Determine the most frequent compare function
        func_counts: dict[str, int] = {}
        for item in unique_items:
            f = item["compare_function"]
            func_counts[f] = func_counts.get(f, 0) + 1
        primary_func = max(func_counts, key=func_counts.get)  # type: ignore[arg-type]

        results.append({
            "variable": var,
            "compare_function": primary_func,
            "keywords": [
                {
                    "keyword": item["keyword"],
                    "start_pos": item["start_pos"],
                    "compare_function": item["compare_function"],
                }
                for item in unique_items
            ],
        })

    return results


def extract_case_handlers(body_text: str) -> dict[int, list[str]]:
    """Extract handler function calls from each case block in switch body.

    Returns {case_value: [function_names_called]}.
    """
    handlers: dict[int, list[str]] = {}
    # Split body into case blocks
    case_positions = []
    for match in RE_CASE.finditer(body_text):
        case_val = _parse_int(match.group(1))
        case_positions.append((case_val, match.end()))

    for i, (case_val, start) in enumerate(case_positions):
        if i + 1 < len(case_positions):
            end = case_positions[i + 1][1] - len(f"case {case_positions[i + 1][0]}:")
            # approximate: find the next case start
            next_case_match = RE_CASE.search(body_text, start)
            if next_case_match and next_case_match.start() > start:
                end = next_case_match.start()
            else:
                end = len(body_text)
        else:
            end = len(body_text)

        block = body_text[start:end]
        # Find function calls in this case block
        calls = []
        for call_match in RE_FUNCTION_CALL.finditer(block):
            fname = call_match.group(1)
            # Filter out C keywords and common non-function identifiers
            if fname not in _C_KEYWORDS and not fname.startswith("__"):
                calls.append(fname)
        handlers[case_val] = calls

    return handlers


def extract_jump_table_targets(outbound_xrefs: list[dict]) -> list[dict[str, Any]]:
    """Extract jump table targets from detailed outbound xrefs.

    Returns list of dicts with: function_name, target_ea, confidence,
    detection_method, is_jump_table_target.
    """
    targets = []
    for xref in outbound_xrefs:
        if xref.get("is_jump_table_target"):
            targets.append({
                "function_name": xref.get("function_name"),
                "target_ea": xref.get("target_ea") or xref.get("resolved_target_ea"),
                "confidence": xref.get("jump_table_detection_confidence", 0),
                "detection_method": xref.get("jump_table_detection_method", "unknown"),
                "source_ea": xref.get("source_instruction_ea"),
                "is_internal": xref.get("function_name") is not None,
            })
    return targets


def classify_outbound_xrefs(simple_xrefs: list[dict]) -> dict[str, list[dict]]:
    """Classify outbound xrefs into internal, external, data, vtable categories.

    Returns dict with keys: internal, external, data, vtable.
    """
    classified: dict[str, list[dict]] = {
        "internal": [], "external": [], "data": [], "vtable": [],
    }
    for xref in simple_xrefs:
        ftype = xref.get("function_type", 0)
        module = xref.get("module_name", "")
        fid = xref.get("function_id")

        if ftype == 4 or module == "data":
            classified["data"].append(xref)
        elif ftype == 8 or module == "vtable":
            classified["vtable"].append(xref)
        elif fid is not None:
            classified["internal"].append(xref)
        else:
            classified["external"].append(xref)

    return classified


# ---------------------------------------------------------------------------
# Assembly jump table detection
# ---------------------------------------------------------------------------

# Patterns for indirect jumps via jump table in x64 assembly
RE_ASM_JUMP_TABLE = re.compile(
    r'\bjmp\s+(?:qword\s+)?(?:cs:)?(?:\[.*?\+.*?\*[48]\]|off_[0-9a-fA-F]+)',
    re.IGNORECASE,
)

# Match cmp + ja/jbe patterns that guard switch ranges
RE_ASM_SWITCH_CMP = re.compile(
    r'\bcmp\s+\w+,\s*(-?(?:0[xX][0-9a-fA-F]+|\d+))\b',
    re.IGNORECASE,
)


def detect_asm_switch_patterns(assembly: str) -> dict[str, Any]:
    """Detect switch/jump table patterns in assembly code.

    Returns dict with: has_jump_table, max_case_value, jump_table_refs.
    """
    jump_tables = RE_ASM_JUMP_TABLE.findall(assembly) if assembly else []
    cmp_values = []
    for match in RE_ASM_SWITCH_CMP.finditer(assembly or ""):
        cmp_values.append(_parse_int(match.group(1)))

    return {
        "has_jump_table": len(jump_tables) > 0,
        "jump_table_count": len(jump_tables),
        "cmp_values": cmp_values,
        "max_case_value": max(cmp_values) if cmp_values else None,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_C_KEYWORDS = frozenset({
    "if", "else", "while", "for", "do", "switch", "case", "default",
    "break", "continue", "return", "goto", "sizeof", "typedef",
    "struct", "union", "enum", "void", "int", "char", "short", "long",
    "unsigned", "signed", "float", "double", "const", "volatile",
    "static", "extern", "register", "auto", "inline",
    "LOBYTE", "HIBYTE", "LOWORD", "HIWORD", "LODWORD", "HIDWORD",
    "BYTE1", "BYTE2", "BYTE3", "BYTE4",
    "LABEL", "JUMPOUT",
})


def _parse_int(s: str) -> int:
    """Parse an integer from decimal or hex string."""
    s = s.strip()
    if s.startswith(("-0x", "-0X")):
        return -int(s[1:], 16)
    if s.startswith(("0x", "0X")):
        return int(s, 16)
    return int(s)


def _extract_brace_block(text: str, start: int) -> Optional[str]:
    """Extract text within the next balanced {} block starting from pos `start`."""
    idx = text.find("{", start)
    if idx == -1:
        return None
    depth = 0
    for i in range(idx, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[idx + 1:i]
    return None  # unbalanced


def format_int(val: int) -> str:
    """Format an integer as hex if large, decimal otherwise."""
    if abs(val) > 255:
        return f"0x{val:X}" if val >= 0 else f"-0x{abs(val):X}"
    return str(val)


__all__ = [
    "CaseEntry",
    "classify_outbound_xrefs",
    "detect_asm_switch_patterns",
    "DispatchTable",
    "emit_error",
    "extract_case_handlers",
    "extract_jump_table_targets",
    "format_int",
    "parse_if_chain",
    "parse_json_safe",
    "parse_string_compare_chain",
    "parse_switch_cases",
    "RE_ASM_JUMP_TABLE",
    "RE_ASM_SWITCH_CMP",
    "RE_CASE",
    "RE_DEFAULT",
    "RE_FUNCTION_CALL",
    "RE_GOTO",
    "RE_IF_EQ_CONST",
    "RE_RETURN",
    "RE_STRING_CMP_CALL",
    "RE_SWITCH",
    "resolve_db_path",
    "resolve_tracking_db",
    "StateInfo",
    "StateMachine",
    "WORKSPACE_ROOT",
]
