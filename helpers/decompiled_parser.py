"""Shared parsing helpers for IDA decompiled C/C++ snippets."""

from __future__ import annotations

import re
from typing import Optional

_CALL_RE = re.compile(r"\b([a-zA-Z_]\w*)\s*\(")

_DEFAULT_KEYWORDS = frozenset(
    {
        "if",
        "while",
        "for",
        "switch",
        "return",
        "sizeof",
        "else",
        "do",
        "goto",
        "case",
        "break",
        "continue",
        "default",
        "LODWORD",
        "HIDWORD",
        "LOBYTE",
        "HIBYTE",
        "LOWORD",
        "HIWORD",
        "BYTE1",
        "BYTE2",
        "BYTE3",
        "BYTE4",
        "COERCE_FLOAT",
        "SHIDWORD",
        "SLODWORD",
    }
)


def extract_balanced_parens(text: str, start: int = 0) -> Optional[str]:
    """Extract content from balanced parentheses at ``text[start]``."""
    if start >= len(text) or text[start] != "(":
        return None
    depth = 0
    for index in range(start, len(text)):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1 : index]
    return None


def split_arguments(args_str: str) -> list[str]:
    """Split comma-delimited args while respecting nested () and []."""
    args: list[str] = []
    current: list[str] = []
    depth = 0
    for char in args_str:
        if char in "([":
            depth += 1
            current.append(char)
        elif char in ")]":
            depth -= 1
            current.append(char)
        elif char == "," and depth == 0:
            arg = "".join(current).strip()
            if arg:
                args.append(arg)
            current = []
        else:
            current.append(char)

    last = "".join(current).strip()
    if last:
        args.append(last)
    return args


def extract_function_calls(
    code: str,
    *,
    keywords: frozenset[str] = _DEFAULT_KEYWORDS,
) -> list[dict]:
    """Extract function-call sites from decompiled code.

    Handles multi-line calls by joining subsequent lines when parentheses
    are not balanced on a single line.
    """
    calls: list[dict] = []
    lines = code.splitlines()

    for line_idx, line in enumerate(lines):
        stripped = line.strip()
        for match in _CALL_RE.finditer(stripped):
            func_name = match.group(1)
            if func_name in keywords:
                continue
            paren_pos = match.end() - 1
            content = extract_balanced_parens(stripped, paren_pos)

            if content is None:
                combined = stripped
                for j in range(line_idx + 1, min(line_idx + 30, len(lines))):
                    combined += " " + lines[j].strip()
                    token = func_name + "("
                    tok_pos = combined.find(token)
                    if tok_pos == -1:
                        break
                    new_paren = tok_pos + len(func_name)
                    content = extract_balanced_parens(combined, new_paren)
                    if content is not None:
                        break

            if content is None:
                calls.append(
                    {
                        "function_name": func_name,
                        "line_number": line_idx + 1,
                        "line": stripped,
                        "arguments": [],
                        "result_var": None,
                    }
                )
                continue

            args = split_arguments(content)
            before = stripped[: match.start()].rstrip()
            assign_match = re.search(r"(\w+)\s*=\s*$", before)
            result_var = assign_match.group(1) if assign_match else None
            calls.append(
                {
                    "function_name": func_name,
                    "line_number": line_idx + 1,
                    "line": stripped,
                    "arguments": args,
                    "result_var": result_var,
                }
            )
    return calls


def discover_calls_with_xrefs(
    code: str,
    xrefs: list[dict],
    *,
    keywords: frozenset[str] = _DEFAULT_KEYWORDS,
) -> list[dict]:
    """Discover function calls using DB xrefs as ground truth, parser for args.

    Uses ``simple_outbound_xrefs`` for authoritative call discovery, then
    enriches with argument expressions from the regex parser where available.
    Calls that appear only in xrefs (missed by the parser due to formatting)
    are included with empty argument lists.
    """
    parser_calls = extract_function_calls(code, keywords=keywords)
    parser_by_name: dict[str, list[dict]] = {}
    for c in parser_calls:
        parser_by_name.setdefault(c["function_name"].lower(), []).append(c)

    _CALL_XREF_TYPES = frozenset({
        "Call Near", "Call_Near_Call", "Code_Near_Call", "Call",
        "call", "Code Near Call",
    })

    for x in xrefs:
        fn = x.get("function_name", "")
        if not fn:
            continue
        xtype = x.get("xref_type", "")
        if xtype and xtype not in _CALL_XREF_TYPES:
            continue
        if fn.lower() not in parser_by_name:
            parser_calls.append(
                {
                    "function_name": fn,
                    "line_number": 0,
                    "line": "",
                    "arguments": [],
                    "result_var": None,
                    "source": "xref",
                }
            )
            parser_by_name.setdefault(fn.lower(), [])

    return parser_calls


def find_param_in_calls(
    code: str,
    param_name: str,
    *,
    keywords: frozenset[str] = _DEFAULT_KEYWORDS,
) -> list[dict]:
    """Find calls where a parameter appears in an argument expression."""
    pattern = re.compile(rf"\b{re.escape(param_name)}\b")
    results: list[dict] = []
    for call in extract_function_calls(code, keywords=keywords):
        for arg_position, arg_expression in enumerate(call["arguments"]):
            if pattern.search(arg_expression):
                results.append(
                    {
                        "function_name": call["function_name"],
                        "arg_position": arg_position,
                        "arg_expression": arg_expression,
                        "line_number": call["line_number"],
                        "line": call["line"],
                        "is_direct": arg_expression.strip() == param_name,
                    }
                )
    return results


__all__ = [
    "discover_calls_with_xrefs",
    "extract_balanced_parens",
    "extract_function_calls",
    "find_param_in_calls",
    "split_arguments",
]
