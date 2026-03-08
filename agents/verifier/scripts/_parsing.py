"""Lifted code parsing and statistics extraction for the verifier.

Extracts function calls, control flow, string literals, global references,
and offset comments from lifted (rewritten) code for comparison against
assembly ground truth.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Regex patterns for lifted code analysis
# ---------------------------------------------------------------------------

# Function calls in lifted code (word followed by open paren)
LIFTED_CALL_RE = re.compile(r"\b(\w+)\s*\(")

# C/C++ keywords and type names to exclude from call detection
LIFTED_CALL_EXCLUDES = frozenset({
    "if", "while", "for", "return", "switch", "sizeof", "typeof", "alignof",
    "do", "else", "case", "default", "goto", "break", "continue", "throw",
    # Type keywords
    "int", "char", "void", "long", "short", "double", "float", "bool",
    "unsigned", "signed", "const", "volatile", "static", "extern", "inline",
    "struct", "class", "enum", "union", "typedef", "namespace", "template",
    # IDA-specific (should NOT appear in lifted code but handle gracefully)
    "LOBYTE", "HIBYTE", "LOWORD", "HIWORD", "LODWORD", "HIDWORD",
    "_QWORD", "_DWORD", "_WORD", "_BYTE", "BYTE", "DWORD", "QWORD", "WORD",
    # Common Win32 macros
    "FAILED", "SUCCEEDED", "HRESULT_FROM_WIN32", "MAKEWORD", "MAKELONG",
    "LOWORD", "HIWORD", "LOBYTE", "HIBYTE",
    # Cast-like patterns
    "reinterpret_cast", "static_cast", "dynamic_cast", "const_cast",
})

# Control flow patterns
LIFTED_IF_RE = re.compile(r"\bif\s*\(")
LIFTED_ELSE_RE = re.compile(r"\belse\b")
LIFTED_SWITCH_RE = re.compile(r"\bswitch\s*\(")
LIFTED_CASE_RE = re.compile(r"^\s*case\s+", re.MULTILINE)
LIFTED_DEFAULT_RE = re.compile(r"^\s*default\s*:", re.MULTILINE)
LIFTED_WHILE_RE = re.compile(r"\bwhile\s*\(")
LIFTED_FOR_RE = re.compile(r"\bfor\s*\(")
LIFTED_AND_OR_RE = re.compile(r"&&|\|\|")
LIFTED_TERNARY_RE = re.compile(r"\?(?!=)")
LIFTED_RETURN_RE = re.compile(r"\breturn\b")
LIFTED_GOTO_RE = re.compile(r"\bgoto\b")

# String literal extraction from lifted code
LIFTED_STRING_RE = re.compile(r'"([^"\\]*(\\.[^"\\]*)*)"')
LIFTED_WSTRING_RE = re.compile(r'L"([^"\\]*(\\.[^"\\]*)*)"')

# Memory access patterns in lifted code (struct field access via ->)
LIFTED_ARROW_RE = re.compile(r"->(\w+)")
LIFTED_DOT_RE = re.compile(r"\.(\w+)")
# Offset comments like // +0x70 or /* offset 0x70 */
LIFTED_OFFSET_COMMENT_RE = re.compile(r"[+]0x([0-9A-Fa-f]+)")

# Global variable patterns (dword_XXXX, qword_XXXX, etc.)
LIFTED_GLOBAL_RE = re.compile(r"\b((?:dword|qword|word|byte|off|unk)_[0-9A-Fa-f]+)\b")


@dataclass
class LiftedCodeStats:
    """Statistics extracted from lifted code for comparison."""
    line_count: int = 0
    call_count: int = 0           # unique function names called
    total_call_sites: int = 0     # total call instances
    if_count: int = 0
    else_count: int = 0
    switch_count: int = 0
    case_count: int = 0
    while_count: int = 0
    for_count: int = 0
    goto_count: int = 0
    and_or_ops: int = 0           # && and || operators
    ternary_ops: int = 0
    return_count: int = 0

    @property
    def total_branch_points(self) -> int:
        """Effective branch point count (for comparison with assembly branches)."""
        return (
            self.if_count
            + self.goto_count
            + self.while_count
            + self.for_count
            + self.and_or_ops
            + self.ternary_ops
            + self.case_count
        )

    # Function names called
    called_functions: list[str] = field(default_factory=list)

    # String literals found in lifted code
    string_literals: list[str] = field(default_factory=list)

    # Global variable references found
    global_refs: list[str] = field(default_factory=list)

    # Offset comments found (hex offsets)
    offset_comments: list[str] = field(default_factory=list)


def parse_lifted_code(lifted_code: str) -> LiftedCodeStats:
    """Parse lifted (rewritten) code into statistics for comparison."""
    stats = LiftedCodeStats()

    if not lifted_code or not lifted_code.strip():
        return stats

    lines = lifted_code.splitlines()
    stats.line_count = len(lines)

    called_set: set[str] = set()
    string_set: set[str] = set()
    global_set: set[str] = set()
    offset_set: set[str] = set()

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            # Still extract offset comments from comment lines
            for m in LIFTED_OFFSET_COMMENT_RE.finditer(stripped):
                offset_set.add(m.group(1).upper())
            continue

        # Count control flow
        stats.if_count += len(LIFTED_IF_RE.findall(stripped))
        stats.else_count += len(LIFTED_ELSE_RE.findall(stripped))
        stats.switch_count += len(LIFTED_SWITCH_RE.findall(stripped))
        stats.while_count += len(LIFTED_WHILE_RE.findall(stripped))
        stats.for_count += len(LIFTED_FOR_RE.findall(stripped))
        stats.and_or_ops += len(LIFTED_AND_OR_RE.findall(stripped))
        stats.ternary_ops += len(LIFTED_TERNARY_RE.findall(stripped))
        stats.return_count += len(LIFTED_RETURN_RE.findall(stripped))
        stats.goto_count += len(LIFTED_GOTO_RE.findall(stripped))

        if LIFTED_CASE_RE.match(stripped):
            stats.case_count += 1
        if LIFTED_DEFAULT_RE.match(stripped):
            stats.case_count += 1

        # Extract function calls
        for m in LIFTED_CALL_RE.finditer(stripped):
            name = m.group(1)
            if name not in LIFTED_CALL_EXCLUDES:
                called_set.add(name)
                stats.total_call_sites += 1

        # Extract string literals
        for m in LIFTED_STRING_RE.finditer(stripped):
            string_set.add(m.group(1))
        for m in LIFTED_WSTRING_RE.finditer(stripped):
            string_set.add(m.group(1))

        # Extract global variable references
        for m in LIFTED_GLOBAL_RE.finditer(stripped):
            global_set.add(m.group(1))

        # Extract offset comments
        for m in LIFTED_OFFSET_COMMENT_RE.finditer(stripped):
            offset_set.add(m.group(1).upper())

    stats.call_count = len(called_set)
    stats.called_functions = sorted(called_set)
    stats.string_literals = sorted(string_set)
    stats.global_refs = sorted(global_set)
    stats.offset_comments = sorted(offset_set)

    return stats
