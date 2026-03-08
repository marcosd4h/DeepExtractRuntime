"""Classify conditional guards in IDA decompiled C code.

Given a range of lines between a taint source and a sink, finds ``if`` /
``while`` conditions and classifies each as an auth check, bounds check,
null check, validation, error check, or generic comparison.  Each guard
is annotated with whether any attacker-controlled (tainted) variable
appears in its condition, allowing downstream consumers to estimate
bypass difficulty.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .decompiled_parser import extract_balanced_parens

# ---------------------------------------------------------------------------
# Security-check API prefixes (prefix matching, case-insensitive)
# ---------------------------------------------------------------------------

AUTH_CHECK_APIS: tuple[str, ...] = (
    "IsAdmin",
    "CheckTokenMembership",
    "AccessCheck",
    "AccessCheckByType",
    "PrivilegeCheck",
    "AuthzAccessCheck",
    "AuthzInitializeContextFromToken",
    "ImpersonateLoggedOnUser",
    "ImpersonateNamedPipeClient",
    "ImpersonateSelf",
    "RevertToSelf",
    "LogonUser",
    "EqualSid",
    "IsWellKnownSid",
    "CheckAccess",
    "AiCheckSecure",
    "SaferIdentifyLevel",
    "SaferComputeTokenFromLevel",
)

VALIDATION_API_PREFIXES: tuple[str, ...] = (
    "Validate",
    "Verify",
    "IsValid",
    "Check",
    "Ensure",
    "Assert",
)

ERROR_CHECK_MACROS: tuple[str, ...] = (
    "SUCCEEDED",
    "FAILED",
    "NT_SUCCESS",
    "NT_ERROR",
    "IS_ERROR",
    "HRESULT_FROM_WIN32",
    "GetLastError",
    "RtlNtStatusToDosError",
)

# ---------------------------------------------------------------------------
# Patterns for detecting common guard shapes
# ---------------------------------------------------------------------------

_IF_RE = re.compile(r"\b(if|while)\s*\(", re.IGNORECASE)
_NULL_CMP_RE = re.compile(
    r"""
    (\b\w+\b)\s*([!=]=)\s*(?:0|NULL|nullptr|0LL|0i64)\b
    |
    (?:0|NULL|nullptr|0LL|0i64)\b\s*[!=]=\s*(\b\w+\b)
    |
    !\s*(\b\w+\b)
    """,
    re.VERBOSE,
)
_BOUNDS_CMP_RE = re.compile(
    r"""
    (\b\w+\b)\s*([<>]=?)\s*(\b\w+|\d+[uUlL]*)
    """,
    re.VERBOSE,
)

# ---------------------------------------------------------------------------
# Guard data class
# ---------------------------------------------------------------------------

@dataclass
class Guard:
    """A conditional guard found in decompiled code."""

    guard_type: str
    line_number: int
    condition_text: str
    attacker_controllable: bool = False
    bypass_difficulty: str = "unknown"
    api_in_condition: Optional[str] = None
    tainted_vars_in_condition: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d: dict = {
            "guard_type": self.guard_type,
            "line_number": self.line_number,
            "condition": self.condition_text,
            "attacker_controllable": self.attacker_controllable,
            "bypass_difficulty": self.bypass_difficulty,
        }
        if self.api_in_condition:
            d["api_in_condition"] = self.api_in_condition
        if self.tainted_vars_in_condition:
            d["tainted_vars_in_condition"] = self.tainted_vars_in_condition
        return d


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _strip_import_prefix(name: str) -> str:
    from .asm_patterns import strip_import_prefix
    return strip_import_prefix(name)


def _find_api_call_in_condition(condition: str) -> Optional[str]:
    """Return the first function-call name found inside *condition*."""
    m = re.search(r"\b([a-zA-Z_]\w*)\s*\(", condition)
    if m:
        name = m.group(1)
        if name.lower() not in ("if", "while", "for", "sizeof"):
            return name
    return None


def _is_auth_check(api: str) -> bool:
    clean = _strip_import_prefix(api)
    for prefix in AUTH_CHECK_APIS:
        if clean.startswith(prefix):
            return True
    return False


def _is_validation_api(api: str) -> bool:
    clean = _strip_import_prefix(api)
    for prefix in VALIDATION_API_PREFIXES:
        if clean.startswith(prefix):
            return True
    return False


def _is_error_check(api: str) -> bool:
    clean = _strip_import_prefix(api)
    for macro in ERROR_CHECK_MACROS:
        if clean.startswith(macro):
            return True
    return False


def _has_null_pattern(condition: str) -> bool:
    return _NULL_CMP_RE.search(condition) is not None


def _has_bounds_pattern(condition: str) -> bool:
    return _BOUNDS_CMP_RE.search(condition) is not None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def classify_guard(condition: str, tainted_vars: set[str]) -> Guard:
    """Classify a single condition string and determine attacker influence.

    *tainted_vars* is a set of variable names (e.g. ``{"a1", "v3"}``)
    considered attacker-controlled.
    """
    api = _find_api_call_in_condition(condition)

    tainted_hits = [v for v in tainted_vars if re.search(rf"\b{re.escape(v)}\b", condition)]
    controllable = len(tainted_hits) > 0

    if controllable:
        bypass = "easy" if len(tainted_hits) == len(tainted_vars) or not api else "medium"
    elif tainted_vars:
        bypass = "hard"
    else:
        bypass = "unknown"

    guard_type = "comparison"
    if api:
        if _is_auth_check(api):
            guard_type = "auth_check"
        elif _is_error_check(api):
            guard_type = "error_check"
        elif _is_validation_api(api):
            guard_type = "validation"
        else:
            guard_type = "function_check"
    elif _has_null_pattern(condition):
        guard_type = "null_check"
    elif _has_bounds_pattern(condition):
        guard_type = "bounds_check"

    return Guard(
        guard_type=guard_type,
        line_number=0,
        condition_text=condition.strip(),
        attacker_controllable=controllable,
        bypass_difficulty=bypass,
        api_in_condition=api,
        tainted_vars_in_condition=tainted_hits,
    )


def find_guards_between(
    code: str,
    source_line: int,
    sink_line: int,
    tainted_vars: set[str],
) -> list[Guard]:
    """Find conditional guards between *source_line* and *sink_line*.

    Scans lines in the half-open range ``[source_line, sink_line)`` for
    ``if (...)`` and ``while (...)`` constructs.  Each condition is
    classified via :func:`classify_guard`.
    """
    lines = code.splitlines()
    guards: list[Guard] = []

    lo = max(source_line - 1, 0)
    hi = min(sink_line - 1, len(lines))

    for idx in range(lo, hi):
        line = lines[idx]
        stripped = line.strip()
        for m in _IF_RE.finditer(stripped):
            paren_pos = m.end() - 1
            cond = extract_balanced_parens(stripped, paren_pos)
            if cond is None:
                continue
            guard = classify_guard(cond, tainted_vars)
            guard.line_number = idx + 1
            guards.append(guard)

    return guards


__all__ = [
    "Guard",
    "classify_guard",
    "find_guards_between",
]
