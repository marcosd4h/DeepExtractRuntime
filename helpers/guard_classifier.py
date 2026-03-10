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
    role: str = "unknown"          # "protects" | "enables" | "sibling" | "unknown"
    on_path_to_sink: bool = True   # False for sibling-branch guards

    def to_dict(self) -> dict:
        d: dict = {
            "guard_type": self.guard_type,
            "line_number": self.line_number,
            "condition": self.condition_text,
            "attacker_controllable": self.attacker_controllable,
            "bypass_difficulty": self.bypass_difficulty,
            "role": self.role,
            "on_path_to_sink": self.on_path_to_sink,
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


def _classify_guard_role(
    guard_line: int,
    sink_line: int,
    code_lines: list[str],
) -> tuple[str, bool]:
    """Determine a guard's role relative to the sink.

    Returns ``(role, on_path_to_sink)`` where *role* is one of
    ``"protects"``, ``"enables"``, ``"sibling"``, or ``"unknown"``.

    Heuristics (lightweight, no full CFG):

    * **protects**: The then-branch contains an early exit
      (``return``/``break``/``goto``) and the sink is AFTER the block.
    * **enables**: The sink is inside the then-branch.
    * **sibling**: The guard's then-branch does not contain the sink AND
      does not early-exit -- the sink is in the continuation or else-branch,
      so this guard is in a sibling scope.
    """
    if guard_line < 1 or guard_line > len(code_lines):
        return "unknown", True

    _early_exit_re = re.compile(r"^\s*(?:return\b|break\s*;|goto\s+\w+)")

    depth = 0
    then_start = None
    then_end = None
    then_has_return = False

    for i in range(guard_line - 1, min(guard_line + 200, len(code_lines))):
        stripped = code_lines[i].strip()
        for ch in stripped:
            if ch == "{":
                depth += 1
                if depth == 1 and then_start is None:
                    then_start = i + 1  # 1-based
            elif ch == "}":
                if depth == 1 and then_start is not None and then_end is None:
                    then_end = i + 1
                depth -= 1
        if _early_exit_re.match(stripped) and depth == 1 and then_start is not None:
            then_has_return = True
        if depth <= 0 and then_start is not None:
            break

    if then_start is None or then_end is None:
        return "unknown", True

    sink_in_then = then_start <= sink_line <= then_end

    if then_has_return and not sink_in_then:
        return "protects", True
    if sink_in_then:
        return "enables", True
    if not then_has_return and not sink_in_then:
        return "sibling", False

    return "unknown", True


def find_guards_between(
    code: str,
    source_line: int,
    sink_line: int,
    tainted_vars: set[str],
    *,
    path_aware: bool = True,
) -> list[Guard]:
    """Find conditional guards between *source_line* and *sink_line*.

    Scans lines in the half-open range ``[source_line, sink_line)`` for
    ``if (...)`` and ``while (...)`` constructs.  Each condition is
    classified via :func:`classify_guard`.

    When *path_aware* is ``True`` (default), each guard is annotated with
    a ``role`` (``"protects"``/``"enables"``/``"sibling"``) and
    ``on_path_to_sink``.  Guards with ``on_path_to_sink=False`` are
    excluded from the returned list.
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

            if path_aware:
                role, on_path = _classify_guard_role(
                    idx + 1, sink_line, lines,
                )
                guard.role = role
                guard.on_path_to_sink = on_path
                if not on_path:
                    continue

            guards.append(guard)

    return guards


__all__ = [
    "Guard",
    "classify_guard",
    "find_guards_between",
]
