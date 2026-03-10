"""Collect path constraints from guard conditions on taint paths.

Given a list of guards (from guard_classifier.find_guards_between), extracts
variable constraints (comparisons, null checks, range checks, flag tests)
that must all hold simultaneously for the taint path to be feasible.

Works with IDA Hex-Rays decompiled condition strings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional, Union


# ---------------------------------------------------------------------------
# Constraint types
# ---------------------------------------------------------------------------

@dataclass
class Constraint:
    """A single constraint extracted from a guard condition."""

    variable: str
    operator: str  # ==, !=, <, <=, >, >=, is_null, not_null, in_set, not_in_set
    value: Union[int, float, str, list, None]
    source_line: int = 0
    raw_condition: str = ""
    negated: bool = False

    def to_dict(self) -> dict:
        return {
            "variable": self.variable,
            "operator": self.operator,
            "value": self.value,
            "source_line": self.source_line,
            "negated": self.negated,
        }


@dataclass
class ConstraintSet:
    """A set of constraints that must hold simultaneously on a path."""

    constraints: list[Constraint] = field(default_factory=list)
    disjuncts: list["ConstraintSet"] = field(default_factory=list)
    source_guards: int = 0
    unparsed_guards: int = 0

    def add(self, c: Constraint) -> None:
        self.constraints.append(c)

    def to_dict(self) -> dict:
        return {
            "constraints": [c.to_dict() for c in self.constraints],
            "disjuncts": [d.to_dict() for d in self.disjuncts],
            "total_constraints": len(self.constraints),
            "source_guards": self.source_guards,
            "unparsed_guards": self.unparsed_guards,
        }


# ---------------------------------------------------------------------------
# Parsing patterns
# ---------------------------------------------------------------------------

_NULL_VALS = frozenset({"0", "NULL", "nullptr", "0LL", "0i64", "0u"})

_CMP_RE = re.compile(
    r"(\b[a-zA-Z_]\w*\b)\s*([!=<>]=?)\s*(-?\d+\w*|0x[0-9a-fA-F]+|\b[a-zA-Z_]\w*\b)"
)

_NULL_CHECK_RE = re.compile(
    r"(\b[a-zA-Z_]\w*\b)\s*([!=]=)\s*(?:0|NULL|nullptr|0LL|0i64)\b"
    r"|(?:0|NULL|nullptr|0LL|0i64)\b\s*([!=]=)\s*(\b[a-zA-Z_]\w*\b)"
    r"|!\s*(\b[a-zA-Z_]\w*\b)"
)

_NEGATION_RE = re.compile(r"^\s*!\s*\((.+)\)\s*$")
_LOGICAL_AND_RE = re.compile(r"\s*&&\s*")
_LOGICAL_OR_RE = re.compile(r"\s*\|\|\s*")


def _split_on_or(condition: str) -> list[str]:
    """Split a condition string on top-level ``||``, respecting parentheses.

    Only splits on ``||`` operators that are not nested inside parentheses.
    Returns a list of stripped branch strings.  If there is no top-level
    ``||``, returns a single-element list containing the original condition.
    """
    parts: list[str] = []
    depth = 0
    start = 0
    i = 0
    while i < len(condition):
        ch = condition[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "|" and i + 1 < len(condition) and condition[i + 1] == "|" and depth == 0:
            parts.append(condition[start:i].strip())
            i += 2
            start = i
            continue
        i += 1
    parts.append(condition[start:].strip())
    return parts


def _parse_int(s: str) -> Optional[int]:
    """Parse an integer literal (decimal, hex, with optional suffix)."""
    s = s.strip().rstrip("uUlL")
    try:
        if s.startswith("0x") or s.startswith("0X"):
            return int(s, 16)
        return int(s)
    except (ValueError, OverflowError):
        return None


def _extract_null_constraints(condition: str, line: int) -> list[Constraint]:
    """Extract null/non-null constraints from a condition."""
    constraints: list[Constraint] = []
    for m in _NULL_CHECK_RE.finditer(condition):
        if m.group(1):
            var = m.group(1)
            op = m.group(2)
            is_eq = op == "=="
            constraints.append(Constraint(
                variable=var,
                operator="is_null" if is_eq else "not_null",
                value=None,
                source_line=line,
                raw_condition=condition,
            ))
        elif m.group(4):
            var = m.group(4)
            op = m.group(3)
            is_eq = op == "=="
            constraints.append(Constraint(
                variable=var,
                operator="is_null" if is_eq else "not_null",
                value=None,
                source_line=line,
                raw_condition=condition,
            ))
        elif m.group(5):
            var = m.group(5)
            constraints.append(Constraint(
                variable=var,
                operator="is_null",
                value=None,
                source_line=line,
                raw_condition=condition,
            ))
    return constraints


def _extract_comparison_constraints(condition: str, line: int) -> list[Constraint]:
    """Extract comparison constraints from a condition."""
    constraints: list[Constraint] = []
    for m in _CMP_RE.finditer(condition):
        var = m.group(1)
        op = m.group(2)
        rhs = m.group(3)

        if rhs in _NULL_VALS and op in ("==", "!="):
            continue

        int_val = _parse_int(rhs)
        if int_val is not None:
            constraints.append(Constraint(
                variable=var,
                operator=op,
                value=int_val,
                source_line=line,
                raw_condition=condition,
            ))
        else:
            constraints.append(Constraint(
                variable=var,
                operator=op,
                value=rhs,
                source_line=line,
                raw_condition=condition,
            ))
    return constraints


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def collect_constraints(
    guards: list[dict],
    code: str = "",
) -> ConstraintSet:
    """Collect constraints from a list of guard dicts (from guard_classifier).

    Each guard dict should have at minimum:
    - ``condition``: the condition text
    - ``line_number``: the source line

    Returns a ConstraintSet with all extracted constraints.
    """
    cs = ConstraintSet()
    cs.source_guards = len(guards)

    for guard in guards:
        condition = guard.get("condition", "")
        line = guard.get("line_number", 0)
        if not condition:
            cs.unparsed_guards += 1
            continue

        if _LOGICAL_OR_RE.search(condition):
            branches = _split_on_or(condition)
            branch_sets: list[ConstraintSet] = []
            for branch in branches:
                branch_cs = ConstraintSet()
                parsed_branch = False

                null_cs = _extract_null_constraints(branch, line)
                if null_cs:
                    parsed_branch = True
                    for c in null_cs:
                        branch_cs.add(c)

                cmp_cs = _extract_comparison_constraints(branch, line)
                if cmp_cs:
                    parsed_branch = True
                    for c in cmp_cs:
                        branch_cs.add(c)

                if parsed_branch:
                    branch_sets.append(branch_cs)

            if branch_sets:
                disjunct_cs = ConstraintSet(disjuncts=branch_sets)
                cs.disjuncts.append(disjunct_cs)
            else:
                cs.unparsed_guards += 1
            continue

        parsed_any = False

        null_cs = _extract_null_constraints(condition, line)
        if null_cs:
            parsed_any = True
            for c in null_cs:
                cs.add(c)

        cmp_cs = _extract_comparison_constraints(condition, line)
        if cmp_cs:
            parsed_any = True
            for c in cmp_cs:
                cs.add(c)

        if not parsed_any:
            cs.unparsed_guards += 1

    return cs


__all__ = [
    "Constraint",
    "ConstraintSet",
    "collect_constraints",
]
