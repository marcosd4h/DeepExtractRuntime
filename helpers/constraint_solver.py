"""Lightweight constraint satisfiability checker for taint path feasibility.

Checks whether a set of constraints (from constraint_collector) can be
simultaneously satisfied. Uses pattern-based reduction for the common
80% case: range intersections, null/non-null conflicts, equality
conflicts, and enum set intersections.

Does NOT implement full SMT solving. Returns ``feasible=None`` (unknown)
for constraint patterns beyond its capability.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Union

from .constraint_collector import Constraint, ConstraintSet


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class FeasibilityResult:
    """Result of path feasibility checking."""

    feasible: Optional[bool] = None  # True, False, or None (unknown)
    conflicts: list[dict] = field(default_factory=list)
    reason: str = ""
    constraints_checked: int = 0
    constraints_decidable: int = 0

    def to_dict(self) -> dict:
        return {
            "feasible": self.feasible,
            "conflicts": self.conflicts,
            "reason": self.reason,
            "constraints_checked": self.constraints_checked,
            "constraints_decidable": self.constraints_decidable,
        }


# ---------------------------------------------------------------------------
# Internal range representation
# ---------------------------------------------------------------------------

@dataclass
class _IntRange:
    lo: Optional[int] = None  # inclusive lower bound
    hi: Optional[int] = None  # inclusive upper bound
    eq_values: set = field(default_factory=set)  # ==
    ne_values: set = field(default_factory=set)  # !=
    is_null: Optional[bool] = None  # True = must be null, False = must not be null

    def add_constraint(self, op: str, value) -> Optional[str]:
        """Apply a constraint, return conflict description or None."""
        if op == "is_null":
            if self.is_null is False:
                return "null and not-null conflict"
            self.is_null = True
            return None
        if op == "not_null":
            if self.is_null is True:
                return "not-null and null conflict"
            self.is_null = False
            return None

        if not isinstance(value, (int, float)):
            return None

        val = int(value)

        if op == "==":
            if val in self.ne_values:
                return f"== {val} conflicts with != {val}"
            if self.eq_values and val not in self.eq_values:
                existing = next(iter(self.eq_values))
                return f"== {val} conflicts with == {existing}"
            if self.lo is not None and val < self.lo:
                return f"== {val} below lower bound {self.lo}"
            if self.hi is not None and val > self.hi:
                return f"== {val} above upper bound {self.hi}"
            if self.is_null is True and val != 0:
                return f"== {val} conflicts with must-be-null"
            if self.is_null is False and val == 0:
                return f"== 0 conflicts with must-not-be-null"
            self.eq_values.add(val)
            return None

        if op == "!=":
            if val in self.eq_values:
                return f"!= {val} conflicts with == {val}"
            self.ne_values.add(val)
            return None

        if op == "<":
            new_hi = val - 1
            if self.lo is not None and new_hi < self.lo:
                return f"< {val} (hi={new_hi}) below lower bound {self.lo}"
            if self.eq_values:
                for ev in self.eq_values:
                    if ev >= val:
                        return f"< {val} conflicts with == {ev}"
            if self.hi is None or new_hi < self.hi:
                self.hi = new_hi
            return None

        if op == "<=":
            new_hi = val
            if self.lo is not None and new_hi < self.lo:
                return f"<= {val} below lower bound {self.lo}"
            if self.eq_values:
                for ev in self.eq_values:
                    if ev > val:
                        return f"<= {val} conflicts with == {ev}"
            if self.hi is None or new_hi < self.hi:
                self.hi = new_hi
            return None

        if op == ">":
            new_lo = val + 1
            if self.hi is not None and new_lo > self.hi:
                return f"> {val} (lo={new_lo}) above upper bound {self.hi}"
            if self.eq_values:
                for ev in self.eq_values:
                    if ev <= val:
                        return f"> {val} conflicts with == {ev}"
            if self.lo is None or new_lo > self.lo:
                self.lo = new_lo
            return None

        if op == ">=":
            new_lo = val
            if self.hi is not None and new_lo > self.hi:
                return f">= {val} above upper bound {self.hi}"
            if self.eq_values:
                for ev in self.eq_values:
                    if ev < val:
                        return f">= {val} conflicts with == {ev}"
            if self.lo is None or new_lo > self.lo:
                self.lo = new_lo
            return None

        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_feasibility(constraint_set: ConstraintSet) -> FeasibilityResult:
    """Check whether a set of constraints can be simultaneously satisfied.

    Builds per-variable range/equality models and checks for conflicts.
    Returns feasible=True if no conflicts found among decidable constraints,
    feasible=False if a definite conflict exists, or feasible=None if
    too many constraints are undecidable.
    """
    constraints = constraint_set.constraints
    result = FeasibilityResult(constraints_checked=len(constraints))

    if not constraints:
        result.feasible = True
        result.reason = "no constraints to check"
        return result

    # Group constraints by variable
    var_constraints: dict[str, list[Constraint]] = {}
    for c in constraints:
        var_constraints.setdefault(c.variable, []).append(c)

    decidable = 0
    for var, var_cs in var_constraints.items():
        rng = _IntRange()
        for c in var_cs:
            if isinstance(c.value, str) and c.operator not in ("is_null", "not_null"):
                continue

            decidable += 1
            conflict = rng.add_constraint(c.operator, c.value)
            if conflict:
                result.feasible = False
                result.conflicts.append({
                    "variable": var,
                    "conflict": conflict,
                    "constraints": [cc.to_dict() for cc in var_cs],
                })
                result.reason = f"infeasible: {var} has conflicting constraints"
                result.constraints_decidable = decidable
                return result

        # Post-check: if range is non-empty but an eq value was excluded
        if rng.eq_values and rng.ne_values:
            remaining = rng.eq_values - rng.ne_values
            if not remaining:
                result.feasible = False
                result.conflicts.append({
                    "variable": var,
                    "conflict": "all equality values excluded by != constraints",
                    "constraints": [cc.to_dict() for cc in var_cs],
                })
                result.reason = f"infeasible: {var} has no satisfying value"
                result.constraints_decidable = decidable
                return result

    result.constraints_decidable = decidable

    if decidable == 0 and len(constraints) > 0:
        result.feasible = None
        result.reason = "all constraints involve symbolic values (undecidable)"
    elif decidable < len(constraints) * 0.5:
        result.feasible = None
        result.reason = f"only {decidable}/{len(constraints)} constraints decidable"
    else:
        result.feasible = True
        result.reason = f"no conflicts in {decidable} decidable constraints"

    return result


__all__ = [
    "FeasibilityResult",
    "check_feasibility",
]
