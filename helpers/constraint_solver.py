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
# Symbolic equivalence via union-find
# ---------------------------------------------------------------------------

class _UnionFind:
    """Weighted quick-union with path compression."""

    def __init__(self) -> None:
        self.parent: dict[str, str] = {}
        self.rank: dict[str, int] = {}

    def _ensure(self, x: str) -> None:
        if x not in self.parent:
            self.parent[x] = x
            self.rank[x] = 0

    def find(self, x: str) -> str:
        self._ensure(x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self.rank[ra] < self.rank[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        if self.rank[ra] == self.rank[rb]:
            self.rank[ra] += 1


def _build_equiv_classes(
    constraints: list[Constraint],
) -> list[Constraint]:
    """Resolve transitive equalities between variables.

    For chains like ``v5 == v6`` and ``v6 == 42``, produces a new
    constraint ``v5 == 42`` so the solver can reason about the concrete
    value.  Returns the original list augmented with any derived
    constraints.
    """
    uf = _UnionFind()
    var_to_const: dict[str, int] = {}

    for c in constraints:
        if c.operator != "==":
            continue
        if isinstance(c.value, str):
            uf.union(c.variable, c.value)
        elif isinstance(c.value, (int, float)):
            uf._ensure(c.variable)
            root = uf.find(c.variable)
            var_to_const[root] = int(c.value)

    # Re-resolve roots after all unions are done, since earlier roots
    # may have been merged by later union operations.
    resolved: dict[str, int] = {}
    for old_root, val in var_to_const.items():
        new_root = uf.find(old_root)
        resolved[new_root] = val

    vars_with_concrete: set[str] = {
        c.variable
        for c in constraints
        if c.operator == "==" and isinstance(c.value, (int, float))
    }

    derived: list[Constraint] = []
    for node in list(uf.parent):
        root = uf.find(node)
        if root in resolved and node not in vars_with_concrete:
            val = resolved[root]
            derived.append(Constraint(
                variable=node,
                operator="==",
                value=val,
                source_line=0,
                raw_condition=f"(derived: {node} == {val})",
            ))

    return list(constraints) + derived


# ---------------------------------------------------------------------------
# Disjunct checking helper
# ---------------------------------------------------------------------------

def _check_conjunctive(constraints: list[Constraint]) -> FeasibilityResult:
    """Check a flat list of conjunctive constraints (no disjuncts)."""
    result = FeasibilityResult(constraints_checked=len(constraints))
    if not constraints:
        result.feasible = True
        result.reason = "no constraints to check"
        return result

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
    elif decidable < len(constraints) * 0.25:
        result.feasible = None
        result.reason = f"only {decidable}/{len(constraints)} constraints decidable"
    else:
        result.feasible = True
        result.reason = f"no conflicts in {decidable} decidable constraints"
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_feasibility(constraint_set: ConstraintSet) -> FeasibilityResult:
    """Check whether a set of constraints can be simultaneously satisfied.

    Builds per-variable range/equality models and checks for conflicts.
    Handles disjuncts (OR branches) -- feasible if ANY branch is feasible.
    Resolves transitive variable equalities via union-find before checking.

    Returns feasible=True if no conflicts found among decidable constraints,
    feasible=False if a definite conflict exists, or feasible=None if
    too many constraints are undecidable.
    """
    augmented = _build_equiv_classes(constraint_set.constraints)
    result = _check_conjunctive(augmented)

    if result.feasible is False:
        return result

    if constraint_set.disjuncts:
        for disjunct_group in constraint_set.disjuncts:
            if not disjunct_group.disjuncts:
                continue
            any_feasible = False
            all_infeasible = True
            for branch_cs in disjunct_group.disjuncts:
                combined = list(augmented) + list(branch_cs.constraints)
                branch_result = _check_conjunctive(combined)
                if branch_result.feasible is not False:
                    any_feasible = True
                    all_infeasible = False
                    break
                all_infeasible = True

            if all_infeasible and not any_feasible:
                result.feasible = False
                result.reason = "infeasible: all OR branches conflict with path constraints"
                return result

    return result


__all__ = [
    "FeasibilityResult",
    "check_feasibility",
]
