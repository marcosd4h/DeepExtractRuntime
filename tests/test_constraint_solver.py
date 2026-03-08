"""Tests for helpers.constraint_collector and helpers.constraint_solver."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from helpers.constraint_collector import Constraint, ConstraintSet, collect_constraints
from helpers.constraint_solver import FeasibilityResult, check_feasibility


# ---------------------------------------------------------------------------
# Constraint collection tests
# ---------------------------------------------------------------------------

class TestConstraintCollection:
    """Test extraction of constraints from guard conditions."""

    def test_null_check_equals(self):
        guards = [{"condition": "a1 == NULL", "line_number": 5}]
        cs = collect_constraints(guards)
        assert len(cs.constraints) == 1
        assert cs.constraints[0].operator == "is_null"
        assert cs.constraints[0].variable == "a1"

    def test_null_check_not_equals(self):
        guards = [{"condition": "a1 != 0", "line_number": 5}]
        cs = collect_constraints(guards)
        assert any(c.operator == "not_null" for c in cs.constraints)

    def test_negation_null(self):
        guards = [{"condition": "!a1", "line_number": 5}]
        cs = collect_constraints(guards)
        assert any(c.operator == "is_null" for c in cs.constraints)

    def test_comparison_less_than(self):
        guards = [{"condition": "v5 < 100", "line_number": 10}]
        cs = collect_constraints(guards)
        assert any(c.operator == "<" and c.value == 100 for c in cs.constraints)

    def test_comparison_greater_equal(self):
        guards = [{"condition": "v5 >= 1", "line_number": 10}]
        cs = collect_constraints(guards)
        assert any(c.operator == ">=" and c.value == 1 for c in cs.constraints)

    def test_equality_integer(self):
        guards = [{"condition": "v3 == 42", "line_number": 8}]
        cs = collect_constraints(guards)
        assert any(c.operator == "==" and c.value == 42 for c in cs.constraints)

    def test_hex_value(self):
        guards = [{"condition": "v3 == 0x80070057", "line_number": 8}]
        cs = collect_constraints(guards)
        assert any(c.value == 0x80070057 for c in cs.constraints)

    def test_multiple_guards(self):
        guards = [
            {"condition": "a1 != 0", "line_number": 5},
            {"condition": "v5 < 100", "line_number": 10},
            {"condition": "v5 > 0", "line_number": 12},
        ]
        cs = collect_constraints(guards)
        assert len(cs.constraints) >= 3
        assert cs.source_guards == 3

    def test_empty_guards(self):
        cs = collect_constraints([])
        assert len(cs.constraints) == 0
        assert cs.source_guards == 0

    def test_unparseable_condition(self):
        guards = [{"condition": "SomeComplexExpression()", "line_number": 5}]
        cs = collect_constraints(guards)
        assert cs.unparsed_guards == 1

    def test_symbolic_comparison(self):
        guards = [{"condition": "v5 < v6", "line_number": 10}]
        cs = collect_constraints(guards)
        assert any(c.variable == "v5" and c.value == "v6" for c in cs.constraints)


# ---------------------------------------------------------------------------
# Feasibility checking tests
# ---------------------------------------------------------------------------

class TestFeasibility:
    """Test constraint satisfiability checking."""

    def test_no_constraints_feasible(self):
        cs = ConstraintSet()
        result = check_feasibility(cs)
        assert result.feasible is True

    def test_simple_range_feasible(self):
        cs = ConstraintSet(constraints=[
            Constraint(variable="v5", operator=">", value=0, source_line=5),
            Constraint(variable="v5", operator="<", value=100, source_line=10),
        ])
        result = check_feasibility(cs)
        assert result.feasible is True

    def test_disjoint_range_infeasible(self):
        cs = ConstraintSet(constraints=[
            Constraint(variable="v5", operator=">", value=100, source_line=5),
            Constraint(variable="v5", operator="<", value=50, source_line=10),
        ])
        result = check_feasibility(cs)
        assert result.feasible is False
        assert len(result.conflicts) > 0

    def test_null_conflict(self):
        cs = ConstraintSet(constraints=[
            Constraint(variable="a1", operator="is_null", value=None, source_line=5),
            Constraint(variable="a1", operator="not_null", value=None, source_line=10),
        ])
        result = check_feasibility(cs)
        assert result.feasible is False

    def test_equality_conflict(self):
        cs = ConstraintSet(constraints=[
            Constraint(variable="v3", operator="==", value=1, source_line=5),
            Constraint(variable="v3", operator="==", value=2, source_line=10),
        ])
        result = check_feasibility(cs)
        assert result.feasible is False

    def test_eq_ne_conflict(self):
        cs = ConstraintSet(constraints=[
            Constraint(variable="v3", operator="==", value=5, source_line=5),
            Constraint(variable="v3", operator="!=", value=5, source_line=10),
        ])
        result = check_feasibility(cs)
        assert result.feasible is False

    def test_eq_out_of_range(self):
        cs = ConstraintSet(constraints=[
            Constraint(variable="v5", operator=">=", value=10, source_line=5),
            Constraint(variable="v5", operator="==", value=3, source_line=10),
        ])
        result = check_feasibility(cs)
        assert result.feasible is False

    def test_null_eq_nonzero_conflict(self):
        cs = ConstraintSet(constraints=[
            Constraint(variable="a1", operator="is_null", value=None, source_line=5),
            Constraint(variable="a1", operator="==", value=42, source_line=10),
        ])
        result = check_feasibility(cs)
        assert result.feasible is False

    def test_not_null_eq_zero_conflict(self):
        cs = ConstraintSet(constraints=[
            Constraint(variable="a1", operator="not_null", value=None, source_line=5),
            Constraint(variable="a1", operator="==", value=0, source_line=10),
        ])
        result = check_feasibility(cs)
        assert result.feasible is False

    def test_independent_variables_feasible(self):
        cs = ConstraintSet(constraints=[
            Constraint(variable="v5", operator=">", value=100, source_line=5),
            Constraint(variable="v6", operator="<", value=50, source_line=10),
        ])
        result = check_feasibility(cs)
        assert result.feasible is True

    def test_symbolic_only_unknown(self):
        cs = ConstraintSet(constraints=[
            Constraint(variable="v5", operator="<", value="v6", source_line=5),
            Constraint(variable="v5", operator=">", value="v7", source_line=10),
        ])
        result = check_feasibility(cs)
        assert result.feasible is None

    def test_mixed_decidable_undecidable(self):
        cs = ConstraintSet(constraints=[
            Constraint(variable="v5", operator=">", value=10, source_line=5),
            Constraint(variable="v5", operator="<", value=5, source_line=10),
            Constraint(variable="v6", operator="<", value="v7", source_line=15),
        ])
        result = check_feasibility(cs)
        assert result.feasible is False

    def test_tight_range_feasible(self):
        cs = ConstraintSet(constraints=[
            Constraint(variable="v5", operator=">=", value=5, source_line=5),
            Constraint(variable="v5", operator="<=", value=5, source_line=10),
        ])
        result = check_feasibility(cs)
        assert result.feasible is True

    def test_ne_excludes_all_eq_values(self):
        cs = ConstraintSet(constraints=[
            Constraint(variable="v5", operator="==", value=3, source_line=5),
            Constraint(variable="v5", operator="!=", value=3, source_line=10),
        ])
        result = check_feasibility(cs)
        assert result.feasible is False


# ---------------------------------------------------------------------------
# Integration: collect + check pipeline
# ---------------------------------------------------------------------------

class TestCollectAndCheck:
    """Test the full pipeline: collect constraints from guards then check."""

    def test_contradictory_guards(self):
        guards = [
            {"condition": "v5 > 100", "line_number": 5},
            {"condition": "v5 < 50", "line_number": 10},
        ]
        cs = collect_constraints(guards)
        result = check_feasibility(cs)
        assert result.feasible is False

    def test_consistent_guards(self):
        guards = [
            {"condition": "a1 != 0", "line_number": 5},
            {"condition": "v5 > 0", "line_number": 10},
            {"condition": "v5 < 1000", "line_number": 15},
        ]
        cs = collect_constraints(guards)
        result = check_feasibility(cs)
        assert result.feasible is True

    def test_null_then_deref_infeasible(self):
        guards = [
            {"condition": "a1 == NULL", "line_number": 5},
            {"condition": "a1 != 0", "line_number": 12},
        ]
        cs = collect_constraints(guards)
        result = check_feasibility(cs)
        assert result.feasible is False


# ---------------------------------------------------------------------------
# Logical OR handling tests
# ---------------------------------------------------------------------------

class TestLogicalOrHandling:
    """Test that || conditions are skipped (not falsely marked infeasible)."""

    def test_or_condition_skipped(self):
        """v5 == 1 || v5 == 2 should NOT produce conflicting constraints."""
        guards = [{"condition": "v5 == 1 || v5 == 2", "line_number": 5}]
        cs = collect_constraints(guards)
        assert cs.unparsed_guards == 1
        assert len(cs.constraints) == 0

    def test_or_condition_not_infeasible(self):
        """A guard with || should not cause the path to be marked infeasible."""
        guards = [
            {"condition": "v5 == 1 || v5 == 2", "line_number": 5},
            {"condition": "v5 > 0", "line_number": 10},
        ]
        cs = collect_constraints(guards)
        result = check_feasibility(cs)
        assert result.feasible is not False

    def test_and_condition_still_extracted(self):
        """&& conditions should still produce constraints normally."""
        guards = [{"condition": "v5 > 0 && v5 < 100", "line_number": 5}]
        cs = collect_constraints(guards)
        assert len(cs.constraints) >= 2
        assert cs.unparsed_guards == 0

    def test_mixed_and_or_guard_skips_or(self):
        """If a condition has ||, skip the whole guard even if && is also present."""
        guards = [{"condition": "v5 > 0 && (v6 == 1 || v6 == 2)", "line_number": 5}]
        cs = collect_constraints(guards)
        assert cs.unparsed_guards == 1

    def test_pure_conjunctive_guards_feasible(self):
        guards = [
            {"condition": "v5 > 0", "line_number": 5},
            {"condition": "v5 < 100", "line_number": 10},
        ]
        cs = collect_constraints(guards)
        result = check_feasibility(cs)
        assert result.feasible is True
        assert len(cs.constraints) >= 2
