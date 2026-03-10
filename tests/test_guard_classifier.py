"""Tests for helpers.guard_classifier -- guard role and path relevance."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from helpers.guard_classifier import (
    Guard,
    classify_guard,
    find_guards_between,
)


# ---------------------------------------------------------------------------
# Guard role classification
# ---------------------------------------------------------------------------

class TestGuardRole:
    """Test protects/enables/sibling classification."""

    def test_early_exit_role_protects(self):
        code = """\
void func(__int64 a1) {
  if ( !a1 )
  {
    return;
  }
  dangerous_op(a1);
}
"""
        guards = find_guards_between(code, 1, 6, {"a1"}, path_aware=True)
        assert len(guards) >= 1
        assert guards[0].role == "protects"
        assert guards[0].on_path_to_sink is True

    def test_enabling_role(self):
        code = """\
void func(__int64 a1) {
  if ( is_admin() )
  {
    dangerous_op(a1);
  }
}
"""
        guards = find_guards_between(code, 1, 4, {"a1"}, path_aware=True)
        assert len(guards) >= 1
        assert guards[0].role == "enables"

    def test_sibling_branch_not_on_path(self):
        code = """\
void func(__int64 a1) {
  if ( a1 > 100 )
  {
    log_something();
  }
  dangerous_op(a1);
}
"""
        guards = find_guards_between(code, 1, 6, {"a1"}, path_aware=True)
        assert len(guards) == 0 or all(g.role != "sibling" for g in guards)


# ---------------------------------------------------------------------------
# Path relevance filtering
# ---------------------------------------------------------------------------

class TestPathRelevance:
    """Test on_path_to_sink filtering."""

    def test_guard_before_sink_on_path(self):
        code = """\
void func(__int64 a1) {
  if ( a1 == NULL )
  {
    return;
  }
  memcpy(buf, a1, 100);
}
"""
        guards = find_guards_between(code, 1, 6, {"a1"}, path_aware=True)
        assert len(guards) >= 1
        assert all(g.on_path_to_sink for g in guards)

    def test_path_aware_disabled_returns_all(self):
        code = """\
void func(__int64 a1) {
  if ( a1 > 100 )
  {
    log_something();
  }
  dangerous_op(a1);
}
"""
        guards_aware = find_guards_between(code, 1, 6, {"a1"}, path_aware=True)
        guards_all = find_guards_between(code, 1, 6, {"a1"}, path_aware=False)
        assert len(guards_all) >= len(guards_aware)

    def test_classic_null_guard_protects(self):
        code = """\
void func(void *a1) {
  if ( !a1 )
  {
    return 0;
  }
  memcpy(dest, a1, size);
}
"""
        guards = find_guards_between(code, 1, 6, {"a1"}, path_aware=True)
        assert len(guards) >= 1
        g = guards[0]
        assert g.role == "protects"
        assert g.guard_type == "null_check"


# ---------------------------------------------------------------------------
# Basic classify_guard tests (backward compat)
# ---------------------------------------------------------------------------

class TestClassifyGuard:
    """Ensure classify_guard still works correctly."""

    def test_auth_check(self):
        g = classify_guard("AccessCheck(hToken)", {"a1"})
        assert g.guard_type == "auth_check"

    def test_null_check(self):
        g = classify_guard("a1 != NULL", {"a1"})
        assert g.guard_type == "null_check"
        assert g.attacker_controllable is True

    def test_bounds_check(self):
        g = classify_guard("v5 < 100", {"v5"})
        assert g.guard_type == "bounds_check"

    def test_error_check(self):
        g = classify_guard("FAILED(hr)", set())
        assert g.guard_type == "error_check"

    def test_new_fields_present(self):
        g = classify_guard("a1 == NULL", {"a1"})
        d = g.to_dict()
        assert "role" in d
        assert "on_path_to_sink" in d
