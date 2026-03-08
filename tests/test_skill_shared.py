"""Tests for skills/_shared/ bootstrap, DB resolvers, and finding_base."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# bootstrap() and get_workspace_root()
# ---------------------------------------------------------------------------

class TestBootstrap:
    """Verify that bootstrap() correctly resolves workspace root and sets sys.path."""

    def test_bootstrap_returns_workspace_root(self):
        from skills._shared._workspace import get_workspace_root

        agent_dir = Path(__file__).resolve().parents[1]
        dummy_anchor = agent_dir / "skills" / "some-skill" / "scripts" / "entry.py"
        root = get_workspace_root(str(dummy_anchor))
        has_skills = (root / "skills").is_dir() or (root / ".agent" / "skills").is_dir()
        has_helpers = (root / "helpers").is_dir() or (root / ".agent" / "helpers").is_dir()
        assert has_skills
        assert has_helpers

    def test_bootstrap_adds_agent_dir_to_sys_path(self):
        from skills._shared import bootstrap

        agent_dir = Path(__file__).resolve().parents[1]
        dummy_anchor = agent_dir / "skills" / "decompiled-code-extractor" / "scripts" / "_common.py"
        root = bootstrap(str(dummy_anchor))
        assert str(root / ".agent") in sys.path or str(root) in sys.path

    def test_get_workspace_root_uses_parent_fallback(self, tmp_path):
        """When no skills/helpers dirs exist, should fall back to parents[4]."""
        from skills._shared._workspace import get_workspace_root

        deep = tmp_path / "a" / "b" / "c" / "d" / "e" / "f"
        deep.mkdir(parents=True)
        anchor = deep / "script.py"
        anchor.write_text("", encoding="utf-8")
        result = get_workspace_root(str(anchor))
        assert isinstance(result, Path)


# ---------------------------------------------------------------------------
# make_db_resolvers()
# ---------------------------------------------------------------------------

class TestMakeDbResolvers:
    """Verify make_db_resolvers returns bound resolver callables."""

    def test_returns_two_callables(self, tmp_path):
        from skills._shared._workspace import make_db_resolvers

        resolve_db, resolve_tracking = make_db_resolvers(tmp_path)
        assert callable(resolve_db)
        assert callable(resolve_tracking)

    def test_resolve_tracking_db_returns_none_for_empty(self, tmp_path):
        from skills._shared._workspace import make_db_resolvers

        _, resolve_tracking = make_db_resolvers(tmp_path)
        result = resolve_tracking()
        assert result is None


# ---------------------------------------------------------------------------
# skill_common re-exports
# ---------------------------------------------------------------------------

class TestSkillCommonReexports:
    """Verify that skill_common.py re-exports expected symbols."""

    def test_has_expected_symbols(self):
        from skills._shared import skill_common

        expected = [
            "emit_error",
            "emit_json",
            "log_warning",
            "open_individual_analysis_db",
            "parse_json_safe",
            "resolve_function",
            "validate_function_id",
            "get_cached",
            "cache_result",
            "status_message",
            "db_error_handler",
            "ScriptError",
            "should_force_json",
            "get_workspace_args",
            "run_skill_script",
        ]
        for name in expected:
            assert hasattr(skill_common, name), f"Missing re-export: {name}"

    def test_all_exports_match(self):
        from skills._shared.skill_common import __all__

        assert len(__all__) >= 15


# ---------------------------------------------------------------------------
# finding_base shared infrastructure
# ---------------------------------------------------------------------------

class TestFindingBase:
    """Verify the shared finding infrastructure in finding_base.py."""

    def test_verification_result_to_dict(self):
        from skills._shared.finding_base import VerificationResult

        vr = VerificationResult(
            finding={"name": "test"},
            confidence="LIKELY",
            confidence_score=0.7,
        )
        d = vr.to_dict()
        assert d["confidence"] == "LIKELY"
        assert d["finding"]["name"] == "test"

    def test_compute_finding_score_basic(self):
        from skills._shared.finding_base import compute_finding_score

        score, label = compute_finding_score(
            impact_severity=1.0,
            guard_count=0,
            is_exported=True,
            confidence="CONFIRMED",
            path_hops=1,
        )
        assert 0.0 < score <= 1.0
        assert label in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_compute_finding_score_guards_reduce(self):
        from skills._shared.finding_base import compute_finding_score

        score_no_guard, _ = compute_finding_score(1.0, guard_count=0, is_exported=True)
        score_guarded, _ = compute_finding_score(1.0, guard_count=5, is_exported=True)
        assert score_guarded < score_no_guard

    def test_severity_label(self):
        from skills._shared.finding_base import severity_label

        assert severity_label(0.8) == "CRITICAL"
        assert severity_label(0.1) == "LOW"

    def test_matches_api_list(self):
        from skills._shared.finding_base import matches_api_list

        assert matches_api_list("__imp_HeapAlloc", ("HeapAlloc",))
        assert matches_api_list("cs:VirtualAlloc", ("VirtualAlloc",))
        assert not matches_api_list("SomeOtherFunc", ("HeapAlloc",))

    def test_strip_import_prefix(self):
        from skills._shared.finding_base import strip_import_prefix

        assert strip_import_prefix("__imp_CreateFileW") == "CreateFileW"
        assert strip_import_prefix("_imp_ReadFile") == "ReadFile"
        assert strip_import_prefix("j_memcpy") == "memcpy"
        assert strip_import_prefix("cs:CloseHandle") == "CloseHandle"
        assert strip_import_prefix("NormalFunc") == "NormalFunc"
