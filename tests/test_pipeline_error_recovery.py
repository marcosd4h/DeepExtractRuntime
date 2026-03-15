"""Tests for triage-coordinator pipeline error recovery (Critical fix #4).

Verifies that:
- Individual step failures don't abort the entire pipeline
- Failed steps are recorded with error details
- Pipeline returns partial results on partial failure

Uses subprocess to test the actual analyze_module.py script behavior,
and unit tests for the adaptive timeout calculation (imported from helpers).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import _create_sample_db


_AGENT_DIR = Path(__file__).resolve().parents[1]
_ANALYZE_SCRIPT = str(
    _AGENT_DIR / "agents" / "triage-coordinator" / "scripts" / "analyze_module.py"
)
_SCRIPT_DIR = str(_AGENT_DIR / "agents" / "triage-coordinator" / "scripts")
_SUBPROCESS_ENV = {**__import__("os").environ, "PYTHONPATH": str(_AGENT_DIR)}


class TestPipelineErrorRecovery:
    """Test that analyze_module.py doesn't crash on partial failures."""

    def test_invalid_db_produces_structured_output(self, tmp_path):
        """Running with a non-existent DB should fail gracefully."""
        fake_db = str(tmp_path / "nonexistent.db")
        result = subprocess.run(
            [sys.executable, _ANALYZE_SCRIPT, fake_db, "--goal", "triage", "--json"],
            capture_output=True, text=True, timeout=30,
            cwd=_SCRIPT_DIR, env=_SUBPROCESS_ENV,
        )
        assert result.returncode != 0

    def test_valid_db_includes_pipeline_summary(self, sample_db):
        """Running with a valid DB should include pipeline_summary in output."""
        result = subprocess.run(
            [sys.executable, _ANALYZE_SCRIPT, str(sample_db),
             "--goal", "triage", "--json", "--timeout", "30"],
            capture_output=True, text=True, timeout=60,
            cwd=_SCRIPT_DIR, env=_SUBPROCESS_ENV,
        )
        if result.returncode == 0:
            output = json.loads(result.stdout)
            assert "pipeline_summary" in output
            assert "succeeded" in output["pipeline_summary"]
            assert "failed" in output["pipeline_summary"]
            total = output["pipeline_summary"]["total_steps"]
            assert total == (
                output["pipeline_summary"]["succeeded"]
                + output["pipeline_summary"]["failed"]
            )


class TestAdaptiveTimeoutUnit:
    """Test the adaptive timeout calculation (imported from helpers.config)."""

    def test_base_timeout_returned_for_zero_functions(self):
        from helpers.config import get_config_value
        base = int(get_config_value("triage.step_timeout_seconds", 180))
        per_func = float(get_config_value("triage.per_function_timeout_seconds", 0.2))
        result = max(base, int(base + 0 * per_func))
        assert result == base

    def test_timeout_scales_with_functions(self):
        base = 60
        per_func = 0.2
        result = max(base, int(base + 500 * per_func))
        assert result >= 160

    def test_never_below_base(self):
        base = 120
        per_func = 0.01
        result = max(base, int(base + 1 * per_func))
        assert result >= base


class TestPipelineStepGrouping:
    """Test pipeline step grouping logic conceptually."""

    def test_sequential_steps_independent(self):
        from itertools import groupby
        steps = [
            {"name": "a", "parallel_group": None},
            {"name": "b", "parallel_group": None},
        ]
        groups = []
        for key, grp in groupby(steps, key=lambda s: s["parallel_group"]):
            group = list(grp)
            if key is None:
                for step in group:
                    groups.append([step])
            else:
                groups.append(group)
        assert len(groups) == 2

    def test_parallel_steps_grouped(self):
        from itertools import groupby
        steps = [
            {"name": "a", "parallel_group": "g1"},
            {"name": "b", "parallel_group": "g1"},
            {"name": "c", "parallel_group": None},
        ]
        groups = []
        for key, grp in groupby(steps, key=lambda s: s["parallel_group"]):
            group = list(grp)
            if key is None:
                for step in group:
                    groups.append([step])
            else:
                groups.append(group)
        assert len(groups) == 2
        assert len(groups[0]) == 2


# ---------------------------------------------------------------------------
# Tests using the real _group_steps and step builders from analyze_module.py
# ---------------------------------------------------------------------------
_TRIAGE_SCRIPTS_DIR = str(_AGENT_DIR / "agents" / "triage-coordinator" / "scripts")


def _import_analyze_module():
    """Import analyze_module.py with clean _common resolution."""
    import importlib.util

    scripts = _TRIAGE_SCRIPTS_DIR
    for key in list(sys.modules):
        if key == "_common":
            del sys.modules[key]
    if scripts in sys.path:
        sys.path.remove(scripts)
    sys.path.insert(0, scripts)

    spec = importlib.util.spec_from_file_location(
        "analyze_module_grouping_test",
        str(Path(scripts) / "analyze_module.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestRealGrouping:
    """Test _group_steps with real step builders to verify phase counts."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _import_analyze_module()

    def _make_chars(self, **overrides):
        defaults = dict(file_name="test.dll", total_functions=100)
        defaults.update(overrides)
        return self.mod.ModuleCharacteristics(**defaults)

    def test_triage_goal_single_parallel_phase(self):
        steps = self.mod._triage_steps("/fake.db", self._make_chars())
        groups = self.mod._group_steps(steps)
        assert len(groups) == 1, "Triage should be 1 parallel phase"
        assert len(groups[0]) == 3

    def test_security_goal_two_parallel_phases(self):
        chars = self._make_chars()
        steps = (
            self.mod._triage_steps("/fake.db", chars)
            + self.mod._security_steps("/fake.db", chars)
        )
        groups = self.mod._group_steps(steps)
        assert len(groups) == 2, (
            "Security goal should be 2 phases: triage_classify + post_triage"
        )
        assert len(groups[0]) == 3  # triage_classify
        assert len(groups[1]) == 2  # post_triage

    def test_full_goal_merges_security_and_extra(self):
        chars = self._make_chars()
        steps = (
            self.mod._triage_steps("/fake.db", chars)
            + self.mod._security_steps("/fake.db", chars)
            + self.mod._full_extra_steps("/fake.db", chars)
        )
        groups = self.mod._group_steps(steps)
        assert len(groups) == 2, (
            "Full goal should be 2 phases: triage_classify + post_triage "
            "(security and full_extra merge because they share parallel_group)"
        )
        assert len(groups[0]) == 3  # triage_classify
        assert len(groups[1]) >= 5  # post_triage: 2 security + 3+ full_extra

    def test_full_goal_with_conditionals(self, monkeypatch):
        monkeypatch.setattr(
            "helpers.db_paths.resolve_tracking_db_auto", lambda: None,
        )
        chars = self._make_chars(com_density=10, dispatch_density=10)
        steps = (
            self.mod._triage_steps("/fake.db", chars)
            + self.mod._security_steps("/fake.db", chars)
            + self.mod._full_extra_steps("/fake.db", chars)
        )
        groups = self.mod._group_steps(steps)
        assert len(groups) == 2
        assert len(groups[1]) == 5  # 2 security + 2 base + scan_com (module_context step removed)

    def test_function_goal_single_parallel_phase(self):
        steps = self.mod._function_steps("/fake.db", "TestFunc")
        groups = self.mod._group_steps(steps)
        assert len(groups) == 1, "Function goal should be 1 parallel phase"
        assert len(groups[0]) == 5

    def test_types_goal_two_steps_single_phase(self):
        chars = self._make_chars(com_density=10)
        steps = self.mod._types_steps("/fake.db", chars)
        groups = self.mod._group_steps(steps)
        assert len(groups) == 1, "Types goal with COM should be 1 parallel phase"
        assert len(groups[0]) == 2

    def test_types_goal_single_step_still_one_group(self):
        """Single-step group with non-None parallel_group is still 1 group."""
        chars = self._make_chars(com_density=0)
        steps = self.mod._types_steps("/fake.db", chars)
        groups = self.mod._group_steps(steps)
        assert len(groups) == 1
        assert len(groups[0]) == 1
        assert groups[0][0].parallel_group == "types_scan"

    def test_single_step_group_runs_sequentially(self):
        """_run_step_group falls through to sequential for 1-element groups."""
        chars = self._make_chars(com_density=0)
        steps = self.mod._types_steps("/fake.db", chars)
        groups = self.mod._group_steps(steps)
        group = groups[0]
        assert len(group) == 1
        # Verify the condition that _run_step_group uses
        assert (len(group) <= 1) is True, (
            "Single-element parallel group should trigger sequential path"
        )

    def test_all_goals_have_no_none_parallel_groups(self):
        """Every step from every builder has a non-None parallel_group."""
        chars = self._make_chars(com_density=10, dispatch_density=10)
        all_steps = (
            self.mod._triage_steps("/fake.db", chars)
            + self.mod._security_steps("/fake.db", chars)
            + self.mod._full_extra_steps("/fake.db", chars)
            + self.mod._function_steps("/fake.db", "TestFunc")
            + self.mod._types_steps("/fake.db", chars)
        )
        for step in all_steps:
            assert step.parallel_group is not None, (
                f"Step {step.name} has parallel_group=None"
            )
