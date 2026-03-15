"""Tests for adaptive timeout and parallel grouping in the triage coordinator.

Target: agents/triage-coordinator/scripts/analyze_module.py
  - compute_adaptive_timeout
  - parallel_group assignments on step builders
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Import the module under test (it lives outside the normal package tree)
# ---------------------------------------------------------------------------
_AGENT_DIR = Path(__file__).resolve().parent.parent
_SCRIPTS_DIR = _AGENT_DIR / "agents" / "triage-coordinator" / "scripts"


def _import_analyze_module():
    """Import analyze_module.py with clean _common resolution.

    The triage-coordinator has its own ``_common.py``.  We must evict
    any previously cached ``_common`` from ``sys.modules`` and ensure
    the correct scripts directory is first on ``sys.path``.
    """
    scripts = str(_SCRIPTS_DIR)

    # Evict stale _common from a different skill/agent
    for key in list(sys.modules):
        if key == "_common":
            del sys.modules[key]

    if scripts in sys.path:
        sys.path.remove(scripts)
    sys.path.insert(0, scripts)

    spec = importlib.util.spec_from_file_location(
        "analyze_module", str(_SCRIPTS_DIR / "analyze_module.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ===================================================================
# compute_adaptive_timeout
# ===================================================================

class TestComputeAdaptiveTimeout:
    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _import_analyze_module()

    def test_zero_functions(self):
        result = self.mod.compute_adaptive_timeout(0, base_timeout=60, per_function_seconds=0.2)
        assert result == 60

    def test_small_module(self):
        result = self.mod.compute_adaptive_timeout(100, base_timeout=60, per_function_seconds=0.2)
        assert result == 80  # 60 + 100*0.2

    def test_large_module(self):
        """coredpus.dll has ~1080 functions."""
        result = self.mod.compute_adaptive_timeout(1080, base_timeout=60, per_function_seconds=0.2)
        assert result == 276  # 60 + 1080*0.2

    def test_very_large_module(self):
        result = self.mod.compute_adaptive_timeout(5000, base_timeout=60, per_function_seconds=0.2)
        assert result == 1060  # 60 + 5000*0.2

    def test_never_below_base(self):
        result = self.mod.compute_adaptive_timeout(0, base_timeout=120, per_function_seconds=0.0)
        assert result >= 120

    def test_custom_base_and_rate(self):
        result = self.mod.compute_adaptive_timeout(500, base_timeout=30, per_function_seconds=0.5)
        assert result == 280  # 30 + 500*0.5

    def test_defaults_from_config(self, monkeypatch):
        """When no explicit args, should use config values."""
        monkeypatch.setattr(
            self.mod, "get_config_value",
            lambda path, default=None: {
                "triage.step_timeout_seconds": 90,
                "triage.per_function_timeout_seconds": 0.3,
            }.get(path, default),
        )
        result = self.mod.compute_adaptive_timeout(100)
        assert result == 120  # 90 + 100*0.3


# ===================================================================
# PipelineStep timeout override
# ===================================================================

class TestPipelineStepTimeout:
    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _import_analyze_module()

    def test_explicit_timeout_overrides_default(self):
        step = self.mod.PipelineStep(
            name="test", skill="s", script="x.py", args=[],
            timeout=180,
        )
        assert step.timeout == 180

    def test_default_timeout_is_180(self):
        step = self.mod.PipelineStep(
            name="test", skill="s", script="x.py", args=[],
        )
        assert step.timeout == 180


# ===================================================================
# Reasonable values for known module sizes
# ===================================================================

class TestReasonableValues:
    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _import_analyze_module()

    @pytest.mark.parametrize("func_count,min_expected,max_expected", [
        (50, 60, 120),
        (200, 60, 200),
        (500, 100, 300),
        (1080, 200, 500),
        (3000, 400, 1200),
    ])
    def test_within_sane_range(self, func_count, min_expected, max_expected):
        result = self.mod.compute_adaptive_timeout(
            func_count, base_timeout=60, per_function_seconds=0.2,
        )
        assert min_expected <= result <= max_expected, (
            f"For {func_count} functions got {result}s, "
            f"expected [{min_expected}, {max_expected}]"
        )


# ===================================================================
# Parallel group assignments on step builders
# ===================================================================

class TestParallelGroupAssignment:
    """Verify every step builder assigns the correct parallel_group."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _import_analyze_module()

    def _make_chars(self, **overrides):
        """Build a ModuleCharacteristics with optional overrides."""
        defaults = dict(
            file_name="test.dll",
            total_functions=100,
            com_density=10,
            dispatch_density=10,
        )
        defaults.update(overrides)
        return self.mod.ModuleCharacteristics(**defaults)

    def test_triage_steps_all_triage_classify(self):
        steps = self.mod._triage_steps("/fake.db", self._make_chars())
        assert len(steps) == 3
        for step in steps:
            assert step.parallel_group == "triage_classify"

    def test_security_steps_all_post_triage(self):
        steps = self.mod._security_steps("/fake.db", self._make_chars())
        assert len(steps) == 2
        for step in steps:
            assert step.parallel_group == "post_triage"

    def test_full_extra_steps_all_post_triage(self):
        chars = self._make_chars()
        steps = self.mod._full_extra_steps("/fake.db", chars)
        assert len(steps) >= 3
        for step in steps:
            assert step.parallel_group == "post_triage", (
                f"Step {step.name} has parallel_group={step.parallel_group!r}"
            )

    def test_full_extra_conditional_steps_post_triage(self, monkeypatch):
        monkeypatch.setattr(
            "helpers.db_paths.resolve_tracking_db_auto", lambda: None,
        )
        chars = self._make_chars(com_density=10, dispatch_density=10)
        steps = self.mod._full_extra_steps("/fake.db", chars)
        assert len(steps) == 3  # 2 base + scan_com (module_context step removed)
        for step in steps:
            assert step.parallel_group == "post_triage"

    def test_function_steps_all_func_analysis(self):
        steps = self.mod._function_steps("/fake.db", "TestFunc")
        assert len(steps) == 5
        for step in steps:
            assert step.parallel_group == "func_analysis", (
                f"Step {step.name} has parallel_group={step.parallel_group!r}"
            )

    def test_types_steps_all_types_scan(self):
        chars = self._make_chars(com_density=0)
        steps = self.mod._types_steps("/fake.db", chars)
        assert len(steps) >= 1
        for step in steps:
            assert step.parallel_group == "types_scan"

    def test_types_steps_with_com_all_types_scan(self):
        chars = self._make_chars(com_density=10)
        steps = self.mod._types_steps("/fake.db", chars)
        assert len(steps) == 2
        for step in steps:
            assert step.parallel_group == "types_scan"

    def test_dossier_steps_all_dossiers(self):
        results = {"rank_entrypoints": {
            "ranked": [
                {"function_name": "fn1"},
                {"function_name": "fn2"},
            ],
        }}
        steps = self.mod._security_dossier_steps("/fake.db", results, "/run")
        assert len(steps) == 2
        for step in steps:
            assert step.parallel_group == "dossiers"

    def test_no_step_builder_produces_none_parallel_group(self):
        """Regression guard: every step from every builder must set parallel_group."""
        chars = self._make_chars(com_density=10, dispatch_density=10)
        builders = [
            ("triage", self.mod._triage_steps("/db", chars)),
            ("security", self.mod._security_steps("/db", chars)),
            ("full_extra", self.mod._full_extra_steps("/db", chars)),
            ("function", self.mod._function_steps("/db", "Fn")),
            ("types", self.mod._types_steps("/db", chars)),
        ]
        for builder_name, steps in builders:
            for step in steps:
                assert step.parallel_group is not None, (
                    f"{builder_name} step {step.name!r} has parallel_group=None"
                )


# ===================================================================
# Phase logging label correctness
# ===================================================================

class TestPhaseLoggingLabel:
    """Verify the label logic matches _run_step_group dispatch."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _import_analyze_module()

    def _label(self, group):
        """Replicate the logging label computation from run_pipeline."""
        return "parallel" if len(group) > 1 and group[0].parallel_group else "sequential"

    def _will_use_pool(self, group):
        """Replicate the _run_step_group dispatch condition."""
        return not (len(group) <= 1 or group[0].parallel_group is None)

    def test_label_matches_dispatch_for_multi_element_parallel(self):
        steps = [
            self.mod.PipelineStep("a", "s", "x.py", [], parallel_group="g1"),
            self.mod.PipelineStep("b", "s", "x.py", [], parallel_group="g1"),
        ]
        assert self._label(steps) == "parallel"
        assert self._will_use_pool(steps) is True

    def test_label_matches_dispatch_for_single_element_parallel(self):
        steps = [
            self.mod.PipelineStep("a", "s", "x.py", [], parallel_group="g1"),
        ]
        assert self._label(steps) == "sequential"
        assert self._will_use_pool(steps) is False

    def test_label_matches_dispatch_for_none_group(self):
        steps = [
            self.mod.PipelineStep("a", "s", "x.py", [], parallel_group=None),
        ]
        assert self._label(steps) == "sequential"
        assert self._will_use_pool(steps) is False
