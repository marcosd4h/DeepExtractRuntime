"""Tests for agent orchestration helpers.

Target: helpers/agent_common.py
"""

from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock

from helpers.agent_common import (
    AgentBase,
    AgentOrchestrator,
    AgentStep,
    AgentStepResult,
)


# ===================================================================
# AgentStep
# ===================================================================


class TestAgentStep:
    def test_minimal_step(self):
        step = AgentStep(name="phase1", skill_name="classify", script_name="triage.py", args=[])
        assert step.name == "phase1"
        assert step.skill_name == "classify"
        assert step.script_name == "triage.py"
        assert step.args == []
        assert step.timeout == 300
        assert step.json_output is True
        assert step.workspace_dir is None
        assert step.workspace_step is None
        assert step.max_retries == 0

    def test_step_with_workspace_args(self):
        step = AgentStep(
            name="phase2",
            skill_name="classify",
            script_name="triage.py",
            args=["extracted_dbs/module.db"],
            workspace_dir="/run/dir",
            workspace_step="triage",
        )
        assert step.workspace_dir == "/run/dir"
        assert step.workspace_step == "triage"

    def test_step_frozen(self):
        step = AgentStep(name="x", skill_name="s", script_name="t.py", args=[])
        with pytest.raises(AttributeError):
            step.name = "y"


# ===================================================================
# AgentStepResult
# ===================================================================


class TestAgentStepResult:
    def test_success_result(self):
        r = AgentStepResult(
            name="phase1",
            skill_name="classify",
            script_name="triage.py",
            success=True,
            elapsed_seconds=1.5,
            exit_code=0,
        )
        assert r.success is True
        assert r.exit_code == 0
        assert r.error is None

    def test_failure_result(self):
        r = AgentStepResult(
            name="phase1",
            skill_name="classify",
            script_name="triage.py",
            success=False,
            elapsed_seconds=0.1,
            exit_code=1,
            error="Script failed",
        )
        assert r.success is False
        assert r.error == "Script failed"

    def test_to_dict(self):
        r = AgentStepResult(
            name="p1",
            skill_name="s",
            script_name="t.py",
            success=True,
            elapsed_seconds=2.0,
            exit_code=0,
            json_data={"count": 10},
        )
        d = r.to_dict()
        assert d["name"] == "p1"
        assert d["success"] is True
        assert d["json_data"] == {"count": 10}
        assert "elapsed_seconds" in d
        assert "exit_code" in d


# ===================================================================
# AgentBase
# ===================================================================


class TestAgentBase:
    @patch("helpers.agent_common._run_skill_script")
    def test_run_skill_script_result_success(self, mock_run):
        mock_run.return_value = {
            "success": True,
            "exit_code": 0,
            "stdout": "{}",
            "stderr": "",
            "json_data": {"total": 5},
            "error": None,
        }
        base = AgentBase()
        result = base.run_skill_script_result(
            "classify-functions",
            "triage_summary.py",
            ["extracted_dbs/mod.db"],
        )
        assert result["success"] is True
        assert result["json_data"] == {"total": 5}
        mock_run.assert_called_once()

    @patch("helpers.agent_common._run_skill_script")
    def test_run_skill_script_returns_json_data(self, mock_run):
        mock_run.return_value = {
            "success": True,
            "exit_code": 0,
            "json_data": [{"name": "foo"}],
            "error": None,
        }
        base = AgentBase()
        data = base.run_skill_script("classify", "triage.py", ["db"])
        assert data == [{"name": "foo"}]

    @patch("helpers.agent_common._run_skill_script")
    def test_run_skill_script_failure_returns_none(self, mock_run):
        mock_run.return_value = {
            "success": False,
            "exit_code": 1,
            "json_data": None,
            "error": "Failed",
        }
        base = AgentBase()
        data = base.run_skill_script("classify", "triage.py", ["db"])
        assert data is None

    @patch("helpers.agent_common._run_skill_script")
    def test_run_skill_script_passes_workspace_args(self, mock_run):
        mock_run.return_value = {"success": True, "exit_code": 0, "json_data": None, "error": None}
        base = AgentBase()
        base.run_skill_script_result(
            "skill",
            "script.py",
            [],
            workspace_dir="/run",
            workspace_step="step1",
        )
        call_kw = mock_run.call_args[1]
        assert call_kw["workspace_dir"] == "/run"
        assert call_kw["workspace_step"] == "step1"


# ===================================================================
# AgentOrchestrator
# ===================================================================


class TestAgentOrchestrator:
    @patch("helpers.agent_common._run_skill_script")
    def test_run_step_success(self, mock_run):
        mock_run.return_value = {
            "success": True,
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "json_data": {},
            "error": None,
        }
        orch = AgentOrchestrator()
        step = AgentStep(name="s1", skill_name="s", script_name="t.py", args=[])
        result = orch.run_step(step)
        assert result.success is True
        assert result.name == "s1"
        assert result.elapsed_seconds >= 0

    @patch("helpers.agent_common._run_skill_script")
    def test_run_step_failure(self, mock_run):
        mock_run.return_value = {
            "success": False,
            "exit_code": 1,
            "stdout": "",
            "stderr": "error",
            "json_data": None,
            "error": "error",
        }
        orch = AgentOrchestrator()
        step = AgentStep(name="s1", skill_name="s", script_name="t.py", args=[])
        result = orch.run_step(step)
        assert result.success is False
        assert orch._failures == 1

    @patch("helpers.agent_common._run_skill_script")
    def test_run_steps_sequential(self, mock_run):
        mock_run.return_value = {
            "success": True,
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "json_data": {},
            "error": None,
        }
        orch = AgentOrchestrator()
        steps = [
            AgentStep(name="a", skill_name="s", script_name="t.py", args=[]),
            AgentStep(name="b", skill_name="s", script_name="t.py", args=[]),
        ]
        results = orch.run_steps(steps, parallel=False)
        assert len(results) == 2
        assert results[0].name == "a"
        assert results[1].name == "b"
        assert mock_run.call_count == 2

    @patch("helpers.agent_common._run_skill_script")
    def test_circuit_breaker_opens_after_threshold(self, mock_run):
        mock_run.return_value = {
            "success": False,
            "exit_code": 1,
            "stdout": "",
            "stderr": "",
            "json_data": None,
            "error": "fail",
        }
        orch = AgentOrchestrator(failure_threshold=2)
        steps = [
            AgentStep(name="s1", skill_name="s", script_name="t.py", args=[]),
            AgentStep(name="s2", skill_name="s", script_name="t.py", args=[]),
            AgentStep(name="s3", skill_name="s", script_name="t.py", args=[]),
        ]
        results = orch.run_steps(steps, parallel=False)
        # First two fail; after second, circuit opens and loop breaks (third never run)
        assert len(results) == 2
        assert results[0].success is False
        assert results[1].success is False
        assert orch.summary()["circuit_open"] is True
        assert mock_run.call_count == 2

    @patch("helpers.agent_common._run_skill_script")
    def test_summary_aggregates_results(self, mock_run):
        mock_run.return_value = {
            "success": True,
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "json_data": {},
            "error": None,
        }
        orch = AgentOrchestrator()
        step = AgentStep(name="s1", skill_name="s", script_name="t.py", args=[])
        orch.run_step(step)
        orch.run_step(step)
        summary = orch.summary()
        assert summary["total_steps"] == 2
        assert summary["success_steps"] == 2
        assert summary["failed_steps"] == 0
        assert len(summary["steps"]) == 2

    def test_run_steps_empty_returns_empty(self):
        orch = AgentOrchestrator()
        assert orch.run_steps([]) == []
