"""Tests for workspace handoff propagation (Issue #4).

Verifies that:
- ``get_workspace_args()`` correctly extracts workspace args from argparse namespaces
- ``run_skill_script()`` appends workspace CLI flags when args are provided
- ``run_skill_script()`` omits workspace CLI flags when args are absent
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from helpers.script_runner import get_workspace_args, run_skill_script


# ---------------------------------------------------------------------------
# get_workspace_args() tests
# ---------------------------------------------------------------------------


class TestGetWorkspaceArgs:
    """Test the utility function for extracting workspace args."""

    def test_both_args_present(self):
        ns = argparse.Namespace(workspace_dir="/tmp/ws", workspace_step="step1")
        result = get_workspace_args(ns)
        assert result == {"workspace_dir": "/tmp/ws", "workspace_step": "step1"}

    def test_no_workspace_attrs(self):
        ns = argparse.Namespace(foo="bar", baz=42)
        result = get_workspace_args(ns)
        assert result == {"workspace_dir": None, "workspace_step": None}

    def test_only_workspace_dir(self):
        ns = argparse.Namespace(workspace_dir="/tmp/ws")
        result = get_workspace_args(ns)
        assert result["workspace_dir"] == "/tmp/ws"
        assert result["workspace_step"] is None

    def test_only_workspace_step(self):
        ns = argparse.Namespace(workspace_step="my_step")
        result = get_workspace_args(ns)
        assert result["workspace_dir"] is None
        assert result["workspace_step"] == "my_step"

    def test_none_values(self):
        ns = argparse.Namespace(workspace_dir=None, workspace_step=None)
        result = get_workspace_args(ns)
        assert result == {"workspace_dir": None, "workspace_step": None}

    def test_empty_namespace(self):
        ns = argparse.Namespace()
        result = get_workspace_args(ns)
        assert result == {"workspace_dir": None, "workspace_step": None}

    def test_return_type_is_dict(self):
        ns = argparse.Namespace()
        result = get_workspace_args(ns)
        assert isinstance(result, dict)
        assert set(result.keys()) == {"workspace_dir", "workspace_step"}

    def test_splatting_into_run_skill_script_signature(self):
        """Verify the returned dict keys match run_skill_script() parameter names."""
        ns = argparse.Namespace(workspace_dir="/ws", workspace_step="s1")
        ws = get_workspace_args(ns)
        # Should not raise -- keys are valid kwargs for run_skill_script
        # We just verify the dict is "splat-safe" by checking the key names
        assert "workspace_dir" in ws
        assert "workspace_step" in ws


# ---------------------------------------------------------------------------
# run_skill_script() workspace arg forwarding tests
# ---------------------------------------------------------------------------


class TestRunSkillScriptWorkspaceForwarding:
    """Test that run_skill_script() correctly builds subprocess commands."""

    @patch("helpers.script_runner.subprocess.run")
    @patch("helpers.script_runner.find_skill_script")
    def test_workspace_args_appended_to_command(self, mock_find, mock_run):
        mock_find.return_value = Path("/fake/skill/scripts/script.py")
        mock_run.return_value = MagicMock(
            returncode=0, stdout="{}", stderr=""
        )

        run_skill_script(
            "test-skill", "script.py", ["arg1"],
            workspace_dir="/tmp/run_dir",
            workspace_step="classify",
        )

        cmd = mock_run.call_args[0][0]
        assert "--workspace-dir" in cmd
        assert "/tmp/run_dir" in cmd
        assert "--workspace-step" in cmd
        assert "classify" in cmd

    @patch("helpers.script_runner.subprocess.run")
    @patch("helpers.script_runner.find_skill_script")
    def test_no_workspace_args_when_none(self, mock_find, mock_run):
        mock_find.return_value = Path("/fake/skill/scripts/script.py")
        mock_run.return_value = MagicMock(
            returncode=0, stdout="{}", stderr=""
        )

        run_skill_script("test-skill", "script.py", ["arg1"])

        cmd = mock_run.call_args[0][0]
        assert "--workspace-dir" not in cmd
        assert "--workspace-step" not in cmd

    @patch("helpers.script_runner.subprocess.run")
    @patch("helpers.script_runner.find_skill_script")
    def test_workspace_dir_without_step(self, mock_find, mock_run):
        mock_find.return_value = Path("/fake/skill/scripts/script.py")
        mock_run.return_value = MagicMock(
            returncode=0, stdout="{}", stderr=""
        )

        run_skill_script(
            "test-skill", "script.py", ["arg1"],
            workspace_dir="/tmp/run_dir",
        )

        cmd = mock_run.call_args[0][0]
        assert "--workspace-dir" in cmd
        assert "/tmp/run_dir" in cmd
        # workspace_step not provided, so it should not appear
        assert "--workspace-step" not in cmd

    @patch("helpers.script_runner.subprocess.run")
    @patch("helpers.script_runner.find_skill_script")
    def test_workspace_step_ignored_without_dir(self, mock_find, mock_run):
        """workspace_step alone (without workspace_dir) should not be appended."""
        mock_find.return_value = Path("/fake/skill/scripts/script.py")
        mock_run.return_value = MagicMock(
            returncode=0, stdout="{}", stderr=""
        )

        run_skill_script(
            "test-skill", "script.py", ["arg1"],
            workspace_step="orphan_step",
        )

        cmd = mock_run.call_args[0][0]
        assert "--workspace-dir" not in cmd
        assert "--workspace-step" not in cmd

    @patch("helpers.script_runner.subprocess.run")
    @patch("helpers.script_runner.find_skill_script")
    def test_workspace_args_after_script_args(self, mock_find, mock_run):
        """Workspace flags should appear after user-provided args."""
        mock_find.return_value = Path("/fake/skill/scripts/script.py")
        mock_run.return_value = MagicMock(
            returncode=0, stdout="{}", stderr=""
        )

        run_skill_script(
            "test-skill", "script.py", ["--db", "test.db"],
            workspace_dir="/ws",
            workspace_step="s1",
        )

        cmd = mock_run.call_args[0][0]
        db_idx = cmd.index("test.db")
        ws_idx = cmd.index("--workspace-dir")
        assert ws_idx > db_idx

    def test_script_not_found_returns_error(self):
        """When the skill script doesn't exist, return an error dict."""
        result = run_skill_script(
            "nonexistent-skill", "nonexistent.py", [],
            workspace_dir="/ws",
            workspace_step="s1",
        )
        assert result["success"] is False
        assert "not found" in result["error"].lower()

    @patch("helpers.script_runner.subprocess.run")
    @patch("helpers.script_runner.find_skill_script")
    def test_json_flag_and_workspace_both_present(self, mock_find, mock_run):
        """Both --json and workspace flags should appear."""
        mock_find.return_value = Path("/fake/skill/scripts/script.py")
        mock_run.return_value = MagicMock(
            returncode=0, stdout='{"result": true}', stderr=""
        )

        run_skill_script(
            "test-skill", "script.py", [],
            json_output=True,
            workspace_dir="/ws",
            workspace_step="s1",
        )

        cmd = mock_run.call_args[0][0]
        assert "--json" in cmd
        assert "--workspace-dir" in cmd
        assert "--workspace-step" in cmd
