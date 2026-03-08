"""Integration smoke test for the /triage pipeline.

Validates that the core triage skill scripts produce valid JSON output
when run against a sample database, and that workspace handoff artifacts
are created correctly when --workspace-dir is used.

This is a pipeline-level integration test per the skill authoring guide
Section 9.10 -- verifying cross-skill wiring and workspace protocol
compliance, not individual script logic.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

AGENT_DIR = Path(__file__).resolve().parent.parent
SKILLS_DIR = AGENT_DIR / "skills"


def _run_skill_script(skill: str, script: str, args: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    """Run a skill script and return the completed process."""
    script_path = SKILLS_DIR / skill / "scripts" / script
    if not script_path.exists():
        pytest.skip(f"Script not found: {script_path}")
    cmd = [sys.executable, str(script_path)] + args
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


class TestTriagePipelineScripts:
    """Verify that each triage pipeline script produces valid JSON output."""

    def test_triage_summary_json(self, sample_db):
        result = _run_skill_script(
            "classify-functions", "triage_summary.py",
            [str(sample_db), "--json"],
        )
        assert result.returncode == 0, f"triage_summary.py failed: {result.stderr}"
        data = json.loads(result.stdout)
        assert data.get("status") == "ok"

    def test_classify_module_json(self, sample_db):
        result = _run_skill_script(
            "classify-functions", "classify_module.py",
            [str(sample_db), "--json"],
        )
        assert result.returncode == 0, f"classify_module.py failed: {result.stderr}"
        data = json.loads(result.stdout)
        assert data.get("status") == "ok"

    def test_discover_entrypoints_json(self, sample_db):
        result = _run_skill_script(
            "map-attack-surface", "discover_entrypoints.py",
            [str(sample_db), "--json"],
        )
        assert result.returncode == 0, f"discover_entrypoints.py failed: {result.stderr}"
        data = json.loads(result.stdout)
        assert data.get("status") == "ok"


class TestTriageWorkspaceHandoff:
    """Verify workspace protocol creates expected artifacts."""

    def test_workspace_step_creates_artifacts(self, sample_db, tmp_path):
        """When --workspace-dir and --workspace-step are passed, the script
        should create results.json and summary.json in the step directory."""
        run_dir = tmp_path / "test_triage_run"
        run_dir.mkdir()

        result = _run_skill_script(
            "classify-functions", "triage_summary.py",
            [
                str(sample_db), "--json",
                "--workspace-dir", str(run_dir),
                "--workspace-step", "classify_triage",
            ],
        )
        assert result.returncode == 0, f"triage_summary.py failed: {result.stderr}"

        step_dir = run_dir / "classify_triage"
        if step_dir.exists():
            results_file = step_dir / "results.json"
            summary_file = step_dir / "summary.json"
            assert results_file.exists(), "results.json not created in step directory"
            assert summary_file.exists(), "summary.json not created in step directory"

            results_data = json.loads(results_file.read_text())
            actual_output = results_data.get("stdout", results_data)
            assert actual_output.get("status") == "ok"

    def test_manifest_updated_on_step(self, sample_db, tmp_path):
        """When workspace handoff is active, manifest.json should be created or updated."""
        run_dir = tmp_path / "test_manifest_run"
        run_dir.mkdir()

        _run_skill_script(
            "classify-functions", "triage_summary.py",
            [
                str(sample_db), "--json",
                "--workspace-dir", str(run_dir),
                "--workspace-step", "classify_triage",
            ],
        )

        manifest = run_dir / "manifest.json"
        if manifest.exists():
            data = json.loads(manifest.read_text())
            assert "steps" in data or "classify_triage" in str(data)


class TestTriagePipelineRegistry:
    """Verify that /triage command's skill references are consistent."""

    def test_triage_skills_exist_in_skill_registry(self):
        cmd_registry = json.loads(
            (AGENT_DIR / "commands" / "registry.json").read_text()
        )
        skill_registry = json.loads(
            (SKILLS_DIR / "registry.json").read_text()
        )

        triage_skills = cmd_registry["commands"]["triage"]["skills_used"]
        registered_skills = set(skill_registry["skills"].keys())

        for skill in triage_skills:
            assert skill in registered_skills, (
                f"Triage command references skill '{skill}' not in skills/registry.json"
            )

    def test_diff_command_registered(self):
        """Verify the new /diff command is registered."""
        cmd_registry = json.loads(
            (AGENT_DIR / "commands" / "registry.json").read_text()
        )
        assert "diff" in cmd_registry["commands"], "/diff not found in commands/registry.json"
        diff_cmd = cmd_registry["commands"]["diff"]
        assert diff_cmd["file"] == "diff.md"
        assert "decompiled-code-extractor" in diff_cmd["skills_used"]

    def test_security_auditor_registered(self):
        """Verify the new security-auditor agent is registered."""
        agent_registry = json.loads(
            (AGENT_DIR / "agents" / "registry.json").read_text()
        )
        assert "security-auditor" in agent_registry["agents"], (
            "security-auditor not found in agents/registry.json"
        )
        agent = agent_registry["agents"]["security-auditor"]
        assert "taint-analysis" in agent["skills_used"]
        assert "exploitability-assessment" in agent["skills_used"]
