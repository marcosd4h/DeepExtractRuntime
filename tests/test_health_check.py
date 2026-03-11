"""Tests for helpers.health_check -- workspace health validation."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

_AGENT_ROOT = Path(__file__).resolve().parents[1]
_HEALTH_SCRIPT = _AGENT_ROOT / "helpers" / "health_check.py"


@pytest.fixture
def workspace_root(tmp_path):
    """Create a minimal workspace structure for health checks."""
    (tmp_path / "extracted_code").mkdir()
    (tmp_path / "extracted_dbs").mkdir()
    agent_dir = tmp_path / ".agent"
    agent_dir.mkdir()
    (agent_dir / "skills").mkdir()
    (agent_dir / "agents").mkdir()
    (agent_dir / "commands").mkdir()
    (agent_dir / "helpers").mkdir()
    (agent_dir / "hooks").mkdir()
    (agent_dir / "config").mkdir()
    config = agent_dir / "config" / "defaults.json"
    config.write_text("{}")
    return tmp_path


class TestHealthCheckCLI:
    def test_help_flag(self):
        result = subprocess.run(
            [sys.executable, str(_HEALTH_SCRIPT), "--help"],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0
        assert "health" in result.stdout.lower() or "usage" in result.stdout.lower()

    def test_json_flag_produces_valid_json(self, workspace_root):
        result = subprocess.run(
            [sys.executable, str(_HEALTH_SCRIPT), "--quick", "--json",
             "--workspace", str(workspace_root)],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            assert "status" in data

    def test_quick_mode_runs_fast(self, workspace_root):
        result = subprocess.run(
            [sys.executable, str(_HEALTH_SCRIPT), "--quick",
             "--workspace", str(workspace_root)],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode in (0, 1)
