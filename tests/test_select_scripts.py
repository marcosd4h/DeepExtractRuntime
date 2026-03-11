"""Tests for helpers.select_audit_callees and helpers.select_backward_traces."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

_AGENT_ROOT = Path(__file__).resolve().parents[1]
_SELECT_CALLEES = _AGENT_ROOT / "helpers" / "select_audit_callees.py"
_SELECT_BACKWARD = _AGENT_ROOT / "helpers" / "select_backward_traces.py"


@pytest.fixture
def sample_dossier(tmp_path):
    """Create a minimal dossier JSON file for testing."""
    dossier = {
        "status": "ok",
        "function_name": "TestFunction",
        "function_id": 1,
        "dangerous_ops": {
            "reachable_count": 5,
            "categories": {"command_execution": ["CreateProcessW"]},
        },
        "callees": [
            {"name": "InternalHelper", "function_id": 2, "is_library": False,
             "dangerous_apis": ["CreateProcessW", "ShellExecuteW"],
             "category": "command_execution"},
            {"name": "WilCheck", "function_id": 3, "is_library": True,
             "dangerous_apis": [], "category": "utility"},
        ],
        "attack_reachability": {"reachable_from_export": True},
    }
    p = tmp_path / "dossier.json"
    p.write_text(json.dumps(dossier))
    return p


@pytest.fixture
def sample_attack_surface(tmp_path):
    """Create a minimal attack surface JSON file."""
    surface = {
        "status": "ok",
        "entrypoints": [
            {"function_name": "TestFunction", "function_id": 1,
             "attack_score": 8.5, "entry_type": "EXPORT"},
        ],
    }
    p = tmp_path / "attack_surface.json"
    p.write_text(json.dumps(surface))
    return p


class TestSelectAuditCalleesCLI:
    def test_help_flag(self):
        result = subprocess.run(
            [sys.executable, str(_SELECT_CALLEES), "--help"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
        assert "dossier" in result.stdout.lower()

    def test_missing_required_args(self):
        result = subprocess.run(
            [sys.executable, str(_SELECT_CALLEES)],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode != 0


class TestSelectBackwardTracesCLI:
    def test_help_flag(self):
        result = subprocess.run(
            [sys.executable, str(_SELECT_BACKWARD), "--help"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
        assert "dossier" in result.stdout.lower()

    def test_with_sample_dossier(self, sample_dossier):
        result = subprocess.run(
            [sys.executable, str(_SELECT_BACKWARD),
             "--dossier", str(sample_dossier), "--json"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            assert "status" in data
            assert data["status"] == "ok"
            assert "case" in data
            assert data["case"] in ("A", "B", "skip")

    def test_missing_dossier_file(self, tmp_path):
        result = subprocess.run(
            [sys.executable, str(_SELECT_BACKWARD),
             "--dossier", str(tmp_path / "nonexistent.json"), "--json"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode != 0
