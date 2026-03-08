"""Regression tests for privilege-boundary batch-audit wiring."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


AGENT_DIR = Path(__file__).resolve().parent.parent
COMMANDS_DIR = AGENT_DIR / "commands"
COMMAND_REGISTRY = COMMANDS_DIR / "registry.json"

INTERFACE_SKILLS = {
    "rpc-interface-analysis",
    "com-interface-analysis",
    "winrt-interface-analysis",
}


def _load_commands() -> dict:
    return json.loads(COMMAND_REGISTRY.read_text(encoding="utf-8"))["commands"]


class TestPrivilegeBoundaryBatchAuditRegistry:
    def test_batch_audit_lists_interface_skills(self):
        skills = set(_load_commands()["batch-audit"]["skills_used"])
        assert INTERFACE_SKILLS.issubset(skills)

    def test_batch_audit_parameters_include_privilege_boundary(self):
        params = _load_commands()["batch-audit"]["parameters"]
        assert "--privilege-boundary" in params


class TestPrivilegeBoundaryBatchAuditCommandMd:
    @pytest.fixture(autouse=True)
    def _load(self):
        self.text = (COMMANDS_DIR / "batch-audit.md").read_text(encoding="utf-8")

    def test_command_mentions_privilege_boundary_mode(self):
        assert "--privilege-boundary" in self.text
        assert "module-scoped" in self.text

    def test_command_references_interface_discovery_scripts(self):
        assert "map_rpc_surface.py" in self.text
        assert "find_com_privesc.py" in self.text
        assert "find_winrt_privesc.py" in self.text

    def test_command_labels_discovery_sources(self):
        assert "RPC_HANDLER" in self.text
        assert "COM_METHOD" in self.text
        assert "WINRT_METHOD" in self.text


class TestPrivilegeBoundaryNegativeChecks:
    @pytest.mark.parametrize("cmd_name", ["xref", "cache-manage", "runs"])
    def test_unrelated_commands_do_not_gain_interface_skills(self, cmd_name):
        skills = set(_load_commands()[cmd_name]["skills_used"])
        assert INTERFACE_SKILLS.isdisjoint(skills)
