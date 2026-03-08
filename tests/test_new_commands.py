"""Tests for newly added commands: /hunt-execute, /batch-audit, /xref.

Validates that the new commands are properly registered, documented,
and reference valid skills and agents.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

_AGENT_DIR = Path(__file__).resolve().parent.parent
COMMANDS_DIR = _AGENT_DIR / "commands"
SKILLS_DIR = _AGENT_DIR / "skills"
COMMAND_REGISTRY = COMMANDS_DIR / "registry.json"
SKILL_REGISTRY = SKILLS_DIR / "registry.json"

NEW_COMMANDS = ["hunt-execute", "batch-audit", "xref"]


def _load_cmd_registry() -> dict:
    return json.loads(COMMAND_REGISTRY.read_text(encoding="utf-8"))["commands"]


def _load_skill_registry() -> dict:
    return json.loads(SKILL_REGISTRY.read_text(encoding="utf-8"))["skills"]


# ======================================================================
# 1. Command file existence
# ======================================================================


class TestNewCommandFiles:

    @pytest.mark.parametrize("cmd", NEW_COMMANDS)
    def test_command_md_exists(self, cmd):
        assert (COMMANDS_DIR / f"{cmd}.md").exists(), (
            f"Command file {cmd}.md not found in {COMMANDS_DIR}"
        )

    @pytest.mark.parametrize("cmd", NEW_COMMANDS)
    def test_command_md_not_empty(self, cmd):
        text = (COMMANDS_DIR / f"{cmd}.md").read_text(encoding="utf-8")
        assert len(text) > 100, f"{cmd}.md is too short to be a valid command"


# ======================================================================
# 2. Command registry entries
# ======================================================================


class TestNewCommandRegistry:

    @pytest.fixture(autouse=True)
    def _load(self):
        self.reg = _load_cmd_registry()

    @pytest.mark.parametrize("cmd", NEW_COMMANDS)
    def test_command_is_registered(self, cmd):
        assert cmd in self.reg, f"/{cmd} not found in commands/registry.json"

    @pytest.mark.parametrize("cmd", NEW_COMMANDS)
    def test_command_has_file(self, cmd):
        assert self.reg[cmd].get("file") == f"{cmd}.md"

    @pytest.mark.parametrize("cmd", NEW_COMMANDS)
    def test_command_has_purpose(self, cmd):
        assert self.reg[cmd].get("purpose"), f"/{cmd} missing purpose"

    @pytest.mark.parametrize("cmd", NEW_COMMANDS)
    def test_command_has_parameters(self, cmd):
        assert self.reg[cmd].get("parameters") is not None

    @pytest.mark.parametrize("cmd", NEW_COMMANDS)
    def test_command_skills_exist_in_skill_registry(self, cmd):
        skill_reg = _load_skill_registry()
        for skill in self.reg[cmd].get("skills_used", []):
            assert skill in skill_reg, (
                f"/{cmd} references skill '{skill}' not in skills/registry.json"
            )


# ======================================================================
# 3. Command-specific content validation
# ======================================================================


class TestHuntExecuteCommand:

    @pytest.fixture(autouse=True)
    def _load(self):
        self.text = (COMMANDS_DIR / "hunt-execute.md").read_text(encoding="utf-8")
        self.reg = _load_cmd_registry()["hunt-execute"]

    def test_uses_grind_loop(self):
        assert self.reg["grind_loop"] is True

    def test_uses_workspace_protocol(self):
        assert self.reg["workspace_protocol"] is True

    def test_references_hunt_plan(self):
        assert "hunt" in self.text.lower()

    def test_has_confidence_scoring(self):
        assert "CONFIRMED" in self.text
        assert "REFUTED" in self.text

    def test_references_taint_skill(self):
        assert "taint-analysis" in self.reg["skills_used"]

    def test_references_exploitability(self):
        assert "exploitability-assessment" in self.reg["skills_used"]


class TestBatchAuditCommand:

    @pytest.fixture(autouse=True)
    def _load(self):
        self.text = (COMMANDS_DIR / "batch-audit.md").read_text(encoding="utf-8")
        self.reg = _load_cmd_registry()["batch-audit"]

    def test_uses_grind_loop(self):
        assert self.reg["grind_loop"] is True

    def test_uses_workspace_protocol(self):
        assert self.reg["workspace_protocol"] is True

    def test_has_top_n_parameter(self):
        assert "--top" in self.text

    def test_has_min_score_parameter(self):
        assert "--min-score" in self.text

    def test_references_security_dossier(self):
        assert "security-dossier" in self.reg["skills_used"]

    def test_references_taint(self):
        assert "taint-analysis" in self.reg["skills_used"]

    def test_references_exploitability(self):
        assert "exploitability-assessment" in self.reg["skills_used"]

    def test_has_class_mode(self):
        assert "--class" in self.text


class TestXrefCommand:

    @pytest.fixture(autouse=True)
    def _load(self):
        self.text = (COMMANDS_DIR / "xref.md").read_text(encoding="utf-8")
        self.reg = _load_cmd_registry()["xref"]

    def test_does_not_use_grind_loop(self):
        assert self.reg["grind_loop"] is False

    def test_does_not_use_workspace_protocol(self):
        assert self.reg["workspace_protocol"] is False

    def test_references_callgraph_tracer(self):
        assert "callgraph-tracer" in self.reg["skills_used"]

    def test_references_function_index(self):
        assert "function-index" in self.reg["skills_used"]

    def test_has_inbound_outbound_sections(self):
        assert "Inbound" in self.text or "Caller" in self.text
        assert "Outbound" in self.text or "Callee" in self.text

    def test_listed_in_readme(self):
        readme = (COMMANDS_DIR / "README.md").read_text(encoding="utf-8")
        assert "xref.md" in readme


# ======================================================================
# 4. README.md updated
# ======================================================================


class TestReadmeUpdated:

    @pytest.fixture(autouse=True)
    def _load(self):
        self.text = (COMMANDS_DIR / "README.md").read_text(encoding="utf-8")

    @pytest.mark.parametrize("cmd_file", ["hunt-execute.md", "batch-audit.md", "xref.md"])
    def test_command_file_in_readme(self, cmd_file):
        assert cmd_file in self.text, f"{cmd_file} not listed in commands/README.md"

    def test_hunt_execute_in_table(self):
        assert "/hunt-execute" in self.text

    def test_batch_audit_in_table(self):
        assert "/batch-audit" in self.text

    def test_xref_in_table(self):
        assert "/xref" in self.text
