"""Integration tests for the /runs command."""

from __future__ import annotations

import json
from pathlib import Path


AGENT_DIR = Path(__file__).resolve().parent.parent
COMMANDS_DIR = AGENT_DIR / "commands"
COMMAND_REGISTRY = COMMANDS_DIR / "registry.json"


def _load_registry() -> dict:
    return json.loads(COMMAND_REGISTRY.read_text(encoding="utf-8"))["commands"]


class TestRunsCommandRegistry:
    def test_runs_registered(self):
        registry = _load_registry()
        assert "runs" in registry

    def test_runs_has_expected_contract(self):
        runs = _load_registry()["runs"]
        assert runs["file"] == "runs.md"
        assert runs["purpose"]
        assert runs["parameters"] == "list [module] | show <run_id> | latest [module]"
        assert runs["grind_loop"] is False
        assert runs["workspace_protocol"] is False
        assert runs["skills_used"] == []
        assert runs["agents_used"] == []


class TestRunsCommandDefinition:
    def test_runs_md_exists(self):
        assert (COMMANDS_DIR / "runs.md").exists()

    def test_runs_md_references_workspace_helpers(self):
        text = (COMMANDS_DIR / "runs.md").read_text(encoding="utf-8")
        assert "list_runs" in text
        assert "read_summary" in text
        assert "validate_workspace_run" in text

    def test_runs_md_has_supported_subcommands(self):
        text = (COMMANDS_DIR / "runs.md").read_text(encoding="utf-8")
        assert "/runs list" in text
        assert "/runs show" in text
        assert "/runs latest" in text


class TestRunsReadmeIntegration:
    def test_runs_listed_in_readme(self):
        text = (COMMANDS_DIR / "README.md").read_text(encoding="utf-8")
        assert "/runs" in text
        assert "runs.md" in text
