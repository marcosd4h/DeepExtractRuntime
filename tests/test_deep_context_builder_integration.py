"""Integration tests for the deep-context-builder skill."""

from __future__ import annotations

import json
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parent.parent


def _load_json(rel_path: str) -> dict:
    return json.loads((AGENT_DIR / rel_path).read_text(encoding="utf-8"))


class TestDeepContextBuilderRegistry:
    """Verify deep-context-builder is properly registered and wired."""

    def test_skill_in_registry(self):
        registry = _load_json("skills/registry.json")
        assert "deep-context-builder" in registry["skills"]
        entry = registry["skills"]["deep-context-builder"]
        assert entry["type"] == "documentation"
        assert entry["entry_scripts"] == []
        assert entry["cacheable"] is False
        assert entry["json_output"] is False

    def test_depends_on_correct(self):
        registry = _load_json("skills/registry.json")
        deps = set(registry["skills"]["deep-context-builder"]["depends_on"])
        expected = {"decompiled-code-extractor", "classify-functions", "callgraph-tracer",
                    "data-flow-tracer", "map-attack-surface"}
        assert deps == expected

    def test_skill_files_exist(self):
        skill_dir = AGENT_DIR / "skills" / "deep-context-builder"
        assert (skill_dir / "SKILL.md").is_file()
        assert (skill_dir / "reference.md").is_file()
        assert (skill_dir / "README.md").is_file()

    def test_no_scripts_directory(self):
        skill_dir = AGENT_DIR / "skills" / "deep-context-builder"
        assert not (skill_dir / "scripts").exists()

    def test_explain_command_wires_skill(self):
        registry = _load_json("commands/registry.json")
        explain = registry["commands"]["explain"]
        all_skills = explain.get("skills_used", []) + explain.get("methodologies_used", [])
        assert "deep-context-builder" in all_skills

    def test_audit_command_wires_skill(self):
        registry = _load_json("commands/registry.json")
        audit = registry["commands"]["audit"]
        all_skills = audit.get("skills_used", []) + audit.get("methodologies_used", [])
        assert "deep-context-builder" in all_skills

    def test_unrelated_commands_not_affected(self):
        registry = _load_json("commands/registry.json")
        for cmd_name in ("triage", "search", "verify", "xref", "brainstorm"):
            cmd = registry["commands"][cmd_name]
            all_skills = cmd.get("skills_used", []) + cmd.get("methodologies_used", [])
            assert "deep-context-builder" not in all_skills, (
                f"Command /{cmd_name} should not reference deep-context-builder"
            )
