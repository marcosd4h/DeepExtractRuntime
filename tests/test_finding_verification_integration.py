"""Integration tests for the finding-verification skill."""

from __future__ import annotations

import json
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parent.parent


def _load_json(rel_path: str) -> dict:
    return json.loads((AGENT_DIR / rel_path).read_text(encoding="utf-8"))


class TestFindingVerificationRegistry:
    """Verify finding-verification is properly registered and wired."""

    def test_skill_in_registry(self):
        registry = _load_json("skills/registry.json")
        assert "finding-verification" in registry["skills"]
        entry = registry["skills"]["finding-verification"]
        assert entry["type"] == "security"
        assert entry["entry_scripts"] == []
        assert entry["cacheable"] is False
        assert entry["json_output"] is False

    def test_depends_on_correct(self):
        registry = _load_json("skills/registry.json")
        deps = set(registry["skills"]["finding-verification"]["depends_on"])
        expected = {"taint-analysis", "data-flow-tracer",
                    "security-dossier", "exploitability-assessment",
                    "import-export-resolver"}
        assert deps == expected

    def test_skill_files_exist(self):
        skill_dir = AGENT_DIR / "skills" / "finding-verification"
        assert (skill_dir / "SKILL.md").is_file()
        assert (skill_dir / "reference.md").is_file()
        assert (skill_dir / "README.md").is_file()

    def test_no_scripts_directory(self):
        skill_dir = AGENT_DIR / "skills" / "finding-verification"
        assert not (skill_dir / "scripts").exists()

    def test_audit_command_wires_skill(self):
        registry = _load_json("commands/registry.json")
        audit = registry["commands"]["audit"]
        all_skills = audit.get("skills_used", []) + audit.get("methodologies_used", [])
        assert "finding-verification" in all_skills

    def test_hunt_execute_command_wires_skill(self):
        registry = _load_json("commands/registry.json")
        hunt_exec = registry["commands"]["hunt-execute"]
        all_skills = hunt_exec.get("skills_used", []) + hunt_exec.get("methodologies_used", [])
        assert "finding-verification" in all_skills

    def test_unrelated_commands_not_affected(self):
        registry = _load_json("commands/registry.json")
        for cmd_name in ("triage", "explain", "search", "verify", "xref"):
            cmd = registry["commands"][cmd_name]
            all_skills = cmd.get("skills_used", []) + cmd.get("methodologies_used", [])
            assert "finding-verification" not in all_skills, (
                f"Command /{cmd_name} should not reference finding-verification"
            )
