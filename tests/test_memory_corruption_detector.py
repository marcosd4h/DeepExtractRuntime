"""Tests for the memory-corruption-detector skill -- registry and structural validation."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

WORKSPACE = Path(__file__).resolve().parents[1]
SKILL_DIR = WORKSPACE / "skills" / "memory-corruption-detector"
SCRIPTS_DIR = SKILL_DIR / "scripts"
SKILLS_REGISTRY = WORKSPACE / "skills" / "registry.json"
COMMANDS_REGISTRY = WORKSPACE / "commands" / "registry.json"


# ---------------------------------------------------------------------------
# Registry and structure tests
# ---------------------------------------------------------------------------

class TestRegistryConsistency:
    """Verify the skill is properly registered and structurally sound."""

    def test_skill_directory_exists(self):
        assert SKILL_DIR.is_dir(), f"Skill directory missing: {SKILL_DIR}"

    def test_skill_md_exists(self):
        assert (SKILL_DIR / "SKILL.md").is_file()

    def test_scripts_directory_exists(self):
        assert SCRIPTS_DIR.is_dir()

    def test_common_module_exists(self):
        assert (SCRIPTS_DIR / "_common.py").is_file()

    def test_all_scanner_scripts_exist(self):
        expected = [
            "scan_buffer_overflows.py",
            "scan_integer_issues.py",
            "scan_use_after_free.py",
            "scan_format_strings.py",
            "verify_findings.py",
        ]
        for script in expected:
            assert (SCRIPTS_DIR / script).is_file(), f"Missing script: {script}"

    def test_skill_in_registry(self):
        with open(SKILLS_REGISTRY) as f:
            registry = json.load(f)
        skills = registry.get("skills", {})
        assert "memory-corruption-detector" in skills

    def test_registry_entry_fields(self):
        with open(SKILLS_REGISTRY) as f:
            registry = json.load(f)
        entry = registry["skills"]["memory-corruption-detector"]
        assert entry["type"] == "security"
        assert entry["cacheable"] is True
        assert "memcorrupt_buffer" in entry.get("cache_keys", [])
        assert "decompiled-code-extractor" in entry.get("depends_on", [])
        assert entry["json_output"] is True

    def test_registry_scripts_exist_on_disk(self):
        with open(SKILLS_REGISTRY) as f:
            registry = json.load(f)
        entry = registry["skills"]["memory-corruption-detector"]
        for script_info in entry.get("entry_scripts", []):
            script_name = script_info["script"]
            assert (SCRIPTS_DIR / script_name).is_file(), f"Registered script missing: {script_name}"

    def test_command_in_registry(self):
        with open(COMMANDS_REGISTRY) as f:
            registry = json.load(f)
        commands = registry.get("commands", {})
        assert "memory-scan" in commands

    def test_command_references_skill(self):
        with open(COMMANDS_REGISTRY) as f:
            registry = json.load(f)
        cmd = registry["commands"]["memory-scan"]
        assert "memory-corruption-detector" in cmd.get("skills_used", [])

    def test_command_md_exists(self):
        cmd_file = WORKSPACE / "commands" / "memory-scan.md"
        assert cmd_file.is_file()


# ---------------------------------------------------------------------------
# SKILL.md frontmatter tests
# ---------------------------------------------------------------------------

class TestSkillFrontmatter:
    """Verify SKILL.md has valid frontmatter for discovery."""

    def test_frontmatter_present(self):
        content = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
        assert content.startswith("---"), "SKILL.md must start with ---"
        parts = content.split("---", 2)
        assert len(parts) >= 3, "SKILL.md must have --- delimited frontmatter"

    def test_name_matches_directory(self):
        content = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
        assert "name: memory-corruption-detector" in content

    def test_description_has_triggers(self):
        content = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
        triggers = ["buffer overflow", "memory corruption", "integer overflow",
                     "use-after-free", "format string"]
        for trigger in triggers:
            assert trigger.lower() in content.lower(), f"Missing trigger phrase: {trigger}"


# ---------------------------------------------------------------------------
# _common.py import tests
# ---------------------------------------------------------------------------

class TestCommonImports:
    """Verify _common.py provides expected symbols."""

    def test_common_has_expected_symbols(self):
        """Verify _common.py defines expected symbols by source inspection."""
        source = (SCRIPTS_DIR / "_common.py").read_text(encoding="utf-8")
        for symbol in [
            "MemCorruptionFinding",
            "ALLOC_APIS",
            "FREE_APIS",
            "COPY_APIS",
            "FORMAT_APIS",
            "compute_memcorrupt_score",
            "load_all_functions_slim",
        ]:
            assert symbol in source, f"_common.py missing symbol: {symbol}"
