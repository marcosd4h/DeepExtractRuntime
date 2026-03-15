"""Tests for the ai-logic-scanner skill -- registry, structure, and script logic."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

WORKSPACE = Path(__file__).resolve().parents[1]
SKILL_DIR = WORKSPACE / "skills" / "ai-logic-scanner"
SCRIPTS_DIR = SKILL_DIR / "scripts"
REFERENCE_DIR = SKILL_DIR / "reference"
SKILLS_REGISTRY = WORKSPACE / "skills" / "registry.json"
AGENTS_REGISTRY = WORKSPACE / "agents" / "registry.json"
COMMANDS_REGISTRY = WORKSPACE / "commands" / "registry.json"


class TestRegistryConsistency:
    def test_skill_directory_exists(self):
        assert SKILL_DIR.is_dir()

    def test_skill_md_exists(self):
        assert (SKILL_DIR / "SKILL.md").is_file()

    def test_scripts_directory_exists(self):
        assert SCRIPTS_DIR.is_dir()

    def test_common_module_exists(self):
        assert (SCRIPTS_DIR / "_common.py").is_file()

    def test_all_scripts_exist(self):
        expected = ["build_threat_model.py", "prepare_context.py"]
        for script in expected:
            assert (SCRIPTS_DIR / script).is_file(), f"Missing script: {script}"

    def test_reference_directory_exists(self):
        assert REFERENCE_DIR.is_dir()

    def test_skill_in_skills_registry(self):
        reg = json.loads(SKILLS_REGISTRY.read_text(encoding="utf-8"))
        skills = reg.get("skills", reg)
        assert "ai-logic-scanner" in skills

    def test_agent_in_agents_registry(self):
        reg = json.loads(AGENTS_REGISTRY.read_text(encoding="utf-8"))
        agents = reg.get("agents", reg)
        assert "logic-scanner" in agents

    def test_command_in_commands_registry(self):
        reg = json.loads(COMMANDS_REGISTRY.read_text(encoding="utf-8"))
        commands = reg.get("commands", reg)
        assert "ai-logical-bug-scan" in commands


class TestSkillFrontmatter:
    @pytest.fixture(autouse=True)
    def _load_frontmatter(self):
        text = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
        import yaml
        parts = text.split("---", 2)
        self.fm = yaml.safe_load(parts[1]) if len(parts) >= 3 else {}

    def test_name_matches_directory(self):
        assert self.fm.get("name") == "ai-logic-scanner"

    def test_description_present(self):
        assert self.fm.get("description")

    def test_description_has_trigger_phrases(self):
        desc = self.fm.get("description", "").lower()
        for phrase in ["logic bugs", "auth bypass", "confused deputy", "state machine"]:
            assert phrase in desc, f"Missing trigger phrase: {phrase}"

    def test_description_excludes_memory_phrases(self):
        desc = self.fm.get("description", "").lower()
        for phrase in ["buffer overflow", "integer overflow", "use-after-free"]:
            assert phrase not in desc, f"Unexpected memory phrase: {phrase}"


class TestCommonImports:
    def test_lean_common_exports(self):
        from conftest import import_skill_module
        mod = import_skill_module("ai-logic-scanner", "_common")
        for sym in ["WORKSPACE_ROOT", "resolve_db_path", "CrossModuleGraph", "emit_json", "status_message"]:
            assert hasattr(mod, sym), f"Missing export: {sym}"

    def test_lean_common_no_domain_constants(self):
        from conftest import import_skill_module
        mod = import_skill_module("ai-logic-scanner", "_common")
        for sym in ["LogicFinding", "compute_logic_score", "IMPACT_SEVERITY", "CallGraph"]:
            assert not hasattr(mod, sym), f"Unexpected domain import: {sym}"

class TestReferenceFiles:
    def test_vulnerability_patterns_exists(self):
        assert (REFERENCE_DIR / "vulnerability_patterns.md").is_file()

    def test_vulnerability_patterns_has_sections(self):
        text = (REFERENCE_DIR / "vulnerability_patterns.md").read_text(encoding="utf-8")
        for cwe in ["CWE-287", "CWE-863", "CWE-269"]:
            assert cwe in text, f"Missing pattern: {cwe}"

    def test_decompiler_pitfalls_exists(self):
        assert (REFERENCE_DIR / "decompiler_pitfalls.md").is_file()


class TestBuildThreatModel:
    def test_infer_service_type_rpc(self):
        from conftest import import_skill_module
        mod = import_skill_module("ai-logic-scanner", "build_threat_model")
        result = mod._infer_service_type([
            {"entry_type": "RPC_HANDLER"},
            {"entry_type": "RPC_HANDLER"},
            {"entry_type": "EXPORT_DLL"},
        ])
        assert result == "rpc_service"

    def test_infer_service_type_com(self):
        from conftest import import_skill_module
        mod = import_skill_module("ai-logic-scanner", "build_threat_model")
        result = mod._infer_service_type([
            {"entry_type": "COM_METHOD"},
            {"entry_type": "COM_METHOD"},
            {"entry_type": "EXPORT_DLL"},
        ])
        assert result == "com_server"

    def test_infer_attacker_model(self):
        from conftest import import_skill_module
        mod = import_skill_module("ai-logic-scanner", "build_threat_model")
        assert "remote" in mod._infer_attacker_model("rpc_service")


class TestVulnerabilityPatternsCompleteness:
    """Verify all API misuse categories have reference patterns."""

    @pytest.fixture(autouse=True)
    def _load_patterns(self):
        self.text = (REFERENCE_DIR / "vulnerability_patterns.md").read_text(encoding="utf-8")

    def test_has_createprocess_pattern(self):
        assert "CreateProcessW" in self.text

    def test_has_loadlibrary_pattern(self):
        assert "LoadLibraryW" in self.text
        assert "CWE-426" in self.text

    def test_has_createservice_pattern(self):
        assert "CreateServiceW" in self.text
        assert "lpBinaryPathName" in self.text

    def test_has_com_clsid_pattern(self):
        assert "CLSIDFromProgID" in self.text or "CoCreateInstance" in self.text
        assert "CWE-94" in self.text

    def test_has_shellexecute_pattern(self):
        assert "ShellExecuteW" in self.text
        assert "CWE-88" in self.text

    def test_has_all_patterns(self):
        pattern_headings = [m for m in re.finditer(r"^## \d+\.", self.text, re.MULTILINE)]
        assert len(pattern_headings) == 14, f"Expected 14 patterns, found {len(pattern_headings)}"

    def test_each_pattern_has_required_sections(self):
        for heading in ["Vulnerable pattern:", "Data flow:", "Exploitation:", "Safe pattern:"]:
            count = self.text.count(f"**{heading}**")
            assert count == 14, f"'{heading}' appears {count} times, expected 14"
