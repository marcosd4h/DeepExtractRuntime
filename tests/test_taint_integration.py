"""Validate taint-analysis skill integration across commands, agents, and skills.

Tests that the taint-analysis skill is properly wired into the registries,
command definitions, agent definitions, and skill SKILL.md cross-references.
These tests serve as regression guards -- if a future edit removes a taint
reference or breaks a registry entry, the suite will catch it.
"""

import json
from pathlib import Path

import pytest

AGENT_DIR = Path(__file__).resolve().parent.parent
SKILLS_DIR = AGENT_DIR / "skills"
AGENTS_DIR = AGENT_DIR / "agents"
COMMANDS_DIR = AGENT_DIR / "commands"
SKILL_REGISTRY = SKILLS_DIR / "registry.json"
AGENT_REGISTRY = AGENTS_DIR / "registry.json"
COMMAND_REGISTRY = COMMANDS_DIR / "registry.json"

TAINT_SKILL = "taint-analysis"


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# ======================================================================
# 1. Skills registry
# ======================================================================

class TestTaintSkillRegistry:
    """taint-analysis must be registered and well-formed in skills/registry.json."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.reg = _load_json(SKILL_REGISTRY)["skills"]

    def test_taint_skill_is_registered(self):
        assert TAINT_SKILL in self.reg

    def test_taint_skill_type_is_security(self):
        assert self.reg[TAINT_SKILL]["type"] == "security"

    def test_taint_skill_has_entry_scripts(self):
        scripts = self.reg[TAINT_SKILL].get("entry_scripts", [])
        names = {s["script"] for s in scripts}
        assert "taint_function.py" in names
        assert "trace_taint_forward.py" in names
        assert "trace_taint_backward.py" in names
        assert "generate_taint_report.py" in names

    def test_taint_skill_depends_on_data_flow(self):
        deps = self.reg[TAINT_SKILL].get("depends_on", [])
        assert "data-flow-tracer" in deps
        assert "callgraph-tracer" in deps
        assert "decompiled-code-extractor" in deps

    def test_taint_skill_is_cacheable(self):
        assert self.reg[TAINT_SKILL].get("cacheable") is True

    def test_taint_skill_supports_json(self):
        assert self.reg[TAINT_SKILL].get("json_output") is True


# ======================================================================
# 2. Command registry integration
# ======================================================================

class TestTaintCommandRegistryIntegration:
    """Commands that should use taint-analysis must list it in skills_used."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.reg = _load_json(COMMAND_REGISTRY)["commands"]

    @pytest.mark.parametrize("cmd", ["taint", "hunt", "audit", "full-report", "trace-export"])
    def test_command_lists_taint_skill(self, cmd):
        skills = self.reg[cmd].get("skills_used", [])
        assert TAINT_SKILL in skills, (
            f"Command '/{cmd}' should list '{TAINT_SKILL}' in skills_used"
        )

    @pytest.mark.parametrize("cmd", [
        "lift-class", "compare-modules", "verify", "explain",
        "search", "reconstruct-types", "data-flow", "state-machines",
        "cache-manage", "data-flow-cross", "verify-batch", "health", "brainstorm",
    ])
    def test_unrelated_command_does_not_list_taint(self, cmd):
        skills = self.reg[cmd].get("skills_used", [])
        assert TAINT_SKILL not in skills, (
            f"Command '/{cmd}' should NOT list '{TAINT_SKILL}' in skills_used"
        )


# ======================================================================
# 3. Agent registry integration
# ======================================================================

class TestTaintAgentRegistryIntegration:
    """Agents that should use taint-analysis must list it in skills_used."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.reg = _load_json(AGENT_REGISTRY)["agents"]

    @pytest.mark.parametrize("agent", ["triage-coordinator", "re-analyst"])
    def test_agent_lists_taint_skill(self, agent):
        skills = self.reg[agent].get("skills_used", [])
        assert TAINT_SKILL in skills, (
            f"Agent '{agent}' should list '{TAINT_SKILL}' in skills_used"
        )

    @pytest.mark.parametrize("agent", ["code-lifter", "type-reconstructor", "verifier"])
    def test_unrelated_agent_does_not_list_taint(self, agent):
        skills = self.reg[agent].get("skills_used", [])
        assert TAINT_SKILL not in skills, (
            f"Agent '{agent}' should NOT list '{TAINT_SKILL}' in skills_used"
        )


# ======================================================================
# 4. deep-research-prompt depends_on
# ======================================================================

class TestTaintDeepResearchDependency:
    """deep-research-prompt must declare taint-analysis as a dependency."""

    def test_deep_research_depends_on_taint(self):
        reg = _load_json(SKILL_REGISTRY)["skills"]
        deps = reg["deep-research-prompt"].get("depends_on", [])
        assert TAINT_SKILL in deps

    def test_adversarial_reasoning_depends_on_taint(self):
        reg = _load_json(SKILL_REGISTRY)["skills"]
        deps = reg["adversarial-reasoning"].get("depends_on", [])
        assert TAINT_SKILL in deps


# ======================================================================
# 5. Command .md files reference taint-analysis
# ======================================================================

class TestTaintCommandMdReferences:
    """Command definitions that use taint-analysis must reference it in their body."""

    @pytest.mark.parametrize("cmd_file", [
        "audit-function.md",
        "full-report.md",
        "trace-export.md",
        "taint.md",
        "hunt.md",
    ])
    def test_command_md_mentions_taint(self, cmd_file):
        path = COMMANDS_DIR / cmd_file
        text = path.read_text(encoding="utf-8")
        assert "taint" in text.lower(), (
            f"Command '{cmd_file}' should reference taint analysis in its body"
        )

    def test_audit_has_taint_step(self):
        text = (COMMANDS_DIR / "audit-function.md").read_text(encoding="utf-8")
        assert "taint_function.py" in text
        assert "taint_forward" in text

    def test_full_report_has_taint_step(self):
        text = (COMMANDS_DIR / "full-report.md").read_text(encoding="utf-8")
        assert "taint_function.py" in text
        assert "Taint analysis for top entry points" in text

    def test_trace_export_has_taint_step(self):
        text = (COMMANDS_DIR / "trace-export.md").read_text(encoding="utf-8")
        assert "taint_function.py" in text
        assert "Taint Summary" in text


# ======================================================================
# 6. Agent .md files reference taint-analysis
# ======================================================================

class TestTaintAgentMdReferences:
    """Agent definitions that use taint-analysis must reference it."""

    def test_triage_coordinator_skill_catalog(self):
        text = (AGENTS_DIR / "triage-coordinator.md").read_text(encoding="utf-8")
        assert "taint-analysis" in text
        assert "taint_function.py" in text

    def test_triage_coordinator_security_pipeline(self):
        text = (AGENTS_DIR / "triage-coordinator.md").read_text(encoding="utf-8")
        assert "taint-analysis/taint_function.py" in text

    def test_triage_coordinator_workflow_template(self):
        text = (AGENTS_DIR / "triage-coordinator.md").read_text(encoding="utf-8")
        assert "taint-analysis (per top export)" in text

    def test_re_analyst_has_taint_scripts(self):
        text = (AGENTS_DIR / "re-analyst.md").read_text(encoding="utf-8")
        assert "taint_function.py" in text
        assert "trace_taint_forward.py" in text
        assert "trace_taint_backward.py" in text


# ======================================================================
# 7. Skill SKILL.md cross-references
# ======================================================================

class TestTaintSkillCrossReferences:
    """Skills that reference taint-analysis must do so in their SKILL.md."""

    def test_security_dossier_integration_table(self):
        text = (SKILLS_DIR / "security-dossier" / "SKILL.md").read_text(encoding="utf-8")
        assert "taint-analysis" in text
        assert "taint_function.py" in text

    def test_deep_research_data_sources(self):
        text = (SKILLS_DIR / "deep-research-prompt" / "SKILL.md").read_text(encoding="utf-8")
        assert "taint-analysis" in text
        assert "Taint Analysis" in text

    def test_taint_skill_md_exists(self):
        skill_md = SKILLS_DIR / TAINT_SKILL / "SKILL.md"
        assert skill_md.exists()

    def test_taint_skill_scripts_dir_exists(self):
        scripts_dir = SKILLS_DIR / TAINT_SKILL / "scripts"
        assert scripts_dir.is_dir()

    def test_taint_skill_has_common_py(self):
        common = SKILLS_DIR / TAINT_SKILL / "scripts" / "_common.py"
        assert common.exists()
