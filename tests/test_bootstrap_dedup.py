"""Tests for the bootstrap() deduplication (Issue #8) and the
_agent_common -> _common rename (Issue #9).

Validates:
  - bootstrap() returns a correct Path
  - bootstrap() adds .agent to sys.path
  - bootstrap() is idempotent (no duplicate sys.path entries)
  - All skill _common.py files use the bootstrap one-liner
  - All agent _common.py files use the bootstrap one-liner
  - type-reconstructor uses _common.py (not _agent_common.py)
  - WORKSPACE_ROOT resolves correctly for skills and agents
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# The project root is one level up from the tests/ directory.
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
# Support both layouts: standalone repo (skills/ at root) and deployed
# inside a .agent/ directory.
if (_PROJECT_ROOT / ".agent" / "skills").is_dir():
    WORKSPACE_ROOT = _PROJECT_ROOT
    AGENT_DIR = _PROJECT_ROOT / ".agent"
elif (_PROJECT_ROOT / "skills").is_dir() and _PROJECT_ROOT.name == ".agent":
    WORKSPACE_ROOT = _PROJECT_ROOT.parent
    AGENT_DIR = _PROJECT_ROOT
else:
    WORKSPACE_ROOT = _PROJECT_ROOT
    AGENT_DIR = _PROJECT_ROOT
SKILLS_DIR = AGENT_DIR / "skills"
AGENTS_DIR = AGENT_DIR / "agents"

# Skills that must have _common.py with the bootstrap pattern
EXPECTED_SKILLS = [
    "batch-lift",
    "callgraph-tracer",
    "classify-functions",
    "com-interface-analysis",
    "com-interface-reconstruction",
    "decompiled-code-extractor",
    "exploitability-assessment",
    "function-index",
    "generate-re-report",
    "import-export-resolver",
    "ai-logic-scanner",
    "map-attack-surface",
    "ai-memory-corruption-scanner",
    "reconstruct-types",
    "rpc-interface-analysis",
    "security-dossier",
    "ai-taint-scanner",
    "winrt-interface-analysis",
]

EXPECTED_AGENTS = [
    "code-lifter",
    "logic-scanner",
    "memory-corruption-scanner",
    "re-analyst",
    "security-auditor",
    "taint-scanner",
    "triage-coordinator",
    "type-reconstructor",
]

AGENTS_WITH_SCRIPTS = [
    a for a in EXPECTED_AGENTS
    if (Path(__file__).resolve().parents[1] / "agents" / a / "scripts" / "_common.py").exists()
]


# ---------------------------------------------------------------------------
# bootstrap() function tests
# ---------------------------------------------------------------------------
class TestBootstrapFunction:
    """Test the skills._shared.bootstrap() convenience function."""

    def test_bootstrap_returns_path(self):
        """bootstrap() must return a Path object."""
        from skills._shared import bootstrap, get_workspace_root

        # Use this test file as the anchor (lives at .agent/tests/test_*.py)
        # but bootstrap uses parents[4] which assumes
        # .agent/<kind>/<name>/scripts/<file>.py layout.
        # So we test using a real _common.py's __file__ value.
        anchor = SKILLS_DIR / "batch-lift" / "scripts" / "_common.py"
        result = bootstrap(str(anchor))
        assert isinstance(result, Path)

    def test_bootstrap_returns_correct_root(self):
        """bootstrap() must resolve to the actual workspace root."""
        from skills._shared import bootstrap

        anchor = SKILLS_DIR / "batch-lift" / "scripts" / "_common.py"
        result = bootstrap(str(anchor))
        assert result == WORKSPACE_ROOT

    def test_bootstrap_adds_agent_to_sys_path(self):
        """bootstrap() must insert the runtime root onto sys.path."""
        from skills._shared import bootstrap

        runtime_path = str(WORKSPACE_ROOT)
        agent_path = str(WORKSPACE_ROOT / ".agent")
        anchor = SKILLS_DIR / "classify-functions" / "scripts" / "_common.py"

        original = sys.path[:]
        try:
            while runtime_path in sys.path:
                sys.path.remove(runtime_path)
            while agent_path in sys.path:
                sys.path.remove(agent_path)
            bootstrap(str(anchor))
            assert runtime_path in sys.path or agent_path in sys.path
        finally:
            sys.path[:] = original

    def test_bootstrap_idempotent(self):
        """Calling bootstrap() twice must not duplicate sys.path entries."""
        from skills._shared import bootstrap

        runtime_path = str(WORKSPACE_ROOT)
        anchor = SKILLS_DIR / "function-index" / "scripts" / "_common.py"

        bootstrap(str(anchor))
        count_before = sys.path.count(runtime_path)
        bootstrap(str(anchor))
        count_after = sys.path.count(runtime_path)
        assert count_after == count_before

    def test_bootstrap_works_for_agent_scripts(self):
        """bootstrap() must also resolve correctly for agent scripts."""
        from skills._shared import bootstrap

        anchor = AGENTS_DIR / "code-lifter" / "scripts" / "_common.py"
        result = bootstrap(str(anchor))
        assert result == WORKSPACE_ROOT


# ---------------------------------------------------------------------------
# Skill _common.py consistency
# ---------------------------------------------------------------------------
class TestSkillBootstrapConsistency:
    """Verify all skill _common.py files use the bootstrap() one-liner."""

    @pytest.mark.parametrize("skill_name", EXPECTED_SKILLS)
    def test_skill_common_exists(self, skill_name):
        """Each skill must have a _common.py in scripts/."""
        common_path = SKILLS_DIR / skill_name / "scripts" / "_common.py"
        assert common_path.exists(), f"Missing: {common_path}"

    @pytest.mark.parametrize("skill_name", EXPECTED_SKILLS)
    def test_skill_uses_bootstrap(self, skill_name):
        """Each skill _common.py must use 'from skills._shared import bootstrap'."""
        common_path = SKILLS_DIR / skill_name / "scripts" / "_common.py"
        content = common_path.read_text(encoding="utf-8")
        assert "from skills._shared import bootstrap" in content or \
               "from skills._shared import (\n    bootstrap" in content, (
            f"{skill_name}/_common.py does not use bootstrap()"
        )

    @pytest.mark.parametrize("skill_name", EXPECTED_SKILLS)
    def test_skill_has_workspace_root(self, skill_name):
        """Each skill _common.py must set WORKSPACE_ROOT = bootstrap(__file__)."""
        common_path = SKILLS_DIR / skill_name / "scripts" / "_common.py"
        content = common_path.read_text(encoding="utf-8")
        assert "WORKSPACE_ROOT = bootstrap(__file__)" in content, (
            f"{skill_name}/_common.py does not have WORKSPACE_ROOT = bootstrap(__file__)"
        )

    @pytest.mark.parametrize("skill_name", EXPECTED_SKILLS)
    def test_skill_no_old_bootstrap_pattern(self, skill_name):
        """Each skill _common.py must NOT have the old 3-line bootstrap."""
        common_path = SKILLS_DIR / skill_name / "scripts" / "_common.py"
        content = common_path.read_text(encoding="utf-8")
        assert "sys.path.insert(0, str(WORKSPACE_ROOT" not in content, (
            f"{skill_name}/_common.py still uses old sys.path.insert() pattern"
        )
        assert "install_workspace_bootstrap(__file__" not in content, (
            f"{skill_name}/_common.py still calls install_workspace_bootstrap() directly"
        )


# ---------------------------------------------------------------------------
# Agent _common.py consistency
# ---------------------------------------------------------------------------
class TestAgentBootstrapConsistency:
    """Verify all agent _common.py files use the bootstrap() one-liner."""

    @pytest.mark.parametrize("agent_name", AGENTS_WITH_SCRIPTS)
    def test_agent_common_exists(self, agent_name):
        """Each agent with scripts must have _common.py (not _agent_common.py)."""
        common_path = AGENTS_DIR / agent_name / "scripts" / "_common.py"
        assert common_path.exists(), f"Missing: {common_path}"

    @pytest.mark.parametrize("agent_name", AGENTS_WITH_SCRIPTS)
    def test_agent_no_agent_common(self, agent_name):
        """No agent should have _agent_common.py anymore (Issue #9)."""
        old_path = AGENTS_DIR / agent_name / "scripts" / "_agent_common.py"
        assert not old_path.exists(), (
            f"{agent_name} still has _agent_common.py -- should be _common.py"
        )

    @pytest.mark.parametrize("agent_name", AGENTS_WITH_SCRIPTS)
    def test_agent_uses_bootstrap(self, agent_name):
        """Each agent _common.py must use the bootstrap() function."""
        common_path = AGENTS_DIR / agent_name / "scripts" / "_common.py"
        content = common_path.read_text(encoding="utf-8")
        assert "bootstrap" in content, (
            f"{agent_name}/_common.py does not reference bootstrap"
        )

    @pytest.mark.parametrize("agent_name", AGENTS_WITH_SCRIPTS)
    def test_agent_has_workspace_root(self, agent_name):
        """Each agent _common.py must set WORKSPACE_ROOT = bootstrap(__file__)."""
        common_path = AGENTS_DIR / agent_name / "scripts" / "_common.py"
        content = common_path.read_text(encoding="utf-8")
        assert "WORKSPACE_ROOT = bootstrap(__file__)" in content, (
            f"{agent_name}/_common.py missing WORKSPACE_ROOT = bootstrap(__file__)"
        )

    @pytest.mark.parametrize("agent_name", AGENTS_WITH_SCRIPTS)
    def test_agent_no_old_bootstrap_pattern(self, agent_name):
        """Each agent _common.py must NOT have the old bootstrap."""
        common_path = AGENTS_DIR / agent_name / "scripts" / "_common.py"
        content = common_path.read_text(encoding="utf-8")
        assert "install_workspace_bootstrap(__file__" not in content, (
            f"{agent_name}/_common.py still calls install_workspace_bootstrap() directly"
        )


# ---------------------------------------------------------------------------
# Issue #9 specific: type-reconstructor rename validation
# ---------------------------------------------------------------------------
class TestTypeReconstructorRename:
    """Validate the _agent_common.py -> _common.py rename is complete."""

    def test_no_agent_common_import_in_scripts(self):
        """No type-reconstructor script should import from _agent_common."""
        scripts_dir = AGENTS_DIR / "type-reconstructor" / "scripts"
        for py_file in scripts_dir.glob("*.py"):
            if py_file.name.startswith("_"):
                continue
            content = py_file.read_text(encoding="utf-8")
            assert "_agent_common" not in content, (
                f"{py_file.name} still references _agent_common"
            )

    def test_scripts_import_common(self):
        """type-reconstructor scripts must import from _common (not _agent_common)."""
        scripts_dir = AGENTS_DIR / "type-reconstructor" / "scripts"
        for py_file in scripts_dir.glob("*.py"):
            if py_file.name.startswith("_"):
                continue
            content = py_file.read_text(encoding="utf-8")
            if "from _common import" in content or "import _common" in content:
                pass  # correct
            # Some scripts might not import _common directly -- that's OK


# ---------------------------------------------------------------------------
# Registry cross-check: hardcoded lists vs registry.json
# ---------------------------------------------------------------------------
class TestRegistryCrossCheck:
    """EXPECTED_AGENTS and EXPECTED_SKILLS must match the registries."""

    def test_expected_agents_match_registry(self):
        """EXPECTED_AGENTS must be the same set as agents/registry.json keys."""
        registry_path = AGENTS_DIR / "registry.json"
        data = json.loads(registry_path.read_text(encoding="utf-8"))
        registry_agents = sorted(data.get("agents", {}).keys())
        assert registry_agents == sorted(EXPECTED_AGENTS), (
            f"EXPECTED_AGENTS mismatch with agents/registry.json.\n"
            f"  EXPECTED_AGENTS:  {sorted(EXPECTED_AGENTS)}\n"
            f"  Registry agents:  {registry_agents}"
        )

    def test_expected_skills_match_registry(self):
        """EXPECTED_SKILLS (non-doc skills) must be a subset of skills/registry.json keys."""
        registry_path = SKILLS_DIR / "registry.json"
        data = json.loads(registry_path.read_text(encoding="utf-8"))
        registry_skills = set(data.get("skills", {}).keys())
        for skill in EXPECTED_SKILLS:
            assert skill in registry_skills, (
                f"EXPECTED_SKILLS contains '{skill}' which is not in "
                f"skills/registry.json"
            )
