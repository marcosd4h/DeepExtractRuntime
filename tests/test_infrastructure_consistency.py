"""Infrastructure consistency validation for the DeepExtractIDA agent framework.

Validates that documentation, registries, and file structure are internally
consistent.  These tests act as a canary -- if a new skill, helper, or command
is added without updating the corresponding manifests the test suite will fail
with a clear message describing what is out of sync.

Contracts validated:
  1. skills/registry.json   <-> skills/ directories + entry_scripts
  2. agents/registry.json   <-> agents/ directories + entry_scripts
  3. commands/registry.json <-> commands/*.md files
  4. SKILL.md               <-> scripts/*.py in each skill
  5. agents/                structure (scripts/, _common.py)
  6. commands/              <-> commands/README.md file listing
  7. helpers/__init__.py    <-> actual helper module files
  8. test coverage breadth (advisory, not hard failure)
"""

import json
import re
import importlib
import ast
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

AGENT_DIR = Path(__file__).resolve().parent.parent          # .agent/
SKILLS_DIR = AGENT_DIR / "skills"
AGENTS_DIR = AGENT_DIR / "agents"
COMMANDS_DIR = AGENT_DIR / "commands"
HELPERS_DIR = AGENT_DIR / "helpers"
TESTS_DIR = AGENT_DIR / "tests"
SKILL_REGISTRY_PATH = SKILLS_DIR / "registry.json"
AGENT_REGISTRY_PATH = AGENTS_DIR / "registry.json"
COMMAND_REGISTRY_PATH = COMMANDS_DIR / "registry.json"
SKILLS_README_PATH = SKILLS_DIR / "README.md"
AGENTS_README_PATH = AGENTS_DIR / "README.md"
HOOKS_DIR = AGENT_DIR / "hooks"
HOOKS_README_PATH = HOOKS_DIR / "README.md"
HOOKS_CONFIG_PATH = AGENT_DIR / "hooks.json"
ROOT_README_PATH = AGENT_DIR / "README.md"
ARCHITECTURE_DOC_PATH = AGENT_DIR / "docs" / "architecture.md"

# Backwards-compat alias used by existing skill tests
REGISTRY_PATH = SKILL_REGISTRY_PATH

# Directories that are infrastructure, not actual skills/agents
SKILL_INFRASTRUCTURE_DIRS = {"_shared", "__pycache__"}
AGENT_INFRASTRUCTURE_DIRS = {"_shared", "__pycache__"}

# Skills that are documentation-only (no scripts/ directory expected)
DOCUMENTATION_ONLY_SKILLS = set()

# Skills that should have methodology_only: true in registry
METHODOLOGY_ONLY_SKILLS = DOCUMENTATION_ONLY_SKILLS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_registry() -> dict:
    """Load and return the skills section of registry.json."""
    data = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    return data.get("skills", {})


def _skill_directories() -> list[str]:
    """Return sorted list of actual skill directory names (excluding infra)."""
    return sorted(
        d.name for d in SKILLS_DIR.iterdir()
        if d.is_dir() and d.name not in SKILL_INFRASTRUCTURE_DIRS
    )


def _agent_directories() -> list[str]:
    """Return sorted list of actual agent directory names (excluding infra)."""
    return sorted(
        d.name for d in AGENTS_DIR.iterdir()
        if d.is_dir() and d.name not in AGENT_INFRASTRUCTURE_DIRS
    )


def _command_files() -> list[str]:
    """Return sorted list of command .md files (excluding README.md)."""
    return sorted(
        f.name for f in COMMANDS_DIR.glob("*.md")
        if f.name.lower() != "readme.md"
    )


def _helper_module_files() -> list[str]:
    """Return sorted list of helper .py module names (top-level, excluding __init__)."""
    return sorted(
        f.stem for f in HELPERS_DIR.glob("*.py")
        if f.name != "__init__.py"
    )


def _helper_subpackage_dirs() -> list[str]:
    """Return sorted list of helper sub-package directory names."""
    return sorted(
        d.name for d in HELPERS_DIR.iterdir()
        if d.is_dir() and d.name != "__pycache__" and (d / "__init__.py").exists()
    )


def _skill_script_files(skill_name: str) -> list[str]:
    """Return sorted list of .py script basenames in a skill's scripts/ dir.

    Excludes _common.py and __init__.py.
    """
    scripts_dir = SKILLS_DIR / skill_name / "scripts"
    if not scripts_dir.is_dir():
        return []
    return sorted(
        f.name for f in scripts_dir.glob("*.py")
        if f.name not in ("_common.py", "__init__.py")
    )


def _agent_script_files(agent_name: str) -> list[str]:
    """Return sorted list of .py entry-script basenames in an agent's scripts/ dir.

    Excludes private modules (files starting with ``_``) and ``__init__.py``.
    """
    scripts_dir = AGENTS_DIR / agent_name / "scripts"
    if not scripts_dir.is_dir():
        return []
    return sorted(
        f.name for f in scripts_dir.glob("*.py")
        if not f.name.startswith("_")
    )


def _load_agent_registry() -> dict:
    """Load and return the agents section of agents/registry.json."""
    data = json.loads(AGENT_REGISTRY_PATH.read_text(encoding="utf-8"))
    return data.get("agents", {})


def _load_command_registry() -> dict:
    """Load and return the commands section of commands/registry.json."""
    data = json.loads(COMMAND_REGISTRY_PATH.read_text(encoding="utf-8"))
    return data.get("commands", {})


def _load_hooks_config() -> dict:
    """Load and return the hooks mapping from hooks.json."""
    data = json.loads(HOOKS_CONFIG_PATH.read_text(encoding="utf-8"))
    return data.get("hooks", {})


def _extract_markdown_table_rows(text: str, heading: str) -> list[list[str]]:
    """Extract the first Markdown table that appears under *heading*."""
    lines = text.splitlines()
    in_section = False
    table_lines: list[str] = []
    started_table = False

    for line in lines:
        stripped = line.strip()
        if stripped == heading:
            in_section = True
            continue
        if not in_section:
            continue

        if not started_table:
            if stripped.startswith("|"):
                started_table = True
                table_lines.append(stripped)
                continue
            if stripped.startswith("## ") or stripped == "---":
                break
            continue

        if stripped.startswith("|"):
            table_lines.append(stripped)
            continue
        if stripped:
            break

    if len(table_lines) < 2:
        return []

    return [
        [cell.strip() for cell in line.strip().strip("|").split("|")]
        for line in table_lines[2:]
    ]


def _markdown_link_text(cell: str) -> str:
    """Return the visible text for a Markdown link cell."""
    match = re.search(r"\[([^\]]+)\]", cell)
    if match:
        return match.group(1)
    return cell.replace("`", "").replace("**", "").strip()


def _markdown_csv_items(cell: str) -> list[str]:
    """Split a comma-separated Markdown table cell into normalized items."""
    normalized = cell.replace("`", "").replace("**", "").strip()
    if normalized in {"", "--"}:
        return []
    return [item.strip() for item in normalized.split(",")]


def _hook_script_name(command: str) -> str:
    """Return the configured hook script basename from a command string."""
    return Path(command.split()[-1]).name


# ======================================================================
# 1. Skills registry.json consistency
# ======================================================================

class TestRegistryConsistency:
    """Every skill in registry.json must have a matching directory and scripts."""

    def test_registry_file_exists(self):
        assert REGISTRY_PATH.exists(), (
            f"registry.json not found at {REGISTRY_PATH}"
        )

    def test_registry_is_valid_json(self):
        data = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        assert "skills" in data, "registry.json must have a top-level 'skills' key"

    def test_every_registered_skill_has_directory(self):
        """Every skill listed in registry.json must have a directory in skills/."""
        registry = _load_registry()
        actual_dirs = set(_skill_directories())
        for skill_name in registry:
            assert skill_name in actual_dirs, (
                f"Skill '{skill_name}' is in registry.json but has no directory "
                f"at {SKILLS_DIR / skill_name}"
            )

    def test_every_skill_directory_is_registered(self):
        """Every skill directory (excluding infra) should be in registry.json."""
        registry = _load_registry()
        for skill_name in _skill_directories():
            assert skill_name in registry, (
                f"Skill directory '{skill_name}' exists at {SKILLS_DIR / skill_name} "
                f"but is not listed in registry.json"
            )

    def test_entry_scripts_exist_on_disk(self):
        """Every entry_scripts entry must have a matching .py file."""
        registry = _load_registry()
        missing = []
        for skill_name, meta in registry.items():
            for entry in meta.get("entry_scripts", []):
                script_name = entry.get("script", "")
                script_path = SKILLS_DIR / skill_name / "scripts" / script_name
                if not script_path.exists():
                    missing.append(f"{skill_name}/scripts/{script_name}")
        assert not missing, (
            f"Entry scripts listed in registry.json but missing on disk:\n"
            + "\n".join(f"  - {m}" for m in missing)
        )

    @pytest.mark.parametrize("skill_name", _skill_directories())
    def test_skill_has_skill_md(self, skill_name):
        """Every skill directory must have a SKILL.md file."""
        skill_md = SKILLS_DIR / skill_name / "SKILL.md"
        assert skill_md.exists(), (
            f"Skill '{skill_name}' is missing SKILL.md at {skill_md}"
        )

    @pytest.mark.parametrize(
        "skill_name",
        [s for s in _skill_directories() if s not in DOCUMENTATION_ONLY_SKILLS],
    )
    def test_skill_has_common_py(self, skill_name):
        """Every skill with scripts must have a _common.py bootstrap file."""
        common_py = SKILLS_DIR / skill_name / "scripts" / "_common.py"
        assert common_py.exists(), (
            f"Skill '{skill_name}' is missing scripts/_common.py at {common_py}"
        )

    def test_methodology_only_flag_matches_documentation_skills(self):
        """Skills with methodology_only: true must have empty entry_scripts."""
        registry = _load_registry()
        for skill_name, meta in registry.items():
            if meta.get("methodology_only"):
                assert skill_name in METHODOLOGY_ONLY_SKILLS, (
                    f"Skill '{skill_name}' has methodology_only=true but is not "
                    f"in METHODOLOGY_ONLY_SKILLS set"
                )
                assert meta.get("entry_scripts") == [], (
                    f"Skill '{skill_name}' has methodology_only=true but has "
                    f"non-empty entry_scripts"
                )
        for skill_name in METHODOLOGY_ONLY_SKILLS:
            if skill_name in registry:
                assert registry[skill_name].get("methodology_only") is True, (
                    f"Skill '{skill_name}' is documentation-only but missing "
                    f"methodology_only=true in registry"
                )


# ======================================================================
# 2. SKILL.md completeness
# ======================================================================

class TestSkillMdCompleteness:
    """Every script file in a skill's scripts/ dir should be mentioned in SKILL.md."""

    @pytest.mark.parametrize(
        "skill_name",
        [s for s in _skill_directories() if s not in DOCUMENTATION_ONLY_SKILLS],
    )
    def test_all_scripts_mentioned_in_skill_md(self, skill_name):
        """Each .py file in scripts/ (excluding _common.py) must appear in SKILL.md."""
        skill_md = SKILLS_DIR / skill_name / "SKILL.md"
        if not skill_md.exists():
            pytest.skip(f"No SKILL.md for {skill_name}")
        skill_md_text = skill_md.read_text(encoding="utf-8")
        scripts = _skill_script_files(skill_name)
        unmentioned = [
            s for s in scripts if s not in skill_md_text
        ]
        assert not unmentioned, (
            f"Skill '{skill_name}' SKILL.md does not mention these scripts:\n"
            + "\n".join(f"  - {s}" for s in unmentioned)
            + f"\n  (SKILL.md: {skill_md})"
        )


# ======================================================================
# 3. Agent consistency
# ======================================================================

class TestAgentConsistency:
    """Every agent must have a scripts/ directory with at least one script."""

    @pytest.mark.parametrize("agent_name", _agent_directories())
    def test_agent_has_scripts_dir(self, agent_name):
        """Every agent must have a scripts/ directory."""
        scripts_dir = AGENTS_DIR / agent_name / "scripts"
        assert scripts_dir.is_dir(), (
            f"Agent '{agent_name}' is missing scripts/ directory at {scripts_dir}"
        )

    @pytest.mark.parametrize("agent_name", _agent_directories())
    def test_agent_has_at_least_one_script(self, agent_name):
        """Every agent's scripts/ directory must contain at least one .py file."""
        scripts_dir = AGENTS_DIR / agent_name / "scripts"
        if not scripts_dir.is_dir():
            pytest.skip(f"No scripts/ dir for agent {agent_name}")
        py_files = list(scripts_dir.glob("*.py"))
        real_scripts = [f for f in py_files if f.name not in ("__init__.py",)]
        assert len(real_scripts) >= 1, (
            f"Agent '{agent_name}' scripts/ directory has no .py files"
        )

    @pytest.mark.parametrize("agent_name", _agent_directories())
    def test_agent_has_common_bootstrap(self, agent_name):
        """Every agent must have _common.py in scripts/."""
        scripts_dir = AGENTS_DIR / agent_name / "scripts"
        if not scripts_dir.is_dir():
            pytest.skip(f"No scripts/ dir for agent {agent_name}")
        assert (scripts_dir / "_common.py").exists(), (
            f"Agent '{agent_name}' scripts/ must contain _common.py "
            f"for workspace bootstrap"
        )


# ======================================================================
# 4. Command consistency
# ======================================================================

class TestCommandConsistency:
    """Command .md files must reference skills/agents, and README must list them."""

    def test_commands_readme_exists(self):
        readme = COMMANDS_DIR / "README.md"
        assert readme.exists(), f"Commands README.md not found at {readme}"

    @pytest.mark.parametrize("cmd_file", _command_files())
    def test_command_references_skill_or_agent(self, cmd_file):
        """Each command .md must reference at least one skill or agent name."""
        cmd_path = COMMANDS_DIR / cmd_file
        text = cmd_path.read_text(encoding="utf-8")
        registry = _load_registry()
        skill_names = set(registry.keys())
        agent_names = set(_agent_directories())
        # Also check for common helper references
        helper_keywords = {"unified_search", "cache", "helpers"}

        referenced = any(
            name in text
            for name in (skill_names | agent_names | helper_keywords)
        )
        assert referenced, (
            f"Command '{cmd_file}' does not reference any known skill, agent, "
            f"or helper. Commands should delegate to at least one skill or agent."
        )

    @pytest.mark.parametrize("cmd_file", _command_files())
    def test_command_listed_in_readme(self, cmd_file):
        """Every command .md file must be listed in commands/README.md."""
        readme = COMMANDS_DIR / "README.md"
        if not readme.exists():
            pytest.skip("README.md not found")
        readme_text = readme.read_text(encoding="utf-8")
        assert cmd_file in readme_text, (
            f"Command file '{cmd_file}' is not listed in commands/README.md"
        )

    def test_readme_lists_no_phantom_commands(self):
        """README.md should not list .md files that don't exist on disk."""
        readme = COMMANDS_DIR / "README.md"
        if not readme.exists():
            pytest.skip("README.md not found")
        readme_text = readme.read_text(encoding="utf-8")
        actual_files = set(_command_files()) | {"README.md"}
        # Extract .md filenames referenced in the README (look for `filename.md`)
        mentioned = set(re.findall(r"`([a-z0-9_-]+\.md)`", readme_text))
        phantoms = mentioned - actual_files
        assert not phantoms, (
            f"commands/README.md references .md files that don't exist:\n"
            + "\n".join(f"  - {p}" for p in sorted(phantoms))
        )


# ======================================================================
# 5. Helpers __init__.py consistency
# ======================================================================

class TestHelpersInitConsistency:
    """Every module imported in helpers/__init__.py must exist on disk."""

    def test_init_file_exists(self):
        init_py = HELPERS_DIR / "__init__.py"
        assert init_py.exists(), f"helpers/__init__.py not found at {init_py}"

    def test_imported_modules_exist(self):
        """Every `from .module import ...` in __init__.py must map to a real file or package."""
        init_py = HELPERS_DIR / "__init__.py"
        source = init_py.read_text(encoding="utf-8")
        tree = ast.parse(source)

        missing = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level == 1:
                mod_name = node.module
                if mod_name is None:
                    continue
                # Top-level module name (e.g., "individual_analysis_db" from
                # "from .individual_analysis_db.records import ...")
                top_module = mod_name.split(".")[0]
                as_file = HELPERS_DIR / f"{top_module}.py"
                as_pkg = HELPERS_DIR / top_module / "__init__.py"
                if not as_file.exists() and not as_pkg.exists():
                    missing.append(top_module)

        # Deduplicate
        missing = sorted(set(missing))
        assert not missing, (
            f"helpers/__init__.py imports from modules that don't exist:\n"
            + "\n".join(f"  - {m} (expected {HELPERS_DIR / m}.py or {HELPERS_DIR / m}/)" for m in missing)
        )

    def test_every_helper_module_imported_or_acknowledged(self):
        """Every .py file in helpers/ should be imported in __init__.py or documented as standalone."""
        init_py = HELPERS_DIR / "__init__.py"
        source = init_py.read_text(encoding="utf-8")

        # Collect all relative-imported module names from __init__.py
        tree = ast.parse(source)
        imported_modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module:
                imported_modules.add(node.module.split(".")[0])

        # Also check for mentions in comments/docstrings (standalone scripts like unified_search)
        # and in lazy import mappings (e.g. ".analyzed_files_db" in _LAZY_IMPORTS)
        mentioned_in_text = set()
        for mod_name in set(_helper_module_files()) | set(_helper_subpackage_dirs()):
            if mod_name in source:
                mentioned_in_text.add(mod_name)

        all_modules = set(_helper_module_files()) | set(_helper_subpackage_dirs())
        unaccounted = all_modules - imported_modules - mentioned_in_text

        assert not unaccounted, (
            f"Helper modules exist but are not imported or mentioned in __init__.py:\n"
            + "\n".join(f"  - {m}" for m in sorted(unaccounted))
            + "\n  Either import them in __init__.py or document them as standalone scripts."
        )


# ======================================================================
# 6. Cross-cutting: registry entry_scripts vs actual scripts on disk
# ======================================================================

class TestRegistryScriptCoverage:
    """Registry entry_scripts should cover all meaningful scripts in each skill."""

    @pytest.mark.parametrize(
        "skill_name",
        [s for s in _skill_directories() if s not in DOCUMENTATION_ONLY_SKILLS],
    )
    def test_all_disk_scripts_in_registry(self, skill_name):
        """Scripts on disk should appear in registry.json entry_scripts."""
        registry = _load_registry()
        if skill_name not in registry:
            pytest.skip(f"Skill {skill_name} not in registry")
        meta = registry[skill_name]
        registered_scripts = {
            e.get("script", "") for e in meta.get("entry_scripts", [])
        }
        disk_scripts = set(_skill_script_files(skill_name))

        unregistered = disk_scripts - registered_scripts
        assert not unregistered, (
            f"Skill '{skill_name}' has scripts on disk not listed in registry.json "
            f"entry_scripts:\n"
            + "\n".join(f"  - {s}" for s in sorted(unregistered))
        )


# ======================================================================
# 8. Agent registry.json consistency
# ======================================================================

class TestAgentRegistryConsistency:
    """Every agent in agents/registry.json must have a matching directory and scripts."""

    def test_agent_registry_file_exists(self):
        assert AGENT_REGISTRY_PATH.exists(), (
            f"agents/registry.json not found at {AGENT_REGISTRY_PATH}"
        )

    def test_agent_registry_is_valid_json(self):
        data = json.loads(AGENT_REGISTRY_PATH.read_text(encoding="utf-8"))
        assert "agents" in data, "agents/registry.json must have a top-level 'agents' key"

    def test_every_registered_agent_has_directory(self):
        """Every agent listed in agents/registry.json must have a directory."""
        registry = _load_agent_registry()
        actual_dirs = set(_agent_directories())
        for agent_name in registry:
            assert agent_name in actual_dirs, (
                f"Agent '{agent_name}' is in agents/registry.json but has no "
                f"directory at {AGENTS_DIR / agent_name}"
            )

    def test_every_agent_directory_is_registered(self):
        """Every agent directory (excluding infra) should be in agents/registry.json."""
        registry = _load_agent_registry()
        for agent_name in _agent_directories():
            assert agent_name in registry, (
                f"Agent directory '{agent_name}' exists at {AGENTS_DIR / agent_name} "
                f"but is not listed in agents/registry.json"
            )

    def test_agent_entry_scripts_exist_on_disk(self):
        """Every entry_scripts entry must have a matching .py file."""
        registry = _load_agent_registry()
        missing = []
        for agent_name, meta in registry.items():
            for entry in meta.get("entry_scripts", []):
                script_name = entry.get("script", "")
                script_path = AGENTS_DIR / agent_name / "scripts" / script_name
                if not script_path.exists():
                    missing.append(f"{agent_name}/scripts/{script_name}")
        assert not missing, (
            f"Entry scripts listed in agents/registry.json but missing on disk:\n"
            + "\n".join(f"  - {m}" for m in missing)
        )

    def test_agent_skills_used_are_registered(self):
        """All skills_used entries must exist in the skills registry."""
        agent_reg = _load_agent_registry()
        skill_reg = _load_registry()
        bad = []
        for agent_name, meta in agent_reg.items():
            for skill in meta.get("skills_used", []):
                if skill not in skill_reg:
                    bad.append(f"{agent_name} -> {skill}")
        assert not bad, (
            f"Agent registry references skills not in skills/registry.json:\n"
            + "\n".join(f"  - {b}" for b in bad)
        )

    def test_agent_methodologies_referenced_are_registered(self):
        """All methodologies_referenced entries must exist in the skills registry."""
        agent_reg = _load_agent_registry()
        skill_reg = _load_registry()
        bad = []
        for agent_name, meta in agent_reg.items():
            for methodology in meta.get("methodologies_referenced", []):
                if methodology not in skill_reg:
                    bad.append(f"{agent_name} -> {methodology} (not in registry)")
                elif not skill_reg[methodology].get("methodology_only"):
                    bad.append(f"{agent_name} -> {methodology} (not marked methodology_only)")
        assert not bad, (
            f"Agent registry methodologies_referenced issues:\n"
            + "\n".join(f"  - {b}" for b in bad)
        )


# ======================================================================
# 9. Agent registry entry_scripts vs actual scripts on disk
# ======================================================================

class TestAgentRegistryScriptCoverage:
    """Agent registry entry_scripts should cover all entry-point scripts."""

    @pytest.mark.parametrize("agent_name", _agent_directories())
    def test_all_agent_disk_scripts_in_registry(self, agent_name):
        """Public scripts on disk should appear in agents/registry.json entry_scripts."""
        registry = _load_agent_registry()
        if agent_name not in registry:
            pytest.skip(f"Agent {agent_name} not in registry")
        meta = registry[agent_name]
        registered_scripts = {
            e.get("script", "") for e in meta.get("entry_scripts", [])
        }
        disk_scripts = set(_agent_script_files(agent_name))

        unregistered = disk_scripts - registered_scripts
        assert not unregistered, (
            f"Agent '{agent_name}' has scripts on disk not listed in "
            f"agents/registry.json entry_scripts:\n"
            + "\n".join(f"  - {s}" for s in sorted(unregistered))
        )


# ======================================================================
# 10. Command registry.json consistency
# ======================================================================

class TestCommandRegistryConsistency:
    """Every command in commands/registry.json must have a matching .md file."""

    def test_command_registry_file_exists(self):
        assert COMMAND_REGISTRY_PATH.exists(), (
            f"commands/registry.json not found at {COMMAND_REGISTRY_PATH}"
        )

    def test_command_registry_is_valid_json(self):
        data = json.loads(COMMAND_REGISTRY_PATH.read_text(encoding="utf-8"))
        assert "commands" in data, (
            "commands/registry.json must have a top-level 'commands' key"
        )

    def test_every_registered_command_has_file(self):
        """Every command in commands/registry.json must have a matching .md file."""
        registry = _load_command_registry()
        actual_files = set(_command_files())
        for cmd_name, meta in registry.items():
            cmd_file = meta.get("file", "")
            assert cmd_file in actual_files, (
                f"Command '{cmd_name}' references file '{cmd_file}' in "
                f"commands/registry.json but that file does not exist"
            )

    def test_every_command_file_is_registered(self):
        """Every command .md file should be referenced by commands/registry.json."""
        registry = _load_command_registry()
        registered_files = {
            meta.get("file", "") for meta in registry.values()
        }
        for cmd_file in _command_files():
            assert cmd_file in registered_files, (
                f"Command file '{cmd_file}' exists on disk but is not "
                f"referenced in commands/registry.json"
            )

    def test_command_skills_used_are_registered(self):
        """All skills_used entries must exist in the skills registry."""
        cmd_reg = _load_command_registry()
        skill_reg = _load_registry()
        bad = []
        for cmd_name, meta in cmd_reg.items():
            for skill in meta.get("skills_used", []):
                if skill not in skill_reg:
                    bad.append(f"/{cmd_name} -> {skill}")
        assert not bad, (
            f"Command registry references skills not in skills/registry.json:\n"
            + "\n".join(f"  - {b}" for b in bad)
        )

    def test_command_methodologies_used_are_registered(self):
        """All methodologies_used entries must exist in the skills registry as methodology_only."""
        cmd_reg = _load_command_registry()
        skill_reg = _load_registry()
        bad = []
        for cmd_name, meta in cmd_reg.items():
            for methodology in meta.get("methodologies_used", []):
                if methodology not in skill_reg:
                    bad.append(f"/{cmd_name} -> {methodology} (not in registry)")
                elif not skill_reg[methodology].get("methodology_only"):
                    bad.append(f"/{cmd_name} -> {methodology} (not marked methodology_only)")
        assert not bad, (
            f"Command registry methodologies_used issues:\n"
            + "\n".join(f"  - {b}" for b in bad)
        )

    def test_command_agents_used_are_registered(self):
        """All agents_used entries must exist in the agents registry."""
        cmd_reg = _load_command_registry()
        agent_reg = _load_agent_registry()
        bad = []
        for cmd_name, meta in cmd_reg.items():
            for agent in meta.get("agents_used", []):
                if agent not in agent_reg:
                    bad.append(f"/{cmd_name} -> {agent}")
        assert not bad, (
            f"Command registry references agents not in agents/registry.json:\n"
            + "\n".join(f"  - {b}" for b in bad)
        )


# ======================================================================
# 11. Skills README.md consistency
# ======================================================================

class TestSkillsReadmeConsistency:
    """skills/README.md should reflect registry-backed skill metadata."""

    def test_skills_readme_exists(self):
        assert SKILLS_README_PATH.exists(), (
            f"skills/README.md not found at {SKILLS_README_PATH}"
        )

    def test_skills_readme_overview_covers_registered_skills(self):
        """The skills overview table should list every registered skill exactly once."""
        registry = _load_registry()
        readme_text = SKILLS_README_PATH.read_text(encoding="utf-8")
        overview_rows = {
            _markdown_link_text(row[0]): row
            for row in _extract_markdown_table_rows(readme_text, "## Overview")
        }

        missing = sorted(set(registry) - set(overview_rows))
        phantoms = sorted(set(overview_rows) - set(registry))

        assert not missing, (
            "skills/README.md overview is missing registered skills:\n"
            + "\n".join(f"  - {name}" for name in missing)
        )
        assert not phantoms, (
            "skills/README.md overview lists skills not present in skills/registry.json:\n"
            + "\n".join(f"  - {name}" for name in phantoms)
        )

    def test_skill_overview_metadata_matches_registry(self):
        """Stable overview columns should mirror registry.json."""
        registry = _load_registry()
        readme_text = SKILLS_README_PATH.read_text(encoding="utf-8")
        overview_rows = {
            _markdown_link_text(row[0]): row
            for row in _extract_markdown_table_rows(readme_text, "## Overview")
        }

        mismatches = []
        for skill_name, meta in registry.items():
            row = overview_rows.get(skill_name)
            if row is None:
                continue
            if len(row) != 6:
                mismatches.append(
                    f"{skill_name}: expected 6 overview columns, found {len(row)}"
                )
                continue

            expected_type = meta.get("type", "")
            if row[1] != expected_type:
                mismatches.append(
                    f"{skill_name}: type column '{row[1]}' != registry '{expected_type}'"
                )

            entry_scripts = meta.get("entry_scripts", [])
            expected_scripts = str(len(entry_scripts)) if entry_scripts else "--"
            if row[3] != expected_scripts:
                mismatches.append(
                    f"{skill_name}: scripts column '{row[3]}' != '{expected_scripts}'"
                )

            expected_cacheable = "Yes" if meta.get("cacheable") else "No"
            if row[4] != expected_cacheable:
                mismatches.append(
                    f"{skill_name}: cacheable column '{row[4]}' != '{expected_cacheable}'"
                )

            expected_deps = meta.get("depends_on", [])
            actual_deps = _markdown_csv_items(row[5])
            if actual_deps != expected_deps:
                mismatches.append(
                    f"{skill_name}: dependencies {actual_deps!r} != {expected_deps!r}"
                )

        assert not mismatches, (
            "skills/README.md overview drift detected:\n"
            + "\n".join(f"  - {item}" for item in mismatches)
        )

    @pytest.mark.parametrize(
        "skill_name",
        sorted(
            skill_name
            for skill_name, meta in _load_registry().items()
            if meta.get("entry_scripts")
        ),
    )
    def test_skills_with_entry_scripts_have_detail_sections(self, skill_name):
        """Every scripted skill should have a detailed section in skills/README.md."""
        readme_text = SKILLS_README_PATH.read_text(encoding="utf-8")
        assert f"#### {skill_name}" in readme_text, (
            f"skills/README.md is missing detail section for skill '{skill_name}'"
        )

    def test_skill_detail_sections_reference_registered_skills_only(self):
        """Detailed skill headings should only reference registered skills."""
        readme_text = SKILLS_README_PATH.read_text(encoding="utf-8")
        detail_headings = set(
            re.findall(r"^#### ([a-z0-9_-]+)$", readme_text, flags=re.MULTILINE)
        )
        phantoms = sorted(detail_headings - set(_load_registry()))
        assert not phantoms, (
            "skills/README.md has detail sections for non-registered skills:\n"
            + "\n".join(f"  - {name}" for name in phantoms)
        )


# ======================================================================
# 12. Agents README.md consistency
# ======================================================================

class TestAgentsReadmeConsistency:
    """agents/README.md should reflect registry-backed agent metadata."""

    def test_agents_readme_exists(self):
        assert AGENTS_README_PATH.exists(), (
            f"agents/README.md not found at {AGENTS_README_PATH}"
        )

    @pytest.mark.parametrize("agent_name", _agent_directories())
    def test_agent_prompt_file_exists_on_disk(self, agent_name):
        """Every registered agent should have a prompt file next to its directory."""
        prompt_path = AGENTS_DIR / f"{agent_name}.md"
        assert prompt_path.exists(), (
            f"Agent '{agent_name}' is missing prompt file at {prompt_path}"
        )

    @pytest.mark.parametrize("agent_name", _agent_directories())
    def test_every_registered_agent_has_readme_section(self, agent_name):
        """Every registered agent should have a section in agents/README.md."""
        readme_text = AGENTS_README_PATH.read_text(encoding="utf-8")
        assert f"### {agent_name}" in readme_text, (
            f"agents/README.md is missing section for agent '{agent_name}'"
        )

    @pytest.mark.parametrize("agent_name", _agent_directories())
    def test_agent_prompt_files_are_documented(self, agent_name):
        """agents/README.md should mention each public agent prompt file."""
        readme_text = AGENTS_README_PATH.read_text(encoding="utf-8")
        prompt_name = f"{agent_name}.md"
        assert prompt_name in readme_text, (
            f"agents/README.md does not mention prompt file '{prompt_name}'"
        )

    def test_agent_entry_scripts_are_documented(self):
        """agents/README.md should mention each public entry script from registry."""
        registry = _load_agent_registry()
        readme_text = AGENTS_README_PATH.read_text(encoding="utf-8")
        missing = []
        for agent_name, meta in registry.items():
            for entry in meta.get("entry_scripts", []):
                script_name = entry.get("script", "")
                if script_name and script_name not in readme_text:
                    missing.append(f"{agent_name} -> {script_name}")

        assert not missing, (
            "agents/README.md does not mention these registered entry scripts:\n"
            + "\n".join(f"  - {item}" for item in missing)
        )


# ======================================================================
# 13. Hook documentation consistency
# ======================================================================

class TestHookDocumentationConsistency:
    """Hook docs should stay aligned with hooks.json and lifecycle behavior."""

    def test_hooks_config_file_exists(self):
        assert HOOKS_CONFIG_PATH.exists(), f"hooks.json not found at {HOOKS_CONFIG_PATH}"

    def test_hooks_readme_exists(self):
        assert HOOKS_README_PATH.exists(), (
            f"hooks/README.md not found at {HOOKS_README_PATH}"
        )

    def test_hooks_readme_documents_all_configured_hooks(self):
        """hooks/README.md should cover every configured hook event and script."""
        hooks = _load_hooks_config()
        readme_text = HOOKS_README_PATH.read_text(encoding="utf-8")
        missing = []
        for event_name, entries in hooks.items():
            if event_name not in readme_text:
                missing.append(f"{event_name} (event name)")
            for entry in entries:
                script_name = _hook_script_name(entry.get("command", ""))
                if script_name not in readme_text:
                    missing.append(f"{event_name} -> {script_name}")

        assert not missing, (
            "hooks/README.md is missing configured hook references:\n"
            + "\n".join(f"  - {item}" for item in missing)
        )

    @pytest.mark.parametrize("doc_path", [ROOT_README_PATH, ARCHITECTURE_DOC_PATH])
    def test_top_level_docs_reference_all_configured_hooks(self, doc_path):
        """Top-level docs should not omit configured lifecycle hooks."""
        hooks = _load_hooks_config()
        doc_text = doc_path.read_text(encoding="utf-8")
        missing = []
        for event_name, entries in hooks.items():
            if event_name not in doc_text:
                missing.append(f"{event_name} (event name)")
            for entry in entries:
                script_name = _hook_script_name(entry.get("command", ""))
                if script_name not in doc_text:
                    missing.append(f"{event_name} -> {script_name}")

        assert not missing, (
            f"{doc_path.relative_to(AGENT_DIR)} is missing configured hook references:\n"
            + "\n".join(f"  - {item}" for item in missing)
        )

    def test_architecture_doc_has_no_stale_two_hook_language(self):
        """Architecture doc should not describe a 3-hook system as 'two hooks'."""
        hook_count = len(_load_hooks_config())
        if hook_count == 2:
            pytest.skip("Current hooks.json defines exactly two hooks")

        doc_text = ARCHITECTURE_DOC_PATH.read_text(encoding="utf-8")
        stale_phrases = [
            phrase for phrase in ("Two hooks", "Both hooks")
            if phrase in doc_text
        ]
        assert not stale_phrases, (
            "docs/architecture.md still contains stale hook-count language for a "
            f"{hook_count}-hook configuration:\n"
            + "\n".join(f"  - {phrase}" for phrase in stale_phrases)
        )


# ======================================================================
# 14. Deployed .agent layout consistency
# ======================================================================

class TestDeploymentModelConsistency:
    """Deployment-facing docs/config should consistently describe the .agent layout."""

    def test_hooks_json_uses_deployed_agent_paths(self):
        """Configured hook commands should execute from the workspace root into .agent/."""
        hooks = _load_hooks_config()
        bad = []
        for event_name, entries in hooks.items():
            for entry in entries:
                command = entry.get("command", "")
                if not command.startswith("python .agent/"):
                    bad.append(f"{event_name} -> {command}")

        assert not bad, (
            "hooks.json commands should use the deployed .agent layout:\n"
            + "\n".join(f"  - {item}" for item in bad)
        )

    @pytest.mark.parametrize("doc_path", [ROOT_README_PATH, ARCHITECTURE_DOC_PATH])
    def test_deployment_docs_use_agent_relative_scratchpad_paths(self, doc_path):
        """Top-level docs should reference scratchpads under .agent/hooks/."""
        doc_text = doc_path.read_text(encoding="utf-8")
        assert ".agent/hooks/scratchpads/{session_id}.md" in doc_text, (
            f"{doc_path.relative_to(AGENT_DIR)} should document scratchpads under "
            ".agent/hooks/scratchpads/{session_id}.md"
        )

    @pytest.mark.parametrize("doc_path", [ROOT_README_PATH, ARCHITECTURE_DOC_PATH])
    def test_deployment_docs_use_agent_root_test_invocation(self, doc_path):
        """Deployment-facing test instructions should run from the .agent root."""
        doc_text = doc_path.read_text(encoding="utf-8")
        match = re.search(
            r"cd [^\n`]*\.agent && python -m pytest tests/ -v",
            doc_text,
        )
        assert match, (
            f"{doc_path.relative_to(AGENT_DIR)} should document a pytest "
            "command that runs from the deployed .agent root"
        )
