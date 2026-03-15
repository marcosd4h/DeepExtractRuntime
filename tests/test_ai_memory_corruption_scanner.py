"""Tests for the ai-memory-corruption-scanner skill -- registry, structure, and script logic."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

WORKSPACE = Path(__file__).resolve().parents[1]
SKILL_DIR = WORKSPACE / "skills" / "ai-memory-corruption-scanner"
SCRIPTS_DIR = SKILL_DIR / "scripts"
REFERENCE_DIR = SKILL_DIR / "reference"
SKILLS_REGISTRY = WORKSPACE / "skills" / "registry.json"
AGENTS_REGISTRY = WORKSPACE / "agents" / "registry.json"
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

    def test_all_scripts_exist(self):
        expected = ["build_threat_model.py", "prepare_context.py"]
        for script in expected:
            assert (SCRIPTS_DIR / script).is_file(), f"Missing script: {script}"

    def test_reference_directory_exists(self):
        assert REFERENCE_DIR.is_dir()

    def test_reference_files_exist(self):
        expected = ["vulnerability_patterns.md", "decompiler_pitfalls.md"]
        for ref in expected:
            assert (REFERENCE_DIR / ref).is_file(), f"Missing reference: {ref}"

    def test_vulnerability_patterns_has_10_patterns(self):
        content = (REFERENCE_DIR / "vulnerability_patterns.md").read_text(encoding="utf-8")
        pattern_headers = re.findall(r"^## \d+\.", content, re.MULTILINE)
        assert len(pattern_headers) == 10, f"Expected 10 patterns, found {len(pattern_headers)}"

    def test_decompiler_pitfalls_has_assembly_rule(self):
        content = (REFERENCE_DIR / "decompiler_pitfalls.md").read_text(encoding="utf-8")
        assert "assembly is ground truth" in content.lower()


# ---------------------------------------------------------------------------
# SKILL.md frontmatter tests
# ---------------------------------------------------------------------------

class TestSkillFrontmatter:
    """Verify SKILL.md has valid frontmatter for discovery."""

    @pytest.fixture(autouse=True)
    def _load_skill_md(self):
        self.content = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")

    def test_frontmatter_present(self):
        assert self.content.startswith("---"), "SKILL.md must start with ---"
        second_delim = self.content.index("---", 3)
        assert second_delim > 3, "SKILL.md needs closing --- for frontmatter"

    def test_name_matches_folder(self):
        match = re.search(r"^name:\s*(.+)$", self.content, re.MULTILINE)
        assert match, "name field required in frontmatter"
        assert match.group(1).strip() == "ai-memory-corruption-scanner"

    def test_description_present(self):
        match = re.search(r"^description:", self.content, re.MULTILINE)
        assert match, "description field required in frontmatter"

    def test_description_has_trigger_phrases(self):
        triggers = ["memory corruption", "buffer overflow", "integer overflow", "use-after-free"]
        desc_block = self.content.split("---")[1]
        for trigger in triggers:
            assert trigger.lower() in desc_block.lower(), f"Missing trigger phrase: {trigger}"

    def test_no_format_string_trigger(self):
        desc_block = self.content.split("---")[1]
        assert "format string" not in desc_block.lower(), \
            "Format string should NOT be a trigger (dead bug class)"


# ---------------------------------------------------------------------------
# _common.py import tests
# ---------------------------------------------------------------------------

class TestCommonImports:
    """Verify _common.py exports expected symbols."""

    @pytest.fixture(autouse=True)
    def _load_common(self):
        from helpers.script_runner import load_skill_module
        self.mod = load_skill_module("ai-memory-corruption-scanner", "_common")

    def test_workspace_root(self):
        assert hasattr(self.mod, "WORKSPACE_ROOT")
        assert Path(self.mod.WORKSPACE_ROOT).is_dir()

    def test_cross_module_graph(self):
        assert hasattr(self.mod, "CrossModuleGraph")

    def test_resolve_db_path(self):
        assert callable(self.mod.resolve_db_path)

    def test_emit_json(self):
        assert callable(self.mod.emit_json)

    def test_is_library_function(self):
        assert callable(self.mod.is_library_function)

    def test_no_api_taxonomy(self):
        assert not hasattr(self.mod, "ALLOC_APIS"), "API taxonomy should NOT be in new skill"
        assert not hasattr(self.mod, "FREE_APIS"), "API taxonomy should NOT be in new skill"
        assert not hasattr(self.mod, "COPY_APIS"), "API taxonomy should NOT be in new skill"

    def test_no_taint_analysis(self):
        assert not hasattr(self.mod, "analyze_taint"), "Removed taint-analysis functions must not appear"
        assert not hasattr(self.mod, "build_taint_summary"), "Removed taint-analysis functions must not appear"

    def test_all_list_present(self):
        assert hasattr(self.mod, "__all__")
        assert len(self.mod.__all__) > 0


# ---------------------------------------------------------------------------
# build_threat_model.py logic tests
# ---------------------------------------------------------------------------

class TestBuildThreatModel:
    """Test threat model generation logic."""

    @pytest.fixture(autouse=True)
    def _load_module(self):
        from helpers.script_runner import load_skill_module
        self.mod = load_skill_module("ai-memory-corruption-scanner", "build_threat_model")

    def test_infer_service_type_rpc(self):
        eps = [
            {"entry_type": "RPC_HANDLER"},
            {"entry_type": "RPC_HANDLER"},
            {"entry_type": "EXPORT_DLL"},
        ]
        assert self.mod._infer_service_type(eps) == "rpc_service"

    def test_infer_service_type_com(self):
        eps = [
            {"entry_type": "COM_METHOD"},
            {"entry_type": "COM_METHOD"},
        ]
        assert self.mod._infer_service_type(eps) == "com_server"

    def test_infer_service_type_library(self):
        eps = [
            {"entry_type": "EXPORT_DLL"},
            {"entry_type": "EXPORT_DLL"},
        ]
        assert self.mod._infer_service_type(eps) == "library"

    def test_infer_service_type_empty(self):
        assert self.mod._infer_service_type([]) == "unknown"

    def test_infer_attacker_model_rpc(self):
        model = self.mod._infer_attacker_model("rpc_service")
        assert "remote" in model.lower()
        assert "unauthenticated" in model.lower()

    def test_infer_attacker_model_com(self):
        model = self.mod._infer_attacker_model("com_server")
        assert "local" in model.lower()


# ---------------------------------------------------------------------------
# prepare_context.py logic tests
# ---------------------------------------------------------------------------

class TestPrepareContextStructure:
    """Test the callgraph JSON structure produced by prepare_context."""

    @pytest.fixture(autouse=True)
    def _load_module(self):
        from helpers.script_runner import load_skill_module
        self.mod = load_skill_module("ai-memory-corruption-scanner", "prepare_context")

    def test_module_loads(self):
        assert hasattr(self.mod, "prepare_context")
        assert callable(self.mod.prepare_context)

    def test_build_callgraph_signature(self):
        assert hasattr(self.mod, "_build_callgraph")
        assert callable(self.mod._build_callgraph)


class TestCallgraphOutputFormat:
    """Verify the output JSON structure has all required fields."""

    def _make_mock_result(self) -> dict:
        """Build a minimal valid prepare_context result for schema checking."""
        return {
            "status": "ok",
            "module": "test.dll",
            "db_path": "test.db",
            "max_depth": 3,
            "root_functions": ["FuncA"],
            "entry_points": [],
            "callgraph": {
                "nodes": {
                    "test.dll::FuncA": {
                        "module": "test.dll",
                        "function": "FuncA",
                        "depth": 0,
                        "is_library": False,
                        "is_entry_point": True,
                    },
                    "test.dll::FuncB": {
                        "module": "test.dll",
                        "function": "FuncB",
                        "depth": 1,
                        "is_library": False,
                    },
                },
                "edges": [
                    {"from": "test.dll::FuncA", "to": "test.dll::FuncB", "edge_type": "call"},
                ],
                "ipc_edges": [],
            },
            "stats": {
                "total_nodes": 2,
                "app_nodes": 2,
                "library_nodes": 0,
                "total_edges": 1,
                "ipc_edges": 0,
                "modules_involved": ["test.dll"],
            },
            "_summary": {
                "module": "test.dll",
                "root_functions": ["FuncA"],
                "depth": 3,
                "total_nodes": 2,
                "app_nodes": 2,
                "total_edges": 1,
                "modules": ["test.dll"],
            },
        }

    def test_top_level_keys(self):
        result = self._make_mock_result()
        required = {"status", "module", "db_path", "max_depth", "root_functions",
                     "entry_points", "callgraph", "stats", "_summary"}
        assert required.issubset(result.keys())

    def test_callgraph_keys(self):
        result = self._make_mock_result()
        cg = result["callgraph"]
        assert "nodes" in cg
        assert "edges" in cg
        assert "ipc_edges" in cg

    def test_node_keys(self):
        result = self._make_mock_result()
        for node_key, node in result["callgraph"]["nodes"].items():
            assert "::" in node_key, "Node key must be module::function"
            assert "module" in node
            assert "function" in node
            assert "depth" in node
            assert "is_library" in node

    def test_edge_keys(self):
        result = self._make_mock_result()
        for edge in result["callgraph"]["edges"]:
            assert "from" in edge
            assert "to" in edge
            assert "edge_type" in edge

    def test_stats_keys(self):
        result = self._make_mock_result()
        stats = result["stats"]
        required = {"total_nodes", "app_nodes", "library_nodes", "total_edges",
                     "ipc_edges", "modules_involved"}
        assert required.issubset(stats.keys())

    def test_summary_is_compact(self):
        result = self._make_mock_result()
        summary = result["_summary"]
        summary_str = json.dumps(summary)
        assert len(summary_str) < 1000, "Summary should be compact (< 1KB)"

    def test_library_filtering(self):
        result = self._make_mock_result()
        result["callgraph"]["nodes"]["test.dll::WilStub"] = {
            "module": "test.dll", "function": "WilStub",
            "depth": 2, "is_library": True,
        }
        lib_nodes = [n for n in result["callgraph"]["nodes"].values() if n.get("is_library")]
        app_nodes = [n for n in result["callgraph"]["nodes"].values() if not n.get("is_library")]
        assert len(lib_nodes) == 1
        assert len(app_nodes) == 2
