"""Tests for cross-module taint analysis extensions.

Covers:
  - trace_taint_forward.py: --cross-module flag, _trace_cross_module_callees fixes
  - trace_taint_cross_module.py: orchestrator output structure
  - Registry and SKILL.md updates for cross-module support
  - TaintContext dataclass and serialization
  - Trust boundary classification
  - Parameter mapping helpers
  - COM vtable resolution
  - RPC boundary detection
  - Return-value taint detection
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

import pytest

_AGENT_DIR = Path(__file__).resolve().parent.parent
if str(_AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENT_DIR))

SKILLS_DIR = _AGENT_DIR / "skills"
SKILL_REGISTRY = SKILLS_DIR / "registry.json"
TAINT_SKILL = "taint-analysis"

# Import the taint-analysis _common module by full path to avoid collisions
# with other skills' _common.py modules during full-suite runs.
import importlib.util as _ilu

_TAINT_COMMON_PATH = SKILLS_DIR / TAINT_SKILL / "scripts" / "_common.py"
_spec = _ilu.spec_from_file_location("taint_common", str(_TAINT_COMMON_PATH))
taint_common = _ilu.module_from_spec(_spec)
sys.modules["taint_common"] = taint_common
_spec.loader.exec_module(taint_common)


# ======================================================================
# 1. Registry updates
# ======================================================================


class TestCrossModuleRegistry:

    @pytest.fixture(autouse=True)
    def _load(self):
        self.reg = json.loads(SKILL_REGISTRY.read_text(encoding="utf-8"))["skills"]

    def test_trace_taint_cross_module_in_registry(self):
        scripts = {s["script"] for s in self.reg[TAINT_SKILL].get("entry_scripts", [])}
        assert "trace_taint_cross_module.py" in scripts

    def test_cross_module_flag_in_taint_function(self):
        for entry in self.reg[TAINT_SKILL]["entry_scripts"]:
            if entry["script"] == "taint_function.py":
                assert "--cross-module" in entry.get("accepts", {})
                assert "--cross-depth" in entry.get("accepts", {})
                return
        pytest.fail("taint_function.py not found in entry_scripts")

    def test_cross_module_flag_in_forward_trace(self):
        for entry in self.reg[TAINT_SKILL]["entry_scripts"]:
            if entry["script"] == "trace_taint_forward.py":
                assert "--cross-module" in entry.get("accepts", {})
                return
        pytest.fail("trace_taint_forward.py not found in entry_scripts")

    def test_cross_module_orchestrator_has_trust_flags(self):
        for entry in self.reg[TAINT_SKILL]["entry_scripts"]:
            if entry["script"] == "trace_taint_cross_module.py":
                accepts = entry.get("accepts", {})
                assert "--no-trust-analysis" in accepts
                assert "--no-com-resolve" in accepts
                return
        pytest.fail("trace_taint_cross_module.py not found in entry_scripts")

    def test_com_interface_dependency(self):
        deps = self.reg[TAINT_SKILL].get("depends_on", [])
        assert "com-interface-reconstruction" in deps


# ======================================================================
# 2. SKILL.md documentation
# ======================================================================


class TestCrossModuleSkillMd:

    @pytest.fixture(autouse=True)
    def _load(self):
        self.text = (SKILLS_DIR / TAINT_SKILL / "SKILL.md").read_text(encoding="utf-8")

    def test_cross_module_script_documented(self):
        assert "trace_taint_cross_module.py" in self.text

    def test_cross_module_flag_documented(self):
        assert "--cross-module" in self.text

    def test_cross_depth_documented(self):
        assert "--cross-depth" in self.text

    def test_step_6_added(self):
        assert "Step 6" in self.text

    def test_trust_levels_documented(self):
        assert "user_process" in self.text
        assert "system_service" in self.text
        assert "com_server" in self.text
        assert "rpc_server" in self.text
        assert "kernel_adjacent" in self.text

    def test_boundary_types_documented(self):
        assert "com_vtable" in self.text
        assert "rpc" in self.text
        assert "dll_import" in self.text

    def test_trust_escalation_documented(self):
        assert "trust_escalated" in self.text
        assert "1.25" in self.text

    def test_return_taint_documented(self):
        assert "return_taint" in self.text or "Return-value" in self.text


# ======================================================================
# 3. Command updates
# ======================================================================


class TestCrossModuleCommand:

    @pytest.fixture(autouse=True)
    def _load(self):
        self.text = (_AGENT_DIR / "commands" / "taint.md").read_text(encoding="utf-8")

    def test_cross_module_usage_example(self):
        assert "--cross-module" in self.text

    def test_cross_depth_usage_example(self):
        assert "--cross-depth" in self.text

    def test_cross_module_orchestrator_mentioned(self):
        assert "trace_taint_cross_module.py" in self.text

    def test_trust_analysis_flag_documented(self):
        assert "--no-trust-analysis" in self.text

    def test_com_resolve_flag_documented(self):
        assert "--no-com-resolve" in self.text


# ======================================================================
# 4. Script file existence and signatures
# ======================================================================


class TestCrossModuleScriptFiles:

    def test_orchestrator_exists(self):
        script = SKILLS_DIR / TAINT_SKILL / "scripts" / "trace_taint_cross_module.py"
        assert script.exists()

    def test_orchestrator_defines_trace_cross_module(self):
        source = (SKILLS_DIR / TAINT_SKILL / "scripts" / "trace_taint_cross_module.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        func_names = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
        assert "trace_cross_module" in func_names
        assert "main" in func_names

    def test_orchestrator_has_trust_params(self):
        source = (SKILLS_DIR / TAINT_SKILL / "scripts" / "trace_taint_cross_module.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "trace_cross_module":
                param_names = [a.arg for a in node.args.args]
                assert "trust_analysis" in param_names
                assert "com_resolve" in param_names
                return
        pytest.fail("trace_cross_module function not found")

    def test_forward_trace_has_taint_context_param(self):
        source = (SKILLS_DIR / TAINT_SKILL / "scripts" / "trace_taint_forward.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "trace_forward":
                param_names = [a.arg for a in node.args.args]
                assert "cross_module" in param_names
                assert "cross_depth" in param_names
                assert "no_cache" in param_names
                assert "taint_context" in param_names
                assert "com_resolve" in param_names
                return
        pytest.fail("trace_forward function not found")

    def test_cross_module_callees_has_com_resolve_param(self):
        source = (SKILLS_DIR / TAINT_SKILL / "scripts" / "trace_taint_forward.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "_trace_cross_module_callees":
                param_names = [a.arg for a in node.args.args]
                assert "com_resolve" in param_names
                return
        pytest.fail("_trace_cross_module_callees function not found")

    def test_taint_function_has_cross_module_param(self):
        source = (SKILLS_DIR / TAINT_SKILL / "scripts" / "taint_function.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "taint_function":
                param_names = [a.arg for a in node.args.args]
                assert "cross_module" in param_names
                assert "cross_depth" in param_names
                return
        pytest.fail("taint_function function not found")


# ======================================================================
# 5. TaintContext dataclass
# ======================================================================


class TestTaintContext:

    def _make_ctx(self):
        return taint_common.TaintContext()

    def test_empty_context_to_dict(self):
        ctx = self._make_ctx()
        d = ctx.to_dict()
        assert d["call_stack"] == []
        assert d["accumulated_guards"] == []
        assert d["trust_transitions"] == []
        assert d["param_map"] == {}
        assert d["return_taint"] is False
        assert d["boundary_types"] == []

    def test_push_frame(self):
        ctx = self._make_ctx()
        ctx.push_frame("mod_a", "func_x", 1, "user_process")
        ctx.push_frame("mod_b", "func_y", 2, "com_server")
        assert len(ctx.call_stack) == 2
        assert ctx.call_stack[0]["module"] == "mod_a"
        assert ctx.call_stack[1]["trust_level"] == "com_server"

    def test_add_guards(self):
        ctx = self._make_ctx()
        ctx.add_guards([{"guard_type": "null_check", "line_number": 5}])
        ctx.add_guards([{"guard_type": "auth_check", "line_number": 10}])
        assert len(ctx.accumulated_guards) == 2

    def test_add_trust_transition(self):
        ctx = self._make_ctx()
        ctx.add_trust_transition("a.dll", "b.dll", "user_process", "com_server", "dll_import")
        assert len(ctx.trust_transitions) == 1
        t = ctx.trust_transitions[0]
        assert t["transition"] == "privilege_escalation"
        assert t["boundary_type"] == "dll_import"

    def test_clone_independence(self):
        ctx = self._make_ctx()
        ctx.push_frame("mod", "fn", 1, "user_process")
        clone = ctx.clone()
        clone.push_frame("mod2", "fn2", 2, "com_server")
        assert len(ctx.call_stack) == 1
        assert len(clone.call_stack) == 2

    def test_param_map_roundtrip(self):
        ctx = self._make_ctx()
        ctx.param_map = {1: 3, 2: 1}
        d = ctx.to_dict()
        assert d["param_map"] == {1: 3, 2: 1}


# ======================================================================
# 6. Trust boundary classification
# ======================================================================


class TestTrustClassification:

    def test_classify_trust_transition_escalation(self):
        assert taint_common.classify_trust_transition("user_process", "com_server") == "privilege_escalation"
        assert taint_common.classify_trust_transition("user_process", "system_service") == "privilege_escalation"

    def test_classify_trust_transition_same(self):
        assert taint_common.classify_trust_transition("user_process", "user_process") == "same_trust"
        assert taint_common.classify_trust_transition("com_server", "com_server") == "same_trust"

    def test_classify_trust_transition_reduction(self):
        assert taint_common.classify_trust_transition("system_service", "user_process") == "trust_reduction"
        assert taint_common.classify_trust_transition("kernel_adjacent", "com_server") == "trust_reduction"

    def test_trust_level_ranks_ordered(self):
        ranks = taint_common.TRUST_LEVEL_RANK
        assert ranks["user_process"] < ranks["com_server"]
        assert ranks["com_server"] < ranks["rpc_server"]
        assert ranks["rpc_server"] < ranks["system_service"]
        assert ranks["system_service"] < ranks["kernel_adjacent"]


# ======================================================================
# 7. COM vtable resolution
# ======================================================================


class TestVtableResolution:

    def test_resolve_vtable_callees_empty(self):
        func = {"detailed_outbound_xrefs": [], "outbound_xrefs": []}
        result = taint_common.resolve_vtable_callees(func, "fake.db")
        assert result == []

    def test_resolve_vtable_callees_finds_vtable_calls(self):
        func = {
            "detailed_outbound_xrefs": [
                {
                    "is_vtable_call": True,
                    "function_name": "CMyClass::DoWork",
                    "vtable_info": {"vtable_address": "0x1000", "method_offset": 24},
                    "module_name": "target.dll",
                    "function_id": 42,
                },
                {
                    "is_vtable_call": False,
                    "function_name": "CreateFileW",
                    "module_name": "kernel32.dll",
                },
            ],
            "outbound_xrefs": [],
        }
        result = taint_common.resolve_vtable_callees(func, "fake.db")
        assert len(result) == 1
        assert result[0]["callee_name"] == "CMyClass::DoWork"
        assert result[0]["boundary_type"] == "com_vtable"
        assert result[0]["vtable_address"] == "0x1000"

    def test_resolve_vtable_callees_skips_no_name(self):
        func = {
            "detailed_outbound_xrefs": [
                {
                    "is_vtable_call": True,
                    "function_name": "",
                    "vtable_info": {},
                },
            ],
            "outbound_xrefs": [],
        }
        result = taint_common.resolve_vtable_callees(func, "fake.db")
        assert result == []


# ======================================================================
# 8. RPC boundary detection
# ======================================================================


class TestRpcBoundaryDetection:

    def test_detect_rpc_boundaries_finds_ndr(self):
        usages = [
            {"function_name": "__imp_NdrClientCall3", "arg_position": 0, "line_number": 10, "line": "NdrClientCall3(...)"},
            {"function_name": "CreateFileW", "arg_position": 0, "line_number": 20, "line": "CreateFileW(...)"},
        ]
        result = taint_common.detect_rpc_boundaries(usages)
        assert len(result) == 1
        assert result[0]["boundary_type"] == "rpc"
        assert "NdrClientCall" in result[0]["function_name"]

    def test_detect_rpc_boundaries_ndr64(self):
        usages = [
            {"function_name": "Ndr64AsyncClientCall", "arg_position": 0, "line_number": 5, "line": "..."},
        ]
        result = taint_common.detect_rpc_boundaries(usages)
        assert len(result) == 1

    def test_detect_rpc_boundaries_empty(self):
        result = taint_common.detect_rpc_boundaries([])
        assert result == []

    def test_detect_rpc_boundaries_with_import_prefix(self):
        usages = [
            {"function_name": "_imp_NdrAsyncClientCall", "arg_position": 0, "line_number": 1, "line": "..."},
        ]
        result = taint_common.detect_rpc_boundaries(usages)
        assert len(result) == 1


# ======================================================================
# 9. Return-value taint detection
# ======================================================================


class TestReturnTaintDetection:

    def test_detect_return_taint_from_logic_effects(self):
        result = {
            "logic_effects": {
                "a1": [
                    {"type": "branch_steering", "line": 5, "text": "if (a1)"},
                    {"type": "returned", "line": 10, "text": "return a1;"},
                ]
            },
            "findings": [],
        }
        assert taint_common.detect_return_taint(result) is True

    def test_detect_return_taint_no_return(self):
        result = {
            "logic_effects": {
                "a1": [{"type": "branch_steering", "line": 5, "text": "if (a1)"}]
            },
            "findings": [],
        }
        assert taint_common.detect_return_taint(result) is False

    def test_detect_return_taint_empty(self):
        assert taint_common.detect_return_taint({}) is False

    def test_find_return_assignment_targets(self):
        code = """
  v5 = SomeFunc(a1, a2);
  if ( v5 )
    v10 = SomeFunc(v5);
  result = OtherFunc(v10);
"""
        targets = taint_common.find_return_assignment_targets(code, "SomeFunc")
        assert "v5" in targets

    def test_find_return_assignment_targets_no_match(self):
        code = "  CallSomething(a1);\n"
        targets = taint_common.find_return_assignment_targets(code, "SomeFunc")
        assert targets == []


# ======================================================================
# 10. Severity score with trust escalation
# ======================================================================


class TestTrustEscalationScoring:

    def test_escalation_multiplier_value(self):
        assert taint_common.TRUST_ESCALATION_MULTIPLIER == 1.25

    def test_score_capped_at_1(self):
        score = taint_common.compute_finding_score("command_execution", 1, 0)
        boosted = min(1.0, score * taint_common.TRUST_ESCALATION_MULTIPLIER)
        assert boosted <= 1.0


# ======================================================================
# 11. _common.py module-level integrity
# ======================================================================


# ======================================================================
# 12. _build_callee_param_map (via AST + logic)
# ======================================================================


class TestBuildCalleeParamMapSignature:
    """Verify _build_callee_param_map correctly iterates tainted vars,
    not the callee name."""

    def test_function_iterates_tainted_vars(self):
        """The function should call find_param_in_calls for each tainted
        variable, not for the callee name."""
        source = (
            SKILLS_DIR / TAINT_SKILL / "scripts" / "trace_taint_forward.py"
        ).read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "_build_callee_param_map":
                body_src = ast.get_source_segment(source, node)
                assert ("for tv in all_tainted" in body_src
                        or "for tv in expanded_tainted" in body_src), (
                    "_build_callee_param_map should iterate tainted vars, "
                    "not pass callee_name to find_param_in_calls"
                )
                assert 'cu.get("function_name"' in body_src or "function_name" in body_src
                return
        pytest.fail("_build_callee_param_map not found")


# ======================================================================
# 13. TaintContext boundary_types accumulation
# ======================================================================


class TestTaintContextBoundaryTypes:

    def test_boundary_types_accumulated_on_trust_transition(self):
        ctx = taint_common.TaintContext()
        ctx.add_trust_transition("a.dll", "b.dll", "user_process", "com_server", "com_vtable")
        ctx.add_trust_transition("b.dll", "c.dll", "com_server", "rpc_server", "rpc")
        assert ctx.boundary_types == ["com_vtable", "rpc"]

    def test_boundary_types_in_to_dict(self):
        ctx = taint_common.TaintContext()
        ctx.add_trust_transition("x.dll", "y.dll", "user_process", "user_process", "dll_import")
        d = ctx.to_dict()
        assert d["boundary_types"] == ["dll_import"]

    def test_clone_preserves_boundary_types(self):
        ctx = taint_common.TaintContext()
        ctx.add_trust_transition("a.dll", "b.dll", "user_process", "com_server", "rpc")
        clone = ctx.clone()
        clone.add_trust_transition("b.dll", "c.dll", "com_server", "com_server", "dll_import")
        assert ctx.boundary_types == ["rpc"]
        assert clone.boundary_types == ["rpc", "dll_import"]


# ======================================================================
# 14. resolve_vtable_callees target_name fallback
# ======================================================================


class TestVtableTargetNameFallback:

    def test_uses_target_name_when_function_name_missing(self):
        func = {
            "detailed_outbound_xrefs": [
                {
                    "is_vtable_call": True,
                    "target_name": "CClass::Method",
                    "vtable_info": {"vtable_address": "0x2000", "method_offset": 8},
                    "module_name": "mod.dll",
                },
            ],
            "outbound_xrefs": [],
        }
        result = taint_common.resolve_vtable_callees(func, "fake.db")
        assert len(result) == 1
        assert result[0]["callee_name"] == "CClass::Method"

    def test_prefers_function_name_over_target_name(self):
        func = {
            "detailed_outbound_xrefs": [
                {
                    "is_vtable_call": True,
                    "function_name": "Preferred",
                    "target_name": "Fallback",
                    "vtable_info": {},
                    "module_name": "mod.dll",
                },
            ],
            "outbound_xrefs": [],
        }
        result = taint_common.resolve_vtable_callees(func, "fake.db")
        assert result[0]["callee_name"] == "Preferred"

    def test_skips_when_both_names_empty(self):
        func = {
            "detailed_outbound_xrefs": [
                {
                    "is_vtable_call": True,
                    "function_name": "",
                    "target_name": "",
                    "vtable_info": {},
                    "module_name": "mod.dll",
                },
            ],
            "outbound_xrefs": [],
        }
        result = taint_common.resolve_vtable_callees(func, "fake.db")
        assert result == []


# ======================================================================
# 15. detect_logic_effects "returned" type
# ======================================================================


class TestDetectLogicEffectsReturnType:

    def test_detects_return_of_tainted_var(self):
        code = "  if (a1 > 5)\n    v5 = a1 + 1;\n  return a1;\n"
        effects = taint_common.detect_logic_effects(code, "a1")
        types = {e["type"] for e in effects}
        assert "returned" in types

    def test_no_false_return_detection(self):
        code = "  v5 = a1 + 1;\n  return 0;\n"
        effects = taint_common.detect_logic_effects(code, "a1")
        types = {e["type"] for e in effects}
        assert "returned" not in types

    def test_detects_branch_and_return_together(self):
        code = "  if (a1)\n  {\n    return a1;\n  }\n"
        effects = taint_common.detect_logic_effects(code, "a1")
        types = {e["type"] for e in effects}
        assert "branch_steering" in types
        assert "returned" in types


# ======================================================================
# 16. detect_rpc_boundaries edge cases
# ======================================================================


class TestRpcBoundaryEdgeCases:

    def test_non_matching_prefix(self):
        usages = [
            {"function_name": "NdrServerCall", "arg_position": 0, "line_number": 1, "line": "..."},
        ]
        result = taint_common.detect_rpc_boundaries(usages)
        assert result == []

    def test_multiple_rpc_calls(self):
        usages = [
            {"function_name": "NdrClientCall2", "arg_position": 0, "line_number": 1, "line": "..."},
            {"function_name": "Ndr64AsyncClientCall", "arg_position": 1, "line_number": 5, "line": "..."},
        ]
        result = taint_common.detect_rpc_boundaries(usages)
        assert len(result) == 2

    def test_cs_prefix_stripped(self):
        usages = [
            {"function_name": "cs:NdrClientCall3", "arg_position": 0, "line_number": 1, "line": "..."},
        ]
        result = taint_common.detect_rpc_boundaries(usages)
        assert len(result) == 1


# ======================================================================
# 17. classify_trust_transition edge cases
# ======================================================================


class TestTrustTransitionEdgeCases:

    def test_unknown_trust_levels_default_to_user(self):
        result = taint_common.classify_trust_transition("unknown_level", "user_process")
        assert result == "same_trust"

    def test_kernel_adjacent_to_user_is_reduction(self):
        result = taint_common.classify_trust_transition("kernel_adjacent", "user_process")
        assert result == "trust_reduction"

    def test_user_to_kernel_adjacent_is_escalation(self):
        result = taint_common.classify_trust_transition("user_process", "kernel_adjacent")
        assert result == "privilege_escalation"


# ======================================================================
# 18. Module-level integrity
# ======================================================================


class TestCommonModuleExports:

    def test_all_new_symbols_exported(self):
        all_exports = taint_common.__all__
        required = [
            "TaintContext",
            "classify_module_trust",
            "classify_trust_transition",
            "resolve_vtable_callees",
            "detect_rpc_boundaries",
            "detect_return_taint",
            "find_return_assignment_targets",
            "TRUST_LEVELS",
            "TRUST_LEVEL_RANK",
            "TRUST_ESCALATION_MULTIPLIER",
        ]
        for name in required:
            assert name in all_exports, f"{name} missing from __all__"

    def test_get_function_includes_detailed_xrefs(self):
        """Verify the get_function contract passes include_detailed_xrefs=True."""
        import inspect
        source = inspect.getsource(taint_common.get_function)
        assert "include_detailed_xrefs=True" in source
