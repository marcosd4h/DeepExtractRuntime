"""Tests for the taint-analysis skill.

Covers:
  - helpers/guard_classifier.py  (classify_guard, find_guards_between)
  - skills/taint-analysis/scripts/_common.py  (classify_sink, severity helpers,
    param inference, logic-effect detection)
  - skills/taint-analysis/scripts/generate_taint_report.py  (build_report,
    render_markdown)
  - skills/taint-analysis/scripts/trace_taint_backward.py  (origin helpers)
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_AGENT_DIR = Path(__file__).resolve().parent.parent
if str(_AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENT_DIR))

from helpers.guard_classifier import Guard, classify_guard, find_guards_between


# ===================================================================
# guard_classifier  --  classify_guard
# ===================================================================


class TestClassifyGuard:
    """Unit tests for classify_guard()."""

    def test_auth_check_is_admin(self):
        g = classify_guard("IsAdmin(a1)", {"a1"})
        assert g.guard_type == "auth_check"
        assert g.attacker_controllable is True
        assert g.bypass_difficulty == "easy"
        assert g.api_in_condition == "IsAdmin"

    def test_auth_check_access_check(self):
        g = classify_guard("AccessCheck(hToken, dwAccess, &status)", {"a2"})
        assert g.guard_type == "auth_check"
        assert g.attacker_controllable is False
        assert g.bypass_difficulty == "hard"

    def test_auth_check_privilege_check(self):
        g = classify_guard("PrivilegeCheck(a2, &privs, &result)", {"a2"})
        assert g.guard_type == "auth_check"
        assert g.attacker_controllable is True

    def test_null_check_not_equal(self):
        g = classify_guard("a1 != 0", {"a1"})
        assert g.guard_type == "null_check"
        assert g.attacker_controllable is True

    def test_null_check_bang(self):
        g = classify_guard("!ptr", {"ptr"})
        assert g.guard_type == "null_check"
        assert g.attacker_controllable is True

    def test_null_check_nullptr(self):
        g = classify_guard("v3 == nullptr", set())
        assert g.guard_type == "null_check"
        assert g.attacker_controllable is False
        assert g.bypass_difficulty == "unknown"

    def test_bounds_check(self):
        g = classify_guard("size < 256", {"size"})
        assert g.guard_type == "bounds_check"
        assert g.attacker_controllable is True

    def test_bounds_check_no_taint(self):
        g = classify_guard("v3 <= maxLen", set())
        assert g.guard_type == "bounds_check"
        assert g.attacker_controllable is False

    def test_error_check_succeeded(self):
        g = classify_guard("SUCCEEDED(hr)", set())
        assert g.guard_type == "error_check"
        assert g.attacker_controllable is False

    def test_error_check_failed(self):
        g = classify_guard("FAILED(hr)", {"hr"})
        assert g.guard_type == "error_check"
        assert g.attacker_controllable is True
        assert g.api_in_condition == "FAILED"

    def test_error_check_nt_success(self):
        g = classify_guard("NT_SUCCESS(status)", set())
        assert g.guard_type == "error_check"

    def test_validation_api(self):
        g = classify_guard("ValidateInput(a1, a2)", {"a1"})
        assert g.guard_type == "validation"
        assert g.attacker_controllable is True

    def test_validation_api_ensure(self):
        g = classify_guard("EnsureInitialized()", set())
        assert g.guard_type == "validation"
        assert g.attacker_controllable is False

    def test_generic_function_check(self):
        g = classify_guard("SomeInternalCheck(v5)", set())
        assert g.guard_type == "function_check"

    def test_generic_comparison(self):
        g = classify_guard("a1 == 42", {"a1"})
        assert g.guard_type == "comparison"
        assert g.attacker_controllable is True

    def test_bypass_easy_full_taint(self):
        g = classify_guard("AccessCheck(a1, 7)", {"a1"})
        assert g.attacker_controllable is True
        assert g.bypass_difficulty == "easy"

    def test_bypass_medium_partial_taint(self):
        g = classify_guard("AccessCheck(a1, v5)", {"a1", "a2"})
        assert g.attacker_controllable is True
        assert g.bypass_difficulty == "medium"

    def test_no_tainted_vars(self):
        g = classify_guard("v5 > 0", set())
        assert g.attacker_controllable is False
        assert g.bypass_difficulty == "unknown"
        assert g.tainted_vars_in_condition == []

    def test_tainted_vars_recorded(self):
        g = classify_guard("a1 + a3 > 0", {"a1", "a3"})
        assert set(g.tainted_vars_in_condition) == {"a1", "a3"}

    def test_to_dict(self):
        g = classify_guard("IsAdmin(a1)", {"a1"})
        d = g.to_dict()
        assert d["guard_type"] == "auth_check"
        assert d["attacker_controllable"] is True
        assert d["api_in_condition"] == "IsAdmin"
        assert "condition" in d


# ===================================================================
# guard_classifier  --  find_guards_between
# ===================================================================


class TestFindGuardsBetween:
    """Unit tests for find_guards_between()."""

    SAMPLE_CODE = """\
void func(__int64 a1, int a2) {
  if ( !a1 )
    return;
  v3 = DoSomething(a1);
  if ( AccessCheck(a2, 7) )
  {
    v4 = strlen(a1);
    if ( v4 < 256 )
      memcpy(buf, a1, v4);
  }
  return;
}"""

    def test_finds_all_guards_in_range(self):
        guards = find_guards_between(self.SAMPLE_CODE, 1, 10, {"a1", "a2"})
        assert len(guards) == 3

    def test_guard_types(self):
        guards = find_guards_between(self.SAMPLE_CODE, 1, 10, {"a1", "a2"})
        types = [g.guard_type for g in guards]
        assert "null_check" in types
        assert "auth_check" in types
        assert "bounds_check" in types

    def test_line_numbers_are_set(self):
        guards = find_guards_between(self.SAMPLE_CODE, 1, 10, {"a1"})
        for g in guards:
            assert g.line_number > 0

    def test_range_excludes_sink_line(self):
        guards = find_guards_between(self.SAMPLE_CODE, 8, 10, {"a1"})
        assert len(guards) == 1
        assert guards[0].guard_type == "bounds_check"

    def test_empty_range(self):
        guards = find_guards_between(self.SAMPLE_CODE, 5, 5, {"a1"})
        assert len(guards) == 0

    def test_no_tainted_vars(self):
        guards = find_guards_between(self.SAMPLE_CODE, 1, 10, set())
        for g in guards:
            assert g.attacker_controllable is False

    def test_while_loop_guard(self):
        code = "  while ( a1 < limit )\n    process(a1);\n"
        guards = find_guards_between(code, 1, 3, {"a1"})
        assert len(guards) == 1
        assert guards[0].attacker_controllable is True


# ===================================================================
# _common  --  classify_sink (extended sink detection)
# ===================================================================


class TestClassifySink:
    """Tests for the extended classify_sink() function.

    The base ``classify_api_security()`` now includes ``reconnaissance``
    and ``anti_forensics`` categories from the updated taxonomy, plus
    ``uncategorized_dangerous`` for APIs found only in the JSON list.
    ``classify_sink()`` overrides ``uncategorized_dangerous`` with the
    more specific extended-prefix category when available.
    """

    @pytest.fixture(autouse=True)
    def _import_common(self):
        from helpers.script_runner import load_skill_module
        self.mod = load_skill_module("taint-analysis", "_common")

    # -- APIs classified by base taxonomy (unchanged) --

    def test_base_taxonomy_apis(self):
        assert self.mod.classify_sink("CreateProcessW") == "command_execution"
        assert self.mod.classify_sink("strcpy") == "memory_unsafe"
        assert self.mod.classify_sink("__imp_ShellExecuteW") == "command_execution"

    # -- APIs classified as "reconnaissance" by updated base taxonomy --

    def test_reconnaissance_from_base(self):
        assert self.mod.classify_sink("EnumProcesses") == "reconnaissance"
        assert self.mod.classify_sink("CreateToolhelp32Snapshot") == "reconnaissance"
        assert self.mod.classify_sink("GetTickCount") == "reconnaissance"

    # -- APIs where extended prefix overrides uncategorized_dangerous --

    def test_extended_device_io(self):
        assert self.mod.classify_sink("DeviceIoControl") == "device_io"
        assert self.mod.classify_sink("NtDeviceIoControlFile") == "device_io"

    def test_extended_named_pipe(self):
        assert self.mod.classify_sink("CreateNamedPipeW") == "named_pipe"
        assert self.mod.classify_sink("ConnectNamedPipe") == "named_pipe"

    def test_extended_alpc(self):
        assert self.mod.classify_sink("NtAlpcCreatePort") == "alpc_ipc"
        assert self.mod.classify_sink("NtConnectPort") == "alpc_ipc"

    def test_extended_com_marshaling(self):
        assert self.mod.classify_sink("CoCreateInstance") == "com_marshaling"
        assert self.mod.classify_sink("OleLoad") == "com_marshaling"
        assert self.mod.classify_sink("StgCreateStorageEx") == "com_marshaling"

    def test_extended_service_control(self):
        assert self.mod.classify_sink("StartServiceW") == "service_control"
        assert self.mod.classify_sink("DeleteService") == "service_control"

    def test_extended_process_enum(self):
        assert self.mod.classify_sink("ReadProcessMemory") == "process_enum"
        assert self.mod.classify_sink("OpenProcess") == "process_enum"
        assert self.mod.classify_sink("MiniDumpWriteDump") == "process_enum"

    def test_extended_debug(self):
        assert self.mod.classify_sink("IsDebuggerPresent") == "debug_control"
        assert self.mod.classify_sink("NtSystemDebugControl") == "debug_control"

    def test_extended_dde(self):
        assert self.mod.classify_sink("DdeConnect") == "dde"

    def test_extended_wow64(self):
        assert self.mod.classify_sink("Wow64DisableWow64FsRedirection") == "wow64"

    def test_extended_thread_ops(self):
        assert self.mod.classify_sink("CreateThread") == "command_execution"
        assert self.mod.classify_sink("TerminateProcess") == "command_execution"
        assert self.mod.classify_sink("NtCreateProcess") == "command_execution"

    def test_extended_privilege(self):
        assert self.mod.classify_sink("RtlAdjustPrivilege") == "privilege"
        assert self.mod.classify_sink("DuplicateHandle") == "privilege"
        assert self.mod.classify_sink("NtCreateToken") == "privilege"

    def test_extended_file_write(self):
        assert self.mod.classify_sink("CreateHardLinkW") == "file_write"
        assert self.mod.classify_sink("NtCreateFile") == "file_write"

    def test_extended_memory(self):
        assert self.mod.classify_sink("NtMapViewOfSection") == "code_injection"
        assert self.mod.classify_sink("NtProtectVirtualMemory") == "memory_alloc"

    def test_extended_network(self):
        assert self.mod.classify_sink("URLDownloadToFileW") == "network"
        assert self.mod.classify_sink("NdrClientCall") == "network"
        assert self.mod.classify_sink("InternetReadFile") == "network"

    def test_import_prefix_stripped(self):
        assert self.mod.classify_sink("__imp_DeviceIoControl") == "device_io"
        assert self.mod.classify_sink("j_NtAlpcCreatePort") == "alpc_ipc"
        assert self.mod.classify_sink("cs:CreateThread") == "command_execution"

    def test_non_sink_returns_none(self):
        assert self.mod.classify_sink("printf") is None
        assert self.mod.classify_sink("SomeInternalFunc") is None

    def test_uncategorized_dangerous_fallback(self):
        """APIs in the JSON but not in any prefix table get uncategorized_dangerous."""
        result = self.mod.classify_sink("fgets")
        assert result is not None


# ===================================================================
# _common  --  severity helpers
# ===================================================================


class TestSeverityHelpers:
    """Tests for severity scoring functions."""

    @pytest.fixture(autouse=True)
    def _import_common(self):
        from helpers.script_runner import load_skill_module
        self.mod = load_skill_module("taint-analysis", "_common")

    def test_severity_label_critical(self):
        assert self.mod.severity_label(0.9) == "CRITICAL"
        assert self.mod.severity_label(0.8) == "CRITICAL"

    def test_severity_label_high(self):
        assert self.mod.severity_label(0.7) == "HIGH"
        assert self.mod.severity_label(0.6) == "HIGH"

    def test_severity_label_medium(self):
        assert self.mod.severity_label(0.5) == "MEDIUM"
        assert self.mod.severity_label(0.3) == "MEDIUM"

    def test_severity_label_low(self):
        assert self.mod.severity_label(0.2) == "LOW"
        assert self.mod.severity_label(0.0) == "LOW"

    def test_compute_score_short_path(self):
        score = self.mod.compute_finding_score("command_execution", 1, 0)
        assert score == 1.0

    def test_compute_score_longer_path(self):
        score = self.mod.compute_finding_score("command_execution", 4, 0)
        assert score < 1.0
        assert score > 0.4

    def test_guard_penalty_reduces_score(self):
        base = self.mod.compute_finding_score("command_execution", 1, 0)
        with_guards = self.mod.compute_finding_score("command_execution", 1, 2)
        assert with_guards < base

    def test_unknown_category_gets_default(self):
        score = self.mod.compute_finding_score("unknown_category", 1, 0)
        assert score == 0.3

    def test_score_capped_at_one(self):
        score = self.mod.compute_finding_score("command_execution", 1, 0)
        assert score <= 1.0

    def test_many_guards_floors_at_zero(self):
        score = self.mod.compute_finding_score("network", 4, 20)
        assert score == 0.0

    def test_new_categories_have_weights(self):
        """Categories added by external modifications have severity weights."""
        for cat in ("reconnaissance", "anti_forensics", "shell_storage", "uncategorized_dangerous"):
            assert cat in self.mod.SINK_SEVERITY, f"Missing weight for {cat}"


# ===================================================================
# _common  --  param inference
# ===================================================================


class TestParamInference:
    """Tests for infer_param_count and resolve_tainted_params."""

    @pytest.fixture(autouse=True)
    def _import_common(self):
        from helpers.script_runner import load_skill_module
        self.mod = load_skill_module("taint-analysis", "_common")

    def test_infer_from_signature(self):
        sig = "__int64 __fastcall AiLaunchProcess(__int64 a1, unsigned int a2, __int64 a3)"
        count = self.mod.infer_param_count(sig, "")
        assert count == 3

    def test_infer_from_code_body(self):
        code = "v1 = a1 + a2;\nv2 = a4;"
        count = self.mod.infer_param_count("", code)
        assert count == 4

    def test_infer_takes_max(self):
        sig = "__int64 func(__int64 a1, int a2)"
        code = "v1 = a3 + 1;"
        count = self.mod.infer_param_count(sig, code)
        assert count == 3

    def test_infer_no_params(self):
        count = self.mod.infer_param_count("void func()", "return 0;")
        assert count == 0

    def test_resolve_explicit_params(self):
        result = self.mod.resolve_tainted_params("1,3", "", "")
        assert result == [1, 3]

    def test_resolve_all_params(self):
        sig = "__int64 func(__int64 a1, int a2, void *a3)"
        result = self.mod.resolve_tainted_params(None, sig, "")
        assert result == [1, 2, 3]

    def test_resolve_defaults_to_one(self):
        result = self.mod.resolve_tainted_params(None, "void func()", "return;")
        assert result == [1]

    def test_resolve_deduplicates(self):
        result = self.mod.resolve_tainted_params("2,2,1", "", "")
        assert result == [1, 2]


# ===================================================================
# _common  --  logic-effect detection
# ===================================================================


class TestDetectLogicEffects:
    """Tests for detect_logic_effects()."""

    @pytest.fixture(autouse=True)
    def _import_common(self):
        from helpers.script_runner import load_skill_module
        self.mod = load_skill_module("taint-analysis", "_common")

    SAMPLE = """\
void func(__int64 a1, int a2) {
  if ( a1 )
    goto LABEL;
  buf[a1] = 0;
  for ( i = 0; i < a1; ++i )
    process(i);
  v3 = HeapAlloc(hHeap, 0, a1);
  return a1;
}"""

    def test_branch_steering(self):
        effects = self.mod.detect_logic_effects(self.SAMPLE, "a1")
        types = [e["type"] for e in effects]
        assert "branch_steering" in types

    def test_array_index(self):
        effects = self.mod.detect_logic_effects(self.SAMPLE, "a1")
        types = [e["type"] for e in effects]
        assert "array_index" in types

    def test_loop_bound(self):
        effects = self.mod.detect_logic_effects(self.SAMPLE, "a1")
        types = [e["type"] for e in effects]
        assert "loop_bound" in types

    def test_size_argument(self):
        effects = self.mod.detect_logic_effects(self.SAMPLE, "a1")
        types = [e["type"] for e in effects]
        assert "size_argument" in types

    def test_returned(self):
        effects = self.mod.detect_logic_effects(self.SAMPLE, "a1")
        types = [e["type"] for e in effects]
        assert "returned" in types

    def test_no_effects_for_unused_var(self):
        effects = self.mod.detect_logic_effects(self.SAMPLE, "a99")
        assert effects == []

    def test_dedup(self):
        effects = self.mod.detect_logic_effects(self.SAMPLE, "a1")
        keys = [(e["type"], e["line"]) for e in effects]
        assert len(keys) == len(set(keys))


# ===================================================================
# generate_taint_report  --  build_report + render_markdown
# ===================================================================


class TestReportGeneration:
    """Tests for report building and markdown rendering."""

    @pytest.fixture(autouse=True)
    def _import_report(self):
        from helpers.script_runner import load_skill_module
        self.mod = load_skill_module("taint-analysis", "generate_taint_report")

    def _make_forward(self):
        return {
            "status": "ok",
            "function": {
                "function_id": 1,
                "function_name": "TestFunc",
                "function_signature": "__int64 __fastcall TestFunc(__int64 a1)",
                "module_name": "test.dll",
                "db": "test.db",
            },
            "tainted_params": [1],
            "depth": 2,
            "findings": [
                {
                    "param": 1,
                    "param_name": "a1",
                    "sink": "memcpy",
                    "sink_category": "memory_unsafe",
                    "severity": "HIGH",
                    "score": 0.72,
                    "path": ["TestFunc.a1", "Helper.a1", "memcpy.arg2"],
                    "path_hops": 2,
                    "sink_line": 15,
                    "sink_expression": "memcpy(buf, a1, len)",
                    "arg_position": 2,
                    "guards": [
                        {
                            "guard_type": "null_check",
                            "line_number": 5,
                            "condition": "!a1",
                            "attacker_controllable": True,
                            "bypass_difficulty": "easy",
                        }
                    ],
                }
            ],
            "logic_effects": {
                "a1": [{"type": "branch_steering", "line": 5, "text": "if ( a1 )"}],
            },
            "summary": {"total_sinks": 1, "critical": 0, "high": 1, "medium": 0, "low": 0, "params_with_effects": 1},
        }

    def _make_backward(self):
        return {
            "status": "ok",
            "function": {
                "function_id": 1,
                "function_name": "TestFunc",
                "function_signature": "__int64 __fastcall TestFunc(__int64 a1)",
                "module_name": "test.dll",
                "db": "test.db",
            },
            "tainted_params": [1],
            "depth": 1,
            "callers": [
                {
                    "caller_name": "CallerA",
                    "caller_id": 10,
                    "status": "resolved",
                    "origins": [
                        {
                            "for_param": 1,
                            "expression": "a1",
                            "origin_type": "parameter",
                            "risk": "HIGH",
                            "classification": {"type": "parameter", "param_number": 1},
                            "line_number": 20,
                            "line": "TestFunc(a1);",
                        }
                    ],
                }
            ],
            "summary": {"total_callers": 1, "resolved": 1, "external": 0, "high_risk_origins": 1},
        }

    def test_build_forward_only(self):
        report = self.mod.build_report(self._make_forward(), None, "forward")
        assert report["status"] == "ok"
        assert report["direction"] == "forward"
        assert len(report["forward_findings"]) == 1
        assert report["summary"]["total_sinks"] == 1

    def test_build_backward_only(self):
        report = self.mod.build_report(None, self._make_backward(), "backward")
        assert report["status"] == "ok"
        assert len(report["backward_callers"]) == 1

    def test_build_both(self):
        report = self.mod.build_report(self._make_forward(), self._make_backward(), "both")
        assert len(report.get("forward_findings", [])) == 1
        assert len(report.get("backward_callers", [])) == 1

    def test_render_markdown_forward(self):
        report = self.mod.build_report(self._make_forward(), None, "forward")
        md = self.mod.render_markdown(report)
        assert "TestFunc" in md
        assert "memcpy" in md
        assert "HIGH" in md
        assert "Guards to bypass" in md
        assert "null_check" in md.upper() or "NULL_CHECK" in md

    def test_render_markdown_backward(self):
        report = self.mod.build_report(None, self._make_backward(), "backward")
        md = self.mod.render_markdown(report)
        assert "CallerA" in md
        assert "parameter" in md

    def test_render_includes_logic_effects(self):
        report = self.mod.build_report(self._make_forward(), None, "forward")
        md = self.mod.render_markdown(report)
        assert "Logic Effects" in md
        assert "BRANCH_STEERING" in md

    def test_render_summary(self):
        report = self.mod.build_report(self._make_forward(), self._make_backward(), "both")
        md = self.mod.render_markdown(report)
        assert "Summary" in md


# ===================================================================
# trace_taint_backward  --  origin helpers
# ===================================================================


class TestBackwardOriginHelpers:
    """Tests for _classify_origin_risk and _extract_caller_origins."""

    @pytest.fixture(autouse=True)
    def _import_backward(self):
        from helpers.script_runner import load_skill_module
        self.mod = load_skill_module("taint-analysis", "trace_taint_backward")

    def test_origin_risk_parameter(self):
        assert self.mod._classify_origin_risk({"type": "parameter"}) == "HIGH"

    def test_origin_risk_param_dereference(self):
        assert self.mod._classify_origin_risk({"type": "param_dereference"}) == "HIGH"

    def test_origin_risk_call_result(self):
        assert self.mod._classify_origin_risk({"type": "call_result"}) == "MEDIUM"

    def test_origin_risk_constant(self):
        assert self.mod._classify_origin_risk({"type": "constant"}) == "NONE"

    def test_origin_risk_string_literal(self):
        assert self.mod._classify_origin_risk({"type": "string_literal"}) == "NONE"

    def test_origin_risk_global(self):
        assert self.mod._classify_origin_risk({"type": "global"}) == "MEDIUM"

    def test_extract_origins_from_bt_result(self):
        bt = {
            "status": "ok",
            "call_sites": [
                {
                    "line_number": 10,
                    "line": "TestFunc(a1, v3);",
                    "arguments": [
                        {
                            "number": 1,
                            "expression": "a1",
                            "classification": {"type": "parameter", "param_number": 1},
                        },
                        {
                            "number": 2,
                            "expression": "v3",
                            "classification": {"type": "local_variable", "name": "v3"},
                        },
                    ],
                }
            ],
        }
        origins = self.mod._extract_caller_origins(bt, [1])
        assert len(origins) == 1
        assert origins[0]["for_param"] == 1
        assert origins[0]["origin_type"] == "parameter"
        assert origins[0]["risk"] == "HIGH"

    def test_extract_origins_filters_by_params(self):
        bt = {
            "status": "ok",
            "call_sites": [
                {
                    "line_number": 10,
                    "line": "TestFunc(a1, v3);",
                    "arguments": [
                        {"number": 1, "expression": "a1", "classification": {"type": "parameter"}},
                        {"number": 2, "expression": "v3", "classification": {"type": "local_variable"}},
                    ],
                }
            ],
        }
        origins = self.mod._extract_caller_origins(bt, [2])
        assert len(origins) == 1
        assert origins[0]["for_param"] == 2

    def test_extract_origins_empty_on_error(self):
        bt = {"status": "target_not_found"}
        origins = self.mod._extract_caller_origins(bt, [1])
        assert origins == []
