"""Tests for the function classification algorithm.

Target: skills/classify-functions/scripts/_common.py
"""

from __future__ import annotations

import json

import pytest

from conftest import _make_function_record as mkfr, import_skill_module

# Load the classify-functions _common module (hyphenated dir)
_mod = import_skill_module("classify-functions")
AsmMetrics = _mod.AsmMetrics
ClassificationResult = _mod.ClassificationResult
W_API_CAP = _mod.W_API_CAP
W_LIBRARY = _mod.W_LIBRARY
W_MANGLED = _mod.W_MANGLED
W_NAME = _mod.W_NAME
_compute_interest = _mod._compute_interest
classify_function = _mod.classify_function
get_asm_metrics = _mod.get_asm_metrics


# ===================================================================
# get_asm_metrics
# ===================================================================

class TestGetAsmMetrics:
    def test_none_input(self):
        m = get_asm_metrics(None)
        assert m.instruction_count == 0
        assert m.call_count == 0
        assert m.is_leaf is True
        assert m.is_tiny is True

    def test_empty_string(self):
        m = get_asm_metrics("")
        assert m.instruction_count == 0

    def test_counts_calls(self):
        asm = "push rbx\ncall CreateFileW\ncall CloseHandle\npop rbx\nret"
        m = get_asm_metrics(asm)
        assert m.call_count == 2
        assert m.is_leaf is False

    def test_counts_branches(self):
        asm = "test rax, rax\njz loc_1\ncmp ecx, 5\njge loc_2\nret"
        m = get_asm_metrics(asm)
        assert m.branch_count == 2

    def test_detects_syscall(self):
        asm = "mov eax, 0x1234\nsyscall\nret"
        m = get_asm_metrics(asm)
        assert m.has_syscall is True

    def test_no_syscall(self):
        m = get_asm_metrics("mov eax, 1\nret")
        assert m.has_syscall is False

    def test_is_leaf_when_no_calls(self):
        m = get_asm_metrics("mov eax, 1\nadd eax, 2\nret")
        assert m.is_leaf is True

    def test_is_tiny(self):
        m = get_asm_metrics("xor eax, eax\nret")
        assert m.is_tiny is True
        assert m.instruction_count == 2

    def test_not_tiny(self):
        lines = "\n".join(f"nop ; inst {i}" for i in range(15))
        m = get_asm_metrics(lines)
        assert m.is_tiny is False
        assert m.instruction_count == 15

    def test_skips_comment_lines(self):
        asm = "; this is a comment\nmov eax, 1\n; another comment\nret"
        m = get_asm_metrics(asm)
        assert m.instruction_count == 2

    def test_skips_empty_lines(self):
        asm = "\n\nmov eax, 1\n\nret\n"
        m = get_asm_metrics(asm)
        assert m.instruction_count == 2

    def test_ret_count(self):
        asm = "mov eax, 1\nret\nmov eax, 2\nretn"
        m = get_asm_metrics(asm)
        assert m.ret_count == 2


# ===================================================================
# classify_function -- name patterns
# ===================================================================

class TestClassifyFunctionNamePatterns:
    def test_telemetry_wpp(self):
        func = mkfr(function_name="WppAutoLogTrace", function_id=1)
        result = classify_function(func)
        assert result.primary_category == "telemetry"

    def test_compiler_security_cookie(self):
        func = mkfr(function_name="__security_check_cookie", function_id=2)
        result = classify_function(func)
        assert result.primary_category == "compiler_generated"

    def test_init_dllmain(self):
        func = mkfr(function_name="DllMain", function_id=3)
        result = classify_function(func)
        assert result.primary_category == "initialization"

    def test_dispatch_handler(self):
        func = mkfr(function_name="DispatchMessage", function_id=4)
        result = classify_function(func)
        assert result.primary_category == "dispatch_routing"

    def test_resource_cleanup(self):
        func = mkfr(function_name="FreeBuffer", function_id=5)
        result = classify_function(func)
        assert result.primary_category == "resource_management"

    def test_error_handling(self):
        func = mkfr(function_name="LogError", function_id=6)
        result = classify_function(func)
        assert result.primary_category == "error_handling"

    def test_data_parsing(self):
        func = mkfr(function_name="ParseConfigFile", function_id=7)
        result = classify_function(func)
        assert result.primary_category == "data_parsing"


# ===================================================================
# classify_function -- mangled names
# ===================================================================

class TestClassifyFunctionMangledNames:
    def test_constructor(self):
        func = mkfr(function_name="CFoo::CFoo", mangled_name="??0CFoo@@QEAA@XZ", function_id=10)
        result = classify_function(func)
        assert "initialization" in result.scores
        assert result.scores["initialization"] >= W_MANGLED

    def test_destructor(self):
        func = mkfr(function_name="CFoo::~CFoo", mangled_name="??1CFoo@@UEAA@XZ", function_id=11)
        result = classify_function(func)
        assert "resource_management" in result.scores
        assert result.scores["resource_management"] >= W_MANGLED

    def test_vftable(self):
        func = mkfr(function_name="CFoo::`vftable'", mangled_name="??_7CFoo@@6B@", function_id=12)
        result = classify_function(func)
        assert "compiler_generated" in result.scores


# ===================================================================
# classify_function -- API classification
# ===================================================================

class TestClassifyFunctionAPI:
    def test_file_io_from_api(self):
        xrefs = json.dumps([
            {"function_name": "CreateFileW", "function_id": None, "module_name": "kernel32.dll", "function_type": 0},
            {"function_name": "ReadFile", "function_id": None, "module_name": "kernel32.dll", "function_type": 0},
        ])
        func = mkfr(function_name="DoFileOp", function_id=20, simple_outbound_xrefs=xrefs)
        result = classify_function(func)
        assert "file_io" in result.scores
        assert result.api_count == 2

    def test_skips_data_xrefs(self):
        xrefs = json.dumps([
            {"function_name": "CreateFileW", "function_id": None, "module_name": "kernel32.dll", "function_type": 0},
            {"function_name": "g_data", "function_id": None, "module_name": "data", "function_type": 4},
        ])
        func = mkfr(function_name="Mixed", function_id=21, simple_outbound_xrefs=xrefs)
        result = classify_function(func)
        assert result.api_count == 1

    def test_api_cap_per_category(self):
        xrefs = json.dumps([
            {"function_name": f"CreateFile{chr(65+i)}", "function_id": None,
             "module_name": "kernel32.dll", "function_type": 0}
            for i in range(10)
        ])
        func = mkfr(function_name="ManyFiles", function_id=22, simple_outbound_xrefs=xrefs)
        result = classify_function(func)
        file_io_score = result.scores.get("file_io", 0)
        assert file_io_score <= W_API_CAP


# ===================================================================
# classify_function -- string classification
# ===================================================================

class TestClassifyFunctionStrings:
    def test_registry_string(self):
        strings = json.dumps(["HKEY_LOCAL_MACHINE\\SOFTWARE\\Test"])
        func = mkfr(function_name="ReadReg", function_id=30, string_literals=strings)
        result = classify_function(func)
        assert "registry" in result.scores

    def test_url_string(self):
        strings = json.dumps(["https://example.com/api"])
        func = mkfr(function_name="FetchData", function_id=31, string_literals=strings)
        result = classify_function(func)
        assert "network" in result.scores

    def test_etw_provider_string(self):
        strings = json.dumps(["Microsoft-Windows-TestProvider"])
        func = mkfr(function_name="LogEvent", function_id=32, string_literals=strings)
        result = classify_function(func)
        assert "telemetry" in result.scores

    def test_alpc_path_string(self):
        strings = json.dumps([r"\RPC Control\SomePort"])
        func = mkfr(function_name="ConnectPort", function_id=33, string_literals=strings)
        result = classify_function(func)
        assert "rpc" in result.scores

    def test_service_account_string(self):
        strings = json.dumps([r"NT AUTHORITY\LOCAL SYSTEM"])
        func = mkfr(function_name="RunAsSystem", function_id=34, string_literals=strings)
        result = classify_function(func)
        assert "security" in result.scores

    def test_certificate_string(self):
        strings = json.dumps(["certs\\root.cer"])
        func = mkfr(function_name="LoadCert", function_id=35, string_literals=strings)
        result = classify_function(func)
        assert "crypto" in result.scores


# ===================================================================
# classify_function -- structural classification
# ===================================================================

class TestClassifyFunctionStructural:
    def test_algorithmic_high_loops_complexity(self):
        loop_data = json.dumps({
            "loop_count": 5,
            "loops": [
                {"cyclomatic_complexity": 8},
                {"cyclomatic_complexity": 3},
            ],
        })
        asm = "\n".join(["nop"] * 50)  # Not tiny
        func = mkfr(function_name="sub_algo", function_id=40,
                     loop_analysis=loop_data, assembly_code=asm)
        result = classify_function(func)
        assert "data_parsing" in result.scores

    def test_dispatch_branchy(self):
        branches = "\n".join([f"jz loc_{i}" for i in range(20)])
        calls = "\n".join([f"call func_{i}" for i in range(8)])
        asm = branches + "\n" + calls + "\nret"
        func = mkfr(function_name="sub_dispatch", function_id=41, assembly_code=asm)
        result = classify_function(func)
        assert "dispatch_routing" in result.scores

    def test_tiny_utility(self):
        func = mkfr(function_name="sub_tiny", function_id=42,
                     assembly_code="xor eax, eax\nret")
        result = classify_function(func)
        assert "utility" in result.scores


# ===================================================================
# classify_function -- library tag (function_index)
# ===================================================================

class TestClassifyFunctionLibraryTag:
    def test_wil_library_tag(self, sample_function_index):
        func = mkfr(function_name="WppAutoLogTrace", function_id=4)
        result = classify_function(func, function_index=sample_function_index)
        assert result.scores.get("telemetry", 0) >= W_LIBRARY

    def test_stl_library_tag(self, sample_function_index):
        func = mkfr(function_name="STLHelper", function_id=100)
        result = classify_function(func, function_index=sample_function_index)
        assert result.scores.get("utility", 0) >= W_LIBRARY


# ===================================================================
# classify_function -- unknown / edge cases
# ===================================================================

class TestClassifyFunctionEdgeCases:
    def test_no_signals_sub_function(self):
        # Give enough assembly to avoid tiny + leaf utility classification.
        # Needs >20 instructions and at least 1 call (not leaf).
        asm = "\n".join(["nop"] * 25 + ["call some_func"])
        func = mkfr(function_name="sub_140099000", function_id=50, assembly_code=asm)
        result = classify_function(func)
        assert result.primary_category == "unknown"
        assert any("unnamed" in s for s in result.signals.get("unknown", []))

    def test_no_signals_named_function(self):
        asm = "\n".join(f"nop" for _ in range(25))
        func = mkfr(function_name="XyzUnknown", function_id=51, assembly_code=asm)
        result = classify_function(func)
        assert result.primary_category == "unknown"
        assert any("no classification" in s for s in result.signals.get("unknown", []))

    def test_empty_function_name(self):
        asm = "\n".join(f"nop" for _ in range(25))
        func = mkfr(function_name=None, function_id=52, assembly_code=asm)
        result = classify_function(func)
        assert result.primary_category == "unknown"

    def test_malformed_xrefs_json(self):
        func = mkfr(function_name="BadXrefs", function_id=53,
                     simple_outbound_xrefs="NOT VALID JSON {{{")
        result = classify_function(func)
        assert isinstance(result, ClassificationResult)

    def test_result_has_expected_fields(self):
        func = mkfr(function_name="TestFunc", function_id=60,
                     assembly_code="mov eax, 1\nret",
                     decompiled_code="int TestFunc() { return 1; }")
        result = classify_function(func)
        assert result.function_id == 60
        assert result.function_name == "TestFunc"
        assert result.has_decompiled is True
        assert result.asm_metrics is not None
        assert 0 <= result.interest_score <= 10


# ===================================================================
# _compute_interest
# ===================================================================

class TestComputeInterest:
    def _make_asm(self, **kw) -> AsmMetrics:
        return AsmMetrics(**kw)

    def test_base_score_zero(self):
        score = _compute_interest("unknown", 0, 0, 0, self._make_asm(), 0, 0, False)
        assert score == 0

    def test_dangerous_apis_boost(self):
        score = _compute_interest("file_io", 2, 0, 0, self._make_asm(), 0, 0, False)
        assert score >= 2

    def test_dangerous_apis_capped_at_3(self):
        score = _compute_interest("file_io", 10, 0, 0, self._make_asm(), 0, 0, False)
        assert score >= 3

    def test_loops_boost(self):
        s1 = _compute_interest("data_parsing", 0, 3, 0, self._make_asm(), 0, 0, False)
        s2 = _compute_interest("data_parsing", 0, 0, 0, self._make_asm(), 0, 0, False)
        assert s1 > s2

    def test_complexity_boost(self):
        s1 = _compute_interest("data_parsing", 0, 0, 8, self._make_asm(), 0, 0, False)
        s2 = _compute_interest("data_parsing", 0, 0, 0, self._make_asm(), 0, 0, False)
        assert s1 > s2

    def test_large_function_boost(self):
        big = self._make_asm(instruction_count=100)
        s1 = _compute_interest("file_io", 0, 0, 0, big, 0, 0, False)
        s2 = _compute_interest("file_io", 0, 0, 0, self._make_asm(), 0, 0, False)
        assert s1 > s2

    def test_has_decompiled_boost(self):
        s1 = _compute_interest("file_io", 0, 0, 0, self._make_asm(), 0, 0, True)
        s2 = _compute_interest("file_io", 0, 0, 0, self._make_asm(), 0, 0, False)
        assert s1 > s2

    def test_library_penalty(self):
        score = _compute_interest("telemetry", 2, 2, 5, self._make_asm(instruction_count=100), 5, 5, True, is_library_tagged=True)
        assert score <= 5

    def test_low_interest_category_penalty(self):
        score = _compute_interest("telemetry", 0, 0, 0, self._make_asm(), 0, 0, False)
        assert score == 0

    def test_tiny_utility_penalty(self):
        tiny = self._make_asm(instruction_count=3, is_tiny=True)
        score = _compute_interest("utility", 0, 0, 0, tiny, 0, 0, False)
        assert score == 0

    def test_clamped_to_10(self):
        big = self._make_asm(instruction_count=200)
        score = _compute_interest("security", 10, 5, 10, big, 10, 10, True)
        assert score <= 10

    def test_clamped_to_0(self):
        score = _compute_interest("compiler_generated", 0, 0, 0, self._make_asm(), 0, 0, False, is_library_tagged=True)
        assert score >= 0
