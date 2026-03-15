"""Tests for the function classification algorithm.

Target: skills/classify-functions/scripts/_common.py
"""

from __future__ import annotations

import json

from conftest import _make_function_record as mkfr, import_skill_module

# Load the classify-functions _common module (hyphenated dir)
_mod = import_skill_module("classify-functions")
ClassificationResult = _mod.ClassificationResult
W_API_CAP = _mod.W_API_CAP
W_LIBRARY = _mod.W_LIBRARY
_compute_interest = _mod._compute_interest
classify_function = _mod.classify_function


# ===================================================================
# classify_function -- demangled name direct assignment
# ===================================================================

class TestClassifyFunctionDemangledNames:
    def test_constructor_simple(self):
        func = mkfr(function_name="CFoo::CFoo", function_id=10)
        result = classify_function(func)
        assert result.primary_category == "initialization"
        assert any("Constructor" in s for s in result.signals.get("initialization", []))

    def test_constructor_nested_namespace(self):
        func = mkfr(function_name="Ns::MyClass::MyClass", function_id=10)
        result = classify_function(func)
        assert result.primary_category == "initialization"

    def test_destructor(self):
        func = mkfr(function_name="CFoo::~CFoo", function_id=11)
        result = classify_function(func)
        assert result.primary_category == "resource_management"
        assert any("Destructor" in s for s in result.signals.get("resource_management", []))

    def test_scalar_deleting_destructor(self):
        func = mkfr(function_name="CFoo::`scalar deleting destructor'", function_id=11)
        result = classify_function(func)
        assert result.primary_category == "resource_management"

    def test_vftable(self):
        func = mkfr(function_name="CFoo::`vftable'", function_id=12)
        result = classify_function(func)
        assert result.primary_category == "compiler_generated"
        assert any("VFTable" in s for s in result.signals.get("compiler_generated", []))

    def test_constructor_overrides_strong_api_scores(self):
        """forced_category should override even strong heuristic API signals."""
        xrefs = json.dumps([
            {"function_name": "CreateFileW", "function_id": None, "module_name": "kernel32.dll", "function_type": 0},
            {"function_name": "ReadFile", "function_id": None, "module_name": "kernel32.dll", "function_type": 0},
            {"function_name": "WriteFile", "function_id": None, "module_name": "kernel32.dll", "function_type": 0},
            {"function_name": "DeleteFileW", "function_id": None, "module_name": "kernel32.dll", "function_type": 0},
            {"function_name": "FindFirstFileW", "function_id": None, "module_name": "kernel32.dll", "function_type": 0},
        ])
        func = mkfr(function_name="CFileHandler::CFileHandler", function_id=13,
                     simple_outbound_xrefs=xrefs)
        result = classify_function(func)
        assert result.primary_category == "initialization"
        assert "file_io" in result.scores
        assert result.scores["file_io"] > 0

    def test_not_constructor_different_segments(self):
        """Foo::Bar should NOT be detected as a constructor."""
        func = mkfr(function_name="Foo::Bar", function_id=14)
        result = classify_function(func)
        assert result.primary_category != "initialization" or \
            not any("Constructor" in s for s in result.signals.get("initialization", []))


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
        func = mkfr(function_name="sub_algo", function_id=40,
                     loop_analysis=loop_data)
        result = classify_function(func)
        assert "data_parsing" in result.scores


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
        func = mkfr(function_name="sub_140099000", function_id=50)
        result = classify_function(func)
        assert result.primary_category == "unknown"
        assert any("unnamed" in s for s in result.signals.get("unknown", []))

    def test_no_signals_named_function(self):
        func = mkfr(function_name="XyzUnknown", function_id=51)
        result = classify_function(func)
        assert result.primary_category == "unknown"
        assert any("no classification" in s for s in result.signals.get("unknown", []))

    def test_empty_function_name(self):
        func = mkfr(function_name=None, function_id=52)
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
        assert 0 <= result.interest_score <= 10


# ===================================================================
# _compute_interest
# ===================================================================

class TestComputeInterest:
    def test_base_score_zero(self):
        score = _compute_interest("unknown", 0, 0, 0, 0, 0, False)
        assert score == 0

    def test_dangerous_apis_boost(self):
        score = _compute_interest("file_io", 2, 0, 0, 0, 0, False)
        assert score >= 2

    def test_dangerous_apis_capped_at_3(self):
        score = _compute_interest("file_io", 10, 0, 0, 0, 0, False)
        assert score >= 3

    def test_loops_boost(self):
        s1 = _compute_interest("data_parsing", 0, 3, 0, 0, 0, False)
        s2 = _compute_interest("data_parsing", 0, 0, 0, 0, 0, False)
        assert s1 > s2

    def test_complexity_boost(self):
        s1 = _compute_interest("data_parsing", 0, 0, 8, 0, 0, False)
        s2 = _compute_interest("data_parsing", 0, 0, 0, 0, 0, False)
        assert s1 > s2

    def test_has_decompiled_boost(self):
        s1 = _compute_interest("file_io", 0, 0, 0, 0, 0, True)
        s2 = _compute_interest("file_io", 0, 0, 0, 0, 0, False)
        assert s1 > s2

    def test_library_penalty(self):
        score = _compute_interest("telemetry", 2, 2, 5, 5, 5, True, is_library_tagged=True)
        assert score <= 5

    def test_low_interest_category_penalty(self):
        score = _compute_interest("telemetry", 0, 0, 0, 0, 0, False)
        assert score == 0

    def test_clamped_to_10(self):
        score = _compute_interest("security", 10, 5, 10, 10, 10, True)
        assert score <= 10

    def test_clamped_to_0(self):
        score = _compute_interest("compiler_generated", 0, 0, 0, 0, 0, False, is_library_tagged=True)
        assert score >= 0


# ===================================================================
# classify_function -- COM index ground-truth
# ===================================================================

class TestClassifyComIndex:
    def test_com_index_confirmed_method(self, monkeypatch):
        """Function found in COM index should score com_ole."""
        import helpers.com_index as com_mod

        class _FakeComIndex:
            loaded = True
            _procedures_by_module = {"test.dll": {"DoComThing"}}

        monkeypatch.setattr(com_mod, "_global_index", _FakeComIndex())

        func = mkfr(function_id=200, function_name="DoComThing",
                     simple_outbound_xrefs="[]")
        result = classify_function(func)
        assert "com_ole" in result.scores
        assert result.scores["com_ole"] >= 20.0  # IPC index ground-truth weight
        assert any("com_index" in s for s in result.signals.get("com_ole", []))

    def test_com_index_not_loaded(self, monkeypatch):
        """When COM index is not loaded, no com_ole signal should appear from it."""
        import helpers.com_index as com_mod

        class _FakeComIndex:
            loaded = False
            _procedures_by_module = {}

        monkeypatch.setattr(com_mod, "_global_index", _FakeComIndex())

        func = mkfr(function_id=201, function_name="DoComThing",
                     simple_outbound_xrefs="[]")
        result = classify_function(func)
        com_signals = result.signals.get("com_ole", [])
        assert not any("com_index" in s for s in com_signals)


# ===================================================================
# classify_function -- WinRT index ground-truth
# ===================================================================

class TestClassifyWinrtIndex:
    def test_winrt_index_confirmed_method(self, monkeypatch):
        """Function found in WinRT index should score winrt."""
        import helpers.winrt_index as winrt_mod

        class _FakeWinrtIndex:
            loaded = True
            _procedures_by_module = {"taskflow.dll": {"GetAppName"}}

        monkeypatch.setattr(winrt_mod, "_global_index", _FakeWinrtIndex())

        func = mkfr(function_id=300, function_name="GetAppName",
                     simple_outbound_xrefs="[]")
        result = classify_function(func)
        assert "winrt" in result.scores
        assert result.scores["winrt"] >= 20.0  # IPC index ground-truth weight
        assert any("winrt_index" in s for s in result.signals.get("winrt", []))

    def test_winrt_index_not_loaded(self, monkeypatch):
        """When WinRT index is not loaded, no winrt signal should appear from it."""
        import helpers.winrt_index as winrt_mod

        class _FakeWinrtIndex:
            loaded = False
            _procedures_by_module = {}

        monkeypatch.setattr(winrt_mod, "_global_index", _FakeWinrtIndex())

        func = mkfr(function_id=301, function_name="GetAppName",
                     simple_outbound_xrefs="[]")
        result = classify_function(func)
        winrt_signals = result.signals.get("winrt", [])
        assert not any("winrt_index" in s for s in winrt_signals)
