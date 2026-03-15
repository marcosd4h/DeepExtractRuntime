"""Tests for DossierBuilder from the security-dossier skill."""

import json
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_AGENT = str(Path(__file__).resolve().parents[1])
if _AGENT not in sys.path:
    sys.path.insert(0, _AGENT)

from helpers.script_runner import load_skill_module
load_skill_module("security-dossier", "_common")
_dossier_mod = load_skill_module("security-dossier", "build_dossier")
DossierBuilder = _dossier_mod.DossierBuilder

from conftest import _make_function_record


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_file_info(
    file_name="test.dll",
    exports="[]",
    entry_point="[]",
    security_features='{"aslr_enabled": true, "dep_enabled": true, "cfg_enabled": true, "seh_enabled": true}',
    file_description="Test module",
    load_config="{}",
):
    return types.SimpleNamespace(
        file_name=file_name,
        file_description=file_description,
        exports=exports,
        entry_point=entry_point,
        security_features=security_features,
        load_config=load_config,
    )


def _build(func, *, all_functions=None, file_info=None, callee_depth=4):
    """Construct a DossierBuilder with sensible defaults and return the dossier."""
    if all_functions is None:
        all_functions = [func]
    if file_info is None:
        file_info = _make_file_info()
    builder = DossierBuilder(
        db_path="fake.db",
        func=func,
        file_info=file_info,
        all_functions=all_functions,
        callee_depth=callee_depth,
    )
    return builder.build()


# ---------------------------------------------------------------------------
# Complexity
# ---------------------------------------------------------------------------

class TestComplexity:
    def test_string_categories_populated(self):
        func = _make_function_record(
            function_name="StringFunc",
            string_literals=json.dumps(["http://example.com", "HKLM\\SOFTWARE\\Test"]),
        )
        dossier = _build(func)
        cats = dossier["complexity"]["string_categories"]
        assert cats == {}

    def test_string_categories_empty(self):
        func = _make_function_record(function_name="NoStrings")
        dossier = _build(func)
        assert dossier["complexity"]["string_categories"] == {}


# ---------------------------------------------------------------------------
# Dangerous Operations
# ---------------------------------------------------------------------------

class TestDangerousOps:
    def test_callee_depth_1_finds_direct(self):
        callee = _make_function_record(
            function_id=2,
            function_name="B",
            dangerous_api_calls=json.dumps(["CreateProcessW"]),
        )
        caller = _make_function_record(
            function_id=1,
            function_name="A",
            simple_outbound_xrefs=json.dumps([
                {"function_name": "B", "function_id": 2,
                 "module_name": "internal", "function_type": 1,
                 "extraction_type": "script", "xref_type": "Call Near"},
            ]),
        )
        dossier = _build(caller, all_functions=[caller, callee], callee_depth=1)
        assert "B" in dossier["dangerous_operations"]["callee_dangerous_apis"]

    def test_callee_depth_4_finds_transitive(self):
        d = _make_function_record(
            function_id=4, function_name="D",
            dangerous_api_calls=json.dumps(["VirtualAlloc"]),
        )
        c = _make_function_record(
            function_id=3, function_name="C",
            simple_outbound_xrefs=json.dumps([
                {"function_name": "D", "function_id": 4,
                 "module_name": "internal", "function_type": 1,
                 "extraction_type": "script", "xref_type": "Call Near"},
            ]),
        )
        b = _make_function_record(
            function_id=2, function_name="B",
            simple_outbound_xrefs=json.dumps([
                {"function_name": "C", "function_id": 3,
                 "module_name": "internal", "function_type": 1,
                 "extraction_type": "script", "xref_type": "Call Near"},
            ]),
        )
        a = _make_function_record(
            function_id=1, function_name="A",
            simple_outbound_xrefs=json.dumps([
                {"function_name": "B", "function_id": 2,
                 "module_name": "internal", "function_type": 1,
                 "extraction_type": "script", "xref_type": "Call Near"},
            ]),
        )
        dossier = _build(a, all_functions=[a, b, c, d], callee_depth=4)
        assert "D" in dossier["dangerous_operations"]["callee_dangerous_apis"]

    def test_callee_depth_0_self_only(self):
        callee = _make_function_record(
            function_id=2, function_name="B",
            dangerous_api_calls=json.dumps(["CreateProcessW"]),
        )
        caller = _make_function_record(
            function_id=1, function_name="A",
            simple_outbound_xrefs=json.dumps([
                {"function_name": "B", "function_id": 2,
                 "module_name": "internal", "function_type": 1,
                 "extraction_type": "script", "xref_type": "Call Near"},
            ]),
        )
        dossier = _build(caller, all_functions=[caller, callee], callee_depth=0)
        assert dossier["dangerous_operations"]["callee_dangerous_apis"] == {}


# ---------------------------------------------------------------------------
# Reachability
# ---------------------------------------------------------------------------

class TestReachability:
    def test_exported_function(self):
        exports = json.dumps([
            {"function_name": "MyExport", "ordinal": 1,
             "address": "0x1000", "is_forwarded": False},
        ])
        func = _make_function_record(function_id=1, function_name="MyExport")
        fi = _make_file_info(exports=exports)
        dossier = _build(func, file_info=fi)
        assert dossier["reachability"]["is_exported"] is True
        assert dossier["reachability"]["externally_reachable"] is True

    def test_rpc_handler_externally_reachable(self):
        index = MagicMock()
        index.get_procedures_for_module.return_value = ["RpcHandler"]

        with patch.object(_dossier_mod, "_HAS_IPC_INDEXES", True), \
             patch.object(_dossier_mod, "get_rpc_index", return_value=index):
            func = _make_function_record(function_id=1, function_name="RpcHandler")
            fi = _make_file_info(file_name="svc.dll")
            dossier = _build(func, file_info=fi)
            assert dossier["reachability"]["externally_reachable"] is True
            assert dossier["reachability"]["ipc_context"]["is_rpc_handler"] is True

    def test_no_ipc_data_graceful(self):
        func = _make_function_record(function_id=1, function_name="InternalFunc")
        fi = _make_file_info(file_name=None)
        dossier = _build(func, file_info=fi)
        ipc = dossier["reachability"]["ipc_context"]
        assert ipc["is_rpc_handler"] is False
        assert ipc["is_com_method"] is False
        assert ipc["is_winrt_method"] is False


# ---------------------------------------------------------------------------
# Data Exposure
# ---------------------------------------------------------------------------

class TestDataExposure:
    def test_receives_external_from_export(self):
        exports = json.dumps([
            {"function_name": "ExportA", "ordinal": 1,
             "address": "0x1000", "is_forwarded": False},
        ])
        export_func = _make_function_record(
            function_id=1, function_name="ExportA",
            simple_outbound_xrefs=json.dumps([
                {"function_name": "Inner", "function_id": 2,
                 "module_name": "internal", "function_type": 1,
                 "extraction_type": "script", "xref_type": "Call Near"},
            ]),
        )
        inner_func = _make_function_record(
            function_id=2, function_name="Inner",
            simple_inbound_xrefs=json.dumps([
                {"function_name": "ExportA", "function_id": 1,
                 "module_name": "internal", "function_type": 1,
                 "extraction_type": "script", "xref_type": "Call Near"},
            ]),
        )
        fi = _make_file_info(exports=exports)
        dossier = _build(
            inner_func, all_functions=[export_func, inner_func], file_info=fi,
        )
        assert dossier["data_exposure"]["receives_external_data"] is True

    def test_param_risk_in_output(self):
        func = _make_function_record(
            function_id=1, function_name="Foo",
            function_signature="void Foo(LPVOID buf, DWORD size)",
        )
        dossier = _build(func)
        exposure = dossier["data_exposure"]
        assert "param_surface" in exposure
        ps = exposure["param_surface"]
        assert ps["has_buffer_size_pair"] is True

    def test_entry_type_tagged(self):
        entries = json.dumps([
            {"function_name": "EP", "address": "0x2000"},
        ])
        ep_func = _make_function_record(
            function_id=1, function_name="EP",
            simple_outbound_xrefs=json.dumps([
                {"function_name": "Worker", "function_id": 2,
                 "module_name": "internal", "function_type": 1,
                 "extraction_type": "script", "xref_type": "Call Near"},
            ]),
        )
        worker = _make_function_record(
            function_id=2, function_name="Worker",
            simple_inbound_xrefs=json.dumps([
                {"function_name": "EP", "function_id": 1,
                 "module_name": "internal", "function_type": 1,
                 "extraction_type": "script", "xref_type": "Call Near"},
            ]),
        )
        fi = _make_file_info(entry_point=entries)
        dossier = _build(worker, all_functions=[ep_func, worker], file_info=fi)
        paths = dossier["data_exposure"]["data_paths"]
        assert len(paths) >= 1
        assert paths[0]["entry_type"] == "entry_point"


# ---------------------------------------------------------------------------
# Module Security
# ---------------------------------------------------------------------------

class TestModuleSecurity:
    def test_no_module_security_in_output(self):
        func = _make_function_record(function_id=1, function_name="F")
        fi = _make_file_info(
            security_features=json.dumps({
                "aslr_enabled": True, "dep_enabled": True,
                "cfg_enabled": False, "seh_enabled": True,
            }),
        )
        dossier = _build(func, file_info=fi)
        assert "module_security" not in dossier


# ---------------------------------------------------------------------------
# Data Quality
# ---------------------------------------------------------------------------

class TestDataQuality:
    def test_analysis_errors_surfaced(self):
        func = _make_function_record(
            function_id=1, function_name="Broken",
            analysis_errors=json.dumps(["timeout during decompilation"]),
        )
        dossier = _build(func)
        assert "data_quality" in dossier
        assert dossier["data_quality"]["has_issues"] is True
        assert dossier["data_quality"]["error_count"] == 1

    def test_no_errors_no_section(self):
        func = _make_function_record(function_id=1, function_name="Clean")
        dossier = _build(func)
        assert "data_quality" not in dossier


# ---------------------------------------------------------------------------
# Neighbors
# ---------------------------------------------------------------------------

class TestNeighbors:
    def test_vtable_class_detection(self):
        func = _make_function_record(
            function_id=1, function_name="DoStuff",
            vtable_contexts=json.dumps([
                {"reconstructed_classes": ["CMyClass::VtableSlot0"]},
            ]),
        )
        dossier = _build(func)
        assert "CMyClass" in dossier["neighboring_context"]["vtable_classes"]
