"""Tests for the COM index helper and COM integration across the runtime.

Covers:
  - helpers/com_index.py  (ComMethod, ComInterface, ComServer, ComIndex)
  - Risk tier logic  (privilege-boundary scoring)
  - Parsing helpers  (GUID extraction, SDDL checks, path normalization)
  - Index build + query  (fixture-based)
  - Multi-context loading  (4 access contexts)
  - Hex address filtering  (raw 0x... addresses excluded)
  - DLL surrogate classification  (effectively OOP)
  - Singleton access  (get_com_index / invalidate_com_index)
  - Secondary indexes  (_by_service, _by_interface_guid)
  - Live index tests  (against config/assets/com_data/)
  - Config integration  (defaults.json com keys)
  - Registry entries  (skills + commands registry, file existence)
  - Edge cases  (empty data, missing files, CLSID normalization)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

_AGENT_DIR = Path(__file__).resolve().parent.parent
if str(_AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENT_DIR))


from helpers.db_paths import module_name_from_path
from helpers.com_index import (
    ComAccessContext,
    ComIndex,
    ComInterface,
    ComMethod,
    ComServer,
    _is_permissive_sddl,
    _parse_guid_from_pseudo_idl,
    _parse_server_detail,
    get_com_index,
    invalidate_com_index,
)


# ===================================================================
# ComMethod dataclass
# ===================================================================

class TestComMethod:
    """Unit tests for the ComMethod dataclass."""

    def test_basic_fields(self):
        m = ComMethod(
            access="DIRECT", type="TYPELIB",
            name="AcceptEula",
            file="C:\\Windows\\System32\\wuapi.dll",
            interface_name="IUpdate3",
        )
        assert m.access == "DIRECT"
        assert m.type == "TYPELIB"
        assert m.interface_name == "IUpdate3"

    def test_short_name(self):
        m = ComMethod(
            access="DIRECT", type="VTABLE",
            name="CBlbEngineWrapper::Initialize",
            file="",
        )
        assert m.short_name == "Initialize"

    def test_short_name_no_colons(self):
        m = ComMethod(access="DIRECT", type="TYPELIB", name="AcceptEula", file="")
        assert m.short_name == "AcceptEula"

    def test_class_name(self):
        m = ComMethod(
            access="DIRECT", type="VTABLE",
            name="CBlbEngineWrapper::Initialize",
            file="",
        )
        assert m.class_name == "CBlbEngineWrapper"

    def test_class_name_empty_for_simple(self):
        m = ComMethod(access="DIRECT", type="TYPELIB", name="AcceptEula", file="")
        assert m.class_name == ""

    def test_binary_name(self):
        m = ComMethod(
            access="DIRECT", type="TYPELIB", name="Foo",
            file="C:\\Windows\\System32\\wuapi.dll",
        )
        assert m.binary_name == "wuapi.dll"

    def test_binary_name_empty(self):
        m = ComMethod(access="DIRECT", type="TYPELIB", name="Foo", file="")
        assert m.binary_name == ""

    def test_to_dict(self):
        m = ComMethod(
            access="DIRECT", type="TYPELIB",
            name="Cls::Method",
            file="C:\\test.dll",
            interface_name="ITest",
        )
        d = m.to_dict()
        assert d["access"] == "DIRECT"
        assert d["short_name"] == "Method"
        assert d["binary_name"] == "test.dll"
        assert d["interface_name"] == "ITest"


# ===================================================================
# ComInterface dataclass
# ===================================================================

class TestComInterface:
    """Unit tests for the ComInterface dataclass."""

    def test_basic_fields(self):
        iface = ComInterface(
            name="IUpdate3",
            guid="c08956a0-1cd3-11d1-b1c5-00805fc1270e",
            methods=[
                ComMethod(access="DIRECT", type="TYPELIB", name="AcceptEula", file="wuapi.dll"),
                ComMethod(access="DIRECT", type="TYPELIB", name="CopyFromCache", file="wuapi.dll"),
            ],
            pseudo_idl=['[Guid("c08956a0-1cd3-11d1-b1c5-00805fc1270e")]', "interface IUpdate3 : IUnknown {", "}"],
        )
        assert iface.method_count == 2
        assert iface.guid == "c08956a0-1cd3-11d1-b1c5-00805fc1270e"

    def test_empty_interface(self):
        iface = ComInterface(name="IEmpty")
        assert iface.method_count == 0
        assert iface.guid == ""
        assert iface.pseudo_idl == []

    def test_to_dict(self):
        iface = ComInterface(
            name="ITest", guid="abc-123",
            methods=[ComMethod(access="DIRECT", type="TYPELIB", name="M", file="t.dll")],
        )
        d = iface.to_dict()
        assert d["name"] == "ITest"
        assert d["guid"] == "abc-123"
        assert d["method_count"] == 1
        assert len(d["methods"]) == 1


# ===================================================================
# ComAccessContext enum
# ===================================================================

class TestComAccessContext:
    """Unit tests for the ComAccessContext enum."""

    def test_members_exist(self):
        assert ComAccessContext.HIGH_IL_ALL is not None
        assert ComAccessContext.HIGH_IL_PRIVILEGED is not None
        assert ComAccessContext.MEDIUM_IL_ALL is not None
        assert ComAccessContext.MEDIUM_IL_PRIVILEGED is not None

    def test_caller_il(self):
        assert ComAccessContext.HIGH_IL_ALL.caller_il == "high"
        assert ComAccessContext.MEDIUM_IL_PRIVILEGED.caller_il == "medium"

    def test_is_privileged_server(self):
        assert ComAccessContext.HIGH_IL_PRIVILEGED.is_privileged_server is True
        assert ComAccessContext.HIGH_IL_ALL.is_privileged_server is False
        assert ComAccessContext.MEDIUM_IL_PRIVILEGED.is_privileged_server is True

    def test_string_conversion(self):
        s = str(ComAccessContext.HIGH_IL_ALL)
        assert "high_il_all" == s


# ===================================================================
# ComServer dataclass
# ===================================================================

class TestComServer:
    """Unit tests for ComServer computed properties."""

    def test_out_of_process_localserver32(self):
        srv = ComServer(clsid="aaa", name="Test", server_type="LocalServer32")
        assert srv.is_out_of_process is True
        assert srv.is_in_process is False

    def test_in_process(self):
        srv = ComServer(clsid="aaa", name="Test", server_type="InProcServer32")
        assert srv.is_out_of_process is False
        assert srv.is_in_process is True

    def test_dll_surrogate_is_oop(self):
        srv = ComServer(clsid="aaa", name="Test", server_type="InProcServer32", has_dll_surrogate=True)
        assert srv.is_out_of_process is True
        assert srv.is_in_process is False

    def test_runs_as_system_via_run_as(self):
        srv = ComServer(clsid="aaa", name="Test", run_as="NT AUTHORITY\\SYSTEM")
        assert srv.runs_as_system is True

    def test_runs_as_system_via_service_user(self):
        srv = ComServer(clsid="aaa", name="Test", service_user="LocalSystem")
        assert srv.runs_as_system is True

    def test_runs_as_system_false(self):
        srv = ComServer(clsid="aaa", name="Test", service_user="NT AUTHORITY\\LocalService")
        assert srv.runs_as_system is False

    def test_has_permissive_launch(self):
        srv = ComServer(
            clsid="aaa", name="Test",
            launch_permission="O:PSG:BUD:(A;;CCDCLCSWRP;;;WD)",
        )
        assert srv.has_permissive_launch is True

    def test_has_permissive_launch_via_appid(self):
        srv = ComServer(
            clsid="aaa", name="Test",
            app_id_launch_permission="O:PSG:BUD:(A;;CCDCLCSWRP;;;AC)",
        )
        assert srv.has_permissive_launch is True

    def test_not_permissive_launch(self):
        srv = ComServer(clsid="aaa", name="Test", launch_permission="O:SYG:SYD:")
        assert srv.has_permissive_launch is False

    def test_has_permissive_access(self):
        srv = ComServer(
            clsid="aaa", name="Test",
            access_permission="O:PSG:BUD:(A;;CCDCLCSWRP;;;WD)",
        )
        assert srv.has_permissive_access is True

    def test_is_remote_activatable(self):
        srv = ComServer(clsid="aaa", name="Test", supports_remote_activation=True)
        assert srv.is_remote_activatable is True

    def test_is_trusted_marshaller(self):
        srv = ComServer(clsid="aaa", name="Test", trusted_marshaller=True)
        assert srv.is_trusted_marshaller is True

    def test_can_elevate(self):
        srv = ComServer(clsid="aaa", name="Test", can_elevate=True)
        assert srv.can_elevate is True

    def test_interface_and_method_counts(self):
        m1 = ComMethod(access="DIRECT", type="TYPELIB", name="A", file="")
        m2 = ComMethod(access="DIRECT", type="TYPELIB", name="B", file="")
        srv = ComServer(
            clsid="aaa", name="Test",
            interfaces=[ComInterface(name="I1", methods=[m1, m2])],
            methods_flat=[m1, m2],
        )
        assert srv.interface_count == 1
        assert srv.method_count == 2

    def test_to_dict(self):
        srv = ComServer(
            clsid="bfe18e9c-6d87-4450-b37c-e02f0b373803",
            name="AutomaticUpdates", server_type="LocalServer32",
            service_user="LocalSystem",
            access_contexts={ComAccessContext.MEDIUM_IL_PRIVILEGED},
        )
        d = srv.to_dict()
        assert d["clsid"] == "bfe18e9c-6d87-4450-b37c-e02f0b373803"
        assert d["name"] == "AutomaticUpdates"
        assert d["is_out_of_process"] is True
        assert d["runs_as_system"] is True


# ===================================================================
# Risk tier logic
# ===================================================================

class TestRiskTier:
    """Tests for the COM privilege-boundary risk model."""

    def test_critical_medium_il_system_oop(self):
        srv = ComServer(
            clsid="aaa", name="Test", server_type="LocalServer32",
            service_user="LocalSystem",
            access_contexts={ComAccessContext.MEDIUM_IL_PRIVILEGED},
        )
        assert srv.risk_tier(ComAccessContext.MEDIUM_IL_PRIVILEGED) == "critical"
        assert srv.best_risk_tier == "critical"

    def test_high_medium_il_can_elevate(self):
        srv = ComServer(
            clsid="aaa", name="Test", server_type="LocalServer32",
            can_elevate=True,
            access_contexts={ComAccessContext.MEDIUM_IL_ALL},
        )
        assert srv.risk_tier(ComAccessContext.MEDIUM_IL_ALL) == "high"

    def test_high_medium_il_permissive_launch(self):
        srv = ComServer(
            clsid="aaa", name="Test", server_type="LocalServer32",
            launch_permission="O:PSG:BUD:(A;;CCDCLCSWRP;;;WD)",
            access_contexts={ComAccessContext.MEDIUM_IL_ALL},
        )
        assert srv.risk_tier(ComAccessContext.MEDIUM_IL_ALL) == "high"

    def test_medium_high_il_system_oop(self):
        srv = ComServer(
            clsid="aaa", name="Test", server_type="LocalServer32",
            service_user="LocalSystem",
            access_contexts={ComAccessContext.HIGH_IL_PRIVILEGED},
        )
        assert srv.risk_tier(ComAccessContext.HIGH_IL_PRIVILEGED) == "medium"

    def test_medium_can_elevate(self):
        srv = ComServer(
            clsid="aaa", name="Test", server_type="InProcServer32",
            can_elevate=True,
            access_contexts={ComAccessContext.HIGH_IL_ALL},
        )
        assert srv.risk_tier(ComAccessContext.HIGH_IL_ALL) == "medium"

    def test_medium_auto_elevation(self):
        srv = ComServer(
            clsid="aaa", name="Test", server_type="InProcServer32",
            auto_elevation=True,
            access_contexts={ComAccessContext.HIGH_IL_ALL},
        )
        assert srv.risk_tier(ComAccessContext.HIGH_IL_ALL) == "medium"

    def test_low_default(self):
        srv = ComServer(
            clsid="aaa", name="Test", server_type="InProcServer32",
            access_contexts={ComAccessContext.HIGH_IL_ALL},
        )
        assert srv.risk_tier(ComAccessContext.HIGH_IL_ALL) == "low"

    def test_dll_surrogate_gets_oop_risk(self):
        srv = ComServer(
            clsid="aaa", name="Test", server_type="InProcServer32",
            has_dll_surrogate=True, service_user="LocalSystem",
            access_contexts={ComAccessContext.MEDIUM_IL_PRIVILEGED},
        )
        assert srv.is_out_of_process is True
        assert srv.risk_tier(ComAccessContext.MEDIUM_IL_PRIVILEGED) == "critical"

    def test_best_risk_tier_picks_highest(self):
        srv = ComServer(
            clsid="aaa", name="Test", server_type="LocalServer32",
            service_user="LocalSystem",
            access_contexts={
                ComAccessContext.HIGH_IL_ALL,
                ComAccessContext.MEDIUM_IL_PRIVILEGED,
            },
        )
        assert srv.best_risk_tier == "critical"

    def test_best_risk_tier_no_contexts(self):
        srv = ComServer(clsid="aaa", name="Test", server_type="InProcServer32")
        assert srv.best_risk_tier == "low"


# ===================================================================
# Parsing helpers
# ===================================================================

class TestParsingHelpers:
    """Unit tests for COM data parsing utilities."""

    def test_parse_guid_from_pseudo_idl(self):
        lines = [
            '[Guid("c08956a0-1cd3-11d1-b1c5-00805fc1270e")]',
            "interface IUpdate3 : IUnknown {",
            "}",
        ]
        assert _parse_guid_from_pseudo_idl(lines) == "c08956a0-1cd3-11d1-b1c5-00805fc1270e"

    def test_parse_guid_missing(self):
        assert _parse_guid_from_pseudo_idl(["interface ITest : IUnknown {"]) == ""

    def test_parse_guid_empty(self):
        assert _parse_guid_from_pseudo_idl([]) == ""

    def test_module_name_from_path(self):
        assert module_name_from_path("C:\\Windows\\System32\\wuapi.dll") == "wuapi.dll"
        assert module_name_from_path("c:\\windows\\system32\\svchost.exe") == "svchost.exe"

    def test_is_permissive_sddl_wd(self):
        assert _is_permissive_sddl("O:PSG:BUD:(A;;CCDCLCSWRP;;;WD)") is True

    def test_is_permissive_sddl_ac(self):
        assert _is_permissive_sddl("O:PSG:BUD:(A;;CCDCLCSWRP;;;AC)") is True

    def test_is_permissive_sddl_restrictive(self):
        assert _is_permissive_sddl("O:SYG:SYD:") is False

    def test_is_permissive_sddl_empty(self):
        assert _is_permissive_sddl("") is False

    def test_parse_server_detail_basic(self):
        raw = {
            "clsid": "bfe18e9c-6d87-4450-b37c-e02f0b373803",
            "display_name": "AutomaticUpdates",
            "registration_type": "LocalServer32",
            "can_elevate": False,
            "auto_elevate": False,
            "elevation_policy": None,
            "has_launch_permission": True,
            "has_run_as_identity": False,
            "access_permission_sddl": "",
            "launch_permission_sddl": "",
            "run_as_identity": "",
            "clsctx_flags": 4,
            "supports_remote_activation": False,
            "is_trusted_marshaller": False,
            "in_trusted_marshaller_category": False,
            "has_typelib": True,
            "app_id": {},
            "interfaces": [],
            "typelib_interfaces": {},
        }
        srv = _parse_server_detail("bfe18e9c-6d87-4450-b37c-e02f0b373803", raw, "wuapi.dll")
        assert srv.name == "AutomaticUpdates"
        assert srv.hosting_binary == "wuapi.dll"
        assert srv.method_count == 0

    def test_parse_server_detail_with_interfaces(self):
        raw = {
            "display_name": "TestServer",
            "registration_type": "InProcServer32",
            "can_elevate": False,
            "auto_elevate": False,
            "elevation_policy": None,
            "has_launch_permission": False,
            "has_run_as_identity": False,
            "access_permission_sddl": "",
            "launch_permission_sddl": "",
            "run_as_identity": "",
            "clsctx_flags": 1,
            "supports_remote_activation": False,
            "is_trusted_marshaller": False,
            "in_trusted_marshaller_category": False,
            "has_typelib": False,
            "app_id": {},
            "interfaces": [
                {
                    "iface_name": "ITestInterface_(aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee)",
                    "methods": [
                        {"access_type": "DIRECT", "dispatch_type": "VTABLE", "method_name": "Cls::Method", "binary_path": "C:\\test.dll"},
                    ],
                    "pseudo_idl": [
                        '[Guid("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")]',
                        "interface ITestInterface : IUnknown {",
                        "}",
                    ],
                }
            ],
            "typelib_interfaces": {},
        }
        srv = _parse_server_detail("11111111-2222-3333-4444-555555555555", raw)
        assert srv.method_count == 1
        assert srv.interface_count == 1
        assert srv.interfaces[0].guid == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


# ===================================================================
# ComIndex building and querying (fixtures)
# ===================================================================

def _make_com_server_entry(clsid, name, reg_type, **overrides):
    """Helper to build a binary-keyed server entry with defaults."""
    base = {
        "clsid": clsid,
        "display_name": name,
        "registration_type": reg_type,
        "can_elevate": False,
        "auto_elevate": False,
        "elevation_policy": None,
        "has_launch_permission": False,
        "has_run_as_identity": False,
        "access_permission_sddl": "",
        "launch_permission_sddl": "",
        "run_as_identity": "",
        "clsctx_flags": 1,
        "supports_remote_activation": False,
        "is_trusted_marshaller": False,
        "in_trusted_marshaller_category": False,
        "has_typelib": False,
        "app_id": {},
        "interfaces": [],
        "typelib_interfaces": {},
    }
    base.update(overrides)
    return base


@pytest.fixture
def sample_com_data():
    """Minimal COM binary-keyed JSON structure."""
    return {
        "c:\\windows\\system32\\test.dll": {
            "binary_path": "C:\\Windows\\System32\\test.dll",
            "servers": [
                _make_com_server_entry(
                    "aaaa1111-bbbb-cccc-dddd-eeeeeeeeeeee", "TestInProc", "InProcServer32",
                    app_id={
                        "app_id_guid": "", "is_service": False, "service_name": "",
                        "has_dll_surrogate": False, "launch_permission_sddl": "",
                        "access_permission_sddl": "", "allows_low_il_access": False,
                        "allows_low_il_launch": False,
                    },
                    interfaces=[{
                        "iface_name": "ITestA",
                        "methods": [
                            {"access_type": "DIRECT", "dispatch_type": "VTABLE", "method_name": "TestClass::MethodOne", "binary_path": "C:\\Windows\\System32\\test.dll"},
                            {"access_type": "DIRECT", "dispatch_type": "VTABLE", "method_name": "TestClass::MethodTwo", "binary_path": "C:\\Windows\\System32\\test.dll"},
                        ],
                        "pseudo_idl": [
                            '[Guid("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")]',
                            "interface ITestA : IUnknown {",
                            "    HRESULT MethodOne();",
                            "    HRESULT MethodTwo();",
                            "}",
                        ],
                    }],
                ),
            ],
            "procedures": ["TestClass::MethodOne", "TestClass::MethodTwo"],
        },
        "c:\\windows\\system32\\svchost.exe": {
            "binary_path": "C:\\Windows\\System32\\svchost.exe",
            "servers": [
                _make_com_server_entry(
                    "bbbb2222-cccc-dddd-eeee-ffffffffffff", "TestOOP", "LocalServer32",
                    can_elevate=True, has_launch_permission=True, clsctx_flags=4,
                    access_permission_sddl="O:PSG:BUD:(A;;CCDCLCSWRP;;;WD)",
                    launch_permission_sddl="O:PSG:BUD:(A;;CCDCLCSWRP;;;WD)",
                    supports_remote_activation=True, has_typelib=True,
                    app_id={
                        "app_id_guid": "e7299e79-75e5-47bb-a03d-6d319fb7f886",
                        "is_service": True, "service_name": "TestSvc",
                        "has_dll_surrogate": False,
                        "launch_permission_sddl": "O:PSG:BUD:(A;;CCDCLCSWRP;;;WD)",
                        "access_permission_sddl": "O:PSG:BUD:(A;;CCDCLCSWRP;;;WD)",
                        "allows_low_il_access": False, "allows_low_il_launch": False,
                        "local_service": {
                            "display_name": "Test Service", "service_name": "TestSvc",
                            "service_type": 48, "account": "LocalSystem",
                            "image_path": "C:\\WINDOWS\\system32\\svchost.exe -k netsvcs -p",
                            "service_dll": "C:\\WINDOWS\\system32\\testsvc.dll",
                            "protection_level": 0,
                        },
                    },
                    interfaces=[{
                        "iface_name": "ITestB",
                        "methods": [
                            {"access_type": "DIRECT", "dispatch_type": "TYPELIB", "method_name": "LaunchProcess", "binary_path": "C:\\Windows\\System32\\other.dll"},
                            {"access_type": "DIRECT", "dispatch_type": "TYPELIB", "method_name": "GetConfig", "binary_path": "C:\\Windows\\System32\\other.dll"},
                            {"access_type": "DIRECT", "dispatch_type": "TYPELIB", "method_name": "SetPolicy", "binary_path": "C:\\Windows\\System32\\other.dll"},
                        ],
                        "pseudo_idl": [
                            '[Guid("11111111-2222-3333-4444-555555555555")]',
                            "interface ITestB : IUnknown {",
                            "}",
                        ],
                    }],
                ),
            ],
            "procedures": [],
        },
        "c:\\windows\\system32\\other.dll": {
            "binary_path": "C:\\Windows\\System32\\other.dll",
            "servers": [],
            "procedures": ["LaunchProcess", "GetConfig", "SetPolicy"],
        },
        "c:\\windows\\system32\\noisy.dll": {
            "binary_path": "C:\\Windows\\System32\\noisy.dll",
            "servers": [],
            "procedures": ["0x7FFEDAED8BC0", "0x7FFEDAED8CA0", "RealFunc"],
        },
    }


@pytest.fixture
def loaded_com_index(sample_com_data, tmp_path):
    """Build and return a loaded ComIndex from sample data."""
    ctx_dir = tmp_path / "extracted_high_il" / "all_servers"
    ctx_dir.mkdir(parents=True)

    with open(ctx_dir / "com_servers.json", "w") as f:
        json.dump(sample_com_data, f)

    med_dir = tmp_path / "extracted_medium_il" / "medium_il" / "privileged_servers"
    med_dir.mkdir(parents=True)
    med_data = {
        "c:\\windows\\system32\\svchost.exe": sample_com_data["c:\\windows\\system32\\svchost.exe"],
        "c:\\windows\\system32\\other.dll": sample_com_data["c:\\windows\\system32\\other.dll"],
    }
    with open(med_dir / "com_servers.json", "w") as f:
        json.dump(med_data, f)

    idx = ComIndex()
    idx.load(data_root=tmp_path)
    return idx


class TestComIndex:
    """Tests for ComIndex query methods."""

    def test_loaded_flag(self, loaded_com_index):
        assert loaded_com_index.loaded is True

    def test_server_count(self, loaded_com_index):
        assert loaded_com_index.server_count == 2

    def test_module_count(self, loaded_com_index):
        assert loaded_com_index.module_count >= 2

    def test_total_methods(self, loaded_com_index):
        assert loaded_com_index.total_methods == 5

    def test_get_servers_for_module(self, loaded_com_index):
        servers = loaded_com_index.get_servers_for_module("test.dll")
        assert len(servers) == 1
        assert servers[0].name == "TestInProc"

    def test_get_servers_case_insensitive(self, loaded_com_index):
        servers = loaded_com_index.get_servers_for_module("TEST.DLL")
        assert len(servers) == 1

    def test_get_servers_nonexistent(self, loaded_com_index):
        assert loaded_com_index.get_servers_for_module("nosuch.dll") == []

    def test_get_server_by_clsid(self, loaded_com_index):
        srv = loaded_com_index.get_server_by_clsid("aaaa1111-bbbb-cccc-dddd-eeeeeeeeeeee")
        assert srv is not None
        assert srv.name == "TestInProc"

    def test_get_server_by_clsid_case_insensitive(self, loaded_com_index):
        srv = loaded_com_index.get_server_by_clsid("AAAA1111-BBBB-CCCC-DDDD-EEEEEEEEEEEE")
        assert srv is not None

    def test_get_server_by_clsid_not_found(self, loaded_com_index):
        assert loaded_com_index.get_server_by_clsid("00000000-0000-0000-0000-000000000000") is None

    def test_get_procedures_for_module(self, loaded_com_index):
        procs = loaded_com_index.get_procedures_for_module("test.dll")
        assert "TestClass::MethodOne" in procs
        assert len(procs) == 2

    def test_is_com_procedure_true(self, loaded_com_index):
        assert loaded_com_index.is_com_procedure(
            "test.dll", "TestClass::MethodOne"
        ) is True

    def test_is_com_procedure_false(self, loaded_com_index):
        assert loaded_com_index.is_com_procedure("test.dll", "NoSuchFunc") is False

    def test_is_com_procedure_wrong_module(self, loaded_com_index):
        assert loaded_com_index.is_com_procedure(
            "other.dll", "TestClass::MethodOne"
        ) is False

    def test_get_interfaces_for_module(self, loaded_com_index):
        ifaces = loaded_com_index.get_interfaces_for_module("test.dll")
        assert len(ifaces) == 1
        assert ifaces[0].name == "ITestA"
        assert ifaces[0].guid == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    def test_get_methods_for_clsid(self, loaded_com_index):
        methods = loaded_com_index.get_methods_for_clsid("bbbb2222-cccc-dddd-eeee-ffffffffffff")
        assert len(methods) == 3
        names = {m.short_name for m in methods}
        assert "LaunchProcess" in names
        assert "GetConfig" in names

    def test_search_methods(self, loaded_com_index):
        results = loaded_com_index.search_methods("Launch")
        assert len(results) == 1
        assert results[0].short_name == "LaunchProcess"

    def test_search_methods_regex(self, loaded_com_index):
        results = loaded_com_index.search_methods(r"Method(One|Two)")
        assert len(results) == 2

    def test_search_methods_invalid_regex(self, loaded_com_index):
        assert loaded_com_index.search_methods("[invalid") == []

    def test_get_all_clsids(self, loaded_com_index):
        clsids = loaded_com_index.get_all_clsids()
        assert "aaaa1111-bbbb-cccc-dddd-eeeeeeeeeeee" in clsids
        assert "bbbb2222-cccc-dddd-eeee-ffffffffffff" in clsids

    def test_get_all_modules(self, loaded_com_index):
        modules = loaded_com_index.get_all_modules()
        assert "test.dll" in modules

    def test_summary(self, loaded_com_index):
        s = loaded_com_index.summary()
        assert s["total_servers"] == 2
        assert s["total_modules"] >= 2
        assert s["total_methods"] == 5
        assert "by_tier" in s
        assert "by_server_type" in s
        assert "can_elevate" in s
        assert "trusted_marshaller" in s

    def test_get_servers_by_risk(self, loaded_com_index):
        low = loaded_com_index.get_servers_by_risk("low")
        names = {s.name for s in low}
        assert "TestInProc" in names

    def test_get_elevatable_servers(self, loaded_com_index):
        elevatable = loaded_com_index.get_elevatable_servers()
        names = {s.name for s in elevatable}
        assert "TestOOP" in names


# ===================================================================
# Hex address filtering
# ===================================================================

class TestHexAddressFiltering:
    """Tests that raw hex addresses are excluded from procedure lists."""

    def test_hex_addresses_filtered(self, loaded_com_index):
        procs = loaded_com_index.get_procedures_for_module("noisy.dll")
        assert "RealFunc" in procs
        assert "0x7FFEDAED8BC0" not in procs
        assert "0x7FFEDAED8CA0" not in procs

    def test_hex_not_com_procedure(self, loaded_com_index):
        assert loaded_com_index.is_com_procedure("noisy.dll", "0x7FFEDAED8BC0") is False

    def test_real_func_is_com_procedure(self, loaded_com_index):
        assert loaded_com_index.is_com_procedure("noisy.dll", "RealFunc") is True


# ===================================================================
# Secondary indexes
# ===================================================================

class TestSecondaryIndexes:
    """Tests for _by_service and _by_interface_guid secondary indexes."""

    def test_get_servers_by_service(self, loaded_com_index):
        servers = loaded_com_index.get_servers_by_service("TestSvc")
        assert len(servers) == 1
        assert servers[0].name == "TestOOP"

    def test_get_servers_by_service_case_insensitive(self, loaded_com_index):
        servers = loaded_com_index.get_servers_by_service("TESTSVC")
        assert len(servers) == 1

    def test_get_servers_by_service_not_found(self, loaded_com_index):
        assert loaded_com_index.get_servers_by_service("NoSuchSvc") == []

    def test_find_servers_for_interface(self, loaded_com_index):
        servers = loaded_com_index.find_servers_for_interface("11111111-2222-3333-4444-555555555555")
        assert len(servers) == 1
        assert servers[0].name == "TestOOP"

    def test_find_servers_for_interface_case_insensitive(self, loaded_com_index):
        servers = loaded_com_index.find_servers_for_interface("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")
        assert len(servers) == 1

    def test_find_servers_for_interface_not_found(self, loaded_com_index):
        assert loaded_com_index.find_servers_for_interface("00000000-0000-0000-0000-000000000000") == []

    def test_get_all_services(self, loaded_com_index):
        services = loaded_com_index.get_all_services()
        assert "testsvc" in services


# ===================================================================
# Multi-context loading
# ===================================================================

class TestMultiContextLoading:
    """Tests for loading across multiple access contexts."""

    def test_clsid_in_multiple_contexts(self, loaded_com_index):
        srv = loaded_com_index.get_server_by_clsid("bbbb2222-cccc-dddd-eeee-ffffffffffff")
        assert srv is not None
        contexts = srv.access_contexts
        assert ComAccessContext.HIGH_IL_ALL in contexts
        assert ComAccessContext.MEDIUM_IL_PRIVILEGED in contexts

    def test_get_access_contexts_for_clsid(self, loaded_com_index):
        contexts = loaded_com_index.get_access_contexts_for_clsid("bbbb2222-cccc-dddd-eeee-ffffffffffff")
        assert len(contexts) >= 2

    def test_privileged_surface(self, loaded_com_index):
        priv = loaded_com_index.get_privileged_surface("medium")
        names = {s.name for s in priv}
        assert "TestOOP" in names

    def test_get_access_contexts_nonexistent(self, loaded_com_index):
        assert loaded_com_index.get_access_contexts_for_clsid("00000000-0000-0000-0000-000000000000") == set()


# ===================================================================
# Singleton access
# ===================================================================

class TestSingleton:
    """Tests for get_com_index / invalidate_com_index."""

    def test_get_com_index_returns_same_instance(self):
        invalidate_com_index()
        idx1 = get_com_index()
        idx2 = get_com_index()
        assert idx1 is idx2

    def test_invalidate_forces_reload(self):
        idx1 = get_com_index()
        invalidate_com_index()
        idx2 = get_com_index()
        assert idx1 is not idx2

    def test_disabled_returns_empty_index(self):
        invalidate_com_index()
        with patch("helpers.com_index.get_config_value") as mock_cfg:
            mock_cfg.return_value = False
            idx = get_com_index(force_reload=True)
            assert idx.loaded is False
            assert idx.server_count == 0
        invalidate_com_index()


# ===================================================================
# Live index tests (against actual data)
# ===================================================================

class TestLiveIndex:
    """Tests against the actual COM data files in config/assets/com_data/."""

    @pytest.fixture(autouse=True)
    def _reset(self):
        invalidate_com_index()
        yield
        invalidate_com_index()

    def test_loads_from_data_root(self):
        idx = get_com_index()
        if not idx.loaded or idx.server_count == 0:
            pytest.skip("COM data not available or empty")
        assert idx.server_count > 50
        assert idx.module_count > 10

    def test_known_module_has_procedures(self):
        idx = get_com_index()
        if not idx.loaded:
            pytest.skip("COM data not available")
        procs = idx.get_procedures_for_module("wbengine.exe")
        if not procs:
            pytest.skip("Known module not in COM data")
        assert any("CBlbEngineWrapper" in p for p in procs)

    def test_privileged_surface_nonempty(self):
        idx = get_com_index()
        if not idx.loaded or idx.server_count == 0:
            pytest.skip("COM data not available or empty")
        priv = idx.get_privileged_surface("medium")
        assert len(priv) > 0

    def test_summary_fields(self):
        idx = get_com_index()
        if not idx.loaded or idx.server_count == 0:
            pytest.skip("COM data not available or empty")
        s = idx.summary()
        assert s["total_servers"] > 0
        assert s["total_modules"] > 0

    def test_no_hex_addresses_in_procedures(self):
        idx = get_com_index()
        if not idx.loaded:
            pytest.skip("COM data not available")
        for mod in idx.get_all_modules()[:20]:
            procs = idx.get_procedures_for_module(mod)
            for p in procs:
                assert not p.startswith("0x"), f"Hex address leaked: {p} in {mod}"


# ===================================================================
# Config integration
# ===================================================================

class TestComConfig:
    """Tests for the com config section in defaults.json."""

    def test_com_section_exists(self):
        from helpers.config import get_config_value
        assert get_config_value("com.enabled") is True

    def test_com_data_root_configured(self):
        from helpers.config import get_config_value
        data_root = get_config_value("com.data_root")
        assert data_root is not None
        assert "com_data" in data_root

    def test_com_config_keys(self):
        root = Path(__file__).resolve().parent.parent
        with open(root / "config" / "defaults.json", "r") as f:
            config = json.load(f)
        assert "com" in config
        assert "enabled" in config["com"]
        assert "data_root" in config["com"]
        assert "cache_loaded_index" in config["com"]


# ===================================================================
# Registry entries
# ===================================================================

class TestRegistryEntries:
    """Tests that skill and command are properly registered."""

    def test_skill_registry_has_com_interface_analysis(self):
        root = Path(__file__).resolve().parent.parent
        with open(root / "skills" / "registry.json", "r") as f:
            reg = json.load(f)
        skills = reg.get("skills", {})
        assert "com-interface-analysis" in skills
        entry = skills["com-interface-analysis"]
        assert entry["type"] == "security"
        assert len(entry["entry_scripts"]) == 6

    def test_command_registry_has_com(self):
        root = Path(__file__).resolve().parent.parent
        with open(root / "commands" / "registry.json", "r") as f:
            reg = json.load(f)
        commands = reg.get("commands", {})
        assert "com" in commands
        entry = commands["com"]
        assert "com-interface-analysis" in entry["skills_used"]
        assert entry["file"] == "com.md"

    def test_command_md_file_exists(self):
        root = Path(__file__).resolve().parent.parent
        assert (root / "commands" / "com.md").exists()

    def test_skill_md_file_exists(self):
        root = Path(__file__).resolve().parent.parent
        assert (root / "skills" / "com-interface-analysis" / "SKILL.md").exists()

    def test_all_skill_scripts_exist(self):
        root = Path(__file__).resolve().parent.parent
        scripts_dir = root / "skills" / "com-interface-analysis" / "scripts"
        expected = [
            "_common.py",
            "resolve_com_server.py",
            "map_com_surface.py",
            "enumerate_com_methods.py",
            "classify_com_entrypoints.py",
            "audit_com_security.py",
            "find_com_privesc.py",
        ]
        for script in expected:
            assert (scripts_dir / script).exists(), f"Missing: {script}"


# ===================================================================
# Edge cases
# ===================================================================

class TestEdgeCases:
    """Tests for graceful degradation on edge-case data."""

    def test_empty_servers_details(self, tmp_path):
        ctx_dir = tmp_path / "extracted_high_il" / "all_servers"
        ctx_dir.mkdir(parents=True)
        with open(ctx_dir / "com_servers.json", "w") as f:
            json.dump({}, f)

        idx = ComIndex()
        idx.load(data_root=tmp_path)
        assert idx.loaded is False, "Empty server details should not set loaded=True"
        assert idx.server_count == 0
        assert idx.get_servers_for_module("any.dll") == []

    def test_server_without_interfaces(self):
        raw = _make_com_server_entry(
            "cccc3333-dddd-eeee-ffff-000000000000", "MetadataOnly", "LocalServer32",
            app_id={},
        )
        srv = _parse_server_detail("cccc3333-dddd-eeee-ffff-000000000000", raw, "test.dll")
        assert srv.method_count == 0
        assert srv.interface_count == 0
        assert srv.hosting_binary == "test.dll"

    def test_server_with_empty_pseudo_interfaces(self):
        raw = _make_com_server_entry(
            "dddd4444-eeee-ffff-0000-111111111111", "NoPseudo", "InProcServer32",
            app_id={},
            interfaces=[{
                "iface_name": "INoPseudo",
                "methods": [
                    {"access_type": "DIRECT", "dispatch_type": "VTABLE", "method_name": "Cls::Method", "binary_path": "a.dll"},
                ],
                "pseudo_idl": [],
            }],
        )
        srv = _parse_server_detail("dddd4444-eeee-ffff-0000-111111111111", raw)
        assert srv.method_count == 1
        assert srv.interfaces[0].guid == ""
        assert srv.interfaces[0].pseudo_idl == []

    def test_missing_data_dir(self, tmp_path):
        idx = ComIndex()
        idx.load(data_root=tmp_path / "nonexistent")
        assert idx.loaded is False
        assert idx.server_count == 0

    def test_all_contexts_missing(self, tmp_path):
        empty_root = tmp_path / "empty_root"
        empty_root.mkdir()
        idx = ComIndex()
        idx.load(data_root=empty_root)
        assert idx.loaded is False, "No context dirs means no data loaded"
        assert idx.server_count == 0
        assert idx.summary()["total_servers"] == 0

    def test_get_servers_by_risk_empty(self):
        idx = ComIndex()
        assert idx.get_servers_by_risk("critical") == []

    def test_pseudo_idl_with_guid(self):
        raw = _make_com_server_entry(
            "eeee5555-ffff-0000-1111-222222222222", "GuidSuffix", "InProcServer32",
            app_id={},
            interfaces=[{
                "iface_name": "IFoo_(12345678-1234-1234-1234-123456789abc)",
                "methods": [
                    {"access_type": "DIRECT", "dispatch_type": "VTABLE", "method_name": "Foo::Bar", "binary_path": "a.dll"},
                ],
                "pseudo_idl": [
                    '[Guid("12345678-1234-1234-1234-123456789abc")]',
                    "interface IFoo : IUnknown {",
                    "}",
                ],
            }],
        )
        srv = _parse_server_detail("eeee5555-ffff-0000-1111-222222222222", raw)
        assert srv.interfaces[0].guid == "12345678-1234-1234-1234-123456789abc"

    def test_pseudo_idl_no_guid(self):
        raw = _make_com_server_entry(
            "ffff6666-0000-1111-2222-333333333333", "NoGuid", "InProcServer32",
            app_id={},
            interfaces=[{
                "iface_name": "ID",
                "methods": [
                    {"access_type": "DIRECT", "dispatch_type": "VTABLE", "method_name": "Foo", "binary_path": "a.dll"},
                ],
                "pseudo_idl": [],
            }],
        )
        srv = _parse_server_detail("ffff6666-0000-1111-2222-333333333333", raw)
        assert srv.interfaces[0].guid == ""
