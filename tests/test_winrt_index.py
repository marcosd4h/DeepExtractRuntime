"""Tests for the WinRT index helper and WinRT integration across the runtime.

Covers:
  - helpers/winrt_index.py  (WinrtMethod, WinrtInterface, WinrtServer, WinrtIndex)
  - Risk tier logic  (privilege-boundary scoring)
  - Parsing helpers  (GUID extraction, SDDL checks, path normalization)
  - Index build + query  (fixture-based)
  - Multi-context loading  (4 access contexts)
  - Nostaterepo filtering  (exclude_staterepo config flag)
  - Singleton access  (get_winrt_index / invalidate_winrt_index)
  - Live index tests  (against work2/extraction_data/)
  - Config integration  (defaults.json winrt keys)
  - Registry entries  (skills + commands registry, file existence)
  - Edge cases  (empty data, missing files, offset-style names)
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
from helpers.winrt_index import (
    WinrtAccessContext,
    WinrtIndex,
    WinrtInterface,
    WinrtMethod,
    WinrtServer,
    _is_permissive_sddl,
    _parse_guid_from_pseudo_idl,
    _parse_server_detail,
    get_winrt_index,
    invalidate_winrt_index,
)


# ===================================================================
# WinrtMethod dataclass
# ===================================================================

class TestWinrtMethod:
    """Unit tests for the WinrtMethod dataclass."""

    def test_basic_fields(self):
        m = WinrtMethod(
            access="DIRECT", type="VTABLE",
            name="Windows::System::ShutdownManagerImpl::BeginShutdown",
            file="C:\\Windows\\System32\\Windows.System.SystemManagement.dll",
        )
        assert m.access == "DIRECT"
        assert m.type == "VTABLE"

    def test_short_name(self):
        m = WinrtMethod(
            access="DIRECT", type="VTABLE",
            name="Windows::System::ShutdownManagerImpl::BeginShutdown",
            file="",
        )
        assert m.short_name == "BeginShutdown"

    def test_short_name_no_colons(self):
        m = WinrtMethod(access="DIRECT", type="VTABLE", name="DllCanUnloadNow+0x7F60", file="")
        assert m.short_name == "DllCanUnloadNow+0x7F60"

    def test_class_name(self):
        m = WinrtMethod(
            access="DIRECT", type="VTABLE",
            name="Windows::System::ShutdownManagerImpl::BeginShutdown",
            file="",
        )
        assert m.class_name == "ShutdownManagerImpl"

    def test_binary_name(self):
        m = WinrtMethod(
            access="DIRECT", type="VTABLE", name="Foo::Bar",
            file="C:\\Windows\\System32\\test.dll",
        )
        assert m.binary_name == "test.dll"

    def test_binary_name_empty(self):
        m = WinrtMethod(access="DIRECT", type="VTABLE", name="Foo", file="")
        assert m.binary_name == ""

    def test_to_dict(self):
        m = WinrtMethod(
            access="DIRECT", type="VTABLE",
            name="Ns::Cls::Method",
            file="C:\\test.dll",
        )
        d = m.to_dict()
        assert d["access"] == "DIRECT"
        assert d["short_name"] == "Method"
        assert d["binary_name"] == "test.dll"


# ===================================================================
# WinrtInterface dataclass
# ===================================================================

class TestWinrtInterface:
    """Unit tests for the WinrtInterface dataclass."""

    def test_basic_fields(self):
        iface = WinrtInterface(
            name="ITestStatics",
            guid="58ec0eef-4ff0-48a5-9bfc-435df052c258",
            methods=[
                WinrtMethod(access="DIRECT", type="VTABLE", name="Cls::MethodA", file="a.dll"),
                WinrtMethod(access="DIRECT", type="VTABLE", name="Cls::MethodB", file="a.dll"),
            ],
            pseudo_idl=["[Guid(\"58ec0eef-4ff0-48a5-9bfc-435df052c258\")]", "interface ITestStatics : IInspectable {", "}"],
        )
        assert iface.method_count == 2
        assert iface.guid == "58ec0eef-4ff0-48a5-9bfc-435df052c258"

    def test_empty_interface(self):
        iface = WinrtInterface(name="IEmpty")
        assert iface.method_count == 0
        assert iface.guid == ""
        assert iface.pseudo_idl == []

    def test_to_dict(self):
        iface = WinrtInterface(
            name="ITest", guid="abc-123",
            methods=[WinrtMethod(access="DIRECT", type="VTABLE", name="M", file="t.dll")],
        )
        d = iface.to_dict()
        assert d["name"] == "ITest"
        assert d["guid"] == "abc-123"
        assert d["method_count"] == 1
        assert len(d["methods"]) == 1


# ===================================================================
# WinrtAccessContext enum
# ===================================================================

class TestWinrtAccessContext:
    """Unit tests for the WinrtAccessContext enum."""

    def test_members_exist(self):
        assert WinrtAccessContext.HIGH_IL_ALL is not None
        assert WinrtAccessContext.HIGH_IL_PRIVILEGED is not None
        assert WinrtAccessContext.MEDIUM_IL_ALL is not None
        assert WinrtAccessContext.MEDIUM_IL_PRIVILEGED is not None

    def test_caller_il(self):
        assert WinrtAccessContext.HIGH_IL_ALL.caller_il == "high"
        assert WinrtAccessContext.MEDIUM_IL_PRIVILEGED.caller_il == "medium"

    def test_is_privileged_server(self):
        assert WinrtAccessContext.HIGH_IL_PRIVILEGED.is_privileged_server is True
        assert WinrtAccessContext.HIGH_IL_ALL.is_privileged_server is False
        assert WinrtAccessContext.MEDIUM_IL_PRIVILEGED.is_privileged_server is True

    def test_string_conversion(self):
        s = str(WinrtAccessContext.HIGH_IL_ALL)
        assert "high_il_all" == s


# ===================================================================
# WinrtServer dataclass
# ===================================================================

class TestWinrtServer:
    """Unit tests for WinrtServer computed properties."""

    def test_out_of_process(self):
        srv = WinrtServer(name="Test", activation_type="OutOfProcess")
        assert srv.is_out_of_process is True
        assert srv.is_in_process is False

    def test_in_process(self):
        srv = WinrtServer(name="Test", activation_type="InProcess")
        assert srv.is_out_of_process is False
        assert srv.is_in_process is True

    def test_runs_as_system(self):
        srv = WinrtServer(name="Test", server_identity="nt authority\\system")
        assert srv.runs_as_system is True

    def test_runs_as_system_false(self):
        srv = WinrtServer(name="Test", server_identity="")
        assert srv.runs_as_system is False

    def test_has_permissive_sddl_allow_wd(self):
        srv = WinrtServer(
            name="Test",
            server_permissions="O:PSG:BUD:(A;;CCDCLCSWRP;;;WD)(A;;CCDCLCSWRP;;;AC)",
        )
        assert srv.has_permissive_sddl is True

    def test_not_permissive_sddl(self):
        srv = WinrtServer(name="Test", server_permissions="O:SYG:SYD:")
        assert srv.has_permissive_sddl is False

    def test_has_permissive_sddl_via_default_access(self):
        srv = WinrtServer(
            name="Test", server_permissions="",
            default_access_permission="(A;;GA;;;WD)",
        )
        assert srv.has_permissive_sddl is True

    def test_deny_ace_not_permissive(self):
        srv = WinrtServer(name="Test", server_permissions="(D;;GA;;;WD)")
        assert srv.has_permissive_sddl is False

    def test_is_remote_activatable(self):
        srv = WinrtServer(name="Test", supports_remote_activation="True")
        assert srv.is_remote_activatable is True

    def test_is_base_trust(self):
        srv = WinrtServer(name="Test", trust_level="BaseTrust")
        assert srv.is_base_trust is True

    def test_not_base_trust(self):
        srv = WinrtServer(name="Test", trust_level="PartialTrust")
        assert srv.is_base_trust is False

    def test_interface_and_method_counts(self):
        m1 = WinrtMethod(access="DIRECT", type="VTABLE", name="A", file="")
        m2 = WinrtMethod(access="DIRECT", type="VTABLE", name="B", file="")
        srv = WinrtServer(
            name="Test",
            interfaces=[WinrtInterface(name="I1", methods=[m1, m2])],
            methods_flat=[m1, m2],
        )
        assert srv.interface_count == 1
        assert srv.method_count == 2

    def test_to_dict(self):
        srv = WinrtServer(
            name="Test.Class", activation_type="OutOfProcess",
            trust_level="BaseTrust", server_identity="nt authority\\system",
            access_contexts={WinrtAccessContext.MEDIUM_IL_PRIVILEGED},
        )
        d = srv.to_dict()
        assert d["name"] == "Test.Class"
        assert d["is_out_of_process"] is True
        assert d["runs_as_system"] is True


# ===================================================================
# Risk tier logic
# ===================================================================

class TestRiskTier:
    """Tests for the privilege-boundary risk model."""

    def test_critical_medium_il_system_oop(self):
        srv = WinrtServer(
            name="Test", activation_type="OutOfProcess",
            server_identity="nt authority\\system",
            access_contexts={WinrtAccessContext.MEDIUM_IL_PRIVILEGED},
        )
        assert srv.risk_tier(WinrtAccessContext.MEDIUM_IL_PRIVILEGED) == "critical"
        assert srv.best_risk_tier == "critical"

    def test_high_medium_il_permissive_sddl(self):
        srv = WinrtServer(
            name="Test", activation_type="OutOfProcess",
            server_permissions="O:PSG:BUD:(A;;CCDCLCSWRP;;;WD)",
            access_contexts={WinrtAccessContext.MEDIUM_IL_ALL},
        )
        assert srv.risk_tier(WinrtAccessContext.MEDIUM_IL_ALL) == "high"

    def test_medium_high_il_system_oop(self):
        srv = WinrtServer(
            name="Test", activation_type="OutOfProcess",
            server_identity="nt authority\\system",
            access_contexts={WinrtAccessContext.HIGH_IL_PRIVILEGED},
        )
        assert srv.risk_tier(WinrtAccessContext.HIGH_IL_PRIVILEGED) == "medium"

    def test_medium_in_process_base_trust(self):
        srv = WinrtServer(
            name="Test", activation_type="InProcess",
            trust_level="BaseTrust",
            access_contexts={WinrtAccessContext.HIGH_IL_ALL},
        )
        assert srv.risk_tier(WinrtAccessContext.HIGH_IL_ALL) == "medium"

    def test_low_default(self):
        srv = WinrtServer(
            name="Test", activation_type="InProcess",
            trust_level="PartialTrust",
            access_contexts={WinrtAccessContext.HIGH_IL_ALL},
        )
        assert srv.risk_tier(WinrtAccessContext.HIGH_IL_ALL) == "low"

    def test_empty_server_identity_not_system(self):
        srv = WinrtServer(
            name="Test", activation_type="OutOfProcess",
            server_identity="",
            access_contexts={WinrtAccessContext.MEDIUM_IL_PRIVILEGED},
        )
        tier = srv.risk_tier(WinrtAccessContext.MEDIUM_IL_PRIVILEGED)
        assert tier != "critical"

    def test_best_risk_tier_picks_highest(self):
        srv = WinrtServer(
            name="Test", activation_type="OutOfProcess",
            server_identity="nt authority\\system",
            access_contexts={
                WinrtAccessContext.HIGH_IL_ALL,
                WinrtAccessContext.MEDIUM_IL_PRIVILEGED,
            },
        )
        assert srv.best_risk_tier == "critical"

    def test_best_risk_tier_no_contexts(self):
        srv = WinrtServer(name="Test", activation_type="InProcess", trust_level="PartialTrust")
        assert srv.best_risk_tier == "low"


# ===================================================================
# Parsing helpers
# ===================================================================

class TestParsingHelpers:
    """Unit tests for WinRT data parsing utilities."""

    def test_parse_guid_from_pseudo_idl(self):
        lines = [
            '[Guid("58ec0eef-4ff0-48a5-9bfc-435df052c258")]',
            "interface ITest : IInspectable {",
            "}",
        ]
        assert _parse_guid_from_pseudo_idl(lines) == "58ec0eef-4ff0-48a5-9bfc-435df052c258"

    def test_parse_guid_missing(self):
        assert _parse_guid_from_pseudo_idl(["interface ITest : IInspectable {"]) == ""

    def test_parse_guid_empty(self):
        assert _parse_guid_from_pseudo_idl([]) == ""

    def test_module_name_from_path(self):
        assert module_name_from_path("C:\\Windows\\System32\\test.dll") == "test.dll"
        assert module_name_from_path("c:\\windows\\system32\\foo.exe") == "foo.exe"

    def test_is_permissive_sddl_wd(self):
        assert _is_permissive_sddl("O:PSG:BUD:(A;;CCDCLCSWRP;;;WD)") is True

    def test_is_permissive_sddl_ac(self):
        assert _is_permissive_sddl("O:PSG:BUD:(A;;CCDCLCSWRP;;;AC)") is True

    def test_is_permissive_sddl_au(self):
        assert _is_permissive_sddl("O:PSG:BUD:(A;;CCDCLCSWRP;;;AU)") is True

    def test_is_permissive_sddl_iu(self):
        assert _is_permissive_sddl("O:PSG:BUD:(A;;CCDCLCSWRP;;;IU)") is True

    def test_is_permissive_sddl_s_1_1_0(self):
        assert _is_permissive_sddl("(A;;GA;;;S-1-1-0)") is True

    def test_is_permissive_sddl_deny_not_permissive(self):
        assert _is_permissive_sddl("(D;;GA;;;WD)") is False

    def test_is_permissive_sddl_restrictive(self):
        assert _is_permissive_sddl("O:SYG:SYD:") is False

    def test_is_permissive_sddl_empty(self):
        assert _is_permissive_sddl("") is False


# ===================================================================
# WinrtIndex building and querying (fixtures)
# ===================================================================

def _make_winrt_server_entry(class_name, activation_type="InProcess", **overrides):
    """Helper to build a binary-keyed WinRT server entry with defaults."""
    base = {
        "class_name": class_name,
        "hosting_server": "",
        "default_hosting_server": "",
        "has_hosting_server": "False",
        "activation_type": activation_type,
        "trust_level": "PartialTrust",
        "server_launch_permission_sddl": "",
        "server_run_as_identity": "",
        "server_display_name": "",
        "server_exe_path": "",
        "server_exe_name": "",
        "server_registration_type": "",
        "service_name": "",
        "default_access_permission_sddl": "O:SYG:SYD:",
        "default_launch_permission_sddl": "O:SYG:SYD:",
        "supports_remote_activation": "False",
        "registration_source": "LocalMachine",
        "activate_in_shared_broker": "False",
        "class_identity": "",
        "class_identity_type": "",
        "instancing_type": "",
        "class_permission_sddl": "",
        "package_id": "",
        "runtime_server": "",
        "interfaces": [],
    }
    base.update(overrides)
    return base


@pytest.fixture
def sample_winrt_data():
    """Minimal WinRT binary-keyed JSON structure."""
    return {
        "c:\\windows\\system32\\test.dll": {
            "binary_path": "C:\\Windows\\System32\\test.dll",
            "servers": [
                _make_winrt_server_entry(
                    "Test.Namespace.ClassA",
                    interfaces=[{
                        "iface_name": "Test::Namespace::IClassAStatics",
                        "methods": [
                            {"access_type": "DIRECT", "dispatch_type": "VTABLE", "method_name": "Test::Namespace::ClassA::MethodOne", "binary_path": "C:\\Windows\\System32\\test.dll"},
                            {"access_type": "DIRECT", "dispatch_type": "VTABLE", "method_name": "Test::Namespace::ClassA::MethodTwo", "binary_path": "C:\\Windows\\System32\\test.dll"},
                        ],
                        "pseudo_idl": [
                            '[Guid("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")]',
                            "interface Test::Namespace::IClassAStatics : IInspectable {",
                            "    HRESULT Proc6();",
                            "    HRESULT Proc7();",
                            "}",
                        ],
                    }],
                ),
            ],
            "procedures": ["Test::Namespace::ClassA::MethodOne", "Test::Namespace::ClassA::MethodTwo"],
        },
        "c:\\windows\\system32\\other.dll": {
            "binary_path": "C:\\Windows\\System32\\other.dll",
            "servers": [
                _make_winrt_server_entry(
                    "Test.Namespace.ClassB", "OutOfProcess",
                    hosting_server="TestServer", default_hosting_server="TestServer",
                    has_hosting_server="True", trust_level="BaseTrust",
                    server_launch_permission_sddl="O:PSG:BUD:(A;;CCDCLCSWRP;;;WD)",
                    server_run_as_identity="nt authority\\system",
                    server_display_name="TestServer",
                    service_name="TestSvc",
                    interfaces=[{
                        "iface_name": "Test::Namespace::IClassBStatics",
                        "methods": [
                            {"access_type": "DIRECT", "dispatch_type": "VTABLE", "method_name": "Test::Namespace::ClassB::LaunchProcess", "binary_path": "C:\\Windows\\System32\\other.dll"},
                            {"access_type": "DIRECT", "dispatch_type": "VTABLE", "method_name": "Test::Namespace::ClassB::GetConfig", "binary_path": "C:\\Windows\\System32\\other.dll"},
                            {"access_type": "DIRECT", "dispatch_type": "VTABLE", "method_name": "Test::Namespace::ClassB::SetPolicy", "binary_path": "C:\\Windows\\System32\\other.dll"},
                        ],
                        "pseudo_idl": [
                            '[Guid("11111111-2222-3333-4444-555555555555")]',
                            "interface Test::Namespace::IClassBStatics : IInspectable {",
                            "}",
                        ],
                    }],
                ),
            ],
            "procedures": [
                "Test::Namespace::ClassB::LaunchProcess",
                "Test::Namespace::ClassB::GetConfig",
                "Test::Namespace::ClassB::SetPolicy",
            ],
        },
    }


@pytest.fixture
def loaded_index(sample_winrt_data, tmp_path):
    """Build and return a loaded WinrtIndex from sample data."""
    ctx_dir = tmp_path / "extracted_high_il" / "all_servers"
    ctx_dir.mkdir(parents=True)

    with open(ctx_dir / "winrt_servers.json", "w") as f:
        json.dump(sample_winrt_data, f)

    med_dir = tmp_path / "extracted_medium_il" / "medium_il" / "privileged_servers"
    med_dir.mkdir(parents=True)
    med_data = {
        "c:\\windows\\system32\\other.dll": sample_winrt_data["c:\\windows\\system32\\other.dll"],
    }
    with open(med_dir / "winrt_servers.json", "w") as f:
        json.dump(med_data, f)

    idx = WinrtIndex()
    idx.load(data_root=tmp_path)
    return idx


class TestWinrtIndex:
    """Tests for WinrtIndex query methods."""

    def test_loaded_flag(self, loaded_index):
        assert loaded_index.loaded is True

    def test_server_count(self, loaded_index):
        assert loaded_index.server_count == 2

    def test_module_count(self, loaded_index):
        assert loaded_index.module_count == 2

    def test_total_methods(self, loaded_index):
        assert loaded_index.total_methods == 5

    def test_get_servers_for_module(self, loaded_index):
        servers = loaded_index.get_servers_for_module("test.dll")
        assert len(servers) == 1
        assert servers[0].name == "Test.Namespace.ClassA"

    def test_get_servers_case_insensitive(self, loaded_index):
        servers = loaded_index.get_servers_for_module("TEST.DLL")
        assert len(servers) == 1

    def test_get_servers_nonexistent(self, loaded_index):
        assert loaded_index.get_servers_for_module("nosuch.dll") == []

    def test_get_servers_by_class(self, loaded_index):
        srv = loaded_index.get_servers_by_class("Test.Namespace.ClassA")
        assert srv is not None
        assert srv.name == "Test.Namespace.ClassA"

    def test_get_servers_by_class_not_found(self, loaded_index):
        assert loaded_index.get_servers_by_class("NoSuch.Class") is None

    def test_get_procedures_for_module(self, loaded_index):
        procs = loaded_index.get_procedures_for_module("test.dll")
        assert "Test::Namespace::ClassA::MethodOne" in procs
        assert len(procs) == 2

    def test_is_winrt_procedure_true(self, loaded_index):
        assert loaded_index.is_winrt_procedure(
            "test.dll", "Test::Namespace::ClassA::MethodOne"
        ) is True

    def test_is_winrt_procedure_false(self, loaded_index):
        assert loaded_index.is_winrt_procedure("test.dll", "NoSuchFunc") is False

    def test_is_winrt_procedure_wrong_module(self, loaded_index):
        assert loaded_index.is_winrt_procedure(
            "other.dll", "Test::Namespace::ClassA::MethodOne"
        ) is False

    def test_get_interfaces_for_module(self, loaded_index):
        ifaces = loaded_index.get_interfaces_for_module("test.dll")
        assert len(ifaces) == 1
        assert ifaces[0].name == "Test::Namespace::IClassAStatics"
        assert ifaces[0].guid == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    def test_get_methods_for_class(self, loaded_index):
        methods = loaded_index.get_methods_for_class("Test.Namespace.ClassB")
        assert len(methods) == 3
        names = {m.short_name for m in methods}
        assert "LaunchProcess" in names
        assert "GetConfig" in names

    def test_search_methods(self, loaded_index):
        results = loaded_index.search_methods("Launch")
        assert len(results) == 1
        assert results[0].short_name == "LaunchProcess"

    def test_search_methods_regex(self, loaded_index):
        results = loaded_index.search_methods(r"Method(One|Two)")
        assert len(results) == 2

    def test_search_methods_invalid_regex(self, loaded_index):
        assert loaded_index.search_methods("[invalid") == []

    def test_get_nonexistent_module(self, loaded_index):
        assert loaded_index.get_servers_for_module("nope.dll") == []

    def test_get_nonexistent_class(self, loaded_index):
        assert loaded_index.get_servers_by_class("No.Such.Class") is None

    def test_get_all_classes(self, loaded_index):
        classes = loaded_index.get_all_classes()
        assert "Test.Namespace.ClassA" in classes
        assert "Test.Namespace.ClassB" in classes

    def test_get_all_modules(self, loaded_index):
        modules = loaded_index.get_all_modules()
        assert "test.dll" in modules
        assert "other.dll" in modules

    def test_summary(self, loaded_index):
        s = loaded_index.summary()
        assert s["total_servers"] == 2
        assert s["total_modules"] == 2
        assert s["total_methods"] == 5


# ===================================================================
# Multi-context loading
# ===================================================================

class TestMultiContextLoading:
    """Tests for loading across multiple access contexts."""

    def test_class_in_multiple_contexts(self, loaded_index):
        srv = loaded_index.get_servers_by_class("Test.Namespace.ClassB")
        assert srv is not None
        contexts = srv.access_contexts
        assert WinrtAccessContext.HIGH_IL_ALL in contexts
        assert WinrtAccessContext.MEDIUM_IL_PRIVILEGED in contexts

    def test_get_access_contexts_for_class(self, loaded_index):
        contexts = loaded_index.get_access_contexts_for_class("Test.Namespace.ClassB")
        assert len(contexts) >= 2

    def test_privileged_surface(self, loaded_index):
        priv = loaded_index.get_privileged_surface("medium")
        names = {s.name for s in priv}
        assert "Test.Namespace.ClassB" in names

    def test_get_access_contexts_nonexistent(self, loaded_index):
        assert loaded_index.get_access_contexts_for_class("No.Class") == set()


# ===================================================================
# Nostaterepo filtering
# ===================================================================

class TestNostaterepoFiltering:
    """Tests for exclude_staterepo config flag."""

    def test_exclude_staterepo(self, tmp_path):
        data = {
            "c:\\windows\\system32\\windows.staterepository.dll": {
                "binary_path": "c:\\windows\\system32\\windows.staterepository.dll",
                "servers": [],
                "procedures": ["StateFunc1"],
            },
            "c:\\windows\\system32\\other.dll": {
                "binary_path": "C:\\Windows\\System32\\other.dll",
                "servers": [],
                "procedures": ["OtherFunc1"],
            },
        }
        ctx_dir = tmp_path / "extracted_high_il" / "all_servers"
        ctx_dir.mkdir(parents=True)
        with open(ctx_dir / "winrt_servers.json", "w") as f:
            json.dump(data, f)

        idx = WinrtIndex()
        with patch("helpers.winrt_index.get_config_value") as mock_cfg:
            mock_cfg.side_effect = lambda k, d=None: {
                "winrt.data_root": str(tmp_path),
                "winrt.exclude_staterepo": True,
                "winrt.enabled": True,
            }.get(k, d)
            idx.load(data_root=tmp_path)

        assert idx.is_winrt_procedure("other.dll", "OtherFunc1") is True
        assert idx.is_winrt_procedure("windows.staterepository.dll", "StateFunc1") is False

    def test_include_staterepo(self, tmp_path):
        data = {
            "c:\\windows\\system32\\windows.staterepository.dll": {
                "binary_path": "c:\\windows\\system32\\windows.staterepository.dll",
                "servers": [],
                "procedures": ["StateFunc1"],
            },
            "c:\\windows\\system32\\other.dll": {
                "binary_path": "C:\\Windows\\System32\\other.dll",
                "servers": [],
                "procedures": ["OtherFunc1"],
            },
        }
        ctx_dir = tmp_path / "extracted_high_il" / "all_servers"
        ctx_dir.mkdir(parents=True)
        with open(ctx_dir / "winrt_servers.json", "w") as f:
            json.dump(data, f)

        idx = WinrtIndex()
        with patch("helpers.winrt_index.get_config_value") as mock_cfg:
            mock_cfg.side_effect = lambda k, d=None: {
                "winrt.data_root": str(tmp_path),
                "winrt.exclude_staterepo": False,
                "winrt.enabled": True,
            }.get(k, d)
            idx.load(data_root=tmp_path)

        assert idx.is_winrt_procedure("windows.staterepository.dll", "StateFunc1") is True


# ===================================================================
# Singleton access
# ===================================================================

class TestSingleton:
    """Tests for get_winrt_index / invalidate_winrt_index."""

    def test_get_winrt_index_returns_same_instance(self):
        invalidate_winrt_index()
        idx1 = get_winrt_index()
        idx2 = get_winrt_index()
        assert idx1 is idx2

    def test_invalidate_forces_reload(self):
        idx1 = get_winrt_index()
        invalidate_winrt_index()
        idx2 = get_winrt_index()
        assert idx1 is not idx2

    def test_disabled_returns_empty_index(self):
        invalidate_winrt_index()
        with patch("helpers.winrt_index.get_config_value") as mock_cfg:
            mock_cfg.return_value = False
            idx = get_winrt_index(force_reload=True)
            assert idx.loaded is False
            assert idx.server_count == 0
        invalidate_winrt_index()


# ===================================================================
# Live index tests (against actual data)
# ===================================================================

class TestLiveIndex:
    """Tests against the actual WinRT data files in work2/extraction_data/."""

    @pytest.fixture(autouse=True)
    def _reset(self):
        invalidate_winrt_index()
        yield
        invalidate_winrt_index()

    def test_loads_from_data_root(self):
        idx = get_winrt_index()
        if not idx.loaded or idx.server_count == 0:
            pytest.skip("WinRT data not available or empty")
        assert idx.server_count > 50
        assert idx.module_count > 20

    def test_known_module_has_procedures(self):
        idx = get_winrt_index()
        if not idx.loaded:
            pytest.skip("WinRT data not available")
        procs = idx.get_procedures_for_module("Windows.System.SystemManagement.dll")
        if not procs:
            pytest.skip("Known module not in WinRT data")
        assert any("ShutdownManager" in p or "BeginShutdown" in p for p in procs)

    def test_known_class_resolves(self):
        idx = get_winrt_index()
        if not idx.loaded:
            pytest.skip("WinRT data not available")
        srv = idx.get_servers_by_class("Windows.Internal.Data.Activities.ActivityImageManager")
        if srv is None:
            pytest.skip("Known class not in WinRT data")
        assert srv.method_count > 0

    def test_privileged_surface_nonempty(self):
        idx = get_winrt_index()
        if not idx.loaded or idx.server_count == 0:
            pytest.skip("WinRT data not available or empty")
        priv = idx.get_privileged_surface("medium")
        assert len(priv) > 0

    def test_summary_fields(self):
        idx = get_winrt_index()
        if not idx.loaded or idx.server_count == 0:
            pytest.skip("WinRT data not available or empty")
        s = idx.summary()
        assert s["total_servers"] > 0
        assert s["total_modules"] > 0
        assert s["total_methods"] > 0


# ===================================================================
# Config integration
# ===================================================================

class TestWinrtConfig:
    """Tests for the winrt config section in defaults.json."""

    def test_winrt_section_exists(self):
        from helpers.config import get_config_value
        assert get_config_value("winrt.enabled") is True

    def test_winrt_data_root_configured(self):
        from helpers.config import get_config_value
        data_root = get_config_value("winrt.data_root")
        assert data_root is not None
        assert "winrt_data" in data_root

    def test_winrt_config_keys(self):
        root = Path(__file__).resolve().parent.parent
        with open(root / "config" / "defaults.json", "r") as f:
            config = json.load(f)
        assert "winrt" in config
        assert "enabled" in config["winrt"]
        assert "data_root" in config["winrt"]
        assert "cache_loaded_index" in config["winrt"]
        assert "exclude_staterepo" in config["winrt"]


# ===================================================================
# Registry entries
# ===================================================================

class TestRegistryEntries:
    """Tests that skill and command are properly registered."""

    def test_skill_registry_has_winrt_interface_analysis(self):
        root = Path(__file__).resolve().parent.parent
        with open(root / "skills" / "registry.json", "r") as f:
            reg = json.load(f)
        skills = reg.get("skills", {})
        assert "winrt-interface-analysis" in skills
        entry = skills["winrt-interface-analysis"]
        assert entry["type"] == "security"
        assert len(entry["entry_scripts"]) == 6

    def test_command_registry_has_winrt(self):
        root = Path(__file__).resolve().parent.parent
        with open(root / "commands" / "registry.json", "r") as f:
            reg = json.load(f)
        commands = reg.get("commands", {})
        assert "winrt" in commands
        entry = commands["winrt"]
        assert "winrt-interface-analysis" in entry["skills_used"]
        assert entry["file"] == "winrt.md"

    def test_command_md_file_exists(self):
        root = Path(__file__).resolve().parent.parent
        assert (root / "commands" / "winrt.md").exists()

    def test_skill_md_file_exists(self):
        root = Path(__file__).resolve().parent.parent
        assert (root / "skills" / "winrt-interface-analysis" / "SKILL.md").exists()

    def test_all_skill_scripts_exist(self):
        root = Path(__file__).resolve().parent.parent
        scripts_dir = root / "skills" / "winrt-interface-analysis" / "scripts"
        expected = [
            "_common.py",
            "resolve_winrt_server.py",
            "map_winrt_surface.py",
            "enumerate_winrt_methods.py",
            "classify_winrt_entrypoints.py",
            "audit_winrt_security.py",
            "find_winrt_privesc.py",
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
        with open(ctx_dir / "winrt_servers.json", "w") as f:
            json.dump({}, f)

        idx = WinrtIndex()
        idx.load(data_root=tmp_path)
        assert idx.loaded is False, "Empty server details should not set loaded=True"
        assert idx.server_count == 0
        assert idx.get_servers_for_module("any.dll") == []

    def test_class_with_empty_methods(self):
        raw = _make_winrt_server_entry("Empty.Class")
        srv = _parse_server_detail(raw)
        assert srv.method_count == 0
        assert srv.interface_count == 0

    def test_class_with_empty_pseudo_interfaces(self):
        raw = _make_winrt_server_entry(
            "NoPseudo.Class",
            interfaces=[{
                "iface_name": "INoPseudo",
                "methods": [
                    {"access_type": "DIRECT", "dispatch_type": "VTABLE", "method_name": "Cls::Method", "binary_path": "a.dll"},
                ],
                "pseudo_idl": [],
            }],
        )
        srv = _parse_server_detail(raw)
        assert srv.method_count == 1
        assert srv.interfaces[0].guid == ""
        assert srv.interfaces[0].pseudo_idl == []

    def test_offset_style_method_name(self):
        m = WinrtMethod(
            access="DIRECT", type="VTABLE",
            name="DllCanUnloadNow+0x7F60",
            file="C:\\Windows\\System32\\test.dll",
        )
        assert m.short_name == "DllCanUnloadNow+0x7F60"
        assert m.class_name == ""
        d = m.to_dict()
        assert d["short_name"] == "DllCanUnloadNow+0x7F60"

    def test_missing_data_dir(self, tmp_path):
        idx = WinrtIndex()
        idx.load(data_root=tmp_path / "nonexistent")
        assert idx.loaded is False
        assert idx.server_count == 0

    def test_all_contexts_missing(self, tmp_path):
        empty_root = tmp_path / "empty_root"
        empty_root.mkdir()
        idx = WinrtIndex()
        idx.load(data_root=empty_root)
        assert idx.loaded is False, "No context dirs means no data loaded"
        assert idx.server_count == 0
        assert idx.summary()["total_servers"] == 0

    def test_get_servers_by_risk_empty(self):
        idx = WinrtIndex()
        assert idx.get_servers_by_risk("critical") == []


# ===================================================================
# Additional coverage: gaps identified in audit
# ===================================================================

class TestGetServersByRiskWithData:
    """Test get_servers_by_risk with actual loaded data."""

    def test_servers_by_risk_low(self, loaded_index):
        low = loaded_index.get_servers_by_risk("low")
        names = {s.name for s in low}
        assert "Test.Namespace.ClassA" in names

    def test_servers_by_risk_nonexistent_tier(self, loaded_index):
        assert loaded_index.get_servers_by_risk("nonexistent") == []


class TestProceduresFallback:
    """Test get_procedures_for_module fallback from server methods."""

    def test_fallback_when_no_procedures_file(self, sample_winrt_data, tmp_path):
        no_procs_data = {}
        for k, v in sample_winrt_data.items():
            no_procs_data[k] = {**v, "procedures": []}
        ctx_dir = tmp_path / "extracted_high_il" / "all_servers"
        ctx_dir.mkdir(parents=True)
        with open(ctx_dir / "winrt_servers.json", "w") as f:
            json.dump(no_procs_data, f)

        idx = WinrtIndex()
        idx.load(data_root=tmp_path)
        procs = idx.get_procedures_for_module("test.dll")
        assert len(procs) > 0
        assert any("MethodOne" in p for p in procs)


class TestShortNameFallback:
    """Test is_winrt_procedure matching via short_name."""

    def test_short_name_match_via_server_methods(self, sample_winrt_data, tmp_path):
        no_procs_data = {}
        for k, v in sample_winrt_data.items():
            no_procs_data[k] = {**v, "procedures": []}
        ctx_dir = tmp_path / "extracted_high_il" / "all_servers"
        ctx_dir.mkdir(parents=True)
        with open(ctx_dir / "winrt_servers.json", "w") as f:
            json.dump(no_procs_data, f)

        idx = WinrtIndex()
        idx.load(data_root=tmp_path)
        assert idx.is_winrt_procedure("test.dll", "MethodOne") is True
        assert idx.is_winrt_procedure("test.dll", "NoSuchMethod") is False


class TestSummarySubfields:
    """Test summary() sub-fields."""

    def test_summary_by_tier(self, loaded_index):
        s = loaded_index.summary()
        assert "by_tier" in s
        assert isinstance(s["by_tier"], dict)

    def test_summary_by_activation(self, loaded_index):
        s = loaded_index.summary()
        assert "by_activation" in s
        assert s["by_activation"]["in_process"] >= 0
        assert s["by_activation"]["out_of_process"] >= 0
        assert s["by_activation"]["in_process"] + s["by_activation"]["out_of_process"] == loaded_index.server_count

    def test_summary_system_counts(self, loaded_index):
        s = loaded_index.summary()
        assert "runs_as_system" in s
        assert "with_permissive_sddl" in s


class TestTemplatedProcedureNames:
    """Test handling of winrt::impl::produce<...> style names."""

    def test_templated_name_in_procedures(self, tmp_path):
        data = {
            "c:\\windows\\system32\\test.dll": {
                "binary_path": "C:\\Windows\\System32\\test.dll",
                "servers": [],
                "procedures": [
                    "winrt::impl::produce<winrt::Windows::System::Update::factory_implementation::SystemUpdateManager,winrt::Windows::System::Update::ISystemUpdateManagerStatics>::IsSupported",
                ],
            },
        }
        ctx_dir = tmp_path / "extracted_high_il" / "all_servers"
        ctx_dir.mkdir(parents=True)
        with open(ctx_dir / "winrt_servers.json", "w") as f:
            json.dump(data, f)

        idx = WinrtIndex()
        idx.load(data_root=tmp_path)

        all_procs = idx.get_procedures_for_module("test.dll")
        assert len(all_procs) == 1
        assert "IsSupported" in all_procs[0]

    def test_templated_short_name(self):
        m = WinrtMethod(
            access="DIRECT", type="VTABLE",
            name="winrt::impl::produce<winrt::Cls,winrt::ICls>::GetValue",
            file="test.dll",
        )
        assert m.short_name == "GetValue"


class TestNostaterepoServerDetails:
    """Test that exclude_staterepo filters servers_details too."""

    def test_staterepo_servers_excluded(self, tmp_path):
        data = {
            "c:\\windows\\system32\\windows.staterepository.dll": {
                "binary_path": "c:\\windows\\system32\\windows.staterepository.dll",
                "servers": [
                    _make_winrt_server_entry(
                        "Windows.Internal.StateRepository.TestClass", "OutOfProcess",
                        hosting_server="StateRepository", has_hosting_server="True",
                        trust_level="BaseTrust",
                        server_run_as_identity="nt authority\\system",
                        server_display_name="StateRepository",
                        interfaces=[{
                            "iface_name": "ITestStatics",
                            "methods": [
                                {"access_type": "DIRECT", "dispatch_type": "VTABLE",
                                 "method_name": "StateRepo::Func",
                                 "binary_path": "c:\\windows\\system32\\windows.staterepository.dll"},
                            ],
                            "pseudo_idl": [],
                        }],
                    ),
                ],
                "procedures": [],
            },
        }
        ctx_dir = tmp_path / "extracted_high_il" / "all_servers"
        ctx_dir.mkdir(parents=True)
        with open(ctx_dir / "winrt_servers.json", "w") as f:
            json.dump(data, f)

        idx = WinrtIndex()
        with patch("helpers.winrt_index.get_config_value") as mock_cfg:
            mock_cfg.side_effect = lambda k, d=None: {
                "winrt.exclude_staterepo": True,
            }.get(k, d)
            idx.load(data_root=tmp_path)

        assert idx.get_servers_by_class("Windows.Internal.StateRepository.TestClass") is None
        assert idx.get_servers_for_module("windows.staterepository.dll") == []
