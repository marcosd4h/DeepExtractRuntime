"""Tests for the RPC index helper and RPC integration across the runtime.

Covers:
  - helpers/rpc_index.py  (RpcInterface, RpcIndex, parsing, querying)
  - map-attack-surface RPC enrichment  (discover_from_rpc_index, protocol scoring)
  - taint-analysis trust levels  (refined rpc_server_* tiers)
  - classify-functions RPC boost  (rpc_index confirmed handler signal)
  - triage-coordinator RPC characteristics  (ModuleCharacteristics fields)
  - config rpc section  (defaults.json rpc keys)
  - hooks/_context_builder.py  (RPC section injection)
  - config/assets/misc_data/vulnerability_patterns.json  (rpc_security patterns)
  - helpers/cross_module_graph.py  (inject_rpc_edges)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

_AGENT_DIR = Path(__file__).resolve().parent.parent
if str(_AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENT_DIR))


# ===================================================================
# RpcInterface dataclass
# ===================================================================

from helpers.db_paths import module_name_from_path
from helpers.rpc_index import (
    RpcIndex,
    RpcInterface,
    _distribute_procedures,
    _parse_complex_types,
    _parse_endpoints,
    _parse_version,
    get_rpc_index,
    invalidate_rpc_index,
)


class TestRpcInterface:
    """Unit tests for the RpcInterface dataclass properties."""

    def test_remote_reachable_tcp(self):
        iface = RpcInterface(
            interface_id="test-uuid", interface_version="1.0",
            binary_path="C:\\test.dll", binary_name="test.dll",
            procedure_count=3, protocols={"ncacn_ip_tcp", "ncalrpc"},
        )
        assert iface.is_remote_reachable is True
        assert iface.is_named_pipe is False
        assert iface.is_local_only is False
        assert iface.risk_tier == "critical"

    def test_remote_reachable_http(self):
        iface = RpcInterface(
            interface_id="test-uuid", interface_version="1.0",
            binary_path="C:\\test.dll", binary_name="test.dll",
            procedure_count=1, protocols={"ncacn_http"},
        )
        assert iface.is_remote_reachable is True
        assert iface.risk_tier == "critical"

    def test_named_pipe(self):
        iface = RpcInterface(
            interface_id="test-uuid", interface_version="1.0",
            binary_path="C:\\test.dll", binary_name="test.dll",
            procedure_count=2, protocols={"ncacn_np"},
        )
        assert iface.is_remote_reachable is False
        assert iface.is_named_pipe is True
        assert iface.risk_tier == "high"

    def test_local_only_with_service(self):
        iface = RpcInterface(
            interface_id="test-uuid", interface_version="1.0",
            binary_path="C:\\test.dll", binary_name="test.dll",
            procedure_count=5, protocols={"ncalrpc"},
            service_name="TestService", is_service_running=True,
        )
        assert iface.is_local_only is True
        assert iface.risk_tier == "medium"

    def test_local_only_no_service(self):
        iface = RpcInterface(
            interface_id="test-uuid", interface_version="1.0",
            binary_path="C:\\test.dll", binary_name="test.dll",
            procedure_count=1, protocols={"ncalrpc"},
        )
        assert iface.risk_tier == "low"

    def test_empty_protocols_is_local(self):
        iface = RpcInterface(
            interface_id="test-uuid", interface_version="1.0",
            binary_path="C:\\test.dll", binary_name="test.dll",
            procedure_count=1,
        )
        assert iface.is_local_only is True
        assert iface.risk_tier == "low"

    def test_has_complex_types(self):
        iface = RpcInterface(
            interface_id="test-uuid", interface_version="1.0",
            binary_path="C:\\test.dll", binary_name="test.dll",
            procedure_count=1,
            complex_types=["FC_BOGUS_STRUCT - NdrBogusStructureTypeReference"],
        )
        assert iface.has_complex_types is True

    def test_no_complex_types(self):
        iface = RpcInterface(
            interface_id="test-uuid", interface_version="1.0",
            binary_path="C:\\test.dll", binary_name="test.dll",
            procedure_count=1,
        )
        assert iface.has_complex_types is False

    def test_to_dict_roundtrip(self):
        iface = RpcInterface(
            interface_id="abc-uuid", interface_version="2.0",
            binary_path="C:\\sys\\svc.dll", binary_name="svc.dll",
            procedure_count=3, procedure_names=["FuncA", "FuncB", "FuncC"],
            protocols={"ncalrpc", "ncacn_np"}, endpoints=["ncalrpc:[LRPC-test]"],
            service_name="MySvc", service_display_name="My Service",
            is_service_running=True, is_client=False,
            complex_types=["FC_STRUCT"], transfer_syntax_id="8a885d04",
        )
        d = iface.to_dict()
        assert d["interface_id"] == "abc-uuid"
        assert d["binary_name"] == "svc.dll"
        assert d["procedure_count"] == 3
        assert "ncacn_np" in d["protocols"]
        assert d["risk_tier"] == "high"
        assert d["service_name"] == "MySvc"
        assert d["has_complex_types"] is True


# ===================================================================
# Parsing helpers
# ===================================================================

class TestParsingHelpers:
    """Unit tests for RPC data parsing utilities."""

    def test_parse_version_string(self):
        assert _parse_version("1.0") == "1.0"

    def test_parse_version_object(self):
        assert _parse_version({"Major": 3, "Minor": 2}) == "3.2"

    def test_parse_version_none(self):
        assert _parse_version(None) == "0.0"

    def test_parse_endpoints_string(self):
        endpoints, protocols, pipe_names, alpc_endpoints, tcp_ports = _parse_endpoints(
            "[uuid, 1.0] ncalrpc:[LRPC-test123]"
        )
        assert len(endpoints) == 1
        assert "ncalrpc" in protocols

    def test_parse_endpoints_list(self):
        endpoints, protocols, pipe_names, alpc_endpoints, tcp_ports = _parse_endpoints([
            "[uuid, 1.0] ncalrpc:[LRPC-a]",
            "[uuid, 1.0] ncacn_np:[\\\\pipe\\\\test]",
        ])
        assert len(endpoints) == 2
        assert protocols == {"ncalrpc", "ncacn_np"}

    def test_parse_endpoints_empty_string(self):
        endpoints, protocols, pipe_names, alpc_endpoints, tcp_ports = _parse_endpoints("")
        assert endpoints == []
        assert protocols == set()

    def test_parse_endpoints_empty_list(self):
        endpoints, protocols, pipe_names, alpc_endpoints, tcp_ports = _parse_endpoints([])
        assert endpoints == []
        assert protocols == set()

    def test_parse_complex_types_string(self):
        result = _parse_complex_types(
            "FC_BOGUS_STRUCT - NdrBogusStructureTypeReference"
        )
        assert len(result) > 0
        assert any("FC_BOGUS_STRUCT" in t for t in result)

    def test_parse_complex_types_list(self):
        result = _parse_complex_types([
            "FC_BOGUS_STRUCT - NdrBogusStructureTypeReference",
            "FC_STRUCT - NdrSimpleStructureTypeReference",
        ])
        assert len(result) == 2

    def test_parse_complex_types_empty(self):
        assert _parse_complex_types("") == []
        assert _parse_complex_types(None) == []

    def test_module_name_from_path(self):
        assert module_name_from_path("C:\\windows\\system32\\appinfo.dll") == "appinfo.dll"
        assert module_name_from_path("C:\\windows\\system32\\IME\\IMEJP\\IMJPDCT.EXE") == "IMJPDCT.EXE"


# ===================================================================
# RpcIndex building and querying
# ===================================================================

@pytest.fixture
def sample_rpc_data():
    """Minimal RPC binary-keyed JSON structure."""
    return {
        "c:\\windows\\system32\\svc.dll": {
            "binary_path": "C:\\windows\\system32\\svc.dll",
            "file_info": {
                "file_description": "",
                "file_version": "",
                "company_name": "",
                "product_version": "",
            },
            "interfaces": [
                {
                    "interface_id": "aaaa-bbbb-cccc",
                    "interface_version": "1.0",
                    "transfer_syntax_id": "8a885d04",
                    "procedure_count": 3,
                    "offset": 1000,
                    "is_client": False,
                    "service_name": "MySvc",
                    "service_display_name": "My Service",
                    "is_service_running": True,
                    "endpoints": ["[aaaa-bbbb-cccc, 1.0] ncalrpc:[LRPC-test]"],
                    "endpoint_count": 1,
                    "complex_types": ["FC_BOGUS_STRUCT", "NdrBogusStructureTypeReference"],
                },
                {
                    "interface_id": "dddd-eeee-ffff",
                    "interface_version": "2.0",
                    "transfer_syntax_id": "8a885d04",
                    "procedure_count": 2,
                    "offset": 2000,
                    "is_client": False,
                    "service_name": "MySvc",
                    "service_display_name": "My Service",
                    "is_service_running": True,
                    "endpoints": ["[dddd-eeee-ffff, 2.0] ncacn_ip_tcp:[1234]"],
                    "endpoint_count": 1,
                    "complex_types": [],
                },
            ],
            "procedures": ["FuncA", "FuncB", "FuncC", "FuncD", "FuncE"],
        },
        "c:\\windows\\system32\\other.exe": {
            "binary_path": "C:\\windows\\system32\\other.exe",
            "file_info": {
                "file_description": "",
                "file_version": "",
                "company_name": "",
                "product_version": "",
            },
            "interfaces": [
                {
                    "interface_id": "1111-2222-3333",
                    "interface_version": "0.0",
                    "transfer_syntax_id": "8a885d04",
                    "procedure_count": 1,
                    "offset": 500,
                    "is_client": False,
                    "service_name": None,
                    "service_display_name": None,
                    "is_service_running": False,
                    "endpoints": [],
                    "endpoint_count": 0,
                    "complex_types": [],
                },
            ],
            "procedures": ["OtherFunc"],
        },
    }


@pytest.fixture
def loaded_index(sample_rpc_data):
    """Build and return a loaded RpcIndex from sample data."""
    idx = RpcIndex()
    idx._build_index(sample_rpc_data)
    idx._loaded = True
    return idx


class TestRpcIndex:
    """Tests for RpcIndex query methods."""

    def test_loaded_flag(self, loaded_index):
        assert loaded_index.loaded is True

    def test_interface_count(self, loaded_index):
        assert loaded_index.interface_count == 3

    def test_module_count(self, loaded_index):
        assert loaded_index.module_count == 2

    def test_get_interfaces_for_module(self, loaded_index):
        ifaces = loaded_index.get_interfaces_for_module("svc.dll")
        assert len(ifaces) == 2
        uuids = {i.interface_id for i in ifaces}
        assert "aaaa-bbbb-cccc" in uuids
        assert "dddd-eeee-ffff" in uuids

    def test_get_interfaces_case_insensitive(self, loaded_index):
        ifaces = loaded_index.get_interfaces_for_module("SVC.DLL")
        assert len(ifaces) == 2

    def test_get_interfaces_nonexistent(self, loaded_index):
        assert loaded_index.get_interfaces_for_module("nosuch.dll") == []

    def test_get_procedures_for_module(self, loaded_index):
        procs = loaded_index.get_procedures_for_module("svc.dll")
        assert "FuncA" in procs
        assert "FuncE" in procs
        assert len(procs) == 5

    def test_get_procedures_other(self, loaded_index):
        procs = loaded_index.get_procedures_for_module("other.exe")
        assert procs == ["OtherFunc"]

    def test_is_rpc_procedure_true(self, loaded_index):
        assert loaded_index.is_rpc_procedure("svc.dll", "FuncA") is True

    def test_is_rpc_procedure_false(self, loaded_index):
        assert loaded_index.is_rpc_procedure("svc.dll", "NotAnRpcFunc") is False

    def test_is_rpc_procedure_wrong_module(self, loaded_index):
        assert loaded_index.is_rpc_procedure("other.exe", "FuncA") is False

    def test_get_interface_for_procedure(self, loaded_index):
        iface = loaded_index.get_interface_for_procedure("svc.dll", "FuncA")
        assert iface is not None
        assert iface.interface_id == "aaaa-bbbb-cccc"

    def test_get_interface_for_procedure_not_found(self, loaded_index):
        assert loaded_index.get_interface_for_procedure("svc.dll", "Unknown") is None

    def test_procedure_to_opnum(self, loaded_index):
        opnum = loaded_index.procedure_to_opnum("svc.dll", "FuncA")
        assert opnum == 0
        opnum2 = loaded_index.procedure_to_opnum("svc.dll", "FuncC")
        assert opnum2 == 2

    def test_procedure_to_opnum_not_found(self, loaded_index):
        assert loaded_index.procedure_to_opnum("svc.dll", "Unknown") is None

    def test_find_modules_for_interface(self, loaded_index):
        modules = loaded_index.find_modules_for_interface("aaaa-bbbb-cccc")
        assert "svc.dll" in modules

    def test_find_modules_for_interface_not_found(self, loaded_index):
        assert loaded_index.find_modules_for_interface("no-such-uuid") == []

    def test_get_all_remote_interfaces(self, loaded_index):
        remote = loaded_index.get_all_remote_interfaces()
        assert len(remote) == 1
        assert remote[0].interface_id == "dddd-eeee-ffff"

    def test_get_all_named_pipe_interfaces(self, loaded_index):
        pipes = loaded_index.get_all_named_pipe_interfaces()
        assert len(pipes) == 0

    def test_get_rpc_service_map(self, loaded_index):
        svc_map = loaded_index.get_rpc_service_map()
        assert "mysvc" in svc_map
        assert len(svc_map["mysvc"]) == 2

    def test_get_interfaces_by_risk(self, loaded_index):
        critical = loaded_index.get_interfaces_by_risk("critical")
        assert len(critical) == 1
        assert critical[0].interface_id == "dddd-eeee-ffff"

    def test_get_servers(self, loaded_index):
        servers = loaded_index.get_servers()
        assert len(servers) == 3

    def test_get_clients(self, loaded_index):
        clients = loaded_index.get_clients()
        assert len(clients) == 0

    def test_summary(self, loaded_index):
        s = loaded_index.summary()
        assert s["total_interfaces"] == 3
        assert s["total_modules"] == 2
        assert s["remote_reachable"] == 1
        assert s["with_services"] == 2
        assert s["with_complex_types"] == 1


class TestDistributeProcedures:
    """Tests for the procedure distribution logic."""

    def test_exact_match_distribution(self):
        ifaces = [
            RpcInterface(
                interface_id="a", interface_version="1.0",
                binary_path="", binary_name="test.dll",
                procedure_count=2, offset=100,
            ),
            RpcInterface(
                interface_id="b", interface_version="1.0",
                binary_path="", binary_name="test.dll",
                procedure_count=3, offset=200,
            ),
        ]
        _distribute_procedures(ifaces, ["F1", "F2", "F3", "F4", "F5"])
        assert ifaces[0].procedure_names == ["F1", "F2"]
        assert ifaces[1].procedure_names == ["F3", "F4", "F5"]

    def test_single_interface_gets_all(self):
        ifaces = [
            RpcInterface(
                interface_id="a", interface_version="1.0",
                binary_path="", binary_name="test.dll",
                procedure_count=1,
            ),
        ]
        _distribute_procedures(ifaces, ["F1", "F2", "F3"])
        assert ifaces[0].procedure_names == ["F1", "F2", "F3"]

    def test_mismatch_gives_all_to_each(self):
        ifaces = [
            RpcInterface(
                interface_id="a", interface_version="1.0",
                binary_path="", binary_name="test.dll",
                procedure_count=2,
            ),
            RpcInterface(
                interface_id="b", interface_version="1.0",
                binary_path="", binary_name="test.dll",
                procedure_count=2,
            ),
        ]
        _distribute_procedures(ifaces, ["F1", "F2", "F3"])
        assert ifaces[0].procedure_names == ["F1", "F2", "F3"]
        assert ifaces[1].procedure_names == ["F1", "F2", "F3"]


# ===================================================================
# Singleton access
# ===================================================================

class TestSingleton:
    """Tests for get_rpc_index / invalidate_rpc_index."""

    def test_get_rpc_index_returns_same_instance(self):
        invalidate_rpc_index()
        idx1 = get_rpc_index()
        idx2 = get_rpc_index()
        assert idx1 is idx2

    def test_invalidate_forces_reload(self):
        idx1 = get_rpc_index()
        invalidate_rpc_index()
        idx2 = get_rpc_index()
        assert idx1 is not idx2

    def test_disabled_returns_empty_index(self):
        invalidate_rpc_index()
        with patch("helpers.rpc_index.get_config_value") as mock_cfg:
            mock_cfg.return_value = False
            idx = get_rpc_index(force_reload=True)
            assert idx.loaded is False
            assert idx.interface_count == 0
        invalidate_rpc_index()


# ===================================================================
# Live index tests (using config/assets data)
# ===================================================================

class TestLiveIndex:
    """Tests against the actual RPC data files in config/assets/."""

    @pytest.fixture(autouse=True)
    def _reset(self):
        invalidate_rpc_index()
        yield
        invalidate_rpc_index()

    def _skip_if_not_loaded(self):
        idx = get_rpc_index()
        if not idx.loaded or idx.interface_count == 0:
            pytest.skip("RPC data not available or empty")
        return idx

    def test_loads_from_config_assets(self):
        idx = self._skip_if_not_loaded()
        assert idx.interface_count > 100
        assert idx.module_count > 50

    def test_appinfo_has_interfaces(self):
        idx = self._skip_if_not_loaded()
        ifaces = idx.get_interfaces_for_module("appinfo.dll")
        assert len(ifaces) >= 5

    def test_appinfo_procedures(self):
        idx = self._skip_if_not_loaded()
        procs = idx.get_procedures_for_module("appinfo.dll")
        assert "RAiLaunchAdminProcess" in procs
        assert "RAiGetTokenForCOM" in procs

    def test_is_rpc_procedure_live(self):
        idx = self._skip_if_not_loaded()
        assert idx.is_rpc_procedure("appinfo.dll", "RAiLaunchAdminProcess") is True
        assert idx.is_rpc_procedure("appinfo.dll", "NotARpcFunction") is False

    def test_sudo_has_interface(self):
        idx = self._skip_if_not_loaded()
        ifaces = idx.get_interfaces_for_module("sudo.exe")
        assert len(ifaces) == 1
        procs = idx.get_procedures_for_module("sudo.exe")
        assert "server_DoElevationRequest" in procs
        assert "server_Shutdown" in procs

    def test_remote_reachable_interfaces_exist(self):
        idx = self._skip_if_not_loaded()
        remote = idx.get_all_remote_interfaces()
        assert len(remote) > 0
        assert all(i.is_remote_reachable for i in remote)

    def test_service_map_has_entries(self):
        idx = self._skip_if_not_loaded()
        svc_map = idx.get_rpc_service_map()
        assert len(svc_map) > 10
        assert "appinfo" in svc_map

    def test_summary_fields(self):
        idx = self._skip_if_not_loaded()
        s = idx.summary()
        assert s["total_interfaces"] > 0
        assert s["total_modules"] > 0
        assert s["total_procedures"] > 0
        assert s["server_interfaces"] > 0


# ===================================================================
# Config integration
# ===================================================================

class TestRpcConfig:
    """Tests for the rpc config section in defaults.json."""

    def test_rpc_section_exists(self):
        from helpers.config import get_config_value
        assert get_config_value("rpc.enabled") is True

    def test_rpc_servers_path_configured(self):
        from helpers.config import get_config_value
        srv_path = get_config_value("rpc.servers_path")
        assert srv_path is not None
        assert "config/assets" in srv_path

    def test_rpc_data_file_exists(self):
        from helpers.config import get_config_value
        root = Path(__file__).resolve().parent.parent
        srv_path = root / get_config_value("rpc.servers_path")
        assert srv_path.exists(), f"Missing: {srv_path}"


# ===================================================================
# Vulnerability patterns
# ===================================================================

class TestRpcVulnPatterns:
    """Tests for RPC-specific vulnerability patterns."""

    @pytest.fixture
    def vuln_patterns(self):
        root = Path(__file__).resolve().parent.parent
        path = root / "config" / "assets" / "misc_data" / "vulnerability_patterns.json"
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def test_rpc_patterns_exist(self, vuln_patterns):
        patterns = vuln_patterns.get("patterns", [])
        rpc_ids = {p["id"] for p in patterns if p.get("category") == "rpc_security"}
        assert "rpc_no_security_callback" in rpc_ids
        assert "rpc_handler_no_impersonation" in rpc_ids
        assert "rpc_missing_revert" in rpc_ids
        assert "rpc_remote_no_auth" in rpc_ids
        assert "rpc_complex_type_confusion" in rpc_ids

    def test_rpc_patterns_have_required_fields(self, vuln_patterns):
        patterns = vuln_patterns.get("patterns", [])
        rpc_patterns = [p for p in patterns if p.get("category") == "rpc_security"]
        for p in rpc_patterns:
            assert "severity_score" in p, f"{p['id']} missing severity_score"
            assert "positive_patterns" in p, f"{p['id']} missing positive_patterns"
            assert "cwe" in p, f"{p['id']} missing cwe"
            assert p["severity_score"] > 0

    def test_remote_no_auth_is_critical(self, vuln_patterns):
        patterns = vuln_patterns.get("patterns", [])
        remote_auth = next(
            (p for p in patterns if p["id"] == "rpc_remote_no_auth"), None
        )
        assert remote_auth is not None
        assert remote_auth["severity"] == "critical"
        assert remote_auth["severity_score"] >= 0.9


# ===================================================================
# Taint-analysis trust level refinement
# ===================================================================

class TestTaintTrustLevels:
    """Tests for the refined RPC trust levels in taint-analysis."""

    def test_trust_levels_include_rpc_variants(self):
        from conftest import import_skill_module
        mod = import_skill_module("taint-analysis")
        levels = mod.TRUST_LEVELS
        assert "rpc_server_remote" in levels
        assert "rpc_server_named_pipe" in levels
        assert "rpc_server_local" in levels
        assert "rpc_server" in levels

    def test_trust_level_ranks(self):
        from conftest import import_skill_module
        mod = import_skill_module("taint-analysis")
        ranks = mod.TRUST_LEVEL_RANK
        assert ranks["rpc_server_remote"] < ranks["rpc_server"]
        assert ranks["rpc_server_named_pipe"] < ranks["rpc_server"]
        assert ranks["rpc_server_local"] == ranks["rpc_server"]

    def test_refine_rpc_trust_remote(self):
        from conftest import import_skill_module
        mod = import_skill_module("taint-analysis")
        invalidate_rpc_index()
        idx = get_rpc_index()
        if not idx.loaded:
            pytest.skip("RPC index not available")
        remote_modules = [i.binary_name for i in idx.get_all_remote_interfaces()]
        if not remote_modules:
            pytest.skip("No remote-reachable modules in test data")
        result = mod._refine_rpc_trust(remote_modules[0])
        assert result == "rpc_server_remote"

    def test_refine_rpc_trust_unknown_module(self):
        from conftest import import_skill_module
        mod = import_skill_module("taint-analysis")
        result = mod._refine_rpc_trust("nonexistent_module_xyz.dll")
        assert result == "rpc_server"


# ===================================================================
# Classify-functions RPC boost
# ===================================================================

class TestClassifyRpcBoost:
    """Tests for RPC-related classification signals."""

    def test_rpc_stub_name_rule(self):
        from conftest import _make_function_record as mkfr, import_skill_module
        mod = import_skill_module("classify-functions")
        func = mkfr(
            function_id=1, function_name="s_DoElevation",
            simple_outbound_xrefs="[]",
        )
        result = mod.classify_function(func)
        assert result.primary_category == "rpc"

    def test_ndr_name_rule(self):
        from conftest import _make_function_record as mkfr, import_skill_module
        mod = import_skill_module("classify-functions")
        func = mkfr(
            function_id=2, function_name="NdrClientCall2",
            simple_outbound_xrefs="[]",
        )
        result = mod.classify_function(func)
        assert result.primary_category == "rpc"

    def test_rpc_server_name_rule(self):
        from conftest import _make_function_record as mkfr, import_skill_module
        mod = import_skill_module("classify-functions")
        func = mkfr(
            function_id=3, function_name="RpcServerRegisterIfEx",
            simple_outbound_xrefs="[]",
        )
        result = mod.classify_function(func)
        assert result.primary_category == "rpc"


# ===================================================================
# Triage-coordinator RPC characteristics
# ===================================================================

def _load_triage_common():
    """Import triage-coordinator _common.py (lives in agents/, not skills/)."""
    import importlib.util
    mod_name = "triage_coordinator_common"
    if mod_name in sys.modules:
        return sys.modules[mod_name]
    script_path = _AGENT_DIR / "agents" / "triage-coordinator" / "scripts" / "_common.py"
    scripts_dir = str(script_path.parent)
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    spec = importlib.util.spec_from_file_location(mod_name, str(script_path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


class TestTriageRpcCharacteristics:
    """Tests for RPC-enriched ModuleCharacteristics."""

    def test_new_fields_exist(self):
        mod = _load_triage_common()
        chars = mod.ModuleCharacteristics()
        assert hasattr(chars, "rpc_interface_count")
        assert hasattr(chars, "rpc_procedure_count")
        assert hasattr(chars, "rpc_remote_reachable")
        assert hasattr(chars, "rpc_service_name")
        assert hasattr(chars, "rpc_risk_tier")

    def test_is_rpc_heavy_with_index(self):
        mod = _load_triage_common()
        chars = mod.ModuleCharacteristics(rpc_interface_count=2, rpc_density=0)
        assert chars.is_rpc_heavy is True

    def test_is_rpc_heavy_without_index(self):
        mod = _load_triage_common()
        chars = mod.ModuleCharacteristics(rpc_interface_count=0, rpc_density=5)
        assert chars.is_rpc_heavy is True

    def test_not_rpc_heavy(self):
        mod = _load_triage_common()
        chars = mod.ModuleCharacteristics(rpc_interface_count=0, rpc_density=1)
        assert chars.is_rpc_heavy is False

    def test_to_dict_includes_rpc_fields(self):
        mod = _load_triage_common()
        chars = mod.ModuleCharacteristics(
            rpc_interface_count=3, rpc_procedure_count=10,
            rpc_remote_reachable=True, rpc_service_name="TestSvc",
            rpc_risk_tier="critical",
        )
        d = chars.to_dict()
        assert d["rpc_interface_count"] == 3
        assert d["rpc_procedure_count"] == 10
        assert d["rpc_remote_reachable"] is True
        assert d["rpc_service_name"] == "TestSvc"
        assert d["rpc_risk_tier"] == "critical"


# ===================================================================
# Context builder RPC section
# ===================================================================

class TestContextBuilderRpc:
    """Tests for the RPC section in session context injection."""

    def test_build_context_includes_rpc_section(self):
        from hooks._context_builder import build_context
        modules = [
            {
                "name": "appinfo_dll",
                "file_name": "appinfo.dll",
                "description": "Application Information Service",
                "total_functions": 200,
                "class_count": 5,
                "export_count": 10,
                "import_func_count": 50,
                "import_dll_count": 8,
            },
        ]
        ctx = build_context(
            modules=modules, dbs=[], has_tracking_db=False,
            skills=[], context_level="full",
        )
        assert "RPC Attack Surface" in ctx or "RPC" in ctx

    def test_build_context_minimal_no_rpc(self):
        from hooks._context_builder import build_context
        ctx = build_context(
            modules=[], dbs=[], has_tracking_db=False,
            skills=[], context_level="minimal",
        )
        assert "RPC Attack Surface" not in ctx


# ===================================================================
# map-attack-surface EntryPoint RPC fields
# ===================================================================

class TestEntryPointRpcFields:
    """Tests for the new RPC fields on the EntryPoint dataclass."""

    def test_entrypoint_has_rpc_fields(self):
        from conftest import import_skill_module
        mod = import_skill_module("map-attack-surface")
        ep = mod.EntryPoint(
            function_name="TestFunc",
            rpc_interface_id="abc-123",
            rpc_opnum=5,
            rpc_protocol="ncacn_ip_tcp",
            rpc_service="TestSvc",
            rpc_risk_tier="critical",
        )
        assert ep.rpc_interface_id == "abc-123"
        assert ep.rpc_opnum == 5
        assert ep.rpc_protocol == "ncacn_ip_tcp"
        assert ep.rpc_service == "TestSvc"
        assert ep.rpc_risk_tier == "critical"

    def test_entrypoint_to_dict_has_rpc_fields(self):
        from conftest import import_skill_module
        mod = import_skill_module("map-attack-surface")
        ep = mod.EntryPoint(
            function_name="TestFunc",
            rpc_interface_id="uuid-test",
            rpc_opnum=0,
            rpc_protocol="ncalrpc",
            rpc_service="Svc",
            rpc_risk_tier="medium",
        )
        d = ep.to_dict()
        assert d["rpc_interface_id"] == "uuid-test"
        assert d["rpc_opnum"] == 0
        assert d["rpc_protocol"] == "ncalrpc"
        assert d["rpc_service"] == "Svc"
        assert d["rpc_risk_tier"] == "medium"

    def test_entrypoint_rpc_fields_default_empty(self):
        from conftest import import_skill_module
        mod = import_skill_module("map-attack-surface")
        ep = mod.EntryPoint(function_name="PlainFunc")
        assert ep.rpc_interface_id == ""
        assert ep.rpc_opnum is None
        assert ep.rpc_protocol == ""
        assert ep.rpc_service == ""
        assert ep.rpc_risk_tier == ""


# ===================================================================
# Rank entrypoints protocol-aware scoring
# ===================================================================

class TestProtocolAwareScoring:
    """Tests for the _rpc_protocol_bonus function."""

    def test_tcp_gets_highest_score(self):
        from conftest import import_skill_module
        atk = import_skill_module("map-attack-surface")
        rank_mod = import_skill_module("map-attack-surface", "rank_entrypoints")

        ep = atk.EntryPoint(
            function_name="F1",
            entry_type=atk.EntryPointType.RPC_HANDLER,
            rpc_protocol="ncacn_ip_tcp,ncalrpc",
        )
        score = rank_mod._rpc_protocol_bonus(ep)
        assert score >= 0.95

    def test_named_pipe_score(self):
        from conftest import import_skill_module
        atk = import_skill_module("map-attack-surface")
        rank_mod = import_skill_module("map-attack-surface", "rank_entrypoints")

        ep = atk.EntryPoint(
            function_name="F2",
            entry_type=atk.EntryPointType.RPC_HANDLER,
            rpc_protocol="ncacn_np",
        )
        score = rank_mod._rpc_protocol_bonus(ep)
        assert 0.80 <= score <= 0.90

    def test_local_with_service(self):
        from conftest import import_skill_module
        atk = import_skill_module("map-attack-surface")
        rank_mod = import_skill_module("map-attack-surface", "rank_entrypoints")

        ep = atk.EntryPoint(
            function_name="F3",
            entry_type=atk.EntryPointType.RPC_HANDLER,
            rpc_protocol="ncalrpc",
            rpc_service="MySvc",
        )
        score = rank_mod._rpc_protocol_bonus(ep)
        assert score >= 0.70

    def test_non_rpc_returns_zero(self):
        from conftest import import_skill_module
        atk = import_skill_module("map-attack-surface")
        rank_mod = import_skill_module("map-attack-surface", "rank_entrypoints")

        ep = atk.EntryPoint(
            function_name="F4",
            entry_type=atk.EntryPointType.EXPORT_DLL,
        )
        score = rank_mod._rpc_protocol_bonus(ep)
        assert score == 0.0

    def test_heuristic_only_fallback(self):
        from conftest import import_skill_module
        atk = import_skill_module("map-attack-surface")
        rank_mod = import_skill_module("map-attack-surface", "rank_entrypoints")

        ep = atk.EntryPoint(
            function_name="F5",
            entry_type=atk.EntryPointType.RPC_HANDLER,
            rpc_protocol="",
        )
        score = rank_mod._rpc_protocol_bonus(ep)
        assert score == 0.9


# ===================================================================
# Cross-module graph RPC edges
# ===================================================================

class TestCrossModuleRpcEdges:
    """Tests for inject_rpc_edges on CrossModuleGraph."""

    def test_inject_rpc_edges_returns_zero_when_no_clients(self):
        from helpers.cross_module_graph import CrossModuleGraph
        cmg = CrossModuleGraph()
        count = cmg.inject_rpc_edges()
        assert count == 0

    def test_get_rpc_edges_empty(self):
        from helpers.cross_module_graph import CrossModuleGraph
        cmg = CrossModuleGraph()
        edges = cmg.get_rpc_edges()
        assert edges == []


# ===================================================================
# Registry entries
# ===================================================================

class TestRegistryEntries:
    """Tests that new skill and command are properly registered."""

    def test_skill_registry_has_rpc_interface_analysis(self):
        root = Path(__file__).resolve().parent.parent
        with open(root / "skills" / "registry.json", "r") as f:
            reg = json.load(f)
        skills = reg.get("skills", {})
        assert "rpc-interface-analysis" in skills
        entry = skills["rpc-interface-analysis"]
        assert entry["type"] == "security"
        assert len(entry["entry_scripts"]) == 6

    def test_command_registry_has_rpc(self):
        root = Path(__file__).resolve().parent.parent
        with open(root / "commands" / "registry.json", "r") as f:
            reg = json.load(f)
        commands = reg.get("commands", {})
        assert "rpc" in commands
        entry = commands["rpc"]
        assert "rpc-interface-analysis" in entry["skills_used"]
        assert entry["file"] == "rpc-analysis.md"

    def test_command_md_file_exists(self):
        root = Path(__file__).resolve().parent.parent
        assert (root / "commands" / "rpc-analysis.md").exists()

    def test_skill_md_file_exists(self):
        root = Path(__file__).resolve().parent.parent
        assert (root / "skills" / "rpc-interface-analysis" / "SKILL.md").exists()

    def test_all_skill_scripts_exist(self):
        root = Path(__file__).resolve().parent.parent
        scripts_dir = root / "skills" / "rpc-interface-analysis" / "scripts"
        expected = [
            "_common.py",
            "resolve_rpc_interface.py",
            "map_rpc_surface.py",
            "audit_rpc_security.py",
            "trace_rpc_chain.py",
            "find_rpc_clients.py",
        ]
        for script in expected:
            assert (scripts_dir / script).exists(), f"Missing: {script}"




# ===================================================================
# Enhanced endpoint parsing (5-tuple return)
# ===================================================================

class TestEnhancedEndpointParsing:
    """Tests for the enhanced _parse_endpoints returning a 5-tuple."""

    def test_pipe_name_extraction(self):
        endpoints, protocols, pipe_names, alpc_endpoints, tcp_ports = _parse_endpoints(
            "[uuid, 1.0] ncacn_np:[\\\\pipe\\\\lsass]"
        )
        assert "ncacn_np" in protocols
        assert "lsass" in pipe_names

    def test_alpc_endpoint_extraction(self):
        endpoints, protocols, pipe_names, alpc_endpoints, tcp_ports = _parse_endpoints(
            "[uuid, 1.0] ncalrpc:[LSARPC_ENDPOINT]"
        )
        assert "LSARPC_ENDPOINT" in alpc_endpoints

    def test_dynamic_alpc_filtered(self):
        endpoints, protocols, pipe_names, alpc_endpoints, tcp_ports = _parse_endpoints(
            "[uuid, 1.0] ncalrpc:[LRPC-abc123]"
        )
        assert alpc_endpoints == []

    def test_tcp_port_extraction(self):
        endpoints, protocols, pipe_names, alpc_endpoints, tcp_ports = _parse_endpoints(
            "[uuid, 1.0] ncacn_ip_tcp:[49664]"
        )
        assert 49664 in tcp_ports

    def test_multi_endpoint_string(self):
        endpoints, protocols, pipe_names, alpc_endpoints, tcp_ports = _parse_endpoints([
            "[uuid, 1.0] ncacn_np:[\\\\pipe\\\\spoolss]",
            "[uuid, 1.0] ncalrpc:[SPOOLSS_ENDPOINT]",
            "[uuid, 1.0] ncacn_ip_tcp:[50000]",
        ])
        assert "spoolss" in pipe_names
        assert "SPOOLSS_ENDPOINT" in alpc_endpoints
        assert 50000 in tcp_ports
        assert protocols == {"ncacn_np", "ncalrpc", "ncacn_ip_tcp"}

    def test_dedup(self):
        endpoints, protocols, pipe_names, alpc_endpoints, tcp_ports = _parse_endpoints([
            "[uuid, 1.0] ncacn_np:[\\\\pipe\\\\samr]",
            "[uuid, 1.0] ncacn_np:[\\\\pipe\\\\samr]",
        ])
        assert pipe_names.count("samr") == 1


# ===================================================================
# VersionInfo extraction
# ===================================================================

class TestVersionInfoExtraction:
    """Tests for VersionInfo metadata extraction during index build."""

    def test_version_info_populated(self):
        idx = RpcIndex()
        data = {
            "c:\\windows\\system32\\test.dll": {
                "binary_path": "C:\\windows\\system32\\test.dll",
                "file_info": {
                    "file_description": "Test Module",
                    "file_version": "10.0.19041.1",
                    "company_name": "Microsoft Corporation",
                    "product_version": "10.0.19041.1",
                },
                "interfaces": [{
                    "interface_id": "vi-uuid-001",
                    "interface_version": "1.0",
                    "procedure_count": 1,
                    "endpoints": [],
                    "is_client": False,
                }],
                "procedures": [],
            },
        }
        idx._build_index(data)
        ifaces = idx.get_interfaces_for_module("test.dll")
        assert len(ifaces) == 1
        assert ifaces[0].file_description == "Test Module"
        assert ifaces[0].file_version == "10.0.19041.1"
        assert ifaces[0].company_name == "Microsoft Corporation"

    def test_version_info_missing(self):
        idx = RpcIndex()
        data = {
            "c:\\windows\\system32\\bare.dll": {
                "binary_path": "C:\\windows\\system32\\bare.dll",
                "file_info": {},
                "interfaces": [{
                    "interface_id": "vi-uuid-002",
                    "interface_version": "1.0",
                    "procedure_count": 1,
                    "endpoints": [],
                    "is_client": False,
                }],
                "procedures": [],
            },
        }
        idx._build_index(data)
        ifaces = idx.get_interfaces_for_module("bare.dll")
        assert len(ifaces) == 1
        assert ifaces[0].file_description == ""
        assert ifaces[0].file_version == ""
        assert ifaces[0].company_name == ""

    def test_is_third_party(self):
        third_party = RpcInterface(
            interface_id="tp-uuid", interface_version="1.0",
            binary_path="", binary_name="test.dll",
            procedure_count=1, company_name="Acme Corp",
        )
        assert third_party.is_third_party is True

        microsoft = RpcInterface(
            interface_id="ms-uuid", interface_version="1.0",
            binary_path="", binary_name="test.dll",
            procedure_count=1, company_name="Microsoft Corporation",
        )
        assert microsoft.is_third_party is False


# ===================================================================
# Procedure classifier
# ===================================================================

from helpers.rpc_procedure_classifier import (
    classify_procedure,
    classify_procedures,
    summarize_classifications,
)


class TestProcedureClassifier:
    """Tests for RPC procedure name semantic classification."""

    def test_read_classification(self):
        cls = classify_procedure("RpcEnumPrinters")
        assert cls.semantic_class == "read"

    def test_mutation_classification(self):
        cls = classify_procedure("RpcAddPrinter")
        assert cls.semantic_class == "mutation"

    def test_destroy_classification(self):
        cls = classify_procedure("RpcDeletePrinter")
        assert cls.semantic_class == "destroy"

    def test_handle_classification(self):
        cls = classify_procedure("RpcOpenPrinter")
        assert cls.semantic_class == "handle"

    def test_identity_classification(self):
        cls = classify_procedure("RpcImpersonateClient")
        assert cls.semantic_class == "identity"

    def test_execute_classification(self):
        cls = classify_procedure("LaunchProcess")
        assert cls.semantic_class == "execute"

    def test_unknown_classification(self):
        cls = classify_procedure("XyzFoo")
        assert cls.semantic_class == "unknown"

    def test_prefix_stripping(self):
        cls = classify_procedure("s_SSCryptProtectData")
        assert cls.name == "s_SSCryptProtectData"
        assert isinstance(cls.semantic_class, str)
        assert cls.semantic_class

    def test_summarize(self):
        results = classify_procedures([
            "RpcEnumPrinters", "RpcAddPrinter", "RpcDeletePrinter",
        ])
        summary = summarize_classifications(results)
        assert summary["total_procedures"] == 3
        assert summary["by_class"]["read"] == 1
        assert summary["by_class"]["mutation"] == 1
        assert summary["by_class"]["destroy"] == 1


# ===================================================================
# Blast radius
# ===================================================================

class TestBlastRadius:
    """Tests for compute_blast_radius co-hosting analysis."""

    def test_blast_radius_found(self):
        idx = RpcIndex()
        data = {
            "c:\\shared.dll": {
                "binary_path": "C:\\shared.dll",
                "file_info": {},
                "interfaces": [
                    {"interface_id": "br-uuid-1", "interface_version": "1.0", "procedure_count": 2, "endpoints": [], "is_client": False, "service_name": "SharedSvc"},
                    {"interface_id": "br-uuid-2", "interface_version": "1.0", "procedure_count": 3, "endpoints": [], "is_client": False, "service_name": "SharedSvc"},
                ],
                "procedures": [],
            },
        }
        idx._build_index(data)
        result = idx.compute_blast_radius("br-uuid-1")
        assert result["found"] is True
        sibling_uuids = {s["interface_id"] for s in result["siblings"]}
        assert "br-uuid-2" in sibling_uuids

    def test_blast_radius_not_found(self):
        idx = RpcIndex()
        idx._build_index({})
        result = idx.compute_blast_radius("no-such-uuid")
        assert result["found"] is False

    def test_blast_radius_combines_protocols(self):
        idx = RpcIndex()
        data = {
            "c:\\multi.dll": {
                "binary_path": "C:\\multi.dll",
                "file_info": {},
                "interfaces": [
                    {"interface_id": "bp-uuid-1", "interface_version": "1.0", "procedure_count": 1, "endpoints": ["[bp-uuid-1, 1.0] ncacn_ip_tcp:[5555]"], "is_client": False, "service_name": "MultiSvc"},
                    {"interface_id": "bp-uuid-2", "interface_version": "1.0", "procedure_count": 1, "endpoints": ["[bp-uuid-2, 1.0] ncalrpc:[LOCAL]"], "is_client": False, "service_name": "MultiSvc"},
                ],
                "procedures": [],
            },
        }
        idx._build_index(data)
        result = idx.compute_blast_radius("bp-uuid-1")
        assert result["found"] is True
        assert "ncacn_ip_tcp" in result["combined_protocols"]
        assert "ncalrpc" in result["combined_protocols"]


# ===================================================================
# String cross-reference
# ===================================================================

class TestStringCrossReference:
    """Tests for cross_reference_strings matching against the RPC index."""

    def test_uuid_match(self):
        idx = RpcIndex()
        data = {
            "c:\\target.dll": {
                "binary_path": "C:\\target.dll", "file_info": {},
                "interfaces": [{"interface_id": "aabbccdd-1122-3344-5566-778899aabbcc", "interface_version": "1.0", "procedure_count": 1, "endpoints": [], "is_client": False}],
                "procedures": [],
            },
        }
        idx._build_index(data)
        results = idx.cross_reference_strings(["binding to aabbccdd-1122-3344-5566-778899aabbcc"])
        assert len(results) >= 1
        assert any(r["match_type"] == "uuid" for r in results)

    def test_pipe_name_match(self):
        idx = RpcIndex()
        data = {
            "c:\\pipe.dll": {
                "binary_path": "C:\\pipe.dll", "file_info": {},
                "interfaces": [{"interface_id": "pipe-uuid-001", "interface_version": "1.0", "procedure_count": 1, "endpoints": ["[pipe-uuid-001, 1.0] ncacn_np:[\\\\pipe\\\\testpipe]"], "is_client": False}],
                "procedures": [],
            },
        }
        idx._build_index(data)
        results = idx.cross_reference_strings(["testpipe"])
        assert len(results) >= 1
        assert any(r["match_type"] == "pipe_name" for r in results)

    def test_alpc_match(self):
        idx = RpcIndex()
        data = {
            "c:\\alpc.dll": {
                "binary_path": "C:\\alpc.dll", "file_info": {},
                "interfaces": [{"interface_id": "alpc-uuid-001", "interface_version": "1.0", "procedure_count": 1, "endpoints": ["[alpc-uuid-001, 1.0] ncalrpc:[TESTALPC]"], "is_client": False}],
                "procedures": [],
            },
        }
        idx._build_index(data)
        results = idx.cross_reference_strings(["TESTALPC"])
        assert len(results) >= 1
        assert any(r["match_type"] == "alpc_endpoint" for r in results)

    def test_no_match(self):
        idx = RpcIndex()
        idx._build_index({})
        results = idx.cross_reference_strings(["random_string_123", "nothing_useful_here"])
        assert results == []


# ===================================================================
# RPC config extension
# ===================================================================

class TestRpcConfigExtended:
    """Extended tests for rpc config keys in defaults.json."""

    def test_rpc_config_client_stubs_path(self):
        root = Path(__file__).resolve().parent.parent
        with open(root / "config" / "defaults.json", "r") as f:
            config = json.load(f)
        assert "client_stubs_path" in config["rpc"]

    def test_rpc_config_load_stubs(self):
        root = Path(__file__).resolve().parent.parent
        with open(root / "config" / "defaults.json", "r") as f:
            config = json.load(f)
        assert "load_stubs" in config["rpc"]
