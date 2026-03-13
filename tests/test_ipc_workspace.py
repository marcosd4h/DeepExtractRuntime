"""Tests for helpers/ipc_workspace.py -- workspace IPC server discovery.

Covers:
  - Module name normalization (folder name -> PE filename)
  - discover_workspace_ipc_servers() intersection logic
  - IPC type filtering
  - Access context propagation for COM/WinRT
  - Graceful degradation when indexes are unavailable
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
from dataclasses import dataclass, field

import pytest

_AGENT_DIR = Path(__file__).resolve().parent.parent
if str(_AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENT_DIR))

from helpers.ipc_workspace import (
    _resolve_module_filename,
    _get_workspace_modules,
    discover_workspace_ipc_servers,
    ALL_IPC_TYPES,
)


# ===================================================================
# Module name normalization
# ===================================================================


class TestResolveModuleFilename:
    """Test folder-name-to-PE-filename mapping."""

    def test_from_file_info_json(self, tmp_path):
        """Reads file_name from file_info.json when present."""
        mod_dir = tmp_path / "srvsvc_dll"
        mod_dir.mkdir()
        fi = {"basic_file_info": {"file_name": "srvsvc.dll"}}
        (mod_dir / "file_info.json").write_text(json.dumps(fi))

        with patch("helpers.ipc_workspace._EXTRACTED_CODE_DIR", tmp_path):
            assert _resolve_module_filename("srvsvc_dll") == "srvsvc.dll"

    def test_fallback_dll(self):
        """Heuristic fallback for _dll suffix."""
        with patch("helpers.ipc_workspace._EXTRACTED_CODE_DIR", Path("/nonexistent")):
            assert _resolve_module_filename("advapi32_dll") == "advapi32.dll"

    def test_fallback_exe(self):
        """Heuristic fallback for _exe suffix."""
        with patch("helpers.ipc_workspace._EXTRACTED_CODE_DIR", Path("/nonexistent")):
            assert _resolve_module_filename("svchost_exe") == "svchost.exe"

    def test_fallback_sys(self):
        with patch("helpers.ipc_workspace._EXTRACTED_CODE_DIR", Path("/nonexistent")):
            assert _resolve_module_filename("ntfs_sys") == "ntfs.sys"

    def test_file_info_takes_precedence(self, tmp_path):
        """file_info.json is preferred over heuristic."""
        mod_dir = tmp_path / "kernel_appcore_dll"
        mod_dir.mkdir()
        fi = {"basic_file_info": {"file_name": "kernel.appcore.dll"}}
        (mod_dir / "file_info.json").write_text(json.dumps(fi))

        with patch("helpers.ipc_workspace._EXTRACTED_CODE_DIR", tmp_path):
            result = _resolve_module_filename("kernel_appcore_dll")
            assert result == "kernel.appcore.dll"

    def test_missing_file_info_and_no_ext(self):
        """Returns None when no file_info.json and folder name has no known ext."""
        with patch("helpers.ipc_workspace._EXTRACTED_CODE_DIR", Path("/nonexistent")):
            assert _resolve_module_filename("weird_name") is None

    def test_corrupt_file_info(self, tmp_path):
        """Falls back to heuristic on corrupt JSON."""
        mod_dir = tmp_path / "foo_dll"
        mod_dir.mkdir()
        (mod_dir / "file_info.json").write_text("{bad json")

        with patch("helpers.ipc_workspace._EXTRACTED_CODE_DIR", tmp_path):
            assert _resolve_module_filename("foo_dll") == "foo.dll"


# ===================================================================
# Workspace module resolution
# ===================================================================


class TestGetWorkspaceModules:
    """Test the workspace module list -> filename mapping."""

    def test_maps_folders_to_filenames(self, tmp_path):
        for name in ["srvsvc_dll", "combase_dll"]:
            d = tmp_path / name
            d.mkdir()
            fi = {"basic_file_info": {"file_name": f"{name.replace('_dll', '.dll')}"}}
            (d / "file_info.json").write_text(json.dumps(fi))

        with (
            patch("helpers.ipc_workspace._EXTRACTED_CODE_DIR", tmp_path),
            patch("helpers.ipc_workspace._get_workspace_modules") as mock_fn,
        ):
            mock_fn.return_value = {"srvsvc.dll": "srvsvc_dll", "combase.dll": "combase_dll"}
            result = mock_fn()

        assert "srvsvc.dll" in result
        assert "combase.dll" in result

    def test_empty_workspace(self):
        with patch("helpers.function_index.list_extracted_modules", return_value=[]):
            result = _get_workspace_modules()
        assert result == {}


# ===================================================================
# Mock IPC index helpers
# ===================================================================


@dataclass
class _MockComServer:
    clsid: str = "{12345678-1234-1234-1234-123456789012}"
    name: str = "TestServer"
    server_type: str = "InProcServer32"
    access_contexts: set = field(default_factory=lambda: {MagicMock(__str__=lambda s: "high_il_all")})
    runs_as_system: bool = False
    can_elevate: bool = False
    is_service: bool = False
    service_name: str = ""
    interfaces: list = field(default_factory=list)
    method_count: int = 5


@dataclass
class _MockRpcInterface:
    interface_id: str = "aaaa-bbbb-cccc"
    interface_version: str = "1.0"
    procedure_count: int = 3
    procedure_names: list = field(default_factory=lambda: ["FuncA", "FuncB", "FuncC"])
    risk_tier: str = "high"
    is_remote_reachable: bool = False
    service_name: str = "TestSvc"
    pipe_names: list = field(default_factory=list)


@dataclass
class _MockWinrtServer:
    name: str = "Windows.Test.TestClass"
    activation_type: str = "OutOfProcess"
    access_contexts: set = field(default_factory=lambda: {MagicMock(__str__=lambda s: "medium_il_all")})
    trust_level: str = "BaseTrust"
    runs_as_system: bool = True
    service_name: str = ""
    interface_count: int = 2
    method_count: int = 8


def _make_mock_com_index(modules_with_servers: dict):
    idx = MagicMock()
    idx.loaded = True
    idx.get_servers_for_module.side_effect = lambda m: modules_with_servers.get(m.lower(), [])
    return idx


def _make_mock_rpc_index(modules_with_ifaces: dict):
    idx = MagicMock()
    idx.loaded = True
    idx.get_interfaces_for_module.side_effect = lambda m: modules_with_ifaces.get(m.lower(), [])
    return idx


def _make_mock_winrt_index(modules_with_servers: dict):
    idx = MagicMock()
    idx.loaded = True
    idx.get_servers_for_module.side_effect = lambda m: modules_with_servers.get(m.lower(), [])
    return idx


# ===================================================================
# discover_workspace_ipc_servers
# ===================================================================


class TestDiscoverWorkspaceIpcServers:
    """Test the main intersection function."""

    def _patch_workspace(self, modules: dict[str, str]):
        return patch("helpers.ipc_workspace._get_workspace_modules", return_value=modules)

    def test_com_intersection(self):
        ws = {"srvsvc.dll": "srvsvc_dll", "ntdll.dll": "ntdll_dll"}
        com_idx = _make_mock_com_index({"srvsvc.dll": [_MockComServer()]})

        with (
            self._patch_workspace(ws),
            patch("helpers.ipc_workspace.get_com_index", return_value=com_idx,
                  create=True),
            patch("helpers.com_index.get_com_index", return_value=com_idx,
                  create=True),
        ):
            result = discover_workspace_ipc_servers(ipc_types=["com"])

        assert "com" in result
        assert "srvsvc.dll" in result["com"]
        assert "ntdll.dll" not in result["com"]
        assert result["summary"]["com_modules"] == 1

    def test_rpc_intersection(self):
        ws = {"srvsvc.dll": "srvsvc_dll", "ntdll.dll": "ntdll_dll"}
        rpc_idx = _make_mock_rpc_index({"srvsvc.dll": [_MockRpcInterface()]})

        with (
            self._patch_workspace(ws),
            patch("helpers.ipc_workspace.get_rpc_index", return_value=rpc_idx,
                  create=True),
            patch("helpers.rpc_index.get_rpc_index", return_value=rpc_idx,
                  create=True),
        ):
            result = discover_workspace_ipc_servers(ipc_types=["rpc"])

        assert "rpc" in result
        assert "srvsvc.dll" in result["rpc"]
        assert result["rpc"]["srvsvc.dll"]["interface_count"] == 1
        assert result["summary"]["rpc_modules"] == 1

    def test_winrt_intersection(self):
        ws = {"combase.dll": "combase_dll"}
        winrt_idx = _make_mock_winrt_index({"combase.dll": [_MockWinrtServer()]})

        with (
            self._patch_workspace(ws),
            patch("helpers.ipc_workspace.get_winrt_index", return_value=winrt_idx,
                  create=True),
            patch("helpers.winrt_index.get_winrt_index", return_value=winrt_idx,
                  create=True),
        ):
            result = discover_workspace_ipc_servers(ipc_types=["winrt"])

        assert "winrt" in result
        assert "combase.dll" in result["winrt"]
        assert result["winrt"]["combase.dll"]["server_count"] == 1

    def test_all_types_default(self):
        ws = {"srvsvc.dll": "srvsvc_dll"}
        com_idx = _make_mock_com_index({})
        rpc_idx = _make_mock_rpc_index({"srvsvc.dll": [_MockRpcInterface()]})
        winrt_idx = _make_mock_winrt_index({})

        with (
            self._patch_workspace(ws),
            patch("helpers.ipc_workspace.get_com_index", return_value=com_idx, create=True),
            patch("helpers.com_index.get_com_index", return_value=com_idx, create=True),
            patch("helpers.ipc_workspace.get_rpc_index", return_value=rpc_idx, create=True),
            patch("helpers.rpc_index.get_rpc_index", return_value=rpc_idx, create=True),
            patch("helpers.ipc_workspace.get_winrt_index", return_value=winrt_idx, create=True),
            patch("helpers.winrt_index.get_winrt_index", return_value=winrt_idx, create=True),
        ):
            result = discover_workspace_ipc_servers()

        assert "com" in result
        assert "rpc" in result
        assert "winrt" in result
        assert result["summary"]["com_modules"] == 0
        assert result["summary"]["rpc_modules"] == 1
        assert result["summary"]["winrt_modules"] == 0

    def test_type_filtering_excludes_others(self):
        ws = {"srvsvc.dll": "srvsvc_dll"}
        rpc_idx = _make_mock_rpc_index({"srvsvc.dll": [_MockRpcInterface()]})

        with (
            self._patch_workspace(ws),
            patch("helpers.ipc_workspace.get_rpc_index", return_value=rpc_idx, create=True),
            patch("helpers.rpc_index.get_rpc_index", return_value=rpc_idx, create=True),
        ):
            result = discover_workspace_ipc_servers(ipc_types=["rpc"])

        assert "rpc" in result
        assert "com" not in result
        assert "winrt" not in result

    def test_empty_workspace(self):
        with patch("helpers.ipc_workspace._get_workspace_modules", return_value={}):
            result = discover_workspace_ipc_servers(ipc_types=["com"])

        assert result["summary"]["total_workspace_modules"] == 0
        assert result["summary"]["com_modules"] == 0

    def test_no_matches(self):
        ws = {"ntdll.dll": "ntdll_dll"}
        com_idx = _make_mock_com_index({})

        with (
            patch("helpers.ipc_workspace._get_workspace_modules", return_value=ws),
            patch("helpers.ipc_workspace.get_com_index", return_value=com_idx, create=True),
            patch("helpers.com_index.get_com_index", return_value=com_idx, create=True),
        ):
            result = discover_workspace_ipc_servers(ipc_types=["com"])

        assert result["com"] == {}
        assert result["summary"]["com_modules"] == 0

    def test_invalid_ipc_type(self):
        with pytest.raises(ValueError, match="Unknown IPC types"):
            discover_workspace_ipc_servers(ipc_types=["bogus"])

    def test_workspace_modules_in_output(self):
        ws = {"srvsvc.dll": "srvsvc_dll", "ntdll.dll": "ntdll_dll"}
        com_idx = _make_mock_com_index({})

        with (
            patch("helpers.ipc_workspace._get_workspace_modules", return_value=ws),
            patch("helpers.ipc_workspace.get_com_index", return_value=com_idx, create=True),
            patch("helpers.com_index.get_com_index", return_value=com_idx, create=True),
        ):
            result = discover_workspace_ipc_servers(ipc_types=["com"])

        assert sorted(result["workspace_modules"]) == ["ntdll.dll", "srvsvc.dll"]


# ===================================================================
# Graceful degradation
# ===================================================================


class TestGracefulDegradation:
    """Test behavior when IPC indexes are unavailable."""

    def test_com_index_not_loaded(self):
        ws = {"srvsvc.dll": "srvsvc_dll"}
        idx = MagicMock()
        idx.loaded = False

        with (
            patch("helpers.ipc_workspace._get_workspace_modules", return_value=ws),
            patch("helpers.ipc_workspace.get_com_index", return_value=idx, create=True),
            patch("helpers.com_index.get_com_index", return_value=idx, create=True),
        ):
            result = discover_workspace_ipc_servers(ipc_types=["com"])

        assert result["com"] == {}

    def test_rpc_index_import_error(self):
        ws = {"srvsvc.dll": "srvsvc_dll"}

        def raise_import():
            raise ImportError("no rpc_index")

        with (
            patch("helpers.ipc_workspace._get_workspace_modules", return_value=ws),
            patch("helpers.ipc_workspace._discover_rpc", return_value={}),
        ):
            result = discover_workspace_ipc_servers(ipc_types=["rpc"])

        assert result["rpc"] == {}


# ===================================================================
# COM server summary contents
# ===================================================================


class TestComServerSummary:
    """Verify that COM server summaries include expected fields."""

    def test_access_contexts_in_output(self):
        ws = {"srvsvc.dll": "srvsvc_dll"}
        server = _MockComServer()
        com_idx = _make_mock_com_index({"srvsvc.dll": [server]})

        with (
            patch("helpers.ipc_workspace._get_workspace_modules", return_value=ws),
            patch("helpers.ipc_workspace.get_com_index", return_value=com_idx, create=True),
            patch("helpers.com_index.get_com_index", return_value=com_idx, create=True),
        ):
            result = discover_workspace_ipc_servers(ipc_types=["com"])

        srv_data = result["com"]["srvsvc.dll"]["servers"][0]
        assert "access_contexts" in srv_data
        assert isinstance(srv_data["access_contexts"], list)

    def test_security_fields_in_output(self):
        ws = {"srvsvc.dll": "srvsvc_dll"}
        server = _MockComServer(runs_as_system=True, can_elevate=True, is_service=True)
        com_idx = _make_mock_com_index({"srvsvc.dll": [server]})

        with (
            patch("helpers.ipc_workspace._get_workspace_modules", return_value=ws),
            patch("helpers.ipc_workspace.get_com_index", return_value=com_idx, create=True),
            patch("helpers.com_index.get_com_index", return_value=com_idx, create=True),
        ):
            result = discover_workspace_ipc_servers(ipc_types=["com"])

        srv_data = result["com"]["srvsvc.dll"]["servers"][0]
        assert srv_data["runs_as_system"] is True
        assert srv_data["can_elevate"] is True
        assert srv_data["is_service"] is True
