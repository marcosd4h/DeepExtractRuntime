"""System-wide RPC interface index built from NtApiDotNet extraction data.

Loads ``config/assets/rpc_data/rpc_servers.json`` (binary-keyed interface metadata,
endpoints, file info, and procedure lists per binary) and exposes a queryable index.

Typical usage::

    from helpers.rpc_index import get_rpc_index

    idx = get_rpc_index()
    ifaces = idx.get_interfaces_for_module("appinfo.dll")
    procs  = idx.get_procedures_for_module("appinfo.dll")
    is_rpc = idx.is_rpc_procedure("appinfo.dll", "RAiLaunchAdminProcess")
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .config import get_config_value
from .db_paths import module_name_from_path
from .errors import log_warning

_log = logging.getLogger(__name__)

_WORKSPACE_ROOT = Path(__file__).resolve().parents[1]

_PROTOCOL_RE = re.compile(r"(ncalrpc|ncacn_np|ncacn_ip_tcp|ncacn_http|ncadg_ip_udp)")
_PIPE_NAME_RE = re.compile(r"ncacn_np:\[\\\\(?:pipe|PIPE)\\\\(.+?)\]")
_ALPC_NAME_RE = re.compile(r"ncalrpc:\[(.+?)\]")
_TCP_PORT_RE = re.compile(r"ncacn_ip_tcp:\[(\d+)\]")
_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class RpcInterface:
    """Metadata for a single RPC interface registered in a binary."""

    interface_id: str
    interface_version: str
    binary_path: str
    binary_name: str
    procedure_count: int
    procedure_names: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    protocols: set[str] = field(default_factory=set)
    service_name: Optional[str] = None
    service_display_name: Optional[str] = None
    is_service_running: bool = False
    is_client: bool = False
    complex_types: list[str] = field(default_factory=list)
    transfer_syntax_id: str = ""
    offset: int = 0

    pipe_names: list[str] = field(default_factory=list)
    alpc_endpoints: list[str] = field(default_factory=list)
    tcp_ports: list[int] = field(default_factory=list)

    file_description: str = ""
    file_version: str = ""
    company_name: str = ""
    product_version: str = ""

    @property
    def is_remote_reachable(self) -> bool:
        return bool({"ncacn_ip_tcp", "ncacn_http"} & self.protocols)

    @property
    def is_named_pipe(self) -> bool:
        return "ncacn_np" in self.protocols

    @property
    def is_local_only(self) -> bool:
        return not self.protocols or self.protocols <= {"ncalrpc"}

    @property
    def risk_tier(self) -> str:
        if self.is_remote_reachable:
            return "critical"
        if self.is_named_pipe:
            return "high"
        if self.is_local_only and self.is_service_running:
            return "medium"
        return "low"

    @property
    def has_complex_types(self) -> bool:
        return bool(self.complex_types)

    @property
    def is_third_party(self) -> bool:
        if not self.company_name:
            return False
        return "microsoft" not in self.company_name.lower()

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "interface_id": self.interface_id,
            "interface_version": self.interface_version,
            "binary_name": self.binary_name,
            "binary_path": self.binary_path,
            "procedure_count": self.procedure_count,
            "procedure_names": self.procedure_names,
            "endpoints": self.endpoints,
            "protocols": sorted(self.protocols),
            "service_name": self.service_name,
            "service_display_name": self.service_display_name,
            "is_service_running": self.is_service_running,
            "is_client": self.is_client,
            "complex_types": self.complex_types,
            "transfer_syntax_id": self.transfer_syntax_id,
            "risk_tier": self.risk_tier,
            "is_remote_reachable": self.is_remote_reachable,
            "has_complex_types": self.has_complex_types,
            "pipe_names": self.pipe_names,
            "alpc_endpoints": self.alpc_endpoints,
            "tcp_ports": self.tcp_ports,
        }
        if self.file_description:
            d["file_description"] = self.file_description
        if self.file_version:
            d["file_version"] = self.file_version
        if self.company_name:
            d["company_name"] = self.company_name
        return d


# ---------------------------------------------------------------------------
# Index
# ---------------------------------------------------------------------------

class RpcIndex:
    """Queryable index over system RPC interfaces and procedures."""

    def __init__(self) -> None:
        self._interfaces: list[RpcInterface] = []
        self._by_module: dict[str, list[RpcInterface]] = {}
        self._procedures_by_module: dict[str, set[str]] = {}
        self._by_uuid: dict[str, list[RpcInterface]] = {}
        self._by_service: dict[str, list[RpcInterface]] = {}
        self._by_pipe_name: dict[str, list[RpcInterface]] = {}
        self._by_alpc: dict[str, list[RpcInterface]] = {}
        self._stubs: dict[str, Any] = {}  # uuid_lower -> RpcStubFile
        self._loaded = False

    @property
    def loaded(self) -> bool:
        return self._loaded

    @property
    def interface_count(self) -> int:
        return len(self._interfaces)

    @property
    def module_count(self) -> int:
        return len(self._by_module)

    # -- Loading -----------------------------------------------------------

    def load(
        self,
        servers_path: Optional[str | Path] = None,
    ) -> None:
        """Load and index RPC data from the binary-keyed JSON file.

        Path defaults to the value in ``config/defaults.json`` under
        ``rpc.servers_path``.
        """
        if servers_path is None:
            servers_path = get_config_value("rpc.servers_path")

        if not servers_path:
            log_warning("RPC servers_path not configured in defaults.json", "NOT_FOUND")
            return

        srv_p = _resolve_asset_path(servers_path)
        data = _load_json_file(srv_p)
        if not isinstance(data, dict):
            return

        self._load_stubs()
        self._build_index(data)
        self._loaded = bool(self._interfaces)
        _log.info(
            "RPC index loaded: %d interfaces across %d modules, %d procedure lists",
            len(self._interfaces), len(self._by_module), len(self._procedures_by_module),
        )

    def _load_stubs(self) -> None:
        if not get_config_value("rpc.load_stubs", False):
            return
        stubs_path_cfg = get_config_value("rpc.client_stubs_path", "")
        if not stubs_path_cfg:
            return
        stubs_path = _resolve_asset_path(stubs_path_cfg)
        if not stubs_path.is_dir():
            return
        try:
            from .rpc_stub_parser import load_stubs_from_directory
            self._stubs = load_stubs_from_directory(stubs_path)
        except Exception as exc:
            log_warning(f"Failed to load RPC stubs: {exc}", "PARSE_ERROR")

    def _build_index(self, data: dict) -> None:
        for bin_key, bin_entry in data.items():
            if not isinstance(bin_entry, dict):
                continue

            binary_path = bin_entry.get("binary_path", "")
            binary_name = module_name_from_path(binary_path) if binary_path else ""
            file_info = bin_entry.get("file_info") or {}

            for iface_obj in bin_entry.get("interfaces", []):
                if not isinstance(iface_obj, dict):
                    continue

                iface = _parse_rpc_interface(iface_obj, binary_name, binary_path)
                if iface is None:
                    continue

                _apply_file_info(iface, file_info)

                self._interfaces.append(iface)

                mod_key = iface.binary_name.lower()
                self._by_module.setdefault(mod_key, []).append(iface)

                uuid_key = iface.interface_id.lower()
                self._by_uuid.setdefault(uuid_key, []).append(iface)

                if iface.service_name:
                    svc_key = iface.service_name.lower()
                    self._by_service.setdefault(svc_key, []).append(iface)

                for pn in iface.pipe_names:
                    self._by_pipe_name.setdefault(pn.lower(), []).append(iface)

                for alpc in iface.alpc_endpoints:
                    self._by_alpc.setdefault(alpc.lower(), []).append(iface)

            procedures = bin_entry.get("procedures", [])
            if isinstance(procedures, list) and procedures and binary_name:
                mod_key = binary_name.lower()
                self._procedures_by_module[mod_key] = set(procedures)

                ifaces = self._by_module.get(mod_key, [])
                if ifaces:
                    _distribute_procedures(ifaces, procedures)

    # -- Query API ---------------------------------------------------------

    def get_interfaces_for_module(self, module_name: str) -> list[RpcInterface]:
        """Return all RPC interfaces registered in *module_name*."""
        return list(self._by_module.get(module_name.lower(), []))

    def get_procedures_for_module(self, module_name: str) -> list[str]:
        """Return confirmed RPC procedure names for *module_name*."""
        procs = self._procedures_by_module.get(module_name.lower())
        if procs is not None:
            return sorted(procs)
        ifaces = self._by_module.get(module_name.lower(), [])
        combined: set[str] = set()
        for iface in ifaces:
            combined.update(iface.procedure_names)
        return sorted(combined)

    def is_rpc_procedure(self, module_name: str, func_name: str) -> bool:
        """Return True if *func_name* is a known RPC procedure in *module_name*."""
        procs = self._procedures_by_module.get(module_name.lower())
        if procs is not None:
            return func_name in procs
        ifaces = self._by_module.get(module_name.lower(), [])
        return any(func_name in iface.procedure_names for iface in ifaces)

    def get_interface_for_procedure(
        self, module_name: str, func_name: str,
    ) -> Optional[RpcInterface]:
        """Return the interface containing *func_name*, or None."""
        for iface in self._by_module.get(module_name.lower(), []):
            if func_name in iface.procedure_names:
                return iface
        return None

    def procedure_to_opnum(self, module_name: str, func_name: str) -> Optional[int]:
        """Return the opnum (0-based index) of *func_name* in its interface."""
        for iface in self._by_module.get(module_name.lower(), []):
            if func_name in iface.procedure_names:
                try:
                    return iface.procedure_names.index(func_name)
                except ValueError:
                    pass
        return None

    def find_modules_for_interface(self, interface_uuid: str) -> list[str]:
        """Return module names that register *interface_uuid*."""
        ifaces = self._by_uuid.get(interface_uuid.lower(), [])
        return sorted({iface.binary_name for iface in ifaces})

    def get_all_remote_interfaces(self) -> list[RpcInterface]:
        """Return all interfaces reachable via TCP/HTTP."""
        return [i for i in self._interfaces if i.is_remote_reachable]

    def get_all_named_pipe_interfaces(self) -> list[RpcInterface]:
        """Return all interfaces using named-pipe transport."""
        return [i for i in self._interfaces if i.is_named_pipe]

    def get_rpc_service_map(self) -> dict[str, list[RpcInterface]]:
        """Return service_name -> list of interfaces across all modules."""
        return {k: list(v) for k, v in self._by_service.items()}

    def get_interfaces_by_risk(self, tier: str) -> list[RpcInterface]:
        """Return interfaces matching a risk tier (critical/high/medium/low)."""
        return [i for i in self._interfaces if i.risk_tier == tier]

    def get_servers(self) -> list[RpcInterface]:
        """Return only server-side interfaces (Client == false)."""
        return [i for i in self._interfaces if not i.is_client]

    def get_clients(self) -> list[RpcInterface]:
        """Return only client-side interfaces (Client == true)."""
        return [i for i in self._interfaces if i.is_client]

    def get_interface_by_pipe_name(self, pipe_name: str) -> list[RpcInterface]:
        """Return interfaces reachable via a named pipe."""
        return list(self._by_pipe_name.get(pipe_name.lower(), []))

    def get_interface_by_alpc(self, alpc_name: str) -> list[RpcInterface]:
        """Return interfaces reachable via an ALPC endpoint."""
        return list(self._by_alpc.get(alpc_name.lower(), []))

    def compute_blast_radius(self, interface_uuid: str) -> dict[str, Any]:
        """Compute co-hosted interfaces that share a process with *interface_uuid*.

        Returns a dict with the target interface info, all sibling interfaces
        in the same service/binary, aggregate procedure count, combined
        protocol set, and risk escalation notes.
        """
        target_ifaces = self._by_uuid.get(interface_uuid.lower(), [])
        if not target_ifaces:
            return {"interface_uuid": interface_uuid, "found": False, "siblings": []}

        siblings: list[RpcInterface] = []
        seen_uuids: set[str] = {interface_uuid.lower()}

        for target in target_ifaces:
            if target.service_name:
                svc_key = target.service_name.lower()
                for sib in self._by_service.get(svc_key, []):
                    uid = sib.interface_id.lower()
                    if uid not in seen_uuids:
                        seen_uuids.add(uid)
                        siblings.append(sib)
            mod_key = target.binary_name.lower()
            for sib in self._by_module.get(mod_key, []):
                uid = sib.interface_id.lower()
                if uid not in seen_uuids:
                    seen_uuids.add(uid)
                    siblings.append(sib)

        all_protocols: set[str] = set()
        total_procedures = 0
        for iface in target_ifaces + siblings:
            all_protocols.update(iface.protocols)
            total_procedures += iface.procedure_count

        return {
            "interface_uuid": interface_uuid,
            "found": True,
            "target_interfaces": [i.to_dict() for i in target_ifaces],
            "siblings": [i.to_dict() for i in siblings],
            "sibling_count": len(siblings),
            "total_procedures": total_procedures,
            "combined_protocols": sorted(all_protocols),
            "is_remote_reachable": bool({"ncacn_ip_tcp", "ncacn_http"} & all_protocols),
        }

    def cross_reference_strings(self, strings: list[str]) -> list[dict[str, Any]]:
        """Match string literals against the RPC index.

        Finds UUID patterns and looks them up in ``_by_uuid``, finds pipe
        names and matches against ``_by_pipe_name``, and finds ALPC endpoint
        names and matches against ``_by_alpc``.

        Returns a list of match dicts with ``string``, ``match_type``,
        ``matched_value``, and ``interfaces``.
        """
        results: list[dict[str, Any]] = []
        for s in strings:
            if not isinstance(s, str) or not s.strip():
                continue
            for uuid_match in _UUID_RE.finditer(s):
                uuid_val = uuid_match.group(0).lower()
                ifaces = self._by_uuid.get(uuid_val, [])
                if ifaces:
                    results.append({
                        "string": s,
                        "match_type": "uuid",
                        "matched_value": uuid_val,
                        "interfaces": [
                            {"binary_name": i.binary_name, "interface_id": i.interface_id}
                            for i in ifaces
                        ],
                    })
            for pipe_match in _PIPE_NAME_RE.finditer(s):
                pname = pipe_match.group(1).lower()
                ifaces = self._by_pipe_name.get(pname, [])
                if ifaces:
                    results.append({
                        "string": s,
                        "match_type": "pipe_name",
                        "matched_value": pname,
                        "interfaces": [
                            {"binary_name": i.binary_name, "interface_id": i.interface_id}
                            for i in ifaces
                        ],
                    })
            s_lower = s.strip().lower()
            if s_lower in self._by_pipe_name:
                results.append({
                    "string": s,
                    "match_type": "pipe_name",
                    "matched_value": s_lower,
                    "interfaces": [
                        {"binary_name": i.binary_name, "interface_id": i.interface_id}
                        for i in self._by_pipe_name[s_lower]
                    ],
                })
            if s_lower in self._by_alpc:
                results.append({
                    "string": s,
                    "match_type": "alpc_endpoint",
                    "matched_value": s_lower,
                    "interfaces": [
                        {"binary_name": i.binary_name, "interface_id": i.interface_id}
                        for i in self._by_alpc[s_lower]
                    ],
                })
        return results

    # -- Stub queries ------------------------------------------------------

    @property
    def stubs_loaded(self) -> bool:
        return bool(self._stubs)

    def get_stub_for_interface(self, interface_uuid: str) -> Any:
        """Return the parsed ``RpcStubFile`` for *interface_uuid*, or None."""
        return self._stubs.get(interface_uuid.lower())

    def get_procedure_signatures(
        self, interface_uuid: str, proc_name: Optional[str] = None,
    ) -> list[Any]:
        """Return procedure signatures from the C# stub for *interface_uuid*.

        If *proc_name* is given, return only the matching procedure.
        Returns an empty list if stubs are not loaded or the UUID is unknown.
        """
        stub = self._stubs.get(interface_uuid.lower())
        if stub is None:
            return []
        if proc_name:
            proc = stub.get_procedure(proc_name)
            return [proc] if proc else []
        return list(stub.procedures)

    def get_high_risk_parameters(
        self, interface_uuid: str, threshold: float = 0.7,
    ) -> list[Any]:
        """Return procedures with input risk >= *threshold* from the stub."""
        stub = self._stubs.get(interface_uuid.lower())
        if stub is None:
            return []
        return stub.get_high_risk_procedures(threshold)

    def summary(self) -> dict[str, Any]:
        """Return a summary dict for diagnostics / context injection."""
        return {
            "total_interfaces": len(self._interfaces),
            "total_modules": len(self._by_module),
            "total_procedures": sum(len(v) for v in self._procedures_by_module.values()),
            "server_interfaces": sum(1 for i in self._interfaces if not i.is_client),
            "client_interfaces": sum(1 for i in self._interfaces if i.is_client),
            "remote_reachable": sum(1 for i in self._interfaces if i.is_remote_reachable),
            "named_pipe": sum(1 for i in self._interfaces if i.is_named_pipe),
            "local_only": sum(1 for i in self._interfaces if i.is_local_only),
            "with_services": sum(1 for i in self._interfaces if i.service_name),
            "with_complex_types": sum(1 for i in self._interfaces if i.has_complex_types),
            "unique_pipe_names": len(self._by_pipe_name),
            "unique_alpc_endpoints": len(self._by_alpc),
            "stubs_loaded": len(self._stubs),
        }


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _resolve_asset_path(path_str: str | Path) -> Path:
    """Resolve a config-relative or absolute path to the RPC data file."""
    p = Path(path_str)
    if p.is_absolute() and p.exists():
        return p
    candidate = _WORKSPACE_ROOT / p
    if candidate.exists():
        return candidate
    return p


def _parse_version(ver: Any) -> str:
    """Normalize InterfaceVersion from object or string form."""
    if isinstance(ver, str):
        return ver
    if isinstance(ver, dict):
        major = ver.get("Major", 0)
        minor = ver.get("Minor", 0)
        return f"{major}.{minor}"
    return "0.0"


def _parse_endpoints(raw: Any) -> tuple[list[str], set[str], list[str], list[str], list[int]]:
    """Parse endpoints into endpoint list, protocol set, pipe names, ALPC names, TCP ports."""
    endpoints: list[str] = []
    protocols: set[str] = set()
    pipe_names: list[str] = []
    alpc_endpoints: list[str] = []
    tcp_ports: list[int] = []

    if isinstance(raw, str):
        if raw.strip():
            endpoints = [raw.strip()]
    elif isinstance(raw, list):
        endpoints = [e.strip() for e in raw if isinstance(e, str) and e.strip()]

    seen_pipes: set[str] = set()
    seen_alpc: set[str] = set()
    seen_ports: set[int] = set()

    for ep in endpoints:
        for match in _PROTOCOL_RE.finditer(ep):
            protocols.add(match.group(1))

        for match in _PIPE_NAME_RE.finditer(ep):
            pname = match.group(1)
            if pname.lower() not in seen_pipes:
                seen_pipes.add(pname.lower())
                pipe_names.append(pname)

        for match in _ALPC_NAME_RE.finditer(ep):
            aname = match.group(1)
            if aname.startswith("LRPC-") or aname.startswith("OLE"):
                continue
            if aname.lower() not in seen_alpc:
                seen_alpc.add(aname.lower())
                alpc_endpoints.append(aname)

        for match in _TCP_PORT_RE.finditer(ep):
            port = int(match.group(1))
            if port not in seen_ports:
                seen_ports.add(port)
                tcp_ports.append(port)

    return endpoints, protocols, pipe_names, alpc_endpoints, tcp_ports


def _parse_complex_types(raw: Any) -> list[str]:
    """Parse ComplexTypes field (string or list) into a list of type names."""
    if isinstance(raw, list):
        return [str(t) for t in raw if t]
    if isinstance(raw, str) and raw.strip():
        return [t.strip() for t in raw.split(" - ") if t.strip() and t.strip() != "-"]
    return []


def _apply_file_info(iface: RpcInterface, file_info: dict) -> None:
    """Populate file info fields on *iface* from the binary-level file_info dict."""
    if not file_info:
        return
    iface.file_description = file_info.get("file_description", "") or ""
    iface.file_version = file_info.get("file_version", "") or ""
    iface.company_name = file_info.get("company_name", "") or ""
    iface.product_version = file_info.get("product_version", "") or ""


def _parse_rpc_interface(
    iface_obj: dict, binary_name: str, binary_full: str,
) -> Optional[RpcInterface]:
    """Parse a single RPC interface dict from the binary-keyed JSON."""
    iface_id = iface_obj.get("interface_id")
    if not iface_id:
        return None

    endpoints, protocols, pipe_names, alpc_endpoints, tcp_ports = _parse_endpoints(
        iface_obj.get("endpoints"),
    )
    complex_types = _parse_complex_types(iface_obj.get("complex_types"))

    svc_name = iface_obj.get("service_name")
    if svc_name and not isinstance(svc_name, str):
        svc_name = None

    svc_display = iface_obj.get("service_display_name")
    if svc_display and not isinstance(svc_display, str):
        svc_display = None

    return RpcInterface(
        interface_id=iface_id,
        interface_version=iface_obj.get("interface_version", "0.0"),
        binary_path=binary_full,
        binary_name=binary_name,
        procedure_count=int(iface_obj.get("procedure_count", 0)),
        endpoints=endpoints,
        protocols=protocols,
        service_name=svc_name,
        service_display_name=svc_display,
        is_service_running=bool(iface_obj.get("is_service_running", False)),
        is_client=bool(iface_obj.get("is_client", False)),
        complex_types=complex_types,
        transfer_syntax_id=iface_obj.get("transfer_syntax_id", ""),
        offset=int(iface_obj.get("offset", 0)),
        pipe_names=pipe_names,
        alpc_endpoints=alpc_endpoints,
        tcp_ports=tcp_ports,
    )


def _distribute_procedures(
    ifaces: list[RpcInterface], func_names: list[str],
) -> None:
    """Distribute procedure names across interfaces by procedure count.

    The procedures-by-binary file gives a flat list of function names.
    Interfaces are ordered by offset within the binary; their
    ``procedure_count`` tells how many procedures each owns.  We assign
    names in order, falling back to giving all names to the first
    interface if counts don't line up.
    """
    total_expected = sum(i.procedure_count for i in ifaces if not i.is_client)
    servers = [i for i in ifaces if not i.is_client]

    if not servers:
        return

    if total_expected == len(func_names):
        idx = 0
        for iface in sorted(servers, key=lambda i: i.offset):
            iface.procedure_names = func_names[idx:idx + iface.procedure_count]
            idx += iface.procedure_count
    elif len(servers) == 1:
        servers[0].procedure_names = list(func_names)
    else:
        for iface in servers:
            iface.procedure_names = list(func_names)


# ---------------------------------------------------------------------------
# File loaders
# ---------------------------------------------------------------------------

def _load_json_file(path: Path) -> Any:
    if not path.exists():
        log_warning(f"RPC data file not found: {path}", "NOT_FOUND")
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        log_warning(f"Failed to parse RPC data {path}: {exc}", "PARSE_ERROR")
        return None




# ---------------------------------------------------------------------------
# Singleton access
# ---------------------------------------------------------------------------

_global_index: Optional[RpcIndex] = None


def get_rpc_index(*, force_reload: bool = False) -> RpcIndex:
    """Return the global RPC index, loading on first call.

    Returns an empty (but usable) index if RPC data is not available
    or ``rpc.enabled`` is false in the config.
    """
    global _global_index

    if _global_index is not None and not force_reload:
        return _global_index

    idx = RpcIndex()
    enabled = get_config_value("rpc.enabled", True)
    if enabled:
        try:
            idx.load()
        except Exception as exc:
            log_warning(
                f"Failed to load RPC index: {exc}. Check that rpc.servers_path "
                f"in config/defaults.json points to a valid JSON file.",
                "PARSE_ERROR",
            )

    _global_index = idx
    return idx


def invalidate_rpc_index() -> None:
    """Clear the cached RPC index so the next call reloads from disk."""
    global _global_index
    _global_index = None
