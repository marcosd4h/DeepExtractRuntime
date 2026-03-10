"""System-wide COM server index built from extraction data.

Loads COM server details and procedures-by-binary JSON files from
``config/assets/com_data/`` across four access contexts (caller
integrity level x server privilege) and exposes a queryable index
with privilege-boundary risk scoring.

Access contexts::

    extracted_high_il/all_servers                   -- high-IL caller, elevated + regular processes
    extracted_high_il/privileged_servers             -- high-IL caller, privileged processes (SYSTEM/high)
    extracted_medium_il/medium_il/all_servers        -- medium-IL caller, elevated + regular processes
    extracted_medium_il/medium_il/privileged_servers -- medium-IL caller, privileged processes (SYSTEM/high)

Typical usage::

    from helpers.com_index import get_com_index

    idx = get_com_index()
    servers = idx.get_servers_for_module("wuapi.dll")
    procs   = idx.get_procedures_for_module("wbengine.exe")
    is_com  = idx.is_com_procedure("wuapi.dll", "AcceptEula")
"""

from __future__ import annotations

import enum
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

_GUID_RE = re.compile(r'\[Guid\("([0-9a-fA-F-]+)"\)\]')
_PERMISSIVE_SDDL_SIDS = {"WD", "AC", "AU", "IU", "S-1-1-0", "S-1-15-2-1"}
_ALLOW_ACE_RE = re.compile(r"\(A[^)]*;;;(" + "|".join(
    re.escape(s) for s in _PERMISSIVE_SDDL_SIDS
) + r")\)", re.IGNORECASE)

_SYSTEM_USERNAMES = {"localsystem", "nt authority\\system", "system"}


# ---------------------------------------------------------------------------
# Access context enum
# ---------------------------------------------------------------------------

class ComAccessContext(enum.Enum):
    """Caller IL x server privilege access context."""

    HIGH_IL_ALL = "extracted_high_il/all_servers"
    HIGH_IL_PRIVILEGED = "extracted_high_il/privileged_servers"
    MEDIUM_IL_ALL = "extracted_medium_il/medium_il/all_servers"
    MEDIUM_IL_PRIVILEGED = "extracted_medium_il/medium_il/privileged_servers"

    @property
    def caller_il(self) -> str:
        return "medium" if "medium_il" in self.value else "high"

    @property
    def is_privileged_server(self) -> bool:
        return "privileged_servers" in self.value

    def __str__(self) -> str:
        return self.name.lower()


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ComMethod:
    """A single method entry from a COM server's Interfaces dict."""

    access: str
    type: str
    name: str
    file: str
    interface_name: str = ""

    @property
    def short_name(self) -> str:
        parts = self.name.rsplit("::", 1)
        return parts[-1] if parts else self.name

    @property
    def class_name(self) -> str:
        parts = self.name.rsplit("::", 2)
        if len(parts) >= 2:
            return parts[-2]
        return ""

    @property
    def binary_name(self) -> str:
        return Path(self.file).name if self.file else ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "access": self.access,
            "type": self.type,
            "name": self.name,
            "short_name": self.short_name,
            "file": self.file,
            "binary_name": self.binary_name,
            "interface_name": self.interface_name,
        }


@dataclass
class ComInterface:
    """A COM interface with its methods and optional pseudo-IDL."""

    name: str
    guid: str = ""
    methods: list[ComMethod] = field(default_factory=list)
    pseudo_idl: list[str] = field(default_factory=list)

    @property
    def method_count(self) -> int:
        return len(self.methods)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "guid": self.guid,
            "method_count": self.method_count,
            "methods": [m.to_dict() for m in self.methods],
            "pseudo_idl": self.pseudo_idl,
        }


@dataclass
class ComServer:
    """Metadata for a COM server (CLSID registration)."""

    clsid: str
    name: str
    full_path: str = ""
    server_type: str = ""
    can_elevate: bool = False
    auto_elevation: bool = False
    elevation: Any = None
    has_launch_permission: bool = False
    has_run_as: bool = False
    access_permission: str = ""
    launch_permission: str = ""
    run_as: str = ""
    create_context: int = 0
    supports_remote_activation: bool = False
    trusted_marshaller: bool = False
    trusted_marshaller_category: bool = False
    type_lib: bool = False

    # AppID / service info
    app_id: str = ""
    service_name: str = ""
    service_user: str = ""
    service_dll: str = ""
    service_protection_level: int = 0
    is_service: bool = False
    has_dll_surrogate: bool = False
    app_id_launch_permission: str = ""
    app_id_access_permission: str = ""
    has_low_il_access: bool = False
    has_low_il_launch: bool = False

    interfaces: list[ComInterface] = field(default_factory=list)
    methods_flat: list[ComMethod] = field(default_factory=list)
    typelib_interfaces: dict[str, list[str]] = field(default_factory=dict)

    access_contexts: set[ComAccessContext] = field(default_factory=set)

    hosting_binary: str = ""

    # -- Computed security properties --

    @property
    def is_out_of_process(self) -> bool:
        return (self.server_type.lower() in ("localserver32", "localserver")
                or self.has_dll_surrogate)

    @property
    def is_in_process(self) -> bool:
        return (self.server_type.lower() in ("inprocserver32", "inprocserver")
                and not self.has_dll_surrogate)

    @property
    def runs_as_system(self) -> bool:
        if self.run_as and self.run_as.lower() in _SYSTEM_USERNAMES:
            return True
        if self.service_user and self.service_user.lower() in _SYSTEM_USERNAMES:
            return True
        return False

    @property
    def has_permissive_launch(self) -> bool:
        sddl = self.launch_permission or self.app_id_launch_permission or ""
        return _is_permissive_sddl(sddl)

    @property
    def has_permissive_access(self) -> bool:
        sddl = self.access_permission or self.app_id_access_permission or ""
        return _is_permissive_sddl(sddl)

    @property
    def is_remote_activatable(self) -> bool:
        return self.supports_remote_activation

    @property
    def is_trusted_marshaller(self) -> bool:
        return self.trusted_marshaller

    @property
    def interface_count(self) -> int:
        return len(self.interfaces)

    @property
    def method_count(self) -> int:
        return len(self.methods_flat)

    def risk_tier(self, context: Optional[ComAccessContext] = None) -> str:
        """Compute risk tier based on server properties and access context.

        The risk model centers on privilege-boundary crossing:
        a medium-IL caller reaching a SYSTEM server is the highest risk.
        """
        is_medium_il = False
        is_privileged = False

        if context is not None:
            is_medium_il = context.caller_il == "medium"
            is_privileged = context.is_privileged_server
        else:
            for ctx in self.access_contexts:
                if ctx.caller_il == "medium":
                    is_medium_il = True
                if ctx.is_privileged_server:
                    is_privileged = True

        if is_medium_il and is_privileged and self.is_out_of_process and self.runs_as_system:
            return "critical"
        if is_medium_il and self.is_out_of_process and (self.has_permissive_launch or self.can_elevate):
            return "high"
        if is_privileged and self.is_out_of_process and self.runs_as_system:
            return "medium"
        if self.can_elevate or self.auto_elevation:
            return "medium"
        return "low"

    @property
    def best_risk_tier(self) -> str:
        tier_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        best = "low"
        if not self.access_contexts:
            return self.risk_tier(None)
        for ctx in self.access_contexts:
            t = self.risk_tier(ctx)
            if tier_order.get(t, 99) < tier_order.get(best, 99):
                best = t
        return best

    def to_dict(self) -> dict[str, Any]:
        return {
            "clsid": self.clsid,
            "name": self.name,
            "full_path": self.full_path,
            "server_type": self.server_type,
            "can_elevate": self.can_elevate,
            "auto_elevation": self.auto_elevation,
            "has_launch_permission": self.has_launch_permission,
            "has_run_as": self.has_run_as,
            "run_as": self.run_as,
            "supports_remote_activation": self.supports_remote_activation,
            "trusted_marshaller": self.trusted_marshaller,
            "service_name": self.service_name,
            "service_user": self.service_user,
            "service_protection_level": self.service_protection_level,
            "is_service": self.is_service,
            "hosting_binary": self.hosting_binary,
            "is_out_of_process": self.is_out_of_process,
            "runs_as_system": self.runs_as_system,
            "has_permissive_launch": self.has_permissive_launch,
            "has_permissive_access": self.has_permissive_access,
            "is_remote_activatable": self.is_remote_activatable,
            "is_trusted_marshaller": self.is_trusted_marshaller,
            "risk_tier": self.best_risk_tier,
            "interface_count": self.interface_count,
            "method_count": self.method_count,
            "access_contexts": sorted(str(c) for c in self.access_contexts),
            "interfaces": [i.to_dict() for i in self.interfaces],
        }


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _parse_guid_from_pseudo_idl(lines: list[str]) -> str:
    """Extract the interface GUID from PseudoInterfaces IDL lines."""
    for line in lines:
        m = _GUID_RE.search(line)
        if m:
            return m.group(1)
    return ""


def _is_permissive_sddl(sddl: str) -> bool:
    """Check if an SDDL string grants wide access via an Allow ACE."""
    if not sddl:
        return False
    return bool(_ALLOW_ACE_RE.search(sddl))


def _parse_server_detail(clsid: str, raw: dict, hosting_binary: str = "") -> ComServer:
    """Parse a single COM server detail dict into a ComServer.

    Accepts the binary-keyed schema (snake_case field names).
    """
    interfaces: list[ComInterface] = []
    methods_flat: list[ComMethod] = []

    raw_interfaces = raw.get("interfaces") or []
    if not isinstance(raw_interfaces, list):
        raw_interfaces = []

    for iface_obj in raw_interfaces:
        if not isinstance(iface_obj, dict):
            continue
        iface_name = iface_obj.get("iface_name", "")
        methods: list[ComMethod] = []
        for m in iface_obj.get("methods", []):
            if not isinstance(m, dict):
                continue
            cm = ComMethod(
                access=m.get("access_type", ""),
                type=m.get("dispatch_type", ""),
                name=m.get("method_name", ""),
                file=m.get("binary_path", ""),
                interface_name=iface_name,
            )
            methods.append(cm)
            methods_flat.append(cm)

        pseudo_lines = iface_obj.get("pseudo_idl", [])
        if not isinstance(pseudo_lines, list):
            pseudo_lines = []
        guid = _parse_guid_from_pseudo_idl(pseudo_lines)

        interfaces.append(ComInterface(
            name=iface_name,
            guid=guid,
            methods=methods,
            pseudo_idl=pseudo_lines,
        ))

    hosting = hosting_binary
    if not hosting and methods_flat:
        hosting = methods_flat[0].binary_name

    app_id_raw = raw.get("app_id") or {}
    if not isinstance(app_id_raw, dict):
        app_id_raw = {}
    local_svc = app_id_raw.get("local_service") or {}
    if not isinstance(local_svc, dict):
        local_svc = {}

    typelib_ifaces = raw.get("typelib_interfaces") or {}
    if not isinstance(typelib_ifaces, dict):
        typelib_ifaces = {}

    return ComServer(
        clsid=clsid,
        name=raw.get("display_name", ""),
        full_path=hosting_binary,
        server_type=raw.get("registration_type", ""),
        can_elevate=bool(raw.get("can_elevate", False)),
        auto_elevation=bool(raw.get("auto_elevate", False)),
        elevation=raw.get("elevation_policy"),
        has_launch_permission=bool(raw.get("has_launch_permission", False)),
        has_run_as=bool(raw.get("has_run_as_identity", False)),
        access_permission=raw.get("access_permission_sddl", ""),
        launch_permission=raw.get("launch_permission_sddl", ""),
        run_as=raw.get("run_as_identity") or app_id_raw.get("run_as_identity", ""),
        create_context=int(raw.get("clsctx_flags") or 0),
        supports_remote_activation=bool(raw.get("supports_remote_activation", False)),
        trusted_marshaller=bool(raw.get("is_trusted_marshaller", False)),
        trusted_marshaller_category=bool(raw.get("in_trusted_marshaller_category", False)),
        type_lib=bool(raw.get("has_typelib", False)),
        app_id=app_id_raw.get("app_id_guid", ""),
        service_name=app_id_raw.get("service_name", "") or local_svc.get("service_name", ""),
        service_user=local_svc.get("account", ""),
        service_dll=local_svc.get("service_dll", ""),
        service_protection_level=int(local_svc.get("protection_level") or 0),
        is_service=bool(app_id_raw.get("is_service", False)),
        has_dll_surrogate=bool(app_id_raw.get("has_dll_surrogate", False)),
        app_id_launch_permission=app_id_raw.get("launch_permission_sddl", ""),
        app_id_access_permission=app_id_raw.get("access_permission_sddl", ""),
        has_low_il_access=bool(app_id_raw.get("allows_low_il_access", False)),
        has_low_il_launch=bool(app_id_raw.get("allows_low_il_launch", False)),
        interfaces=interfaces,
        methods_flat=methods_flat,
        typelib_interfaces=typelib_ifaces,
        hosting_binary=hosting,
    )


# ---------------------------------------------------------------------------
# Index
# ---------------------------------------------------------------------------

_HEX_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]+$")


class ComIndex:
    """Queryable index over COM server registrations and procedures."""

    def __init__(self) -> None:
        self._servers: list[ComServer] = []
        self._by_clsid: dict[str, ComServer] = {}
        self._by_module: dict[str, list[ComServer]] = {}
        self._by_service: dict[str, list[ComServer]] = {}
        self._by_interface_guid: dict[str, list[ComServer]] = {}
        self._procedures_by_module: dict[str, set[str]] = {}
        self._loaded = False

    @property
    def loaded(self) -> bool:
        return self._loaded

    @property
    def server_count(self) -> int:
        return len(self._servers)

    @property
    def module_count(self) -> int:
        return len(self._by_module)

    @property
    def total_methods(self) -> int:
        return sum(s.method_count for s in self._servers)

    # -- Loading -----------------------------------------------------------

    def load(
        self,
        data_root: Optional[str | Path] = None,
        contexts: Optional[list] = None,
    ) -> None:
        """Load COM data from access contexts.

        Args:
            data_root: Path to COM data directory.
            contexts: Optional list of ``ComAccessContext`` values to load.
                      If *None*, all contexts are loaded.
        """
        import sys

        if data_root is None:
            data_root = get_config_value("com.data_root", "config/assets/com_data")

        root = _resolve_path(data_root)
        if not root.is_dir():
            log_warning(f"COM data root not found: {root}", "NOT_FOUND")
            return

        for ctx in ComAccessContext:
            if contexts and ctx not in contexts:
                continue
            ctx_dir = root / ctx.value
            if not ctx_dir.is_dir():
                _log.debug("COM context directory not found: %s", ctx_dir)
                continue
            _log.debug("Loading COM data (%s)...", ctx.value)
            self._load_context(ctx_dir, ctx)

        self._loaded = bool(self._servers)
        _log.info(
            "COM index loaded: %d servers across %d modules, %d total methods",
            len(self._servers), len(self._by_module), self.total_methods,
        )

    def _load_context(self, ctx_dir: Path, context: ComAccessContext) -> None:
        servers_path = ctx_dir / "com_servers.json"

        if servers_path.exists():
            self._load_binary_entries(servers_path, context)

    def _load_binary_entries(
        self, path: Path, context: ComAccessContext,
    ) -> None:
        data = _load_json_file(path)
        if not isinstance(data, dict):
            return

        for bin_key, bin_entry in data.items():
            if not isinstance(bin_entry, dict):
                continue

            binary_path = bin_entry.get("binary_path", "")
            hosting = module_name_from_path(binary_path) if binary_path else ""

            for entry in bin_entry.get("servers", []):
                if not isinstance(entry, dict):
                    continue

                clsid = entry.get("clsid", "")
                clsid_key = clsid.lower()

                existing = self._by_clsid.get(clsid_key)
                if existing is not None:
                    existing.access_contexts.add(context)
                    continue

                server = _parse_server_detail(clsid, entry, hosting)
                server.access_contexts.add(context)
                self._servers.append(server)
                self._by_clsid[clsid_key] = server

                if server.hosting_binary:
                    mod_key = server.hosting_binary.lower()
                    self._by_module.setdefault(mod_key, []).append(server)

                if server.service_name:
                    svc_key = server.service_name.lower()
                    self._by_service.setdefault(svc_key, []).append(server)

                for iface in server.interfaces:
                    if iface.guid:
                        guid_key = iface.guid.lower()
                        self._by_interface_guid.setdefault(guid_key, []).append(server)
                    for method in iface.methods:
                        if method.file:
                            m_key = module_name_from_path(method.file).lower()
                            if m_key != (server.hosting_binary or "").lower():
                                if server not in self._by_module.get(m_key, []):
                                    self._by_module.setdefault(m_key, []).append(server)

            procedures = bin_entry.get("procedures", [])
            if isinstance(procedures, list) and procedures:
                mod_name = module_name_from_path(binary_path) if binary_path else ""
                if mod_name:
                    mod_key = mod_name.lower()
                    filtered = [n for n in procedures if not _HEX_ADDR_RE.match(n)]
                    existing_procs = self._procedures_by_module.get(mod_key)
                    if existing_procs is not None:
                        existing_procs.update(filtered)
                    else:
                        self._procedures_by_module[mod_key] = set(filtered)

    # -- Query API ---------------------------------------------------------

    def get_servers_for_module(self, module_name: str) -> list[ComServer]:
        """Return all COM servers hosted in *module_name*."""
        return list(self._by_module.get(module_name.lower(), []))

    def get_server_by_clsid(self, clsid: str) -> Optional[ComServer]:
        """Return the COM server for *clsid*, or None."""
        return self._by_clsid.get(clsid.lower())

    def get_procedures_for_module(self, module_name: str) -> list[str]:
        """Return COM procedure names for *module_name*."""
        procs = self._procedures_by_module.get(module_name.lower())
        if procs is not None:
            return sorted(procs)
        servers = self._by_module.get(module_name.lower(), [])
        combined: set[str] = set()
        for srv in servers:
            for m in srv.methods_flat:
                combined.add(m.name)
        return sorted(combined)

    def is_com_procedure(self, module_name: str, func_name: str) -> bool:
        """Return True if *func_name* is a known COM procedure in *module_name*."""
        procs = self._procedures_by_module.get(module_name.lower())
        if procs is not None:
            return func_name in procs
        servers = self._by_module.get(module_name.lower(), [])
        return any(
            func_name == m.name or func_name == m.short_name
            for srv in servers for m in srv.methods_flat
        )

    def get_interfaces_for_module(self, module_name: str) -> list[ComInterface]:
        """Return all COM interfaces hosted in *module_name*."""
        result: list[ComInterface] = []
        for srv in self._by_module.get(module_name.lower(), []):
            result.extend(srv.interfaces)
        return result

    def get_methods_for_clsid(self, clsid: str) -> list[ComMethod]:
        """Return all methods across all interfaces for *clsid*."""
        srv = self.get_server_by_clsid(clsid)
        if srv is None:
            return []
        return list(srv.methods_flat)

    def search_methods(self, pattern: str) -> list[ComMethod]:
        """Search method names across all servers using a regex pattern."""
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error:
            return []
        results: list[ComMethod] = []
        for srv in self._servers:
            for m in srv.methods_flat:
                if regex.search(m.name):
                    results.append(m)
        return results

    def get_access_contexts_for_clsid(
        self, clsid: str,
    ) -> set[ComAccessContext]:
        """Return which access contexts expose *clsid*."""
        srv = self.get_server_by_clsid(clsid)
        if srv is None:
            return set()
        return set(srv.access_contexts)

    def get_privileged_surface(
        self, caller_il: str = "medium",
    ) -> list[ComServer]:
        """Return servers on privileged processes reachable from *caller_il*."""
        results: list[ComServer] = []
        for srv in self._servers:
            for ctx in srv.access_contexts:
                if ctx.caller_il == caller_il and ctx.is_privileged_server:
                    results.append(srv)
                    break
        return results

    def get_servers_by_risk(self, tier: str) -> list[ComServer]:
        """Return servers matching a risk tier."""
        return [s for s in self._servers if s.best_risk_tier == tier]

    def get_elevatable_servers(self) -> list[ComServer]:
        """Return servers with CanElevate or AutoElevation set."""
        return [s for s in self._servers if s.can_elevate or s.auto_elevation]

    def get_servers_by_service(self, service_name: str) -> list[ComServer]:
        """Return all COM servers hosted in *service_name*."""
        return list(self._by_service.get(service_name.lower(), []))

    def find_servers_for_interface(self, iid: str) -> list[ComServer]:
        """Return all COM servers exposing interface with GUID *iid*."""
        return list(self._by_interface_guid.get(iid.lower(), []))

    def get_all_services(self) -> list[str]:
        """Return all service names that host COM servers."""
        return sorted(self._by_service.keys())

    def get_all_clsids(self) -> list[str]:
        """Return all registered CLSIDs."""
        return sorted(self._by_clsid.keys())

    def get_all_modules(self) -> list[str]:
        """Return all module names that host COM servers."""
        return sorted(self._by_module.keys())

    def summary(self) -> dict[str, Any]:
        """Return a summary dict for diagnostics / context injection."""
        tier_counts: dict[str, int] = {}
        for srv in self._servers:
            t = srv.best_risk_tier
            tier_counts[t] = tier_counts.get(t, 0) + 1

        return {
            "total_servers": len(self._servers),
            "total_modules": len(self._by_module),
            "total_clsids": len(self._by_clsid),
            "total_methods": self.total_methods,
            "total_procedures": sum(len(v) for v in self._procedures_by_module.values()),
            "by_tier": tier_counts,
            "by_server_type": {
                "in_process": sum(1 for s in self._servers if s.is_in_process),
                "out_of_process": sum(1 for s in self._servers if s.is_out_of_process),
            },
            "runs_as_system": sum(1 for s in self._servers if s.runs_as_system),
            "can_elevate": sum(1 for s in self._servers if s.can_elevate),
            "auto_elevation": sum(1 for s in self._servers if s.auto_elevation),
            "trusted_marshaller": sum(1 for s in self._servers if s.trusted_marshaller),
            "is_service": sum(1 for s in self._servers if s.is_service),
            "with_permissive_launch": sum(1 for s in self._servers if s.has_permissive_launch),
            "with_permissive_access": sum(1 for s in self._servers if s.has_permissive_access),
        }


# ---------------------------------------------------------------------------
# File loaders
# ---------------------------------------------------------------------------

def _resolve_path(path_str: str | Path) -> Path:
    """Resolve a config-relative or absolute path."""
    p = Path(path_str)
    if p.is_absolute() and p.exists():
        return p
    candidate = _WORKSPACE_ROOT / p
    if candidate.exists():
        return candidate
    return p


def _load_json_file(path: Path) -> Any:
    if not path.exists():
        log_warning(f"COM data file not found: {path}", "NOT_FOUND")
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        log_warning(f"Failed to parse COM data {path}: {exc}", "PARSE_ERROR")
        return None


# ---------------------------------------------------------------------------
# Singleton access
# ---------------------------------------------------------------------------

_global_index: Optional[ComIndex] = None


def get_com_index(*, force_reload: bool = False) -> ComIndex:
    """Return the global COM index, loading on first call.

    Returns an empty (but usable) index if COM data is not available
    or ``com.enabled`` is false in the config.
    """
    global _global_index

    if _global_index is not None and not force_reload:
        return _global_index

    idx = ComIndex()
    enabled = get_config_value("com.enabled", True)
    if enabled:
        try:
            idx.load()
        except Exception as exc:
            log_warning(
                f"Failed to load COM index: {exc}. Check that com.data_root "
                f"in config/defaults.json points to a valid directory.",
                "PARSE_ERROR",
            )

    _global_index = idx
    return idx


def invalidate_com_index() -> None:
    """Clear the cached COM index so the next call reloads from disk."""
    global _global_index
    _global_index = None
