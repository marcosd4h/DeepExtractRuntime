"""System-wide WinRT server index built from extraction data.

Loads WinRT server details and procedures-by-binary JSON files from
``config/assets/winrt_data/`` across four access contexts (caller
integrity level x server privilege) and exposes a queryable index
with privilege-boundary risk scoring.

Access contexts::

    extracted_high_il/all_servers                   -- high-IL caller, elevated + regular processes
    extracted_high_il/privileged_servers             -- high-IL caller, privileged processes (SYSTEM/high)
    extracted_medium_il/medium_il/all_servers        -- medium-IL caller, elevated + regular processes
    extracted_medium_il/medium_il/privileged_servers -- medium-IL caller, privileged processes (SYSTEM/high)

Typical usage::

    from helpers.winrt_index import get_winrt_index

    idx = get_winrt_index()
    servers = idx.get_servers_for_module("TaskFlowDataEngine.dll")
    procs   = idx.get_procedures_for_module("TaskFlowDataEngine.dll")
    is_wrt  = idx.is_winrt_procedure("TaskFlowDataEngine.dll", "GetAppName")
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
from .sddl_parser import is_permissive_sddl as _sddl_is_permissive

_log = logging.getLogger(__name__)

_WORKSPACE_ROOT = Path(__file__).resolve().parents[1]

_GUID_RE = re.compile(r'\[Guid\("([0-9a-fA-F-]+)"\)\]')
_STATEREPO_DLL = "windows.staterepository.dll"

_GENERIC_HOST_PROCESSES = frozenset({
    "svchost.exe", "dllhost.exe", "rundll32.exe",
    "taskhostw.exe", "sihost.exe",
})


# ---------------------------------------------------------------------------
# Access context enum
# ---------------------------------------------------------------------------

class WinrtAccessContext(enum.Enum):
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
class WinrtMethod:
    """A single method entry from a WinRT server's Methods dict."""

    access: str
    type: str
    name: str
    file: str

    @property
    def short_name(self) -> str:
        """Extract the method name after the last ``::``."""
        parts = self.name.rsplit("::", 1)
        return parts[-1] if parts else self.name

    @property
    def class_name(self) -> str:
        """Extract the class name (second-to-last ``::`` segment)."""
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
        }


@dataclass
class WinrtInterface:
    """A WinRT interface with its GUID, methods, and pseudo-IDL."""

    name: str
    guid: str = ""
    methods: list[WinrtMethod] = field(default_factory=list)
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
class WinrtServer:
    """Metadata for a WinRT activation server (class registration)."""

    name: str
    server: str = ""
    activation_type: str = ""
    trust_level: str = ""
    server_permissions: str = ""
    server_identity: str = ""
    server_name: str = ""
    server_exe_path: str = ""
    server_exe_name: str = ""
    service_name: str = ""
    default_access_permission: str = ""
    default_launch_permission: str = ""
    supports_remote_activation: str = "False"
    source: str = ""
    activate_in_shared_broker: str = "False"
    has_server: str = "False"
    package_id: str = ""

    interfaces: list[WinrtInterface] = field(default_factory=list)
    methods_flat: list[WinrtMethod] = field(default_factory=list)

    access_contexts: set[WinrtAccessContext] = field(default_factory=set)

    # Populated during indexing: which binary hosts this class
    hosting_binary: str = ""

    @property
    def is_out_of_process(self) -> bool:
        return self.activation_type.lower() == "outofprocess"

    @property
    def is_in_process(self) -> bool:
        return self.activation_type.lower() == "inprocess"

    @property
    def runs_as_system(self) -> bool:
        return "system" in self.server_identity.lower() if self.server_identity else False

    @property
    def has_permissive_sddl(self) -> bool:
        sddl = self.server_permissions or self.default_access_permission or ""
        return _is_permissive_sddl(sddl)

    @property
    def is_remote_activatable(self) -> bool:
        return self.supports_remote_activation.lower() == "true"

    @property
    def is_base_trust(self) -> bool:
        return self.trust_level.lower() == "basetrust"

    @property
    def interface_count(self) -> int:
        return len(self.interfaces)

    @property
    def method_count(self) -> int:
        return len(self.methods_flat)

    def risk_tier(self, context: Optional[WinrtAccessContext] = None) -> str:
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
        if is_medium_il and self.is_out_of_process and self.has_permissive_sddl:
            return "high"
        if is_privileged and self.is_out_of_process and self.runs_as_system:
            return "medium"
        if self.is_in_process and self.is_base_trust:
            return "medium"
        return "low"

    @property
    def best_risk_tier(self) -> str:
        """Return the highest risk tier across all access contexts."""
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
            "name": self.name,
            "server": self.server,
            "activation_type": self.activation_type,
            "trust_level": self.trust_level,
            "server_identity": self.server_identity,
            "server_name": self.server_name,
            "server_permissions": self.server_permissions,
            "service_name": self.service_name,
            "supports_remote_activation": self.supports_remote_activation,
            "hosting_binary": self.hosting_binary,
            "is_out_of_process": self.is_out_of_process,
            "runs_as_system": self.runs_as_system,
            "has_permissive_sddl": self.has_permissive_sddl,
            "is_remote_activatable": self.is_remote_activatable,
            "is_base_trust": self.is_base_trust,
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
    """Check if an SDDL string grants wide access (Deny-aware).

    Delegates to ``sddl_parser.is_permissive_sddl`` which evaluates
    Deny ACEs before Allow ACEs, so a Deny for WD/AC correctly
    overrides a subsequent Allow.
    """
    return _sddl_is_permissive(sddl)


def _parse_server_detail(raw: dict, hosting_binary: str = "") -> WinrtServer:
    """Parse a single server detail dict into a WinrtServer.

    Accepts the binary-keyed schema (snake_case field names).
    """
    interfaces: list[WinrtInterface] = []
    methods_flat: list[WinrtMethod] = []

    raw_interfaces = raw.get("interfaces") or []
    if not isinstance(raw_interfaces, list):
        raw_interfaces = []

    for iface_obj in raw_interfaces:
        if not isinstance(iface_obj, dict):
            continue
        iface_name = iface_obj.get("iface_name", "")
        methods: list[WinrtMethod] = []
        for m in iface_obj.get("methods", []):
            if not isinstance(m, dict):
                continue
            wm = WinrtMethod(
                access=m.get("access_type", ""),
                type=m.get("dispatch_type", ""),
                name=m.get("method_name", ""),
                file=m.get("binary_path", ""),
            )
            methods.append(wm)
            methods_flat.append(wm)

        pseudo_lines = iface_obj.get("pseudo_idl", [])
        if not isinstance(pseudo_lines, list):
            pseudo_lines = []
        guid = _parse_guid_from_pseudo_idl(pseudo_lines)

        interfaces.append(WinrtInterface(
            name=iface_name,
            guid=guid,
            methods=methods,
            pseudo_idl=pseudo_lines,
        ))

    hosting = hosting_binary
    if not hosting and methods_flat:
        hosting = methods_flat[0].binary_name

    if hosting.lower() in _GENERIC_HOST_PROCESSES:
        if methods_flat and methods_flat[0].binary_name:
            hosting = methods_flat[0].binary_name

    return WinrtServer(
        name=raw.get("class_name", ""),
        server=raw.get("hosting_server", ""),
        activation_type=raw.get("activation_type", ""),
        trust_level=raw.get("trust_level", ""),
        server_permissions=raw.get("server_launch_permission_sddl", ""),
        server_identity=raw.get("server_run_as_identity", ""),
        server_name=raw.get("server_display_name", ""),
        server_exe_path=raw.get("server_exe_path", ""),
        server_exe_name=raw.get("server_exe_name", ""),
        service_name=raw.get("service_name", ""),
        default_access_permission=raw.get("default_access_permission_sddl", ""),
        default_launch_permission=raw.get("default_launch_permission_sddl", ""),
        supports_remote_activation=raw.get("supports_remote_activation", "False"),
        source=raw.get("registration_source", ""),
        activate_in_shared_broker=raw.get("activate_in_shared_broker", "False"),
        has_server=raw.get("has_hosting_server", "False"),
        package_id=raw.get("package_id", ""),
        interfaces=interfaces,
        methods_flat=methods_flat,
        hosting_binary=hosting,
    )


# ---------------------------------------------------------------------------
# Index
# ---------------------------------------------------------------------------

class WinrtIndex:
    """Queryable index over WinRT server registrations and procedures."""

    def __init__(self) -> None:
        self._servers: list[WinrtServer] = []
        self._by_class: dict[str, WinrtServer] = {}
        self._by_module: dict[str, list[WinrtServer]] = {}
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

    def load(self, data_root: Optional[str | Path] = None) -> None:
        """Load WinRT data from all four access contexts."""
        if data_root is None:
            data_root = get_config_value("winrt.data_root", "config/assets/winrt_data")

        root = _resolve_path(data_root)
        if not root.is_dir():
            log_warning(f"WinRT data root not found: {root}", "NOT_FOUND")
            return

        exclude_staterepo = get_config_value("winrt.exclude_staterepo", False)

        for ctx in WinrtAccessContext:
            ctx_dir = root / ctx.value
            if not ctx_dir.is_dir():
                _log.debug("WinRT context directory not found: %s", ctx_dir)
                continue
            self._load_context(ctx_dir, ctx, exclude_staterepo)

        self._loaded = bool(self._servers)
        _log.info(
            "WinRT index loaded: %d servers across %d modules, %d total methods",
            len(self._servers), len(self._by_module), self.total_methods,
        )

    def _load_context(
        self,
        ctx_dir: Path,
        context: WinrtAccessContext,
        exclude_staterepo: bool,
    ) -> None:
        servers_path = ctx_dir / "winrt_servers.json"

        if servers_path.exists():
            self._load_binary_entries(servers_path, context, exclude_staterepo)

    def _load_binary_entries(
        self, path: Path, context: WinrtAccessContext,
        exclude_staterepo: bool = False,
    ) -> None:
        data = _load_json_file(path)
        if not isinstance(data, dict):
            return

        for bin_key, bin_entry in data.items():
            if not isinstance(bin_entry, dict):
                continue

            binary_path = bin_entry.get("binary_path", "")
            hosting = module_name_from_path(binary_path) if binary_path else ""

            if exclude_staterepo and hosting and hosting.lower() == _STATEREPO_DLL:
                continue

            for entry in bin_entry.get("servers", []):
                if not isinstance(entry, dict):
                    continue

                class_name = entry.get("class_name", "")
                class_key = class_name.lower()

                existing = self._by_class.get(class_key)
                if existing is not None:
                    existing.access_contexts.add(context)
                    continue

                server = _parse_server_detail(entry, hosting)

                server.access_contexts.add(context)
                self._servers.append(server)
                self._by_class[class_key] = server

                if server.hosting_binary:
                    mod_key = server.hosting_binary.lower()
                    self._by_module.setdefault(mod_key, []).append(server)

                for iface in server.interfaces:
                    for method in iface.methods:
                        if method.file:
                            m_key = module_name_from_path(method.file).lower()
                            if m_key != (server.hosting_binary or "").lower():
                                if server not in self._by_module.get(m_key, []):
                                    self._by_module.setdefault(m_key, []).append(server)

            procedures = bin_entry.get("procedures", [])
            if isinstance(procedures, list) and procedures:
                mod_name = module_name_from_path(binary_path) if binary_path else ""
                if mod_name and mod_name.lower() not in _GENERIC_HOST_PROCESSES:
                    if exclude_staterepo and mod_name.lower() == _STATEREPO_DLL:
                        continue
                    mod_key = mod_name.lower()
                    existing_procs = self._procedures_by_module.get(mod_key)
                    if existing_procs is not None:
                        existing_procs.update(procedures)
                    else:
                        self._procedures_by_module[mod_key] = set(procedures)

    # -- Query API ---------------------------------------------------------

    def get_servers_for_module(self, module_name: str) -> list[WinrtServer]:
        """Return all WinRT servers hosted in *module_name*."""
        return list(self._by_module.get(module_name.lower(), []))

    def get_servers_by_class(self, class_name: str) -> Optional[WinrtServer]:
        """Return the WinRT server for *class_name*, or None."""
        return self._by_class.get(class_name.lower())

    def get_procedures_for_module(self, module_name: str) -> list[str]:
        """Return WinRT procedure names for *module_name*."""
        procs = self._procedures_by_module.get(module_name.lower())
        if procs is not None:
            return sorted(procs)
        servers = self._by_module.get(module_name.lower(), [])
        combined: set[str] = set()
        for srv in servers:
            for m in srv.methods_flat:
                combined.add(m.name)
        return sorted(combined)

    def is_winrt_procedure(self, module_name: str, func_name: str) -> bool:
        """Return True if *func_name* is a known WinRT procedure in *module_name*."""
        procs = self._procedures_by_module.get(module_name.lower())
        if procs is not None:
            return func_name in procs
        servers = self._by_module.get(module_name.lower(), [])
        return any(
            func_name == m.name or func_name == m.short_name
            for srv in servers for m in srv.methods_flat
        )

    def get_interfaces_for_module(self, module_name: str) -> list[WinrtInterface]:
        """Return all WinRT interfaces hosted in *module_name*."""
        result: list[WinrtInterface] = []
        for srv in self._by_module.get(module_name.lower(), []):
            result.extend(srv.interfaces)
        return result

    def get_methods_for_class(self, class_name: str) -> list[WinrtMethod]:
        """Return all methods across all interfaces for *class_name*."""
        srv = self._by_class.get(class_name.lower())
        if srv is None:
            return []
        return list(srv.methods_flat)

    def search_methods(self, pattern: str) -> list[WinrtMethod]:
        """Search method names across all servers using a regex pattern."""
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error:
            return []
        results: list[WinrtMethod] = []
        for srv in self._servers:
            for m in srv.methods_flat:
                if regex.search(m.name):
                    results.append(m)
        return results

    def get_access_contexts_for_class(
        self, class_name: str,
    ) -> set[WinrtAccessContext]:
        """Return which access contexts expose *class_name*."""
        srv = self._by_class.get(class_name.lower())
        if srv is None:
            return set()
        return set(srv.access_contexts)

    def get_privileged_surface(
        self, caller_il: str = "medium",
    ) -> list[WinrtServer]:
        """Return servers on privileged processes reachable from *caller_il*."""
        results: list[WinrtServer] = []
        for srv in self._servers:
            for ctx in srv.access_contexts:
                if ctx.caller_il == caller_il and ctx.is_privileged_server:
                    results.append(srv)
                    break
        return results

    def get_servers_by_risk(self, tier: str) -> list[WinrtServer]:
        """Return servers matching a risk tier."""
        return [s for s in self._servers if s.best_risk_tier == tier]

    def get_all_classes(self) -> list[str]:
        """Return all registered WinRT class names."""
        return sorted(srv.name for srv in self._by_class.values())

    def get_all_modules(self) -> list[str]:
        """Return all module names that host WinRT servers."""
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
            "total_classes": len(self._by_class),
            "total_methods": self.total_methods,
            "total_procedures": sum(len(v) for v in self._procedures_by_module.values()),
            "by_tier": tier_counts,
            "by_activation": {
                "in_process": sum(1 for s in self._servers if s.is_in_process),
                "out_of_process": sum(1 for s in self._servers if s.is_out_of_process),
            },
            "runs_as_system": sum(1 for s in self._servers if s.runs_as_system),
            "with_permissive_sddl": sum(1 for s in self._servers if s.has_permissive_sddl),
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
        log_warning(f"WinRT data file not found: {path}", "NOT_FOUND")
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        log_warning(f"Failed to parse WinRT data {path}: {exc}", "PARSE_ERROR")
        return None


# ---------------------------------------------------------------------------
# Singleton access
# ---------------------------------------------------------------------------

_global_index: Optional[WinrtIndex] = None


def get_winrt_index(*, force_reload: bool = False) -> WinrtIndex:
    """Return the global WinRT index, loading on first call.

    Returns an empty (but usable) index if WinRT data is not available
    or ``winrt.enabled`` is false in the config.
    """
    global _global_index

    if _global_index is not None and not force_reload:
        return _global_index

    idx = WinrtIndex()
    enabled = get_config_value("winrt.enabled", True)
    if enabled:
        try:
            idx.load()
        except Exception as exc:
            log_warning(
                f"Failed to load WinRT index: {exc}. Check that winrt.data_root "
                f"in config/defaults.json points to a valid directory.",
                "PARSE_ERROR",
            )

    _global_index = idx
    return idx


def invalidate_winrt_index() -> None:
    """Clear the cached WinRT index so the next call reloads from disk."""
    global _global_index
    _global_index = None
