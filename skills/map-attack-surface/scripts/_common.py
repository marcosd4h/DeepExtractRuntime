"""Shared utilities for attack surface mapping skill.

Provides entry point type definitions, API pattern databases for callback/handler
detection, parameter risk scoring, and callgraph reachability analysis.
"""

from __future__ import annotations

import sys
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, Optional

_AGENT_DIR = str(Path(__file__).resolve().parents[3])
if _AGENT_DIR not in sys.path:
    sys.path.insert(0, _AGENT_DIR)

from skills._shared import bootstrap, make_db_resolvers

WORKSPACE_ROOT = bootstrap(__file__)
resolve_db_path, resolve_tracking_db = make_db_resolvers(WORKSPACE_ROOT)

from helpers import _resolve_module_db, emit_error, parse_json_safe  # noqa: E402
from helpers.callgraph import CallGraph  # noqa: E402
from helpers.api_taxonomy import get_dangerous_api_set  # noqa: E402


# ===========================================================================
# Entry Point Type Taxonomy
# ===========================================================================

class EntryPointType(IntEnum):
    """Categorization of entry point types by origin."""
    EXPORT_DLL = 1
    EXPORT_ORDINAL_ONLY = 2
    MAIN_ENTRY = 3          # main, wmain, WinMain, wWinMain
    DLLMAIN = 4             # DllMain / DllEntryPoint
    SERVICE_MAIN = 5        # ServiceMain, SvcMain
    COM_METHOD = 6          # COM vtable methods (IUnknown, custom interfaces)
    WINRT_METHOD = 7        # WinRT / WRL vtable methods
    RPC_HANDLER = 8         # RPC server routines, Ndr* dispatchers
    NAMED_PIPE_HANDLER = 9  # Named pipe IPC dispatchers
    CALLBACK_REGISTRATION = 10  # SetTimer, CreateThread, RegisterClassEx targets
    WINDOW_PROC = 11        # WndProc, DlgProc, window message handlers
    SERVICE_CTRL_HANDLER = 12  # RegisterServiceCtrlHandler targets
    TLS_CALLBACK = 13       # TLS directory callbacks
    IPC_DISPATCHER = 14     # Generic IPC: ALPC, mailslots, shared memory
    TCP_UDP_HANDLER = 15    # Socket accept/recv dispatchers
    EXCEPTION_HANDLER = 16  # SEH, VEH handlers
    DRIVER_DISPATCH = 17    # DriverEntry, IRP dispatch routines
    COM_CLASS_FACTORY = 18  # DllGetClassObject, IClassFactory
    SCHEDULED_CALLBACK = 19  # Timer, APC, thread pool callbacks
    HOOK_PROCEDURE = 20     # SetWindowsHookEx targets
    FORWARDED_EXPORT = 21   # Forwarded DLL exports


# ===========================================================================
# API Patterns for Hidden Entry Point Discovery
# ===========================================================================

# APIs that register callback functions (the callback param index matters)
CALLBACK_REGISTRATION_APIS: dict[str, dict[str, Any]] = {
    # Thread/fiber creation
    "CreateThread": {"param_idx": 2, "category": "thread_callback"},
    "CreateRemoteThread": {"param_idx": 3, "category": "thread_callback"},
    "CreateRemoteThreadEx": {"param_idx": 3, "category": "thread_callback"},
    "_beginthreadex": {"param_idx": 2, "category": "thread_callback"},
    "_beginthread": {"param_idx": 0, "category": "thread_callback"},
    "RtlCreateUserThread": {"param_idx": 4, "category": "thread_callback"},
    "CreateFiber": {"param_idx": 2, "category": "fiber_callback"},
    "CreateFiberEx": {"param_idx": 3, "category": "fiber_callback"},
    # Timer callbacks
    "SetTimer": {"param_idx": 3, "category": "timer_callback"},
    "CreateTimerQueueTimer": {"param_idx": 2, "category": "timer_callback"},
    "SetWaitableTimer": {"param_idx": 3, "category": "timer_callback"},
    "SetWaitableTimerEx": {"param_idx": 3, "category": "timer_callback"},
    "timeSetEvent": {"param_idx": 2, "category": "timer_callback"},
    # Thread pool
    "TpAllocWork": {"param_idx": 1, "category": "threadpool_callback"},
    "TpAllocTimer": {"param_idx": 1, "category": "threadpool_callback"},
    "TpAllocWait": {"param_idx": 1, "category": "threadpool_callback"},
    "CreateThreadpoolWork": {"param_idx": 0, "category": "threadpool_callback"},
    "CreateThreadpoolTimer": {"param_idx": 0, "category": "threadpool_callback"},
    "CreateThreadpoolWait": {"param_idx": 0, "category": "threadpool_callback"},
    "CreateThreadpoolIo": {"param_idx": 1, "category": "threadpool_callback"},
    "QueueUserWorkItem": {"param_idx": 0, "category": "threadpool_callback"},
    "RegisterWaitForSingleObject": {"param_idx": 1, "category": "threadpool_callback"},
    # Window/dialog procedures
    "RegisterClassW": {"param_idx": "wndproc_field", "category": "window_proc"},
    "RegisterClassExW": {"param_idx": "wndproc_field", "category": "window_proc"},
    "RegisterClassA": {"param_idx": "wndproc_field", "category": "window_proc"},
    "RegisterClassExA": {"param_idx": "wndproc_field", "category": "window_proc"},
    "SetWindowLongPtrW": {"param_idx": 2, "category": "window_proc"},
    "SetWindowLongPtrA": {"param_idx": 2, "category": "window_proc"},
    "SetWindowLongW": {"param_idx": 2, "category": "window_proc"},
    "SetWindowLongA": {"param_idx": 2, "category": "window_proc"},
    "DialogBoxParamW": {"param_idx": 4, "category": "dialog_proc"},
    "DialogBoxParamA": {"param_idx": 4, "category": "dialog_proc"},
    "CreateDialogParamW": {"param_idx": 4, "category": "dialog_proc"},
    "CreateDialogParamA": {"param_idx": 4, "category": "dialog_proc"},
    # APC
    "QueueUserAPC": {"param_idx": 0, "category": "apc_callback"},
    "QueueUserAPC2": {"param_idx": 0, "category": "apc_callback"},
    "NtQueueApcThread": {"param_idx": 1, "category": "apc_callback"},
    # Hooks
    "SetWindowsHookExW": {"param_idx": 2, "category": "hook_procedure"},
    "SetWindowsHookExA": {"param_idx": 2, "category": "hook_procedure"},
    # Enumeration callbacks
    "EnumWindows": {"param_idx": 0, "category": "enum_callback"},
    "EnumChildWindows": {"param_idx": 1, "category": "enum_callback"},
    "EnumDesktopWindows": {"param_idx": 1, "category": "enum_callback"},
    "EnumThreadWindows": {"param_idx": 1, "category": "enum_callback"},
    "EnumFontsW": {"param_idx": 2, "category": "enum_callback"},
    "EnumFontFamiliesExW": {"param_idx": 3, "category": "enum_callback"},
    # Exception handlers
    "AddVectoredExceptionHandler": {"param_idx": 1, "category": "exception_handler"},
    "AddVectoredContinueHandler": {"param_idx": 1, "category": "exception_handler"},
    "SetUnhandledExceptionFilter": {"param_idx": 0, "category": "exception_handler"},
    # Service handlers
    "RegisterServiceCtrlHandlerW": {"param_idx": 1, "category": "service_handler"},
    "RegisterServiceCtrlHandlerA": {"param_idx": 1, "category": "service_handler"},
    "RegisterServiceCtrlHandlerExW": {"param_idx": 2, "category": "service_handler"},
    "RegisterServiceCtrlHandlerExA": {"param_idx": 2, "category": "service_handler"},
    # Completion routines
    "ReadFileEx": {"param_idx": 4, "category": "io_completion"},
    "WriteFileEx": {"param_idx": 4, "category": "io_completion"},
    "BindIoCompletionCallback": {"param_idx": 1, "category": "io_completion"},
    # WinSock async callbacks
    "WSAAsyncSelect": {"param_idx": -1, "category": "socket_callback"},
    "WSAEventSelect": {"param_idx": -1, "category": "socket_callback"},
    "AcceptEx": {"param_idx": -1, "category": "socket_callback"},
    "ConnectEx": {"param_idx": -1, "category": "socket_callback"},
    "WSARecv": {"param_idx": 5, "category": "socket_callback"},
    "WSASend": {"param_idx": 5, "category": "socket_callback"},
}

# APIs indicating network/socket entry points
SOCKET_APIS: set[str] = {
    "accept", "AcceptEx", "WSAAccept",
    "recv", "recvfrom", "WSARecv", "WSARecvFrom",
    "listen", "bind", "connect", "WSAConnect",
    "WSASocket", "socket",
    "WinHttpOpen", "WinHttpReceiveResponse", "WinHttpReadData",
    "HttpOpenRequest", "HttpSendRequest",
    "InternetReadFile",
    "RpcServerListen", "RpcServerUseProtseq",
}

# APIs indicating RPC server-side functionality
RPC_SERVER_APIS: set[str] = {
    "RpcServerListen", "RpcServerUseProtseq", "RpcServerUseProtseqEp",
    "RpcServerUseAllProtseqs", "RpcServerUseAllProtseqsIf",
    "RpcServerRegisterIf", "RpcServerRegisterIf2", "RpcServerRegisterIf3",
    "RpcServerRegisterIfEx", "RpcServerInqBindings",
    "NdrServerCall2", "NdrStubCall2", "NdrStubCall3",
    "NdrServerCallAll", "NdrServerCallNdr64",
    "NdrAsyncServerCall", "Ndr64AsyncServerCall64",
    "RpcServerUnregisterIf", "RpcServerUnregisterIfEx",
    "I_RpcServerUnregisterEndpoint",
}

# APIs indicating named pipe server functionality
NAMED_PIPE_APIS: set[str] = {
    "CreateNamedPipeW", "CreateNamedPipeA",
    "ConnectNamedPipe", "TransactNamedPipe",
    "PeekNamedPipe", "DisconnectNamedPipe",
    "ImpersonateNamedPipeClient",
}

# APIs indicating ALPC/LPC IPC
ALPC_APIS: set[str] = {
    "NtAlpcCreatePort", "NtAlpcConnectPort", "NtAlpcSendWaitReceivePort",
    "NtAlpcAcceptConnectPort", "NtAlpcDisconnectPort",
    "NtCreatePort", "NtConnectPort", "NtListenPort",
    "NtReplyWaitReceivePort", "NtRequestWaitReplyPort",
}

# COM class factory / server APIs
COM_SERVER_APIS: set[str] = {
    "DllGetClassObject", "DllCanUnloadNow",
    "DllRegisterServer", "DllUnregisterServer",
    "CoRegisterClassObject", "CoRevokeClassObject",
    "RoRegisterActivationFactories",
    "RoGetActivationFactory",
}

# Service control APIs -- split into dispatcher vs handler for accurate classification
SERVICE_DISPATCHER_APIS: set[str] = {
    "StartServiceCtrlDispatcherW", "StartServiceCtrlDispatcherA",
}
SERVICE_HANDLER_APIS: set[str] = {
    "RegisterServiceCtrlHandlerW", "RegisterServiceCtrlHandlerA",
    "RegisterServiceCtrlHandlerExW", "RegisterServiceCtrlHandlerExA",
    "SetServiceStatus",
}
SERVICE_APIS: set[str] = SERVICE_DISPATCHER_APIS | SERVICE_HANDLER_APIS

# Dangerous APIs (sinks) for reachability analysis.
# Derived from the centralized security taxonomy with additional entries
# for memory-copy and security-descriptor APIs not covered by the taxonomy.
DANGEROUS_SINK_APIS: set[str] = get_dangerous_api_set() | {
    # Memory copy primitives (not in taxonomy -- not "unsafe" per se but
    # dangerous when paired with attacker-controlled sizes)
    "memcpy", "memmove", "RtlCopyMemory", "CopyMemory",
    # Security descriptor modification
    "SetSecurityInfo", "SetNamedSecurityInfo",
    "SetNamedSecurityInfoW", "SetNamedSecurityInfoA",
    # Network write
    "InternetWriteFile",
}


# ===========================================================================
# Parameter Risk Analysis
# ===========================================================================

from helpers.param_risk import (
    describe_parameter_surface,
    PARAM_TYPE_PATTERNS,
    BUFFER_SIZE_PAIR_PATTERNS,
)


# ===========================================================================
# Entry Point Type Classification (Fallback)
# ===========================================================================

def _classify_entry_name(function_name: str) -> "EntryPointType":
    """Default fallback -- returns EXPORT_DLL.

    Entry point type classification is done by structured data sources
    (RPC/COM/WinRT indexes, file_info.json exports) in the callers,
    not by name-pattern heuristics.
    """
    return EntryPointType.EXPORT_DLL


# ===========================================================================
# Entry Point Record
# ===========================================================================

@dataclass
class EntryPoint:
    """Represents a discovered entry point with scoring metadata."""

    function_name: str
    function_id: Optional[int] = None
    entry_type: EntryPointType = EntryPointType.EXPORT_DLL
    type_label: str = ""
    category: str = ""               # e.g., "DLL export", "COM method", "callback"
    detection_source: str = ""       # How it was found
    signature: str = ""
    mangled_name: str = ""
    address: str = ""
    ordinal: Optional[int] = None

    # Parameter surface metadata
    param_surface: dict = field(default_factory=dict)

    # Callgraph reachability (populated by ranker)
    reachable_count: int = 0
    dangerous_ops_reachable: int = 0
    dangerous_ops_list: list[str] = field(default_factory=list)
    depth_to_first_danger: Optional[int] = None
    reachable_functions: list[str] = field(default_factory=list)

    # RPC enrichment (populated when RPC index is available)
    rpc_interface_id: str = ""
    rpc_opnum: Optional[int] = None
    rpc_protocol: str = ""
    rpc_service: str = ""
    rpc_risk_tier: str = ""

    # COM enrichment (populated when COM index is available)
    com_clsid: str = ""
    com_interface_name: str = ""
    com_service: str = ""
    com_risk_tier: str = ""
    com_can_elevate: bool = False
    com_access_contexts: str = ""

    # WinRT enrichment (populated when WinRT index is available)
    winrt_class_name: str = ""
    winrt_interface_name: str = ""
    winrt_activation_type: str = ""
    winrt_risk_tier: str = ""
    winrt_access_contexts: str = ""

    # Final composite score
    attack_score: float = 0.0
    attack_rank: int = 0
    tainted_args: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "function_name": self.function_name,
            "function_id": self.function_id,
            "entry_type": self.entry_type.name,
            "type_label": self.type_label or self.entry_type.name,
            "category": self.category,
            "detection_source": self.detection_source,
            "signature": self.signature,
            "mangled_name": self.mangled_name,
            "address": self.address,
            "ordinal": self.ordinal,
            "param_surface": self.param_surface,
            "reachable_count": self.reachable_count,
            "dangerous_ops_reachable": self.dangerous_ops_reachable,
            "dangerous_ops_list": self.dangerous_ops_list[:20],
            "depth_to_first_danger": self.depth_to_first_danger,
            "rpc_interface_id": self.rpc_interface_id,
            "rpc_opnum": self.rpc_opnum,
            "rpc_protocol": self.rpc_protocol,
            "rpc_service": self.rpc_service,
            "rpc_risk_tier": self.rpc_risk_tier,
            "com_clsid": self.com_clsid,
            "com_interface_name": self.com_interface_name,
            "com_service": self.com_service,
            "com_risk_tier": self.com_risk_tier,
            "com_can_elevate": self.com_can_elevate,
            "com_access_contexts": self.com_access_contexts,
            "winrt_class_name": self.winrt_class_name,
            "winrt_interface_name": self.winrt_interface_name,
            "winrt_activation_type": self.winrt_activation_type,
            "winrt_risk_tier": self.winrt_risk_tier,
            "winrt_access_contexts": self.winrt_access_contexts,
            "attack_score": round(self.attack_score, 3),
            "attack_rank": self.attack_rank,
            "tainted_args": self.tainted_args,
            "notes": self.notes,
        }


# ===========================================================================
# JSON Parsing Helper
# ===========================================================================

# parse_json_safe imported from helpers


# ===========================================================================
# Callgraph Reachability Engine (delegates to helpers.callgraph.CallGraph)
# ===========================================================================

# Re-export filter constants for any code that still references them
from helpers.callgraph import SKIP_MODULES, SKIP_FTYPES, _is_followable_xref


def build_adjacency(db) -> dict[str, list[dict]]:
    """Build name -> outbound xref list from all functions in a DB.

    Returns dict mapping function_name -> list of outbound xref dicts.
    Only includes followable xrefs (no data/vtable refs).

    Note: Kept for backward compatibility. New code should use
    ``CallGraph.from_functions(db.get_all_functions())`` directly.
    """
    adjacency: dict[str, list[dict]] = {}
    all_funcs = db.get_all_functions()
    for func in all_funcs:
        name = func.function_name
        if not name:
            continue
        xrefs = parse_json_safe(func.simple_outbound_xrefs)
        if not xrefs or not isinstance(xrefs, list):
            adjacency[name] = []
            continue
        filtered = [x for x in xrefs if isinstance(x, dict) and _is_followable_xref(x)]
        adjacency[name] = filtered
    return adjacency


def compute_reachability(
    adjacency: dict[str, list[dict]],
    start_func: str,
    max_depth: int = 10,
) -> dict[str, int]:
    """BFS from start_func, return dict of reachable_name -> depth.

    Only follows internal functions (function_id is not None).

    Note: Kept for backward compatibility.  New code should use
    ``CallGraph.reachable_from_internal_only()`` directly.
    """
    visited: dict[str, int] = {}
    queue: deque[tuple[str, int]] = deque()
    queue.append((start_func, 0))
    visited[start_func] = 0

    while queue:
        current, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for xref in adjacency.get(current, []):
            callee = xref.get("function_name", "")
            if not callee or callee in visited:
                continue
            fid = xref.get("function_id")
            if fid is not None and callee in adjacency:
                visited[callee] = depth + 1
                queue.append((callee, depth + 1))
    return visited


def find_dangerous_ops_reachable(
    adjacency: dict[str, list[dict]],
    reachable: dict[str, int],
    func_dangerous_apis: dict[str, list[str]],
) -> tuple[int, list[str], Optional[int]]:
    """Count dangerous operations reachable from a set of reachable functions.

    Returns: (count, unique_api_list, min_depth_to_first_danger)
    """
    total = 0
    apis_seen: set[str] = set()
    min_depth: Optional[int] = None

    for func_name, depth in reachable.items():
        dangerous = func_dangerous_apis.get(func_name, [])
        if dangerous:
            total += len(dangerous)
            apis_seen.update(dangerous)
            if min_depth is None or depth < min_depth:
                min_depth = depth

    return total, sorted(apis_seen), min_depth


def collect_dangerous_apis_map(db) -> dict[str, list[str]]:
    """Build function_name -> list[dangerous_api_name] from all functions."""
    result: dict[str, list[str]] = {}
    all_funcs = db.get_all_functions()
    for func in all_funcs:
        name = func.function_name
        if not name:
            continue
        apis = parse_json_safe(func.dangerous_api_calls)
        if apis and isinstance(apis, list):
            result[name] = [a for a in apis if isinstance(a, str)]
    return result


# ===========================================================================
# Resolve Module DB Path
# ===========================================================================

def resolve_module_db(module_name: str) -> Optional[Path]:
    """Resolve a module name to its analysis DB path."""
    result = _resolve_module_db(module_name, WORKSPACE_ROOT)
    return Path(result) if result else None
