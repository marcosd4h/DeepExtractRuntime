"""Shared utilities for attack surface mapping skill.

Provides entry point type definitions, API pattern databases for callback/handler
detection, parameter risk scoring, and callgraph reachability analysis.
"""

from __future__ import annotations

import re
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
from helpers.asm_metrics import get_asm_metrics, AsmMetrics  # noqa: E402


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

# Service control APIs
SERVICE_APIS: set[str] = {
    "StartServiceCtrlDispatcherW", "StartServiceCtrlDispatcherA",
    "RegisterServiceCtrlHandlerW", "RegisterServiceCtrlHandlerA",
    "RegisterServiceCtrlHandlerExW", "RegisterServiceCtrlHandlerExA",
    "SetServiceStatus",
}

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

# Type patterns that indicate attacker-controllable input
HIGH_RISK_PARAM_PATTERNS: list[tuple[str, float]] = [
    # Buffer + size pairs (highest risk)
    (r"(?:void|PVOID|LPVOID|char|BYTE|PBYTE|LPBYTE)\s*\*", 1.0),
    (r"(?:wchar_t|WCHAR|LPWSTR|PWSTR|OLECHAR)\s*\*", 0.9),
    (r"(?:LPSTR|LPCSTR|PSTR|PCSTR|char\s+const)\s*\*?", 0.9),
    (r"(?:LPCWSTR|PCWSTR|wchar_t\s+const)\s*\*?", 0.85),
    (r"(?:BSTR|VARIANT|SAFEARRAY)", 0.85),
    # Size/length parameters (amplifiers when paired with buffers)
    (r"(?:DWORD|ULONG|SIZE_T|size_t|unsigned|int)\b", 0.3),
    # Handle parameters (moderate -- can reference attacker objects)
    (r"(?:HANDLE|HKEY|HMODULE|HINSTANCE|SOCKET|HWND)", 0.5),
    # Interface pointers (COM attack surface)
    (r"(?:IUnknown|IDispatch|I[A-Z]\w+)\s*\*", 0.7),
    (r"(?:REFIID|REFCLSID|GUID|IID)", 0.4),
    # Struct pointers
    (r"(?:struct|SECURITY_ATTRIBUTES|OVERLAPPED)\s*\*", 0.5),
    # Flags (low risk alone but can change behavior)
    (r"(?:FLAGS|ULONG|DWORD)\b.*(?:flags|options|mode)", 0.2),
]

BUFFER_SIZE_PAIR_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?:void|char|BYTE|wchar_t|WCHAR)\s*\*.*,\s*(?:DWORD|ULONG|SIZE_T|size_t|unsigned|int)\b", re.I),
    re.compile(r"(?:LPVOID|PVOID|LPBYTE|PBYTE)\s.*,\s*(?:DWORD|ULONG|SIZE_T|size_t|unsigned)\b", re.I),
    re.compile(r"(?:LPWSTR|LPSTR|PWSTR|PSTR)\s.*,\s*(?:DWORD|ULONG|SIZE_T|int|unsigned)\b", re.I),
]


def score_parameter_risk(signature: Optional[str]) -> tuple[float, list[str]]:
    """Score parameter risk from a function signature.

    Returns (risk_score 0.0-1.0, list of risk reasons).
    """
    if not signature:
        return 0.0, []

    risk = 0.0
    reasons: list[str] = []

    # Check for buffer+size pairs (highest risk)
    for pat in BUFFER_SIZE_PAIR_PATTERNS:
        if pat.search(signature):
            risk = max(risk, 0.9)
            reasons.append("buffer+size parameter pair")
            break

    # Score individual parameters
    # Extract parameter list from signature
    paren_match = re.search(r"\(([^)]*)\)", signature)
    if not paren_match:
        return risk, reasons

    param_str = paren_match.group(1)
    if not param_str.strip() or param_str.strip().lower() in ("void", ""):
        return 0.1, ["no parameters (limited attack surface)"]

    params = [p.strip() for p in param_str.split(",") if p.strip()]
    param_scores: list[float] = []

    for param in params:
        best_score = 0.0
        for pattern, score in HIGH_RISK_PARAM_PATTERNS:
            if re.search(pattern, param, re.I):
                best_score = max(best_score, score)
        param_scores.append(best_score)

    if param_scores:
        max_param = max(param_scores)
        avg_param = sum(param_scores) / len(param_scores)
        # Weighted: max matters more but count of risky params amplifies
        combined = max_param * 0.6 + avg_param * 0.2 + min(len(params) / 10.0, 0.2)
        risk = max(risk, min(combined, 1.0))

        if max_param >= 0.8:
            reasons.append("high-risk pointer/buffer parameters")
        elif max_param >= 0.5:
            reasons.append("handle/interface pointer parameters")

    return risk, reasons


# ===========================================================================
# Function Name Pattern Detection
# ===========================================================================

# Patterns for identifying entry point types from function names
ENTRY_NAME_PATTERNS: dict[str, list[re.Pattern]] = {
    "main_entry": [
        re.compile(r"^(?:w?W?main|wmain|WinMain|wWinMain|_?tmain|_?wmain)$", re.I),
    ],
    "dllmain": [
        re.compile(r"^(?:Dll(?:Main|Entry(?:Point)?))$", re.I),
        re.compile(r"^_?DllMainCRTStartup$", re.I),
    ],
    "service_main": [
        re.compile(r"^(?:Service(?:Main|Entry)|Svc(?:Main|Entry|Host))$", re.I),
        re.compile(r"ServiceMain", re.I),
    ],
    "window_proc": [
        re.compile(r"(?:Wnd|Dlg|Dialog|Window)Proc", re.I),
        re.compile(r"(?:WM_|MSG_).*(?:Handler|Proc|Callback)", re.I),
    ],
    "rpc_handler": [
        re.compile(r"^(?:Rpc|RPC_|Ndr).*(?:ServerCall|StubCall|Dispatch)", re.I),
        re.compile(r"_?(?:Rpc)?(?:Server)?(?:Interface|If)(?:Callback|Handler)", re.I),
        re.compile(r"^s_\w+$"),  # RPC-generated server-side stubs (s_FuncName)
    ],
    "named_pipe": [
        re.compile(r"(?:Pipe|PIPE).*(?:Handler|Dispatch|Process|Server|Thread)", re.I),
        re.compile(r"(?:Handle|Process).*(?:Pipe|Connection|Request)", re.I),
    ],
    "ipc_dispatcher": [
        re.compile(r"(?:ALPC|LPC|Mailslot|SharedMem).*(?:Handler|Dispatch|Callback)", re.I),
        re.compile(r"(?:Handle|Process|Dispatch).*(?:Message|Request|Command|Packet)", re.I),
    ],
    "socket_handler": [
        re.compile(r"(?:Socket|Tcp|Udp|Http|Net)(?:Server|Client)?(?:Handler|Dispatch|Callback|Accept|Recv|Listen)", re.I),
        re.compile(r"(?:^|::)(?:Handle|Process|On)(?:Connection|Request|Packet|Client)(?:$|[A-Z])", re.I),
        re.compile(r"(?:^|::)(?:Accept|Receive|Listen)(?:Thread|Callback|Handler)$", re.I),
    ],
    "driver_dispatch": [
        re.compile(r"^DriverEntry$", re.I),
        re.compile(r"^(?:Irp|IRP).*Dispatch", re.I),
        re.compile(r"^(?:DeviceIoControl|IOCTL).*Handler", re.I),
    ],
    "com_class_factory": [
        re.compile(r"^Dll(?:GetClassObject|CanUnloadNow|RegisterServer|UnregisterServer)$", re.I),
        re.compile(r"(?:ClassFactory|ActivationFactory).*(?:Create|Query)", re.I),
    ],
    "exception_handler": [
        re.compile(r"(?:Exception|SEH|VEH).*(?:Handler|Filter|Callback)", re.I),
        re.compile(r"(?:Unhandled|Vectored).*(?:Exception)", re.I),
    ],
}

# String patterns suggesting function is an entry point or dispatcher
ENTRY_STRING_PATTERNS: dict[str, list[re.Pattern]] = {
    "rpc_handler": [
        re.compile(r"ncalrpc|ncacn_np|ncacn_ip_tcp|ncacn_http", re.I),
        re.compile(r"RPC\s+server|RPC\s+interface", re.I),
    ],
    "named_pipe": [
        re.compile(r"\\\\.\\pipe\\", re.I),
        re.compile(r"named\s+pipe|pipe\s+server", re.I),
    ],
    "socket_handler": [
        re.compile(r"(?:bind|listen|accept)\s+(?:on|failed|error)", re.I),
        re.compile(r"(?:tcp|udp|socket)\s+(?:server|handler|connection)", re.I),
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b"),  # IP:port
        re.compile(r"(?:HTTP/\d|GET |POST |PUT |DELETE )", re.I),
    ],
    "ipc_dispatcher": [
        re.compile(r"\\Device\\", re.I),
        re.compile(r"ALPC|alpc|\\RPC Control\\", re.I),
    ],
}


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

    # Risk scoring
    param_risk_score: float = 0.0
    param_risk_reasons: list[str] = field(default_factory=list)

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
            "param_risk_score": round(self.param_risk_score, 3),
            "param_risk_reasons": self.param_risk_reasons,
            "reachable_count": self.reachable_count,
            "dangerous_ops_reachable": self.dangerous_ops_reachable,
            "dangerous_ops_list": self.dangerous_ops_list[:20],
            "depth_to_first_danger": self.depth_to_first_danger,
            "rpc_interface_id": self.rpc_interface_id,
            "rpc_opnum": self.rpc_opnum,
            "rpc_protocol": self.rpc_protocol,
            "rpc_service": self.rpc_service,
            "rpc_risk_tier": self.rpc_risk_tier,
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
