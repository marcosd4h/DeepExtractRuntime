"""Canonical Win32/NT API taxonomy for DeepExtractIDA analysis skills.

Provides two classification dimensions:

1. **Functional-area classification** (`API_TAXONOMY` / `classify_api`):
   Maps ~600 Win32/NT/WinRT API prefixes to 17 capability categories.

2. **Security-impact classification** (`SECURITY_API_CATEGORIES` / `classify_api_security`):
   Maps ~80 security-sensitive API prefixes to 11 impact categories.

Both use prefix-based matching (``startswith``), so ``CreateFileW``,
``CreateFileA``, and ``CreateFileMappingW`` all match the ``CreateFile``
prefix.  Import prefixes (``__imp_``, ``_imp_``, ``j_``, ``cs:``) are
stripped before matching.

This module is the single source of truth -- all skills that need API
classification should import from here (or from ``helpers`` which
re-exports these symbols).
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Optional

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# IDA import-thunk prefix stripping
# ---------------------------------------------------------------------------

IMP_PREFIX_RE = re.compile(r"(?:__imp_|_imp_|__imp__|j_)(.+)")

_IDA_IMPORT_PREFIXES = ("__imp_", "_imp_", "j_", "cs:")


def strip_import_prefix(api_name: str) -> str:
    """Remove IDA import-thunk prefixes (``__imp_``, ``_imp_``, ``j_``, ``cs:``) from *api_name*."""
    for pfx in _IDA_IMPORT_PREFIXES:
        if api_name.startswith(pfx):
            return api_name[len(pfx):]
    return api_name


_strip_api_prefix = strip_import_prefix

# ---------------------------------------------------------------------------
# Comprehensive Win32 API Taxonomy  (functional-area classification)
# ---------------------------------------------------------------------------
API_TAXONOMY: dict[str, list[str]] = {
    "file_io": [
        "CreateFile", "ReadFile", "WriteFile", "DeleteFile", "CopyFile", "MoveFile",
        "FindFirstFile", "FindNextFile", "FindClose", "GetFileAttributes", "SetFileAttributes",
        "GetFileSize", "SetFilePointer", "FlushFileBuffers", "LockFile", "UnlockFile",
        "CreateDirectory", "RemoveDirectory", "GetCurrentDirectory", "SetCurrentDirectory",
        "GetTempPath", "GetTempFileName", "SearchPath", "GetFullPathName",
        "SetEndOfFile", "GetFileType", "GetFileInformationByHandle",
        "ReplaceFile", "SetFileInformationByHandle", "GetFinalPathNameByHandle",
        "GetFileVersionInfo", "VerQueryValue",
        "NtCreateFile", "NtReadFile", "NtWriteFile", "NtDeleteFile",
        "NtQueryDirectoryFile", "NtQueryInformationFile", "NtSetInformationFile",
        "ZwCreateFile", "ZwReadFile", "ZwWriteFile",
        "PathFileExists", "PathIsDirectory", "PathCombine", "PathAppend",
        "PathFindFileName", "PathFindExtension", "PathRemoveFileSpec",
        "SHGetFolderPath", "SHGetKnownFolderPath", "SHCreateDirectory",
    ],
    "registry": [
        "RegOpenKey", "RegCloseKey", "RegQueryValue", "RegSetValue", "RegDeleteKey",
        "RegDeleteValue", "RegDeleteTree", "RegEnumKey", "RegEnumValue", "RegCreateKey",
        "RegNotifyChangeKeyValue", "RegGetValue", "RegLoadKey", "RegSaveKey",
        "RegFlushKey", "RegConnectRegistry", "RegOverridePredefKey",
        "NtOpenKey", "NtQueryValueKey", "NtSetValueKey", "NtCreateKey",
        "NtDeleteKey", "NtEnumerateKey", "NtEnumerateValueKey",
        "ZwOpenKey", "ZwQueryValueKey",
    ],
    "network": [
        "WSAStartup", "WSACleanup", "WSASocket", "WSASend", "WSARecv", "WSAConnect",
        "WSAAccept", "WSAIoctl", "WSAGetLastError", "WSAAddressToString",
        "connect", "bind", "listen", "accept", "send", "recv", "sendto", "recvfrom",
        "socket", "closesocket", "select", "getaddrinfo", "freeaddrinfo",
        "gethostbyname", "gethostname", "inet_addr", "inet_ntop", "inet_pton",
        "htons", "ntohs", "htonl", "ntohl",
        "HttpOpenRequest", "HttpSendRequest", "HttpQueryInfo", "HttpEndRequest",
        "InternetOpen", "InternetConnect", "InternetReadFile", "InternetCloseHandle",
        "InternetCrackUrl", "InternetSetOption", "InternetQueryOption",
        "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest",
        "WinHttpReceiveResponse", "WinHttpReadData", "WinHttpCloseHandle",
        "WinHttpSetOption", "WinHttpQueryHeaders", "WinHttpQueryDataAvailable",
        "URLDownloadToFile", "URLDownloadToCacheFile",
    ],
    "process_thread": [
        "CreateProcess", "OpenProcess", "TerminateProcess", "ExitProcess",
        "GetExitCodeProcess", "GetCurrentProcess", "GetCurrentProcessId",
        "ShellExecute", "WinExec", "CreateProcessAsUser",
        "CreateProcessWithToken", "CreateProcessWithLogon",
        "CreateThread", "ExitThread", "ResumeThread", "SuspendThread", "TerminateThread",
        "GetCurrentThread", "GetCurrentThreadId", "GetThreadId",
        "QueueUserAPC", "QueueUserWorkItem", "CreateRemoteThread",
        "OpenThread", "SetThreadPriority", "SetProcessAffinityMask",
        "NtCreateProcess", "NtTerminateProcess", "NtCreateThread",
        "NtOpenProcess", "NtSuspendThread", "NtResumeThread",
        "RtlCreateUserThread", "RtlExitUserThread",
        # Module loading
        "LoadLibrary", "LoadLibraryEx", "FreeLibrary", "GetModuleHandle",
        "GetModuleHandleEx", "GetModuleFileName", "GetProcAddress",
        "LdrLoadDll", "LdrGetProcedureAddress", "LdrUnloadDll",
    ],
    "crypto": [
        "BCryptOpenAlgorithmProvider", "BCryptCloseAlgorithmProvider",
        "BCryptEncrypt", "BCryptDecrypt", "BCryptHash", "BCryptGenRandom",
        "BCryptCreateHash", "BCryptHashData", "BCryptFinishHash", "BCryptDestroyHash",
        "BCryptSignHash", "BCryptVerifySignature", "BCryptDeriveKey",
        "BCryptGetProperty", "BCryptSetProperty", "BCryptGenerateSymmetricKey",
        "BCryptImportKey", "BCryptExportKey", "BCryptDestroyKey",
        "NCryptOpenKey", "NCryptEncrypt", "NCryptDecrypt", "NCryptSignHash",
        "NCryptVerifySignature", "NCryptOpenStorageProvider", "NCryptFreeObject",
        "NCryptCreatePersistedKey", "NCryptDeleteKey", "NCryptDeriveKey",
        "NCryptEnumAlgorithms", "NCryptEnumKeys", "NCryptEnumStorageProviders",
        "NCryptFinalizeKey", "NCryptGetProperty", "NCryptSetProperty",
        "NCryptImportKey", "NCryptExportKey", "NCryptIsAlgSupported",
        "NCryptKeyDerivation", "NCryptSecretAgreement", "NCryptTranslateHandle",
        "NCryptNotifyChangeKey",
        "CryptAcquireContext", "CryptReleaseContext", "CryptGenRandom",
        "CryptCreateHash", "CryptHashData", "CryptGetHashParam",
        "CryptEncrypt", "CryptDecrypt", "CryptSignHash", "CryptVerifySignature",
        "CryptImportKey", "CryptExportKey", "CryptDeriveKey", "CryptDestroyKey",
        "CryptStringToBinary", "CryptBinaryToString", "CryptProtectData", "CryptUnprotectData",
        "CertOpenStore", "CertCloseStore", "CertFindCertificateInStore",
        "CertFreeCertificateContext", "CertGetCertificateContextProperty",
        "CertVerifyCertificateChainPolicy", "CertGetCertificateChain",
        "CertOpenSystemStore", "CertEnumCertificatesInStore",
        "CryptAcquireCertificatePrivateKey",
        "CryptDecodeObject", "CryptEncodeObject",
        "CryptMsgOpenToDecode", "CryptMsgOpenToEncode", "CryptMsgClose",
        "CryptMsgGetParam", "CryptMsgUpdate",
        "PFXImportCertStore", "PFXExportCertStore", "PFXVerifyPassword",
    ],
    "security": [
        "CheckTokenMembership", "AdjustTokenPrivileges", "OpenProcessToken",
        "OpenThreadToken", "GetTokenInformation", "SetTokenInformation",
        "DuplicateToken", "DuplicateTokenEx", "CreateRestrictedToken",
        "LookupAccountSid", "LookupAccountName", "LookupPrivilegeValue",
        "LookupPrivilegeName", "PrivilegeCheck",
        "InitializeSecurityDescriptor", "SetSecurityDescriptorDacl",
        "SetSecurityDescriptorOwner", "SetSecurityDescriptorGroup",
        "SetSecurityDescriptorSacl", "GetSecurityDescriptorSacl",
        "GetSecurityDescriptorControl", "SetSecurityDescriptorControl",
        "ConvertStringSecurityDescriptor", "ConvertSecurityDescriptor",
        "GetSecurityInfo", "SetSecurityInfo", "GetNamedSecurityInfo",
        "AccessCheck", "AccessCheckByType", "AccessCheckAndAuditAlarm",
        "ImpersonateLoggedOnUser", "ImpersonateNamedPipeClient", "RevertToSelf",
        "ImpersonateSelf", "ImpersonateAnonymousToken",
        "IsWellKnownSid", "EqualSid", "AllocateAndInitializeSid",
        "ConvertSidToStringSid", "ConvertStringSidToSid", "CopySid",
        "InitializeAcl", "AddAccessAllowedAce", "AddAccessDeniedAce",
        "LogonUser", "AuthzInitializeResourceManager", "AuthzAccessCheck",
        "AuthzInitializeContextFromToken", "AuthzFreeContext",
        "NtOpenProcessToken", "NtQueryInformationToken",
        "RtlCreateAcl", "RtlAddAccessAllowedAce",
        # Credential Management
        "CredRead", "CredWrite", "CredFree", "CredDelete", "CredEnumerate",
        "CredGetTargetInfo", "CredUnprotect", "CredProtect",
        # Safer API (code integrity / restricted tokens)
        "SaferCreateLevel", "SaferCloseLevel", "SaferGetPolicyInformation",
        "SaferSetLevelInformation", "SaferIdentifyLevel",
        # LSA (Local Security Authority)
        "LsaLookupNames2", "LsaLookupSids2", "LsaConnectUntrusted",
        "LsaOpenPolicy", "LsaLookupNames", "LsaLookupSids",
        # Audit
        "AuditQuerySystemPolicy", "AuditSetSystemPolicy",
        "AuditEnumerateCategories", "AuditEnumerateSubCategories",
    ],
    "com_ole": [
        "CoCreateInstance", "CoCreateInstanceEx", "CoInitialize", "CoInitializeEx",
        "CoUninitialize", "CoGetClassObject", "CoRegisterClassObject",
        "CoMarshalInterface", "CoUnmarshalInterface",
        "CoTaskMemAlloc", "CoTaskMemFree", "CoTaskMemRealloc",
        "OleInitialize", "OleUninitialize",
        "ProgIDFromCLSID", "CLSIDFromProgID", "CLSIDFromString",
        "StringFromCLSID", "StringFromGUID2", "StringFromIID",
        "CoGetMalloc", "CoGetInterfaceAndReleaseStream",
        # BSTR management (OLEAUT32)
        "SysAllocString", "SysFreeString", "SysReAllocString",
        "SysAllocStringLen", "SysAllocStringByteLen",
        "SysStringLen", "SysStringByteLen",
        # VARIANT (OLEAUT32)
        "VariantInit", "VariantClear", "VariantCopy", "VariantCopyInd",
        "VariantChangeType", "VariantChangeTypeEx",
        "SystemTimeToVariantTime", "VariantTimeToSystemTime",
        # SafeArray (OLEAUT32)
        "SafeArrayCreate", "SafeArrayCreateVector", "SafeArrayDestroy",
        "SafeArrayGetElement", "SafeArrayPutElement",
        "SafeArrayAccessData", "SafeArrayUnaccessData",
        "SafeArrayGetDim", "SafeArrayGetLBound", "SafeArrayGetUBound",
        "SafeArrayLock", "SafeArrayUnlock", "SafeArrayCopy",
        "SafeArrayAllocData", "SafeArrayAllocDescriptor",
        # Type library / IDispatch support
        "LoadTypeLib", "LoadRegTypeLib", "RegisterTypeLib",
        "DispGetIDsOfNames", "DispInvoke", "DispGetParam",
        "CreateDispTypeInfo", "CreateStdDispatch",
        # Misc OLE automation
        "GetActiveObject", "RegisterActiveObject", "RevokeActiveObject",
    ],
    "rpc": [
        "RpcServerListen", "RpcServerUseProtseq", "RpcServerRegisterIf",
        "RpcServerRegisterIf2", "RpcServerRegisterIf3",
        "RpcBindingFromStringBinding", "RpcStringBindingCompose",
        "RpcEpRegister", "RpcEpResolveBinding",
        "NdrClientCall", "NdrClientCall2", "NdrClientCall3",
        "NdrServerCall", "NdrServerCall2", "NdrStubCall", "NdrStubCall2",
        "NdrAsyncClientCall", "NdrDcomAsyncClientCall",
        "RpcBindingSetAuthInfo", "RpcMgmtSetServerStackSize",
        "I_RpcBindingInqTransportType",
    ],
    "memory": [
        "VirtualAlloc", "VirtualAllocEx", "VirtualFree", "VirtualFreeEx",
        "VirtualProtect", "VirtualProtectEx", "VirtualQuery", "VirtualQueryEx",
        "HeapAlloc", "HeapFree", "HeapReAlloc", "HeapCreate", "HeapDestroy", "HeapSize",
        "LocalAlloc", "LocalFree", "LocalReAlloc",
        "GlobalAlloc", "GlobalFree", "GlobalReAlloc", "GlobalLock", "GlobalUnlock",
        "MapViewOfFile", "MapViewOfFileEx", "UnmapViewOfFile", "CreateFileMapping",
        "OpenFileMapping", "FlushViewOfFile",
        "RtlAllocateHeap", "RtlFreeHeap", "RtlReAllocateHeap",
        "NtAllocateVirtualMemory", "NtFreeVirtualMemory",
        "NtMapViewOfSection", "NtUnmapViewOfSection",
    ],
    "ui_shell": [
        "MessageBox", "DialogBox", "EndDialog", "CreateDialog",
        "CreateWindow", "DestroyWindow", "ShowWindow", "UpdateWindow",
        "GetMessage", "PeekMessage", "DispatchMessage", "TranslateMessage",
        "PostMessage", "SendMessage", "PostQuitMessage",
        "GetDlgItem", "SetDlgItem", "GetWindowText", "SetWindowText",
        "LoadString", "LoadIcon", "LoadCursor", "LoadImage",
        "EnableWindow", "SetFocus", "BeginPaint", "EndPaint",
        "RegisterClass", "UnregisterClass",
        "ShellExecuteEx", "SHGetSpecialFolderPath",
        "SHFileOperation", "SHBrowseForFolder", "SHGetPathFromIDList",
        "Shell_NotifyIcon", "ExtractIcon",
    ],
    "sync": [
        "EnterCriticalSection", "LeaveCriticalSection", "InitializeCriticalSection",
        "DeleteCriticalSection", "TryEnterCriticalSection",
        "InitializeCriticalSectionAndSpinCount", "InitializeCriticalSectionEx",
        "WaitForSingleObject", "WaitForSingleObjectEx",
        "WaitForMultipleObjects", "WaitForMultipleObjectsEx",
        "CreateEvent", "SetEvent", "ResetEvent", "OpenEvent",
        "CreateMutex", "ReleaseMutex", "OpenMutex",
        "CreateSemaphore", "ReleaseSemaphore",
        "InitOnceExecuteOnce", "InitOnceBeginInitialize", "InitOnceComplete",
        "AcquireSRWLockExclusive", "AcquireSRWLockShared",
        "ReleaseSRWLockExclusive", "ReleaseSRWLockShared",
        "TryAcquireSRWLockExclusive", "TryAcquireSRWLockShared",
        "InitializeSRWLock",
        "SleepConditionVariableCS", "SleepConditionVariableSRW",
        "WakeConditionVariable", "WakeAllConditionVariable",
        "SignalObjectAndWait", "MsgWaitForMultipleObjects",
    ],
    "string_manipulation": [
        "lstrcpy", "lstrcmp", "lstrcat", "lstrlen",
        "lstrcmpi", "lstrcpyn",
        "MultiByteToWideChar", "WideCharToMultiByte",
        "CompareString", "CompareStringOrdinal",
        "CharUpper", "CharLower", "CharNext", "CharPrev",
        "wcsncpy", "wcscpy", "wcscat", "wcscmp", "wcslen", "wcsstr", "wcschr", "wcsrchr",
        "strncpy", "strcpy", "strcat", "strcmp", "strlen", "strstr", "strchr", "strrchr",
        "StringCchCopy", "StringCchCat", "StringCchPrintf", "StringCchLength",
        "StringCbCopy", "StringCbCat", "StringCbPrintf",
        "RtlStringCchCopy", "RtlStringCchCat", "RtlStringCchPrintf",
        "sprintf", "swprintf", "snprintf", "_snwprintf", "_snprintf",
        "sscanf", "swscanf",
    ],
    "error_handling": [
        "SetLastError", "GetLastError", "FormatMessage",
        "RaiseException", "_CxxThrowException",
        "RtlRaiseException", "RtlUnwind", "RtlNtStatusToDosError",
        "SetUnhandledExceptionFilter", "AddVectoredExceptionHandler",
        "RemoveVectoredExceptionHandler",
        "RtlRaiseStatus", "NtRaiseException",
    ],
    "service": [
        "StartServiceCtrlDispatcher", "RegisterServiceCtrlHandler",
        "RegisterServiceCtrlHandlerEx",
        "SetServiceStatus", "OpenSCManager", "OpenService",
        "StartService", "ControlService", "QueryServiceStatus",
        "QueryServiceStatusEx", "QueryServiceConfig",
        "ChangeServiceConfig", "ChangeServiceConfig2",
        "CreateService", "DeleteService", "CloseServiceHandle",
        "EnumServicesStatus", "EnumServicesStatusEx",
    ],
    "telemetry": [
        "EventRegister", "EventWrite", "EventWriteTransfer", "EventUnregister",
        "EventWriteEx", "EventWriteString", "EventEnabled", "EventProviderEnabled",
        "TraceEvent", "TraceMessage", "TraceMessageVa",
        "RegisterTraceGuids", "UnregisterTraceGuids",
        "StartTrace", "StopTrace", "ControlTrace", "EnableTrace", "EnableTraceEx",
        "WppAutoLogStart", "WppAutoLogStop", "WppAutoLogTrace",
        "EtwEventWrite", "EtwEventRegister", "EtwEventUnregister",
        "TlgWrite", "TraceLoggingWrite", "TraceLoggingRegister", "TraceLoggingUnregister",
    ],
    "debug_diagnostics": [
        "OutputDebugString", "IsDebuggerPresent", "DebugBreak",
        "CheckRemoteDebuggerPresent",
        "SetThreadContext", "GetThreadContext",
        "ReadProcessMemory", "WriteProcessMemory",
        "NtQuerySystemInformation", "NtQueryInformationProcess",
        "MiniDumpWriteDump",
    ],
    "winrt": [
        # Activation
        "RoActivateInstance", "RoGetActivationFactory",
        "RoRegisterActivationFactories", "RoRevokeActivationFactories",
        "RoGetApartmentIdentifier", "RoGetActivatableClasses",
        "RoGetActivatableClassesWithMetadata",
        # Initialization
        "RoInitialize", "RoUninitialize",
        # String (HSTRING)
        "WindowsCreateString", "WindowsDeleteString", "WindowsDuplicateString",
        "WindowsGetStringRawBuffer", "WindowsStringHasEmbeddedNull",
        "WindowsCompareStringOrdinal", "WindowsConcatString",
        "WindowsSubstring", "WindowsTrimString",
        "WindowsPreallocateStringBuffer", "WindowsPromoteStringBuffer",
        "WindowsDeleteStringBuffer", "WindowsGetStringLen",
        "WindowsIsStringEmpty",
        # Error / diagnostics
        "RoOriginateError", "RoOriginateLanguageException",
        "RoTransformError", "RoCaptureErrorContext",
        "RoFailFastWithErrorContext", "RoReportUnhandledError",
        "RoReportCapabilityCheckFailure", "RoReportFailedDelegate",
        "GetRestrictedErrorInfo", "SetRestrictedErrorInfo",
        "RoGetErrorReportingFlags",
        # Metadata / marshaling
        "RoGetMetaDataFile", "RoGetParameterizedTypeInstanceIID",
        "RoGetBufferMarshaler", "RoResolveNamespace",
        "RoParseTypeName", "RoResolveNamespace",
        # Agile references / thread capture
        "RoGetAgileReference", "RoCreateAgileReference",
        "RoInspectThreadCapturer", "RoInspectCaptureSnapshot",
        # Apartment
        "RoRegisterForApartmentShutdown", "RoUnregisterForApartmentShutdown",
        "RoGetServerActivatableClassRegistration",
    ],
    "wmi": [
        # Security setup (WMI-typical COM security)
        "CoInitializeSecurity", "CoSetProxyBlanket", "CoQueryProxyBlanket",
        # WMI provider framework
        "WmiSetSingleInstance", "WmiSetSingleItem", "WmiQueryAllData",
        "WmiQuerySingleInstance", "WmiFireEvent", "WmiSystemControl",
        "WmiCompleteRequest", "WmiOpenBlock", "WmiCloseBlock",
        "WmiEnableEvent", "WmiDisableEvent", "WmiNotificationRegistration",
        # CIM / MOF
        "MofCompile",
    ],
}

# Build a flattened lookup: (prefix, category) sorted longest-first for greedy match
_API_PREFIX_LOOKUP: list[tuple[str, str]] = []
for _cat, _prefixes in API_TAXONOMY.items():
    for _prefix in _prefixes:
        _API_PREFIX_LOOKUP.append((_prefix, _cat))
_API_PREFIX_LOOKUP.sort(key=lambda x: -len(x[0]))


def classify_api(api_name: str) -> Optional[str]:
    """Classify an API name into a functional-area category.

    Strips common import prefixes (``__imp_``, ``_imp_``, ``j_``, ``cs:``),
    then performs longest-prefix matching against :data:`API_TAXONOMY`.

    Returns the category string, or ``None`` if unrecognized.
    """
    clean = _strip_api_prefix(api_name)
    for pfx, cat in _API_PREFIX_LOOKUP:
        if clean.startswith(pfx):
            return cat
    return None


# ---------------------------------------------------------------------------
# Security-Impact API Classification
# ---------------------------------------------------------------------------
SECURITY_API_CATEGORIES: dict[str, list[str]] = {
    "memory_unsafe": [
        "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf",
        "wcscpy", "wcscat", "wsprintf", "wvsprintf", "lstrcpy", "lstrcat",
        "memcpy", "memmove", "RtlCopyMemory", "RtlMoveMemory",
        "wmemcpy", "wmemmove", "CopyMemory",
        "strncpy", "wcsncpy", "strncat", "lstrcpyn",
        "swprintf", "vswprintf", "_snprintf", "_snwprintf",
        "fgets", "fwrite", "sscanf", "swscanf",
        "alloca", "_alloca",
        "MultiByteToWideChar",
    ],
    "command_execution": [
        "CreateProcess", "ShellExecute", "WinExec", "system", "_wsystem",
        "CreateProcessAsUser", "CreateProcessWithLogon",
        "CreateProcessWithToken",
        "NtCreateProcess", "NtCreateUserProcess", "RtlCreateUserProcess",
        "CreateThread", "ResumeThread", "SuspendThread",
        "TerminateProcess", "ExitProcess",
    ],
    "code_injection": [
        "WriteProcessMemory", "VirtualAllocEx", "CreateRemoteThread",
        "QueueUserAPC", "NtWriteVirtualMemory", "SetWindowsHookEx",
        "NtMapViewOfSection", "RtlCreateUserThread",
        "NtQueueApcThread", "NtQueueApcThreadEx",
        "SetThreadContext", "NtSetContextThread",
        "NtSetInformationThread", "NtSetInformationProcess",
        "CreateRemoteThreadEx",
    ],
    "privilege": [
        "AdjustTokenPrivileges", "ImpersonateLoggedOnUser",
        "ImpersonateNamedPipeClient", "SetTokenInformation",
        "OpenProcessToken", "OpenThreadToken", "DuplicateTokenEx",
        "CoInitializeSecurity",
        "CredRead", "CredWrite", "CredDelete", "CredEnumerate",
        "LsaLookupNames2", "LsaLookupSids2", "LsaConnectUntrusted",
        "LsaOpenPolicy", "SaferCreateLevel", "SaferCloseLevel",
        "NtCreateToken", "NtDuplicateToken", "NtDuplicateObject",
        "SetThreadToken", "ImpersonateSelf", "RtlAdjustPrivilege",
    ],
    "file_write": [
        "CreateFile", "WriteFile", "DeleteFile", "MoveFile", "CopyFile",
        "NtCreateFile", "NtDeleteFile", "NtSetInformationFile",
        "CreateHardLink", "NtCreateSymbolicLinkObject",
        "ReplaceFile", "SetFileInformationByHandle",
    ],
    "registry_write": [
        "RegSetValue", "RegCreateKey", "RegDeleteKey", "RegDeleteValue",
        "NtSetValueKey", "NtCreateKey", "NtDeleteKey",
        "RtlWriteRegistryValue",
    ],
    "network": [
        "connect", "send", "recv", "WSASend", "WSARecv",
        "InternetOpen", "WinHttpOpen", "URLDownloadToFile",
        "socket", "listen", "bind", "accept",
        "InternetConnect", "InternetReadFile",
        "WinHttpSendRequest", "WinHttpReadData",
        "HttpSendRequest",
    ],
    "crypto": [
        "BCryptEncrypt", "BCryptDecrypt", "CryptEncrypt", "CryptDecrypt",
        "BCryptGenRandom", "CryptGenRandom",
    ],
    "sync": [
        "EnterCriticalSection", "LeaveCriticalSection",
        "AcquireSRWLock", "ReleaseSRWLock",
        "WaitForSingleObject", "WaitForMultipleObjects",
        "CreateMutex", "OpenMutex", "CreateSemaphore",
    ],
    "memory_alloc": [
        "VirtualAlloc", "VirtualFree", "VirtualProtect",
        "HeapAlloc", "HeapFree", "MapViewOfFile",
        "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
        "VirtualAllocEx", "VirtualProtectEx",
    ],
    "code_loading": [
        "LoadLibrary", "LoadLibraryEx", "GetProcAddress",
        "LdrLoadDll", "LdrGetProcedureAddress",
        "RoActivateInstance", "RoGetActivationFactory",
        "NtLoadDriver",
    ],
    "reconnaissance": [
        "GetAdaptersInfo", "GetNetworkParams",
        "WTSQuerySessionInformation",
        "NetUserEnum", "NetGroupEnum", "NetLocalGroupEnum",
        "GetVersion", "GetTickCount", "QueryPerformanceCounter",
        "IsProcessorFeaturePresent", "GetLogicalProcessorInformation",
        "GlobalMemoryStatus", "GetSystemInfo",
        "FindWindow", "GetForegroundWindow",
        "GetWindowText", "GetWindowThreadProcessId",
        "GetClassName", "EnumWindows",
        "GetModuleBaseName", "GetProcessImageFileName",
        "QueryFullProcessImageName",
        "EnumProcesses", "EnumProcessModules",
        "CreateToolhelp32Snapshot",
        "NtQuerySystemInformation", "NtQueryInformationProcess",
    ],
    "anti_forensics": [
        "ClearEventLog",
    ],
}

# Build lookup sorted longest-prefix-first for greedy matching
_SECURITY_API_LOOKUP: list[tuple[str, str]] = []
for _cat, _prefixes in SECURITY_API_CATEGORIES.items():
    for _prefix in _prefixes:
        _SECURITY_API_LOOKUP.append((_prefix, _cat))
_SECURITY_API_LOOKUP.sort(key=lambda x: -len(x[0]))


def classify_api_security(api_name: str) -> Optional[str]:
    """Classify an API by its security impact.

    Uses the same prefix-stripping logic as :func:`classify_api` but
    matches against :data:`SECURITY_API_CATEGORIES` first, then falls
    back to the JSON auto-classify map, and finally checks whether the
    API appears in the comprehensive ``dangerous_apis.json`` (returning
    ``"uncategorized_dangerous"`` as a catch-all).

    Returns the security-impact category string, or ``None`` if not
    security-relevant.
    """
    clean = _strip_api_prefix(api_name)
    for pfx, cat in _SECURITY_API_LOOKUP:
        if clean.startswith(pfx):
            return cat
    # Fall back to JSON auto-classify map
    jcat = _JSON_AUTO_LOOKUP.get(clean.lower())
    if jcat:
        return jcat
    # Final fall-through: present in comprehensive JSON list?
    if is_in_dangerous_apis_json(clean):
        return "uncategorized_dangerous"
    return None


# ---------------------------------------------------------------------------
# Convenience helpers for downstream consumers
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Module-fingerprinting helpers
# ---------------------------------------------------------------------------
# Coarser categories useful for quick module characterization (e.g.
# triage-coordinator routing decisions).  Maps ``API_TAXONOMY`` categories
# to higher-level fingerprint buckets.

_FINGERPRINT_MAP: dict[str, str] = {
    "com_ole": "com",
    "rpc": "rpc",
    "security": "security",
    "crypto": "crypto",
    "network": "network",
    "process_thread": "process",
    "file_io": "file",
    "registry": "registry",
    "memory": "memory",
    "service": "service",
    "debug_diagnostics": "debug",
    "winrt": "winrt",
    "wmi": "wmi",
    "ui_shell": "ui",
    "telemetry": "telemetry",
    "string_manipulation": "string",
    "sync": "sync",
    "error_handling": "error",
}

DISPATCH_KEYWORDS: tuple[str, ...] = (
    "Dispatch", "Handler", "Callback", "WndProc", "WinProc",
)
"""Function-name substrings that suggest dispatch/routing behaviour."""


def classify_api_fingerprint(api_name: str) -> Optional[str]:
    """Classify an API into a coarse fingerprint bucket.

    Returns one of ``"com"``, ``"rpc"``, ``"security"``, ``"crypto"``
    or ``None``.  Useful for module-level density counting without
    maintaining separate prefix lists.
    """
    cat = classify_api(api_name)
    return _FINGERPRINT_MAP.get(cat) if cat else None


# ---------------------------------------------------------------------------
# Dangerous-API JSON data source (loaded from config/assets/misc_data/dangerous_apis.json)
# ---------------------------------------------------------------------------

def _resolve_dangerous_apis_path() -> Path:
    """Resolve dangerous_apis.json path from config, falling back to default."""
    try:
        from .config import get_config_value
        configured = get_config_value("dangerous_apis.json_path")
        if configured:
            agent_dir = Path(__file__).resolve().parent.parent
            p = agent_dir / configured
            if p.exists():
                return p
    except (ImportError, KeyError, FileNotFoundError, TypeError):
        pass
    return Path(__file__).resolve().parent.parent / "config" / "assets" / "misc_data" / "dangerous_apis.json"

_DANGEROUS_APIS_JSON_PATH = _resolve_dangerous_apis_path()

_dangerous_apis_json_cache: set[str] | None = None


def _load_dangerous_apis_json() -> set[str]:
    """Load the comprehensive dangerous-API set from the config JSON file.

    The file is a flat JSON array of API name strings produced by
    DeepExtractIDA.  Results are cached after first load.  Returns an
    empty set if the file is missing or malformed.
    """
    global _dangerous_apis_json_cache
    if _dangerous_apis_json_cache is not None:
        return _dangerous_apis_json_cache

    if not _DANGEROUS_APIS_JSON_PATH.exists():
        _dangerous_apis_json_cache = set()
        return _dangerous_apis_json_cache

    try:
        with open(_DANGEROUS_APIS_JSON_PATH, encoding="utf-8") as f:
            data = json.load(f)
        _dangerous_apis_json_cache = set(data) if isinstance(data, list) else set()
    except (json.JSONDecodeError, OSError) as exc:
        _log.warning("Failed to load %s: %s", _DANGEROUS_APIS_JSON_PATH, exc)
        _dangerous_apis_json_cache = set()

    return _dangerous_apis_json_cache


# Auto-classify map: JSON entries that don't match any taxonomy prefix are
# assigned a category by exact (case-insensitive) lookup here.  Entries
# already covered by SECURITY_API_CATEGORIES prefix matching are skipped.
_JSON_AUTO_CLASSIFY: dict[str, list[str]] = {
    "reconnaissance": [
        "GetAdaptersInfo", "GetNetworkParams", "WTSQuerySessionInformation",
        "NetUserEnum", "NetGroupEnum", "NetLocalGroupEnum",
        "GetVersion", "GetTickCount", "QueryPerformanceCounter",
        "IsProcessorFeaturePresent", "GetLogicalProcessorInformation",
        "GlobalMemoryStatus", "GlobalMemoryStatusEx", "GetSystemInfo",
        "FindWindow", "GetForegroundWindow", "GetWindowText",
        "GetWindowThreadProcessId", "GetClassName", "EnumWindows",
        "GetModuleBaseName", "GetProcessImageFileName",
        "QueryFullProcessImageName", "EnumProcesses", "EnumProcessModules",
        "CreateToolhelp32Snapshot", "GetDC", "GetDCEx", "GetWindowDC",
        "SetKeyboardState", "GetUserName",
    ],
    "anti_forensics": [
        "ClearEventLog",
    ],
    "com_marshaling": [
        "CreateAntiMoniker", "CreateBindCtx", "CreateClassMoniker",
        "CreateFileMoniker", "CreateItemMoniker", "CreatePointerMoniker",
        "CreateURLMoniker", "CreateGenericComposite", "BindToObject",
        "AppContainerDeriveSidFromMoniker",
    ],
    "shell_storage": [
        "SHCreateDataObject", "SHCreateMemStream",
        "SHCreateShellItemArrayFromDataObject",
        "SHCreateStreamOnFileEx", "GetShellItemFromStorageItem",
        "PSCreateMemoryPropertyStore", "IStorage",
    ],
}

# Build a case-insensitive reverse lookup: lowercase(name) -> category
_JSON_AUTO_LOOKUP: dict[str, str] = {}
for _jcat, _jnames in _JSON_AUTO_CLASSIFY.items():
    for _jname in _jnames:
        _JSON_AUTO_LOOKUP[_jname.lower()] = _jcat


def classify_from_json(api_name: str) -> Optional[str]:
    """Classify an API using the JSON auto-classify map.

    Strips import prefixes, then does a case-insensitive exact lookup.
    Returns the category or ``None``.
    """
    clean = _strip_api_prefix(api_name)
    return _JSON_AUTO_LOOKUP.get(clean.lower())


_dangerous_apis_json_lower_cache: set[str] | None = None


def is_in_dangerous_apis_json(api_name: str) -> bool:
    """Check if an API name appears in the comprehensive JSON list.

    Comparison is case-insensitive.  The lowercase set is cached after
    the first call.
    """
    global _dangerous_apis_json_lower_cache
    if _dangerous_apis_json_lower_cache is None:
        loaded = _load_dangerous_apis_json()
        _dangerous_apis_json_lower_cache = {n.lower() for n in loaded}

    clean = _strip_api_prefix(api_name)
    return clean.lower() in _dangerous_apis_json_lower_cache


# ---------------------------------------------------------------------------
# Dangerous-API convenience helpers
# ---------------------------------------------------------------------------

def get_dangerous_api_prefixes() -> set[str]:
    """Return all security-sensitive API prefixes as a flat set.

    Flattens every list in :data:`SECURITY_API_CATEGORIES` into a single
    set of prefix strings.
    """
    return {pfx for prefixes in SECURITY_API_CATEGORIES.values() for pfx in prefixes}


_COMMON_SUFFIXES: tuple[str, ...] = ("A", "W", "Ex", "ExA", "ExW")


def get_dangerous_api_set() -> set[str]:
    """Expand taxonomy prefixes into an exact-match set with A/W/Ex suffixes,
    then merge in the comprehensive ``dangerous_apis.json`` entries.

    Useful for call sites that need to match fully-resolved import names
    (e.g. ``CreateProcessW``) rather than prefix-based matching.
    """
    result: set[str] = set()
    for pfx in get_dangerous_api_prefixes():
        result.add(pfx)
        for suffix in _COMMON_SUFFIXES:
            result.add(pfx + suffix)
    result |= _load_dangerous_apis_json()
    return result
