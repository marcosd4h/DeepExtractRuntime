"""Canonical string categorization for DeepExtractIDA analysis.

Consolidates four duplicate pattern lists that were independently maintained
in classify-functions, generate-re-report, deep-research-prompt, and the
re-analyst agent.

Categories
----------
file_path      -- Drive-letter paths, device paths, system paths, PE refs
registry_key   -- Registry hives, keys, and well-known paths
url            -- HTTP/HTTPS/FTP/WSS/file URLs
rpc_endpoint   -- ALPC, named-pipe, TCP RPC endpoint strings
named_pipe     -- ``\\\\.\\pipe\\...`` paths
alpc_path      -- ALPC port paths (\\RPC Control\\, \\BaseNamedObjects\\)
service_account -- NT AUTHORITY\\*, LocalSystem, etc.
certificate    -- Certificate file extensions (.cer, .pfx, .pem, etc.)
etw_provider   -- ``Microsoft-Windows-*`` provider names
guid           -- ``{xxxxxxxx-xxxx-...}`` CLSID / IID patterns
error_message  -- Strings containing error/failure keywords (phrase context)
format_string  -- printf-style format specifiers
debug_trace    -- TraceLogging / ETW / WPP keywords
"""

from __future__ import annotations

import re
from typing import Optional

# ---------------------------------------------------------------------------
# Canonical taxonomy (superset of all 4 prior implementations)
# ---------------------------------------------------------------------------
STRING_TAXONOMY: list[tuple[re.Pattern, str, str]] = [
    # File system paths
    (re.compile(r"^[A-Za-z]:\\", re.I), "file_path", "Drive letter path"),
    (re.compile(r"^\\\\[?.]\\", re.I), "file_path", "Device path"),
    (re.compile(r"%[A-Za-z]+%\\", re.I), "file_path", "Environment variable path"),
    (re.compile(r"\\Windows\\|\\System32\\|\\SysWOW64\\", re.I), "file_path", "System path"),
    (re.compile(r"\\.(?:dll|exe|sys|inf|cat|mof|man)$", re.I), "file_path", "PE/system file reference"),
    # Certificate file extensions (high-value for security analysis)
    (re.compile(r"\.(?:cer|crt|pem|pfx|p12|p7b|p7c|der|key)$", re.I), "certificate", "Certificate/key file"),
    # Registry
    (re.compile(r"\\Registry\\|HKEY_|^HKLM\\|^HKCU\\|^HKCR\\", re.I), "registry_key", "Registry key"),
    (re.compile(r"SOFTWARE\\|SYSTEM\\CurrentControlSet|CurrentVersion\\", re.I), "registry_key", "Registry path"),
    # URLs / network (including file://)
    (re.compile(r"https?://|ftp://|wss?://|file://", re.I), "url", "URL"),
    # RPC
    (re.compile(r"ncalrpc:|ncacn_np:|ncacn_ip_tcp:", re.I), "rpc_endpoint", "RPC endpoint"),
    # Named pipes
    (re.compile(r"\\\\\\\\.\\\\pipe\\\\|\\.\\pipe\\", re.I), "named_pipe", "Named pipe"),
    # ALPC paths (Object Manager namespace - high-value for IPC analysis)
    # Match \RPC Control\, \BaseNamedObjects\, \Sessions\ (single backslashes)
    (re.compile(r"(?:^|[^\\])\\(?:RPC Control|BaseNamedObjects|Sessions)\\", re.I), "alpc_path", "ALPC/Object Manager path"),
    # Service account strings
    (re.compile(r"NT AUTHORITY\\(?:LOCAL SYSTEM|NETWORK SERVICE|LOCAL SERVICE|SYSTEM)", re.I), "service_account", "Built-in service account"),
    (re.compile(r"(?:^|\\)LocalSystem(?:$|\\| )", re.I), "service_account", "LocalSystem account"),
    (re.compile(r"\.\\(?:LocalSystem|NetworkService|LocalService)", re.I), "service_account", "Dot-prefix service account"),
    # ETW / telemetry
    (re.compile(r"Microsoft-Windows-", re.I), "etw_provider", "ETW provider name"),
    # GUIDs
    (re.compile(r"\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}"), "guid", "GUID/CLSID"),
    # Error / status messages (require phrase context to reduce enum/identifier false positives)
    (re.compile(r"^(?=.{15,}).*\b(?:error|fail(?:ed|ure)?|invalid|denied|refused|exception|abort|critical)\b", re.I | re.DOTALL), "error_message", "Error/status string"),
    # Format strings
    (re.compile(r"%[-+0 #]*(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:h{1,2}|l{1,2}|L|z|j|t|q|I|I32|I64|w)?[diouxXeEfFgGaAcCsSpn%]"), "format_string", "printf-style format"),
    # Debug / trace
    (re.compile(r"TraceLogging|TRACE_LEVEL|ETW_KEYWORD|WPP_", re.I), "debug_trace", "Trace/ETW keyword"),
]

# All canonical category names, in definition order.
CATEGORIES = [
    "file_path", "registry_key", "url", "rpc_endpoint", "named_pipe",
    "alpc_path", "service_account", "certificate",
    "etw_provider", "guid", "error_message", "format_string", "debug_trace",
]

# Mapping from canonical taxonomy names to the classify-functions scoring
# categories.  classify-functions uses coarser buckets (e.g. ``rpc`` covers
# both RPC endpoints and named pipes).
TAXONOMY_TO_CLASSIFICATION: dict[str, str] = {
    "registry_key": "registry",
    "url": "network",
    "rpc_endpoint": "rpc",
    "named_pipe": "rpc",
    "alpc_path": "rpc",
    "service_account": "security",
    "certificate": "crypto",
    "etw_provider": "telemetry",
    "format_string": "data_parsing",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def categorize_string(s: str) -> Optional[tuple[str, str]]:
    """Categorize a string literal.

    Returns ``(category, description)`` for the first matching pattern,
    or ``None`` if no pattern matches.
    """
    for pattern, category, desc in STRING_TAXONOMY:
        if pattern.search(s):
            return (category, desc)
    return None


def categorize_string_simple(s: str) -> str:
    """Categorize a string literal, returning just the category name.

    Returns the category name for the first matching pattern, or
    ``"other"`` if nothing matches.  This matches the return convention
    used by the re-analyst and deep-research-prompt consumers.
    """
    for pattern, category, _desc in STRING_TAXONOMY:
        if pattern.search(s):
            return category
    return "other"


def categorize_strings(strings: list[str]) -> dict[str, list[str]]:
    """Batch-categorize string literals into ``{category: [strings...]}``.

    Skips non-string and blank entries.  Category ``"other"`` collects
    strings that match no pattern.
    """
    from collections import defaultdict
    result: dict[str, list[str]] = defaultdict(list)
    for s in strings:
        if isinstance(s, str) and s.strip():
            cat = categorize_string_simple(s)
            result[cat].append(s)
    return dict(result)
