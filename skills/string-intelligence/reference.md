# String Intelligence -- Reference

## Contents

- [String Categories](#string-categories)
- [Risk Levels](#risk-levels)
- [Regex Patterns](#regex-patterns)
- [Category-to-Classification Mapping](#category-to-classification-mapping)
- [Output Schema](#output-schema)

## String Categories

The canonical taxonomy is defined in `helpers/string_taxonomy.py` and
contains 16 categories:

| Category | Description | Risk |
|----------|-------------|------|
| `file_path` | Drive-letter paths, device paths, system paths, PE references | MEDIUM |
| `registry_key` | Registry hives, keys, well-known paths | MEDIUM |
| `url` | HTTP/HTTPS/FTP/WSS/file URLs | HIGH |
| `rpc_endpoint` | ALPC, named-pipe, TCP RPC endpoint strings | HIGH |
| `named_pipe` | `\\.\pipe\...` paths | HIGH |
| `alpc_path` | ALPC port paths (`\RPC Control\`, `\BaseNamedObjects\`) | MEDIUM |
| `service_account` | NT AUTHORITY\*, LocalSystem, etc. | MEDIUM |
| `certificate` | Certificate file extensions (.cer, .pfx, .pem, etc.) | HIGH |
| `credentials` | Hardcoded passwords, API keys, tokens, auth headers | HIGH |
| `embedded_command` | Shell commands, PowerShell strings, WMI queries | HIGH |
| `source_path` | Build/source file paths leaked from compilation | LOW |
| `etw_provider` | `Microsoft-Windows-*` provider names | LOW |
| `guid` | `{xxxxxxxx-xxxx-...}` CLSID/IID patterns | LOW |
| `error_message` | Strings containing error/failure keywords (phrase context) | LOW |
| `format_string` | printf-style format specifiers | MEDIUM |
| `debug_trace` | TraceLogging/ETW/WPP keywords | LOW |

Strings matching no pattern are categorized as `uncategorized`.

## Risk Levels

The `CATEGORY_RISK` dict in `helpers/string_taxonomy.py` assigns a risk
level to each category. Risk is included in every string entry in the
output and used for sorting `top_referenced` (HIGH first).

| Risk | Categories |
|------|-----------|
| HIGH | `credentials`, `named_pipe`, `rpc_endpoint`, `url`, `certificate`, `embedded_command` |
| MEDIUM | `registry_key`, `alpc_path`, `format_string`, `file_path`, `service_account` |
| LOW | `source_path`, `error_message`, `guid`, `etw_provider`, `debug_trace` |

## Regex Patterns

Each pattern is a compiled `re.Pattern` with associated category and
description. The taxonomy is evaluated top-to-bottom; the first match wins.

Key patterns (see `helpers/string_taxonomy.py` for full list):

| Pattern | Category | Example Match |
|---------|----------|---------------|
| `^[A-Za-z]:\\` | file_path | `C:\Windows\System32\appinfo.dll` |
| `^\\\\[?.]\\` | file_path | `\\?\C:\long\path` |
| `\\Registry\\|HKEY_` | registry_key | `HKEY_LOCAL_MACHINE\SOFTWARE\...` |
| `https?://` | url | `https://example.com/api` |
| `ncalrpc:|ncacn_np:` | rpc_endpoint | `ncalrpc:[AppInfo]` |
| `\\\\.\\pipe\\` | named_pipe | `\\.\pipe\appinfo` |
| `\\RPC Control\\` | alpc_path | `\RPC Control\AppInfo` |
| `NT AUTHORITY\\` | service_account | `NT AUTHORITY\SYSTEM` |
| `\.(?:cer|pfx|pem)$` | certificate | `server.pfx` |
| `\bpassword\|passwd\|pwd\b.*[:=]` | credentials | `password=admin123` |
| `\bapi[_-]?key\b.*[:=]` | credentials | `api_key=sk-abc123` |
| `\bcmd(.exe)?\s+/[ckr]` | embedded_command | `cmd /c whoami` |
| `\bpowershell(.exe)?` | embedded_command | `powershell -enc ...` |
| `SELECT.*FROM.*Win32_` | embedded_command | `SELECT * FROM Win32_Process` |
| `Microsoft-Windows-` | etw_provider | `Microsoft-Windows-AppInfo` |
| `\{[0-9a-f]{8}-...` | guid | `{12345678-1234-...}` |
| `%[-+0 #]*...` | format_string | `%s: error %d` |
| `\.(?:cpp|cxx|hpp|h)$` | source_path | `onecore\...\launch.cxx` |
| `onecore\\|onecoreuap\\` | source_path | `onecore\base\appmodel\...` |

## Category-to-Classification Mapping

The `TAXONOMY_TO_CLASSIFICATION` dict maps string categories to the coarser
classification categories used by `classify-functions`:

| String Category | Classification Category |
|----------------|----------------------|
| `registry_key` | `registry` |
| `url` | `network` |
| `rpc_endpoint` | `rpc` |
| `named_pipe` | `rpc` |
| `alpc_path` | `rpc` |
| `service_account` | `security` |
| `certificate` | `crypto` |
| `credentials` | `security` |
| `embedded_command` | `security` |
| `etw_provider` | `telemetry` |
| `format_string` | `data_parsing` |

Categories not listed here (`file_path`, `source_path`, `guid`,
`error_message`, `debug_trace`) do not contribute to function
classification scoring.

## Output Schema

### Module-Wide Analysis

```json
{
  "status": "ok",
  "categories": {
    "<category>": [
      {
        "string": "the string value",
        "functions": ["func1", "func2"],
        "function_count": 2,
        "description": "pattern description",
        "risk": "HIGH"
      }
    ]
  },
  "summary": {"<category>": "<unique_string_count>"},
  "total_unique_strings": 300,
  "total_string_refs": 850,
  "uncategorized_count": 45,
  "uncategorized_sample": ["first 50 uncategorized strings"],
  "top_referenced": [
    {"string": "...", "category": "...", "function_count": 12, "risk": "HIGH", "functions": ["..."]}
  ],
  "top_functions": [
    {"function": "FuncName", "string_count": 42}
  ],
  "_meta": {
    "db": "path/to/db",
    "generated": "ISO8601",
    "params": {"function_id": null, "function_name": null, "top": 10, "category": null}
  }
}
```

**Filtering**: `--top N` limits entries per category, `top_referenced`,
and `top_functions` to N items. `--category <name>` restricts output to
a single category. Both flags apply in `--json` and human-readable modes.

**Sorting**: `top_referenced` is sorted by risk (HIGH first), then by
`function_count` descending.

### Single-Function Analysis

Same structure, but `categories` only contains strings from the target
function. The `functions` list in each entry will contain only the target
function name.
