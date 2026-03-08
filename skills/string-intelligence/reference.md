# String Intelligence -- Reference

## Contents

- [String Categories](#string-categories)
- [Regex Patterns](#regex-patterns)
- [Category-to-Classification Mapping](#category-to-classification-mapping)
- [Output Schema](#output-schema)

## String Categories

The canonical taxonomy is defined in `helpers/string_taxonomy.py` and
contains 13 categories:

| Category | Description | Security Value |
|----------|-------------|----------------|
| `file_path` | Drive-letter paths, device paths, system paths, PE references | Medium-High |
| `registry_key` | Registry hives, keys, well-known paths | High |
| `url` | HTTP/HTTPS/FTP/WSS/file URLs | High |
| `rpc_endpoint` | ALPC, named-pipe, TCP RPC endpoint strings | High |
| `named_pipe` | `\\.\pipe\...` paths | High |
| `alpc_path` | ALPC port paths (`\RPC Control\`, `\BaseNamedObjects\`) | High |
| `service_account` | NT AUTHORITY\*, LocalSystem, etc. | Medium |
| `certificate` | Certificate file extensions (.cer, .pfx, .pem, etc.) | High |
| `etw_provider` | `Microsoft-Windows-*` provider names | Low |
| `guid` | `{xxxxxxxx-xxxx-...}` CLSID/IID patterns | Medium |
| `error_message` | Strings containing error/failure keywords (phrase context) | Low |
| `format_string` | printf-style format specifiers | Medium |
| `debug_trace` | TraceLogging/ETW/WPP keywords | Low |

Strings matching no pattern are categorized as `uncategorized`.

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
| `Microsoft-Windows-` | etw_provider | `Microsoft-Windows-AppInfo` |
| `\{[0-9a-f]{8}-...` | guid | `{12345678-1234-...}` |
| `%[-+0 #]*...` | format_string | `%s: error %d` |

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
| `etw_provider` | `telemetry` |
| `format_string` | `data_parsing` |

Categories not listed here (`file_path`, `guid`, `error_message`,
`debug_trace`) do not contribute to function classification scoring.

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
        "count": 2,
        "description": "pattern description"
      }
    ]
  },
  "summary": {"<category>": <unique_string_count>},
  "total_unique_strings": 300,
  "total_string_refs": 850,
  "uncategorized_count": 45,
  "uncategorized_sample": ["first 50 uncategorized strings"],
  "top_referenced": [
    {"string": "...", "category": "...", "count": 12, "functions": [...]}
  ],
  "_meta": {
    "db": "path/to/db",
    "generated": "ISO8601",
    "params": {"function_id": null, "top": 10}
  }
}
```

### Single-Function Analysis

Same structure, but `categories` only contains strings from the target
function. The `functions` list in each entry will contain only the target
function name.
