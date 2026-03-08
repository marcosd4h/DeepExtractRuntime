---
description: Convention for discovering function calls in decompiled code
globs:
  - ".agent/skills/*/scripts/*.py"
  - ".agent/agents/*/scripts/*.py"
  - ".agent/helpers/*.py"
alwaysApply: true
---

# Call Discovery Convention

## Ground Truth: `simple_outbound_xrefs`

When discovering which APIs a function calls, ALWAYS use
`simple_outbound_xrefs` from the analysis DB as the authoritative
source. IDA's extraction is complete and handles multi-line calls,
indirect calls, and vtable calls that regex parsing cannot.

## Regex Parser: Argument Extraction Only

Use `extract_function_calls()` from `helpers.decompiled_parser` ONLY
when you need argument expressions, line numbers, or `result_var`.
The regex parser handles multi-line calls but may still miss edge
cases that IDA captures.

## Preferred Pattern

For scripts that need both call discovery and argument details, use
`discover_calls_with_xrefs()` which merges xref ground truth with
parser argument data:

```python
from helpers.decompiled_parser import discover_calls_with_xrefs

all_calls = discover_calls_with_xrefs(code, func_record["outbound_xrefs"])
```

The function uses `simple_outbound_xrefs` for authoritative call
discovery, then enriches with argument expressions from the regex
parser where available. Calls that appear only in xrefs (missed by
the parser) are included with empty argument lists.

## Forbidden Pattern

NEVER use `extract_function_calls()` alone for call discovery when
DB xrefs are available. This produces false negatives for multi-line
calls and other formatting variations.

```python
# BAD -- misses multi-line calls
calls = extract_function_calls(code)

# GOOD -- xref ground truth + parser args
calls = discover_calls_with_xrefs(code, func.get("outbound_xrefs", []))
```
