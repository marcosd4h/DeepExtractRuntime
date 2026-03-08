---
description: Error handling conventions for skill and agent scripts
globs:
  - ".agent/skills/*/scripts/*.py"
  - ".agent/agents/*/scripts/*.py"
  - ".agent/helpers/*.py"
alwaysApply: true
---

# Error Handling Convention

## Layer-Based Error Handling

Use different error mechanisms depending on the code layer:

### Entry-Point Scripts (`if __name__ == "__main__"`)

Use `emit_error(message, code)` from `helpers.errors` for fatal errors.
This writes structured JSON to stderr and exits with code 1.

```python
from helpers.errors import emit_error, ErrorCode

if not args.db_path:
    emit_error("No database path provided", ErrorCode.INVALID_ARGS)
```

### Library / Helper Functions

Raise `ScriptError(message, code)` from `helpers.errors` so callers
retain control over the error:

```python
from helpers.errors import ScriptError, ErrorCode

def resolve_something(name):
    if not found:
        raise ScriptError(f"Not found: {name}", ErrorCode.NOT_FOUND)
```

### Non-Fatal Conditions

Use `log_warning(message, code)` for issues that should be visible
but don't require aborting:

```python
from helpers.errors import log_warning

log_warning("Cache expired, recomputing", "DB_ERROR")
```

### Database Operations

Wrap DB access with `db_error_handler(db_path, operation)` context
manager, which catches SQLite exceptions and emits structured errors:

```python
with db_error_handler(db_path, "loading functions"):
    db = open_individual_analysis_db(db_path)
```

### Mandatory DB Wrapping

Every entry-point script (`if __name__ == "__main__"`) that opens a
database MUST wrap the DB access with `db_error_handler`. No direct
`open_individual_analysis_db()` or `open_analyzed_files_db()` call
should exist outside a `db_error_handler` context in an entry-point
script. Library functions may raise `ScriptError` instead.

### Argparse Error Wrapping

Entry-point scripts MUST use `safe_parse_args(parser)` from
`helpers.errors` instead of calling `parser.parse_args()` directly.
This suppresses argparse's built-in stderr output and emits only
structured `INVALID_ARGS` JSON on error:

```python
from helpers.errors import safe_parse_args

args = safe_parse_args(parser)
```

Do NOT use the manual `try/except SystemExit` pattern -- it does not
suppress argparse's usage text from appearing on stderr before the
structured error.

### Empty Search Results

When a `--search` pattern under `--json` mode yields zero matches,
emit `NO_DATA` (not `status: ok` with an empty list):

```python
if args.pattern and not rows:
    emit_error(f"No functions matching '{args.pattern}'", ErrorCode.NO_DATA)
```

Without `--search`, an empty result set is a valid `status: ok` response
(e.g. a DB with no functions).

## Error Codes

Always use `ErrorCode` enum values:
- `NOT_FOUND` -- entity does not exist
- `INVALID_ARGS` -- bad command-line arguments
- `DB_ERROR` -- database open/query failure
- `PARSE_ERROR` -- JSON/assembly parse failure
- `NO_DATA` -- query succeeded, empty results
- `AMBIGUOUS` -- multiple matches when one expected
- `UNKNOWN` -- catch-all
