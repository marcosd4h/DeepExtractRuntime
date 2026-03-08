Individual Analysis DB Helper
=============================

This helper module provides read-only access to a single per-binary DeepExtract
SQLite database (the files under `extracted_dbs/` like `cmd_exe_*.db`).

Quick start
-----------

Import from the package (preferred):

```python
from helpers.individual_analysis_db import open_individual_analysis_db

with open_individual_analysis_db("extracted_dbs/cmd_exe_6d109a3a00.db") as db:
    info = db.get_file_info()
    if info:
        print(info.file_name, info.parsed_security_features)
```

You can also import from the top-level `helpers` package:

```python
from helpers import IndividualAnalysisDB

db = IndividualAnalysisDB("extracted_dbs/cmd_exe_6d109a3a00.db")
try:
    functions = db.search_functions(name_contains="Create", has_decompiled_code=True)
    for func in functions:
        print(func.function_name, func.parsed_dangerous_api_calls)
finally:
    db.close()
```

API overview
------------

Classes:
- `IndividualAnalysisDB` -- read-only DB wrapper and query methods.
- `FileInfoRecord` -- row in the `file_info` table.
- `FunctionRecord` -- row in the `functions` table.

Common queries:
- `get_file_info() -> FileInfoRecord | None`
- `get_file_info_field(field_name: str) -> Any`
- `get_function_by_id(function_id: int) -> FunctionRecord | None`
- `get_function_by_name(name: str, case_insensitive: bool = True) -> list[FunctionRecord]`
- `get_function_by_mangled_name(name: str, case_insensitive: bool = True) -> list[FunctionRecord]`
- `search_functions_by_signature(pattern: str, case_insensitive: bool = True) -> list[FunctionRecord]`
- `get_all_functions(limit: int | None = None, offset: int | None = None) -> list[FunctionRecord]`
- `count_functions() -> int`
- `search_functions(...) -> list[FunctionRecord]` for combined filters
- `get_function_names() -> list[str]`
- `execute_query(sql: str, params: Iterable[Any]) -> list[sqlite3.Row]`

JSON fields
-----------

Many columns in `file_info` and `functions` are stored as JSON strings. Each
record provides `parsed_*` properties that return decoded JSON (or `None` if
missing/invalid). Examples:

```python
info = db.get_file_info()
imports = info.parsed_imports if info else None

func = db.get_function_by_id(123)
outbound = func.parsed_outbound_xrefs if func else None
```

Notes
-----

- Connections are opened read-only with `PRAGMA query_only = ON`.
- This module does not modify the database; it is safe for concurrent readers.
