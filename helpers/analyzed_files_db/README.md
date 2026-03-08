# analyzed_files_db helper

This helper provides read-only access to the `analyzed_files` tracking table in
`extracted_dbs/analyzed_files.db`. It is designed to be imported by external
Python scripts or Cursor skills without extra dependencies.

## Quick start

```python
from helpers.analyzed_files_db import AnalyzedFilesDB

with AnalyzedFilesDB("extracted_dbs/analyzed_files.db") as db:
    for record in db.get_complete():
        print(record.file_name, record.analysis_db_path)
```

## Shortcuts

```python
from helpers.analyzed_files_db import open_analyzed_files_db

with open_analyzed_files_db() as db:
    print(db.list_statuses())
```

## Import options

```python
# Direct module import
from helpers.analyzed_files_db import AnalyzedFilesDB, AnalyzedFileRecord

# Convenience import
from helpers.analyzed_files_db import open_analyzed_files_db
```

## Common queries

```python
with AnalyzedFilesDB() as db:
    by_path = db.get_by_file_path(r"C:\Windows\System32\cmd.exe")
    by_name = db.get_by_file_name("cmd.exe")
    by_ext = db.get_by_extension(".dll")
    by_md5 = db.get_by_hash("deadbeef...", "md5")
    counts = db.count_by_status()
    pending = db.get_pending()
```

## Search helpers

```python
with AnalyzedFilesDB() as db:
    results = db.search(
        status="COMPLETE",
        extension=".dll",
        name_contains="api",
    )
```

## Record fields

Each `AnalyzedFileRecord` maps the `analyzed_files` table columns:

- `file_path`, `base_dir`, `file_name`, `file_extension`
- `md5_hash`, `sha256_hash`
- `analysis_db_path`
- `status`
- `analysis_flags` (raw JSON string)
- `analysis_start_timestamp`, `analysis_completion_timestamp`

For convenience, `AnalyzedFileRecord.parsed_analysis_flags` returns the JSON
decoded dictionary (or `None` if empty or invalid).

## Notes

- Connections are read-only (`mode=ro`) and enforce `PRAGMA query_only = ON`.
- If no DB path is passed, the helper searches for
  `extracted_dbs/analyzed_files.db` relative to the project root or cwd.
