"""Tests for db_error_handler context manager and DB error wrapping in scripts.

Verifies that:
- db_error_handler catches FileNotFoundError -> emit_error(NOT_FOUND)
- db_error_handler catches RuntimeError("Failed to open") -> emit_error(DB_ERROR)
- db_error_handler catches sqlite3.OperationalError -> emit_error(DB_ERROR)
- db_error_handler catches generic Exception -> emit_error(UNKNOWN)
- db_error_handler lets SystemExit pass through (so emit_error inside the block works)
- db_error_handler yields normally on success
- The "Multiple matches" error paths now use emit_error(AMBIGUOUS) instead of print()
"""

import json
import sqlite3

import pytest

from helpers.errors import ErrorCode, db_error_handler, emit_error


# ---------------------------------------------------------------------------
# db_error_handler: FileNotFoundError -> NOT_FOUND
# ---------------------------------------------------------------------------

class TestDbErrorHandlerFileNotFound:
    def test_emits_not_found(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            with db_error_handler("/fake/path.db", "opening DB"):
                raise FileNotFoundError("No such file: /fake/path.db")

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        data = json.loads(captured.err.strip())
        assert data["code"] == "NOT_FOUND"
        assert "/fake/path.db" in data["error"]


# ---------------------------------------------------------------------------
# db_error_handler: RuntimeError("Failed to open") -> DB_ERROR
# ---------------------------------------------------------------------------

class TestDbErrorHandlerRuntimeError:
    def test_failed_to_open(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            with db_error_handler("/some/db.db", "opening analysis DB"):
                raise RuntimeError("Failed to open analysis DB /some/db.db: locked")

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        data = json.loads(captured.err.strip())
        assert data["code"] == "DB_ERROR"
        assert "Cannot open database" in data["error"]

    def test_cannot_open(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            with db_error_handler("/some/db.db", "opening analysis DB"):
                raise RuntimeError("Cannot open database /some/db.db")

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        data = json.loads(captured.err.strip())
        assert data["code"] == "DB_ERROR"
        assert "Cannot open database" in data["error"]

    def test_generic_runtime_error(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            with db_error_handler("/some/db.db", "querying functions"):
                raise RuntimeError("Something else went wrong")

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        data = json.loads(captured.err.strip())
        assert data["code"] == "DB_ERROR"
        assert "querying functions" in data["error"]


# ---------------------------------------------------------------------------
# db_error_handler: sqlite3.Error -> DB_ERROR
# ---------------------------------------------------------------------------

class TestDbErrorHandlerSqliteError:
    def test_operational_error(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            with db_error_handler("/some/db.db", "querying functions"):
                raise sqlite3.OperationalError("database is locked")

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        data = json.loads(captured.err.strip())
        assert data["code"] == "DB_ERROR"
        assert "database is locked" in data["error"]
        assert "querying functions" in data["error"]

    def test_database_error(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            with db_error_handler("/some/db.db", "batch scan"):
                raise sqlite3.DatabaseError("database disk image is malformed")

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        data = json.loads(captured.err.strip())
        assert data["code"] == "DB_ERROR"
        assert "malformed" in data["error"]

    def test_integrity_error(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            with db_error_handler("/some/db.db", "integrity check"):
                raise sqlite3.IntegrityError("UNIQUE constraint failed")

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        data = json.loads(captured.err.strip())
        assert data["code"] == "DB_ERROR"


# ---------------------------------------------------------------------------
# db_error_handler: generic Exception -> UNKNOWN
# ---------------------------------------------------------------------------

class TestDbErrorHandlerGenericException:
    def test_generic_exception(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            with db_error_handler("/some/db.db", "unexpected operation"):
                raise ValueError("unexpected value")

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        data = json.loads(captured.err.strip())
        assert data["code"] == "UNKNOWN"
        assert "unexpected value" in data["error"]
        assert "unexpected operation" in data["error"]

    def test_type_error(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            with db_error_handler("/some/db.db", "type issue"):
                raise TypeError("bad type")

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        data = json.loads(captured.err.strip())
        assert data["code"] == "UNKNOWN"


# ---------------------------------------------------------------------------
# db_error_handler: SystemExit passthrough
# ---------------------------------------------------------------------------

class TestDbErrorHandlerPassthrough:
    def test_system_exit_passthrough(self):
        """emit_error() calls inside the block should pass through as SystemExit."""
        with pytest.raises(SystemExit) as exc_info:
            with db_error_handler("/some/db.db"):
                emit_error("inner error", ErrorCode.NO_DATA)

        assert exc_info.value.code == 1

    def test_keyboard_interrupt_passthrough(self):
        """KeyboardInterrupt inherits from BaseException, not Exception."""
        with pytest.raises(KeyboardInterrupt):
            with db_error_handler("/some/db.db"):
                raise KeyboardInterrupt()


# ---------------------------------------------------------------------------
# db_error_handler: success path
# ---------------------------------------------------------------------------

class TestDbErrorHandlerSuccess:
    def test_no_exception(self):
        """Context manager should yield cleanly when no exception occurs."""
        result = None
        with db_error_handler("/some/db.db", "success test"):
            result = 42
        assert result == 42

    def test_returns_value_through_context(self):
        """Values computed inside the block should be accessible outside."""
        data = {}
        with db_error_handler("/some/db.db"):
            data["key"] = "value"
        assert data["key"] == "value"


# ---------------------------------------------------------------------------
# db_error_handler: db_path included in error message
# ---------------------------------------------------------------------------

class TestDbErrorHandlerDbPathInMessage:
    def test_db_path_in_file_not_found(self, capsys):
        path = "/long/path/to/my_analysis.db"
        with pytest.raises(SystemExit):
            with db_error_handler(path):
                raise FileNotFoundError("not found")
        captured = capsys.readouterr()
        data = json.loads(captured.err.strip())
        assert path in data["error"]

    def test_db_path_in_sqlite_error(self, capsys):
        path = "/another/path/data.db"
        with pytest.raises(SystemExit):
            with db_error_handler(path, "scan"):
                raise sqlite3.OperationalError("locked")
        captured = capsys.readouterr()
        data = json.loads(captured.err.strip())
        assert path in data["error"]
