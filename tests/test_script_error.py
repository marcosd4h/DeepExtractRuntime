"""Tests for helpers.errors -- ScriptError exception class and error utilities.

Target: .agent/helpers/errors.py
"""

from __future__ import annotations

import json
import sys

import pytest

from helpers.errors import (
    ErrorCode,
    ScriptError,
    emit_error,
    log_error,
    log_warning,
)


class TestScriptError:
    """Test the new ScriptError exception class."""

    def test_basic_creation(self):
        err = ScriptError("something failed", ErrorCode.NOT_FOUND)
        assert str(err) == "something failed"
        assert err.code == "NOT_FOUND"

    def test_string_code(self):
        err = ScriptError("bad input", "INVALID_ARGS")
        assert err.code == "INVALID_ARGS"

    def test_enum_code_converted(self):
        err = ScriptError("db error", ErrorCode.DB_ERROR)
        assert err.code == "DB_ERROR"
        assert isinstance(err.code, str)

    def test_default_code(self):
        err = ScriptError("unknown issue")
        assert err.code == "UNKNOWN"

    def test_is_exception(self):
        err = ScriptError("test")
        assert isinstance(err, Exception)

    def test_can_be_raised_and_caught(self):
        with pytest.raises(ScriptError) as exc_info:
            raise ScriptError("test error", ErrorCode.PARSE_ERROR)
        assert exc_info.value.code == "PARSE_ERROR"
        assert "test error" in str(exc_info.value)

    def test_catch_as_generic_exception(self):
        """ScriptError should be catchable as a regular Exception."""
        caught = False
        try:
            raise ScriptError("test", ErrorCode.NO_DATA)
        except Exception as e:
            caught = True
            assert hasattr(e, "code")
            assert e.code == "NO_DATA"
        assert caught


class TestEmitError:
    """Test emit_error exits with code 1."""

    def test_exits_with_code_1(self):
        with pytest.raises(SystemExit) as exc_info:
            emit_error("test", ErrorCode.INVALID_ARGS)
        assert exc_info.value.code == 1

    def test_stderr_json(self, capsys):
        with pytest.raises(SystemExit):
            emit_error("test message", "TEST_CODE")
        captured = capsys.readouterr()
        parsed = json.loads(captured.err.strip())
        assert parsed["error"] == "test message"
        assert parsed["code"] == "TEST_CODE"


class TestLogError:
    """Test log_error writes to stderr without exiting."""

    def test_does_not_exit(self, capsys):
        log_error("non-fatal error", ErrorCode.DB_ERROR)
        captured = capsys.readouterr()
        parsed = json.loads(captured.err.strip())
        assert parsed["error"] == "non-fatal error"


class TestLogWarning:
    """Test log_warning writes warning format to stderr."""

    def test_warning_format(self, capsys):
        log_warning("cache miss", ErrorCode.NO_DATA)
        captured = capsys.readouterr()
        parsed = json.loads(captured.err.strip())
        assert "warning" in parsed
        assert parsed["warning"] == "cache miss"
