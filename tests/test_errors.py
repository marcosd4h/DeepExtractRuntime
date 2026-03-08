import pytest
import sys
import json
from helpers.errors import ErrorCode, emit_error, log_error

def test_error_code_enum():
    assert ErrorCode.NOT_FOUND == "NOT_FOUND"
    assert ErrorCode.AMBIGUOUS == "AMBIGUOUS"

def test_log_error(capsys):
    log_error("test message", ErrorCode.INVALID_ARGS)
    captured = capsys.readouterr()
    data = json.loads(captured.err.strip())
    assert data["error"] == "test message"
    assert data["code"] == "INVALID_ARGS"

def test_emit_error(monkeypatch, capsys):
    # emit_error calls sys.exit(1), so we need to catch it
    with pytest.raises(SystemExit) as excinfo:
        emit_error("fatal error", ErrorCode.DB_ERROR)
    
    assert excinfo.value.code == 1
    captured = capsys.readouterr()
    data = json.loads(captured.err.strip())
    assert data["error"] == "fatal error"
    assert data["code"] == "DB_ERROR"
