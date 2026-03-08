"""Tests for helpers.json_output (High fix #5).

Verifies that emit_json and emit_json_list:
- Always include a "status" key
- Preserve existing dict keys
- Handle list payloads correctly
- Support custom default and ensure_ascii
- Raise TypeError on non-dict input to emit_json
"""

from __future__ import annotations

import json
import sys
from io import StringIO

import pytest

from helpers.json_output import emit_json, emit_json_list


def _capture_json(func, *args, **kwargs) -> dict:
    """Call func and return the parsed JSON from stdout."""
    buf = StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        func(*args, **kwargs)
    finally:
        sys.stdout = old
    return json.loads(buf.getvalue())


class TestEmitJson:

    def test_adds_status_ok(self):
        result = _capture_json(emit_json, {"key": "value"})
        assert result["status"] == "ok"
        assert result["key"] == "value"

    def test_preserves_all_keys(self):
        data = {"module": "test.dll", "functions": [1, 2, 3], "count": 42}
        result = _capture_json(emit_json, data)
        assert result["module"] == "test.dll"
        assert result["functions"] == [1, 2, 3]
        assert result["count"] == 42
        assert result["status"] == "ok"

    def test_custom_status(self):
        result = _capture_json(emit_json, {"info": "partial"}, status="partial")
        assert result["status"] == "partial"

    def test_existing_status_preserved(self):
        result = _capture_json(emit_json, {"status": "already_set", "data": 1})
        assert result["status"] == "already_set"

    def test_default_for_nonserializable(self):
        from pathlib import Path
        result = _capture_json(emit_json, {"path": Path("/tmp/test")}, default=str)
        assert "tmp" in result["path"]

    def test_ensure_ascii(self):
        buf = StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            emit_json({"text": "caf\u00e9"}, ensure_ascii=True)
        finally:
            sys.stdout = old
        raw = buf.getvalue()
        assert "\\u00e9" in raw
        parsed = json.loads(raw)
        assert parsed["text"] == "caf\u00e9"

    def test_rejects_non_dict(self):
        with pytest.raises(TypeError, match="expects a dict"):
            emit_json([1, 2, 3])

    def test_rejects_string(self):
        with pytest.raises(TypeError, match="expects a dict"):
            emit_json("hello")

    def test_empty_dict(self):
        result = _capture_json(emit_json, {})
        assert result == {"status": "ok"}

    def test_nested_data(self):
        data = {
            "summary": {"total": 10, "passed": 8},
            "items": [{"id": 1}, {"id": 2}],
        }
        result = _capture_json(emit_json, data)
        assert result["summary"]["total"] == 10
        assert len(result["items"]) == 2


class TestEmitJsonList:

    def test_wraps_list_with_status(self):
        result = _capture_json(emit_json_list, "entrypoints", [{"name": "ep1"}, {"name": "ep2"}])
        assert result["status"] == "ok"
        assert len(result["entrypoints"]) == 2

    def test_custom_key(self):
        result = _capture_json(emit_json_list, "functions", [1, 2, 3])
        assert result["functions"] == [1, 2, 3]

    def test_extra_keys(self):
        result = _capture_json(emit_json_list, "items", [1], extra={"total": 100, "page": 1})
        assert result["total"] == 100
        assert result["page"] == 1
        assert result["items"] == [1]

    def test_empty_list(self):
        result = _capture_json(emit_json_list, "results", [])
        assert result["results"] == []
        assert result["status"] == "ok"

    def test_default_for_nonserializable(self):
        from pathlib import Path
        result = _capture_json(emit_json_list, "paths", [Path("/a"), Path("/b")], default=str)
        assert len(result["paths"]) == 2

    def test_custom_status(self):
        result = _capture_json(emit_json_list, "items", [], status="error")
        assert result["status"] == "error"


class TestOutputFormat:

    def test_output_is_valid_json(self):
        buf = StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            emit_json({"key": "value"})
        finally:
            sys.stdout = old
        parsed = json.loads(buf.getvalue())
        assert isinstance(parsed, dict)

    def test_output_ends_with_newline(self):
        buf = StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            emit_json({"key": "value"})
        finally:
            sys.stdout = old
        assert buf.getvalue().endswith("\n")

    def test_output_is_indented(self):
        buf = StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            emit_json({"key": "value"})
        finally:
            sys.stdout = old
        lines = buf.getvalue().strip().split("\n")
        assert len(lines) > 1, "Output should be multi-line (indented)"
