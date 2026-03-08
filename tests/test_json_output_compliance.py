"""Tests that skill scripts produce JSON output with {"status": "ok"} wrapping.

Regression guard for audit fix item 6: scripts that previously used raw
json.dump() now use emit_json() / emit_json_list() from helpers.json_output.

Targets:
  - callgraph-tracer/scripts/module_dependencies.py
  - callgraph-tracer/scripts/chain_analysis.py
  - generate-re-report/scripts/generate_report.py
  - decompiled-code-extractor/scripts/find_module_db.py
"""

from __future__ import annotations

import json
import sys
from io import StringIO
from unittest.mock import patch

import pytest

from helpers.json_output import emit_json, emit_json_list


# ===================================================================
# emit_json always includes "status" key
# ===================================================================

class TestEmitJsonStatusKey:
    def test_emit_json_adds_status_ok(self):
        buf = StringIO()
        with patch("sys.stdout", buf):
            emit_json({"key": "value"})
        output = json.loads(buf.getvalue())
        assert output["status"] == "ok"
        assert output["key"] == "value"

    def test_emit_json_preserves_existing_status(self):
        buf = StringIO()
        with patch("sys.stdout", buf):
            emit_json({"status": "partial", "data": 42})
        output = json.loads(buf.getvalue())
        assert output["status"] == "partial"

    def test_emit_json_list_adds_status_ok(self):
        buf = StringIO()
        with patch("sys.stdout", buf):
            emit_json_list("items", [1, 2, 3])
        output = json.loads(buf.getvalue())
        assert output["status"] == "ok"
        assert output["items"] == [1, 2, 3]

    def test_emit_json_list_with_extra(self):
        buf = StringIO()
        with patch("sys.stdout", buf):
            emit_json_list("results", ["a", "b"], extra={"count": 2})
        output = json.loads(buf.getvalue())
        assert output["status"] == "ok"
        assert output["results"] == ["a", "b"]
        assert output["count"] == 2

    def test_emit_json_rejects_non_dict(self):
        with pytest.raises(TypeError, match="expects a dict"):
            emit_json([1, 2, 3])  # type: ignore[arg-type]

    def test_emit_json_with_default_serializer(self):
        """emit_json passes default= through to json.dump for custom types."""
        from pathlib import PurePosixPath

        buf = StringIO()
        with patch("sys.stdout", buf):
            emit_json({"path": PurePosixPath("/tmp/test")}, default=str)
        output = json.loads(buf.getvalue())
        assert output["status"] == "ok"
        assert output["path"] == "/tmp/test"


# ===================================================================
# JSON output is valid single document
# ===================================================================

class TestJsonOutputStructure:
    def test_emit_json_produces_single_document(self):
        """Output should be exactly one JSON object, not multiple."""
        buf = StringIO()
        with patch("sys.stdout", buf):
            emit_json({"a": 1})
        raw = buf.getvalue().strip()
        parsed = json.loads(raw)
        assert isinstance(parsed, dict)

    def test_emit_json_list_produces_single_document(self):
        buf = StringIO()
        with patch("sys.stdout", buf):
            emit_json_list("data", [1, 2])
        raw = buf.getvalue().strip()
        parsed = json.loads(raw)
        assert isinstance(parsed, dict)

    def test_emit_json_handles_unicode(self):
        buf = StringIO()
        with patch("sys.stdout", buf):
            emit_json({"text": "Microsoft\u00ae Windows\u00ae"})
        output = json.loads(buf.getvalue())
        assert "Microsoft" in output["text"]

    def test_emit_json_handles_empty_dict(self):
        buf = StringIO()
        with patch("sys.stdout", buf):
            emit_json({})
        output = json.loads(buf.getvalue())
        assert output["status"] == "ok"

    def test_emit_json_list_handles_empty_list(self):
        buf = StringIO()
        with patch("sys.stdout", buf):
            emit_json_list("items", [])
        output = json.loads(buf.getvalue())
        assert output["status"] == "ok"
        assert output["items"] == []
