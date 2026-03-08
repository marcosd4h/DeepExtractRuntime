"""Tests for helpers.session_utils -- session ID resolution and hook input."""

import io
import json
import os
import sys
import pytest
from unittest import mock

from helpers.session_utils import resolve_session_id, read_hook_input


class TestResolveSessionId:
    def test_env_var_takes_priority(self, monkeypatch):
        monkeypatch.setenv("AGENT_SESSION_ID", "env-session-42")
        result = resolve_session_id({"conversation_id": "conv-1", "session_id": "sess-1"})
        assert result == "env-session-42"

    def test_conversation_id_fallback(self, monkeypatch):
        monkeypatch.delenv("AGENT_SESSION_ID", raising=False)
        result = resolve_session_id({"conversation_id": "conv-99"})
        assert result == "conv-99"

    def test_session_id_fallback(self, monkeypatch):
        monkeypatch.delenv("AGENT_SESSION_ID", raising=False)
        result = resolve_session_id({"session_id": "sess-77"})
        assert result == "sess-77"

    def test_uuid_fallback(self, monkeypatch):
        monkeypatch.delenv("AGENT_SESSION_ID", raising=False)
        result = resolve_session_id({})
        assert len(result) == 36  # UUID4 format

    def test_none_stdin_data(self, monkeypatch):
        monkeypatch.delenv("AGENT_SESSION_ID", raising=False)
        result = resolve_session_id(None)
        assert len(result) == 36  # UUID4 fallback


class TestReadHookInput:
    def test_valid_json(self):
        payload = json.dumps({"session_id": "test-123"})
        with mock.patch("sys.stdin", io.StringIO(payload)):
            result = read_hook_input()
        assert result == {"session_id": "test-123"}

    def test_empty_stdin(self):
        with mock.patch("sys.stdin", io.StringIO("")):
            result = read_hook_input()
        assert result == {}

    def test_whitespace_only(self):
        with mock.patch("sys.stdin", io.StringIO("   \n  ")):
            result = read_hook_input()
        assert result == {}

    def test_invalid_json(self):
        with mock.patch("sys.stdin", io.StringIO("not json at all")):
            result = read_hook_input()
        assert result == {}
