"""Tests for helpers.session_utils -- session ID resolution, hook input,
platform detection, and cross-platform output helpers."""

import io
import json
import os
import sys
import pytest
from unittest import mock

from helpers.session_utils import (
    resolve_session_id,
    read_hook_input,
    detect_hook_platform,
    emit_session_start_output,
    emit_stop_output,
    _persist_env_claude_code,
    PLATFORM_CLAUDE_CODE,
    PLATFORM_CURSOR,
)


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


# ===================================================================
# detect_hook_platform
# ===================================================================


class TestDetectHookPlatform:
    def test_empty_dict_returns_cursor(self):
        assert detect_hook_platform({}) == PLATFORM_CURSOR

    def test_none_returns_cursor(self):
        assert detect_hook_platform(None) == PLATFORM_CURSOR

    def test_cursor_payload_no_hook_event(self):
        assert detect_hook_platform({"conversation_id": "c-1"}) == PLATFORM_CURSOR

    def test_claude_code_stop_event(self):
        assert detect_hook_platform({"hook_event_name": "Stop"}) == PLATFORM_CLAUDE_CODE

    def test_claude_code_session_start_event(self):
        payload = {"hook_event_name": "SessionStart", "session_id": "s-1"}
        assert detect_hook_platform(payload) == PLATFORM_CLAUDE_CODE

    def test_claude_code_with_extra_fields(self):
        payload = {"hook_event_name": "Stop", "transcript_so_far": "..."}
        assert detect_hook_platform(payload) == PLATFORM_CLAUDE_CODE


# ===================================================================
# emit_session_start_output
# ===================================================================


class TestEmitSessionStartOutput:
    def test_cursor_format(self):
        result = emit_session_start_output("ctx-text", "sid-1", PLATFORM_CURSOR)
        assert result == {
            "env": {"AGENT_SESSION_ID": "sid-1"},
            "additional_context": "ctx-text",
        }

    def test_claude_code_format(self, monkeypatch, tmp_path):
        env_file = tmp_path / "env"
        env_file.touch()
        monkeypatch.setenv("CLAUDE_ENV_FILE", str(env_file))
        result = emit_session_start_output("ctx-text", "sid-2", PLATFORM_CLAUDE_CODE)
        assert "hookSpecificOutput" in result
        hso = result["hookSpecificOutput"]
        assert hso["hookEventName"] == "SessionStart"
        assert hso["additionalContext"] == "ctx-text"
        assert "env" not in result

    def test_claude_code_persists_session_id(self, monkeypatch, tmp_path):
        env_file = tmp_path / "env"
        env_file.touch()
        monkeypatch.setenv("CLAUDE_ENV_FILE", str(env_file))
        emit_session_start_output("ctx", "my-sess-id", PLATFORM_CLAUDE_CODE)
        contents = env_file.read_text(encoding="utf-8")
        assert "AGENT_SESSION_ID" in contents
        assert "my-sess-id" in contents

    def test_cursor_does_not_touch_env_file(self, monkeypatch, tmp_path):
        env_file = tmp_path / "env"
        env_file.touch()
        monkeypatch.setenv("CLAUDE_ENV_FILE", str(env_file))
        emit_session_start_output("ctx", "sid-3", PLATFORM_CURSOR)
        assert env_file.read_text(encoding="utf-8") == ""

    def test_output_is_json_serializable(self):
        for platform in (PLATFORM_CURSOR, PLATFORM_CLAUDE_CODE):
            result = emit_session_start_output("context", "sid", platform)
            serialized = json.dumps(result)
            assert json.loads(serialized) == result


# ===================================================================
# emit_stop_output
# ===================================================================


class TestEmitStopOutput:
    def test_cursor_with_followup(self):
        result = emit_stop_output("continue working", PLATFORM_CURSOR)
        assert result == {"followup_message": "continue working"}

    def test_claude_code_with_followup(self):
        result = emit_stop_output("continue working", PLATFORM_CLAUDE_CODE)
        assert result == {"decision": "block", "reason": "continue working"}

    def test_cursor_no_followup_none(self):
        assert emit_stop_output(None, PLATFORM_CURSOR) == {}

    def test_cursor_no_followup_empty(self):
        assert emit_stop_output("", PLATFORM_CURSOR) == {}

    def test_claude_code_no_followup_none(self):
        assert emit_stop_output(None, PLATFORM_CLAUDE_CODE) == {}

    def test_claude_code_no_followup_empty(self):
        assert emit_stop_output("", PLATFORM_CLAUDE_CODE) == {}

    def test_output_is_json_serializable(self):
        for platform in (PLATFORM_CURSOR, PLATFORM_CLAUDE_CODE):
            result = emit_stop_output("text", platform)
            serialized = json.dumps(result)
            assert json.loads(serialized) == result


# ===================================================================
# _persist_env_claude_code
# ===================================================================


class TestPersistEnvClaudeCode:
    def test_writes_export_lines(self, monkeypatch, tmp_path):
        env_file = tmp_path / "claude_env"
        env_file.touch()
        monkeypatch.setenv("CLAUDE_ENV_FILE", str(env_file))
        _persist_env_claude_code({"FOO": "bar", "BAZ": "qux"})
        contents = env_file.read_text(encoding="utf-8")
        assert "export FOO=" in contents
        assert "bar" in contents
        assert "export BAZ=" in contents
        assert "qux" in contents

    def test_noop_when_env_var_unset(self, monkeypatch, tmp_path):
        monkeypatch.delenv("CLAUDE_ENV_FILE", raising=False)
        _persist_env_claude_code({"KEY": "val"})

    def test_appends_to_existing_file(self, monkeypatch, tmp_path):
        env_file = tmp_path / "claude_env"
        env_file.write_text("export EXISTING='yes'\n", encoding="utf-8")
        monkeypatch.setenv("CLAUDE_ENV_FILE", str(env_file))
        _persist_env_claude_code({"NEW": "value"})
        contents = env_file.read_text(encoding="utf-8")
        assert "EXISTING" in contents
        assert "NEW" in contents

    def test_silent_on_bad_path(self, monkeypatch):
        monkeypatch.setenv("CLAUDE_ENV_FILE", "/nonexistent/dir/file")
        _persist_env_claude_code({"KEY": "val"})
