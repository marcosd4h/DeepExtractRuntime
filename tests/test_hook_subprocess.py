"""Subprocess integration tests for hook cross-platform output.

Runs inject-module-context.py and grind-until-done.py as real subprocesses,
piping JSON on stdin and capturing JSON on stdout.  Tests both Cursor and
Claude Code output formats with zero mocks -- exercises the complete
stdin -> platform detection -> output pipeline.

The grind hook resolves its scratchpad directory from a path relative to the
script file (not an env var), so tests write scratchpads to the real
.agent/hooks/scratchpads/ directory using unique session IDs and clean up
after themselves.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

_AGENT_DIR = Path(__file__).resolve().parent.parent
_WORKSPACE_ROOT = _AGENT_DIR.parent
_GRIND_HOOK = _AGENT_DIR / "hooks" / "grind-until-done.py"
_INJECT_HOOK = _AGENT_DIR / "hooks" / "inject-module-context.py"
_SCRATCHPADS_DIR = _AGENT_DIR / "hooks" / "scratchpads"

_TIMEOUT = 20


def _unique_session_id() -> str:
    return f"pytest-{uuid.uuid4().hex[:12]}"


def _run_hook(
    hook_script: Path,
    stdin_payload: dict,
    *,
    env_overrides: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    """Run a hook script as a subprocess with JSON on stdin."""
    env = os.environ.copy()
    env.pop("AGENT_SESSION_ID", None)
    env.pop("CLAUDE_ENV_FILE", None)
    if env_overrides:
        env.update(env_overrides)
    return subprocess.run(
        [sys.executable, str(hook_script)],
        input=json.dumps(stdin_payload),
        capture_output=True,
        text=True,
        cwd=str(_WORKSPACE_ROOT),
        env=env,
        timeout=_TIMEOUT,
    )


@pytest.fixture
def scratchpad_session():
    """Yield a unique session ID and clean up its scratchpad file after the test."""
    sid = _unique_session_id()
    yield sid
    path = _SCRATCHPADS_DIR / f"{sid}.md"
    if path.exists():
        path.unlink(missing_ok=True)


def _write_scratchpad(session_id: str, content: str) -> Path:
    """Write a scratchpad to the real scratchpads directory."""
    _SCRATCHPADS_DIR.mkdir(parents=True, exist_ok=True)
    path = _SCRATCHPADS_DIR / f"{session_id}.md"
    path.write_text(content, encoding="utf-8")
    return path


_PENDING_SCRATCHPAD = (
    "# Task: Test task\n\n"
    "## Items\n"
    "- [x] Step 1\n"
    "- [ ] Step 2\n"
    "- [ ] Step 3\n\n"
    "## Status\n"
    "IN_PROGRESS\n"
)

_DONE_SCRATCHPAD = (
    "# Task: Test task\n\n"
    "## Items\n"
    "- [x] Step 1\n"
    "- [x] Step 2\n\n"
    "## Status\n"
    "DONE\n"
)


# ===================================================================
# Grind hook -- Cursor platform
# ===================================================================


class TestGrindSubprocessCursor:
    """Grind hook produces Cursor-format output when stdin has no hook_event_name."""

    def test_pending_items_cursor_format(self, scratchpad_session):
        _write_scratchpad(scratchpad_session, _PENDING_SCRATCHPAD)
        proc = _run_hook(
            _GRIND_HOOK,
            {"conversation_id": scratchpad_session},
        )
        assert proc.returncode == 0, f"stderr: {proc.stderr}"
        output = json.loads(proc.stdout)
        assert "followup_message" in output
        assert "Step 2" in output["followup_message"] or "2 item(s)" in output["followup_message"]
        assert "decision" not in output

    def test_no_scratchpad_cursor(self):
        proc = _run_hook(
            _GRIND_HOOK,
            {"conversation_id": _unique_session_id()},
        )
        assert proc.returncode == 0
        output = json.loads(proc.stdout)
        assert output == {}

    def test_done_scratchpad_cursor(self, scratchpad_session):
        _write_scratchpad(scratchpad_session, _DONE_SCRATCHPAD)
        proc = _run_hook(
            _GRIND_HOOK,
            {"conversation_id": scratchpad_session},
        )
        assert proc.returncode == 0
        output = json.loads(proc.stdout)
        assert output == {}


# ===================================================================
# Grind hook -- Claude Code platform
# ===================================================================


class TestGrindSubprocessClaudeCode:
    """Grind hook produces Claude Code-format output when stdin has hook_event_name."""

    def test_pending_items_claude_code_format(self, scratchpad_session):
        _write_scratchpad(scratchpad_session, _PENDING_SCRATCHPAD)
        proc = _run_hook(
            _GRIND_HOOK,
            {"hook_event_name": "Stop", "session_id": scratchpad_session},
        )
        assert proc.returncode == 0, f"stderr: {proc.stderr}"
        output = json.loads(proc.stdout)
        assert "decision" in output
        assert output["decision"] == "block"
        assert "reason" in output
        assert "Step 2" in output["reason"] or "2 item(s)" in output["reason"]
        assert "followup_message" not in output

    def test_no_scratchpad_claude_code(self):
        proc = _run_hook(
            _GRIND_HOOK,
            {"hook_event_name": "Stop", "session_id": _unique_session_id()},
        )
        assert proc.returncode == 0
        output = json.loads(proc.stdout)
        assert output == {}

    def test_done_scratchpad_claude_code(self, scratchpad_session):
        _write_scratchpad(scratchpad_session, _DONE_SCRATCHPAD)
        proc = _run_hook(
            _GRIND_HOOK,
            {"hook_event_name": "Stop", "session_id": scratchpad_session},
        )
        assert proc.returncode == 0
        output = json.loads(proc.stdout)
        assert output == {}


# ===================================================================
# Inject context hook -- Cursor platform
# ===================================================================


class TestInjectContextSubprocessCursor:
    """Inject-context hook produces Cursor-format output."""

    def test_cursor_format_has_env_and_context(self):
        proc = _run_hook(_INJECT_HOOK, {"conversation_id": "cursor-sess-1"})
        assert proc.returncode == 0, f"stderr: {proc.stderr}"
        output = json.loads(proc.stdout)
        assert "env" in output
        assert "AGENT_SESSION_ID" in output["env"]
        assert output["env"]["AGENT_SESSION_ID"] == "cursor-sess-1"
        assert "additional_context" in output
        assert isinstance(output["additional_context"], str)
        assert "hookSpecificOutput" not in output

    def test_cursor_context_contains_workspace_info(self):
        proc = _run_hook(_INJECT_HOOK, {})
        assert proc.returncode == 0
        output = json.loads(proc.stdout)
        ctx = output["additional_context"]
        assert "DeepExtractIDA" in ctx or "extracted module" in ctx


# ===================================================================
# Inject context hook -- Claude Code platform
# ===================================================================


class TestInjectContextSubprocessClaudeCode:
    """Inject-context hook produces Claude Code-format output."""

    def test_claude_code_format_has_hook_specific_output(self):
        proc = _run_hook(
            _INJECT_HOOK,
            {"hook_event_name": "SessionStart", "session_id": "cc-sess-1"},
        )
        assert proc.returncode == 0, f"stderr: {proc.stderr}"
        output = json.loads(proc.stdout)
        assert "hookSpecificOutput" in output
        hso = output["hookSpecificOutput"]
        assert hso["hookEventName"] == "SessionStart"
        assert "additionalContext" in hso
        assert isinstance(hso["additionalContext"], str)
        assert "env" not in output

    def test_claude_code_context_contains_workspace_info(self):
        proc = _run_hook(
            _INJECT_HOOK,
            {"hook_event_name": "SessionStart"},
        )
        assert proc.returncode == 0
        output = json.loads(proc.stdout)
        ctx = output["hookSpecificOutput"]["additionalContext"]
        assert "DeepExtractIDA" in ctx or "extracted module" in ctx

    def test_claude_code_persists_session_id_to_env_file(self, tmp_path):
        env_file = tmp_path / "claude_env"
        env_file.touch()
        proc = _run_hook(
            _INJECT_HOOK,
            {"hook_event_name": "SessionStart", "session_id": "persist-test"},
            env_overrides={"CLAUDE_ENV_FILE": str(env_file)},
        )
        assert proc.returncode == 0, f"stderr: {proc.stderr}"
        contents = env_file.read_text(encoding="utf-8")
        assert "AGENT_SESSION_ID" in contents
        assert "persist-test" in contents


# ===================================================================
# Cross-platform session ID propagation
# ===================================================================


class TestSessionIdPropagation:
    """Session ID flows correctly through both platform paths."""

    def test_cursor_conversation_id_becomes_session(self):
        proc = _run_hook(_INJECT_HOOK, {"conversation_id": "conv-42"})
        assert proc.returncode == 0
        output = json.loads(proc.stdout)
        assert output["env"]["AGENT_SESSION_ID"] == "conv-42"

    def test_cursor_session_id_field_used(self):
        proc = _run_hook(_INJECT_HOOK, {"session_id": "sess-77"})
        assert proc.returncode == 0
        output = json.loads(proc.stdout)
        assert output["env"]["AGENT_SESSION_ID"] == "sess-77"

    def test_env_var_takes_priority(self):
        proc = _run_hook(
            _INJECT_HOOK,
            {"conversation_id": "should-be-overridden"},
            env_overrides={"AGENT_SESSION_ID": "env-wins"},
        )
        assert proc.returncode == 0
        output = json.loads(proc.stdout)
        assert output["env"]["AGENT_SESSION_ID"] == "env-wins"

    def test_uuid_fallback_when_no_id(self):
        proc = _run_hook(_INJECT_HOOK, {})
        assert proc.returncode == 0
        output = json.loads(proc.stdout)
        sid = output["env"]["AGENT_SESSION_ID"]
        assert len(sid) == 36
        assert sid.count("-") == 4
