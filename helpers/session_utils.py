"""Session ID resolution, scratchpad path, hook I/O, and platform detection.

Consolidates the session-resolution logic and hook stdin reading
previously duplicated between ``inject-module-context.py``
(sessionStart hook) and ``grind-until-done.py`` (stop hook).

Resolution priority:
  1. ``AGENT_SESSION_ID`` env var (set by a prior sessionStart on Cursor)
  2. ``conversation_id``  (Cursor -- stable across all hook events)
  3. ``session_id``       (Claude Code / Cursor sessionStart)
  4. UUID4 fallback       (never breaks, just loses cross-hook correlation)

Platform detection:
  Claude Code sends ``hook_event_name`` in every hook's stdin JSON.
  Cursor does not.  Use ``detect_hook_platform()`` to branch output format.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path

_HELPERS_DIR = Path(__file__).resolve().parent
_AGENT_DIR = _HELPERS_DIR.parent

SCRATCHPADS_DIR: Path = _AGENT_DIR / "hooks" / "scratchpads"
"""Default directory for session-scoped grind-loop scratchpads."""

PLATFORM_CLAUDE_CODE = "claude_code"
PLATFORM_CURSOR = "cursor"


def detect_hook_platform(stdin_data: dict) -> str:
    """Detect whether the hook is running under Claude Code or Cursor.

    Claude Code always includes ``hook_event_name`` in every hook's
    stdin JSON payload.  Cursor does not send this field.

    Returns ``PLATFORM_CLAUDE_CODE`` or ``PLATFORM_CURSOR``.
    """
    if not stdin_data:
        return PLATFORM_CURSOR
    if "hook_event_name" in stdin_data:
        return PLATFORM_CLAUDE_CODE
    return PLATFORM_CURSOR


def resolve_session_id(stdin_data: dict) -> str:
    """Extract session ID from env or stdin JSON.  Platform-agnostic.

    Parameters
    ----------
    stdin_data:
        Parsed JSON dict from the hook protocol's stdin payload.

    Returns
    -------
    str
        A session identifier (UUID-style string).
    """
    sid = os.environ.get("AGENT_SESSION_ID")
    if sid:
        return sid
    if stdin_data is None:
        stdin_data = {}
    sid = stdin_data.get("conversation_id")
    if sid:
        return str(sid)
    sid = stdin_data.get("session_id")
    if sid:
        return str(sid)
    return str(uuid.uuid4())


def scratchpad_path(session_id: str) -> Path:
    """Return the expected scratchpad path for *session_id*.

    Does **not** check whether the file exists -- callers decide that.

    Raises :class:`ValueError` if the resolved path would escape
    the scratchpads directory (path-traversal protection).
    """
    candidate = SCRATCHPADS_DIR / f"{session_id}.md"
    try:
        resolved = candidate.resolve()
        resolved.relative_to(SCRATCHPADS_DIR.resolve())
    except (ValueError, OSError) as exc:
        raise ValueError(
            f"Invalid session_id {session_id!r}: resolved path escapes "
            f"scratchpads directory"
        ) from exc
    return candidate


def read_hook_input() -> dict:
    """Read JSON from stdin (hook protocol).  Graceful on empty/malformed."""
    if sys.stdin.isatty():
        return {}
    try:
        raw = sys.stdin.read()
        if raw.strip():
            return json.loads(raw)
    except json.JSONDecodeError as exc:
        sys.stderr.write(json.dumps({"warning": f"Hook stdin JSON parse error: {exc}", "code": "PARSE_ERROR"}) + "\n")
    except (UnicodeDecodeError, OSError) as exc:
        sys.stderr.write(json.dumps({"warning": f"Hook stdin read error: {exc}", "code": "UNKNOWN"}) + "\n")
    return {}


# ---------------------------------------------------------------------------
# Platform-aware output helpers
# ---------------------------------------------------------------------------

def _persist_env_claude_code(env_vars: dict[str, str]) -> None:
    """Write environment variables to ``$CLAUDE_ENV_FILE`` for persistence.

    Claude Code makes this file path available only in SessionStart hooks.
    If the env var is unset, this is a no-op.
    """
    env_file = os.environ.get("CLAUDE_ENV_FILE")
    if not env_file:
        return
    try:
        with open(env_file, "a", encoding="utf-8") as fh:
            for key, value in env_vars.items():
                fh.write(f"export {key}={value!r}\n")
    except OSError:
        pass


def emit_session_start_output(
    context: str,
    session_id: str,
    platform: str,
) -> dict:
    """Build the JSON output dict for a SessionStart hook.

    For Claude Code: uses ``hookSpecificOutput.additionalContext`` and
    writes ``AGENT_SESSION_ID`` to ``$CLAUDE_ENV_FILE``.

    For Cursor: uses the legacy ``env`` + ``additional_context`` format.

    The caller should ``json.dumps()`` and ``print()`` the returned dict.
    """
    if platform == PLATFORM_CLAUDE_CODE:
        _persist_env_claude_code({"AGENT_SESSION_ID": session_id})
        return {
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": context,
            },
        }
    return {
        "env": {"AGENT_SESSION_ID": session_id},
        "additional_context": context,
    }


def emit_stop_output(
    followup_text: str | None,
    platform: str,
) -> dict:
    """Build the JSON output dict for a Stop hook.

    When *followup_text* is ``None`` or empty, returns ``{}`` (allow stop).

    For Claude Code: ``{"decision": "block", "reason": followup_text}``
    to prevent the agent from stopping.

    For Cursor: ``{"followup_message": followup_text}`` (legacy format).
    """
    if not followup_text:
        return {}
    if platform == PLATFORM_CLAUDE_CODE:
        return {
            "decision": "block",
            "reason": followup_text,
        }
    return {
        "followup_message": followup_text,
    }
