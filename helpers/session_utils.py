"""Session ID resolution, scratchpad path, and hook I/O utilities.

Consolidates the session-resolution logic and hook stdin reading
previously duplicated between ``inject-module-context.py``
(sessionStart hook) and ``grind-until-done.py`` (stop hook).

Resolution priority:
  1. ``AGENT_SESSION_ID`` env var (set by a prior sessionStart on Cursor)
  2. ``conversation_id``  (Cursor -- stable across all hook events)
  3. ``session_id``       (Claude Code / Cursor sessionStart)
  4. UUID4 fallback       (never breaks, just loses cross-hook correlation)
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
