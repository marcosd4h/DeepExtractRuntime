#!/usr/bin/env python3
"""Hook: stop -- Grind-until-done iterative task loop (session-scoped).

Reads a session-scoped scratchpad from .agent/hooks/scratchpads/{session_id}.md
for a task checklist.  If unchecked items remain and no DONE marker is present,
sends a followup_message to re-invoke the agent.  Combined with loop_limit in
hooks.json, this creates bounded iterative workflows.

Session ID resolution is platform-agnostic -- works with both Cursor
(conversation_id / AGENT_SESSION_ID env) and Claude Code (session_id).

Scratchpad format (written by the agent or a skill):
```
# Task: <description>

## Items
- [x] Item 1 -- completed
- [ ] Item 2 -- pending
- [ ] Item 3 -- pending

## Status
IN_PROGRESS
```

When all items are checked or Status is set to DONE, the hook stops
sending follow-ups and the agent loop ends normally.

Input  (stdin JSON):  event metadata from host stop hook
Output (stdout JSON): { "followup_message": "..." } or {}
Exit 0 on success.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Workspace root resolution
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).resolve().parent
_AGENT_DIR = _SCRIPT_DIR.parent
_WORKSPACE_ROOT = _AGENT_DIR.parent
sys.path.insert(0, str(_AGENT_DIR))

from helpers.config import get_config_value  # noqa: E402
from helpers.session_utils import resolve_session_id, scratchpad_path as get_scratchpad_path, SCRATCHPADS_DIR, read_hook_input  # noqa: E402

_SCRATCHPADS_DIR = SCRATCHPADS_DIR

_DEFAULT_STALE_AGE_SECONDS = int(
    get_config_value("hooks.grind_scratchpad_stale_hours", 24)
) * 60 * 60


# ---------------------------------------------------------------------------
# Hook protocol helpers
# ---------------------------------------------------------------------------
def _read_hook_input() -> dict:
    """Read JSON from stdin (hook protocol).  Delegates to shared helper."""
    return read_hook_input()


def _stale_age_seconds() -> int:
    """Configurable stale-age threshold for scratchpad cleanup."""
    raw_hours = os.environ.get("GRIND_SCRATCHPAD_STALE_HOURS")
    if not raw_hours:
        return _DEFAULT_STALE_AGE_SECONDS
    try:
        hours = float(raw_hours)
        if hours <= 0:
            return _DEFAULT_STALE_AGE_SECONDS
        return int(hours * 60 * 60)
    except ValueError:
        return _DEFAULT_STALE_AGE_SECONDS


# ---------------------------------------------------------------------------
# Scratchpad parsing
# ---------------------------------------------------------------------------

# Matches: - [x] text  or  - [ ] text  (with optional leading whitespace)
_CHECKBOX_RE = re.compile(r"^\s*-\s*\[([ xX])\]\s*(.+)", re.MULTILINE)
# Status line: ## Status\n<STATUS>  or  Status: <STATUS>
_STATUS_RE = re.compile(
    r"(?:^##\s*Status\s*\n\s*(\S+))|(?:^Status:\s*(\S+))",
    re.MULTILINE,
)


def _strip_fenced_code_blocks(content: str) -> str:
    """Remove fenced-code block bodies before checkbox parsing."""
    lines: list[str] = []
    in_fence = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            lines.append(line)
    return "\n".join(lines)


def _validate_scratchpad_format(content: str) -> tuple[bool, list[str]]:
    """Validate scratchpad structure and return (is_valid, issues)."""
    issues: list[str] = []
    trimmed = content.strip()
    if not trimmed:
        issues.append("Scratchpad is empty.")
        return False, issues

    if "## Items" not in trimmed:
        issues.append("Missing '## Items' section.")
    if "## Status" not in trimmed and "Status:" not in trimmed:
        issues.append("Missing status section ('## Status' or 'Status:').")

    cleaned = _strip_fenced_code_blocks(trimmed)
    has_checkbox = bool(_CHECKBOX_RE.search(cleaned))
    has_done_marker = "DONE" in cleaned.upper() or "COMPLETE" in cleaned.upper()
    if not has_checkbox and not has_done_marker:
        issues.append("No checklist items or completion marker found.")

    return len(issues) == 0, issues


def _parse_scratchpad(content: str) -> tuple[list[str], list[str], str]:
    """Parse scratchpad into (completed, pending, status).

    Returns:
        completed: list of completed item descriptions
        pending:   list of pending item descriptions
        status:    status string (e.g., "IN_PROGRESS", "DONE")
    """
    cleaned = _strip_fenced_code_blocks(content)
    completed: list[str] = []
    pending: list[str] = []

    for match in _CHECKBOX_RE.finditer(cleaned):
        check = match.group(1).strip().lower()
        text = match.group(2).strip()
        if check == "x":
            completed.append(text)
        else:
            pending.append(text)

    # Extract status
    status = "UNKNOWN"
    status_match = _STATUS_RE.search(cleaned)
    if status_match:
        status = (status_match.group(1) or status_match.group(2) or "UNKNOWN").upper()

    # Check for DONE marker only in the ## Status section to avoid
    # false positives from task descriptions mentioning "DONE".
    if status != "DONE":
        # Fallback: look for a standalone DONE line only after the
        # ## Status header, not in arbitrary content lines.
        in_status_section = False
        for line in cleaned.splitlines():
            stripped = line.strip()
            if stripped.startswith("## Status"):
                in_status_section = True
                continue
            if in_status_section and stripped.startswith("##"):
                break  # left the status section
            if in_status_section and stripped.upper() in ("DONE", "COMPLETE"):
                status = "DONE"
                break

    return completed, pending, status


# ---------------------------------------------------------------------------
# Scratchpad discovery
# ---------------------------------------------------------------------------
def _is_safe_scratchpad_path(path: Path) -> bool:
    """Verify *path* is safely contained within the scratchpads directory.

    Prevents path-traversal attacks where a malicious session ID like
    ``../../etc/passwd`` could escape the scratchpads sandbox.
    """
    try:
        resolved = path.resolve()
        scratchpads_resolved = _SCRATCHPADS_DIR.resolve()
        # Python 3.9+ has is_relative_to(); use try/except for compat
        try:
            resolved.relative_to(scratchpads_resolved)
            return True
        except ValueError:
            return False
    except OSError:
        return False


def _find_scratchpad(session_id: str) -> Path | None:
    """Locate the scratchpad for this session.

    Returns the Path to the scratchpad file, or None if no scratchpad exists.

    Resolution order:
      1. Session-specific scratchpad: ``{session_id}.md``
      2. Fallback to ``default.md`` when no session-specific file exists.
         This supports the grind-loop-protocol rule which says agents
         should fall back to ``default.md`` when the session ID is not
         available in context.

    All returned paths are validated to be inside the scratchpads
    directory to prevent path-traversal via crafted session IDs.
    """
    if _SCRATCHPADS_DIR.is_dir():
        session_path = _SCRATCHPADS_DIR / f"{session_id}.md"
        if _is_safe_scratchpad_path(session_path) and session_path.exists():
            return session_path
        # Fallback to default.md for sessions without a specific scratchpad
        default_path = _SCRATCHPADS_DIR / "default.md"
        if default_path.exists():
            return default_path

    return None


def _cleanup_stale() -> None:
    """Remove scratchpad files older than 24 hours (orphaned sessions).

    ``default.md`` is never cleaned up because it is an intentional
    shared fallback scratchpad, not an orphaned session artifact.
    """
    if not _SCRATCHPADS_DIR.is_dir():
        return

    now = time.time()
    max_age_seconds = _stale_age_seconds()
    try:
        for path in _SCRATCHPADS_DIR.iterdir():
            if path.name.startswith("."):
                continue
            if not path.name.endswith(".md"):
                continue
            # Never clean up default.md -- it is an intentional fallback
            if path.name == "default.md":
                continue
            try:
                age = now - path.stat().st_mtime
                if age > max_age_seconds:
                    path.unlink()
            except OSError:
                pass
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def _emit_and_exit(output: dict, cleanup_path: Path | None = None) -> None:
    """Write JSON output, optionally delete scratchpad, and exit cleanly."""
    if cleanup_path is not None:
        try:
            cleanup_path.unlink()
        except OSError:
            pass
    print(json.dumps(output))
    sys.exit(0)


def main() -> None:
    stdin_data = _read_hook_input()

    session_id = resolve_session_id(stdin_data)
    scratchpad_path = _find_scratchpad(session_id)

    # Opportunistic stale cleanup (non-blocking, best-effort)
    _cleanup_stale()

    output: dict = {}

    if scratchpad_path is None:
        _emit_and_exit(output)

    try:
        content = scratchpad_path.read_text(encoding="utf-8")
    except OSError:
        _emit_and_exit(output)

    if not content.strip():
        _emit_and_exit(output)

    is_valid, validation_issues = _validate_scratchpad_format(content)
    completed, pending, status = _parse_scratchpad(content)

    if status == "DONE":
        _emit_and_exit(output, cleanup_path=scratchpad_path)

    if not pending and completed:
        _emit_and_exit(output, cleanup_path=scratchpad_path)

    if not pending and not completed:
        upper = content.upper()
        if "DONE" in upper or "COMPLETE" in upper:
            _emit_and_exit(output, cleanup_path=scratchpad_path)
        _emit_and_exit(output)

    # --- Items remain -- send followup ---
    total = len(completed) + len(pending)
    progress = f"{len(completed)}/{total}"

    remaining_list = "\n".join(f"  - [ ] {item}" for item in pending[:10])
    if len(pending) > 10:
        remaining_list += f"\n  ... and {len(pending) - 10} more"

    # Build a display-friendly path for the followup message
    try:
        rel_path = scratchpad_path.relative_to(_WORKSPACE_ROOT)
        display_path = str(rel_path).replace("\\", "/")
    except ValueError:
        display_path = str(scratchpad_path).replace("\\", "/")

    validation_note = ""
    if not is_valid and validation_issues:
        issue_lines = "\n".join(f"  - {issue}" for issue in validation_issues[:5])
        if len(validation_issues) > 5:
            issue_lines += f"\n  - ... and {len(validation_issues) - 5} more issue(s)"
        validation_note = (
            "\n\nScratchpad format warnings detected:\n"
            f"{issue_lines}\n"
            "Use the standard checklist format to keep the grind loop reliable."
        )

    followup = (
        f"Task scratchpad shows {progress} items completed.  "
        f"{len(pending)} item(s) remaining:\n"
        f"{remaining_list}\n\n"
        f"Continue working on the next pending item.  "
        f"Check off completed items in `{display_path}` "
        f"and set Status to DONE when all items are finished."
        f"{validation_note}"
    )

    output["followup_message"] = followup
    print(json.dumps(output))
    sys.exit(0)


if __name__ == "__main__":
    main()
