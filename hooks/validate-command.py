#!/usr/bin/env python3
"""Hook: preCommand -- Validate command arguments before execution.

Runs command_preflight() automatically before any slash command executes,
catching invalid module names, missing DBs, or malformed function IDs
before the agent begins work.

**NOTE**: This hook requires platform support for a ``preCommand`` hook type,
which is not yet available in Cursor or Claude Code. The script is implemented
and ready to be wired into hooks.json once the hook type becomes available:

    "preCommand": [
      {"command": "python .agent/hooks/validate-command.py", "timeout": 5000}
    ]

Input  (stdin JSON):  {"command": "<command_name>", "args": {"module": "...", "function": "..."}}
Output (stdout JSON): {} on success, or exit 2 to block with error message.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
_AGENT_DIR = _SCRIPT_DIR.parent
sys.path.insert(0, str(_AGENT_DIR))

from helpers.command_validation import validate_command_args  # noqa: E402


def main() -> None:
    try:
        raw = sys.stdin.read().strip()
        data = json.loads(raw) if raw else {}
    except json.JSONDecodeError as exc:
        print(f"Warning: malformed JSON in command input: {exc}", file=sys.stderr)
        print(json.dumps({}))
        return
    except Exception as exc:
        print(f"Warning: failed to read command input: {exc}", file=sys.stderr)
        print(json.dumps({}))
        return

    command_name = data.get("command", "").lstrip("/").strip()
    if not command_name:
        print(json.dumps({}))
        return

    args = data.get("args", {})

    result = validate_command_args(command_name, args)

    if result.warnings:
        for w in result.warnings:
            print(f"Warning: {w}", file=sys.stderr)

    if not result.ok:
        msg = "; ".join(result.errors)
        print(f"Preflight failed for /{command_name}: {msg}", file=sys.stderr)
        sys.exit(2)

    print(json.dumps({}))


if __name__ == "__main__":
    main()
