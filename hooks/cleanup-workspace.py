#!/usr/bin/env python3
"""Hook: sessionEnd -- Clean up stale workspace run directories and agent state.

Delegates to helpers.cleanup_workspace.cleanup_workspace() which handles:
- Workspace run directory removal
- Stale agent state file cleanup
- Cache eviction

The age threshold is controlled by config/defaults.json
``hooks.workspace_cleanup_age_hours`` (default: 48 hours), converted to days
for the helper's API.

Input  (stdin JSON):  event metadata from host sessionEnd hook
Output (stdout JSON): {}
Exit 0 on success.
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
_AGENT_DIR = _SCRIPT_DIR.parent
_WORKSPACE_ROOT = _AGENT_DIR.parent
sys.path.insert(0, str(_AGENT_DIR))

from helpers.config import get_config_value  # noqa: E402
from helpers.cleanup_workspace import cleanup_workspace  # noqa: E402
from helpers.errors import log_warning  # noqa: E402


def main() -> None:
    try:
        _input = sys.stdin.read()
    except Exception as exc:
        log_warning(f"Failed to read stdin in cleanup hook: {exc}", "UNKNOWN")

    hours = float(get_config_value("hooks.workspace_cleanup_age_hours", 48))
    older_than_days = max(1, math.ceil(hours / 24))

    try:
        result = cleanup_workspace(
            older_than_days=older_than_days,
            dry_run=False,
            workspace_root=_WORKSPACE_ROOT,
        )
        total = result["runs_deleted"] + result["states_deleted"] + result.get("cache_evicted", 0)
        if total > 0:
            print(
                f"Session cleanup: {result['runs_deleted']} run(s), "
                f"{result['states_deleted']} state file(s), "
                f"{result.get('cache_evicted', 0)} cache entries evicted",
                file=sys.stderr,
            )
    except Exception as exc:
        print(f"Cleanup error: {exc}", file=sys.stderr)

    print(json.dumps({}))


if __name__ == "__main__":
    main()
