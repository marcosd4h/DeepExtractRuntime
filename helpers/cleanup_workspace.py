#!/usr/bin/env python3
"""Cleanup utility for workspace run directories and stale state files.

Usage:
    python .agent/helpers/cleanup_workspace.py [--older-than DAYS] [--dry-run] [--json]
"""

from __future__ import annotations

import argparse
import shutil
import sys
import time
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
_RUNTIME_ROOT = _SCRIPT_DIR.parent
if str(_RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(_RUNTIME_ROOT))

from helpers.errors import emit_error, log_warning  # noqa: E402
from helpers.json_output import emit_json  # noqa: E402
from helpers.progress import status_message  # noqa: E402


def cleanup_workspace(
    older_than_days: int,
    dry_run: bool = False,
    workspace_root: Path | None = None,
) -> dict[str, int]:
    """Remove workspace run directories and stale state files older than *older_than_days*.

    Returns a dict with ``runs_deleted`` and ``states_deleted`` counts.
    """
    if workspace_root is None:
        from .db_paths import _auto_workspace_root
        workspace_root = _auto_workspace_root()
    workspace_dir = workspace_root / ".agent" / "workspace"

    result = {"runs_deleted": 0, "states_deleted": 0}

    if not workspace_dir.exists():
        log_warning(f"Workspace directory not found: {workspace_dir}", "NOT_FOUND")
        return result

    cutoff_time = time.time() - (older_than_days * 86400)

    status_message(f"Cleaning up workspace runs older than {older_than_days} days...")

    deleted_count = 0
    for run_dir in workspace_dir.iterdir():
        if not run_dir.is_dir():
            continue

        try:
            dir_mtime = run_dir.stat().st_mtime
        except OSError:
            continue

        if dir_mtime < cutoff_time:
            if dry_run:
                status_message(f"[DRY RUN] Would delete: {run_dir.name}")
            else:
                try:
                    shutil.rmtree(run_dir)
                    status_message(f"Deleted: {run_dir.name}")
                    deleted_count += 1
                except OSError as e:
                    log_warning(f"Error deleting {run_dir.name}: {e}", "UNKNOWN")

    status_message(f"Cleanup complete. Deleted {deleted_count} run directories.")
    result["runs_deleted"] = deleted_count

    state_deleted = 0
    agents_dir = workspace_root / ".agent" / "agents"
    if agents_dir.exists():
        status_message("Cleaning up stale agent state files...")
        for agent_dir in agents_dir.iterdir():
            if not agent_dir.is_dir():
                continue
            state_dir = agent_dir / "state"
            if not state_dir.exists():
                continue
            for state_file in state_dir.glob("*.json"):
                try:
                    if state_file.stat().st_mtime < cutoff_time:
                        if dry_run:
                            status_message(f"[DRY RUN] Would delete state: {agent_dir.name}/{state_file.name}")
                        else:
                            try:
                                state_file.unlink()
                                status_message(f"Deleted state: {agent_dir.name}/{state_file.name}")
                                state_deleted += 1
                            except OSError as e:
                                log_warning(f"Error deleting state {state_file.name}: {e}", "UNKNOWN")
                except OSError:
                    continue
        status_message(f"State cleanup complete. Deleted {state_deleted} files.")
    result["states_deleted"] = state_deleted

    if not dry_run:
        from .cache import evict_stale
        eviction = evict_stale()
        result["cache_evicted"] = eviction["evicted"]
    else:
        result["cache_evicted"] = 0

    if not dry_run:
        try:
            from helpers.findings_store import purge_old_findings
            from helpers.config import get_config_value
            retention_days = get_config_value("findings_store.retention_days", default=30)
            purged = purge_old_findings(older_than_days=max(1, int(retention_days)))
            result["findings_purged"] = purged
        except Exception:
            pass
    else:
        result["findings_purged"] = 0

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Cleanup old workspace runs.")
    parser.add_argument("--older-than", type=int, default=7, help="Delete runs older than N days (default: 7)")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be deleted without actually deleting")
    parser.add_argument("--json", action="store_true", help="Emit JSON output to stdout")
    args = parser.parse_args()

    result = cleanup_workspace(args.older_than, args.dry_run)

    if args.json:
        emit_json({"status": "ok", "dry_run": args.dry_run, **result})
    else:
        total = result["runs_deleted"] + result["states_deleted"] + result.get("cache_evicted", 0)
        status_message(f"Total deleted: {total} items (cache evicted: {result.get('cache_evicted', 0)})")


if __name__ == "__main__":
    main()
