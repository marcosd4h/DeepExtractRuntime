"""Shared utilities for multi-skill script integration."""

import sys
from pathlib import Path

from ._workspace import (
    bootstrap_workspace_handoff,
    create_run_dir,
    get_step_paths,
    install_workspace_bootstrap,
    make_db_resolvers,
    read_results,
    read_summary,
    update_manifest,
    write_results,
    get_workspace_root,
    resolve_db_path,
    resolve_tracking_db,
)


def bootstrap(anchor_file: str | Path) -> Path:
    """One-liner bootstrap for skill/agent _common.py files.

    Resolves workspace root from *anchor_file*, ensures the runtime
    root is on ``sys.path`` (idempotently), and installs workspace
    handoff.  Returns the workspace root ``Path``.
    """
    root = get_workspace_root(anchor_file)
    agent_path = root / ".agent"
    if agent_path.is_dir():
        path_entry = str(agent_path)
    else:
        path_entry = str(root)
    if path_entry not in sys.path:
        sys.path.insert(0, path_entry)
    install_workspace_bootstrap(anchor_file, root)
    return root


__all__ = [
    "bootstrap",
    "bootstrap_workspace_handoff",
    "create_run_dir",
    "get_step_paths",
    "install_workspace_bootstrap",
    "make_db_resolvers",
    "read_results",
    "read_summary",
    "update_manifest",
    "write_results",
    "get_workspace_root",
    "resolve_db_path",
    "resolve_tracking_db",
]

