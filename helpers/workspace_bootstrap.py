"""Workspace step setup bootstrap for skill scripts.

Reduces boilerplate when preparing and completing workspace steps.
Integrates with helpers.workspace for path resolution and I/O.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from helpers.workspace import get_step_paths, update_manifest, write_results


def prepare_step(run_dir: str | Path, step_name: str) -> dict[str, str]:
    """Prepare a workspace step directory and return paths for output files.

    Creates the step subdirectory under run_dir and returns paths for
    results.json and summary.json. Use before writing step output.

    Args:
        run_dir: Workspace run directory (e.g. .agent/workspace/<run_id>/)
        step_name: Step identifier (will be sanitized for path safety)

    Returns:
        Dict with keys: step_name, step_path, results_path, summary_path
    """
    paths = get_step_paths(run_dir, step_name)
    Path(paths["step_path"]).mkdir(parents=True, exist_ok=True)
    return paths


def complete_step(
    run_dir: str | Path,
    step_name: str,
    full_data: Any,
    summary_data: Any,
    status: str = "ok",
) -> dict[str, str]:
    """Write step results and summary, then update manifest.

    Convenience wrapper for write_results + update_manifest.
    Use when a script has produced full_data and summary_data and
    wants to persist them per the workspace handoff contract.

    Args:
        run_dir: Workspace run directory
        step_name: Step identifier
        full_data: Full payload for results.json
        summary_data: Compact summary for summary.json
        status: Step status (e.g. "success", "error")

    Returns:
        Dict from write_results: step_name, results_path, summary_path
    """
    paths = write_results(run_dir, step_name, full_data, summary_data)
    update_manifest(run_dir, step_name, status, paths["summary_path"])
    return paths
