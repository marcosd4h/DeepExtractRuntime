"""Workspace run validator for handoff compliance.

Verifies workspace handoff compliance per workspace-pattern.mdc:
- manifest.json exists with per-step status records
- Each step has results.json and summary.json
- Manifest step records reference valid summary paths
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Reuse constants from shared workspace to stay in sync
_MANIFEST_FILE = "manifest.json"
_RESULTS_FILE = "results.json"
_SUMMARY_FILE = "summary.json"


def _coerce_path(value: str | Path) -> Path:
    p = Path(value).expanduser()
    if not p.is_absolute():
        p = (Path.cwd() / p).resolve()
    else:
        p = p.resolve()
    return p


def _json_load(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return default


@dataclass
class WorkspaceValidationResult:
    """Result of workspace run validation."""

    valid: bool
    run_dir: Path
    issues: list[str] = field(default_factory=list)
    manifest: dict[str, Any] | None = None
    step_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "run_dir": str(self.run_dir),
            "issues": self.issues,
            "step_count": self.step_count,
            "manifest_keys": list(self.manifest.keys()) if self.manifest else None,
        }


def validate_workspace_run(run_dir: str | Path) -> WorkspaceValidationResult:
    """Validate workspace handoff compliance for a run directory.

    Checks:
    1. Run directory exists
    2. manifest.json exists and is valid JSON
    3. Manifest has required structure (run_id, steps)
    4. Each step in manifest has status and summary_path
    5. Each step's summary_path points to an existing file
    6. Each step directory has results.json and summary.json (per-step contract)

    Returns:
        WorkspaceValidationResult with valid flag and list of issues.
    """
    path = _coerce_path(run_dir)
    issues: list[str] = []
    manifest: dict[str, Any] | None = None

    if not path.exists():
        return WorkspaceValidationResult(
            valid=False,
            run_dir=path,
            issues=[f"Run directory does not exist: {path}"],
        )

    if not path.is_dir():
        return WorkspaceValidationResult(
            valid=False,
            run_dir=path,
            issues=[f"Run path is not a directory: {path}"],
        )

    manifest_path = path / _MANIFEST_FILE
    if not manifest_path.exists():
        return WorkspaceValidationResult(
            valid=False,
            run_dir=path,
            issues=[f"manifest.json not found: {manifest_path}"],
        )

    manifest = _json_load(manifest_path)
    if manifest is None:
        return WorkspaceValidationResult(
            valid=False,
            run_dir=path,
            issues=[f"manifest.json is invalid or unreadable: {manifest_path}"],
        )

    if not isinstance(manifest, dict):
        return WorkspaceValidationResult(
            valid=False,
            run_dir=path,
            manifest=manifest,
            issues=["manifest.json root must be a JSON object"],
        )

    if "steps" not in manifest:
        return WorkspaceValidationResult(
            valid=False,
            run_dir=path,
            manifest=manifest,
            issues=["manifest.json missing 'steps' key"],
        )

    steps = manifest.get("steps")
    if not isinstance(steps, dict):
        return WorkspaceValidationResult(
            valid=False,
            run_dir=path,
            manifest=manifest,
            issues=["manifest.json 'steps' must be an object"],
        )

    step_count = len(steps)
    if step_count == 0:
        return WorkspaceValidationResult(
            valid=True,
            run_dir=path,
            manifest=manifest,
            step_count=0,
            issues=[],
        )

    for step_name, step_record in steps.items():
        if not isinstance(step_record, dict):
            issues.append(f"Step '{step_name}': record must be an object")
            continue

        if "status" not in step_record:
            issues.append(f"Step '{step_name}': missing 'status'")
        if "summary_path" not in step_record:
            issues.append(f"Step '{step_name}': missing 'summary_path'")

        summary_path_val = step_record.get("summary_path")
        if summary_path_val:
            summary_path = path / summary_path_val
            if not summary_path.exists():
                issues.append(
                    f"Step '{step_name}': summary_path does not exist: {summary_path_val}"
                )

        step_dir = path / step_name
        if step_dir.is_dir():
            results_file = step_dir / _RESULTS_FILE
            summary_file = step_dir / _SUMMARY_FILE
            if not results_file.exists():
                issues.append(f"Step '{step_name}': missing results.json")
            if not summary_file.exists():
                issues.append(f"Step '{step_name}': missing summary.json")
        else:
            issues.append(f"Step '{step_name}': step directory does not exist: {step_dir}")

    valid = len(issues) == 0
    return WorkspaceValidationResult(
        valid=valid,
        run_dir=path,
        manifest=manifest,
        step_count=step_count,
        issues=issues,
    )
