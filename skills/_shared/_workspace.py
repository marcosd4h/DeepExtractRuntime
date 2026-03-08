"""Shared workspace handoff helpers for skill scripts.

Layer 1 (workspace I/O) now lives in ``helpers.workspace``.  This module
re-exports those symbols for backward compatibility and adds Layer 2:

    - reusable script-level workspace handoff bootstrap
      (--workspace-dir / --workspace-step)
    - workspace root resolution from skill script anchors
    - DB path resolver wrappers bound to a workspace root
"""

from __future__ import annotations

import argparse
import atexit
import io
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

# Re-export Layer 1 workspace I/O from helpers (correct dependency direction).
from helpers.workspace import (  # noqa: F401  -- re-exported
    MANIFEST_FILE as _MANIFEST_FILE,
    RESULTS_FILE as _RESULTS_FILE,
    SUMMARY_FILE as _SUMMARY_FILE,
    coerce_path as _coerce_path,
    compact_item_preview as _compact_item_preview,
    create_run_dir,
    get_step_paths,
    infer_default_step as _infer_default_step,
    json_dump as _json_dump,
    json_load as _json_load,
    normalize_run_dir as _normalize_run_dir,
    read_results,
    read_summary,
    safe_name as _safe_name,
    step_dir as _step_dir,
    summarize_json_payload as _summarize_json_payload,
    summarize_text_payload as _summarize_text_payload,
    truncate_text as _truncate_text,
    update_manifest,
    utc_iso as _utc_iso,
    write_results,
    _utc_now,
)


# ---------------------------------------------------------------------------
# Layer 2: Workspace root resolution (skill-specific)
# ---------------------------------------------------------------------------

def get_workspace_root(anchor_file: str | Path) -> Path:
    """Resolve the workspace root from a skill script's __file__ anchor.

    Walks up from the anchor file looking for a directory that contains
    a ``.agent/`` subdirectory with ``skills/`` and ``helpers/`` inside it.
    Falls back to a directory that directly contains ``skills/`` and
    ``helpers/`` (but is not ``.agent/`` itself).  Last resort is
    ``parents[4]`` (legacy layout) or ``Path.cwd()``.
    """
    anchor = Path(anchor_file).resolve()
    for parent in anchor.parents:
        agent_sub = parent / ".agent"
        if (agent_sub.is_dir()
                and (agent_sub / "skills").is_dir()
                and (agent_sub / "helpers").is_dir()):
            return parent
        if (parent.name != ".agent"
                and (parent / "skills").is_dir()
                and (parent / "helpers").is_dir()):
            return parent
    if len(anchor.parents) > 4:
        return anchor.parents[4]
    return Path.cwd()


def resolve_db_path(db_path: str, workspace_root: Path) -> str:
    """Canonical wrapper for DB path resolution, bound to a workspace root."""
    from helpers import _resolve_db_path
    return _resolve_db_path(db_path, workspace_root)


def resolve_tracking_db(workspace_root: Path) -> Optional[str]:
    """Canonical wrapper for tracking DB resolution."""
    from helpers import _resolve_tracking_db
    return _resolve_tracking_db(workspace_root)


def make_db_resolvers(workspace_root: Path) -> tuple:
    """Create workspace-bound DB path resolvers.

    Returns a ``(resolve_db_path, resolve_tracking_db)`` tuple where each
    function has ``workspace_root`` already bound, eliminating the need for
    boilerplate wrapper functions in every skill ``_common.py``.

    Usage in a skill ``_common.py``::

        from skills._shared import bootstrap, make_db_resolvers

        WORKSPACE_ROOT = bootstrap(__file__)
        resolve_db_path, resolve_tracking_db = make_db_resolvers(WORKSPACE_ROOT)
    """

    def _bound_resolve_db_path(db_path: str) -> str:
        return resolve_db_path(db_path, workspace_root)

    def _bound_resolve_tracking_db() -> Optional[str]:
        return resolve_tracking_db(workspace_root)

    return _bound_resolve_db_path, _bound_resolve_tracking_db


# ---------------------------------------------------------------------------
# Layer 2: Script-level workspace handoff bootstrap
# ---------------------------------------------------------------------------

@dataclass
class _BootstrapState:
    script_path: Path
    workspace_root: Path
    enabled: bool = False
    workspace_dir: Optional[Path] = None
    workspace_step: Optional[str] = None
    stdout_buffer: Optional[io.StringIO] = None
    original_stdout: Optional[Any] = None
    original_stderr: Optional[Any] = None
    exit_code: Any = None
    uncaught_exception: Optional[tuple[str, str]] = None
    finalized: bool = False
    started_at: datetime = field(default_factory=_utc_now)

    def activate(self, workspace_dir: str, workspace_step: Optional[str]) -> None:
        if self.enabled:
            return
        self.enabled = True
        self.workspace_dir = _normalize_run_dir(workspace_dir)
        self.workspace_step = workspace_step
        self.stdout_buffer = io.StringIO()
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr
        self.started_at = _utc_now()
        sys.stdout = self.stdout_buffer

    def finalize(self) -> None:
        if self.finalized or not self.enabled:
            return
        self.finalized = True

        captured_stdout = self.stdout_buffer.getvalue() if self.stdout_buffer else ""

        if self.original_stdout is not None:
            sys.stdout = self.original_stdout

        argparse.ArgumentParser.parse_args = _ORIG_PARSE_ARGS  # type: ignore[assignment]
        sys.exit = _ORIG_SYS_EXIT
        sys.excepthook = _ORIG_EXCEPTHOOK

        step_name = _safe_name(
            self.workspace_step or _infer_default_step(self.script_path),
            fallback="step",
        )

        status = "success"
        if self.uncaught_exception is not None:
            status = "error"
        elif self.exit_code not in (None, 0):
            status = "error"

        stripped = captured_stdout.strip()
        output_type = "empty"
        parsed_json: Any = None
        if stripped:
            try:
                parsed_json = json.loads(stripped)
                output_type = "json"
            except json.JSONDecodeError:
                output_type = "text"

        if output_type == "json":
            full_data = {
                "output_type": "json",
                "captured_at": _utc_iso(),
                "stdout": parsed_json,
                "stdout_char_count": len(captured_stdout),
            }
            compact_payload = _summarize_json_payload(parsed_json)
        elif output_type == "text":
            full_data = {
                "output_type": "text",
                "captured_at": _utc_iso(),
                "stdout_text": captured_stdout,
                "stdout_char_count": len(captured_stdout),
            }
            compact_payload = _summarize_text_payload(captured_stdout)
        else:
            full_data = {
                "output_type": "empty",
                "captured_at": _utc_iso(),
                "stdout_text": "",
                "stdout_char_count": 0,
            }
            compact_payload = {"kind": "empty"}

        elapsed = max(0.0, (_utc_now() - self.started_at).total_seconds())
        key_counts: dict[str, Any] = {}
        top_items: list[Any] = []
        if output_type == "json":
            if isinstance(parsed_json, dict):
                key_counts["top_level_keys"] = len(parsed_json)
                for key, value in parsed_json.items():
                    if isinstance(value, list):
                        key_counts[f"{key}_count"] = len(value)
                top_items = list(parsed_json.keys())[:10]
            elif isinstance(parsed_json, list):
                key_counts["items"] = len(parsed_json)
                top_items = [_compact_item_preview(item) for item in parsed_json[:5]]
        elif output_type == "text":
            lines = [line for line in captured_stdout.splitlines() if line.strip()]
            key_counts["lines"] = len(lines)
            key_counts["chars"] = len(captured_stdout)
            top_items = [_truncate_text(line) for line in lines[:5]]

        summary_data: dict[str, Any] = {
            "step_name": step_name,
            "status": status,
            "output_type": output_type,
            "elapsed_seconds": round(elapsed, 3),
            "key_counts": key_counts,
            "top_items": top_items,
            "compact": compact_payload,
        }
        if self.uncaught_exception is not None:
            summary_data["error"] = {
                "type": self.uncaught_exception[0],
                "message": self.uncaught_exception[1],
            }
        elif self.exit_code not in (None, 0):
            summary_data["exit_code"] = self.exit_code

        try:
            paths = write_results(
                run_dir=self.workspace_dir,
                step_name=step_name,
                full_data=full_data,
                summary_data=summary_data,
            )
        except (OSError, PermissionError):
            paths = {"summary_path": "", "results_path": ""}

        try:
            update_manifest(
                run_dir=self.workspace_dir,
                step_name=step_name,
                status=status,
                summary_path=paths["summary_path"],
            )
        except (OSError, PermissionError):
            pass

        summary_data["summary_path"] = paths["summary_path"]
        summary_data["results_path"] = paths["results_path"]
        try:
            print(json.dumps(summary_data, separators=(",", ":"), ensure_ascii=False))
            sys.stdout.flush()
        except (BrokenPipeError, OSError):
            pass


_BOOTSTRAP_INSTALLED = False
_BOOTSTRAP_STATE: Optional[_BootstrapState] = None
_ORIG_PARSE_ARGS = argparse.ArgumentParser.parse_args
_ORIG_SYS_EXIT = sys.exit
_ORIG_EXCEPTHOOK = sys.excepthook


def _extract_workspace_args(args: Any) -> tuple[Optional[str], Optional[str], list[str]]:
    shim = argparse.ArgumentParser(add_help=False)
    shim.add_argument("--workspace-dir", dest="_workspace_dir")
    shim.add_argument("--workspace-step", dest="_workspace_step")
    known, remaining = shim.parse_known_args(args)
    return known._workspace_dir, known._workspace_step, remaining


def _patched_parse_args(self, args=None, namespace=None):  # type: ignore[override]
    workspace_dir, workspace_step, remaining = _extract_workspace_args(args)
    parsed = _ORIG_PARSE_ARGS(self, remaining, namespace)
    setattr(parsed, "workspace_dir", workspace_dir)
    setattr(parsed, "workspace_step", workspace_step)

    global _BOOTSTRAP_STATE
    if workspace_dir and _BOOTSTRAP_STATE is not None:
        _BOOTSTRAP_STATE.activate(workspace_dir=workspace_dir, workspace_step=workspace_step)
    return parsed


def _patched_sys_exit(code=0):
    if _BOOTSTRAP_STATE is not None:
        _BOOTSTRAP_STATE.exit_code = code
    raise SystemExit(code)


def _patched_excepthook(exc_type, exc_value, exc_traceback):
    if _BOOTSTRAP_STATE is not None:
        _BOOTSTRAP_STATE.uncaught_exception = (
            getattr(exc_type, "__name__", str(exc_type)),
            str(exc_value),
        )
    _ORIG_EXCEPTHOOK(exc_type, exc_value, exc_traceback)


def bootstrap_workspace_handoff(
    script_file: str | Path,
    workspace_root: str | Path,
) -> None:
    """Install script-level workspace handoff bootstrap exactly once."""
    global _BOOTSTRAP_INSTALLED, _BOOTSTRAP_STATE
    if _BOOTSTRAP_INSTALLED:
        return

    runtime_script = None
    if sys.argv and sys.argv[0]:
        try:
            runtime_script = Path(sys.argv[0]).resolve()
        except OSError:
            runtime_script = None
    _BOOTSTRAP_STATE = _BootstrapState(
        script_path=runtime_script or Path(script_file).resolve(),
        workspace_root=_coerce_path(workspace_root),
    )

    argparse.ArgumentParser.parse_args = _patched_parse_args  # type: ignore[assignment]
    sys.exit = _patched_sys_exit
    sys.excepthook = _patched_excepthook
    atexit.register(_BOOTSTRAP_STATE.finalize)
    _BOOTSTRAP_INSTALLED = True


install_workspace_bootstrap = bootstrap_workspace_handoff
