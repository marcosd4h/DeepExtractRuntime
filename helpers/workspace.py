"""Workspace run-directory I/O primitives.

Provides functions for creating run directories, writing step results and
summaries, reading them back, and updating manifests.  These are pure
infrastructure with no skill-specific domain logic.

Moved here from ``skills/_shared/_workspace.py`` so that helpers can use
workspace I/O without depending on the skills layer (which would violate
the ``Helpers -> Data`` dependency direction).
"""

from __future__ import annotations

import json
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")
_MAX_SAFE_NAME_LEN = 80
_RUN_ID_TIME_FMT = "%Y%m%d_%H%M%S"
MANIFEST_FILE = "manifest.json"
RESULTS_FILE = "results.json"
SUMMARY_FILE = "summary.json"
_MAX_PREVIEW_STR_LEN = 200


# ---------------------------------------------------------------------------
# Internal utilities
# ---------------------------------------------------------------------------

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_iso() -> str:
    return _utc_now().isoformat().replace("+00:00", "Z")


def coerce_path(value: str | Path) -> Path:
    p = Path(value).expanduser()
    if not p.is_absolute():
        p = (Path.cwd() / p).resolve()
    else:
        p = p.resolve()
    return p


def safe_name(value: str, fallback: str = "item", max_len: int = _MAX_SAFE_NAME_LEN) -> str:
    text = (value or "").strip()
    if not text:
        text = fallback
    text = text.replace("\\", "/")
    text = text.replace("/", "-")
    text = _SAFE_NAME_RE.sub("-", text)
    text = text.strip(".-_")
    if not text:
        text = fallback
    if len(text) > max_len:
        text = text[:max_len].rstrip(".-_")
    return text or fallback


def to_json_compatible(value: Any) -> Any:
    """Convert *value* to a JSON-serializable form without double-serializing."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(k): to_json_compatible(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_json_compatible(v) for v in value]
    try:
        json.dumps(value, ensure_ascii=False)
        return value
    except (TypeError, ValueError):
        return repr(value)


def truncate_text(text: str, max_len: int = _MAX_PREVIEW_STR_LEN) -> str:
    if len(text) <= max_len:
        return text
    omitted = len(text) - max_len
    return f"{text[:max_len]}...<{omitted} chars omitted>"


def compact_scalar_preview(value: Any) -> Any:
    if isinstance(value, str):
        return truncate_text(value)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, list):
        return f"list[{len(value)}]"
    if isinstance(value, dict):
        return f"object[{len(value)}]"
    return truncate_text(repr(value))


def compact_item_preview(item: Any) -> Any:
    if isinstance(item, dict):
        preferred_keys = (
            "name",
            "function_name",
            "class_name",
            "id",
            "function_id",
            "entry_type",
            "category",
            "status",
            "step_name",
            "module",
        )
        preview: dict[str, Any] = {}
        for key in preferred_keys:
            if key in item:
                preview[key] = compact_scalar_preview(item[key])
        if not preview:
            for key, value in list(item.items())[:5]:
                preview[str(key)] = compact_scalar_preview(value)
        preview["__key_count"] = len(item)
        return preview

    if isinstance(item, list):
        return {"kind": "array", "length": len(item)}

    if isinstance(item, str):
        return truncate_text(item)

    if isinstance(item, (int, float, bool)) or item is None:
        return item

    return truncate_text(type(item).__name__)


# ---------------------------------------------------------------------------
# JSON I/O
# ---------------------------------------------------------------------------

def json_load(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return default


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(path.parent),
            delete=False,
            newline="\n",
        ) as tmp:
            tmp.write(text)
            tmp_path = Path(tmp.name)
        tmp_path.replace(path)
    finally:
        if tmp_path and tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass


def json_dump(path: Path, data: Any) -> None:
    json_text = json.dumps(
        to_json_compatible(data),
        indent=2,
        ensure_ascii=False,
        sort_keys=False,
    )
    atomic_write_text(path, json_text + "\n")


# ---------------------------------------------------------------------------
# Workspace path helpers
# ---------------------------------------------------------------------------

def _default_workspace_root() -> Path:
    # helpers/workspace.py -> helpers/ -> runtime root
    _runtime_root = Path(__file__).resolve().parent.parent
    if _runtime_root.name == ".agent":
        return _runtime_root.parent
    return _runtime_root


def _workspace_base_dir() -> Path:
    return _default_workspace_root() / ".agent" / "workspace"


def normalize_run_dir(run_dir: str | Path) -> Path:
    p = coerce_path(run_dir)
    p.mkdir(parents=True, exist_ok=True)
    return p


def step_dir(run_dir: str | Path, step_name: str) -> Path:
    safe_step = safe_name(step_name, fallback="step")
    return normalize_run_dir(run_dir) / safe_step


def _parse_manifest_timestamp(value: Any) -> datetime:
    if isinstance(value, str) and value.strip():
        text = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            pass
    return datetime.fromtimestamp(0, tz=timezone.utc)


def _summarize_run_steps(steps: Any) -> dict[str, Any]:
    if not isinstance(steps, dict):
        steps = {}

    statuses: list[str] = []
    for step_record in steps.values():
        if isinstance(step_record, dict):
            status = str(step_record.get("status", "unknown")).strip().lower()
        else:
            status = "unknown"
        statuses.append(status or "unknown")

    if not statuses:
        overall = "empty"
    elif any(status == "error" for status in statuses):
        overall = "error"
    elif all(status == "success" for status in statuses):
        overall = "success"
    elif any(status in {"running", "in_progress", "pending"} for status in statuses):
        overall = "in_progress"
    else:
        overall = "partial"

    counts: dict[str, int] = {}
    for status in statuses:
        counts[status] = counts.get(status, 0) + 1

    return {
        "status": overall,
        "step_count": len(statuses),
        "success_steps": counts.get("success", 0),
        "error_steps": counts.get("error", 0),
        "step_status_counts": counts,
    }


# ---------------------------------------------------------------------------
# Public workspace I/O API
# ---------------------------------------------------------------------------

def create_run_dir(module_name: str, goal: str) -> str:
    """Create and return a new workspace run directory path.

    Directory format:
        .agent/workspace/<timestamp>_<module>_<goal>/
    """
    base = _workspace_base_dir()
    base.mkdir(parents=True, exist_ok=True)

    module_part = safe_name(module_name, fallback="module")
    goal_part = safe_name(goal, fallback="goal")
    run_id_seed = f"{module_part}_{goal_part}_{_utc_now().strftime(_RUN_ID_TIME_FMT)}"
    run_id = run_id_seed
    counter = 2

    run_dir = base / run_id
    while run_dir.exists():
        run_id = f"{run_id_seed}_{counter}"
        run_dir = base / run_id
        counter += 1

    run_dir.mkdir(parents=True, exist_ok=False)

    manifest = {
        "run_id": run_id,
        "module_name": module_name,
        "goal": goal,
        "created_at": utc_iso(),
        "updated_at": utc_iso(),
        "steps": {},
    }
    json_dump(run_dir / MANIFEST_FILE, manifest)
    return str(run_dir)


def list_runs(
    module: Optional[str] = None,
    goal: Optional[str] = None,
    limit: Optional[int] = 10,
) -> list[dict[str, Any]]:
    """Return workspace runs sorted by most recently updated first.

    The returned rows include the manifest fields plus derived status metadata
    so callers can render a compact runs table without re-reading each step.
    Invalid manifests are included with ``status="invalid"`` so users can still
    discover broken runs and inspect them manually.
    """
    base = _workspace_base_dir()
    if not base.exists():
        return []

    module_filter = module.strip().lower() if isinstance(module, str) and module.strip() else None
    goal_filter = goal.strip().lower() if isinstance(goal, str) and goal.strip() else None

    runs: list[dict[str, Any]] = []
    for run_dir in base.iterdir():
        if not run_dir.is_dir():
            continue

        manifest_path = run_dir / MANIFEST_FILE
        manifest = json_load(manifest_path, default=None)

        if isinstance(manifest, dict):
            run_module = str(manifest.get("module_name", "")).strip()
            run_goal = str(manifest.get("goal", "")).strip()
            if module_filter and run_module.lower() != module_filter:
                continue
            if goal_filter and run_goal.lower() != goal_filter:
                continue

            step_summary = _summarize_run_steps(manifest.get("steps", {}))
            runs.append(
                {
                    "run_id": str(manifest.get("run_id") or run_dir.name),
                    "module_name": run_module,
                    "goal": run_goal,
                    "created_at": manifest.get("created_at"),
                    "updated_at": manifest.get("updated_at"),
                    "status": step_summary["status"],
                    "step_count": step_summary["step_count"],
                    "success_steps": step_summary["success_steps"],
                    "error_steps": step_summary["error_steps"],
                    "step_status_counts": step_summary["step_status_counts"],
                    "steps": manifest.get("steps", {}),
                    "run_dir": str(run_dir),
                    "manifest_path": str(manifest_path),
                }
            )
            continue

        if module_filter or goal_filter:
            continue

        runs.append(
            {
                "run_id": run_dir.name,
                "module_name": "",
                "goal": "",
                "created_at": None,
                "updated_at": None,
                "status": "invalid",
                "step_count": 0,
                "success_steps": 0,
                "error_steps": 0,
                "step_status_counts": {},
                "steps": {},
                "run_dir": str(run_dir),
                "manifest_path": str(manifest_path),
            }
        )

    runs.sort(
        key=lambda run: (
            _parse_manifest_timestamp(run.get("updated_at")),
            _parse_manifest_timestamp(run.get("created_at")),
            run.get("run_id", ""),
        ),
        reverse=True,
    )

    if limit is not None and limit > 0:
        return runs[:limit]
    return runs


def write_results(
    run_dir: str | Path,
    step_name: str,
    full_data: Any,
    summary_data: Any,
) -> dict[str, str]:
    """Write step full output + compact summary into the run workspace."""
    sp = step_dir(run_dir, step_name)
    sp.mkdir(parents=True, exist_ok=True)

    results_path = sp / RESULTS_FILE
    summary_path = sp / SUMMARY_FILE
    json_dump(results_path, full_data)
    json_dump(summary_path, summary_data)

    return {
        "step_name": sp.name,
        "results_path": str(results_path),
        "summary_path": str(summary_path),
    }


def get_step_paths(run_dir: str | Path, step_name: str) -> dict[str, str]:
    """Return paths for a step's results.json and summary.json (no I/O).

    Use with prepare_step() from helpers.workspace_bootstrap for full setup.
    """
    sp = step_dir(run_dir, step_name)
    return {
        "step_name": sp.name,
        "step_path": str(sp),
        "results_path": str(sp / RESULTS_FILE),
        "summary_path": str(sp / SUMMARY_FILE),
    }


def read_results(run_dir: str | Path, step_name: str) -> Any:
    """Read and return full results JSON for a step (or None)."""
    path = step_dir(run_dir, step_name) / RESULTS_FILE
    return json_load(path, default=None)


def read_summary(run_dir: str | Path, step_name: str) -> Any:
    """Read and return summary JSON for a step (or None)."""
    path = step_dir(run_dir, step_name) / SUMMARY_FILE
    return json_load(path, default=None)


def update_manifest(
    run_dir: str | Path,
    step_name: str,
    status: str,
    summary_path: str | Path,
) -> dict[str, Any]:
    """Upsert a step status record in run manifest.json."""
    run_path = normalize_run_dir(run_dir)
    manifest_path = run_path / MANIFEST_FILE

    manifest = json_load(manifest_path, default={})
    if not isinstance(manifest, dict):
        manifest = {}

    steps = manifest.setdefault("steps", {})
    if not isinstance(steps, dict):
        steps = {}
        manifest["steps"] = steps

    safe_step = safe_name(step_name, fallback="step")
    summary_raw = Path(summary_path).expanduser()
    if summary_raw.is_absolute():
        summary_abs = summary_raw.resolve()
    else:
        summary_abs = (run_path / summary_raw).resolve()
    try:
        summary_rel = summary_abs.relative_to(run_path).as_posix()
    except ValueError:
        summary_rel = str(summary_abs)

    steps[safe_step] = {
        "status": status,
        "summary_path": summary_rel,
        "updated_at": utc_iso(),
    }

    manifest.setdefault("run_id", run_path.name)
    manifest.setdefault("created_at", utc_iso())
    manifest["updated_at"] = utc_iso()
    json_dump(manifest_path, manifest)
    return manifest


# ---------------------------------------------------------------------------
# Summary helpers (used by bootstrap finalization)
# ---------------------------------------------------------------------------

def summarize_json_payload(payload: Any) -> dict[str, Any]:
    if isinstance(payload, dict):
        keys = list(payload.keys())
        summary: dict[str, Any] = {
            "kind": "object",
            "key_count": len(keys),
            "keys": keys[:20],
        }
        list_lengths = {
            key: len(value)
            for key, value in payload.items()
            if isinstance(value, list)
        }
        if list_lengths:
            summary["list_lengths"] = dict(list(list_lengths.items())[:20])

        scalar_preview = {}
        for key, value in payload.items():
            if isinstance(value, (str, int, float, bool)) or value is None:
                scalar_preview[key] = compact_scalar_preview(value)
            if len(scalar_preview) >= 10:
                break
        if scalar_preview:
            summary["scalars"] = scalar_preview
        return summary

    if isinstance(payload, list):
        summary = {
            "kind": "array",
            "length": len(payload),
            "item_type": type(payload[0]).__name__ if payload else None,
        }
        if payload:
            summary["sample"] = [compact_item_preview(item) for item in payload[:3]]
        return summary

    if isinstance(payload, str):
        return {
            "kind": "string",
            "char_count": len(payload),
            "preview": truncate_text(payload),
        }

    return {
        "kind": type(payload).__name__,
        "value": (
            payload
            if isinstance(payload, (int, float, bool)) or payload is None
            else truncate_text(repr(payload))
        ),
    }


def summarize_text_payload(text: str) -> dict[str, Any]:
    lines = text.splitlines()
    non_empty = [line for line in lines if line.strip()]
    preview = [truncate_text(line) for line in non_empty[:5]]
    return {
        "kind": "text",
        "char_count": len(text),
        "line_count": len(lines),
        "non_empty_line_count": len(non_empty),
        "preview_lines": preview,
    }


def infer_default_step(script_path: Path) -> str:
    if script_path.parent.name == "scripts" and script_path.parent.parent.name:
        return script_path.parent.parent.name
    return script_path.stem
