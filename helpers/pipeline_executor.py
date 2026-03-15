"""Execution engine for headless batch pipelines."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .db_paths import safe_makedirs
from .errors import ErrorCode, ScriptError, log_warning
from .pipeline_schema import (
    PipelineDef,
    PipelineSettings,
    ResolvedModule,
    StepDef,
    render_output_path,
    resolve_modules,
)
from .progress import status_message
from .script_runner import find_agent_script, get_workspace_root, run_skill_script
from .validation import ValidationResult
from .workspace import read_results, read_summary


@dataclass
class StepResult:
    """Outcome of one top-level pipeline step."""

    step_name: str
    status: str
    elapsed_seconds: float
    workspace_path: str | None = None
    error: str | None = None
    data: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_name": self.step_name,
            "status": self.status,
            "elapsed_seconds": self.elapsed_seconds,
            "workspace_path": self.workspace_path,
            "error": self.error,
            "data": self.data,
        }


@dataclass
class ModuleResult:
    """Execution summary for a single module."""

    module_name: str
    db_path: str
    status: str
    elapsed_seconds: float
    step_results: list[StepResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_name": self.module_name,
            "db_path": self.db_path,
            "status": self.status,
            "elapsed_seconds": self.elapsed_seconds,
            "errors": self.errors,
            "step_results": [step.to_dict() for step in self.step_results],
        }


@dataclass
class BatchResult:
    """Execution summary for a full batch pipeline run."""

    pipeline_name: str
    source_path: str
    output_dir: str
    status: str
    dry_run: bool
    settings: dict[str, Any]
    modules: list[ModuleResult]
    total_elapsed_seconds: float

    def to_dict(self) -> dict[str, Any]:
        succeeded_modules = sum(1 for module in self.modules if module.status == "success")
        failed_modules = sum(1 for module in self.modules if module.status == "failed")
        total_steps = sum(len(module.step_results) for module in self.modules)
        return {
            "status": self.status,
            "pipeline_complete": failed_modules == 0,
            "pipeline_name": self.pipeline_name,
            "source_path": self.source_path,
            "output_dir": self.output_dir,
            "dry_run": self.dry_run,
            "settings": self.settings,
            "total_modules": len(self.modules),
            "succeeded_modules": succeeded_modules,
            "failed_modules": failed_modules,
            "total_steps_run": total_steps,
            "total_elapsed_seconds": self.total_elapsed_seconds,
            "modules": {module.module_name: module.to_dict() for module in self.modules},
        }


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_name(value: str, fallback: str = "item") -> str:
    text = (value or "").strip()
    if not text:
        text = fallback
    safe = []
    for ch in text:
        if ch.isalnum() or ch in "._-":
            safe.append(ch)
        else:
            safe.append("-")
    normalized = "".join(safe).strip(".-_")
    return normalized or fallback


def _json_dump(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False, default=str) + "\n",
        encoding="utf-8",
    )


def _ensure_clean_directory(path: Path) -> None:
    if path.exists():
        if not path.is_dir():
            raise ScriptError(f"Output path exists and is not a directory: {path}", ErrorCode.INVALID_ARGS)
        if any(path.iterdir()):
            raise ScriptError(
                f"Output directory already exists and is not empty: {path}",
                ErrorCode.INVALID_ARGS,
            )
        return
    safe_makedirs(path)


def _init_workspace_run(run_dir: Path, module_name: str, goal: str) -> None:
    safe_makedirs(run_dir)
    manifest_path = run_dir / "manifest.json"
    if manifest_path.exists():
        return
    _json_dump(
        manifest_path,
        {
            "run_id": run_dir.name,
            "module_name": module_name,
            "goal": goal,
            "created_at": _utc_iso(),
            "updated_at": _utc_iso(),
            "steps": {},
        },
    )


def _unwrap_workspace_output(full_result: dict | None) -> dict | list | str | None:
    if not isinstance(full_result, dict):
        return full_result
    output_type = full_result.get("output_type")
    if output_type == "json":
        return full_result.get("stdout")
    if output_type == "text":
        return full_result.get("stdout_text", "")
    return full_result


def _load_workspace_payload(run_dir: Path, step_name: str) -> dict | list | str | None:
    return _unwrap_workspace_output(read_results(str(run_dir), step_name))


def _workspace_summary(run_dir: Path) -> dict[str, Any]:
    manifest_path = run_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    steps = manifest.get("steps", {}) if isinstance(manifest, dict) else {}
    substeps: dict[str, Any] = {}
    succeeded = 0
    failed = 0
    for step_name, step_record in steps.items():
        summary = read_summary(str(run_dir), step_name)
        substeps[step_name] = summary
        if isinstance(step_record, dict) and step_record.get("status") in ("ok", "success"):
            succeeded += 1
        else:
            failed += 1
    status = "ok"
    if failed and succeeded:
        status = "partial"
    elif failed and not succeeded:
        status = "failed"
    return {
        "status": status,
        "substeps": substeps,
        "pipeline_summary": {
            "total_steps": len(steps),
            "succeeded": succeeded,
            "failed": failed,
        },
    }


def _prefixed_env(settings: PipelineSettings) -> dict[str, str]:
    env = os.environ.copy()
    # Existing triage-coordinator uses triage.max_workers for grouped execution.
    env["DEEPEXTRACT_TRIAGE__MAX_WORKERS"] = str(settings.max_workers)
    return env


def _run_agent_script(
    agent_name: str,
    script_name: str,
    args: list[str],
    *,
    timeout: int,
    json_output: bool = True,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    script_path = find_agent_script(agent_name, script_name)
    if script_path is None:
        return {
            "success": False,
            "stdout": "",
            "stderr": "",
            "json_data": None,
            "exit_code": -1,
            "error": f"Agent script not found: {agent_name}/scripts/{script_name}",
        }

    cmd = [sys.executable, str(script_path)] + [str(arg) for arg in args]
    if json_output and "--json" not in cmd:
        cmd.append("--json")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(get_workspace_root()),
            env=env or os.environ.copy(),
        )
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "stdout": "",
            "stderr": "",
            "json_data": None,
            "exit_code": -1,
            "error": f"Timeout after {timeout}s",
        }
    except Exception as exc:  # pragma: no cover - defensive
        return {
            "success": False,
            "stdout": "",
            "stderr": "",
            "json_data": None,
            "exit_code": -1,
            "error": str(exc),
        }

    if result.stderr.strip():
        for line in result.stderr.strip().splitlines():
            print(f"  [{script_name}] {line}", file=sys.stderr)

    json_data = None
    json_error = None
    if json_output and result.stdout.strip():
        try:
            json_data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            json_error = f"Failed to parse JSON stdout from {script_name}: {exc}"

    return {
        "success": result.returncode == 0 and json_error is None,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "json_data": json_data,
        "exit_code": result.returncode,
        "error": (
            json_error
            if json_error is not None
            else (None if result.returncode == 0 else result.stderr[:500])
        ),
    }


def _extract_ranked_names(run_dir: Path, step_name: str = "rank_entrypoints") -> list[str]:
    payload = _load_workspace_payload(run_dir, step_name)
    if payload is None:
        return []

    names: list[str] = []
    if isinstance(payload, list):
        for entry in payload:
            if isinstance(entry, dict):
                name = entry.get("function_name") or entry.get("name")
                if isinstance(name, str) and name:
                    names.append(name)
    elif isinstance(payload, dict):
        for key in ("ranked", "entrypoints", "top_entrypoints", "ranked_entrypoints"):
            entries = payload.get(key)
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if isinstance(entry, dict):
                    name = entry.get("function_name") or entry.get("name")
                    if isinstance(name, str) and name:
                        names.append(name)
            if names:
                break
    return names


def _status_from_result(result: dict[str, Any]) -> str:
    return "success" if result.get("success") else "failed"


def _step_result_from_workspace(
    step_name: str,
    workspace_dir: Path,
    started_at: float,
    *,
    error: str | None = None,
) -> StepResult:
    summary = _workspace_summary(workspace_dir)
    raw_status = summary.get("status", "ok")
    status = "success" if raw_status in ("ok", "success") else raw_status
    if error and status == "success":
        status = "partial"
    return StepResult(
        step_name=step_name,
        status=status,
        elapsed_seconds=round(time.time() - started_at, 3),
        workspace_path=str(workspace_dir),
        error=error,
        data=summary,
    )


def _run_grouped_skill_steps(
    workspace_dir: Path,
    steps: list[tuple[str, str, str, list[str]]],
    settings: PipelineSettings,
    *,
    parallel: bool = True,
) -> tuple[dict[str, dict[str, Any]], str | None]:
    results: dict[str, dict[str, Any]] = {}
    first_error: str | None = None

    def _invoke(step_name: str, skill: str, script: str, args: list[str]) -> dict[str, Any]:
        return run_skill_script(
            skill,
            script,
            args,
            timeout=settings.step_timeout,
            json_output=True,
            workspace_dir=str(workspace_dir),
            workspace_step=step_name,
            max_retries=1,
        )

    if parallel and len(steps) > 1:
        workers = max(1, min(settings.max_workers, len(steps)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {
                pool.submit(_invoke, step_name, skill, script, args): step_name
                for step_name, skill, script, args in steps
            }
            for future in as_completed(future_map):
                step_name = future_map[future]
                try:
                    result = future.result()
                except Exception as exc:  # pragma: no cover - defensive
                    result = {
                        "success": False,
                        "error": str(exc),
                        "stdout": "",
                        "stderr": "",
                        "json_data": None,
                        "exit_code": -1,
                    }
                results[step_name] = result
                if not result.get("success") and first_error is None:
                    first_error = result.get("error") or f"{step_name} failed"
    else:
        for step_name, skill, script, args in steps:
            result = _invoke(step_name, skill, script, args)
            results[step_name] = result
            if not result.get("success") and first_error is None:
                first_error = result.get("error") or f"{step_name} failed"
    return results, first_error


def dispatch_goal_step(
    module: ResolvedModule,
    step: StepDef,
    workspace_dir: Path,
    settings: PipelineSettings,
) -> StepResult:
    started_at = time.time()
    _init_workspace_run(workspace_dir, module.module_name, step.name)

    args = [
        module.db_path,
        "--goal",
        step.config.goal or step.name,
        "--timeout",
        str(settings.step_timeout),
        "--workspace-run-dir",
        str(workspace_dir),
    ]
    if "top" in step.options:
        args.extend(["--top", str(step.options["top"])])
    if settings.no_cache:
        args.append("--no-cache")
    if step.options.get("quick") is True:
        args.append("--quick")

    result = _run_agent_script(
        "triage-coordinator",
        "analyze_module.py",
        args,
        timeout=max(settings.step_timeout, settings.step_timeout + 30),
        json_output=True,
        env=_prefixed_env(settings),
    )
    status = "success" if result.get("success") else "failed"
    return StepResult(
        step_name=step.name,
        status=status if status == "success" else "failed",
        elapsed_seconds=round(time.time() - started_at, 3),
        workspace_path=str(workspace_dir),
        error=result.get("error"),
        data=result.get("json_data"),
    )


def dispatch_scan_step(
    module: ResolvedModule,
    step: StepDef,
    workspace_dir: Path,
    settings: PipelineSettings,
) -> StepResult:
    if step.options.get("memory_only"):
        return _dispatch_memory_scan(module, step, workspace_dir, settings)
    if step.options.get("logic_only"):
        return _dispatch_ai_logic_scan(module, step, workspace_dir, settings)
    started_at = time.time()
    _init_workspace_run(workspace_dir, module.module_name, step.name)

    args = [
        module.db_path,
        "--goal",
        "scan",
        "--top",
        str(step.options.get("top", 10)),
        "--timeout",
        str(settings.step_timeout),
        "--workspace-run-dir",
        str(workspace_dir),
        "--max-workers",
        str(settings.max_workers),
    ]
    if settings.no_cache:
        args.append("--no-cache")

    result = _run_agent_script(
        "security-auditor",
        "run_security_scan.py",
        args,
        timeout=max(settings.step_timeout, settings.step_timeout + 30),
        json_output=True,
        env=_prefixed_env(settings),
    )
    status = "success" if result.get("success") else "failed"
    return StepResult(
        step_name=step.name,
        status=status,
        elapsed_seconds=round(time.time() - started_at, 3),
        workspace_path=str(workspace_dir),
        error=result.get("error"),
        data=result.get("json_data"),
    )


def _dispatch_memory_scan(
    module: ResolvedModule,
    step: StepDef,
    workspace_dir: Path,
    settings: PipelineSettings,
) -> StepResult:
    # Stage 1 only: build threat model + prepare callgraph context.
    # Stages 2-4 (LLM-driven analysis, specialist scans, skeptic verification)
    # are orchestrated by the /memory-scan command, not by the pipeline executor.
    started_at = time.time()
    _init_workspace_run(workspace_dir, module.module_name, step.name)

    depth = str(step.options.get("depth", 5))

    threat_model_result = run_skill_script(
        "ai-memory-corruption-scanner",
        "build_threat_model.py",
        [module.db_path],
        timeout=settings.step_timeout,
        json_output=True,
        workspace_dir=str(workspace_dir),
        workspace_step="threat_model",
        max_retries=1,
    )
    if not threat_model_result.get("success"):
        error = threat_model_result.get("error", "build_threat_model failed")
        return _step_result_from_workspace(step.name, workspace_dir, started_at, error=error)

    prepare_result = run_skill_script(
        "ai-memory-corruption-scanner",
        "prepare_context.py",
        [module.db_path, "--entry-points", "--depth", depth],
        timeout=settings.step_timeout,
        json_output=True,
        workspace_dir=str(workspace_dir),
        workspace_step="prepare_context",
        max_retries=1,
    )
    error = None if prepare_result.get("success") else prepare_result.get("error")
    return _step_result_from_workspace(step.name, workspace_dir, started_at, error=error)


def _dispatch_ai_logic_scan(
    module: ResolvedModule,
    step: StepDef,
    workspace_dir: Path,
    settings: PipelineSettings,
) -> StepResult:
    started_at = time.time()
    _init_workspace_run(workspace_dir, module.module_name, step.name)
    depth = str(step.options.get("depth", 5))
    error = None
    try:
        run_skill_script("ai-logic-scanner", "build_threat_model.py",
                         [module.db_path], json_output=True, timeout=settings.step_timeout,
                         workspace_dir=str(workspace_dir), workspace_step="threat_model")
    except Exception as exc:
        error = str(exc)
    try:
        run_skill_script("ai-logic-scanner", "prepare_context.py",
                         [module.db_path, "--entry-points", "--depth", depth],
                         json_output=True, timeout=settings.step_timeout,
                         workspace_dir=str(workspace_dir), workspace_step="context")
    except Exception as exc:
        error = error or str(exc)
    return _step_result_from_workspace(step.name, workspace_dir, started_at, error=error)


def _dispatch_entrypoints(
    module: ResolvedModule,
    step: StepDef,
    workspace_dir: Path,
    settings: PipelineSettings,
) -> StepResult:
    started_at = time.time()
    _init_workspace_run(workspace_dir, module.module_name, step.name)

    discover_args = [module.db_path]
    rank_args = [module.db_path, "--top", str(step.options.get("top", 10))]
    if settings.no_cache:
        discover_args.append("--no-cache")

    steps = [
        ("discover_entrypoints", "map-attack-surface", "discover_entrypoints.py", discover_args),
        ("rank_entrypoints", "map-attack-surface", "rank_entrypoints.py", rank_args),
    ]
    _, error = _run_grouped_skill_steps(workspace_dir, steps, settings, parallel=True)
    return _step_result_from_workspace(step.name, workspace_dir, started_at, error=error)


def _dispatch_classify(
    module: ResolvedModule,
    step: StepDef,
    workspace_dir: Path,
    settings: PipelineSettings,
) -> StepResult:
    started_at = time.time()
    _init_workspace_run(workspace_dir, module.module_name, step.name)

    args = [module.db_path, "--top", str(step.options.get("top", 20))]
    if settings.no_cache:
        args.append("--no-cache")
    result = run_skill_script(
        "classify-functions",
        "triage_summary.py",
        args,
        timeout=settings.step_timeout,
        json_output=True,
        workspace_dir=str(workspace_dir),
        workspace_step="classify_triage",
        max_retries=1,
    )
    error = None if result.get("success") else result.get("error")
    return _step_result_from_workspace(step.name, workspace_dir, started_at, error=error)


def _dispatch_callgraph(
    module: ResolvedModule,
    step: StepDef,
    workspace_dir: Path,
    settings: PipelineSettings,
) -> StepResult:
    started_at = time.time()
    _init_workspace_run(workspace_dir, module.module_name, step.name)

    args = [module.db_path]
    if step.options.get("stats", True):
        args.append("--stats")
    if settings.no_cache:
        args.append("--no-cache")

    result = run_skill_script(
        "callgraph-tracer",
        "build_call_graph.py",
        args,
        timeout=settings.step_timeout,
        json_output=True,
        workspace_dir=str(workspace_dir),
        workspace_step="call_graph",
        max_retries=1,
    )
    error = None if result.get("success") else result.get("error")
    return _step_result_from_workspace(step.name, workspace_dir, started_at, error=error)


def _dispatch_dossiers(
    module: ResolvedModule,
    step: StepDef,
    workspace_dir: Path,
    settings: PipelineSettings,
) -> StepResult:
    started_at = time.time()
    _init_workspace_run(workspace_dir, module.module_name, step.name)

    top = int(step.options.get("top", 5))
    rank_args = [module.db_path, "--top", str(top)]
    rank_result = run_skill_script(
        "map-attack-surface",
        "rank_entrypoints.py",
        rank_args,
        timeout=settings.step_timeout,
        json_output=True,
        workspace_dir=str(workspace_dir),
        workspace_step="rank_entrypoints",
        max_retries=1,
    )
    if not rank_result.get("success"):
        return _step_result_from_workspace(
            step.name,
            workspace_dir,
            started_at,
            error=rank_result.get("error"),
        )

    target_names = _extract_ranked_names(workspace_dir)[:top]
    if not target_names:
        return _step_result_from_workspace(step.name, workspace_dir, started_at)

    steps = []
    for function_name in target_names:
        args = [module.db_path, function_name, "--callee-depth", "2"]
        if settings.no_cache:
            args.append("--no-cache")
        steps.append(
            (
                f"dossier_{function_name}",
                "security-dossier",
                "build_dossier.py",
                args,
            )
        )
    _, error = _run_grouped_skill_steps(workspace_dir, steps, settings, parallel=True)
    return _step_result_from_workspace(step.name, workspace_dir, started_at, error=error)


def dispatch_skill_step(
    module: ResolvedModule,
    step: StepDef,
    workspace_dir: Path,
    settings: PipelineSettings,
) -> StepResult:
    if step.name == "memory-scan":
        return _dispatch_memory_scan(module, step, workspace_dir, settings)
    if step.name == "ai-logic-scan":
        return _dispatch_ai_logic_scan(module, step, workspace_dir, settings)
    if step.name == "entrypoints":
        return _dispatch_entrypoints(module, step, workspace_dir, settings)
    if step.name == "classify":
        return _dispatch_classify(module, step, workspace_dir, settings)
    if step.name == "callgraph":
        return _dispatch_callgraph(module, step, workspace_dir, settings)
    if step.name == "dossiers":
        return _dispatch_dossiers(module, step, workspace_dir, settings)
    raise ScriptError(f"Unsupported skill-group step: {step.name}", ErrorCode.INVALID_ARGS)


def _dispatch_step(
    module: ResolvedModule,
    step: StepDef,
    workspace_dir: Path,
    settings: PipelineSettings,
) -> StepResult:
    if step.config.kind == "triage_goal":
        return dispatch_goal_step(module, step, workspace_dir, settings)
    if step.config.kind == "security_scan":
        return dispatch_scan_step(module, step, workspace_dir, settings)
    if step.config.kind == "skill_group":
        return dispatch_skill_step(module, step, workspace_dir, settings)
    raise ScriptError(f"Unsupported step kind for {step.name}: {step.config.kind}", ErrorCode.INVALID_ARGS)


def write_batch_manifest(
    batch_dir: str | Path,
    pipeline_def: PipelineDef,
    progress: dict[str, Any],
) -> str:
    """Write the top-level batch manifest."""
    batch_path = Path(batch_dir)
    manifest_path = batch_path / "batch_manifest.json"
    _json_dump(
        manifest_path,
        {
            "pipeline_name": pipeline_def.name,
            "pipeline_file": pipeline_def.source_path,
            "started_at": progress.get("started_at"),
            "updated_at": _utc_iso(),
            "modules": progress.get("modules", []),
            "steps": [step.name for step in pipeline_def.steps],
            "settings": pipeline_def.settings.to_dict(),
            "progress": progress.get("progress", {}),
        },
    )
    return str(manifest_path)


def write_batch_summary(batch_dir: str | Path, batch_result: BatchResult) -> str:
    """Write the final consolidated batch summary."""
    summary_path = Path(batch_dir) / "batch_summary.json"
    _json_dump(summary_path, batch_result.to_dict())
    return str(summary_path)


def execute_module(
    module: ResolvedModule,
    steps: list[StepDef],
    settings: PipelineSettings,
    batch_dir: str | Path,
    *,
    progress_callback: Callable[[str, StepResult], None] | None = None,
) -> ModuleResult:
    """Execute all requested steps for one module."""
    module_started = time.time()
    module_dir = Path(batch_dir) / _safe_name(module.module_name, fallback="module")
    safe_makedirs(module_dir)

    step_results: list[StepResult] = []
    errors: list[str] = []

    for step in steps:
        status_message(f"[{module.module_name}] Running step '{step.name}'")
        step_dir = module_dir / _safe_name(step.name, fallback="step")
        _ensure_clean_directory(step_dir)
        step_result = _dispatch_step(module, step, step_dir, settings)
        step_results.append(step_result)
        if progress_callback is not None:
            progress_callback(module.module_name, step_result)
        if step_result.status not in {"success", "partial"} and step_result.error:
            errors.append(f"{step.name}: {step_result.error}")
            if not settings.continue_on_error:
                break

    succeeded = sum(1 for step in step_results if step.status == "success")
    failed = sum(1 for step in step_results if step.status == "failed")
    status = "success"
    if failed and succeeded:
        status = "partial"
    elif failed and not succeeded:
        status = "failed"

    return ModuleResult(
        module_name=module.module_name,
        db_path=module.db_path,
        status=status,
        elapsed_seconds=round(time.time() - module_started, 3),
        step_results=step_results,
        errors=errors,
    )


def execute_pipeline(
    pipeline_def: PipelineDef,
    workspace_root: str | Path | None = None,
    dry_run: bool = False,
) -> BatchResult:
    """Execute or dry-run a parsed pipeline definition."""
    started_at = time.time()
    root = Path(workspace_root).resolve() if workspace_root is not None else get_workspace_root()
    resolved_modules = resolve_modules(pipeline_def.modules, root)
    output_dir = render_output_path(pipeline_def.output, pipeline_def.name, root)

    if dry_run:
        modules = [
            ModuleResult(
                module_name=module.module_name,
                db_path=module.db_path,
                status="planned",
                elapsed_seconds=0.0,
                step_results=[
                    StepResult(
                        step_name=step.name,
                        status="planned",
                        elapsed_seconds=0.0,
                    )
                    for step in pipeline_def.steps
                ],
            )
            for module in resolved_modules
        ]
        return BatchResult(
            pipeline_name=pipeline_def.name,
            source_path=pipeline_def.source_path,
            output_dir=str(output_dir),
            status="ok",
            dry_run=True,
            settings=pipeline_def.settings.to_dict(),
            modules=modules,
            total_elapsed_seconds=round(time.time() - started_at, 3),
        )

    _ensure_clean_directory(output_dir)

    progress_lock = threading.Lock()
    progress_state: dict[str, Any] = {
        "started_at": _utc_iso(),
        "modules": [module.module_name for module in resolved_modules],
        "progress": {
            module.module_name: {
                step.name: {"status": "pending"} for step in pipeline_def.steps
            }
            for module in resolved_modules
        },
    }
    write_batch_manifest(output_dir, pipeline_def, progress_state)

    def _record_progress(module_name: str, step_result: StepResult) -> None:
        with progress_lock:
            progress_state["progress"][module_name][step_result.step_name] = {
                "status": step_result.status,
                "elapsed_seconds": step_result.elapsed_seconds,
                "workspace_path": step_result.workspace_path,
                "error": step_result.error,
            }
            write_batch_manifest(output_dir, pipeline_def, progress_state)

    settings = pipeline_def.settings
    modules: list[ModuleResult] = []

    if settings.module_workers <= 1 or len(resolved_modules) <= 1:
        for module in resolved_modules:
            modules.append(
                execute_module(
                    module,
                    pipeline_def.steps,
                    settings,
                    output_dir,
                    progress_callback=_record_progress,
                )
            )
    else:
        results_by_name: dict[str, ModuleResult] = {}
        workers = min(settings.module_workers, len(resolved_modules))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {
                pool.submit(
                    execute_module,
                    module,
                    pipeline_def.steps,
                    settings,
                    output_dir,
                    progress_callback=_record_progress,
                ): module
                for module in resolved_modules
            }
            for future in as_completed(future_map):
                module = future_map[future]
                try:
                    results_by_name[module.module_name] = future.result()
                except Exception as exc:  # pragma: no cover - defensive
                    log_warning(
                        f"Module execution failed for {module.module_name}: {exc}",
                        ErrorCode.UNKNOWN,
                    )
                    results_by_name[module.module_name] = ModuleResult(
                        module_name=module.module_name,
                        db_path=module.db_path,
                        status="failed",
                        elapsed_seconds=0.0,
                        errors=[str(exc)],
                    )
        modules = [results_by_name[module.module_name] for module in resolved_modules]

    succeeded = sum(1 for module in modules if module.status == "success")
    failed = sum(1 for module in modules if module.status == "failed")
    status = "error" if failed and not succeeded else "ok"

    batch_result = BatchResult(
        pipeline_name=pipeline_def.name,
        source_path=pipeline_def.source_path,
        output_dir=str(output_dir),
        status=status,
        dry_run=False,
        settings=settings.to_dict(),
        modules=modules,
        total_elapsed_seconds=round(time.time() - started_at, 3),
    )
    write_batch_summary(output_dir, batch_result)
    return batch_result


__all__ = [
    "BatchResult",
    "ModuleResult",
    "StepResult",
    "dispatch_goal_step",
    "dispatch_skill_step",
    "execute_module",
    "execute_pipeline",
    "write_batch_manifest",
    "write_batch_summary",
]
