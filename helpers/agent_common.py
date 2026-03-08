"""Shared orchestration helpers for agent scripts.

This module provides:
- ``AgentBase``: consistent skill-script invocation wrapper
- ``AgentOrchestrator``: lightweight step execution with retry/circuit metadata
"""

from __future__ import annotations

import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Optional

from .progress import status_message
from .script_runner import run_skill_script as _run_skill_script


@dataclass(frozen=True)
class AgentStep:
    """Description of a single orchestrated skill-script invocation."""

    name: str
    skill_name: str
    script_name: str
    args: list[str]
    timeout: int = 300
    json_output: bool = True
    workspace_dir: str | None = None
    workspace_step: str | None = None
    max_retries: int = 0


@dataclass
class AgentStepResult:
    """Execution result for one :class:`AgentStep`."""

    name: str
    skill_name: str
    script_name: str
    success: bool
    elapsed_seconds: float
    exit_code: int
    error: str | None = None
    stdout: str = ""
    stderr: str = ""
    json_data: dict | list | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "skill_name": self.skill_name,
            "script_name": self.script_name,
            "success": self.success,
            "elapsed_seconds": self.elapsed_seconds,
            "exit_code": self.exit_code,
            "error": self.error,
            "json_data": self.json_data,
        }


class AgentBase:
    """Shared runner wrapper for agent skill invocations."""

    def __init__(
        self,
        default_timeout: int = 300,
        default_max_retries: int = 0,
    ) -> None:
        self.default_timeout = default_timeout
        self.default_max_retries = default_max_retries

    def run_skill_script_result(
        self,
        skill_name: str,
        script_name: str,
        args: list[str],
        *,
        timeout: int | None = None,
        json_output: bool = True,
        workspace_dir: str | None = None,
        workspace_step: str | None = None,
        max_retries: int | None = None,
        warn_on_failure: bool = True,
    ) -> dict[str, Any]:
        """Execute a skill script and return the full helper result envelope."""
        result = _run_skill_script(
            skill_name,
            script_name,
            args,
            timeout=timeout if timeout is not None else self.default_timeout,
            json_output=json_output,
            workspace_dir=workspace_dir,
            workspace_step=workspace_step,
            max_retries=(
                self.default_max_retries if max_retries is None else max_retries
            ),
        )
        if warn_on_failure and not result.get("success"):
            err = result.get("error") or ""
            err = f": {err}" if err else ""
            status_message(
                f"WARNING: {script_name} exited with code {result.get('exit_code', -1)}{err}"
            )
        return result

    def run_skill_script(
        self,
        skill_name: str,
        script_name: str,
        args: list[str],
        *,
        timeout: int | None = None,
        workspace_dir: str | None = None,
        workspace_step: str | None = None,
        max_retries: int | None = None,
    ) -> Optional[dict | list]:
        """Execute a skill script and return parsed JSON payload or ``None``."""
        result = self.run_skill_script_result(
            skill_name,
            script_name,
            args,
            timeout=timeout,
            json_output=True,
            workspace_dir=workspace_dir,
            workspace_step=workspace_step,
            max_retries=max_retries,
            warn_on_failure=True,
        )
        return result.get("json_data")


class AgentOrchestrator:
    """Run one or more :class:`AgentStep` definitions with aggregation.

    This class intentionally stays lightweight so existing agent pipelines can
    adopt it incrementally.
    """

    def __init__(
        self,
        runner: AgentBase | None = None,
        *,
        max_workers: int = 4,
        failure_threshold: int | None = None,
    ) -> None:
        self.runner = runner or AgentBase()
        self.max_workers = max_workers
        self.failure_threshold = failure_threshold
        self._results: list[AgentStepResult] = []
        self._failures = 0

    @property
    def results(self) -> list[AgentStepResult]:
        return list(self._results)

    def _circuit_open(self) -> bool:
        if self.failure_threshold is None:
            return False
        return self._failures >= self.failure_threshold

    def _record(self, step: AgentStep, result: dict[str, Any], elapsed: float) -> AgentStepResult:
        step_result = AgentStepResult(
            name=step.name,
            skill_name=step.skill_name,
            script_name=step.script_name,
            success=bool(result.get("success")),
            elapsed_seconds=round(elapsed, 3),
            exit_code=int(result.get("exit_code", -1)),
            error=result.get("error"),
            stdout=result.get("stdout", ""),
            stderr=result.get("stderr", ""),
            json_data=result.get("json_data"),
        )
        self._results.append(step_result)
        if not step_result.success:
            self._failures += 1
        return step_result

    def run_step(self, step: AgentStep) -> AgentStepResult:
        """Run a single step and return its structured result."""
        if self._circuit_open():
            result = AgentStepResult(
                name=step.name,
                skill_name=step.skill_name,
                script_name=step.script_name,
                success=False,
                elapsed_seconds=0.0,
                exit_code=-1,
                error="Circuit open: failure threshold reached",
            )
            self._results.append(result)
            return result

        started = time.time()
        raw = self.runner.run_skill_script_result(
            step.skill_name,
            step.script_name,
            step.args,
            timeout=step.timeout,
            json_output=step.json_output,
            workspace_dir=step.workspace_dir,
            workspace_step=step.workspace_step,
            max_retries=step.max_retries,
            warn_on_failure=False,
        )
        elapsed = time.time() - started
        return self._record(step, raw, elapsed)

    def run_steps(self, steps: list[AgentStep], *, parallel: bool = False) -> list[AgentStepResult]:
        """Run a list of steps sequentially or in parallel."""
        if not steps:
            return []
        if not parallel or len(steps) == 1:
            results: list[AgentStepResult] = []
            for step in steps:
                results.append(self.run_step(step))
                if self._circuit_open():
                    break
            return results

        workers = max(1, min(self.max_workers, len(steps)))
        results_by_name: dict[str, AgentStepResult] = {}
        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_to_step = {pool.submit(self.run_step, step): step for step in steps}
            for future in as_completed(future_to_step):
                step = future_to_step[future]
                try:
                    step_result = future.result()
                except Exception as exc:  # pragma: no cover - defensive fallback
                    step_result = AgentStepResult(
                        name=step.name,
                        skill_name=step.skill_name,
                        script_name=step.script_name,
                        success=False,
                        elapsed_seconds=0.0,
                        exit_code=-1,
                        error=str(exc),
                    )
                    self._results.append(step_result)
                    self._failures += 1
                results_by_name[step.name] = step_result

        return [results_by_name[s.name] for s in steps if s.name in results_by_name]

    def summary(self) -> dict[str, Any]:
        """Return compact aggregate statistics for executed steps."""
        total = len(self._results)
        failed = sum(1 for r in self._results if not r.success)
        return {
            "total_steps": total,
            "success_steps": total - failed,
            "failed_steps": failed,
            "circuit_open": self._circuit_open(),
            "failure_threshold": self.failure_threshold,
            "steps": [r.to_dict() for r in self._results],
        }


__all__ = [
    "AgentBase",
    "AgentOrchestrator",
    "AgentStep",
    "AgentStepResult",
]
