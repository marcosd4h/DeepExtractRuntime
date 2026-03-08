"""Tests for helpers.pipeline_executor."""

from __future__ import annotations

import json
from pathlib import Path

from helpers.pipeline_executor import (
    ModuleResult,
    StepResult,
    execute_module,
    execute_pipeline,
)
from helpers.pipeline_schema import PipelineDef, PipelineSettings, StepConfig, StepDef, ResolvedModule


def _settings(**overrides) -> PipelineSettings:
    base = {
        "continue_on_error": True,
        "max_workers": 4,
        "step_timeout": 300,
        "parallel_modules": False,
        "max_module_workers": 2,
        "no_cache": False,
    }
    base.update(overrides)
    return PipelineSettings(**base)


def _pipeline(output_dir: str, settings: PipelineSettings | None = None) -> PipelineDef:
    return PipelineDef(
        name="security-sweep",
        source_path="config/pipelines/security-sweep.yaml",
        modules=["appinfo.dll"],
        steps=[
            StepDef(
                name="triage",
                options={},
                config=StepConfig(
                    name="triage",
                    kind="triage_goal",
                    description="Triage",
                    goal="triage",
                ),
            ),
            StepDef(
                name="scan",
                options={"top": 10},
                config=StepConfig(
                    name="scan",
                    kind="security_scan",
                    description="Scan",
                ),
            ),
        ],
        settings=settings or _settings(),
        output=output_dir,
    )


def _fake_dispatch(module, step, step_dir, settings):
    step_dir = Path(step_dir)
    step_dir.mkdir(parents=True, exist_ok=True)
    (step_dir / "manifest.json").write_text(
        json.dumps({"run_id": step_dir.name, "steps": {}}),
        encoding="utf-8",
    )
    return StepResult(
        step_name=step.name,
        status="success",
        elapsed_seconds=0.01,
        workspace_path=str(step_dir),
        data={"module": module.module_name, "step": step.name},
    )


def test_execute_module_runs_all_steps(monkeypatch, tmp_path):
    monkeypatch.setattr("helpers.pipeline_executor._dispatch_step", _fake_dispatch)

    module = ResolvedModule("appinfo.dll", str(tmp_path / "appinfo.db"))
    result = execute_module(
        module,
        _pipeline(str(tmp_path / "out")).steps,
        _settings(),
        tmp_path / "out",
    )

    assert isinstance(result, ModuleResult)
    assert result.status == "success"
    assert [step.step_name for step in result.step_results] == ["triage", "scan"]


def test_execute_module_stops_after_failure_when_continue_on_error_false(monkeypatch, tmp_path):
    def fake_dispatch(module, step, step_dir, settings):
        if step.name == "triage":
            return StepResult(
                step_name=step.name,
                status="failed",
                elapsed_seconds=0.01,
                workspace_path=str(step_dir),
                error="triage failed",
            )
        return _fake_dispatch(module, step, step_dir, settings)

    monkeypatch.setattr("helpers.pipeline_executor._dispatch_step", fake_dispatch)

    module = ResolvedModule("appinfo.dll", str(tmp_path / "appinfo.db"))
    result = execute_module(
        module,
        _pipeline(str(tmp_path / "out"), settings=_settings(continue_on_error=False)).steps,
        _settings(continue_on_error=False),
        tmp_path / "out",
    )

    assert result.status == "failed"
    assert [step.step_name for step in result.step_results] == ["triage"]
    assert result.errors == ["triage: triage failed"]


def test_execute_pipeline_dry_run_returns_planned_steps(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "helpers.pipeline_executor.resolve_modules",
        lambda modules, root=None: [
            ResolvedModule("appinfo.dll", str(tmp_path / "appinfo.db")),
            ResolvedModule("consent.exe", str(tmp_path / "consent.db")),
        ],
    )

    result = execute_pipeline(_pipeline(str(tmp_path / "out")), dry_run=True)
    payload = result.to_dict()

    assert payload["status"] == "ok"
    assert payload.get("dry_run") is True
    assert payload["total_modules"] == 2
    assert payload["modules"]["appinfo.dll"]["step_results"][0]["status"] == "planned"
    assert not (tmp_path / "out").exists()


def test_execute_pipeline_writes_manifest_and_summary(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "helpers.pipeline_executor.resolve_modules",
        lambda modules, root=None: [ResolvedModule("appinfo.dll", str(tmp_path / "appinfo.db"))],
    )
    monkeypatch.setattr("helpers.pipeline_executor._dispatch_step", _fake_dispatch)

    output_dir = tmp_path / "batch_out"
    result = execute_pipeline(_pipeline(str(output_dir)))

    assert result.status == "ok"
    assert (output_dir / "batch_manifest.json").exists()
    assert (output_dir / "batch_summary.json").exists()

    summary = json.loads((output_dir / "batch_summary.json").read_text(encoding="utf-8"))
    assert summary["status"] == "ok"
    assert summary["modules"]["appinfo.dll"]["status"] == "success"


def test_execute_pipeline_parallel_modules_preserves_input_order(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "helpers.pipeline_executor.resolve_modules",
        lambda modules, root=None: [
            ResolvedModule("consent.exe", str(tmp_path / "consent.db")),
            ResolvedModule("appinfo.dll", str(tmp_path / "appinfo.db")),
        ],
    )
    monkeypatch.setattr("helpers.pipeline_executor._dispatch_step", _fake_dispatch)

    pipeline = _pipeline(
        str(tmp_path / "parallel_out"),
        settings=_settings(parallel_modules=2, max_module_workers=2),
    )
    result = execute_pipeline(pipeline)

    assert [module.module_name for module in result.modules] == ["consent.exe", "appinfo.dll"]
