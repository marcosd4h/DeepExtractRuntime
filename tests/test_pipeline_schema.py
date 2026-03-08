"""Tests for helpers.pipeline_schema."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from helpers.command_validation import CommandValidationResult
from helpers.errors import ScriptError
from helpers.pipeline_schema import (
    PipelineDef,
    STEP_REGISTRY,
    PipelineSettings,
    ResolvedModule,
    load_pipeline,
    render_output_path,
    resolve_modules,
    validate_pipeline,
)
from helpers.validation import ValidationResult


def _write_pipeline(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "pipeline.yaml"
    path.write_text(textwrap.dedent(text).strip() + "\n", encoding="utf-8")
    return path


def test_load_pipeline_parses_minimal_definition(tmp_path):
    path = _write_pipeline(
        tmp_path,
        """
        name: nightly-security-sweep
        modules:
          - appinfo.dll
          - consent.exe
        steps:
          - triage: {}
          - scan:
              top: 10
        settings:
          continue_on_error: true
          max_workers: 4
          step_timeout: 300
          parallel_modules: false
          no_cache: false
        output: workspace/batch_{name}_{timestamp}/
        """,
    )

    pipeline = load_pipeline(path)

    assert isinstance(pipeline, PipelineDef)
    assert pipeline.name == "nightly-security-sweep"
    assert pipeline.modules == ["appinfo.dll", "consent.exe"]
    assert [step.name for step in pipeline.steps] == ["triage", "scan"]
    assert pipeline.steps[1].options["top"] == 10
    assert pipeline.settings.max_workers == 4


def test_load_pipeline_accepts_bare_steps(tmp_path):
    path = _write_pipeline(
        tmp_path,
        """
        modules: all
        steps:
          - triage
          - types
        """,
    )

    pipeline = load_pipeline(path)

    assert pipeline.modules == "all"
    assert [step.name for step in pipeline.steps] == ["triage", "types"]
    assert pipeline.steps[0].options == {}


def test_load_pipeline_rejects_unknown_step(tmp_path):
    path = _write_pipeline(
        tmp_path,
        """
        modules: all
        steps:
          - made-up-step: {}
        """,
    )

    with pytest.raises(ScriptError, match="Unknown pipeline step"):
        load_pipeline(path)


def test_load_pipeline_rejects_invalid_step_option_type(tmp_path):
    path = _write_pipeline(
        tmp_path,
        """
        modules: all
        steps:
          - scan:
              top: "ten"
        """,
    )

    with pytest.raises(ScriptError, match="must be an integer"):
        load_pipeline(path)


def test_load_pipeline_rejects_multiple_scan_modes(tmp_path):
    path = _write_pipeline(
        tmp_path,
        """
        modules: all
        steps:
          - scan:
              memory_only: true
              logic_only: true
        """,
    )

    with pytest.raises(ScriptError, match="at most one of"):
        load_pipeline(path)


def test_render_output_path_supports_workspace_shorthand(tmp_path):
    rendered = render_output_path(
        "workspace/batch_{name}_{timestamp}/",
        "security-sweep",
        tmp_path,
        timestamp="20260306_010203",
    )

    assert rendered == (tmp_path / ".agent" / "workspace" / "batch_security-sweep_20260306_010203").resolve()


def test_resolve_modules_uses_validate_module(monkeypatch, tmp_path):
    def fake_validate_module(module_name, workspace_root):
        result = CommandValidationResult()
        result.resolved["db_path"] = str(tmp_path / f"{module_name}.db")
        return result

    monkeypatch.setattr("helpers.command_validation.validate_module", fake_validate_module)

    resolved = resolve_modules(["appinfo.dll"], tmp_path)

    assert resolved == [
        ResolvedModule(
            module_name="appinfo.dll",
            db_path=str((tmp_path / "appinfo.dll.db").resolve()),
        )
    ]


def test_resolve_modules_all_uses_filesystem_fallback(monkeypatch, tmp_path):
    expected = [ResolvedModule("appinfo.dll", str((tmp_path / "appinfo.db").resolve()))]

    monkeypatch.setattr("helpers.pipeline_schema._resolve_all_modules_from_tracking", lambda _root: [])
    monkeypatch.setattr(
        "helpers.pipeline_schema._resolve_all_modules_from_filesystem",
        lambda _root: expected,
    )

    resolved = resolve_modules("all", tmp_path)

    assert resolved == expected


def test_validate_pipeline_aggregates_db_validation_errors(monkeypatch, tmp_path):
    path = _write_pipeline(
        tmp_path,
        """
        modules:
          - appinfo.dll
        steps:
          - triage: {}
        """,
    )
    pipeline = load_pipeline(path)

    monkeypatch.setattr(
        "helpers.pipeline_schema.resolve_modules",
        lambda modules, root=None: [ResolvedModule("appinfo.dll", str(tmp_path / "appinfo.db"))],
    )
    bad = ValidationResult(ok=False, errors=["Missing required table: functions"])
    monkeypatch.setattr("helpers.pipeline_schema.validate_analysis_db", lambda _path: bad)

    result = validate_pipeline(pipeline, tmp_path)

    assert not result.ok
    assert any("Missing required table" in error for error in result.errors)


def test_step_registry_contains_documented_core_steps():
    for name in (
        "triage",
        "security",
        "full-analysis",
        "types",
        "scan",
        "memory-scan",
        "logic-scan",
        "entrypoints",
        "classify",
        "callgraph",
        "taint",
        "dossiers",
    ):
        assert name in STEP_REGISTRY


def test_pipeline_settings_module_workers_for_bool_and_int():
    bool_settings = PipelineSettings(
        continue_on_error=True,
        max_workers=4,
        step_timeout=300,
        parallel_modules=True,
        max_module_workers=2,
        no_cache=False,
    )
    int_settings = PipelineSettings(
        continue_on_error=True,
        max_workers=4,
        step_timeout=300,
        parallel_modules=3,
        max_module_workers=2,
        no_cache=False,
    )

    assert bool_settings.module_workers == 2
    assert int_settings.module_workers == 3
