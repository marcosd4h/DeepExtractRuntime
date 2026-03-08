"""Tests for workspace validation and bootstrap helpers."""

import json
import pytest
from pathlib import Path

from helpers.workspace_validation import (
    WorkspaceValidationResult,
    validate_workspace_run,
)
from helpers.workspace_bootstrap import prepare_step, complete_step


def test_validate_nonexistent_run_dir(tmp_path):
    """Validate returns invalid for non-existent run directory."""
    run_dir = tmp_path / "nonexistent"
    result = validate_workspace_run(run_dir)
    assert result.valid is False
    assert "does not exist" in result.issues[0]
    assert result.run_dir == run_dir.resolve()


def test_validate_not_a_directory(tmp_path):
    """Validate returns invalid when path is a file."""
    file_path = tmp_path / "file"
    file_path.write_text("x")
    result = validate_workspace_run(file_path)
    assert result.valid is False
    assert "not a directory" in result.issues[0]


def test_validate_missing_manifest(tmp_path):
    """Validate returns invalid when manifest.json is missing."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    result = validate_workspace_run(run_dir)
    assert result.valid is False
    assert "manifest.json" in result.issues[0]


def test_validate_invalid_manifest_json(tmp_path):
    """Validate returns invalid for malformed manifest.json."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "manifest.json").write_text("not json {")
    result = validate_workspace_run(run_dir)
    assert result.valid is False
    assert "invalid" in result.issues[0].lower() or "unreadable" in result.issues[0].lower()


def test_validate_empty_manifest_steps(tmp_path):
    """Validate passes for run dir with empty steps."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    manifest = {"run_id": "test", "steps": {}, "created_at": "2024-01-01T00:00:00Z"}
    (run_dir / "manifest.json").write_text(json.dumps(manifest))
    result = validate_workspace_run(run_dir)
    assert result.valid is True
    assert result.step_count == 0
    assert result.manifest is not None


def test_validate_compliant_run(tmp_path):
    """Validate passes for a fully compliant workspace run."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    step_dir = run_dir / "step1"
    step_dir.mkdir()
    (step_dir / "results.json").write_text('{"data": []}')
    (step_dir / "summary.json").write_text('{"status": "success"}')
    manifest = {
        "run_id": "run",
        "steps": {
            "step1": {
                "status": "success",
                "summary_path": "step1/summary.json",
                "updated_at": "2024-01-01T00:00:00Z",
            }
        },
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest))
    result = validate_workspace_run(run_dir)
    assert result.valid is True
    assert result.step_count == 1
    assert len(result.issues) == 0


def test_validate_step_missing_results(tmp_path):
    """Validate fails when step has summary but no results.json."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    step_dir = run_dir / "step1"
    step_dir.mkdir()
    (step_dir / "summary.json").write_text('{"status": "success"}')
    # no results.json
    manifest = {
        "run_id": "run",
        "steps": {
            "step1": {
                "status": "success",
                "summary_path": "step1/summary.json",
            }
        },
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest))
    result = validate_workspace_run(run_dir)
    assert result.valid is False
    assert any("results.json" in i for i in result.issues)


def test_validate_step_missing_summary_path(tmp_path):
    """Validate fails when step record lacks summary_path."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    step_dir = run_dir / "step1"
    step_dir.mkdir()
    (step_dir / "results.json").write_text("{}")
    (step_dir / "summary.json").write_text("{}")
    manifest = {
        "run_id": "run",
        "steps": {"step1": {"status": "success"}},  # no summary_path
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest))
    result = validate_workspace_run(run_dir)
    assert result.valid is False
    assert any("summary_path" in i for i in result.issues)


def test_validation_result_to_dict(tmp_path):
    """WorkspaceValidationResult.to_dict returns serializable dict."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "manifest.json").write_text('{"run_id": "x", "steps": {}}')
    result = validate_workspace_run(run_dir)
    d = result.to_dict()
    assert isinstance(d, dict)
    assert "valid" in d
    assert "run_dir" in d
    assert "issues" in d
    assert "step_count" in d


def test_prepare_step_creates_directory(tmp_path):
    """prepare_step creates step directory and returns paths."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "manifest.json").write_text('{"run_id": "run", "steps": {}}')
    paths = prepare_step(run_dir, "my-step")
    assert "step_path" in paths
    assert "results_path" in paths
    assert "summary_path" in paths
    assert Path(paths["step_path"]).exists()
    assert Path(paths["step_path"]).is_dir()
    assert paths["results_path"].endswith("results.json")
    assert paths["summary_path"].endswith("summary.json")


def test_prepare_step_sanitizes_name(tmp_path):
    """prepare_step sanitizes step name for path safety."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "manifest.json").write_text('{"run_id": "run", "steps": {}}')
    paths = prepare_step(run_dir, "step/with\\bad:chars")
    step_path = Path(paths["step_path"])
    assert step_path.exists()
    assert step_path.name != "step/with\\bad:chars"


def test_complete_step_writes_and_updates_manifest(tmp_path):
    """complete_step writes results/summary and updates manifest."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    manifest = {"run_id": "run", "steps": {}, "created_at": "2024-01-01T00:00:00Z"}
    (run_dir / "manifest.json").write_text(json.dumps(manifest))
    full_data = {"output_type": "json", "items": [1, 2, 3]}
    summary_data = {"status": "success", "count": 3}
    paths = complete_step(run_dir, "phase1", full_data, summary_data)
    assert Path(paths["results_path"]).exists()
    assert Path(paths["summary_path"]).exists()
    results = json.loads(Path(paths["results_path"]).read_text())
    assert results["items"] == [1, 2, 3]
    summary = json.loads(Path(paths["summary_path"]).read_text())
    assert summary["status"] == "success"
    manifest_after = json.loads((run_dir / "manifest.json").read_text())
    assert "phase1" in manifest_after["steps"]
    assert manifest_after["steps"]["phase1"]["status"] == "success"


def test_complete_step_with_error_status(tmp_path):
    """complete_step records error status in manifest."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "manifest.json").write_text('{"run_id": "run", "steps": {}}')
    complete_step(
        run_dir,
        "failed_step",
        {"error": "something failed"},
        {"status": "error", "message": "failed"},
        status="error",
    )
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["steps"]["failed_step"]["status"] == "error"


def test_validate_after_complete_step(tmp_path):
    """Workspace validated after complete_step is compliant."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "manifest.json").write_text('{"run_id": "run", "steps": {}}')
    complete_step(run_dir, "step1", {"x": 1}, {"status": "success"})
    result = validate_workspace_run(run_dir)
    assert result.valid is True
    assert result.step_count == 1
