"""Tests for workspace run directory lifecycle: creation, manifest updates,
step completion, and cleanup.

Extends the basic coverage in test_workspace.py with full lifecycle tests.

Targets:
  helpers/workspace.py  (create_run_dir, write_results, update_manifest, read_results, read_summary)
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from helpers.workspace import (
    create_run_dir,
    list_runs,
    read_results,
    read_summary,
    update_manifest,
    write_results,
)


# ===================================================================
# Run directory creation
# ===================================================================

class TestRunDirectoryCreation:
    def test_creates_run_directory(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "helpers.workspace._workspace_base_dir", lambda: tmp_path
        )
        run_dir = create_run_dir("appinfo.dll", "triage")
        assert Path(run_dir).exists()
        assert Path(run_dir).is_dir()

    def test_creates_manifest(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "helpers.workspace._workspace_base_dir", lambda: tmp_path
        )
        run_dir = create_run_dir("appinfo.dll", "triage")
        manifest_path = Path(run_dir) / "manifest.json"
        assert manifest_path.exists()
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        assert manifest["module_name"] == "appinfo.dll"
        assert manifest["goal"] == "triage"
        assert "created_at" in manifest
        assert "steps" in manifest

    def test_unique_run_dirs(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "helpers.workspace._workspace_base_dir", lambda: tmp_path
        )
        dir1 = create_run_dir("mod.dll", "goal")
        dir2 = create_run_dir("mod.dll", "goal")
        assert dir1 != dir2
        assert Path(dir1).exists()
        assert Path(dir2).exists()

    def test_sanitizes_module_name(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "helpers.workspace._workspace_base_dir", lambda: tmp_path
        )
        run_dir = create_run_dir("path\\to\\mod.dll", "test/goal")
        assert Path(run_dir).exists()
        dir_name = Path(run_dir).name
        assert "\\" not in dir_name
        assert "/" not in dir_name


# ===================================================================
# Step results write/read
# ===================================================================

class TestStepResults:
    def test_write_and_read_results(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "helpers.workspace._workspace_base_dir", lambda: tmp_path
        )
        run_dir = create_run_dir("mod.dll", "test")
        full_data = {"functions": [1, 2, 3], "count": 3}
        summary_data = {"count": 3, "status": "ok"}

        paths = write_results(run_dir, "classify", full_data, summary_data)
        assert "results_path" in paths
        assert "summary_path" in paths

        loaded_full = read_results(run_dir, "classify")
        assert loaded_full is not None
        assert loaded_full["functions"] == [1, 2, 3]

        loaded_summary = read_summary(run_dir, "classify")
        assert loaded_summary is not None
        assert loaded_summary["count"] == 3

    def test_read_nonexistent_step(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "helpers.workspace._workspace_base_dir", lambda: tmp_path
        )
        run_dir = create_run_dir("mod.dll", "test")
        assert read_results(run_dir, "nonexistent") is None
        assert read_summary(run_dir, "nonexistent") is None

    def test_multiple_steps(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "helpers.workspace._workspace_base_dir", lambda: tmp_path
        )
        run_dir = create_run_dir("mod.dll", "full")

        write_results(run_dir, "step1", {"phase": 1}, {"status": "ok"})
        write_results(run_dir, "step2", {"phase": 2}, {"status": "ok"})
        write_results(run_dir, "step3", {"phase": 3}, {"status": "ok"})

        assert read_results(run_dir, "step1")["phase"] == 1
        assert read_results(run_dir, "step2")["phase"] == 2
        assert read_results(run_dir, "step3")["phase"] == 3


# ===================================================================
# Manifest updates
# ===================================================================

class TestManifestUpdates:
    def test_update_manifest_adds_step(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "helpers.workspace._workspace_base_dir", lambda: tmp_path
        )
        run_dir = create_run_dir("mod.dll", "test")
        paths = write_results(run_dir, "classify", {"data": 1}, {"ok": True})

        manifest = update_manifest(run_dir, "classify", "success", paths["summary_path"])
        assert "classify" in manifest["steps"]
        assert manifest["steps"]["classify"]["status"] == "success"

    def test_update_manifest_tracks_multiple_steps(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "helpers.workspace._workspace_base_dir", lambda: tmp_path
        )
        run_dir = create_run_dir("mod.dll", "test")

        p1 = write_results(run_dir, "step1", {}, {"ok": True})
        update_manifest(run_dir, "step1", "success", p1["summary_path"])

        p2 = write_results(run_dir, "step2", {}, {"ok": True})
        update_manifest(run_dir, "step2", "success", p2["summary_path"])

        manifest_path = Path(run_dir) / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        assert "step1" in manifest["steps"]
        assert "step2" in manifest["steps"]

    def test_update_manifest_records_error_status(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "helpers.workspace._workspace_base_dir", lambda: tmp_path
        )
        run_dir = create_run_dir("mod.dll", "test")
        paths = write_results(run_dir, "failing-step", {"error": "boom"}, {"status": "error"})

        manifest = update_manifest(run_dir, "failing-step", "error", paths["summary_path"])
        assert manifest["steps"]["failing-step"]["status"] == "error"

    def test_update_manifest_updates_timestamp(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "helpers.workspace._workspace_base_dir", lambda: tmp_path
        )
        run_dir = create_run_dir("mod.dll", "test")
        manifest_path = Path(run_dir) / "manifest.json"

        m1 = json.loads(manifest_path.read_text(encoding="utf-8"))
        created_at = m1["created_at"]

        paths = write_results(run_dir, "step1", {}, {})
        update_manifest(run_dir, "step1", "success", paths["summary_path"])

        m2 = json.loads(manifest_path.read_text(encoding="utf-8"))
        assert m2["created_at"] == created_at
        assert "updated_at" in m2


# ===================================================================
# Run listing
# ===================================================================

class TestListRuns:
    def _set_manifest_times(
        self,
        run_dir: str,
        *,
        created_at: str,
        updated_at: str,
    ) -> None:
        manifest_path = Path(run_dir) / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["created_at"] = created_at
        manifest["updated_at"] = updated_at
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    def test_returns_most_recent_runs_first(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "helpers.workspace._workspace_base_dir", lambda: tmp_path
        )

        older = create_run_dir("alpha.dll", "triage")
        newer = create_run_dir("alpha.dll", "scan")

        self._set_manifest_times(
            older,
            created_at="2026-03-01T00:00:00Z",
            updated_at="2026-03-01T01:00:00Z",
        )
        self._set_manifest_times(
            newer,
            created_at="2026-03-02T00:00:00Z",
            updated_at="2026-03-02T01:00:00Z",
        )

        runs = list_runs(limit=10)
        assert [run["run_id"] for run in runs] == [
            Path(newer).name,
            Path(older).name,
        ]

    def test_filters_by_module_and_goal(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "helpers.workspace._workspace_base_dir", lambda: tmp_path
        )

        keep = create_run_dir("alpha.dll", "triage")
        create_run_dir("beta.dll", "triage")
        create_run_dir("alpha.dll", "scan")

        runs = list_runs(module="alpha.dll", goal="triage", limit=10)
        assert len(runs) == 1
        assert runs[0]["run_id"] == Path(keep).name
        assert runs[0]["module_name"] == "alpha.dll"
        assert runs[0]["goal"] == "triage"

    def test_reports_aggregate_status_counts(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "helpers.workspace._workspace_base_dir", lambda: tmp_path
        )

        run_dir = create_run_dir("alpha.dll", "triage")
        ok_paths = write_results(run_dir, "classify", {"ok": True}, {"ok": True})
        update_manifest(run_dir, "classify", "success", ok_paths["summary_path"])

        err_paths = write_results(run_dir, "audit", {"ok": False}, {"ok": False})
        update_manifest(run_dir, "audit", "error", err_paths["summary_path"])

        runs = list_runs(limit=10)
        assert len(runs) == 1
        run = runs[0]
        assert run["status"] == "error"
        assert run["step_count"] == 2
        assert run["success_steps"] == 1
        assert run["error_steps"] == 1
        assert run["step_status_counts"]["success"] == 1
        assert run["step_status_counts"]["error"] == 1
