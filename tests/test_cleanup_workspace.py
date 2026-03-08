"""Tests for helpers/cleanup_workspace.py.

Covers workspace run cleanup (--older-than, --dry-run), code-lifter state
file cleanup, empty/missing workspace handling, and recent-run preservation.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from helpers.cleanup_workspace import cleanup_workspace


def _make_old(path: Path, age_days: int = 30) -> None:
    """Set mtime of *path* to *age_days* days ago."""
    old_time = time.time() - (age_days * 86400)
    os.utime(path, (old_time, old_time))


@pytest.fixture
def fake_workspace(tmp_path: Path):
    """Create a minimal workspace tree for cleanup testing."""
    ws = tmp_path / "workspace"
    ws.mkdir()
    workspace_dir = ws / ".agent" / "workspace"
    workspace_dir.mkdir(parents=True)
    return ws


class TestCleanupRuns:
    def test_deletes_old_run_dirs(self, fake_workspace: Path):
        ws_dir = fake_workspace / ".agent" / "workspace"
        old_run = ws_dir / "old_run_20240101"
        old_run.mkdir()
        (old_run / "manifest.json").write_text("{}")
        _make_old(old_run, age_days=30)

        result = cleanup_workspace(older_than_days=7, workspace_root=fake_workspace)
        assert result["runs_deleted"] == 1
        assert not old_run.exists()

    def test_preserves_recent_run_dirs(self, fake_workspace: Path):
        ws_dir = fake_workspace / ".agent" / "workspace"
        recent_run = ws_dir / "recent_run_today"
        recent_run.mkdir()
        (recent_run / "manifest.json").write_text("{}")

        result = cleanup_workspace(older_than_days=7, workspace_root=fake_workspace)
        assert result["runs_deleted"] == 0
        assert recent_run.exists()

    def test_dry_run_does_not_delete(self, fake_workspace: Path):
        ws_dir = fake_workspace / ".agent" / "workspace"
        old_run = ws_dir / "old_run_20240101"
        old_run.mkdir()
        _make_old(old_run, age_days=30)

        result = cleanup_workspace(older_than_days=7, dry_run=True, workspace_root=fake_workspace)
        assert result["runs_deleted"] == 0
        assert old_run.exists()

    def test_mixed_old_and_recent(self, fake_workspace: Path):
        ws_dir = fake_workspace / ".agent" / "workspace"
        old_run = ws_dir / "old_run"
        old_run.mkdir()
        _make_old(old_run, age_days=30)

        recent_run = ws_dir / "recent_run"
        recent_run.mkdir()

        result = cleanup_workspace(older_than_days=7, workspace_root=fake_workspace)
        assert result["runs_deleted"] == 1
        assert not old_run.exists()
        assert recent_run.exists()

    def test_skips_plain_files(self, fake_workspace: Path):
        ws_dir = fake_workspace / ".agent" / "workspace"
        plain_file = ws_dir / "stray_file.txt"
        plain_file.write_text("stray")
        _make_old(plain_file, age_days=30)

        result = cleanup_workspace(older_than_days=7, workspace_root=fake_workspace)
        assert result["runs_deleted"] == 0
        assert plain_file.exists()


class TestCleanupState:
    def test_deletes_old_state_files(self, fake_workspace: Path):
        state_dir = fake_workspace / ".agent" / "agents" / "code-lifter" / "state"
        state_dir.mkdir(parents=True)
        old_state = state_dir / "class_a_state.json"
        old_state.write_text("{}")
        _make_old(old_state, age_days=30)

        result = cleanup_workspace(older_than_days=7, workspace_root=fake_workspace)
        assert result["states_deleted"] == 1
        assert not old_state.exists()

    def test_preserves_recent_state_files(self, fake_workspace: Path):
        state_dir = fake_workspace / ".agent" / "agents" / "code-lifter" / "state"
        state_dir.mkdir(parents=True)
        recent_state = state_dir / "class_b_state.json"
        recent_state.write_text("{}")

        result = cleanup_workspace(older_than_days=7, workspace_root=fake_workspace)
        assert result["states_deleted"] == 0
        assert recent_state.exists()

    def test_ignores_non_state_files(self, fake_workspace: Path):
        state_dir = fake_workspace / ".agent" / "agents" / "code-lifter" / "state"
        state_dir.mkdir(parents=True)
        other = state_dir / "readme.txt"
        other.write_text("not a state file")
        _make_old(other, age_days=30)

        result = cleanup_workspace(older_than_days=7, workspace_root=fake_workspace)
        assert result["states_deleted"] == 0
        assert other.exists()


class TestEdgeCases:
    def test_missing_workspace_dir(self, tmp_path: Path):
        result = cleanup_workspace(older_than_days=7, workspace_root=tmp_path)
        assert result["runs_deleted"] == 0
        assert result["states_deleted"] == 0

    def test_empty_workspace_dir(self, fake_workspace: Path):
        result = cleanup_workspace(older_than_days=7, workspace_root=fake_workspace)
        assert result["runs_deleted"] == 0

    def test_zero_days_deletes_everything_old(self, fake_workspace: Path):
        ws_dir = fake_workspace / ".agent" / "workspace"
        run = ws_dir / "any_run"
        run.mkdir()
        _make_old(run, age_days=1)

        result = cleanup_workspace(older_than_days=0, workspace_root=fake_workspace)
        assert result["runs_deleted"] == 1
