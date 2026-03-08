"""Tests for file locking on state files (Issue #18).

Target: agents/code-lifter/scripts/_common.py :: _locked_state_file
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path

import pytest

# Import from code-lifter's _common via importlib to avoid path collisions
# (multiple scripts directories have _common.py)
import importlib.util

_LIFTER_COMMON = Path(__file__).resolve().parents[1] / "agents" / "code-lifter" / "scripts" / "_common.py"
_spec = importlib.util.spec_from_file_location("lifter_common", _LIFTER_COMMON)
_lifter_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_lifter_mod)
_locked_state_file = _lifter_mod._locked_state_file


# ===================================================================
# Basic lock acquire/release
# ===================================================================

class TestBasicLocking:
    """Test fundamental lock acquire and release."""

    def test_lock_acquire_and_release(self, tmp_path):
        state_file = tmp_path / "test_state.json"
        state_file.write_text("{}", encoding="utf-8")

        with _locked_state_file(state_file) as path:
            assert path == state_file
            lock_file = state_file.with_suffix(".lock")
            assert lock_file.exists()

        assert not lock_file.exists()

    def test_lock_file_cleanup_on_normal_exit(self, tmp_path):
        state_file = tmp_path / "test_state.json"
        state_file.write_text("{}", encoding="utf-8")

        with _locked_state_file(state_file):
            pass

        lock_file = state_file.with_suffix(".lock")
        assert not lock_file.exists()

    def test_lock_file_cleanup_on_exception(self, tmp_path):
        state_file = tmp_path / "test_state.json"
        state_file.write_text("{}", encoding="utf-8")

        with pytest.raises(ValueError):
            with _locked_state_file(state_file):
                raise ValueError("test error")

        lock_file = state_file.with_suffix(".lock")
        assert not lock_file.exists()


# ===================================================================
# State file content preservation
# ===================================================================

class TestContentPreservation:
    """Test that state file content survives the lock cycle."""

    def test_read_through_lock(self, tmp_path):
        state_file = tmp_path / "test_state.json"
        data = {"class_name": "TestClass", "fields": [1, 2, 3]}
        state_file.write_text(json.dumps(data), encoding="utf-8")

        with _locked_state_file(state_file) as path:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            assert loaded == data

    def test_write_through_lock(self, tmp_path):
        state_file = tmp_path / "test_state.json"
        state_file.write_text("{}", encoding="utf-8")

        new_data = {"updated": True, "count": 42}
        with _locked_state_file(state_file) as path:
            path.write_text(json.dumps(new_data), encoding="utf-8")

        result = json.loads(state_file.read_text(encoding="utf-8"))
        assert result == new_data

    def test_read_modify_write(self, tmp_path):
        state_file = tmp_path / "test_state.json"
        state_file.write_text(json.dumps({"counter": 0}), encoding="utf-8")

        with _locked_state_file(state_file) as path:
            data = json.loads(path.read_text(encoding="utf-8"))
            data["counter"] += 1
            path.write_text(json.dumps(data), encoding="utf-8")

        result = json.loads(state_file.read_text(encoding="utf-8"))
        assert result["counter"] == 1


# ===================================================================
# Concurrent access
# ===================================================================

class TestConcurrentAccess:
    """Test that concurrent threads cannot corrupt state files."""

    def test_concurrent_increments(self, tmp_path):
        state_file = tmp_path / "test_state.json"
        state_file.write_text(json.dumps({"counter": 0}), encoding="utf-8")

        n_threads = 8
        increments_per_thread = 10
        errors = []

        def increment():
            for _ in range(increments_per_thread):
                try:
                    with _locked_state_file(state_file, timeout=15.0) as path:
                        data = json.loads(path.read_text(encoding="utf-8"))
                        data["counter"] += 1
                        path.write_text(json.dumps(data), encoding="utf-8")
                except Exception as e:
                    errors.append(str(e))

        threads = [threading.Thread(target=increment) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert errors == [], f"Errors during concurrent access: {errors}"
        result = json.loads(state_file.read_text(encoding="utf-8"))
        assert result["counter"] == n_threads * increments_per_thread


# ===================================================================
# Stale lock cleanup
# ===================================================================

class TestStaleLockCleanup:
    """Test that stale locks are cleaned up after timeout."""

    def test_stale_lock_broken(self, tmp_path):
        state_file = tmp_path / "test_state.json"
        state_file.write_text("{}", encoding="utf-8")

        lock_file = state_file.with_suffix(".lock")
        fd = os.open(str(lock_file), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(fd)
        assert lock_file.exists()

        with _locked_state_file(state_file, timeout=0.2) as path:
            assert path == state_file

        assert not lock_file.exists()


# ===================================================================
# Timeout behavior
# ===================================================================

class TestTimeout:
    """Test lock timeout and stale lock recovery."""

    def test_acquires_after_release(self, tmp_path):
        state_file = tmp_path / "test_state.json"
        state_file.write_text("{}", encoding="utf-8")

        acquired = threading.Event()
        can_release = threading.Event()

        def holder():
            with _locked_state_file(state_file, timeout=5.0):
                acquired.set()
                can_release.wait(timeout=5.0)

        t = threading.Thread(target=holder)
        t.start()
        acquired.wait(timeout=5.0)

        can_release.set()
        t.join(timeout=5.0)

        with _locked_state_file(state_file, timeout=2.0) as path:
            assert path == state_file


# ===================================================================
# Non-existent state file
# ===================================================================

class TestNonExistentFile:
    """Lock should work even if the state file doesn't exist yet."""

    def test_lock_on_nonexistent_file(self, tmp_path):
        state_file = tmp_path / "new_state.json"
        assert not state_file.exists()

        with _locked_state_file(state_file) as path:
            path.write_text(json.dumps({"created": True}), encoding="utf-8")

        assert state_file.exists()
        data = json.loads(state_file.read_text(encoding="utf-8"))
        assert data["created"] is True
