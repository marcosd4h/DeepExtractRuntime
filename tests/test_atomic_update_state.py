"""Tests for atomic_update_state context manager (Critical fix #2).

Verifies that atomic_update_state:
- Holds the lock for the entire read-modify-write cycle
- Does not save state if an exception occurs
- Auto-creates initial state for new classes
- Works correctly under concurrent access
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

import importlib.util

_LIFTER_COMMON = Path(__file__).resolve().parents[1] / "agents" / "code-lifter" / "scripts" / "_common.py"
_spec = importlib.util.spec_from_file_location("lifter_common_atomic", _LIFTER_COMMON)
_lifter_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_lifter_mod)

atomic_update_state = _lifter_mod.atomic_update_state
load_state = _lifter_mod.load_state
save_state = _lifter_mod.save_state
create_initial_state = _lifter_mod.create_initial_state
get_state_file_path = _lifter_mod.get_state_file_path
STATE_DIR = _lifter_mod.STATE_DIR


@pytest.fixture(autouse=True)
def _use_tmp_state_dir(tmp_path, monkeypatch):
    """Redirect STATE_DIR to tmp_path for test isolation."""
    monkeypatch.setattr(_lifter_mod, "STATE_DIR", tmp_path)


class TestAtomicUpdateBasics:
    """Basic read-modify-write operations."""

    def test_creates_initial_state_if_missing(self, tmp_path):
        with atomic_update_state("NewClass") as state:
            assert state["class_name"] == "NewClass"
            state["constants"]["MY_CONST"] = {"value": 42}

        loaded = load_state("NewClass")
        assert loaded is not None
        assert loaded["constants"]["MY_CONST"]["value"] == 42

    def test_modifies_existing_state(self, tmp_path):
        initial = create_initial_state("TestClass", "mod.dll", "db.db", [], [])
        initial["constants"]["OLD"] = {"value": 1}
        save_state("TestClass", initial)

        with atomic_update_state("TestClass") as state:
            assert state["constants"]["OLD"]["value"] == 1
            state["constants"]["NEW"] = {"value": 2}

        loaded = load_state("TestClass")
        assert "OLD" in loaded["constants"]
        assert "NEW" in loaded["constants"]
        assert loaded["constants"]["NEW"]["value"] == 2

    def test_no_save_on_exception(self, tmp_path):
        initial = create_initial_state("SafeClass", "", "", [], [])
        initial["constants"]["BEFORE"] = {"value": 100}
        save_state("SafeClass", initial)

        with pytest.raises(ValueError):
            with atomic_update_state("SafeClass") as state:
                state["constants"]["BAD"] = {"value": 999}
                raise ValueError("rollback test")

        loaded = load_state("SafeClass")
        assert "BAD" not in loaded["constants"]
        assert loaded["constants"]["BEFORE"]["value"] == 100

    def test_struct_field_update(self, tmp_path):
        initial = create_initial_state("FieldClass", "", "", [], [])
        initial["struct_definition"]["fields"] = [
            {"offset": 0, "size": 8, "name": "vtable", "c_type": "void*"}
        ]
        save_state("FieldClass", initial)

        with atomic_update_state("FieldClass") as state:
            state["struct_definition"]["fields"].append(
                {"offset": 8, "size": 4, "name": "refcount", "c_type": "LONG"}
            )

        loaded = load_state("FieldClass")
        assert len(loaded["struct_definition"]["fields"]) == 2

    def test_naming_map_update(self, tmp_path):
        with atomic_update_state("NamingClass") as state:
            state.setdefault("naming_map", {})["field_30"] = "pDacl"

        loaded = load_state("NamingClass")
        assert loaded["naming_map"]["field_30"] == "pDacl"


class TestAtomicUpdateConcurrency:
    """Verify atomicity under concurrent access."""

    def test_concurrent_increments(self, tmp_path):
        """Multiple threads incrementing a counter atomically."""
        initial = create_initial_state("CounterClass", "", "", [], [])
        initial["constants"]["counter"] = {"value": 0}
        save_state("CounterClass", initial)

        n_threads = 6
        increments_per_thread = 8
        errors: list[str] = []

        def worker():
            for _ in range(increments_per_thread):
                try:
                    with atomic_update_state("CounterClass") as state:
                        old = state["constants"]["counter"]["value"]
                        state["constants"]["counter"]["value"] = old + 1
                except Exception as e:
                    errors.append(str(e))

        threads = [threading.Thread(target=worker) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert errors == [], f"Errors: {errors}"
        loaded = load_state("CounterClass")
        expected = n_threads * increments_per_thread
        assert loaded["constants"]["counter"]["value"] == expected, (
            f"Expected {expected}, got {loaded['constants']['counter']['value']}"
        )

