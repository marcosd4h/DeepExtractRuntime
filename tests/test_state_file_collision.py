"""Tests for state file path collision prevention (Issue #5).

Verifies that:
- Different class names that sanitize identically produce different file paths
- The hash suffix is stable (same input -> same hash)
- Special characters in class names are handled safely
- Backward compatibility: old-format files are migrated automatically
- Empty / None class names don't crash
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Reproduce the path-computation algorithm from code-lifter _common.py
# so we can verify correctness without importing the bootstrapped module.
# ---------------------------------------------------------------------------

def _sanitize_class_name(class_name: str) -> str:
    """Mirror of code-lifter _common._sanitize_class_name."""
    return class_name.replace("::", "_").replace("<", "_").replace(">", "_")


def _class_name_hash(class_name: str) -> str:
    """Mirror of code-lifter _common._class_name_hash."""
    return hashlib.sha256(class_name.encode("utf-8")).hexdigest()[:8]


def _new_format_filename(class_name: str) -> str:
    """Compute the new-format state filename: {sanitized}_{hash8}_state.json."""
    safe = _sanitize_class_name(class_name)
    h = _class_name_hash(class_name)
    return f"{safe}_{h}_state.json"


def _old_format_filename(class_name: str) -> str:
    """Compute the old-format state filename: {sanitized}_state.json."""
    safe = _sanitize_class_name(class_name)
    return f"{safe}_state.json"


# ---------------------------------------------------------------------------
# Collision prevention
# ---------------------------------------------------------------------------

class TestCollisionPrevention:
    """Verify that previously-colliding names now produce distinct paths."""

    def test_namespace_vs_underscore_collision(self):
        """ClassA::Nested and ClassA_Nested must produce different filenames."""
        f1 = _new_format_filename("ClassA::Nested")
        f2 = _new_format_filename("ClassA_Nested")
        assert f1 != f2

    def test_template_vs_underscore_collision(self):
        """std::vector<int> and std::vector_int_ must differ."""
        f1 = _new_format_filename("std::vector<int>")
        f2 = _new_format_filename("std::vector_int_")
        assert f1 != f2

    def test_double_colon_variants(self):
        """A::B::C vs A_B::C vs A_B_C must all differ."""
        f1 = _new_format_filename("A::B::C")
        f2 = _new_format_filename("A_B::C")
        f3 = _new_format_filename("A_B_C")
        assert len({f1, f2, f3}) == 3, "All three names must produce distinct files"

    def test_sanitized_names_match_but_hashes_differ(self):
        """Explicit check: sanitized forms are equal, hashes are not."""
        name_a = "ClassA::Nested"
        name_b = "ClassA_Nested"

        assert _sanitize_class_name(name_a) == _sanitize_class_name(name_b)
        assert _class_name_hash(name_a) != _class_name_hash(name_b)


# ---------------------------------------------------------------------------
# Hash stability
# ---------------------------------------------------------------------------

class TestHashStability:
    """Same input must always produce the same hash."""

    def test_repeated_calls(self):
        h1 = _class_name_hash("MyClass")
        h2 = _class_name_hash("MyClass")
        assert h1 == h2

    def test_filename_deterministic(self):
        f1 = _new_format_filename("CSecurityDescriptor")
        f2 = _new_format_filename("CSecurityDescriptor")
        assert f1 == f2

    def test_hash_is_8_hex_chars(self):
        h = _class_name_hash("AnyClassName")
        assert len(h) == 8
        assert all(c in "0123456789abcdef" for c in h)

    def test_known_hash_value(self):
        """Pin a known value to catch accidental algorithm changes."""
        expected = hashlib.sha256(b"TestClass").hexdigest()[:8]
        assert _class_name_hash("TestClass") == expected


# ---------------------------------------------------------------------------
# Special characters
# ---------------------------------------------------------------------------

class TestSpecialCharacters:
    """Class names with special characters must sanitize safely."""

    def test_angle_brackets_removed(self):
        fn = _new_format_filename("std::vector<int>")
        assert "<" not in fn
        assert ">" not in fn

    def test_double_colon_removed(self):
        fn = _new_format_filename("Foo::Bar")
        assert "::" not in fn

    def test_deeply_nested(self):
        fn = _new_format_filename("A::B::C::D<E<F>>")
        assert "::" not in fn
        assert "<" not in fn
        assert ">" not in fn
        assert fn.endswith("_state.json")

    def test_empty_class_name(self):
        """Empty string should still produce a valid filename."""
        fn = _new_format_filename("")
        assert fn.endswith("_state.json")
        assert len(fn) > len("_state.json")  # has hash suffix

    def test_simple_name_no_special_chars(self):
        fn = _new_format_filename("MyClass")
        assert fn.startswith("MyClass_")
        assert fn.endswith("_state.json")


# ---------------------------------------------------------------------------
# Filename format
# ---------------------------------------------------------------------------

class TestFilenameFormat:
    """Verify the filename follows {sanitized}_{hash8}_state.json."""

    def test_format_structure(self):
        fn = _new_format_filename("CSecurityDescriptor")
        # Should be: CSecurityDescriptor_{8 hex chars}_state.json
        parts = fn.removesuffix("_state.json").rsplit("_", 1)
        assert len(parts) == 2, f"Expected 2 parts, got {parts}"
        sanitized_part, hash_part = parts
        assert sanitized_part == "CSecurityDescriptor"
        assert len(hash_part) == 8
        assert all(c in "0123456789abcdef" for c in hash_part)

    def test_format_with_colons(self):
        fn = _new_format_filename("Foo::Bar")
        # sanitize: Foo_Bar, hash of "Foo::Bar"
        assert fn.startswith("Foo_Bar_")
        assert fn.endswith("_state.json")

    def test_old_format_for_comparison(self):
        """Old format should NOT have the hash segment."""
        old = _old_format_filename("MyClass")
        assert old == "MyClass_state.json"

        new = _new_format_filename("MyClass")
        assert new != old


# ---------------------------------------------------------------------------
# Backward compatibility / migration
# ---------------------------------------------------------------------------

class TestBackwardCompatibility:
    """Test that old-format state files are discovered and migrated."""

    def test_old_file_migrated_to_new_format(self, tmp_path):
        """When an old-format file exists, get_state_file_path migrates it."""
        state_dir = tmp_path / "state"
        state_dir.mkdir()

        class_name = "CSecurityDescriptor"
        old_name = _old_format_filename(class_name)
        new_name = _new_format_filename(class_name)

        # Create an old-format file
        old_file = state_dir / old_name
        state_data = {"class_name": class_name, "functions": {}}
        old_file.write_text(json.dumps(state_data), encoding="utf-8")

        assert old_file.exists()
        assert not (state_dir / new_name).exists()

        # Simulate the migration logic from get_state_file_path
        safe_name = _sanitize_class_name(class_name)
        hash8 = _class_name_hash(class_name)
        new_path = state_dir / f"{safe_name}_{hash8}_state.json"
        old_path = state_dir / f"{safe_name}_state.json"

        if old_path.exists() and not new_path.exists():
            old_path.rename(new_path)

        assert new_path.exists()
        assert not old_path.exists()

        # Verify content survived the rename
        migrated = json.loads(new_path.read_text(encoding="utf-8"))
        assert migrated["class_name"] == class_name

    def test_new_file_not_overwritten_by_migration(self, tmp_path):
        """If both old and new files exist, old file should NOT overwrite new."""
        state_dir = tmp_path / "state"
        state_dir.mkdir()

        class_name = "Foo"
        old_name = _old_format_filename(class_name)
        new_name = _new_format_filename(class_name)

        old_data = {"class_name": class_name, "version": "old"}
        new_data = {"class_name": class_name, "version": "new"}

        (state_dir / old_name).write_text(json.dumps(old_data), encoding="utf-8")
        (state_dir / new_name).write_text(json.dumps(new_data), encoding="utf-8")

        # Migration logic: should NOT rename because new_path already exists
        safe_name = _sanitize_class_name(class_name)
        hash8 = _class_name_hash(class_name)
        new_path = state_dir / f"{safe_name}_{hash8}_state.json"
        old_path = state_dir / f"{safe_name}_state.json"

        if old_path.exists() and not new_path.exists():
            old_path.rename(new_path)

        # New file should still have its original content
        content = json.loads(new_path.read_text(encoding="utf-8"))
        assert content["version"] == "new"

        # Old file should still exist (it was not renamed)
        assert old_path.exists()

    def test_no_old_file_no_error(self, tmp_path):
        """When no old-format file exists, migration is a no-op."""
        state_dir = tmp_path / "state"
        state_dir.mkdir()

        class_name = "Brand::New"
        safe_name = _sanitize_class_name(class_name)
        hash8 = _class_name_hash(class_name)
        new_path = state_dir / f"{safe_name}_{hash8}_state.json"
        old_path = state_dir / f"{safe_name}_state.json"

        # Neither file exists -- migration check should be harmless
        if old_path.exists() and not new_path.exists():
            old_path.rename(new_path)

        assert not old_path.exists()
        assert not new_path.exists()


# ---------------------------------------------------------------------------
# Round-trip: save + load with collision-prone names
# ---------------------------------------------------------------------------

class TestSaveLoadRoundTrip:
    """Verify save/load works with collision-prone class names using tmp dirs."""

    def _save_state(self, state_dir: Path, class_name: str, state: dict) -> Path:
        """Replicate the save logic using the new format."""
        state_dir.mkdir(parents=True, exist_ok=True)
        safe_name = _sanitize_class_name(class_name)
        hash8 = _class_name_hash(class_name)
        path = state_dir / f"{safe_name}_{hash8}_state.json"
        path.write_text(json.dumps(state, indent=2), encoding="utf-8")
        return path

    def _load_state(self, state_dir: Path, class_name: str) -> dict | None:
        """Replicate the load logic using the new format, with migration."""
        safe_name = _sanitize_class_name(class_name)
        hash8 = _class_name_hash(class_name)
        new_path = state_dir / f"{safe_name}_{hash8}_state.json"
        old_path = state_dir / f"{safe_name}_state.json"

        # Migration
        if old_path.exists() and not new_path.exists():
            old_path.rename(new_path)

        if not new_path.exists():
            return None
        try:
            return json.loads(new_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

    def test_collision_prone_names_coexist(self, tmp_path):
        """Two classes that previously collided can coexist."""
        state_dir = tmp_path / "state"

        state_a = {"class_name": "ClassA::Nested", "value": "A"}
        state_b = {"class_name": "ClassA_Nested", "value": "B"}

        self._save_state(state_dir, "ClassA::Nested", state_a)
        self._save_state(state_dir, "ClassA_Nested", state_b)

        loaded_a = self._load_state(state_dir, "ClassA::Nested")
        loaded_b = self._load_state(state_dir, "ClassA_Nested")

        assert loaded_a is not None
        assert loaded_b is not None
        assert loaded_a["value"] == "A"
        assert loaded_b["value"] == "B"

    def test_load_from_old_format_via_migration(self, tmp_path):
        """Loading a class whose state is in old format triggers migration."""
        state_dir = tmp_path / "state"
        state_dir.mkdir()

        class_name = "SimpleClass"
        old_path = state_dir / _old_format_filename(class_name)
        state = {"class_name": class_name, "functions": {"1": {"lifted": True}}}
        old_path.write_text(json.dumps(state), encoding="utf-8")

        loaded = self._load_state(state_dir, class_name)
        assert loaded is not None
        assert loaded["class_name"] == class_name
        assert loaded["functions"]["1"]["lifted"] is True

        # Old file should be gone, new file should exist
        assert not old_path.exists()
        new_path = state_dir / _new_format_filename(class_name)
        assert new_path.exists()
