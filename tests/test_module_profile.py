"""Tests for helpers.module_profile -- profile loading and fingerprint queries.

Target: .agent/helpers/module_profile.py
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from helpers.module_profile import (
    load_module_profile,
    load_all_profiles,
    get_noise_ratio,
    get_technology_flags,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_profile(tmp_path):
    """Create a minimal module_profile.json for testing."""
    profile = {
        "identity": {
            "file_name": "test.dll",
            "module_name": "test_dll",
            "file_size_bytes": 204800,
        },
        "scale": {
            "total_functions": 100,
            "decompiled_functions": 80,
            "assembly_only_functions": 15,
            "no_output_functions": 5,
        },
        "library_profile": {
            "noise_ratio": 0.35,
            "library_breakdown": {
                "WIL": 20,
                "STL": 10,
                "CRT": 5,
            },
            "application_count": 65,
        },
        "api_profile": {
            "import_surface": {
                "dangerous_api_categories": {
                    "process": ["CreateProcessW"],
                    "memory": ["VirtualAlloc"],
                },
                "com_present": True,
                "rpc_present": False,
                "winrt_present": False,
                "named_pipes_present": True,
            },
        },
        "complexity_profile": {
            "functions_with_loops": 12,
            "max_loop_count": 5,
            "asm_size_stats": {
                "mean": 45.2,
                "median": 30,
                "max": 500,
            },
        },
        "security_posture": {
            "canary_coverage_pct": 0.85,
            "aslr": True,
            "dep": True,
            "cfg": True,
        },
    }
    module_dir = tmp_path / "extracted_code" / "test_dll"
    module_dir.mkdir(parents=True)
    (module_dir / "module_profile.json").write_text(
        json.dumps(profile, indent=2), encoding="utf-8"
    )
    return module_dir, profile


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestLoadModuleProfile:

    def test_load_existing_profile(self, sample_profile):
        module_dir, expected = sample_profile
        result = load_module_profile(module_dir)
        assert result is not None
        assert result["identity"]["file_name"] == "test.dll"

    def test_load_missing_profile(self, tmp_path):
        result = load_module_profile(tmp_path / "nonexistent")
        assert result is None

    def test_load_corrupted_json(self, tmp_path):
        module_dir = tmp_path / "bad_module"
        module_dir.mkdir()
        (module_dir / "module_profile.json").write_text("not json{", encoding="utf-8")
        result = load_module_profile(module_dir)
        assert result is None


class TestLoadAllProfiles:

    def test_load_all(self, sample_profile):
        module_dir, _ = sample_profile
        code_dir = module_dir.parent
        profiles = load_all_profiles(code_dir, max_modules=0)
        assert isinstance(profiles, dict)
        assert "test_dll" in profiles

    def test_empty_dir(self, tmp_path):
        code_dir = tmp_path / "extracted_code"
        code_dir.mkdir()
        profiles = load_all_profiles(code_dir, max_modules=0)
        assert profiles == {}


class TestNoiseRatio:

    def test_with_profile(self, sample_profile):
        _, profile = sample_profile
        ratio = get_noise_ratio(profile)
        assert ratio == pytest.approx(0.35)

    def test_without_library_section(self):
        profile = {"identity": {"file_name": "test.dll"}}
        ratio = get_noise_ratio(profile)
        assert ratio == 0.0


class TestTechnologyFlags:

    def test_with_flags(self, sample_profile):
        _, profile = sample_profile
        flags = get_technology_flags(profile)
        assert flags["com"] is True
        assert flags["rpc"] is False

    def test_missing_section(self):
        profile = {}
        flags = get_technology_flags(profile)
        # Returns defaults (all False) from the function
        assert isinstance(flags, dict)


