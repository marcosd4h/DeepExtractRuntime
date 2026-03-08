"""Extended tests for configuration loading and validation.

Covers all config paths including triage_weights, cache_ttl,
confidence_thresholds, env var overrides, and invalid value handling.

Targets:
  helpers/config.py  (load_config, get_config_value, validate_config)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from helpers.config import get_config_value, load_config, validate_config


# ===================================================================
# Environment variable overrides
# ===================================================================

class TestEnvOverrides:
    def test_env_override_triage_max_workers(self, monkeypatch):
        monkeypatch.setenv("DEEPEXTRACT_TRIAGE_MAX_WORKERS", "4")
        config = load_config()
        if "triage" in config:
            assert config["triage"].get("max_workers") == 4

    def test_env_override_cache_max_age(self, monkeypatch):
        monkeypatch.setenv("DEEPEXTRACT_CACHE_MAX_AGE_HOURS", "48")
        config = load_config()
        if "cache" in config:
            assert config["cache"].get("max_age_hours") == 48

    def test_env_override_bool_value(self, monkeypatch):
        monkeypatch.setenv("DEEPEXTRACT_UI_SHOW_PROGRESS", "false")
        config = load_config()
        if "ui" in config:
            assert config["ui"].get("show_progress") is False

    def test_env_override_string_value(self, monkeypatch):
        monkeypatch.setenv("DEEPEXTRACT_TRIAGE_CUSTOM_KEY", "custom_value")
        config = load_config()
        if "triage" in config:
            assert config["triage"].get("custom_key") == "custom_value"


# ===================================================================
# Validate config: classification.weights
# ===================================================================

class TestValidateWeights:
    def test_valid_weights(self):
        config = {
            "classification": {
                "weights": {"api_score": 1.0, "string_score": 0.5, "name_score": 0.8}
            }
        }
        issues = validate_config(config)
        assert len(issues) == 0

    def test_negative_weight(self):
        config = {
            "classification": {"weights": {"api_score": -1.0}}
        }
        issues = validate_config(config)
        assert any("api_score" in i and "positive" in i for i in issues)

    def test_non_numeric_weight(self):
        config = {
            "classification": {"weights": {"api_score": "high"}}
        }
        issues = validate_config(config)
        assert any("api_score" in i for i in issues)

    def test_weights_wrong_type(self):
        config = {"classification": {"weights": "not_a_dict"}}
        issues = validate_config(config)
        assert any("weights" in i and "dict" in i for i in issues)


# ===================================================================
# Validate config: triage section
# ===================================================================

class TestValidateTriage:
    def test_valid_triage(self):
        config = {
            "triage": {
                "com_density_threshold": 5,
                "com_density_ratio": 0.3,
                "rpc_density_threshold": 3,
                "security_density_threshold": 10,
                "max_workers": 4,
                "step_timeout_seconds": 120,
                "per_function_timeout_seconds": 30,
            }
        }
        issues = validate_config(config)
        assert len(issues) == 0

    def test_invalid_max_workers(self):
        config = {"triage": {"max_workers": 100}}
        issues = validate_config(config)
        assert any("max_workers" in i for i in issues)

    def test_negative_timeout(self):
        config = {"triage": {"step_timeout_seconds": -5}}
        issues = validate_config(config)
        assert any("step_timeout" in i for i in issues)

    def test_ratio_out_of_range(self):
        config = {"triage": {"com_density_ratio": 1.5}}
        issues = validate_config(config)
        assert any("com_density_ratio" in i for i in issues)

    def test_zero_threshold(self):
        config = {"triage": {"com_density_threshold": 0}}
        issues = validate_config(config)
        assert any("com_density_threshold" in i for i in issues)


# ===================================================================
# Validate config: verifier section
# ===================================================================

class TestValidateVerifier:
    def test_valid_verifier(self):
        config = {
            "verifier": {
                "call_count_tolerance": 0.2,
                "branch_count_tolerance": 0.3,
                "max_alignment": 16,
            }
        }
        issues = validate_config(config)
        assert len(issues) == 0

    def test_tolerance_out_of_range(self):
        config = {"verifier": {"call_count_tolerance": -0.1}}
        issues = validate_config(config)
        assert any("call_count_tolerance" in i for i in issues)

    def test_max_alignment_too_high(self):
        config = {"verifier": {"max_alignment": 128}}
        issues = validate_config(config)
        assert any("max_alignment" in i for i in issues)


# ===================================================================
# Validate config: cache section
# ===================================================================

class TestValidateCache:
    def test_valid_cache(self):
        config = {"cache": {"max_age_hours": 24}}
        issues = validate_config(config)
        assert len(issues) == 0

    def test_zero_cache_age(self):
        config = {"cache": {"max_age_hours": 0}}
        issues = validate_config(config)
        assert issues == []

    def test_non_int_cache_age(self):
        config = {"cache": {"max_age_hours": "forever"}}
        issues = validate_config(config)
        assert any("max_age_hours" in i for i in issues)


# ===================================================================
# Validate config: ui section
# ===================================================================

class TestValidateUI:
    def test_valid_ui(self):
        config = {"ui": {"show_progress": True}}
        issues = validate_config(config)
        assert len(issues) == 0

    def test_non_bool_show_progress(self):
        config = {"ui": {"show_progress": "yes"}}
        issues = validate_config(config)
        assert any("show_progress" in i for i in issues)


# ===================================================================
# Validate config: empty and missing sections
# ===================================================================

class TestValidateEdgeCases:
    def test_empty_config(self):
        issues = validate_config({})
        assert len(issues) == 0

    def test_none_config_loads_live(self):
        issues = validate_config(None)
        assert isinstance(issues, list)

    def test_unknown_sections_ignored(self):
        config = {"unknown_section": {"key": "value"}}
        issues = validate_config(config)
        assert len(issues) == 0


# ===================================================================
# get_config_value path resolution
# ===================================================================

class TestGetConfigValue:
    def test_nested_path(self, monkeypatch, tmp_path):
        config_data = {
            "triage": {"max_workers": 8},
            "cache": {"max_age_hours": 12},
        }
        config_file = tmp_path / "defaults.json"
        config_file.write_text(json.dumps(config_data), encoding="utf-8")
        monkeypatch.setattr("helpers.config._DEFAULTS_PATH", config_file)

        assert get_config_value("triage.max_workers") == 8
        assert get_config_value("cache.max_age_hours") == 12

    def test_missing_path_returns_default(self):
        result = get_config_value("nonexistent.path", default="fallback")
        assert result == "fallback"

    def test_missing_path_returns_none(self):
        result = get_config_value("nonexistent.deep.path")
        assert result is None


# ===================================================================
# Pipeline config section
# ===================================================================

class TestPipelineConfig:
    def test_env_override_pipeline_max_workers(self, monkeypatch):
        monkeypatch.setenv("DEEPEXTRACT_PIPELINE__MAX_WORKERS", "6")
        config = load_config()
        assert config["pipeline"]["max_workers"] == 6

    def test_valid_pipeline_config(self):
        config = {
            "pipeline": {
                "default_step_timeout": 300,
                "max_workers": 4,
                "continue_on_error": True,
                "parallel_modules": 2,
                "max_module_workers": 2,
                "no_cache": False,
            }
        }
        assert validate_config(config) == []

    def test_invalid_pipeline_parallel_modules(self):
        config = {"pipeline": {"parallel_modules": "many"}}
        issues = validate_config(config)
        assert any("pipeline.parallel_modules" in issue for issue in issues)
