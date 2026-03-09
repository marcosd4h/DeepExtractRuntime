"""Tests for config validation (helpers/config.py).

Target: helpers/config.py -- validate_config, get_config_validated
"""

from __future__ import annotations

import copy
import json
import logging
from pathlib import Path

import pytest

from helpers.config import (
    get_config_validated,
    get_config_value,
    load_config,
    validate_config,
)


# ===================================================================
# Fixtures
# ===================================================================

@pytest.fixture
def valid_config():
    """Return a known-valid config dict."""
    return {
        "classification": {
            "weights": {
                "W_NAME": 10.0,
                "W_API": 5.0,
                "W_API_CAP": 25.0,
                "W_STRING": 2.0,
                "W_STRING_CAP": 10.0,
                "W_STRUCTURAL": 4.0,
                "W_LIBRARY": 20.0,
            }
        },
        "triage": {
            "com_density_threshold": 5,
            "com_density_ratio": 0.1,
            "rpc_density_threshold": 3,
            "security_density_threshold": 3,
            "max_workers": 4,
            "step_timeout_seconds": 180,
            "per_function_timeout_seconds": 0.2,
        },
        "cache": {"max_age_hours": 24},
        "ui": {"show_progress": True},
    }


# ===================================================================
# Valid config
# ===================================================================

class TestValidConfig:
    def test_defaults_are_valid(self):
        """The shipped defaults.json must pass validation."""
        issues = validate_config(load_config())
        assert issues == []

    def test_explicit_valid_config(self, valid_config):
        assert validate_config(valid_config) == []

    def test_none_config_loads_defaults(self):
        issues = validate_config(None)
        assert isinstance(issues, list)


# ===================================================================
# classification.weights
# ===================================================================

class TestWeightsValidation:
    def test_negative_weight(self, valid_config):
        valid_config["classification"]["weights"]["W_NAME"] = -1.0
        issues = validate_config(valid_config)
        assert any("W_NAME" in i and "positive" in i for i in issues)

    def test_zero_weight(self, valid_config):
        valid_config["classification"]["weights"]["W_API"] = 0.0
        issues = validate_config(valid_config)
        assert any("W_API" in i and "positive" in i for i in issues)

    def test_string_weight(self, valid_config):
        valid_config["classification"]["weights"]["W_NAME"] = "ten"
        issues = validate_config(valid_config)
        assert any("W_NAME" in i and "number" in i for i in issues)

    def test_weights_not_dict(self, valid_config):
        valid_config["classification"]["weights"] = [1, 2, 3]
        issues = validate_config(valid_config)
        assert any("weights" in i and "dict" in i for i in issues)


# ===================================================================
# triage section
# ===================================================================

class TestTriageValidation:
    def test_negative_com_density_threshold(self, valid_config):
        valid_config["triage"]["com_density_threshold"] = -1
        issues = validate_config(valid_config)
        assert any("com_density_threshold" in i for i in issues)

    def test_zero_com_density_threshold(self, valid_config):
        valid_config["triage"]["com_density_threshold"] = 0
        issues = validate_config(valid_config)
        assert any("com_density_threshold" in i and "positive" in i for i in issues)

    def test_float_com_density_threshold(self, valid_config):
        valid_config["triage"]["com_density_threshold"] = 5.5
        issues = validate_config(valid_config)
        assert any("com_density_threshold" in i and "int" in i for i in issues)

    def test_com_density_ratio_too_high(self, valid_config):
        valid_config["triage"]["com_density_ratio"] = 1.5
        issues = validate_config(valid_config)
        assert any("com_density_ratio" in i for i in issues)

    def test_com_density_ratio_negative(self, valid_config):
        valid_config["triage"]["com_density_ratio"] = -0.1
        issues = validate_config(valid_config)
        assert any("com_density_ratio" in i for i in issues)

    def test_com_density_ratio_boundary_valid(self, valid_config):
        valid_config["triage"]["com_density_ratio"] = 0.0
        issues = validate_config(valid_config)
        assert not any("com_density_ratio" in i for i in issues)

        valid_config["triage"]["com_density_ratio"] = 1.0
        issues = validate_config(valid_config)
        assert not any("com_density_ratio" in i for i in issues)

    def test_negative_rpc_density_threshold(self, valid_config):
        valid_config["triage"]["rpc_density_threshold"] = -3
        issues = validate_config(valid_config)
        assert any("rpc_density_threshold" in i for i in issues)

    def test_negative_security_density_threshold(self, valid_config):
        valid_config["triage"]["security_density_threshold"] = 0
        issues = validate_config(valid_config)
        assert any("security_density_threshold" in i for i in issues)

    def test_max_workers_too_high(self, valid_config):
        valid_config["triage"]["max_workers"] = 32
        issues = validate_config(valid_config)
        assert any("max_workers" in i and "16" in i for i in issues)

    def test_max_workers_zero(self, valid_config):
        valid_config["triage"]["max_workers"] = 0
        issues = validate_config(valid_config)
        assert any("max_workers" in i and "positive" in i for i in issues)

    def test_max_workers_bool(self, valid_config):
        valid_config["triage"]["max_workers"] = True
        issues = validate_config(valid_config)
        assert any("max_workers" in i for i in issues)

    def test_step_timeout_negative(self, valid_config):
        valid_config["triage"]["step_timeout_seconds"] = -10
        issues = validate_config(valid_config)
        assert any("step_timeout_seconds" in i for i in issues)

    def test_per_function_timeout_string(self, valid_config):
        valid_config["triage"]["per_function_timeout_seconds"] = "fast"
        issues = validate_config(valid_config)
        assert any("per_function_timeout_seconds" in i for i in issues)


# ===================================================================
# cache section
# ===================================================================

class TestCacheValidation:
    def test_zero_ttl(self, valid_config):
        valid_config["cache"]["max_age_hours"] = 0
        issues = validate_config(valid_config)
        assert issues == []

    def test_negative_ttl(self, valid_config):
        valid_config["cache"]["max_age_hours"] = -24
        issues = validate_config(valid_config)
        assert any("max_age_hours" in i for i in issues)

    def test_string_ttl(self, valid_config):
        valid_config["cache"]["max_age_hours"] = "24"
        issues = validate_config(valid_config)
        assert any("max_age_hours" in i for i in issues)


# ===================================================================
# ui section
# ===================================================================

class TestUIValidation:
    def test_show_progress_not_bool(self, valid_config):
        valid_config["ui"]["show_progress"] = 1
        issues = validate_config(valid_config)
        assert any("show_progress" in i and "bool" in i for i in issues)

    def test_show_progress_string(self, valid_config):
        valid_config["ui"]["show_progress"] = "yes"
        issues = validate_config(valid_config)
        assert any("show_progress" in i for i in issues)


# ===================================================================
# Partial / missing sections
# ===================================================================

class TestPartialConfig:
    def test_empty_config(self):
        issues = validate_config({})
        assert issues == []

    def test_missing_triage_section(self, valid_config):
        del valid_config["triage"]
        issues = validate_config(valid_config)
        assert not any("triage" in i for i in issues)

    def test_missing_classification_section(self, valid_config):
        del valid_config["classification"]
        issues = validate_config(valid_config)
        assert not any("classification" in i for i in issues)

    def test_missing_cache_section(self, valid_config):
        del valid_config["cache"]
        issues = validate_config(valid_config)
        assert issues == [] or not any("cache" in i for i in issues)


# ===================================================================
# Multiple issues
# ===================================================================

class TestMultipleIssues:
    def test_returns_all_issues_not_just_first(self, valid_config):
        valid_config["classification"]["weights"]["W_NAME"] = -1.0
        valid_config["triage"]["max_workers"] = 99
        valid_config["cache"]["max_age_hours"] = -1
        issues = validate_config(valid_config)
        assert len(issues) >= 3

    def test_does_not_crash_on_invalid(self, valid_config):
        """Validation never raises, always returns a list."""
        valid_config["triage"]["com_density_ratio"] = "not-a-number"
        valid_config["classification"]["weights"] = None
        issues = validate_config(valid_config)
        assert isinstance(issues, list)
        assert len(issues) >= 1


# ===================================================================
# get_config_validated
# ===================================================================

class TestGetConfigValidated:
    def test_returns_config_dict(self):
        config = get_config_validated()
        assert isinstance(config, dict)
        assert "classification" in config

    def test_logs_warnings_on_issues(self, monkeypatch, valid_config, caplog):
        valid_config["cache"]["max_age_hours"] = -1
        monkeypatch.setattr("helpers.config.load_config", lambda _mutable=False: valid_config)
        with caplog.at_level(logging.WARNING, logger="helpers.config"):
            config = get_config_validated()
        assert any("max_age_hours" in rec.message for rec in caplog.records)
        assert isinstance(config, dict)

    def test_no_warnings_on_valid(self, monkeypatch, valid_config, caplog):
        monkeypatch.setattr("helpers.config.load_config", lambda _mutable=False: valid_config)
        with caplog.at_level(logging.WARNING, logger="helpers.config"):
            get_config_validated()
        config_warnings = [
            r for r in caplog.records if r.name == "helpers.config"
        ]
        assert config_warnings == []


# ===================================================================
# Backward compatibility
# ===================================================================

class TestBackwardCompat:
    def test_get_config_value_still_works(self):
        val = get_config_value("classification.weights.W_NAME")
        assert val == 10.0

    def test_get_config_value_default(self):
        val = get_config_value("nonexistent.path", default="fallback")
        assert val == "fallback"

    def test_load_config_still_returns_dict(self):
        config = load_config()
        assert isinstance(config, dict)
        assert "triage" in config


# ===================================================================
# pipeline section
# ===================================================================

class TestPipelineValidation:
    def test_valid_pipeline_section(self, valid_config):
        valid_config["pipeline"] = {
            "default_step_timeout": 300,
            "max_workers": 4,
            "continue_on_error": True,
            "parallel_modules": False,
            "max_module_workers": 2,
            "no_cache": False,
        }
        assert validate_config(valid_config) == []

    def test_pipeline_default_step_timeout_must_be_positive(self, valid_config):
        valid_config["pipeline"] = {"default_step_timeout": 0}
        issues = validate_config(valid_config)
        assert any("pipeline.default_step_timeout" in issue for issue in issues)

    def test_pipeline_continue_on_error_must_be_bool(self, valid_config):
        valid_config["pipeline"] = {"continue_on_error": "yes"}
        issues = validate_config(valid_config)
        assert any("pipeline.continue_on_error" in issue for issue in issues)

    def test_pipeline_parallel_modules_accepts_positive_int(self, valid_config):
        valid_config["pipeline"] = {"parallel_modules": 3}
        issues = validate_config(valid_config)
        assert not any("pipeline.parallel_modules" in issue for issue in issues)
