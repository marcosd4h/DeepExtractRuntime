import pytest
import os
import json
from helpers.config import load_config, get_config_value

def test_load_config_defaults():
    config = load_config()
    assert "classification" in config
    assert config["classification"]["weights"]["W_NAME"] == 10.0

def test_get_config_value():
    val = get_config_value("classification.weights.W_NAME")
    assert val == 10.0
    
    val = get_config_value("non.existent.path", default="fallback")
    assert val == "fallback"

def test_env_override_double_underscore(monkeypatch):
    monkeypatch.setenv("DEEPEXTRACT_SCRIPT_RUNNER__MAX_RETRIES", "5")
    config = load_config()
    assert config["script_runner"]["max_retries"] == 5

def test_env_override(monkeypatch):
    monkeypatch.setenv("DEEPEXTRACT_TRIAGE_MAX_WORKERS", "10")
    config = load_config()
    assert config["triage"]["max_workers"] == 10

def test_env_override_bool(monkeypatch):
    monkeypatch.setenv("DEEPEXTRACT_UI_SHOW_PROGRESS", "false")
    config = load_config()
    assert config["ui"]["show_progress"] is False
