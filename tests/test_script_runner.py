"""Tests for helpers/script_runner.py."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from helpers.script_runner import load_skill_module, run_skill_script


def test_run_skill_script_fails_on_malformed_json_stdout(tmp_path, monkeypatch):
    script_path = tmp_path / "fake_skill.py"
    script_path.write_text("print('unused')\n", encoding="utf-8")

    monkeypatch.setattr(
        "helpers.script_runner.find_skill_script",
        lambda skill_name, script_name: script_path,
    )

    completed = subprocess.CompletedProcess(
        args=[sys.executable, str(script_path)],
        returncode=0,
        stdout="not-json",
        stderr="",
    )
    monkeypatch.setattr("helpers.script_runner.subprocess.run", lambda *args, **kwargs: completed)

    result = run_skill_script("fake-skill", "fake_skill.py", [], json_output=True)

    assert result["success"] is False
    assert result["json_data"] is None
    assert "Failed to parse JSON stdout" in result["error"]
    assert result["exit_code"] == 0


def test_load_skill_module_clears_failed_import_cache_and_recovers(tmp_path, monkeypatch):
    skill_name = "bad-skill"
    module_name = "broken"
    scripts_dir = tmp_path / skill_name / "scripts"
    scripts_dir.mkdir(parents=True)
    module_path = scripts_dir / f"{module_name}.py"
    cache_key = f"_skill__{skill_name}__{module_name}"

    monkeypatch.setattr("helpers.script_runner.get_skills_dir", lambda: tmp_path)
    sys.modules.pop(cache_key, None)

    module_path.write_text("raise RuntimeError('boom')\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="boom"):
        load_skill_module(skill_name, module_name)
    assert cache_key not in sys.modules

    module_path.write_text("VALUE = 42\n", encoding="utf-8")
    loaded = load_skill_module(skill_name, module_name)

    assert loaded.VALUE == 42
    assert sys.modules[cache_key] is loaded

    sys.modules.pop(cache_key, None)
