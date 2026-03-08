"""Tests for scan_module.py emit_error fix (Critical fix #3).

Verifies that scan_module uses emit_error() (structured JSON to stderr)
instead of sys.exit(1) when no decompiled functions are found.

Uses subprocess to avoid import path collisions with _common.py files.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import _create_sample_db


_AGENT_DIR = Path(__file__).resolve().parents[1]
_SCAN_SCRIPT = str(
    _AGENT_DIR / "skills" / "verify-decompiled" / "scripts" / "scan_module.py"
)
_SCRIPT_DIR = str(_AGENT_DIR / "skills" / "verify-decompiled" / "scripts")
_SUBPROCESS_ENV = {**__import__("os").environ, "PYTHONPATH": str(_AGENT_DIR)}


def _create_empty_module_db(tmp_path: Path) -> Path:
    """Create a module DB with no decompiled functions."""
    db_path = tmp_path / "empty_module.db"
    _create_sample_db(db_path)
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO file_info (file_path, file_name, file_extension) "
        "VALUES (?, ?, ?)",
        ("C:\\Windows\\System32\\empty.dll", "empty.dll", ".dll"),
    )
    conn.execute(
        "INSERT INTO functions (function_id, function_name, assembly_code) "
        "VALUES (?, ?, ?)",
        (1, "sub_100", "mov eax, 1\nret"),
    )
    conn.commit()
    conn.close()
    return db_path


def _create_no_functions_db(tmp_path: Path) -> Path:
    """Create a module DB with zero functions."""
    db_path = tmp_path / "nofunc_module.db"
    _create_sample_db(db_path)
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO file_info (file_path, file_name, file_extension) "
        "VALUES (?, ?, ?)",
        ("C:\\Windows\\System32\\nofunc.dll", "nofunc.dll", ".dll"),
    )
    conn.commit()
    conn.close()
    return db_path


class TestScanModuleNoDecompiledCode:
    """Verify emit_error is used instead of sys.exit(1)."""

    def test_no_decompiled_exits_with_structured_error(self, tmp_path):
        db_path = _create_empty_module_db(tmp_path)
        result = subprocess.run(
            [sys.executable, _SCAN_SCRIPT, str(db_path), "--json"],
            capture_output=True, text=True, timeout=30,
            cwd=_SCRIPT_DIR, env=_SUBPROCESS_ENV,
        )
        assert result.returncode == 1
        error_data = json.loads(result.stderr.strip().splitlines()[-1])
        assert "error" in error_data
        assert error_data["code"] == "NO_DATA"

    def test_empty_db_exits_with_structured_error(self, tmp_path):
        db_path = _create_no_functions_db(tmp_path)
        result = subprocess.run(
            [sys.executable, _SCAN_SCRIPT, str(db_path)],
            capture_output=True, text=True, timeout=30,
            cwd=_SCRIPT_DIR, env=_SUBPROCESS_ENV,
        )
        assert result.returncode == 1
        stderr_lines = result.stderr.strip().splitlines()
        error_line = stderr_lines[-1]
        error_data = json.loads(error_line)
        assert error_data["code"] == "NO_DATA"


class TestScanModuleWithDecompiledCode:
    """Verify normal operation when decompiled code exists."""

    def test_normal_scan_completes(self, sample_db):
        result = subprocess.run(
            [sys.executable, _SCAN_SCRIPT, str(sample_db), "--json"],
            capture_output=True, text=True, timeout=30,
            cwd=_SCRIPT_DIR, env=_SUBPROCESS_ENV,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        output = json.loads(result.stdout)
        assert "module_name" in output or "status" in output
