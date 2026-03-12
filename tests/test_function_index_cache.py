"""Tests for function_index.json caching and invalidation."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import helpers.function_index.index as function_index_mod


def test_load_function_index_reuses_cached_parse_when_mtime_is_unchanged(tmp_path, monkeypatch):
    index_path = tmp_path / "function_index.json"
    index_path.write_text(
        json.dumps({"FuncA": {"function_id": 1, "files": ["f.cpp"]}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        function_index_mod,
        "function_index_path",
        lambda module_name: index_path,
    )

    with patch("builtins.open", wraps=open) as mock_open:
        first = function_index_mod.load_function_index("mod")
        second = function_index_mod.load_function_index("mod")

    assert first == second
    opened_index_paths = [
        Path(call.args[0]) for call in mock_open.call_args_list
        if call.args and Path(call.args[0]) == index_path
    ]
    assert len(opened_index_paths) == 1


def test_load_function_index_invalidates_cache_when_file_mtime_changes(tmp_path, monkeypatch):
    index_path = tmp_path / "function_index.json"
    index_path.write_text(
        json.dumps({"FuncA": {"function_id": 1, "files": ["a.cpp"]}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        function_index_mod,
        "function_index_path",
        lambda module_name: index_path,
    )

    first = function_index_mod.load_function_index("mod")
    index_path.write_text(
        json.dumps({"FuncB": {"function_id": 2, "files": ["b.cpp"]}}),
        encoding="utf-8",
    )
    # Force a distinct mtime_ns so the cache sees a change even when the
    # filesystem clock hasn't ticked between the two writes (common on Windows).
    st = index_path.stat()
    os.utime(index_path, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))

    with patch("builtins.open", wraps=open) as mock_open:
        second = function_index_mod.load_function_index("mod")

    assert first != second
    assert "FuncB" in second
    opened_index_paths = [
        Path(call.args[0]) for call in mock_open.call_args_list
        if call.args and Path(call.args[0]) == index_path
    ]
    assert len(opened_index_paths) == 1


def test_load_function_index_rejects_non_dict_top_level(tmp_path, monkeypatch):
    index_path = tmp_path / "function_index.json"
    index_path.write_text(json.dumps(["not", "a", "dict"]), encoding="utf-8")
    monkeypatch.setattr(
        function_index_mod,
        "function_index_path",
        lambda module_name: index_path,
    )

    result = function_index_mod.load_function_index("mod")

    assert result is None


def test_load_function_index_skips_malformed_entries(tmp_path, monkeypatch):
    index_path = tmp_path / "function_index.json"
    index_path.write_text(
        json.dumps(
            {
                "FuncA": {"function_id": 1, "files": ["a.cpp"]},
                "FuncB": "not-an-entry",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        function_index_mod,
        "function_index_path",
        lambda module_name: index_path,
    )

    result = function_index_mod.load_function_index("mod")

    assert result == {"FuncA": {"function_id": 1, "files": ["a.cpp"]}}


def test_list_extracted_modules_invalidates_when_function_index_is_added(
    tmp_path,
    monkeypatch,
):
    extracted_code_dir = tmp_path / "extracted_code"
    extracted_code_dir.mkdir()
    module_dir = extracted_code_dir / "foo_dll"
    module_dir.mkdir()

    monkeypatch.setattr(function_index_mod, "EXTRACTED_CODE_DIR", extracted_code_dir)
    monkeypatch.setattr(function_index_mod, "_cached_module_list", None)
    monkeypatch.setattr(function_index_mod, "_cached_module_list_fingerprint", None)

    first = function_index_mod.list_extracted_modules()
    assert first == []

    index_path = module_dir / function_index_mod.FUNCTION_INDEX_FILENAME
    index_path.write_text(
        json.dumps({"FuncA": {"function_id": 1, "files": ["a.cpp"]}}),
        encoding="utf-8",
    )

    second = function_index_mod.list_extracted_modules()
    assert second == ["foo_dll"]
