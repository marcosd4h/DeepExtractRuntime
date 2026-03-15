"""Tests for helpers.param_risk.describe_parameter_surface."""

import pytest

from helpers.param_risk import describe_parameter_surface


def test_buffer_size_pair():
    sig = "void foo(void *buf, DWORD cbSize)"
    meta = describe_parameter_surface(sig)
    assert meta["has_buffer_size_pair"] is True
    assert meta["has_buffer_pointer"] is True
    assert "buffer+size pair" in meta["characteristics"]


def test_handle_parameter():
    sig = "void foo(HANDLE h)"
    meta = describe_parameter_surface(sig)
    assert meta["has_handle"] is True
    assert meta["param_count"] == 1
    assert "handle parameter" in meta["characteristics"]


def test_string_parameter():
    sig = "void foo(LPCWSTR path)"
    meta = describe_parameter_surface(sig)
    assert meta["has_string_pointer"] is True
    assert "string pointer" in meta["characteristics"]


def test_void_params():
    sig = "HRESULT DoWork(void)"
    meta = describe_parameter_surface(sig)
    assert meta["param_count"] == 0
    assert meta["characteristics"] == []


def test_no_signature():
    meta = describe_parameter_surface(None)
    assert meta["param_count"] == 0
    assert meta["characteristics"] == []


def test_empty_string():
    meta = describe_parameter_surface("")
    assert meta["param_count"] == 0
    assert meta["characteristics"] == []


def test_characteristics_populated():
    sig = "void ProcessInput(void *pBuf, DWORD cbLen, LPCWSTR wszName)"
    meta = describe_parameter_surface(sig)
    assert meta["param_count"] == 3
    assert meta["has_buffer_pointer"] is True
    assert meta["has_string_pointer"] is True
    assert meta["has_buffer_size_pair"] is True
    assert len(meta["characteristics"]) >= 2


def test_com_interface_pointer():
    sig = "HRESULT Activate(IUnknown *punk)"
    meta = describe_parameter_surface(sig)
    assert meta["has_com_interface"] is True
    assert "COM interface pointer" in meta["characteristics"]


def test_multiple_types():
    sig = "HRESULT Read(void *pBuffer, ULONG cbSize, LPCWSTR wszPath)"
    meta = describe_parameter_surface(sig)
    assert meta["param_count"] == 3
    assert meta["has_buffer_pointer"] is True
    assert meta["has_string_pointer"] is True
    assert meta["has_buffer_size_pair"] is True
    assert meta["pointer_param_count"] >= 2
