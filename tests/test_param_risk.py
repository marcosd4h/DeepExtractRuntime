"""Tests for helpers.param_risk.score_parameter_risk."""

import pytest

from helpers.param_risk import score_parameter_risk


def test_buffer_size_pair():
    sig = "void foo(void *buf, DWORD cbSize)"
    score, reasons = score_parameter_risk(sig)
    assert score >= 0.9
    assert any("buffer" in r for r in reasons)


def test_handle_parameter():
    sig = "void foo(HANDLE h)"
    score, reasons = score_parameter_risk(sig)
    assert 0.4 <= score <= 0.6


def test_string_parameter():
    sig = "void foo(LPCWSTR path)"
    score, reasons = score_parameter_risk(sig)
    assert score >= 0.7


def test_void_params():
    sig = "HRESULT DoWork(void)"
    score, reasons = score_parameter_risk(sig)
    assert score < 0.3
    assert any("no parameters" in r for r in reasons)


def test_no_signature():
    score, reasons = score_parameter_risk(None)
    assert score == 0.0
    assert reasons == []


def test_empty_string():
    score, reasons = score_parameter_risk("")
    assert score == 0.0
    assert reasons == []


def test_reasons_populated():
    sig = "void ProcessInput(void *pBuf, DWORD cbLen, LPCWSTR wszName)"
    score, reasons = score_parameter_risk(sig)
    assert score >= 0.8
    assert len(reasons) > 0


def test_com_interface_pointer():
    sig = "HRESULT Activate(IUnknown *punk)"
    score, reasons = score_parameter_risk(sig)
    assert score >= 0.5


def test_multiple_high_risk():
    sig = "HRESULT Read(void *pBuffer, ULONG cbSize, LPCWSTR wszPath)"
    score, reasons = score_parameter_risk(sig)
    assert score >= 0.85
    assert len(reasons) >= 1
