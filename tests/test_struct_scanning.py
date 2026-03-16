"""Tests for struct field scanning from assembly code.

Target: skills/reconstruct-types/scripts/scan_struct_fields.py
"""

from __future__ import annotations

import pytest

from conftest import import_skill_module

_scan_mod = import_skill_module("reconstruct-types", "scan_struct_fields")
scan_assembly_code = _scan_mod.scan_assembly_code
parse_signature_params = _scan_mod.parse_signature_params

_common_mod = import_skill_module("reconstruct-types")
TYPE_SIZES = _common_mod.TYPE_SIZES


# ===================================================================
# scan_assembly_code
# ===================================================================

class TestScanAssemblyCode:
    def test_empty_input(self):
        assert scan_assembly_code("") == []
        assert scan_assembly_code(None) == []

    def test_dword_ptr_offset(self):
        """mov dword ptr [rcx+8], eax -> offset=8, size=4."""
        code = "mov dword ptr [rcx+8h], eax"
        results = scan_assembly_code(code)
        assert len(results) >= 1
        hit = results[0]
        assert hit["byte_offset"] == 8
        assert hit["size"] == 4

    def test_qword_ptr_offset(self):
        """mov qword ptr [rdi+20h], rax -> offset=32, size=8."""
        code = "mov qword ptr [rdi+20h], rax"
        results = scan_assembly_code(code)
        assert len(results) >= 1
        assert results[0]["byte_offset"] == 0x20
        assert results[0]["size"] == 8

    def test_zero_offset(self):
        """mov dword ptr [rcx], eax -> offset=0, size=4."""
        code = "mov dword ptr [rcx], eax"
        results = scan_assembly_code(code)
        assert len(results) >= 1
        assert results[0]["byte_offset"] == 0
        assert results[0]["size"] == 4

    def test_default_size_without_ptr_qualifier(self):
        """mov [rcx+10h], eax -- no ptr qualifier -> defaults to 8 (QWORD on x64)."""
        code = "mov [rcx+10h], eax"
        results = scan_assembly_code(code)
        assert len(results) >= 1
        hit = results[0]
        assert hit["byte_offset"] == 0x10
        # Without explicit ptr qualifier, scanner defaults to 8
        assert hit["size"] == 8

    def test_param_register_detection(self):
        """rcx is param 1 in x64 fastcall."""
        code = "mov dword ptr [rcx+4h], 0"
        results = scan_assembly_code(code)
        assert len(results) >= 1
        assert results[0]["param_num"] == 1

    def test_rdx_is_param2(self):
        code = "mov qword ptr [rdx+8h], rax"
        results = scan_assembly_code(code)
        assert len(results) >= 1
        assert results[0]["param_num"] == 2

    def test_skips_stack_registers(self):
        """Accesses through rsp/rbp are stack frame, not struct fields."""
        code = "mov dword ptr [rsp+20h], eax\nmov dword ptr [rbp+8h], ecx"
        results = scan_assembly_code(code)
        assert len(results) == 0

    def test_prologue_alias_detection(self):
        """mov r13, rcx in prologue -> r13 aliases param 1."""
        code = (
            "push r13\n"
            "mov r13, rcx\n"
            "mov dword ptr [r13+10h], 0\n"
        )
        results = scan_assembly_code(code)
        r13_hits = [r for r in results if r["base"] == "r13"]
        assert len(r13_hits) >= 1
        assert r13_hits[0]["param_num"] == 1


# ===================================================================
# parse_signature_params
# ===================================================================

class TestParseSignatureParams:
    def test_empty(self):
        assert parse_signature_params("") == {}
        assert parse_signature_params(None) == {}

    def test_standard_signature(self):
        sig = "__int64 __fastcall Foo(void *a1, int a2)"
        params = parse_signature_params(sig)
        assert "a1" in params
        assert "a2" in params

    def test_void_params(self):
        sig = "void __fastcall Foo(void)"
        params = parse_signature_params(sig)
        assert len(params) == 0

    def test_no_parens(self):
        assert parse_signature_params("no_parens_here") == {}
