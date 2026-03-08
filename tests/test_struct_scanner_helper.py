"""Tests for helpers/struct_scanner.py (batch scanning and merge).

The skill reconstruct-types uses scan_decompiled_struct_accesses; this file
tests scan_batch_struct_accesses and merge_struct_fields from the helper.
"""

from __future__ import annotations

import pytest

from helpers.struct_scanner import (
    merge_struct_fields,
    parse_signature_params,
    scan_assembly_struct_accesses,
    scan_batch_struct_accesses,
    scan_decompiled_struct_accesses,
)


# Type sizes used by batch scanner (matches reconstruct-types _common)
_TYPE_SIZES = {"_DWORD": 4, "_QWORD": 8, "_BYTE": 1, "_WORD": 2}


# ===================================================================
# scan_batch_struct_accesses
# ===================================================================


class TestScanBatchStructAccesses:
    def test_empty_returns_empty(self):
        assert scan_batch_struct_accesses("", _TYPE_SIZES) == []

    def test_indexed_pattern(self):
        code = "*((_DWORD *)a1 + 5) = 0;"
        accesses = scan_batch_struct_accesses(code, _TYPE_SIZES)
        assert len(accesses) >= 1
        hit = next(a for a in accesses if a["pattern"] == "indexed")
        assert hit["base"] == "a1"
        assert hit["offset"] == 20  # 5 * 4
        assert hit["size"] == 4
        assert hit["type_name"] == "_DWORD"

    def test_direct_offset_pattern(self):
        code = "*(_DWORD *)(a1 + 0x10) = 1;"
        accesses = scan_batch_struct_accesses(code, _TYPE_SIZES)
        assert len(accesses) >= 1
        hit = next((a for a in accesses if a["pattern"] == "direct"), None)
        assert hit is not None, "Expected 'direct' pattern in accesses"
        assert hit["offset"] == 16
        assert hit["size"] == 4

    def test_zero_offset_pattern(self):
        code = "v1 = *(_QWORD *)a1;"
        accesses = scan_batch_struct_accesses(code, _TYPE_SIZES)
        assert len(accesses) >= 1
        hit = next((a for a in accesses if a["pattern"] == "zero_offset"), None)
        assert hit is not None, "Expected 'zero_offset' pattern in accesses"
        assert hit["offset"] == 0
        assert hit["size"] == 8


# ===================================================================
# scan_decompiled_struct_accesses (helper directly)
# ===================================================================


class TestScanDecompiledStructAccesses:
    def test_empty_returns_empty(self):
        assert scan_decompiled_struct_accesses("", _TYPE_SIZES) == []

    def test_typed_ptr_arith(self):
        code = "  *((_DWORD *)this + 5) = 0;"
        accesses = scan_decompiled_struct_accesses(code, _TYPE_SIZES)
        assert len(accesses) >= 1
        hit = accesses[0]
        assert hit["base"] == "this"
        assert hit["byte_offset"] == 20
        assert hit["size"] == 4
        assert hit["pattern"] == "typed_ptr_arith"


# ===================================================================
# scan_assembly_struct_accesses
# ===================================================================


class TestScanAssemblyStructAccesses:
    def test_empty_returns_empty(self):
        assert scan_assembly_struct_accesses("") == []

    def test_dword_ptr_offset(self):
        code = "mov dword ptr [rcx+8h], eax"
        accesses = scan_assembly_struct_accesses(code)
        assert len(accesses) >= 1
        assert accesses[0]["byte_offset"] == 8
        assert accesses[0]["size"] == 4
        assert accesses[0]["param_num"] == 1

    def test_skips_stack_regs(self):
        code = "mov dword ptr [rsp+20h], eax"
        assert scan_assembly_struct_accesses(code) == []


# ===================================================================
# parse_signature_params
# ===================================================================


class TestParseSignatureParams:
    def test_empty(self):
        assert parse_signature_params("") == {}
        assert parse_signature_params(None) == {}

    def test_void_params(self):
        assert parse_signature_params("void foo(void)") == {}

    def test_multiple_params(self):
        params = parse_signature_params("void foo(int a1, char *a2)")
        assert "a1" in params
        assert "a2" in params

    def test_byref_param(self):
        params = parse_signature_params("void foo(int * /*BYREF*/ p)")
        assert "p" in params or len(params) >= 1


# ===================================================================
# merge_struct_fields
# ===================================================================


class TestMergeStructFields:
    def test_empty_accesses(self):
        merged = merge_struct_fields({}, {4: "uint32_t", 8: "uint64_t"})
        assert merged == []

    def test_merge_by_offset(self):
        all_accesses = {
            "func1": [
                {"offset": 0, "size": 8, "type_name": "_QWORD"},
                {"offset": 8, "size": 4, "type_name": "_DWORD"},
            ],
            "func2": [
                {"offset": 8, "size": 4, "type_name": "_DWORD"},
            ],
        }
        size_to_type = {4: "uint32_t", 8: "uint64_t"}
        merged = merge_struct_fields(all_accesses, size_to_type)
        assert len(merged) == 2
        offsets = [m["offset"] for m in merged]
        assert 0 in offsets
        assert 8 in offsets
        assert merged[0]["c_type"] == "uint64_t"
        assert merged[1]["c_type"] == "uint32_t"

    def test_larger_size_wins(self):
        all_accesses = {
            "f1": [{"offset": 0, "size": 4, "type_name": "_DWORD"}],
            "f2": [{"offset": 0, "size": 8, "type_name": "_QWORD"}],
        }
        size_to_type = {4: "uint32_t", 8: "uint64_t"}
        merged = merge_struct_fields(all_accesses, size_to_type)
        assert len(merged) == 1
        assert merged[0]["size"] == 8
        assert merged[0]["c_type"] == "uint64_t"
