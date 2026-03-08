"""Tests for calling convention and assembly width constants.

Target: helpers/calling_conventions.py
"""

from __future__ import annotations

import pytest

from helpers.calling_conventions import (
    ASM_PTR_SIZES,
    ASM_REG_SIZES,
    PARAM_REGISTERS,
    PARAM_REGS_X64,
    REGISTER_TO_PARAM,
    STACK_REGS,
    param_name_for,
)


# ===================================================================
# Parameter registers (x64 fastcall)
# ===================================================================


class TestParamRegisters:
    def test_param1_aliases(self):
        assert "rcx" in PARAM_REGISTERS[1]
        assert "ecx" in PARAM_REGISTERS[1]
        assert "cx" in PARAM_REGISTERS[1]
        assert "cl" in PARAM_REGISTERS[1]

    def test_param2_aliases(self):
        assert "rdx" in PARAM_REGISTERS[2]
        assert "edx" in PARAM_REGISTERS[2]

    def test_param3_param4(self):
        assert "r8" in PARAM_REGISTERS[3]
        assert "r9" in PARAM_REGISTERS[4]

    def test_register_to_param_reverse_lookup(self):
        assert REGISTER_TO_PARAM["rcx"] == 1
        assert REGISTER_TO_PARAM["rdx"] == 2
        assert REGISTER_TO_PARAM["r8"] == 3
        assert REGISTER_TO_PARAM["r9"] == 4
        assert REGISTER_TO_PARAM["ecx"] == 1
        assert REGISTER_TO_PARAM["r8d"] == 3

    def test_param_regs_x64_alias(self):
        assert PARAM_REGS_X64 is REGISTER_TO_PARAM


# ===================================================================
# Assembly register sizes
# ===================================================================


class TestAsmRegSizes:
    def test_64bit_regs(self):
        assert ASM_REG_SIZES["rax"] == 8
        assert ASM_REG_SIZES["rcx"] == 8
        assert ASM_REG_SIZES["r8"] == 8
        assert ASM_REG_SIZES["r15"] == 8

    def test_32bit_regs(self):
        assert ASM_REG_SIZES["eax"] == 4
        assert ASM_REG_SIZES["ecx"] == 4
        assert ASM_REG_SIZES["r8d"] == 4

    def test_16bit_regs(self):
        assert ASM_REG_SIZES["ax"] == 2
        assert ASM_REG_SIZES["r8w"] == 2

    def test_8bit_regs(self):
        assert ASM_REG_SIZES["al"] == 1
        assert ASM_REG_SIZES["cl"] == 1
        assert ASM_REG_SIZES["r8b"] == 1


# ===================================================================
# Pointer sizes
# ===================================================================


class TestAsmPtrSizes:
    def test_ptr_sizes(self):
        assert ASM_PTR_SIZES["byte"] == 1
        assert ASM_PTR_SIZES["word"] == 2
        assert ASM_PTR_SIZES["dword"] == 4
        assert ASM_PTR_SIZES["qword"] == 8
        assert ASM_PTR_SIZES["xmmword"] == 16


# ===================================================================
# Stack registers
# ===================================================================


class TestStackRegs:
    def test_stack_regs_excluded(self):
        assert "rsp" in STACK_REGS
        assert "esp" in STACK_REGS
        assert "rbp" in STACK_REGS
        assert "ebp" in STACK_REGS

    def test_param_regs_not_in_stack(self):
        assert "rcx" not in STACK_REGS
        assert "rdx" not in STACK_REGS


# ===================================================================
# param_name_for
# ===================================================================


class TestParamNameFor:
    def test_param_names(self):
        assert param_name_for(1) == "a1"
        assert param_name_for(2) == "a2"
        assert param_name_for(4) == "a4"
