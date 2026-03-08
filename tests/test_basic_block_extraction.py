"""Tests for basic block extraction enhancements (Issue #17).

Target: agents/verifier/scripts/extract_basic_blocks.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Bootstrap the verifier scripts directory so extract_basic_blocks can be imported
_VERIFIER_SCRIPTS = Path(__file__).resolve().parents[1] / "agents" / "verifier" / "scripts"
if str(_VERIFIER_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_VERIFIER_SCRIPTS))

from extract_basic_blocks import (
    BasicBlock,
    _is_indirect_jump_or_call,
    compute_limitations,
    detect_seh_patterns,
    extract_basic_blocks,
)


# ===================================================================
# Indirect jump detection
# ===================================================================

class TestIndirectJumpDetection:
    """Test _is_indirect_jump_or_call for various patterns."""

    def test_jmp_register(self):
        assert _is_indirect_jump_or_call("jmp", "rax") is True

    def test_jmp_memory(self):
        assert _is_indirect_jump_or_call("jmp", "[rax]") is True

    def test_jmp_complex_memory(self):
        assert _is_indirect_jump_or_call("jmp", "qword ptr [rax+rcx*8]") is True

    def test_call_memory(self):
        assert _is_indirect_jump_or_call("call", "[rbx+10h]") is True

    def test_jmp_label_is_not_indirect(self):
        assert _is_indirect_jump_or_call("jmp", "loc_140001234") is False

    def test_call_function_is_not_indirect(self):
        assert _is_indirect_jump_or_call("call", "CreateFileW") is False

    def test_call_import_is_not_indirect(self):
        assert _is_indirect_jump_or_call("call", "__imp_CreateFileW") is False

    def test_jmp_short_label_is_not_indirect(self):
        assert _is_indirect_jump_or_call("jmp", "short loc_140001234") is False

    def test_jmp_eax_32bit(self):
        assert _is_indirect_jump_or_call("jmp", "eax") is True

    def test_jmp_dword_ptr(self):
        assert _is_indirect_jump_or_call("jmp", "dword ptr [eax+ecx*4]") is True


class TestIndirectJumpInBlocks:
    """Test that indirect jumps create block terminators and set exit_type."""

    def test_indirect_jump_creates_block_boundary(self):
        asm = (
            "mov rax, [rcx+8]\n"
            "jmp rax\n"
            "mov rbx, 1\n"
            "ret\n"
        )
        blocks = extract_basic_blocks(asm)
        assert len(blocks) >= 2
        indirect_blocks = [b for b in blocks if b.exit_type == "indirect_jump"]
        assert len(indirect_blocks) == 1
        assert indirect_blocks[0].has_indirect_jump is True

    def test_indirect_jump_no_successors(self):
        asm = (
            "mov rax, [rcx+8]\n"
            "jmp rax\n"
        )
        blocks = extract_basic_blocks(asm)
        indirect_blocks = [b for b in blocks if b.exit_type == "indirect_jump"]
        assert len(indirect_blocks) == 1
        assert indirect_blocks[0].successors == []

    def test_indirect_jump_qword_ptr(self):
        asm = (
            "mov rax, [rbx]\n"
            "jmp qword ptr [rax+rcx*8]\n"
            "nop\n"
        )
        blocks = extract_basic_blocks(asm)
        indirect_blocks = [b for b in blocks if b.exit_type == "indirect_jump"]
        assert len(indirect_blocks) == 1


# ===================================================================
# SEH handler detection
# ===================================================================

class TestSEHDetection:
    """Test detect_seh_patterns for SEH-related patterns."""

    def test_no_seh(self):
        result = detect_seh_patterns("mov eax, 1\nret", "int f() { return 1; }")
        assert result["has_seh"] is False
        assert result["indicators"] == []

    def test_seh_try_in_decompiled(self):
        decompiled = "void f() { __try { DoSomething(); } __except(1) { HandleError(); } }"
        result = detect_seh_patterns("", decompiled)
        assert result["has_seh"] is True
        assert any("__try" in i for i in result["indicators"])

    def test_seh_except_in_decompiled(self):
        decompiled = "void f() { __try {} __finally { cleanup(); } }"
        result = detect_seh_patterns("", decompiled)
        assert result["has_seh"] is True
        assert any("__finally" in i for i in result["indicators"])

    def test_seh_handler_in_assembly(self):
        asm = "call __C_specific_handler\nret"
        result = detect_seh_patterns(asm)
        assert result["has_seh"] is True

    def test_pdata_reference_in_assembly(self):
        asm = "lea rax, pdata_section\nmov [rsp], rax"
        result = detect_seh_patterns(asm)
        assert result["has_seh"] is True


# ===================================================================
# Complex addressing mode regex
# ===================================================================

class TestComplexAddressingInMemoryExtraction:
    """Test that the expanded _ASM_MEM_OFFSET_RE handles complex modes."""

    def test_simple_base_plus_offset(self):
        asm = "mov eax, [rcx+10h]\nret"
        blocks = extract_basic_blocks(asm)
        mem_blocks = [b for b in blocks if b.has_memory_access]
        assert len(mem_blocks) >= 1


# ===================================================================
# Limitations field
# ===================================================================

class TestLimitations:
    """Test compute_limitations returns appropriate limitation strings."""

    def test_no_limitations(self):
        blocks = [BasicBlock(block_id=0, exit_type="ret")]
        seh = {"has_seh": False, "indicators": []}
        assert compute_limitations(blocks, seh) == []

    def test_indirect_jump_limitation(self):
        blocks = [
            BasicBlock(block_id=0, exit_type="indirect_jump", has_indirect_jump=True),
        ]
        seh = {"has_seh": False, "indicators": []}
        lims = compute_limitations(blocks, seh)
        assert len(lims) == 1
        assert "indirect_jump" in lims[0]

    def test_seh_limitation(self):
        blocks = [BasicBlock(block_id=0, exit_type="ret")]
        seh = {"has_seh": True, "indicators": ["__try pattern"]}
        lims = compute_limitations(blocks, seh)
        assert len(lims) == 1
        assert "unresolved_exception_flow" in lims[0]

    def test_combined_limitations(self):
        blocks = [
            BasicBlock(block_id=0, exit_type="indirect_jump", has_indirect_jump=True),
        ]
        seh = {"has_seh": True, "indicators": ["SEH handler"]}
        lims = compute_limitations(blocks, seh)
        assert len(lims) == 2

    def test_unresolved_jump_target(self):
        block = BasicBlock(
            block_id=0,
            exit_type="unconditional_jump",
            jump_target="loc_DEADBEEF",
            successors=[],
        )
        seh = {"has_seh": False, "indicators": []}
        lims = compute_limitations([block], seh)
        assert any("unresolved_targets" in l for l in lims)


class TestBasicBlockToDict:
    """Test that BasicBlock.to_dict() includes the new has_indirect_jump field."""

    def test_to_dict_includes_indirect_jump(self):
        block = BasicBlock(block_id=0, has_indirect_jump=True)
        d = block.to_dict()
        assert "has_indirect_jump" in d
        assert d["has_indirect_jump"] is True
