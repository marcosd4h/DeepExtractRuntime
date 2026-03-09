"""Tests for assembly-level semantic diffing in verify-decompiled.

Targets:
    .agent/skills/verify-decompiled/scripts/_common.py
        - extract_basic_blocks()
        - check_semantic_block_mismatch()
        - BasicBlock, SemanticDiffResult
"""

from __future__ import annotations

import pytest

from conftest import _make_function_record, import_skill_module

_mod = import_skill_module("verify-decompiled", "_common")

extract_basic_blocks = _mod.extract_basic_blocks
check_semantic_block_mismatch = _mod.check_semantic_block_mismatch
BasicBlock = _mod.BasicBlock
parse_assembly = _mod.parse_assembly
parse_decompiled = _mod.parse_decompiled
Severity = _mod.Severity
run_heuristic_checks = _mod.run_heuristic_checks


# ===================================================================
# extract_basic_blocks
# ===================================================================


class TestExtractBasicBlocks:
    def test_empty_assembly(self):
        blocks = extract_basic_blocks("")
        assert blocks == []

    def test_none_assembly(self):
        blocks = extract_basic_blocks(None)
        assert blocks == []

    def test_single_instruction(self):
        asm = "mov eax, 1\nret"
        blocks = extract_basic_blocks(asm)
        assert len(blocks) >= 1
        assert blocks[-1].is_exit is True

    def test_branch_creates_new_block(self):
        asm = (
            "test rcx, rcx\n"
            "jz loc_1234\n"
            "call SomeFunc\n"
            "ret"
        )
        blocks = extract_basic_blocks(asm)
        assert len(blocks) >= 2

    def test_call_targets_extracted(self):
        asm = (
            "mov rcx, rbx\n"
            "call CreateFileW\n"
            "test eax, eax\n"
            "jz error\n"
            "call CloseHandle\n"
            "ret"
        )
        blocks = extract_basic_blocks(asm)
        all_targets = []
        for b in blocks:
            all_targets.extend(b.call_targets)
        assert "CreateFileW" in all_targets
        assert "CloseHandle" in all_targets

    def test_imp_prefix_stripped(self):
        asm = "call __imp_CreateProcessW\nret"
        blocks = extract_basic_blocks(asm)
        all_targets = []
        for b in blocks:
            all_targets.extend(b.call_targets)
        assert "CreateProcessW" in all_targets
        assert "__imp_CreateProcessW" not in all_targets

    def test_first_block_is_entry(self):
        asm = "push rbp\nmov rbp, rsp\nret"
        blocks = extract_basic_blocks(asm)
        assert blocks[0].is_entry is True

    def test_ret_block_is_exit(self):
        asm = "mov eax, 0\nret"
        blocks = extract_basic_blocks(asm)
        exit_blocks = [b for b in blocks if b.is_exit]
        assert len(exit_blocks) >= 1

    def test_multiple_branches_create_multiple_blocks(self):
        asm = (
            "test rcx, rcx\n"
            "jz skip1\n"
            "call Func1\n"
            "test rax, rax\n"
            "jz skip2\n"
            "call Func2\n"
            "ret"
        )
        blocks = extract_basic_blocks(asm)
        assert len(blocks) >= 3

    def test_numeric_call_target_excluded(self):
        asm = "call 0x140001000\nret"
        blocks = extract_basic_blocks(asm)
        all_targets = []
        for b in blocks:
            all_targets.extend(b.call_targets)
        assert all(not t.startswith("0x") for t in all_targets)

    def test_layered_prefix_stripped(self):
        """cs:__imp_Foo must resolve to Foo, not __imp_Foo."""
        asm = "call cs:__imp_CreateFileW\nret"
        blocks = extract_basic_blocks(asm)
        all_targets = []
        for b in blocks:
            all_targets.extend(b.call_targets)
        assert "CreateFileW" in all_targets
        assert "cs:__imp_CreateFileW" not in all_targets
        assert "__imp_CreateFileW" not in all_targets

    def test_mangled_call_target_normalized(self):
        """MSVC-mangled ?Func@@... must resolve to Func."""
        asm = (
            "call ?AiBuildAxISParams@@YAKPEBG0PEAPEAU_CONSENTUI_PARAM_HEADER@@@Z\n"
            "call ?AiLogPerfTrackEvent@@YAKPEBU_EVENT_DESCRIPTOR@@@Z\n"
            "ret"
        )
        blocks = extract_basic_blocks(asm)
        all_targets = []
        for b in blocks:
            all_targets.extend(b.call_targets)
        assert "AiBuildAxISParams" in all_targets
        assert "AiLogPerfTrackEvent" in all_targets
        assert not any(t.startswith("?") for t in all_targets)


# ===================================================================
# check_semantic_block_mismatch
# ===================================================================


class TestCheckSemanticBlockMismatch:
    def test_empty_inputs(self):
        asm_stats = _mod.AsmStats()
        decomp_stats = _mod.DecompStats()
        issues = check_semantic_block_mismatch(asm_stats, decomp_stats, "", "")
        assert issues == []

    def test_none_inputs(self):
        asm_stats = _mod.AsmStats()
        decomp_stats = _mod.DecompStats()
        issues = check_semantic_block_mismatch(asm_stats, decomp_stats, None, None)
        assert issues == []

    def test_missing_call_targets_detected(self):
        asm = (
            "call CreateFileW\n"
            "test eax, eax\n"
            "jz error\n"
            "call WriteFile\n"
            "call CloseHandle\n"
            "ret"
        )
        decomp = (
            "int __fastcall MyFunc(__int64 a1)\n"
            "{\n"
            "  CreateFileW(a1);\n"
            "  return 0;\n"
            "}\n"
        )
        _, asm_stats = parse_assembly(asm)
        decomp_stats = parse_decompiled(decomp)
        issues = check_semantic_block_mismatch(asm_stats, decomp_stats, asm, decomp)
        missing_ops = [i for i in issues if i.category == "missing_operation"]
        assert len(missing_ops) >= 1

    def test_guarded_call_blocks_detected(self):
        asm = (
            "mov rcx, [rbx+18h]\n"
            "test rcx, rcx\n"
            "jz skip1\n"
            "call FuncA\n"
            "mov rcx, [rbx+20h]\n"
            "test rcx, rcx\n"
            "jz skip2\n"
            "call FuncB\n"
            "mov rcx, [rbx+28h]\n"
            "test rcx, rcx\n"
            "jz skip3\n"
            "call FuncC\n"
            "ret"
        )
        decomp = (
            "void __fastcall Func(__int64 a1)\n"
            "{\n"
            "  FuncA(*(_QWORD *)(a1 + 0x18));\n"
            "  FuncB(*(_QWORD *)(a1 + 0x20));\n"
            "  FuncC(*(_QWORD *)(a1 + 0x28));\n"
            "}\n"
        )
        _, asm_stats = parse_assembly(asm)
        decomp_stats = parse_decompiled(decomp)
        issues = check_semantic_block_mismatch(asm_stats, decomp_stats, asm, decomp)
        critical = [i for i in issues if i.severity == Severity.CRITICAL]
        assert len(critical) >= 1
        assert any("NULL-guarded" in i.summary or "guard" in i.summary.lower() for i in critical)

    def test_no_issues_when_calls_match(self):
        asm = (
            "call CreateFileW\n"
            "test eax, eax\n"
            "jz error\n"
            "ret"
        )
        decomp = (
            "int __fastcall MyFunc(__int64 a1)\n"
            "{\n"
            "  if ( !CreateFileW(a1) )\n"
            "    return -1;\n"
            "  return 0;\n"
            "}\n"
        )
        _, asm_stats = parse_assembly(asm)
        decomp_stats = parse_decompiled(decomp)
        issues = check_semantic_block_mismatch(asm_stats, decomp_stats, asm, decomp)
        missing_call_issues = [
            i for i in issues
            if i.category == "missing_operation" and "call target" in i.summary.lower()
        ]
        assert len(missing_call_issues) == 0

    def test_no_false_positive_for_mangled_calls(self):
        """Mangled asm targets matching demangled decompiled names must not flag."""
        asm = (
            "call ?AiBuildAxISParams@@YAKPEBG0PEAPEAU_CONSENTUI_PARAM_HEADER@@@Z\n"
            "call cs:__imp_LocalFree\n"
            "call cs:__imp_RpcAsyncCompleteCall\n"
            "ret"
        )
        decomp = (
            "void __fastcall Func(void)\n"
            "{\n"
            "  AiBuildAxISParams(a1, a2, &hMem);\n"
            "  LocalFree(hMem);\n"
            "  RpcAsyncCompleteCall(pAsync, &Reply);\n"
            "}\n"
        )
        _, asm_stats = parse_assembly(asm)
        decomp_stats = parse_decompiled(decomp)
        issues = check_semantic_block_mismatch(asm_stats, decomp_stats, asm, decomp)
        missing_call_issues = [
            i for i in issues
            if i.category == "missing_operation" and "call target" in i.summary.lower()
        ]
        assert len(missing_call_issues) == 0

    def test_byte_access_mismatch(self):
        asm = (
            "mov al, [rcx+10h]\n"
            "mov bl, [rcx+11h]\n"
            "mov cl, [rcx+12h]\n"
            "ret"
        )
        decomp = (
            "void __fastcall Func(__int64 a1)\n"
            "{\n"
            "  *(_DWORD *)(a1 + 0x10) = 1;\n"
            "}\n"
        )
        _, asm_stats = parse_assembly(asm)
        decomp_stats = parse_decompiled(decomp)
        issues = check_semantic_block_mismatch(asm_stats, decomp_stats, asm, decomp)
        size_issues = [i for i in issues if i.category == "wrong_access_size"]
        assert len(size_issues) >= 1

    def test_issues_sorted_by_severity(self):
        asm = (
            "mov al, [rcx+10h]\n"
            "mov bl, [rcx+11h]\n"
            "mov cl, [rcx+12h]\n"
            "test rcx, rcx\n"
            "jz skip\n"
            "call FuncA\n"
            "test rcx, rcx\n"
            "jz skip2\n"
            "call FuncB\n"
            "test rcx, rcx\n"
            "jz skip3\n"
            "call FuncC\n"
            "ret"
        )
        decomp = (
            "void __fastcall Func(__int64 a1)\n"
            "{\n"
            "  FuncA(a1);\n"
            "  FuncB(a1);\n"
            "  FuncC(a1);\n"
            "}\n"
        )
        _, asm_stats = parse_assembly(asm)
        decomp_stats = parse_decompiled(decomp)
        issues = check_semantic_block_mismatch(asm_stats, decomp_stats, asm, decomp)
        if len(issues) >= 2:
            for i in range(len(issues) - 1):
                assert int(issues[i].severity) >= int(issues[i + 1].severity)


# ===================================================================
# Integration: run_heuristic_checks passes assembly/decompiled code
# ===================================================================


class TestRunHeuristicChecksIntegration:
    def test_without_code_skips_block_check(self):
        asm_stats = _mod.AsmStats()
        decomp_stats = _mod.DecompStats()
        issues = run_heuristic_checks(asm_stats, decomp_stats)
        block_issues = [i for i in issues if i.category in ("missing_operation",) and "block" in (i.summary or "").lower()]
        assert len(block_issues) == 0

    def test_with_code_runs_block_check(self):
        asm = (
            "test rcx, rcx\n"
            "jz skip\n"
            "call MissingFunc1\n"
            "call MissingFunc2\n"
            "ret"
        )
        decomp = (
            "void Func()\n"
            "{\n"
            "  return;\n"
            "}\n"
        )
        _, asm_stats = parse_assembly(asm)
        decomp_stats = parse_decompiled(decomp)
        issues = run_heuristic_checks(
            asm_stats, decomp_stats,
            assembly_code=asm,
            decompiled_code=decomp,
        )
        has_block_level = any(
            i.category in ("missing_operation", "wrong_access_size")
            for i in issues
        )
        assert has_block_level
