"""Tests for the decompiler verification heuristics.

Target: skills/verify-decompiled/scripts/_common.py
"""

from __future__ import annotations

import pytest

from conftest import import_skill_module

# Load verify-decompiled _common (hyphenated dir)
_mod = import_skill_module("verify-decompiled")
AsmInstruction = _mod.AsmInstruction
AsmStats = _mod.AsmStats
DecompStats = _mod.DecompStats
Severity = _mod.Severity
VerificationIssue = _mod.VerificationIssue
check_access_size_mismatch = _mod.check_access_size_mismatch
check_branch_count_mismatch = _mod.check_branch_count_mismatch
check_call_count_mismatch = _mod.check_call_count_mismatch
check_decompiler_artifacts = _mod.check_decompiler_artifacts
check_null_check_mismatch = _mod.check_null_check_mismatch
check_return_type_mismatch = _mod.check_return_type_mismatch
check_signedness_mismatch = _mod.check_signedness_mismatch
decode_mangled_return_type = _mod.decode_mangled_return_type
is_decompilation_failure = _mod.is_decompilation_failure
parse_asm_instruction = _mod.parse_asm_instruction
parse_assembly = _mod.parse_assembly
parse_decompiled = _mod.parse_decompiled
run_heuristic_checks = _mod.run_heuristic_checks


# ===================================================================
# parse_asm_instruction
# ===================================================================

class TestParseAsmInstruction:
    def test_none_for_empty(self):
        assert parse_asm_instruction("") is None
        assert parse_asm_instruction("; comment only") is None

    def test_mov_instruction(self):
        inst = parse_asm_instruction("mov eax, [rcx+8]")
        assert inst is not None
        assert inst.mnemonic == "mov"
        assert inst.is_mov is True

    def test_call_instruction(self):
        inst = parse_asm_instruction("call CreateFileW")
        assert inst is not None
        assert inst.is_call is True
        assert inst.mnemonic == "call"

    def test_branch_jnz(self):
        inst = parse_asm_instruction("jnz loc_140001234")
        assert inst is not None
        assert inst.is_branch is True
        assert inst.branch_signedness == "neutral"

    def test_branch_signed(self):
        inst = parse_asm_instruction("jl loc_1234")
        assert inst is not None
        assert inst.is_branch is True
        assert inst.branch_signedness == "signed"

    def test_branch_unsigned(self):
        inst = parse_asm_instruction("ja loc_1234")
        assert inst is not None
        assert inst.is_branch is True
        assert inst.branch_signedness == "unsigned"

    def test_ret_instruction(self):
        inst = parse_asm_instruction("ret")
        assert inst is not None
        assert inst.is_ret is True

    def test_retn_instruction(self):
        inst = parse_asm_instruction("retn")
        assert inst is not None
        assert inst.is_ret is True

    def test_test_instruction(self):
        inst = parse_asm_instruction("test rax, rax")
        assert inst is not None
        assert inst.is_test is True

    def test_cmp_instruction(self):
        inst = parse_asm_instruction("cmp ecx, 5")
        assert inst is not None
        assert inst.is_cmp is True

    def test_lea_no_memory_access(self):
        inst = parse_asm_instruction("lea rax, [rcx+8]")
        assert inst is not None
        assert inst.is_lea is True
        assert inst.memory_access_size == 0  # LEA doesn't access memory

    def test_memory_access_size_dword_ptr(self):
        inst = parse_asm_instruction("mov eax, dword ptr [rcx+10h]")
        assert inst is not None
        assert inst.memory_access_size == 4

    def test_memory_access_size_qword_ptr(self):
        inst = parse_asm_instruction("mov rax, qword ptr [rcx+18h]")
        assert inst is not None
        assert inst.memory_access_size == 8

    def test_memory_access_size_byte_ptr(self):
        inst = parse_asm_instruction("mov al, byte ptr [rcx]")
        assert inst is not None
        assert inst.memory_access_size == 1

    def test_skips_directives(self):
        assert parse_asm_instruction("align 10h") is None
        assert parse_asm_instruction("db 90h") is None

    def test_ida_address_prefix(self):
        inst = parse_asm_instruction(".text:0000000140001000 mov eax, 1")
        assert inst is not None
        assert inst.mnemonic == "mov"


# ===================================================================
# parse_assembly (full function)
# ===================================================================

class TestParseAssembly:
    def test_empty_returns_zeroed(self):
        insts, stats = parse_assembly("")
        assert len(insts) == 0
        assert stats.instruction_count == 0

    def test_counts_calls_branches_ret(self):
        asm = (
            "push rbx\n"
            "call CreateFileW\n"
            "test rax, rax\n"
            "jz loc_err\n"
            "call ReadFile\n"
            "pop rbx\n"
            "ret\n"
        )
        insts, stats = parse_assembly(asm)
        assert stats.call_count == 2
        assert stats.branch_count == 1
        assert stats.ret_count == 1

    def test_null_check_pattern(self):
        """test reg,reg + jz = NULL check pattern."""
        asm = (
            "test rax, rax\n"
            "jz loc_null\n"
        )
        _, stats = parse_assembly(asm)
        assert stats.null_check_patterns == 1

    def test_non_self_test_not_null_check(self):
        """test rax, rcx (different regs) + jz is NOT a NULL check."""
        asm = (
            "test rax, rcx\n"
            "jz loc_1\n"
        )
        _, stats = parse_assembly(asm)
        assert stats.null_check_patterns == 0

    def test_memory_access_counting(self):
        asm = (
            "mov dword ptr [rcx+8], eax\n"    # DWORD write
            "mov rax, qword ptr [rcx+10h]\n"  # QWORD read
            "mov al, byte ptr [rdx]\n"         # BYTE read
        )
        _, stats = parse_assembly(asm)
        assert stats.dword_accesses == 1
        assert stats.qword_accesses == 1
        assert stats.byte_accesses == 1

    def test_signed_unsigned_branch_counts(self):
        asm = (
            "jl loc_1\n"   # signed
            "jg loc_2\n"   # signed
            "ja loc_3\n"   # unsigned
            "jz loc_4\n"   # neutral
        )
        _, stats = parse_assembly(asm)
        assert stats.signed_branch_count == 2
        assert stats.unsigned_branch_count == 1
        assert stats.neutral_branch_count == 1
        assert stats.branch_count == 4


# ===================================================================
# parse_decompiled
# ===================================================================

class TestParseDecompiled:
    def test_empty_returns_zeroed(self):
        stats = parse_decompiled("")
        assert stats.line_count == 0
        assert stats.if_count == 0
        assert stats.call_count == 0

    def test_decompilation_failure(self):
        stats = parse_decompiled("Decompiler returned None for this function")
        assert stats.line_count == 0

    def test_counts_if_statements(self):
        code = "int f() {\n  if (x) {\n    if (y) {\n    }\n  }\n}"
        stats = parse_decompiled(code)
        assert stats.if_count == 2

    def test_counts_goto(self):
        code = "void f() { goto LABEL; LABEL: return; }"
        stats = parse_decompiled(code)
        assert stats.goto_count == 1

    def test_counts_function_calls(self):
        code = "int f() {\n  CreateFileW(path);\n  ReadFile(h, buf, n);\n  return 0;\n}"
        stats = parse_decompiled(code)
        assert stats.call_count >= 2
        assert "CreateFileW" in stats.called_functions

    def test_skips_keywords(self):
        code = "void f() { if (x) while (y) for (;;) return 0; }"
        stats = parse_decompiled(code)
        # Keywords should not be counted as function calls
        assert "if" not in stats.called_functions
        assert "while" not in stats.called_functions
        assert "for" not in stats.called_functions

    def test_type_casts(self):
        code = (
            "void f() {\n"
            "  *((_DWORD *)a + 1) = 0;\n"
            "  *((_QWORD *)a + 2) = 0;\n"
            "  *((_BYTE *)a + 3) = 0;\n"
            "}\n"
        )
        stats = parse_decompiled(code)
        assert stats.dword_casts >= 1
        assert stats.qword_casts >= 1
        assert stats.byte_casts >= 1

    def test_decompiler_artifacts(self):
        code = "void f() { do { x = 1; } while ( 0 ); LOBYTE(v) = 1; }"
        stats = parse_decompiled(code)
        assert stats.do_while_0_count >= 1
        assert stats.lobyte_count >= 1

    def test_return_type_extraction(self):
        code = "int __fastcall MyFunc(void *a1)\n{\n  return 0;\n}"
        stats = parse_decompiled(code)
        assert stats.return_type == "int"

    def test_short_circuit_ops(self):
        code = "void f() { if (a && b || c) x(); }"
        stats = parse_decompiled(code)
        assert stats.short_circuit_ops >= 2

    def test_ternary(self):
        code = "int f() { return a ? 1 : 0; }"
        stats = parse_decompiled(code)
        assert stats.ternary_ops >= 1

    def test_switch_case(self):
        code = (
            "void f() {\n"
            "  switch (x) {\n"
            "    case 1:\n"
            "    case 2:\n"
            "    default:\n"
            "      break;\n"
            "  }\n"
            "}\n"
        )
        stats = parse_decompiled(code)
        assert stats.switch_count >= 1
        assert stats.case_count >= 3  # 2 cases + 1 default


# ===================================================================
# is_decompilation_failure
# ===================================================================

class TestIsDecompilationFailure:
    def test_none(self):
        assert is_decompilation_failure(None) is True

    def test_empty(self):
        assert is_decompilation_failure("") is True
        assert is_decompilation_failure("   ") is True

    def test_failure_prefix(self):
        assert is_decompilation_failure("Decompiler returned None for ...") is True
        assert is_decompilation_failure("Decompilation failed ...") is True

    def test_valid_code(self):
        assert is_decompilation_failure("int f() { return 0; }") is False


# ===================================================================
# decode_mangled_return_type
# ===================================================================

class TestDecodeMangledReturnType:
    def test_none_input(self):
        assert decode_mangled_return_type(None) is None

    def test_non_mangled(self):
        assert decode_mangled_return_type("DllMain") is None

    def test_void_return(self):
        # ?Func@@YAXXZ = void __cdecl Func()
        result = decode_mangled_return_type("?Func@@YAXXZ")
        assert result == "void"

    def test_int_return(self):
        # ?Func@@YAHXZ = int __cdecl Func()
        result = decode_mangled_return_type("?Func@@YAHXZ")
        assert result == "int"

    def test_bool_return(self):
        # ?Func@@YA_NXZ = bool __cdecl Func()
        result = decode_mangled_return_type("?Func@@YA_NXZ")
        assert result == "bool"


# ===================================================================
# Heuristic checks
# ===================================================================

class TestCheckCallCountMismatch:
    def test_no_issue_when_close(self):
        asm = AsmStats(call_count=5)
        dec = DecompStats(total_call_sites=4)
        assert check_call_count_mismatch(asm, dec) is None

    def test_issue_when_large_diff(self):
        asm = AsmStats(call_count=10)
        dec = DecompStats(total_call_sites=3)
        issue = check_call_count_mismatch(asm, dec)
        assert issue is not None
        assert issue.category == "call_count_mismatch"

    def test_no_issue_both_zero(self):
        asm = AsmStats(call_count=0)
        dec = DecompStats(total_call_sites=0)
        assert check_call_count_mismatch(asm, dec) is None


class TestCheckBranchCountMismatch:
    def test_no_issue_close(self):
        asm = AsmStats(branch_count=5)
        dec = DecompStats(if_count=4, goto_count=0, while_count=0, for_count=0,
                          short_circuit_ops=0, ternary_ops=0, case_count=0)
        assert check_branch_count_mismatch(asm, dec) is None

    def test_issue_large_diff(self):
        asm = AsmStats(branch_count=20, signed_branch_count=5,
                       unsigned_branch_count=5, neutral_branch_count=10)
        dec = DecompStats(if_count=3, goto_count=0, while_count=0, for_count=0,
                          short_circuit_ops=0, ternary_ops=0, case_count=0)
        issue = check_branch_count_mismatch(asm, dec)
        assert issue is not None
        assert issue.category == "branch_count_mismatch"

    def test_critical_severity(self):
        asm = AsmStats(branch_count=30, signed_branch_count=10,
                       unsigned_branch_count=10, neutral_branch_count=10)
        dec = DecompStats(if_count=2, goto_count=0, while_count=0, for_count=0,
                          short_circuit_ops=0, ternary_ops=0, case_count=0)
        issue = check_branch_count_mismatch(asm, dec)
        assert issue is not None
        assert issue.severity == Severity.CRITICAL


class TestCheckNullCheckMismatch:
    def test_no_issue_when_balanced(self):
        asm = AsmStats(null_check_patterns=3)
        dec = DecompStats(if_count=3, short_circuit_ops=0, ternary_ops=0)
        assert check_null_check_mismatch(asm, dec) is None

    def test_issue_excess_null_checks(self):
        asm = AsmStats(null_check_patterns=10)
        dec = DecompStats(if_count=2, short_circuit_ops=0, ternary_ops=0)
        issue = check_null_check_mismatch(asm, dec)
        assert issue is not None
        assert issue.severity == Severity.CRITICAL

    def test_no_null_checks(self):
        asm = AsmStats(null_check_patterns=0)
        dec = DecompStats(if_count=5)
        assert check_null_check_mismatch(asm, dec) is None


class TestCheckSignednessMismatch:
    def test_no_issue_no_branches(self):
        asm = AsmStats(unsigned_branch_count=0, signed_branch_count=0)
        dec = DecompStats(unsigned_casts=0)
        assert check_signedness_mismatch(asm, dec) is None

    def test_issue_unsigned_no_casts(self):
        asm = AsmStats(unsigned_branch_count=5, signed_branch_count=1)
        dec = DecompStats(unsigned_casts=0, signed_comparisons=3)
        issue = check_signedness_mismatch(asm, dec)
        assert issue is not None
        assert issue.category == "wrong_branch_signedness"

    def test_no_issue_casts_present(self):
        asm = AsmStats(unsigned_branch_count=3, signed_branch_count=0)
        dec = DecompStats(unsigned_casts=2)
        assert check_signedness_mismatch(asm, dec) is None


class TestCheckAccessSizeMismatch:
    def test_no_issue_balanced(self):
        asm = AsmStats(dword_accesses=5, qword_accesses=2, byte_accesses=1)
        dec = DecompStats(dword_casts=5, qword_casts=2, byte_casts=1)
        assert check_access_size_mismatch(asm, dec) is None

    def test_issue_dword_vs_qword(self):
        asm = AsmStats(dword_accesses=10, qword_accesses=1)
        dec = DecompStats(dword_casts=2, qword_casts=8)
        issue = check_access_size_mismatch(asm, dec)
        assert issue is not None
        assert issue.category == "wrong_access_size"

    def test_issue_missing_byte_casts(self):
        asm = AsmStats(byte_accesses=5, dword_accesses=0, qword_accesses=0)
        dec = DecompStats(byte_casts=0, dword_casts=0, qword_casts=0)
        issue = check_access_size_mismatch(asm, dec)
        assert issue is not None


class TestCheckDecompilerArtifacts:
    def test_no_artifacts(self):
        stats = DecompStats()
        assert check_decompiler_artifacts(stats) == []

    def test_do_while_0(self):
        stats = DecompStats(do_while_0_count=2)
        issues = check_decompiler_artifacts(stats)
        assert len(issues) == 1
        assert issues[0].category == "decompiler_artifact"

    def test_excessive_lobyte(self):
        stats = DecompStats(lobyte_count=5)
        issues = check_decompiler_artifacts(stats)
        assert len(issues) == 1

    def test_lobyte_under_threshold(self):
        stats = DecompStats(lobyte_count=2)
        issues = check_decompiler_artifacts(stats)
        assert len(issues) == 0


class TestCheckReturnTypeMismatch:
    def test_no_mangled_name(self):
        assert check_return_type_mismatch(None, "int", None, None) is None

    def test_matching_types(self):
        assert check_return_type_mismatch("?Func@@YAHXZ", "int", None, None) is None

    def test_void_vs_int(self):
        issue = check_return_type_mismatch("?Func@@YAXXZ", "int", "int Func()", None)
        assert issue is not None
        assert issue.severity == Severity.HIGH

    def test_int_width_difference_is_low(self):
        # __int64 vs int -> both integer types -> LOW
        issue = check_return_type_mismatch("?Func@@YA_JXZ", "int", "int Func()", None)
        if issue:
            assert issue.severity == Severity.LOW


# ===================================================================
# run_heuristic_checks integration
# ===================================================================

class TestRunHeuristicChecks:
    def test_clean_function(self):
        asm = AsmStats(call_count=3, branch_count=2, null_check_patterns=1,
                       ret_count=1)
        dec = DecompStats(total_call_sites=3, if_count=2,
                          short_circuit_ops=0, ternary_ops=0,
                          goto_count=0, while_count=0, for_count=0, case_count=0)
        issues = run_heuristic_checks(asm, dec)
        assert len(issues) == 0

    def test_problematic_function(self):
        asm = AsmStats(call_count=15, branch_count=20, null_check_patterns=10,
                       unsigned_branch_count=5, signed_branch_count=5,
                       neutral_branch_count=10, dword_accesses=10, qword_accesses=1)
        dec = DecompStats(total_call_sites=3, call_count=2, if_count=2,
                          goto_count=0, while_count=0, for_count=0,
                          short_circuit_ops=0, ternary_ops=0, case_count=0,
                          unsigned_casts=0, signed_comparisons=3,
                          dword_casts=1, qword_casts=8,
                          do_while_0_count=1)
        issues = run_heuristic_checks(asm, dec)
        assert len(issues) > 0
        # Should be sorted by severity (highest first)
        severities = [i.severity for i in issues]
        assert severities == sorted(severities, reverse=True)
