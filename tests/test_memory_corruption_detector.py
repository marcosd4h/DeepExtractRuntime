"""Tests for the memory-corruption-detector skill -- registry and structural validation."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

WORKSPACE = Path(__file__).resolve().parents[1]
SKILL_DIR = WORKSPACE / "skills" / "memory-corruption-detector"
SCRIPTS_DIR = SKILL_DIR / "scripts"
SKILLS_REGISTRY = WORKSPACE / "skills" / "registry.json"
COMMANDS_REGISTRY = WORKSPACE / "commands" / "registry.json"


# ---------------------------------------------------------------------------
# Registry and structure tests
# ---------------------------------------------------------------------------

class TestRegistryConsistency:
    """Verify the skill is properly registered and structurally sound."""

    def test_skill_directory_exists(self):
        assert SKILL_DIR.is_dir(), f"Skill directory missing: {SKILL_DIR}"

    def test_skill_md_exists(self):
        assert (SKILL_DIR / "SKILL.md").is_file()

    def test_scripts_directory_exists(self):
        assert SCRIPTS_DIR.is_dir()

    def test_common_module_exists(self):
        assert (SCRIPTS_DIR / "_common.py").is_file()

    def test_all_scanner_scripts_exist(self):
        expected = [
            "scan_buffer_overflows.py",
            "scan_integer_issues.py",
            "scan_use_after_free.py",
            "scan_format_strings.py",
            "verify_findings.py",
        ]
        for script in expected:
            assert (SCRIPTS_DIR / script).is_file(), f"Missing script: {script}"

    def test_skill_in_registry(self):
        with open(SKILLS_REGISTRY) as f:
            registry = json.load(f)
        skills = registry.get("skills", {})
        assert "memory-corruption-detector" in skills

    def test_registry_entry_fields(self):
        with open(SKILLS_REGISTRY) as f:
            registry = json.load(f)
        entry = registry["skills"]["memory-corruption-detector"]
        assert entry["type"] == "security"
        assert entry["cacheable"] is True
        assert "memcorrupt_buffer" in entry.get("cache_keys", [])
        assert "decompiled-code-extractor" in entry.get("depends_on", [])
        assert entry["json_output"] is True

    def test_registry_scripts_exist_on_disk(self):
        with open(SKILLS_REGISTRY) as f:
            registry = json.load(f)
        entry = registry["skills"]["memory-corruption-detector"]
        for script_info in entry.get("entry_scripts", []):
            script_name = script_info["script"]
            assert (SCRIPTS_DIR / script_name).is_file(), f"Registered script missing: {script_name}"

    def test_command_in_registry(self):
        with open(COMMANDS_REGISTRY) as f:
            registry = json.load(f)
        commands = registry.get("commands", {})
        assert "memory-scan" in commands

    def test_command_references_skill(self):
        with open(COMMANDS_REGISTRY) as f:
            registry = json.load(f)
        cmd = registry["commands"]["memory-scan"]
        assert "memory-corruption-detector" in cmd.get("skills_used", [])

    def test_command_md_exists(self):
        cmd_file = WORKSPACE / "commands" / "memory-scan.md"
        assert cmd_file.is_file()


# ---------------------------------------------------------------------------
# SKILL.md frontmatter tests
# ---------------------------------------------------------------------------

class TestSkillFrontmatter:
    """Verify SKILL.md has valid frontmatter for discovery."""

    def test_frontmatter_present(self):
        content = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
        assert content.startswith("---"), "SKILL.md must start with ---"
        parts = content.split("---", 2)
        assert len(parts) >= 3, "SKILL.md must have --- delimited frontmatter"

    def test_name_matches_directory(self):
        content = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
        assert "name: memory-corruption-detector" in content

    def test_description_has_triggers(self):
        content = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
        triggers = ["buffer overflow", "memory corruption", "integer overflow",
                     "use-after-free", "format string"]
        for trigger in triggers:
            assert trigger.lower() in content.lower(), f"Missing trigger phrase: {trigger}"


# ---------------------------------------------------------------------------
# _common.py import tests
# ---------------------------------------------------------------------------

class TestCommonImports:
    """Verify _common.py provides expected symbols."""

    def test_common_has_expected_symbols(self):
        """Verify _common.py defines expected symbols by source inspection."""
        source = (SCRIPTS_DIR / "_common.py").read_text(encoding="utf-8")
        for symbol in [
            "MemCorruptionFinding",
            "ALLOC_APIS",
            "FREE_APIS",
            "COPY_APIS",
            "FORMAT_APIS",
            "compute_memcorrupt_score",
            "load_all_functions_slim",
            "SAFE_BOUNDED_COPY_APIS",
            "RE_SIZE_CAP_MIN",
            "_is_size_capped",
            "is_safe_bounded_copy_api",
        ]:
            assert symbol in source, f"_common.py missing symbol: {symbol}"


# ---------------------------------------------------------------------------
# Import detection functions (add scripts dir to path)
# ---------------------------------------------------------------------------

sys.path.insert(0, str(SCRIPTS_DIR))

# Ensure we import the memory-corruption-detector _common, not another
# skill's _common that might be cached from a prior test collection.
if "_common" in sys.modules:
    _prev_common = sys.modules.pop("_common")
else:
    _prev_common = None

import importlib  # noqa: E402
import _common  # noqa: E402
importlib.reload(_common)

from _common import (  # noqa: E402
    SAFE_BOUNDED_COPY_APIS,
    RE_SIZE_CAP_MIN,
    _is_size_capped,
    is_safe_bounded_copy_api,
)
from scan_buffer_overflows import detect_buffer_overflows  # noqa: E402
from scan_integer_issues import _check_asm_mul_before_alloc, RE_CMP_OVERFLOW, RE_ABOVE_JUMP  # noqa: E402
from scan_use_after_free import detect_use_after_free, _is_null_after_free  # noqa: E402


def _make_func(code: str, asm: str = "", sig: str = "__int64 __fastcall test_func(__int64 a1, __int64 a2)",
               name: str = "test_func", fid: int = 1) -> dict:
    """Build a minimal function record for scanner testing."""
    return {
        "function_name": name,
        "function_id": fid,
        "decompiled_code": code,
        "assembly_code": asm,
        "function_signature": sig,
        "outbound_xrefs": [],
    }


class TestSafeBoundedCopyAPIs:
    """Verify SAFE_BOUNDED_COPY_APIS and is_safe_bounded_copy_api()."""

    def test_stringcchcopy_is_safe(self):
        assert is_safe_bounded_copy_api("StringCchCopyW")

    def test_stringcbprintf_is_safe(self):
        assert is_safe_bounded_copy_api("StringCbPrintfA")

    def test_memcpy_is_not_safe(self):
        assert not is_safe_bounded_copy_api("memcpy")

    def test_import_prefix_stripped(self):
        assert is_safe_bounded_copy_api("__imp_StringCchCopy")

    def test_safe_api_suppresses_finding(self):
        code = (
            "__int64 __fastcall test_func(__int64 a1, __int64 a2) {\n"
            "  char buf[260];\n"
            "  StringCchCopyW(buf, 260, a1);\n"
            "  return 0;\n"
            "}\n"
        )
        func = _make_func(code)
        findings = detect_buffer_overflows(func)
        assert len(findings) == 0, "StringCchCopyW should be suppressed as a safe bounded copy API"


class TestSizeCapRecognition:
    """Verify RE_SIZE_CAP_MIN and _is_size_capped()."""

    def test_regex_matches_min_sizeof(self):
        assert RE_SIZE_CAP_MIN.search("min(cbData, sizeof(buf))")

    def test_regex_matches_min_constant(self):
        assert RE_SIZE_CAP_MIN.search("min(a2, 1024)")

    def test_regex_no_match_plain_var(self):
        assert not RE_SIZE_CAP_MIN.search("a2")

    def test_is_size_capped_direct_min(self):
        code = "v1 = min(a2, sizeof(buf));\nmemcpy(dst, src, v1);\n"
        assert _is_size_capped("min(a2, sizeof(buf))", code, 2)

    def test_is_size_capped_assigned_var(self):
        code = (
            "v10 = min(a2, 512);\n"
            "some_other_stuff();\n"
            "memcpy(dst, src, v10);\n"
        )
        assert _is_size_capped("v10", code, 3)

    def test_is_size_capped_not_capped(self):
        code = "v10 = a2;\nmemcpy(dst, src, v10);\n"
        assert not _is_size_capped("v10", code, 2)

    def test_size_capped_suppresses_finding(self):
        code = (
            "__int64 __fastcall test_func(__int64 a1, __int64 a2) {\n"
            "  char dst[256];\n"
            "  __int64 v3 = min(a2, sizeof(dst));\n"
            "  memcpy(dst, a1, v3);\n"
            "  return 0;\n"
            "}\n"
        )
        func = _make_func(code)
        findings = detect_buffer_overflows(func)
        assert len(findings) == 0, "Size-capped memcpy should not produce a finding"

    def test_uncapped_memcpy_still_detected(self):
        code = (
            "__int64 __fastcall test_func(__int64 a1, __int64 a2) {\n"
            "  char dst[256];\n"
            "  memcpy(dst, a1, a2);\n"
            "  return 0;\n"
            "}\n"
        )
        func = _make_func(code)
        findings = detect_buffer_overflows(func)
        assert len(findings) > 0, "Uncapped memcpy with tainted size should still be detected"


class TestComparisonOverflowPatterns:
    """Verify RE_CMP_OVERFLOW and RE_ABOVE_JUMP patterns."""

    def test_cmp_eax_hex_max(self):
        assert RE_CMP_OVERFLOW.search("cmp eax, 0xFFFFFFFF")

    def test_cmp_rax_uint_max(self):
        assert RE_CMP_OVERFLOW.search("cmp rax, UINT_MAX")

    def test_cmp_r8d_maxdword(self):
        assert RE_CMP_OVERFLOW.search("cmp r8d, MAXDWORD")

    def test_cmp_ecx_size_max(self):
        assert RE_CMP_OVERFLOW.search("cmp ecx, SIZE_MAX")

    def test_cmp_large_decimal(self):
        assert RE_CMP_OVERFLOW.search("cmp edx, 65535")

    def test_cmp_no_match_small_value(self):
        assert not RE_CMP_OVERFLOW.search("cmp eax, 42")

    def test_above_jump_ja(self):
        assert RE_ABOVE_JUMP.search("ja loc_140001234")

    def test_above_jump_jae(self):
        assert RE_ABOVE_JUMP.search("jae short loc_ABCD")

    def test_above_jump_jb(self):
        assert RE_ABOVE_JUMP.search("jb loc_1400055AA")

    def test_above_jump_jbe(self):
        assert RE_ABOVE_JUMP.search("jbe loc_1400055AA")

    def test_no_match_je(self):
        assert not RE_ABOVE_JUMP.search("je loc_140001234")


class TestAsmMulOverflowCheckSuppression:
    """Verify _check_asm_mul_before_alloc suppresses with cmp+ja patterns."""

    def test_mul_with_jo_suppressed(self):
        asm = (
            "imul eax, ecx\n"
            "jo overflow_handler\n"
            "call HeapAlloc\n"
        )
        hits = _check_asm_mul_before_alloc(asm)
        assert len(hits) == 0, "mul followed by jo should be suppressed"

    def test_mul_with_cmp_ja_suppressed(self):
        asm = (
            "imul eax, ecx\n"
            "cmp eax, 0xFFFFFFFF\n"
            "ja overflow_handler\n"
            "call HeapAlloc\n"
        )
        hits = _check_asm_mul_before_alloc(asm)
        assert len(hits) == 0, "mul followed by cmp+ja should be suppressed"

    def test_mul_with_cmp_jae_suppressed(self):
        asm = (
            "imul rax, rdx\n"
            "cmp rax, UINT_MAX\n"
            "jae error_path\n"
            "call malloc\n"
        )
        hits = _check_asm_mul_before_alloc(asm)
        assert len(hits) == 0, "mul followed by cmp+jae should be suppressed"

    def test_mul_without_check_detected(self):
        asm = (
            "imul eax, ecx\n"
            "mov edx, eax\n"
            "call HeapAlloc\n"
        )
        hits = _check_asm_mul_before_alloc(asm)
        assert len(hits) == 1, "mul without overflow check should be detected"

    def test_cmp_ja_with_gap_still_suppressed(self):
        asm = (
            "imul eax, ecx\n"
            "cmp eax, 0xFFFF\n"
            "nop\n"
            "ja overflow_handler\n"
            "call HeapAlloc\n"
        )
        hits = _check_asm_mul_before_alloc(asm)
        assert len(hits) == 0, "cmp+ja within 3-line lookahead should suppress"


class TestExtendedNullAfterFreeWindow:
    """Verify _is_null_after_free uses 50-line window and recognizes new patterns."""

    def test_null_at_line_6_detected(self):
        lines = ["free(v1);"] + ["nop();"] * 5 + ["v1 = NULL;"]
        assert _is_null_after_free(lines, 0, "v1"), \
            "Null at line 6 (within 50-line window) should be detected"

    def test_null_at_line_45_detected(self):
        lines = ["free(v1);"] + ["nop();"] * 44 + ["v1 = NULL;"]
        assert _is_null_after_free(lines, 0, "v1"), \
            "Null at line 45 (within 50-line window) should be detected"

    def test_null_beyond_50_not_detected(self):
        lines = ["free(v1);"] + ["nop();"] * 55 + ["v1 = NULL;"]
        assert not _is_null_after_free(lines, 0, "v1"), \
            "Null beyond 50-line window should not be detected"

    def test_struct_field_null_detected(self):
        lines = [
            "HeapFree(hHeap, 0, v1);",
            "some_cleanup();",
            "this->ptr = NULL;  // v1",
        ]
        assert _is_null_after_free(lines, 0, "v1"), \
            "Struct-field null assignment mentioning freed var should be detected"

    def test_struct_field_null_different_var_not_matched(self):
        lines = [
            "HeapFree(hHeap, 0, v1);",
            "this->ptr = NULL;  // v2",
        ]
        assert not _is_null_after_free(lines, 0, "v1"), \
            "Struct-field null not mentioning freed var should not match"

    def test_realloc_reassignment_detected(self):
        lines = [
            "free(v1);",
            "do_something();",
            "v1 = malloc(new_size);",
        ]
        assert _is_null_after_free(lines, 0, "v1"), \
            "Re-assignment via malloc should be detected as safe"

    def test_heapalloc_reassignment_detected(self):
        lines = [
            "HeapFree(hHeap, 0, v1);",
            "do_something();",
            "v1 = HeapAlloc(hHeap, 0, 256);",
        ]
        assert _is_null_after_free(lines, 0, "v1"), \
            "Re-assignment via HeapAlloc should be detected as safe"


class TestUAFWithExtendedWindow:
    """Integration tests: verify detect_use_after_free respects the extended window."""

    def test_null_far_after_free_suppresses_uaf(self):
        free_line = "  free(v1);"
        nop_lines = ["  nop();"] * 10
        null_line = "  v1 = 0;"
        use_line = "  memcpy(dst, v1, 100);"
        code_lines = [
            "__int64 __fastcall test_func(__int64 a1) {",
            free_line,
            *nop_lines,
            null_line,
            use_line,
            "  return 0;",
            "}",
        ]
        code = "\n".join(code_lines) + "\n"
        func = _make_func(code)
        findings = detect_use_after_free(func)
        uaf_findings = [f for f in findings if f.category == "use_after_free"]
        assert len(uaf_findings) == 0, \
            "UAF should be suppressed when null assignment is within extended window"

    def test_realloc_after_free_suppresses_uaf(self):
        code = (
            "__int64 __fastcall test_func(__int64 a1) {\n"
            "  __int64 v1 = a1;\n"
            "  free(v1);\n"
            "  v1 = malloc(256);\n"
            "  memcpy(dst, v1, 100);\n"
            "  return 0;\n"
            "}\n"
        )
        func = _make_func(code)
        findings = detect_use_after_free(func)
        uaf_findings = [f for f in findings if f.category == "use_after_free"]
        assert len(uaf_findings) == 0, \
            "UAF should be suppressed when variable is reallocated after free"
