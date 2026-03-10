"""Tests for helpers.def_use_chain -- def-use chain analysis for IDA decompiled code."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from helpers.def_use_chain import (
    SANITIZER_APIS,
    TaintResult,
    VarDef,
    VarUse,
    analyze_taint,
    parse_def_use,
    propagate_taint,
    _extract_field_vars,
    _parse_blocks,
    _var_covers,
)


# ---------------------------------------------------------------------------
# Parse tests
# ---------------------------------------------------------------------------

class TestParsing:
    """Test def-use parsing of IDA decompiled patterns."""

    def test_simple_assignment(self):
        code = "  v5 = a1;\n"
        defs, uses = parse_def_use(code)
        assert len(defs) == 1
        assert defs[0].var == "v5"
        assert "a1" in defs[0].rhs_vars

    def test_expression_assignment(self):
        code = "  v5 = a1 + 16;\n"
        defs, uses = parse_def_use(code)
        assert len(defs) == 1
        assert "a1" in defs[0].rhs_vars

    def test_function_call_assignment(self):
        code = "  v5 = CreateFileW(a1, 0, 0);\n"
        defs, uses = parse_def_use(code)
        assert any(d.var == "v5" for d in defs)
        call_uses = [u for u in uses if u.context == "call_arg"]
        assert any(u.var == "a1" and u.target_func == "CreateFileW" for u in call_uses)

    def test_struct_field_read(self):
        code = "  v6 = *(_QWORD *)(a1 + 8);\n"
        defs, uses = parse_def_use(code)
        assert any(d.var == "v6" and "a1" in d.rhs_vars for d in defs)

    def test_arrow_member_read(self):
        code = "  v3 = a1->dwSize;\n"
        defs, uses = parse_def_use(code)
        assert any(d.var == "v3" and "a1" in d.rhs_vars for d in defs)

    def test_condition_use(self):
        code = "  if ( a1 > 5 )\n"
        defs, uses = parse_def_use(code)
        cond_uses = [u for u in uses if u.context == "condition"]
        assert any(u.var == "a1" for u in cond_uses)

    def test_return_use(self):
        code = "  return v5;\n"
        defs, uses = parse_def_use(code)
        ret_uses = [u for u in uses if u.context == "return"]
        assert any(u.var == "v5" for u in ret_uses)

    def test_array_index_use(self):
        code = "  v5 = buffer[a2];\n"
        defs, uses = parse_def_use(code)
        idx_uses = [u for u in uses if u.context == "array_index"]
        assert any(u.var == "a2" for u in idx_uses)

    def test_struct_write_use(self):
        code = "  *(_DWORD *)(v5 + 4) = a1;\n"
        defs, uses = parse_def_use(code)
        sw_uses = [u for u in uses if u.context == "struct_write"]
        assert any(u.var == "v5" for u in sw_uses)

    def test_lodword_assignment(self):
        code = "  LODWORD(v5) = a1;\n"
        defs, uses = parse_def_use(code)
        assert any(d.var == "v5" for d in defs)

    def test_multiple_vars_in_expression(self):
        code = "  v5 = a1 + a2 * v3;\n"
        defs, uses = parse_def_use(code)
        assert len(defs) >= 1
        rhs = defs[0].rhs_vars
        assert "a1" in rhs
        assert "a2" in rhs
        assert "v3" in rhs


# ---------------------------------------------------------------------------
# Taint propagation tests
# ---------------------------------------------------------------------------

class TestTaintPropagation:
    """Test fixed-point taint propagation through def-use chains."""

    def test_direct_alias(self):
        code = "v5 = a1;\nmemcpy(v5, src, size);\n"
        result = analyze_taint(code, {"a1"})
        assert "v5" in result.tainted_vars
        assert "a1" in result.tainted_vars

    def test_chain_propagation(self):
        code = "v5 = a1;\nv6 = v5 + 4;\nfunc(v6);\n"
        result = analyze_taint(code, {"a1"})
        assert "v5" in result.tainted_vars
        assert "v6" in result.tainted_vars

    def test_no_propagation_from_untainted(self):
        code = "v5 = 42;\nv6 = v5;\n"
        result = analyze_taint(code, {"a1"})
        assert "v5" not in result.tainted_vars
        assert "v6" not in result.tainted_vars

    def test_struct_read_propagates(self):
        code = "v5 = *(_QWORD *)(a1 + 8);\nfunc(v5);\n"
        result = analyze_taint(code, {"a1"})
        assert "v5" in result.tainted_vars

    def test_tainted_call_detection(self):
        code = "v5 = a1;\nmemcpy(buf, v5, size);\n"
        result = analyze_taint(code, {"a1"})
        assert len(result.tainted_calls) > 0
        assert any(c["target_func"] == "memcpy" for c in result.tainted_calls)

    def test_tainted_condition_detection(self):
        code = "v5 = a1;\nif ( v5 > 0 )\n  func();\n"
        result = analyze_taint(code, {"a1"})
        assert len(result.tainted_conditions) > 0

    def test_tainted_return_detection(self):
        code = "v5 = a1;\nreturn v5;\n"
        result = analyze_taint(code, {"a1"})
        assert len(result.tainted_returns) > 0

    def test_empty_code(self):
        result = analyze_taint("", {"a1"})
        assert len(result.tainted_vars) == 0

    def test_empty_tainted_set(self):
        result = analyze_taint("v5 = a1;\n", set())
        assert len(result.tainted_vars) == 0

    def test_multi_param_taint(self):
        code = "v5 = a1;\nv6 = a2;\nfunc(v5, v6);\n"
        result = analyze_taint(code, {"a1", "a2"})
        assert "v5" in result.tainted_vars
        assert "v6" in result.tainted_vars

    def test_realistic_ida_code(self):
        code = """__int64 __fastcall sub_180001000(__int64 a1, unsigned int a2)
{
  void *v3;
  unsigned int v4;

  v3 = *(void **)(a1 + 8);
  v4 = a2;
  if ( !a1 )
    return 0xC0000005;
  memcpy(v3, *(const void **)(a1 + 16), v4);
  return 0;
}
"""
        result = analyze_taint(code, {"a1", "a2"})
        assert "v3" in result.tainted_vars
        assert "v4" in result.tainted_vars
        assert any(
            c["target_func"] == "memcpy"
            for c in result.tainted_calls
        )


# ---------------------------------------------------------------------------
# Edge case tests
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Test edge cases and robustness."""

    def test_comment_lines_ignored(self):
        code = "// v5 = a1;\nv6 = 42;\n"
        defs, uses = parse_def_use(code)
        assert not any(d.var == "v5" for d in defs)

    def test_no_infinite_loop(self):
        code = "v5 = v6;\nv6 = v5;\n"
        result = analyze_taint(code, {"v5"})
        assert "v6" in result.tainted_vars

    def test_max_iterations_respected(self):
        code = "\n".join(f"v{i+1} = v{i};" for i in range(100))
        defs, uses = parse_def_use(code)
        result = propagate_taint(defs, uses, {"v0"}, max_iterations=5)
        assert len(result.tainted_vars) <= 10


# ---------------------------------------------------------------------------
# Compound assignment tests
# ---------------------------------------------------------------------------

class TestCompoundAssignments:
    """Test that compound assignments (+=, -=, |=, etc.) propagate taint."""

    def test_plus_equals(self):
        code = "v5 += a1;\n"
        defs, uses = parse_def_use(code)
        assert any(d.var == "v5" and "a1" in d.rhs_vars for d in defs)

    def test_or_equals(self):
        code = "v5 |= a1;\n"
        defs, uses = parse_def_use(code)
        assert any(d.var == "v5" and "a1" in d.rhs_vars for d in defs)

    def test_minus_equals(self):
        code = "v5 -= a2;\n"
        defs, uses = parse_def_use(code)
        assert any(d.var == "v5" and "a2" in d.rhs_vars for d in defs)

    def test_shift_left_equals(self):
        code = "v5 <<= a1;\n"
        defs, uses = parse_def_use(code)
        assert any(d.var == "v5" and "a1" in d.rhs_vars for d in defs)

    def test_compound_propagates_taint(self):
        code = "v5 = 0;\nv5 += a1;\nfunc(v5);\n"
        result = analyze_taint(code, {"a1"})
        assert "v5" in result.tainted_vars

    def test_compound_self_reference(self):
        """v5 += a1 means v5 = v5 + a1, so v5 is in its own RHS."""
        code = "v5 += a1;\n"
        defs, uses = parse_def_use(code)
        d = next(d for d in defs if d.var == "v5")
        assert "v5" in d.rhs_vars
        assert "a1" in d.rhs_vars

    def test_and_equals(self):
        code = "v5 &= a1;\n"
        defs, uses = parse_def_use(code)
        assert any(d.var == "v5" for d in defs)

    def test_compound_not_confused_with_comparison(self):
        """v5 == a1 should NOT create a definition."""
        code = "if ( v5 == a1 )\n"
        defs, uses = parse_def_use(code)
        assert not any(d.var == "v5" for d in defs)


class TestScopeAwareTaint:
    """Defs inside early-exit blocks should not taint the continuation."""

    def test_early_exit_block_does_not_taint_continuation(self):
        code = """\
{
  if ( a1 == 0 )
  {
    v5 = a1;
    return 0;
  }
  memcpy(buf, v5, 10);
}
"""
        result = analyze_taint(code, {"a1"}, scope_aware=True)
        assert "v5" not in result.tainted_vars

    def test_non_exit_block_does_taint_continuation(self):
        code = """\
{
  if ( a1 > 0 )
  {
    v5 = a1;
  }
  memcpy(buf, v5, 10);
}
"""
        result = analyze_taint(code, {"a1"}, scope_aware=True)
        assert "v5" in result.tainted_vars

    def test_scope_aware_disabled_preserves_old_behavior(self):
        code = """\
{
  if ( a1 == 0 )
  {
    v5 = a1;
    return 0;
  }
  memcpy(buf, v5, 10);
}
"""
        result = analyze_taint(code, {"a1"}, scope_aware=False)
        assert "v5" in result.tainted_vars

    def test_else_block_with_return_does_not_taint(self):
        code = """\
{
  if ( a1 )
  {
    v5 = 42;
  }
  else
  {
    v5 = a1;
    return -1;
  }
  func(v5);
}
"""
        result = analyze_taint(code, {"a1"}, scope_aware=True)
        assert "v5" not in result.tainted_vars

    def test_block_parsing_returns_root(self):
        lines = ["int x = 0;", "return x;"]
        blocks = _parse_blocks(lines)
        assert len(blocks) >= 1
        assert blocks[0].block_type == "root"


class TestFieldSensitiveTaint:
    """Field-qualified variable tracking."""

    def test_var_covers_base_covers_field(self):
        tainted = {"a1"}
        assert _var_covers(tainted, ("a1", "buffer"))

    def test_var_covers_field_does_not_cover_other_field(self):
        tainted = {("a1", "length")}
        assert not _var_covers(tainted, ("a1", "buffer"))

    def test_var_covers_exact_field_match(self):
        tainted = {("a1", "buffer")}
        assert _var_covers(tainted, ("a1", "buffer"))

    def test_var_covers_plain_match(self):
        tainted = {"v5"}
        assert _var_covers(tainted, "v5")

    def test_extract_field_vars_arrow(self):
        fields = _extract_field_vars("a1->buffer + a1->length")
        field_tuples = [f for f in fields if isinstance(f, tuple)]
        assert ("a1", "buffer") in field_tuples
        assert ("a1", "length") in field_tuples

    def test_extract_field_vars_deref_offset(self):
        fields = _extract_field_vars("*(_QWORD *)(a1 + 0x10)")
        field_tuples = [f for f in fields if isinstance(f, tuple)]
        assert ("a1", "offset_0x10") in field_tuples

    def test_extract_field_vars_plain(self):
        fields = _extract_field_vars("v5 + v6")
        assert "v5" in fields
        assert "v6" in fields


class TestSanitizerKill:
    """Sanitizer API calls kill taint on LHS."""

    def test_sanitizer_api_kills_taint(self):
        code = "v5 = PathCchCanonicalize(a1, buf, size);\nfunc(v5);\n"
        result = analyze_taint(code, {"a1"}, sanitizer_kill=True)
        assert "v5" not in result.tainted_vars

    def test_non_sanitizer_propagates(self):
        code = "v5 = SomeFunc(a1);\nfunc(v5);\n"
        result = analyze_taint(code, {"a1"}, sanitizer_kill=True)
        assert "v5" in result.tainted_vars

    def test_sanitizer_kill_disabled_propagates(self):
        code = "v5 = PathCchCanonicalize(a1, buf, size);\nfunc(v5);\n"
        result = analyze_taint(code, {"a1"}, sanitizer_kill=False)
        assert "v5" in result.tainted_vars

    def test_rhs_call_detected_in_parse(self):
        code = "v5 = GetFullPathNameW(a1, 260, buf, 0);\n"
        defs, _ = parse_def_use(code)
        d = next(d for d in defs if d.var == "v5")
        assert d.rhs_call == "GetFullPathNameW"

    def test_non_call_rhs_has_no_rhs_call(self):
        code = "v5 = a1 + 16;\n"
        defs, _ = parse_def_use(code)
        d = next(d for d in defs if d.var == "v5")
        assert d.rhs_call is None

    def test_sanitizer_list_not_empty(self):
        assert len(SANITIZER_APIS) > 10
