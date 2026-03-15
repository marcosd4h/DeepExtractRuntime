"""Tests for decompiled code parsing helpers.

Target: helpers/decompiled_parser.py
"""

from __future__ import annotations

import pytest

from helpers.decompiled_parser import (
    extract_balanced_parens,
    extract_function_calls,
    split_arguments,
)


# ===================================================================
# extract_balanced_parens
# ===================================================================


class TestExtractBalancedParens:
    def test_simple_parens(self):
        assert extract_balanced_parens("(a + b)", 0) == "a + b"

    def test_nested_parens(self):
        assert extract_balanced_parens("(a + (b * c))", 0) == "a + (b * c)"

    def test_start_offset(self):
        text = "foo(x, y)"
        # Position 3 is the '('
        assert extract_balanced_parens(text, 3) == "x, y"

    def test_no_paren_at_start(self):
        assert extract_balanced_parens("no paren", 0) is None

    def test_empty_parens(self):
        assert extract_balanced_parens("()", 0) == ""

    def test_unbalanced_returns_none(self):
        # No closing paren - returns None (depth never reaches 0)
        assert extract_balanced_parens("(unclosed", 0) is None


# ===================================================================
# split_arguments
# ===================================================================


class TestSplitArguments:
    def test_simple_args(self):
        assert split_arguments("a, b, c") == ["a", "b", "c"]

    def test_nested_parens(self):
        assert split_arguments("foo(a,b), bar(x)") == ["foo(a,b)", "bar(x)"]

    def test_nested_brackets(self):
        assert split_arguments("arr[0], arr[1]") == ["arr[0]", "arr[1]"]

    def test_single_arg(self):
        assert split_arguments("x") == ["x"]

    def test_empty_string(self):
        assert split_arguments("") == []

    def test_whitespace_trimmed(self):
        assert split_arguments("  a  ,  b  ") == ["a", "b"]

    def test_complex_nested(self):
        args = split_arguments("func(a, b(c,d)), x")
        assert len(args) == 2
        assert args[0] == "func(a, b(c,d))"
        assert args[1] == "x"


# ===================================================================
# extract_function_calls
# ===================================================================


class TestExtractFunctionCalls:
    def test_simple_call(self):
        code = "  foo(a, b);"
        calls = extract_function_calls(code)
        assert len(calls) == 1
        assert calls[0]["function_name"] == "foo"
        assert calls[0]["arguments"] == ["a", "b"]
        assert calls[0]["line_number"] == 1

    def test_skips_keywords(self):
        code = "  if (x) return;"
        calls = extract_function_calls(code)
        assert len(calls) == 0

    def test_result_var_assignment(self):
        code = "  result = getValue();"
        calls = extract_function_calls(code)
        assert len(calls) == 1
        assert calls[0]["result_var"] == "result"
        assert calls[0]["function_name"] == "getValue"

    def test_multiple_calls(self):
        code = """
  foo(1);
  bar(2, 3);
  baz();
"""
        calls = extract_function_calls(code)
        assert len(calls) == 3
        names = [c["function_name"] for c in calls]
        assert names == ["foo", "bar", "baz"]

    def test_skips_sizeof(self):
        code = "  size = sizeof(int);"
        calls = extract_function_calls(code)
        assert len(calls) == 0

    def test_nested_call_in_arg(self):
        code = "  outer(inner(x));"
        calls = extract_function_calls(code)
        # Extracts both outer and inner (regex finds all call sites on the line)
        assert len(calls) >= 1
        outer = next(c for c in calls if c["function_name"] == "outer")
        assert outer["arguments"] == ["inner(x)"]


