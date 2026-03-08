"""Tests for validate_function_id input validation helper.

Target: helpers/validation.py :: validate_function_id
"""

from __future__ import annotations

import pytest

from helpers.errors import ScriptError
from helpers.validation import validate_function_id


class TestValidatePositiveInts:
    """Valid positive integers should pass and return int."""

    def test_positive_int(self):
        assert validate_function_id(1) == 1

    def test_large_positive_int(self):
        assert validate_function_id(99999) == 99999

    def test_positive_int_min(self):
        assert validate_function_id(1) == 1


class TestValidateStringConversion:
    """String values that represent valid positive integers should convert."""

    def test_string_positive(self):
        assert validate_function_id("123") == 123

    def test_string_with_whitespace(self):
        assert validate_function_id(" 42 ") == 42

    def test_string_large(self):
        assert validate_function_id("100000") == 100000


class TestValidateFloatConversion:
    """Float values that are integer-valued should convert."""

    def test_float_integer_valued(self):
        assert validate_function_id(5.0) == 5

    def test_float_large(self):
        assert validate_function_id(42.0) == 42

    def test_float_fractional_rejected(self):
        with pytest.raises(ScriptError):
            validate_function_id(5.7)


class TestRejectZero:
    """Zero should be rejected with ScriptError."""

    def test_zero_int(self):
        with pytest.raises(ScriptError):
            validate_function_id(0)

    def test_zero_string(self):
        with pytest.raises(ScriptError):
            validate_function_id("0")


class TestRejectNegative:
    """Negative values should be rejected with ScriptError."""

    def test_negative_int(self):
        with pytest.raises(ScriptError):
            validate_function_id(-1)

    def test_negative_large(self):
        with pytest.raises(ScriptError):
            validate_function_id(-999)

    def test_negative_string(self):
        with pytest.raises(ScriptError):
            validate_function_id("-5")


class TestRejectNonNumeric:
    """Non-numeric values should be rejected with ScriptError."""

    def test_non_numeric_string(self):
        with pytest.raises(ScriptError):
            validate_function_id("abc")

    def test_empty_string(self):
        with pytest.raises(ScriptError):
            validate_function_id("")

    def test_none(self):
        with pytest.raises(ScriptError):
            validate_function_id(None)

    def test_mixed_string(self):
        with pytest.raises(ScriptError):
            validate_function_id("12abc")


class TestArgNameInError:
    """The arg_name parameter should be used in error messages."""

    def test_custom_arg_name(self):
        with pytest.raises(ScriptError, match="--function-id"):
            validate_function_id(-1, "--function-id")

    def test_default_arg_name(self):
        with pytest.raises(ScriptError, match="--id"):
            validate_function_id(-1)
