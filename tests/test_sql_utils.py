"""Tests for helpers.sql_utils -- SQL LIKE escaping utilities."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from helpers.sql_utils import escape_like, LIKE_ESCAPE


class TestEscapeLike:
    def test_plain_string_unchanged(self):
        assert escape_like("hello") == "hello"

    def test_escapes_percent(self):
        assert escape_like("100%") == r"100\%"

    def test_escapes_underscore(self):
        assert escape_like("a_b") == r"a\_b"

    def test_escapes_backslash(self):
        assert escape_like(r"path\to") == r"path\\to"

    def test_escapes_all_metacharacters(self):
        result = escape_like(r"a\b%c_d")
        assert result == r"a\\b\%c\_d"

    def test_empty_string(self):
        assert escape_like("") == ""

    def test_multiple_percent(self):
        assert escape_like("%%") == r"\%\%"

    def test_multiple_underscore(self):
        assert escape_like("__init__") == r"\_\_init\_\_"

    def test_backslash_before_percent(self):
        result = escape_like(r"\%")
        assert result == r"\\\%"

    def test_like_escape_constant(self):
        assert "ESCAPE" in LIKE_ESCAPE
        assert "'" in LIKE_ESCAPE
