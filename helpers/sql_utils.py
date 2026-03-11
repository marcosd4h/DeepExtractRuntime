"""Shared SQL utilities for DeepExtract helpers."""

from __future__ import annotations


def escape_like(value: str) -> str:
    """Escape SQL LIKE meta-characters so *value* is matched literally.

    Escapes ``\\``, ``%``, and ``_`` with a backslash.  Callers must
    append ``ESCAPE '\\'`` to the LIKE clause.
    """
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


LIKE_ESCAPE = r" ESCAPE '\'"
