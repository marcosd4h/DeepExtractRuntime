"""Standardized JSON output for skill scripts.

Enforces the JSON output convention: every JSON document written to
stdout must be a dict with a ``"status"`` key (``"ok"`` or ``"error"``).

Usage::

    from helpers.json_output import emit_json, emit_json_list

    # Wrap a dict result
    emit_json({"module": "appinfo.dll", "functions": [...]})
    # -> {"status": "ok", "module": "appinfo.dll", "functions": [...]}

    # Wrap a list result under a named key
    emit_json_list("entrypoints", [...])
    # -> {"status": "ok", "entrypoints": [...]}

    # Override default serialization options
    emit_json(data, default=str, ensure_ascii=True)
"""

from __future__ import annotations

import json
import sys
from typing import Any


def should_force_json(args) -> bool:
    """Determine whether a script should emit JSON output.

    Returns ``True`` when either ``--json`` was passed on the command
    line or the script was invoked inside a workspace handoff pipeline
    (``--workspace-dir`` is set).

    Typical usage at the top of a script's ``main()``::

        force_json = should_force_json(args)
    """
    if getattr(args, "json", False):
        return True
    if getattr(args, "workspace_dir", None):
        return True
    return False


def emit_json(
    data: dict[str, Any],
    *,
    status: str = "ok",
    default: Any = None,
    ensure_ascii: bool = False,
) -> None:
    """Write a dict to stdout wrapped with ``"status"`` key.

    If *data* already contains a ``"status"`` key it is preserved as-is
    (the wrapper does not overwrite it).

    Parameters
    ----------
    data:
        The dict payload.  Must be a dict -- use :func:`emit_json_list`
        for list payloads.
    status:
        Value for the ``"status"`` key (default ``"ok"``).
    default:
        ``json.dumps`` *default* parameter for non-serializable types.
    ensure_ascii:
        ``json.dumps`` *ensure_ascii* parameter.
    """
    if not isinstance(data, dict):
        raise TypeError(
            f"emit_json expects a dict, got {type(data).__name__}. "
            "Use emit_json_list() for list payloads."
        )
    output = {"status": status}
    output.update(data)
    json.dump(output, sys.stdout, indent=2, ensure_ascii=ensure_ascii, default=default)
    sys.stdout.write("\n")


def emit_json_list(
    key: str,
    items: list[Any],
    *,
    status: str = "ok",
    extra: dict[str, Any] | None = None,
    default: Any = None,
    ensure_ascii: bool = False,
) -> None:
    """Write a list payload to stdout under *key*, wrapped with ``"status"``.

    Parameters
    ----------
    key:
        Top-level key name for the list (e.g. ``"entrypoints"``).
    items:
        The list payload.
    extra:
        Optional extra top-level keys to include alongside the list.
    default:
        ``json.dumps`` *default* parameter.
    ensure_ascii:
        ``json.dumps`` *ensure_ascii* parameter.
    """
    output: dict[str, Any] = {"status": status, key: items}
    if extra:
        output.update(extra)
    json.dump(output, sys.stdout, indent=2, ensure_ascii=ensure_ascii, default=default)
    sys.stdout.write("\n")
