"""Standardized error output for skill scripts.

All skill scripts should use ``emit_error()`` instead of ad-hoc
``print(..., file=sys.stderr); sys.exit(1)`` so that agents and
coordinators can parse errors programmatically.

Error codes:
    NOT_FOUND    -- Requested entity (function, module, DB) does not exist.
    INVALID_ARGS -- Bad or missing command-line arguments.
    DB_ERROR     -- Database could not be opened or queried.
    PARSE_ERROR  -- Data could not be parsed (JSON, assembly, etc.).
    NO_DATA      -- Query succeeded but returned empty results.
    AMBIGUOUS    -- Multiple matches found when exactly one was expected.
    UNKNOWN      -- Catch-all for uncategorised errors.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from contextlib import contextmanager
from enum import Enum
from typing import Generator


class ErrorCode(str, Enum):
    """Standardized error codes for DeepExtractIDA."""
    NOT_FOUND = "NOT_FOUND"        # Requested entity (function, module, DB) does not exist.
    INVALID_ARGS = "INVALID_ARGS"  # Bad or missing command-line arguments.
    DB_ERROR = "DB_ERROR"          # Database could not be opened or queried.
    PARSE_ERROR = "PARSE_ERROR"    # Data could not be parsed (JSON, assembly, etc.).
    NO_DATA = "NO_DATA"            # Query succeeded but returned empty results.
    AMBIGUOUS = "AMBIGUOUS"        # Multiple matches found when exactly one was expected.
    UNKNOWN = "UNKNOWN"            # Catch-all for uncategorised errors.


class ScriptError(Exception):
    """Typed exception for structured error propagation in helper/library code.

    Library and helper functions should raise ``ScriptError`` instead of
    calling ``emit_error()`` directly so that callers retain control over
    whether to abort, retry, or aggregate errors.  Entry-point scripts
    should catch ``ScriptError`` at the top level and call ``emit_error()``::

        try:
            result = some_helper(...)
        except ScriptError as exc:
            emit_error(str(exc), exc.code)

    Convention summary:
      - **Entry-point scripts** (``if __name__ == "__main__"``): use ``emit_error()``
      - **Library / helper functions**: raise ``ScriptError``
      - **Non-fatal conditions**: use ``log_warning()``
      - **Recoverable DB issues**: use ``log_error()`` + return sentinel
    """

    def __init__(self, message: str, code: ErrorCode | str = ErrorCode.UNKNOWN) -> None:
        super().__init__(message)
        self.code: str = code.value if isinstance(code, ErrorCode) else code


def emit_error(message: str, code: ErrorCode | str = ErrorCode.UNKNOWN) -> None:
    """Write structured error JSON to stderr and exit with code 1.

    Output format (single line on stderr)::

        {"error": "<message>", "code": "<code>"}
    """
    code_val = code.value if isinstance(code, ErrorCode) else code
    json.dump({"error": message, "code": code_val}, sys.stderr)
    sys.stderr.write("\n")
    sys.exit(1)


def log_error(message: str, code: ErrorCode | str = ErrorCode.UNKNOWN) -> None:
    """Write structured error JSON to stderr WITHOUT exiting.

    Use in helper functions that report errors but let callers
    decide whether to abort.  Callers should check the return
    value and call ``emit_error()`` at the script boundary if
    the error is fatal.

    Output format is identical to ``emit_error``::

        {"error": "<message>", "code": "<code>"}
    """
    code_val = code.value if isinstance(code, ErrorCode) else code
    json.dump({"error": message, "code": code_val}, sys.stderr)
    sys.stderr.write("\n")


@contextmanager
def db_error_handler(
    db_path: str,
    operation: str = "database operation",
    *,
    fatal: bool = True,
) -> Generator[None, None, None]:
    """Context manager that catches DB exceptions and emits structured errors.

    Wraps a block of code that performs database operations.  On known
    failure modes the manager either calls :func:`emit_error` (fatal exit)
    or raises :class:`ScriptError` depending on the *fatal* flag.

    Use ``fatal=True`` (default) in entry-point scripts, and
    ``fatal=False`` in library/helper code where callers need to
    recover or aggregate errors.

    Usage::

        # Entry-point script -- exits on error:
        with db_error_handler(db_path, "opening analysis DB"):
            db = open_individual_analysis_db(db_path)

        # Library code -- raises ScriptError:
        with db_error_handler(db_path, "loading function", fatal=False):
            db = open_individual_analysis_db(db_path)
    """
    def _handle(message: str, code: ErrorCode) -> None:
        if fatal:
            emit_error(message, code)
        else:
            raise ScriptError(message, code)

    try:
        yield
    except SystemExit:
        raise
    except ScriptError:
        raise
    except FileNotFoundError as exc:
        _handle(f"Database not found: {db_path} -- {exc}", ErrorCode.NOT_FOUND)
    except RuntimeError as exc:
        msg = str(exc)
        if "Failed to open" in msg or "Cannot open" in msg:
            _handle(f"Cannot open database {db_path}: {exc}", ErrorCode.DB_ERROR)
        else:
            _handle(
                f"Runtime error during {operation} on {db_path}: {exc}",
                ErrorCode.DB_ERROR,
            )
    except sqlite3.Error as exc:
        _handle(
            f"Database error during {operation} on {db_path}: {exc}",
            ErrorCode.DB_ERROR,
        )
    except Exception as exc:
        _handle(
            f"Unexpected error during {operation} on {db_path}: {exc}. "
            f"Ensure the database file exists, is readable, and matches "
            f"the expected schema version.",
            ErrorCode.UNKNOWN,
        )


def safe_parse_args(parser, args=None):
    """Parse arguments, suppressing argparse output and emitting structured JSON on error.

    Replaces raw ``parser.parse_args()`` calls in entry-point scripts.
    Redirects stderr so argparse's built-in usage text does not leak,
    then emits a single structured INVALID_ARGS error on failure.
    """
    import contextlib
    import io

    try:
        with contextlib.redirect_stderr(io.StringIO()):
            return parser.parse_args(args)
    except SystemExit as exc:
        if exc.code != 0:
            emit_error(
                "Missing or invalid arguments -- run with --help",
                ErrorCode.INVALID_ARGS,
            )
        sys.exit(0)


def log_warning(message: str, code: ErrorCode | str = ErrorCode.UNKNOWN) -> None:
    """Write structured warning JSON to stderr WITHOUT exiting.

    Use in helper functions for non-fatal conditions that should be
    visible for debugging but do not represent hard errors (e.g.
    missing optional files, invalid regex patterns, cache misses).

    Output format (single line on stderr)::

        {"warning": "<message>", "code": "<code>"}
    """
    code_val = code.value if isinstance(code, ErrorCode) else code
    json.dump({"warning": message, "code": code_val}, sys.stderr)
    sys.stderr.write("\n")
