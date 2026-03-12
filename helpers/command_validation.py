"""Command-layer input validation for slash commands.

Validates arguments (module existence, function resolvability, flag
conflicts) before any skill scripts run, producing friendly errors
and avoiding wasted computation.

Usage::

    from helpers.command_validation import validate_command_args

    result = validate_command_args("triage", {"module": "appinfo.dll"})
    if not result.ok:
        for err in result.errors:
            print(err)
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .db_paths import resolve_module_db, resolve_module_db_auto
from .errors import ErrorCode, ScriptError
from .validation import validate_function_id


@dataclass
class CommandValidationResult:
    """Result of command argument validation."""

    ok: bool = True
    errors: list[str] = field(default_factory=list)
    error_codes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    resolved: dict[str, Any] = field(default_factory=dict)

    def add_error(
        self,
        msg: str,
        code: ErrorCode | str = ErrorCode.INVALID_ARGS,
    ) -> None:
        self.ok = False
        self.errors.append(msg)
        self.error_codes.append(code.value if isinstance(code, ErrorCode) else code)

    def add_warning(self, msg: str) -> None:
        self.warnings.append(msg)


def validate_module(
    module_name: str,
    workspace_root: Optional[Path] = None,
    *,
    allow_code_only: bool = False,
) -> CommandValidationResult:
    """Validate that a module exists and its DB is accessible.

    On success, ``result.resolved["db_path"]`` contains the absolute
    path to the module's analysis database.  When ``allow_code_only`` is
    true, modules with extracted code but no DB are accepted with a warning.
    """
    result = CommandValidationResult()

    if not module_name or not module_name.strip():
        result.add_error("Module name is required but was empty.")
        return result

    module_name = module_name.strip()

    if workspace_root is not None:
        db_path = resolve_module_db(module_name, workspace_root)
    else:
        db_path = resolve_module_db_auto(module_name)
    if db_path is None:
        code_dir = _find_extracted_code_dir(module_name, workspace_root)
        if code_dir is not None:
            result.resolved["code_dir"] = str(code_dir)
            if allow_code_only:
                result.add_warning(
                    f"No analysis DB for '{module_name}', but extracted_code/ "
                    f"exists at {code_dir}. Some DB-dependent features will be "
                    f"unavailable."
                )
            else:
                result.add_error(
                    f"Module '{module_name}' has extracted_code at {code_dir}, "
                    "but no analysis DB. This command requires an analysis DB.",
                    ErrorCode.NO_DATA,
                )
        else:
            result.add_error(
                f"Module '{module_name}' not found. Check available modules "
                f"with: python .agent/skills/decompiled-code-extractor/"
                f"scripts/find_module_db.py --list",
                ErrorCode.NOT_FOUND,
            )
        return result

    result.resolved["db_path"] = db_path
    result.resolved["module_name"] = module_name
    return result


def validate_function_arg(
    db_path: str,
    function_ref: str,
) -> CommandValidationResult:
    """Validate that a function reference resolves in the given DB.

    *function_ref* can be a function name or a numeric ID string.
    On success, ``result.resolved["function"]`` contains the resolved
    ``FunctionRecord`` and ``result.resolved["function_id"]`` the numeric ID.
    """
    from .individual_analysis_db import open_individual_analysis_db
    from .function_resolver import resolve_function

    result = CommandValidationResult()

    if not function_ref or not function_ref.strip():
        result.add_error("Function name or ID is required but was empty.")
        return result

    function_ref = function_ref.strip()

    function_id: Optional[int] = None
    function_name: Optional[str] = None

    numeric_ref = function_ref.isdigit() or (
        len(function_ref) > 1
        and function_ref[0] in "+-"
        and function_ref[1:].isdigit()
    )
    if numeric_ref:
        try:
            function_id = validate_function_id(int(function_ref))
        except (ScriptError, SystemExit):
            result.add_error(
                f"Invalid function ID: '{function_ref}'. "
                f"IDs must be positive integers.",
                ErrorCode.INVALID_ARGS,
            )
            return result
    else:
        function_name = function_ref

    try:
        with open_individual_analysis_db(db_path) as db:
            func, err = resolve_function(
                db, name=function_name, function_id=function_id,
            )
    except (OSError, RuntimeError, sqlite3.Error) as exc:
        result.add_error(f"DB access failed for '{db_path}': {exc}", ErrorCode.DB_ERROR)
        return result

    if err:
        result.add_error(err, _error_code_for_resolution_error(err))
        return result

    if func is None:
        result.add_error(
            f"Function '{function_ref}' not found in {Path(db_path).name}.",
            ErrorCode.NOT_FOUND,
        )
        return result

    result.resolved["function"] = func
    result.resolved["function_id"] = func.function_id
    result.resolved["function_name"] = func.function_name
    return result


def validate_depth_param(value: Any, max_depth: int = 20) -> CommandValidationResult:
    """Validate a depth parameter for command input."""
    result = CommandValidationResult()
    try:
        d = int(value)
    except (TypeError, ValueError):
        result.add_error(f"Depth must be an integer, got: {value!r}")
        return result
    if d < 1:
        result.add_error(f"Depth must be >= 1, got: {d}")
    elif d > max_depth:
        result.add_warning(f"Depth {d} exceeds recommended max ({max_depth}); clamping.")
        result.resolved["depth"] = max_depth
    else:
        result.resolved["depth"] = d
    return result


_COMMAND_REQUIREMENTS: dict[str, dict] = {
    "triage": {"requires": ["module"]},
    "audit": {"requires": ["function"], "optional": ["module"]},
    "explain": {"requires": ["function"], "optional": ["module"]},
    "verify-decompiler": {"requires": [], "optional": ["module", "function"]},
    "data-flow": {"requires": ["module", "function"]},
    "data-flow-cross": {"requires": ["module", "function"]},
    "taint": {"requires": ["module", "function"]},
    "lift-class": {"requires": ["class"], "optional": ["module"]},
    "search": {"requires": ["term"], "optional": ["module"]},
    "reconstruct-types": {"requires": ["module"]},
    "state-machines": {"requires": ["module"]},
    "full-report": {"requires": ["module"]},
    "compare-modules": {"requires": ["module"], "optional_override": "all"},
    "verify-decompiler-batch": {"requires": ["module"]},
    "verify-finding": {"requires": ["module"], "optional": ["function"]},
    "batch-audit": {"requires": ["module"]},
    "xref": {"requires": ["module", "function"]},
    "memory-scan": {"requires": ["module"]},
    "logic-scan": {"requires": ["module"]},
    "callgraph": {"requires": ["module"]},
    "imports": {"requires": []},
    "strings": {"requires": ["module"]},
    "scan": {"requires": ["module"]},
    "hunt-execute": {"requires": []},
    "quickstart": {"requires": []},
    "health": {"requires": []},
    "cache-manage": {"requires": []},
    "runs": {"requires": [], "optional": ["module"]},
    "brainstorm": {"requires": []},
    "hunt-plan": {"requires": []},
    "diff": {"requires": ["module"]},
    "rpc": {
        "requires": ["module"],
        "moduleless_modes": {"surface", "clients", "topology", "stubs"},
    },
    "winrt": {
        "requires": ["module"],
        "moduleless_modes": {"surface", "privesc"},
    },
    "com": {
        "requires": ["module"],
        "moduleless_modes": {"surface", "privesc"},
    },
    "prioritize": {"requires": []},
    "pipeline": {"requires": []},
}


def validate_command_args(
    command_name: str,
    args: dict[str, Any],
    workspace_root: Optional[Path] = None,
) -> CommandValidationResult:
    """Validate arguments for a slash command.

    Parameters
    ----------
    command_name : str
        The command name without the leading slash (e.g. ``"triage"``).
    args : dict
        Keys are parameter names (``"module"``, ``"function"``, ``"depth"``,
        ``"term"``, ``"class"``).
    workspace_root : Path | None
        Workspace root for module resolution.  Auto-detected if ``None``.

    Returns
    -------
    CommandValidationResult
        ``ok=True`` if all validations pass.  ``resolved`` dict contains
        resolved entities (``db_path``, ``function``, ``function_id``, etc.).
    """
    result = CommandValidationResult()

    reqs = _COMMAND_REQUIREMENTS.get(command_name)
    if reqs is None:
        result.add_warning(f"Unknown command '{command_name}'; skipping validation.")
        return result

    required = list(reqs.get("requires", []))
    optional = set(reqs.get("optional", []))

    override_flag = reqs.get("optional_override")
    if override_flag and args.get(override_flag):
        required = [r for r in required if r != "module"]

    requested_mode = None
    for key in ("mode", "subcommand", "action"):
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            requested_mode = value.strip().lower()
            break
    if requested_mode and requested_mode in reqs.get("moduleless_modes", set()):
        required = [r for r in required if r != "module"]

    module = args.get("module")
    db_path = None

    if "module" in required or ("module" in optional and module):
        if not module:
            result.add_error(f"/{command_name} requires a <module> argument.")
            return result
        mod_result = validate_module(module, workspace_root)
        result.errors.extend(mod_result.errors)
        result.error_codes.extend(mod_result.error_codes)
        result.warnings.extend(mod_result.warnings)
        result.resolved.update(mod_result.resolved)
        if not mod_result.ok:
            result.ok = False
            return result
        db_path = result.resolved.get("db_path")
    else:
        db_path = result.resolved.get("db_path")

    func_ref = args.get("function")
    should_validate_function = "function" in required or ("function" in optional and func_ref)
    if should_validate_function:
        if not func_ref:
            result.add_error(f"/{command_name} requires a <function> argument.")
            return result
        if db_path:
            func_result = validate_function_arg(db_path, func_ref)
            result.errors.extend(func_result.errors)
            result.error_codes.extend(func_result.error_codes)
            result.warnings.extend(func_result.warnings)
            result.resolved.update(func_result.resolved)
            if not func_result.ok:
                result.ok = False

    if "class" in required:
        class_name = args.get("class")
        if not class_name or not class_name.strip():
            result.add_error(f"/{command_name} requires a <class_name> argument.")
            result.ok = False

    if "term" in required:
        term = args.get("term")
        if not term or not term.strip():
            result.add_error(f"/{command_name} requires a <search_term> argument.")
            result.ok = False

    depth = args.get("depth")
    if depth is not None:
        depth_result = validate_depth_param(depth)
        result.errors.extend(depth_result.errors)
        result.error_codes.extend(depth_result.error_codes)
        result.warnings.extend(depth_result.warnings)
        result.resolved.update(depth_result.resolved)
        if not depth_result.ok:
            result.ok = False

    return result


def command_preflight(
    command_name: str,
    module: str | None = None,
    function: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Convenience wrapper: validate and resolve command arguments in one call.

    Returns the ``resolved`` dict (with ``db_path``, ``function_id``, etc.)
    on success.  Calls :func:`~helpers.errors.emit_error` and exits on
    validation failure.

    Parameters
    ----------
    command_name : str
        Command name without leading slash (e.g. ``"triage"``).
    module : str | None
        Module name, if the command requires one.
    function : str | None
        Function name or ID, if the command requires one.
    **kwargs
        Additional arguments (``depth``, ``term``, ``class``, etc.).
    """
    from .errors import emit_error, ErrorCode

    args: dict[str, Any] = {}
    if module is not None:
        args["module"] = module
    if function is not None:
        args["function"] = function
    args.update(kwargs)

    result = validate_command_args(command_name, args)

    if result.warnings:
        import sys
        for w in result.warnings:
            print(f"Warning: {w}", file=sys.stderr)

    if not result.ok:
        msg = "; ".join(result.errors)
        code = ErrorCode.INVALID_ARGS
        if result.error_codes:
            first_code = result.error_codes[0]
            try:
                code = ErrorCode(first_code)
            except ValueError:
                code = ErrorCode.UNKNOWN
        emit_error(msg, code)

    return result.resolved


def _find_extracted_code_dir(
    module_name: str,
    workspace_root: Optional[Path] = None,
) -> Optional[Path]:
    """Check if extracted_code/<module>/ exists even without a DB."""
    if workspace_root is None:
        from .script_runner import get_workspace_root
        workspace_root = get_workspace_root()
    if workspace_root is None:
        return None

    code_dir = Path(workspace_root) / "extracted_code"
    if not code_dir.is_dir():
        return None

    normalized = module_name.replace(".", "_").lower()
    for d in code_dir.iterdir():
        if d.is_dir() and d.name.lower() == normalized:
            return d

    return None


def _error_code_for_resolution_error(message: str) -> ErrorCode:
    """Map resolver error text to the closest structured error code."""
    lowered = message.lower()
    if lowered.startswith("multiple matches"):
        return ErrorCode.AMBIGUOUS
    if "not found" in lowered or lowered.startswith("no function"):
        return ErrorCode.NOT_FOUND
    return ErrorCode.UNKNOWN
