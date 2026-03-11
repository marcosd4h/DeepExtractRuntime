"""Shared script path resolution and invocation for skill and agent scripts.

Consolidates the duplicated script-finding, subprocess-running, and
``importlib``-based module-loading patterns that were scattered across
individual agent ``_common.py`` files into a single reusable module.

Capabilities
~~~~~~~~~~~~
A. **Path resolution** -- ``find_skill_script``, ``find_agent_script``,
   ``get_skills_dir``, ``get_agents_dir``
B. **Subprocess invocation** -- ``run_skill_script``
C. **Module loading** -- ``load_skill_module``
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Any, Optional

from .errors import log_error, log_warning
from .progress import status_message

# ---------------------------------------------------------------------------
# Workspace / directory resolution
# ---------------------------------------------------------------------------

from .db_paths import _auto_workspace_root

_HELPERS_DIR = Path(__file__).resolve().parent
_RUNTIME_ROOT = _HELPERS_DIR.parent
_WORKSPACE_ROOT = _auto_workspace_root()


def get_workspace_root() -> Path:
    """Return the resolved workspace root directory."""
    return _WORKSPACE_ROOT


def get_runtime_root() -> Path:
    """Return the runtime root (the directory containing helpers/, skills/, etc.)."""
    return _RUNTIME_ROOT


def get_skills_dir() -> Path:
    """Return the skills directory (``<runtime_root>/skills``)."""
    return _RUNTIME_ROOT / "skills"


def get_agents_dir() -> Path:
    """Return the agents directory (``<runtime_root>/agents``)."""
    return _RUNTIME_ROOT / "agents"


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------

def find_skill_script(skill_name: str, script_name: str) -> Optional[Path]:
    """Resolve a skill script by skill name and script filename.

    Looks for ``<runtime_root>/skills/<skill_name>/scripts/<script_name>``.
    Returns the resolved :class:`Path` if the file exists, otherwise ``None``.
    """
    script_path = get_skills_dir() / skill_name / "scripts" / script_name
    if script_path.exists():
        return script_path
    return None


def find_agent_script(agent_name: str, script_name: str) -> Optional[Path]:
    """Resolve an agent script by agent name and script filename.

    Looks for ``<runtime_root>/agents/<agent_name>/scripts/<script_name>``.
    Returns the resolved :class:`Path` if the file exists, otherwise ``None``.
    """
    script_path = get_agents_dir() / agent_name / "scripts" / script_name
    if script_path.exists():
        return script_path
    return None


# ---------------------------------------------------------------------------
# Subprocess invocation
# ---------------------------------------------------------------------------

# Error strings that indicate transient failures worth retrying.
_TRANSIENT_ERROR_PATTERNS = (
    "database is locked",
    "disk I/O error",
    "OperationalError",
    "unable to open database",
)


def _is_transient_error(error_text: str) -> bool:
    """Return ``True`` if *error_text* matches a known transient pattern."""
    lower = error_text.lower()
    return any(p.lower() in lower for p in _TRANSIENT_ERROR_PATTERNS)


def run_skill_script(
    skill_name: str,
    script_name: str,
    args: list[str],
    timeout: int | None = None,
    json_output: bool = False,
    workspace_dir: str | None = None,
    workspace_step: str | None = None,
    max_retries: int | None = None,
) -> dict:
    """Run a skill script as a subprocess and capture output.

    Args:
        skill_name: Name of the skill directory (e.g. ``'classify-functions'``).
        script_name: Script filename (e.g. ``'triage_summary.py'``).
        args: Command-line arguments to pass to the script.
        timeout: Subprocess timeout in seconds.  When ``None``, uses
            ``script_runner.default_timeout_seconds`` from config (default 180).
        json_output: If ``True``, append ``--json`` to the argument list and
            attempt to parse stdout as JSON.
        workspace_dir: Optional run workspace directory to pass through via
            ``--workspace-dir``.
        workspace_step: Optional per-step key for workspace result
            partitioning via ``--workspace-step``.
        max_retries: Number of automatic retries for transient errors
            (DB locks, I/O errors).  When ``None``, uses
            ``script_runner.max_retries`` from config (default 0).
            Maximum value clamped to ``2``.

    Returns:
        A dict with keys ``success``, ``stdout``, ``stderr``, ``json_data``,
        ``exit_code``, and ``error``.
    """
    from helpers.config import get_config_value

    if timeout is None:
        timeout = int(get_config_value("script_runner.default_timeout_seconds", 180))
    if max_retries is None:
        max_retries = int(get_config_value("script_runner.max_retries", 0))

    script_path = find_skill_script(skill_name, script_name)
    if script_path is None:
        return {
            "success": False,
            "error": f"Script not found: {skill_name}/scripts/{script_name}",
            "stdout": "",
            "stderr": "",
            "json_data": None,
            "exit_code": -1,
        }

    cmd = [sys.executable, str(script_path)] + [str(a) for a in args]

    if json_output:
        cmd.append("--json")

    if workspace_dir:
        cmd += ["--workspace-dir", workspace_dir]
        if workspace_step:
            cmd += ["--workspace-step", workspace_step]

    max_retries = min(max(int(max_retries), 0), 2)
    last_result: dict = {}

    for attempt in range(1 + max_retries):
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(_WORKSPACE_ROOT),
            )

            if result.stderr.strip():
                for line in result.stderr.strip().splitlines():
                    status_message(f"[{script_name}] {line}")

            json_data = None
            json_error = None
            parse_stdout_as_json = json_output or bool(workspace_dir)
            if parse_stdout_as_json and result.stdout.strip():
                try:
                    json_data = json.loads(result.stdout)
                except json.JSONDecodeError as exc:
                    json_error = (
                        f"Failed to parse JSON stdout from {script_name}: {exc}"
                    )
                    log_warning(
                        f"Failed to parse JSON stdout from {script_name}: "
                        f"{result.stdout[:200]}",
                        "PARSE_ERROR",
                    )

            last_result = {
                "success": result.returncode == 0 and json_error is None,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "json_data": json_data,
                "exit_code": result.returncode,
                "error": (
                    json_error
                    if json_error is not None
                    else (None if result.returncode == 0 else result.stderr[:500])
                ),
            }

            if last_result["success"]:
                return last_result

            if attempt < max_retries and _is_transient_error(result.stderr):
                delay = 2 ** attempt
                log_warning(
                    f"Transient error in {script_name} (attempt {attempt + 1}/"
                    f"{1 + max_retries}), retrying in {delay}s: "
                    f"{result.stderr[:200]}",
                    "DB_ERROR",
                )
                time.sleep(delay)
                continue

            return last_result

        except subprocess.TimeoutExpired:
            last_result = {
                "success": False,
                "error": f"Timeout after {timeout}s",
                "stdout": "",
                "stderr": "",
                "json_data": None,
                "exit_code": -1,
            }
            if attempt < max_retries:
                delay = 2 ** attempt
                log_warning(
                    f"Timeout in {script_name} (attempt {attempt + 1}/"
                    f"{1 + max_retries}), retrying in {delay}s",
                    "DB_ERROR",
                )
                time.sleep(delay)
                continue
            return last_result

        except Exception as e:
            last_result = {
                "success": False,
                "error": str(e),
                "stdout": "",
                "stderr": "",
                "json_data": None,
                "exit_code": -1,
            }
            return last_result

    return last_result


# ---------------------------------------------------------------------------
# Workspace arg extraction
# ---------------------------------------------------------------------------

def get_workspace_args(args) -> dict[str, str | None]:
    """Extract workspace handoff arguments from an argparse namespace.

    Returns a dict with ``workspace_dir`` and ``workspace_step`` keys,
    suitable for forwarding as ``**kwargs`` to :func:`run_skill_script`.
    Missing attributes default to ``None`` so the caller never needs
    ``getattr`` boilerplate.
    """
    return {
        "workspace_dir": getattr(args, "workspace_dir", None),
        "workspace_step": getattr(args, "workspace_step", None),
    }


# ---------------------------------------------------------------------------
# Module loading (importlib)
# ---------------------------------------------------------------------------

def load_skill_module(
    skill_name: str,
    module_name: str = "_common",
) -> ModuleType:
    """Import a Python module from a skill's ``scripts/`` directory.

    Uses :mod:`importlib` to load
    ``<runtime_root>/skills/<skill_name>/scripts/<module_name>.py``
    under a namespaced key in :data:`sys.modules` to avoid collisions
    (e.g. multiple skills each having their own ``_common.py``).

    The module is cached in ``sys.modules`` after the first load so
    repeated calls return the same object.

    During execution of the target module, any bare ``_common`` entry in
    ``sys.modules`` is temporarily replaced with the correct skill-local
    ``_common.py`` so that ``from _common import ...`` inside the target
    module resolves to its own sibling ``_common`` rather than a stale
    cached version from a different skill.

    Raises:
        FileNotFoundError: If the target module file does not exist.
        ImportError: If the module fails to load.
    """
    cache_key = f"_skill__{skill_name}__{module_name}"
    if cache_key in sys.modules:
        return sys.modules[cache_key]

    module_path = get_skills_dir() / skill_name / "scripts" / f"{module_name}.py"
    if not module_path.exists():
        raise FileNotFoundError(
            f"Skill module not found: {skill_name}/scripts/{module_name}.py"
        )

    spec = importlib.util.spec_from_file_location(cache_key, str(module_path))
    if spec is None or spec.loader is None:
        raise ImportError(
            f"Could not create import spec for {module_path}"
        )

    mod = importlib.util.module_from_spec(spec)
    sys.modules[cache_key] = mod  # register before exec to handle circular refs

    # Ensure the skill's own _common.py is importable as bare "_common"
    # during execution, preventing cross-skill sys.modules collisions.
    scripts_dir = module_path.parent
    common_path = scripts_dir / "_common.py"
    saved_common = sys.modules.get("_common", _SENTINEL)
    if module_name != "_common" and common_path.exists():
        common_cache_key = f"_skill__{skill_name}___common"
        if common_cache_key in sys.modules:
            sys.modules["_common"] = sys.modules[common_cache_key]
        elif saved_common is not _SENTINEL:
            saved_file = getattr(saved_common, "__file__", None)
            if saved_file and Path(saved_file).resolve() != common_path.resolve():
                sys.modules.pop("_common", None)
    try:
        try:
            spec.loader.exec_module(mod)
        except BaseException:
            sys.modules.pop(cache_key, None)
            raise
    finally:
        if saved_common is _SENTINEL:
            sys.modules.pop("_common", None)
        else:
            sys.modules["_common"] = saved_common

    return mod


_SENTINEL = object()
