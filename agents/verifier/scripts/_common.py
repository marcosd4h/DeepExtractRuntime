"""Shared utilities for the verifier subagent scripts.

Resolves workspace root, provides access to the verify-decompiled skill's
assembly/decompiled parsing code, and re-exports verifier-specific helpers
from ``_parsing`` and ``_comparison`` submodules.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

_AGENT_DIR = str(Path(__file__).resolve().parents[3])
if _AGENT_DIR not in sys.path:
    sys.path.insert(0, _AGENT_DIR)

from skills._shared import (
    bootstrap,
    create_run_dir,
    read_results,
    read_summary,
)

WORKSPACE_ROOT = bootstrap(__file__)
SCRIPT_DIR = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Import verify-decompiled _common via shared load_skill_module
# (avoids name collision -- both this file and the skill file are _common.py)
# ---------------------------------------------------------------------------
from helpers import AgentBase, load_skill_module  # noqa: E402

_AGENT_BASE = AgentBase(default_timeout=300)

_vdc = load_skill_module("verify-decompiled", "_common")

# Re-bind names from the verify-decompiled module
AsmInstruction = _vdc.AsmInstruction
AsmStats = _vdc.AsmStats
DecompStats = _vdc.DecompStats
Severity = _vdc.Severity
SEVERITY_LABELS = _vdc.SEVERITY_LABELS
VerificationIssue = _vdc.VerificationIssue
VerificationResult = _vdc.VerificationResult
parse_assembly = _vdc.parse_assembly
parse_asm_instruction = _vdc.parse_asm_instruction
parse_decompiled = _vdc.parse_decompiled
run_heuristic_checks = _vdc.run_heuristic_checks
resolve_db_path = _vdc.resolve_db_path
resolve_tracking_db = _vdc.resolve_tracking_db
parse_json_safe = _vdc.parse_json_safe
is_decompilation_failure = _vdc.is_decompilation_failure

# ---------------------------------------------------------------------------
# Subprocess-based skill script invocation
# ---------------------------------------------------------------------------


def run_skill_script(
    skill_name: str,
    script_name: str,
    args: list[str],
    timeout: int = 300,
    workspace_dir: str | None = None,
    workspace_step: str | None = None,
) -> Optional[dict | list]:
    """Run a skill script via subprocess and return parsed JSON output.

    Thin wrapper around ``helpers.run_skill_script`` that preserves the
    original return convention: parsed JSON on success, ``None`` on failure.
    Always requests ``--json`` output from the child script.
    """
    return _AGENT_BASE.run_skill_script(
        skill_name,
        script_name,
        args,
        timeout=timeout,
        workspace_dir=workspace_dir,
        workspace_step=workspace_step,
    )


# ---------------------------------------------------------------------------
# Re-exports from verifier submodules
# ---------------------------------------------------------------------------
from _parsing import (  # noqa: E402, F401
    LiftedCodeStats,
    parse_lifted_code,
)
from _comparison import (  # noqa: E402, F401
    CheckResult,
    ComparisonResult,
    extract_api_calls_from_assembly,
    extract_memory_offsets_from_assembly as _extract_memory_offsets_raw,
)


def extract_memory_offsets_from_assembly(assembly_code: str) -> list[dict]:
    """Extract [base+offset] memory access patterns from assembly.

    Pre-binds ``parse_asm_instruction`` from the verify-decompiled skill
    so callers don't need to pass it explicitly.
    """
    return _extract_memory_offsets_raw(assembly_code, parse_asm_instruction)


# Re-export everything the verifier scripts need
__all__ = [
    "SCRIPT_DIR",
    "WORKSPACE_ROOT",
    "create_run_dir",
    "read_results",
    "read_summary",
    "run_skill_script",
    # verify-decompiled skill types
    "AsmInstruction",
    "AsmStats",
    "DecompStats",
    "Severity",
    "SEVERITY_LABELS",
    "VerificationIssue",
    "VerificationResult",
    "parse_assembly",
    "parse_asm_instruction",
    "parse_decompiled",
    "run_heuristic_checks",
    "resolve_db_path",
    "resolve_tracking_db",
    "parse_json_safe",
    "is_decompilation_failure",
    # Lifted code parsing (_parsing.py)
    "LiftedCodeStats",
    "parse_lifted_code",
    # Comparison types (_comparison.py)
    "ComparisonResult",
    "CheckResult",
    "extract_api_calls_from_assembly",
    "extract_memory_offsets_from_assembly",
]
