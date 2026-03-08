#!/usr/bin/env python3
"""Workspace health check for the DeepExtractIDA agent runtime.

Validates that extraction data, analysis databases, skill/agent/command
registries, and configuration are present and consistent.

Usage:
    python .agent/helpers/health_check.py
    python .agent/helpers/health_check.py --quick
    python .agent/helpers/health_check.py --full
    python .agent/helpers/health_check.py --json
    python .agent/helpers/health_check.py --workspace /path/to/workspace

Modes:
    (default)  -- standard: sample DBs and function indexes at scale
    --quick    -- skip DB validation and function index checks
    --full     -- validate every DB and index, run pytest test suite
"""

from __future__ import annotations

import argparse
import json
import random
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Bootstrap: ensure helpers/ is importable from any cwd
# ---------------------------------------------------------------------------

_SCRIPT_DIR = Path(__file__).resolve().parent   # .agent/helpers/
_RUNTIME_ROOT = _SCRIPT_DIR.parent              # .agent/
_WORKSPACE_ROOT = _RUNTIME_ROOT.parent          # workspace root

if str(_RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(_RUNTIME_ROOT))

from helpers.config import validate_config, get_config_value  # noqa: E402
from helpers.errors import log_warning  # noqa: E402
from helpers.json_output import emit_json  # noqa: E402
from helpers.progress import status_message  # noqa: E402
from helpers.validation import (  # noqa: E402
    ValidationResult,
    validate_analysis_db,
    validate_function_index,
    validate_tracking_db,
    validate_workspace_data,
)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

_LINE = "=" * 56


@dataclass
class CheckResult:
    label: str
    ok: bool = True
    detail: str = ""
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def status_str(self) -> str:
        if self.ok:
            s = "OK"
            if self.detail:
                s += f"  ({self.detail})"
            return s
        return f"FAIL  ({self.detail})" if self.detail else "FAIL"


@dataclass
class HealthReport:
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def all_ok(self) -> bool:
        return all(c.ok for c in self.checks)

    def add(self, result: CheckResult) -> None:
        self.checks.append(result)

    def render_text(self) -> str:
        lines = ["Workspace Health Check", _LINE]
        label_w = max((len(c.label) for c in self.checks), default=20) + 2
        for c in self.checks:
            lines.append(f"{c.label + ':':<{label_w}}{c.status_str()}")
        lines.append(_LINE)
        lines.append("Overall: OK" if self.all_ok else "Overall: FAIL")
        detail_lines: list[str] = []
        for c in self.checks:
            for w in c.warnings:
                detail_lines.append(f"  WARNING [{c.label}]: {w}")
            for e in c.errors:
                detail_lines.append(f"  ERROR   [{c.label}]: {e}")
        if detail_lines:
            lines.append("")
            lines.extend(detail_lines)
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "status": "ok" if self.all_ok else "error",
            "overall_ok": self.all_ok,
            "checks": [
                {
                    "label": c.label,
                    "ok": c.ok,
                    "detail": c.detail,
                    "warnings": c.warnings,
                    "errors": c.errors,
                }
                for c in self.checks
            ],
        }


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------

def check_extraction_data(workspace_root: Path) -> CheckResult:
    """Step 1: verify extracted_code/ and extracted_dbs/ are present."""
    status_message("Checking extraction data availability...")
    result = CheckResult("Extraction Data")
    ws = validate_workspace_data(str(workspace_root))
    if not ws.ok:
        result.ok = False
        result.detail = "No extraction data found"
        result.errors.append(
            "Neither extracted_code/ nor extracted_dbs/ contains usable data. "
            "Run DeepExtractIDA first."
        )
        return result
    if ws.json_only:
        result.warnings.append("No analysis DBs found; DB-backed features unavailable")
    n_dbs = len(ws.modules_with_dbs)
    n_json = len(ws.json_only_modules)
    parts = []
    if n_dbs:
        parts.append(f"{n_dbs} module{'s' if n_dbs != 1 else ''} with DBs")
    if n_json:
        parts.append(f"{n_json} JSON-only")
    result.detail = ", ".join(parts) if parts else "no modules"
    return result


def check_analysis_dbs(
    workspace_root: Path,
    *,
    full: bool = False,
) -> tuple[CheckResult, CheckResult]:
    """Steps 2a-b: validate analysis DBs (sampled unless --full) and tracking DB."""
    status_message("Validating analysis databases...")
    db_result = CheckResult("Analysis DBs")
    tracking_result = CheckResult("Tracking DB")

    dbs_dir = workspace_root / "extracted_dbs"
    if not dbs_dir.exists():
        db_result.ok = False
        db_result.detail = "extracted_dbs/ not found"
        tracking_result.ok = False
        tracking_result.detail = "extracted_dbs/ not found"
        return db_result, tracking_result

    # Tracking DB
    tracking_path = dbs_dir / "analyzed_files.db"
    if tracking_path.exists():
        vr = validate_tracking_db(str(tracking_path))
        if not vr.ok:
            tracking_result.ok = False
            tracking_result.errors.extend(vr.errors)
        tracking_result.warnings.extend(vr.warnings)
        tracking_result.detail = "analyzed_files.db found"
    else:
        tracking_result.warnings.append(
            "analyzed_files.db not found; cross-module features unavailable"
        )
        tracking_result.detail = "not found"

    # Individual analysis DBs
    all_dbs = [p for p in dbs_dir.glob("*.db") if p.name != "analyzed_files.db"]
    total = len(all_dbs)
    if total == 0:
        db_result.detail = "no analysis DBs found"
        db_result.warnings.append("No individual analysis DBs found in extracted_dbs/")
        return db_result, tracking_result

    sample_limit: int = get_config_value("scale.health_sample_count", 50)
    if full or total <= sample_limit:
        to_validate = all_dbs
        sampled = False
    else:
        to_validate = random.sample(all_dbs, sample_limit)
        sampled = True

    failed: list[str] = []
    for db_path in to_validate:
        vr = validate_analysis_db(str(db_path), deep=full)
        if not vr.ok:
            failed.append(db_path.name)
            db_result.errors.extend(
                [f"{db_path.name}: {e}" for e in vr.errors]
            )
        db_result.warnings.extend(
            [f"{db_path.name}: {w}" for w in vr.warnings]
        )

    validated = len(to_validate)
    if sampled:
        db_result.detail = f"{validated}/{total} sampled, {len(failed)} failed"
    else:
        db_result.detail = f"{validated} validated, {len(failed)} failed"

    if failed:
        db_result.ok = False

    return db_result, tracking_result


def _load_registry(path: Path, key: str) -> dict:
    """Load a registry JSON file and return the dict under *key*.

    Registry files use a named-dict structure:
        {"<key>": {"entry-name": {...}, ...}}
    Callers must iterate with .items(), not treat entries as a list.
    """
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data.get(key, {})
    except (json.JSONDecodeError, OSError):
        return {}


def check_skills(agent_dir: Path) -> CheckResult:
    """Step 3: verify skill directories and scripts match registry.json."""
    status_message("Verifying skill scripts...")
    result = CheckResult("Skills")
    skills_dir = agent_dir / "skills"
    registry = _load_registry(skills_dir / "registry.json", "skills")
    if not registry:
        result.ok = False
        result.detail = "registry.json missing or empty"
        result.errors.append(f"Could not load {skills_dir / 'registry.json'}")
        return result

    missing: list[str] = []
    for name, meta in registry.items():
        if meta.get("methodology_only"):
            # Documentation-only skills have no scripts/ directory
            continue
        scripts_dir = skills_dir / name / "scripts"
        if not scripts_dir.is_dir():
            missing.append(f"{name}/scripts/ (directory missing)")
            continue
        common_py = scripts_dir / "_common.py"
        if not common_py.exists():
            missing.append(f"{name}/scripts/_common.py")
        for entry in meta.get("entry_scripts", []):
            script_name = entry.get("script", "")
            if script_name and not (scripts_dir / script_name).exists():
                missing.append(f"{name}/scripts/{script_name}")

    total = len(registry)
    if missing:
        result.ok = False
        result.errors.extend(missing)
        result.detail = f"{total - len(missing)}/{total} present"
    else:
        result.detail = f"{total}/{total} present"
    return result


def check_agents(agent_dir: Path) -> CheckResult:
    """Step 4: verify agent directories and entry scripts match registry.json."""
    status_message("Verifying agent scripts...")
    result = CheckResult("Agents")
    agents_dir = agent_dir / "agents"
    registry = _load_registry(agents_dir / "registry.json", "agents")
    if not registry:
        result.ok = False
        result.detail = "registry.json missing or empty"
        result.errors.append(f"Could not load {agents_dir / 'registry.json'}")
        return result

    missing: list[str] = []
    for name, meta in registry.items():
        scripts_dir = agents_dir / name / "scripts"
        if not scripts_dir.is_dir():
            missing.append(f"{name}/scripts/ (directory missing)")
            continue
        common_py = scripts_dir / "_common.py"
        if not common_py.exists():
            missing.append(f"{name}/scripts/_common.py")
        for entry in meta.get("entry_scripts", []):
            script_name = entry.get("script", "")
            if script_name and not (scripts_dir / script_name).exists():
                missing.append(f"{name}/scripts/{script_name}")

    total = len(registry)
    if missing:
        result.ok = False
        result.errors.extend(missing)
        result.detail = f"{total - len(missing)}/{total} present"
    else:
        result.detail = f"{total}/{total} present"
    return result


def check_commands(agent_dir: Path) -> CheckResult:
    """Step 5: verify command .md files and cross-registry references."""
    status_message("Verifying command registry...")
    result = CheckResult("Commands")
    commands_dir = agent_dir / "commands"
    registry = _load_registry(commands_dir / "registry.json", "commands")
    if not registry:
        result.ok = False
        result.detail = "registry.json missing or empty"
        result.errors.append(f"Could not load {commands_dir / 'registry.json'}")
        return result

    skills_reg = _load_registry(agent_dir / "skills" / "registry.json", "skills")
    agents_reg = _load_registry(agent_dir / "agents" / "registry.json", "agents")

    errors: list[str] = []
    for name, meta in registry.items():
        cmd_file = meta.get("file", "")
        if cmd_file and not (commands_dir / cmd_file).exists():
            errors.append(f"/{name}: missing file '{cmd_file}'")
        for skill in meta.get("skills_used", []):
            if skill not in skills_reg:
                errors.append(f"/{name}: skills_used references unknown skill '{skill}'")
        for skill in meta.get("methodologies_used", []):
            if skill not in skills_reg:
                errors.append(f"/{name}: methodologies_used references unknown skill '{skill}'")
        for agent in meta.get("agents_used", []):
            if agent not in agents_reg:
                errors.append(f"/{name}: agents_used references unknown agent '{agent}'")

    total = len(registry)
    if errors:
        result.ok = False
        result.errors.extend(errors)
        result.detail = f"{total - len(errors)}/{total} consistent"
    else:
        result.detail = f"{total}/{total} registered"
    return result


def check_configuration(agent_dir: Path) -> CheckResult:
    """Step 6: validate helpers.config values."""
    status_message("Validating configuration...")
    result = CheckResult("Configuration")
    try:
        issues = validate_config()
    except Exception as exc:  # noqa: BLE001
        result.ok = False
        result.errors.append(f"validate_config raised: {exc}")
        return result
    if issues:
        result.ok = False
        result.errors.extend(issues)
        result.detail = f"{len(issues)} issue(s)"
    return result


def check_function_indexes(
    workspace_root: Path,
    *,
    full: bool = False,
) -> CheckResult:
    """Step 7: spot-check function_index.json files under extracted_code/."""
    status_message("Checking function indexes...")
    result = CheckResult("Function Indexes")
    code_dir = workspace_root / "extracted_code"
    if not code_dir.exists():
        result.detail = "extracted_code/ not found"
        result.warnings.append("extracted_code/ directory missing; skipping index check")
        return result

    all_dirs = [d for d in code_dir.iterdir() if d.is_dir()]
    total = len(all_dirs)
    if total == 0:
        result.detail = "no module directories found"
        return result

    sample_limit: int = get_config_value("scale.health_sample_count", 50)
    if full or total <= sample_limit:
        to_check = all_dirs
        sampled = False
    else:
        to_check = random.sample(all_dirs, sample_limit)
        sampled = True

    missing: list[str] = []
    invalid: list[str] = []
    for module_dir in to_check:
        index_path = module_dir / "function_index.json"
        if not index_path.exists():
            # OK when module has 0 functions (e.g. forwarder DLL like sfc.dll)
            profile_path = module_dir / "module_profile.json"
            if profile_path.exists():
                try:
                    profile = json.loads(profile_path.read_text(encoding="utf-8"))
                    total_funcs = profile.get("scale", {}).get("total_functions", -1)
                    if total_funcs == 0:
                        continue
                except (json.JSONDecodeError, OSError):
                    pass
            missing.append(module_dir.name)
            continue
        vr = validate_function_index(str(index_path))
        if not vr.ok:
            invalid.append(module_dir.name)
            result.errors.extend([f"{module_dir.name}: {e}" for e in vr.errors])

    checked = len(to_check)
    n_fail = len(missing) + len(invalid)
    if sampled:
        result.detail = f"{checked}/{total} sampled, {n_fail} failed"
    else:
        result.detail = f"{checked} checked, {n_fail} failed"

    if missing:
        result.warnings.extend([f"{m}: function_index.json missing" for m in missing])
    if missing or invalid:
        result.ok = False
    return result


def check_test_suite(workspace_root: Path) -> CheckResult:
    """Step 8 (--full only): run pytest and report pass/fail counts."""
    status_message("Running test suite...")
    result = CheckResult("Test Suite")
    tests_dir = workspace_root / ".agent" / "tests"
    if not tests_dir.exists():
        result.warnings.append(f"tests/ directory not found at {tests_dir}")
        result.detail = "skipped (tests/ not found)"
        return result

    cmd = [
        sys.executable, "-m", "pytest",
        str(tests_dir),
        "-x", "-q", "--tb=short",
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(workspace_root / ".agent"),
        )
    except OSError as exc:
        result.ok = False
        result.errors.append(f"Could not run pytest: {exc}")
        return result

    output = proc.stdout + proc.stderr
    result.detail = _parse_pytest_summary(output)

    if proc.returncode != 0:
        result.ok = False
        # Capture failure lines (trim to avoid flooding)
        failure_lines = [
            line for line in output.splitlines()
            if line.strip() and not line.startswith(".")
        ]
        result.errors.extend(failure_lines[:40])
        if len(failure_lines) > 40:
            result.errors.append(
                f"... {len(failure_lines) - 40} more lines. "
                "Run: cd .agent && python -m pytest tests/ -v"
            )
    return result


def _parse_pytest_summary(output: str) -> str:
    """Extract the summary line from pytest output, e.g. '55 passed, 2 skipped'."""
    for line in reversed(output.splitlines()):
        stripped = line.strip()
        if "passed" in stripped or "failed" in stripped or "error" in stripped:
            # Remove ANSI colour codes
            import re
            clean = re.sub(r"\x1b\[[0-9;]*m", "", stripped)
            return clean
    return "no summary available"


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def run_health_check(
    workspace_root: Path,
    *,
    quick: bool = False,
    full: bool = False,
) -> HealthReport:
    report = HealthReport()

    # 1. Extraction data
    report.add(check_extraction_data(workspace_root))

    agent_dir = workspace_root / ".agent"

    # 2. Analysis DBs (skip for --quick)
    if not quick:
        db_result, tracking_result = check_analysis_dbs(workspace_root, full=full)
        report.add(db_result)
        report.add(tracking_result)

    # 3-5. Registries
    report.add(check_skills(agent_dir))
    report.add(check_agents(agent_dir))
    report.add(check_commands(agent_dir))

    # 6. Configuration
    report.add(check_configuration(agent_dir))

    # 7. Function indexes (skip for --quick)
    if not quick:
        report.add(check_function_indexes(workspace_root, full=full))

    # 8. Test suite (--full only)
    if full:
        report.add(check_test_suite(workspace_root))

    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Pre-flight workspace health check for the DeepExtractIDA runtime.",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Skip DB validation and function index checks.",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Validate every DB and index; run the pytest test suite.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit a JSON document instead of human-readable text.",
    )
    parser.add_argument(
        "--workspace",
        metavar="PATH",
        default=None,
        help="Workspace root path (default: parent of .agent/).",
    )
    args = parser.parse_args()

    if args.quick and args.full:
        print("ERROR: --quick and --full are mutually exclusive.", file=sys.stderr)
        return 1

    workspace_root = Path(args.workspace).resolve() if args.workspace else _WORKSPACE_ROOT

    report = run_health_check(workspace_root, quick=args.quick, full=args.full)

    if args.as_json:
        emit_json(report.to_dict())
    else:
        print(report.render_text())

    return 0 if report.all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
