#!/usr/bin/env python3
"""QA test runner: parse testing_guide.md, execute testable commands, report results.

Parses the machine-readable test metadata blocks from the QA test plan markdown,
resolves DB path variables, executes all script-level test cases, and produces
structured JSON + markdown reports.

Usage:
    # Run all testable test cases
    python .agent/helpers/qa_runner.py

    # Run only tests matching a prefix
    python .agent/helpers/qa_runner.py --prefix TEST-SKILL

    # Run a single test
    python .agent/helpers/qa_runner.py --test TEST-SKILL-039

    # Run tests for a specific section
    python .agent/helpers/qa_runner.py --section "Skill Scripts"

    # List all tests without running them
    python .agent/helpers/qa_runner.py --list

    # List only runnable tests with their resolved commands
    python .agent/helpers/qa_runner.py --list-runnable

    # Parallel execution with 4 workers (default: 1 = sequential)
    python .agent/helpers/qa_runner.py --workers 4

    # Use a custom QA plan file
    python .agent/helpers/qa_runner.py --plan path/to/custom_plan.md

    # Custom output directory and timeout
    python .agent/helpers/qa_runner.py --output-dir work/qa_results --timeout 120

    # JSON output (summary only, no per-test execution output)
    python .agent/helpers/qa_runner.py --json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Workspace bootstrap
# ---------------------------------------------------------------------------

_SCRIPT_DIR = Path(__file__).resolve().parent
_RUNTIME_ROOT = _SCRIPT_DIR.parent
_WORKSPACE_ROOT = _RUNTIME_ROOT.parent
_QA_PLAN_PATH = _WORKSPACE_ROOT / ".agent" / "docs" / "testing_guide.md"

if str(_RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(_RUNTIME_ROOT))

from helpers.json_output import emit_json  # noqa: E402

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

RUNNABLE_COMPONENTS = frozenset({
    "skill-script",
    "agent-script",
    "pipeline",
    "hook",
    "infrastructure",
})

SKIP_COMPONENTS = frozenset({
    "command",
    "workflow",
})


@dataclass
class TestCase:
    test_id: str
    title: str
    category: str = ""
    component: str = ""
    component_name: str = ""
    target_module: str = ""
    target_function: str = ""
    command: str = ""
    expected: str = ""
    validates: str = ""
    flags_tested: str = ""
    protocol: str = ""

    @property
    def is_runnable(self) -> bool:
        if self.component in SKIP_COMPONENTS:
            return False
        if not self.command:
            return False
        cmd = self.command.strip()
        if cmd.startswith("/"):
            return False
        if cmd.startswith("python "):
            return True
        if cmd.startswith("Create ") or cmd.startswith("Verify ") or cmd.startswith("Set "):
            return False
        return False

    @property
    def expects_json(self) -> bool:
        return "--json" in self.command

    @property
    def expects_error(self) -> bool:
        exp = self.expected.lower()
        error_codes = ["no_data", "not_found", "invalid_args",
                       "db_error", "parse_error", "ambiguous"]
        if any(code in exp for code in error_codes):
            if "status ok" in exp or "status: ok" in exp:
                return False
            # Conditional / hedged error descriptions ("may fail with INVALID_ARGS",
            # "might fail", "could fail", "possibly") describe optional outcomes and
            # must NOT be treated as a mandatory error requirement.
            if re.search(r"\b(may|might|possibly|could)\s+(fail|error)\b", exp):
                return False
            return True
        if "exit code 1" in exp:
            return True
        error_phrases = [
            "error json", "error code", "error on stderr",
            "structured error", "emit_error", "emits error",
            "returns error", "produces error", "expects error",
        ]
        if any(phrase in exp for phrase in error_phrases):
            return True
        return False

    @property
    def expects_no_data_ok(self) -> bool:
        exp = self.expected.lower()
        return "no_data" in exp and "result" in exp


@dataclass
class TestResult:
    test_id: str
    status: str  # "pass", "fail", "warn", "skip", "error", "timeout"
    exit_code: int = 0
    elapsed_s: float = 0.0
    notes: str = ""
    stdout_len: int = 0
    stderr_len: int = 0
    command: str = ""


# ---------------------------------------------------------------------------
# QA plan parser
# ---------------------------------------------------------------------------

_HEADER_RE = re.compile(r"^### (TEST-[A-Z]+-\d+):\s*(.+)$")
_META_RE = re.compile(r"^- \*\*([^*]+)\*\*:\s*(.+)$")
_CMD_BACKTICK_RE = re.compile(r"`([^`]+)`")


def parse_qa_plan(plan_path: Path) -> list[TestCase]:
    """Parse all test cases from the QA plan markdown file."""
    tests: list[TestCase] = []
    current: Optional[TestCase] = None

    text = plan_path.read_text(encoding="utf-8")
    for line in text.splitlines():
        header = _HEADER_RE.match(line)
        if header:
            if current:
                tests.append(current)
            current = TestCase(test_id=header.group(1), title=header.group(2))
            continue

        if current is None:
            continue

        meta = _META_RE.match(line)
        if meta:
            key = meta.group(1).strip().lower().replace("-", "_")
            value = meta.group(2).strip()

            if key == "category":
                current.category = value
            elif key == "component":
                current.component = value
            elif key in ("component_name", "component name"):
                current.component_name = value
            elif key in ("target_module", "target module"):
                current.target_module = value
            elif key in ("target_function", "target function"):
                current.target_function = value
            elif key == "command":
                m = _CMD_BACKTICK_RE.search(value)
                current.command = m.group(1) if m else value
            elif key == "expected":
                current.expected = value
            elif key == "validates":
                current.validates = value
            elif key in ("flags_tested", "flags tested"):
                current.flags_tested = value
            elif key == "protocol":
                current.protocol = value

    if current:
        tests.append(current)

    return tests


# ---------------------------------------------------------------------------
# Variable resolution
# ---------------------------------------------------------------------------


def resolve_db_paths(workspace: Path) -> dict[str, str]:
    """Discover DB path aliases by running find_module_db.py.

    Builds two tiers of aliases per module so that exact matches always win
    over substring fallback.  For a module named ``appinfo.dll`` whose DB
    is ``appinfo_dll_f2bbf324a1.db`` we register:

    * ``appinfo_dll`` -> exact key (derived from ``file_name`` with dots/dashes
      replaced by underscores)
    * ``appinfo``     -> short key (the stem before the first dot in
      ``file_name``).  Only registered when there is no collision with
      another module's short key.
    """
    aliases: dict[str, str] = {}
    short_keys: dict[str, list[str]] = {}
    script = workspace / ".agent/skills/decompiled-code-extractor/scripts/find_module_db.py"
    if not script.exists():
        return aliases

    try:
        r = subprocess.run(
            ["python", str(script), "--list", "--json"],
            capture_output=True, text=True, cwd=str(workspace), timeout=30,
        )
        if r.returncode == 0 and r.stdout.strip():
            data = json.loads(r.stdout)
            for mod in data.get("modules", []):
                name = mod.get("file_name", "")
                db = mod.get("analysis_db_path", "")
                if name and db:
                    db_path = f"extracted_dbs/{db}" if not db.startswith("extracted_dbs") else db
                    full_key = name.lower().replace(".", "_").replace("-", "_")
                    aliases[full_key] = db_path

                    short = name.split(".")[0].lower().replace("-", "_")
                    short_keys.setdefault(short, []).append(db_path)

            for short, paths in short_keys.items():
                if short not in aliases and len(paths) == 1:
                    aliases[short] = paths[0]
    except Exception:
        pass

    return aliases


_VAR_RE = re.compile(r"<db:(\w+)>")


def resolve_command(
    command: str,
    db_aliases: dict[str, str],
    workspace: Path,
) -> Optional[list[str]]:
    """Resolve a command string into an argument list ready for subprocess.

    Returns None if the command is not runnable (slash command, manual step, etc.)
    """
    cmd = command.strip()
    if cmd.startswith("/"):
        return None
    if not cmd.startswith("python "):
        return None

    def _replace_db(m: re.Match) -> str:
        alias = m.group(1).lower()
        if alias in db_aliases:
            return db_aliases[alias]
        # Fallback: try alias + "_dll", alias + "_exe" etc.
        for suffix in ("_dll", "_exe", "_sys", "_drv"):
            candidate = alias + suffix
            if candidate in db_aliases:
                return db_aliases[candidate]
        return m.group(0)

    resolved = _VAR_RE.sub(_replace_db, cmd)
    resolved = resolved.replace("<path>", os.devnull)

    # Strip shell redirections (subprocess.run captures output already)
    resolved = re.sub(r"\s+2>\S+", "", resolved)
    resolved = re.sub(r"\s+2>&1", "", resolved)
    resolved = re.sub(r"\s+>\S+", "", resolved)

    if "<" in resolved and ">" in resolved:
        return None

    # Always use posix=True to avoid Windows shlex preserving literal quotes
    try:
        parts = shlex.split(resolved, posix=True)
    except ValueError:
        parts = resolved.split()

    return parts


# ---------------------------------------------------------------------------
# Test execution
# ---------------------------------------------------------------------------


def run_one_test(
    tc: TestCase,
    cmd_parts: list[str],
    workspace: Path,
    timeout: int = 120,
) -> TestResult:
    """Execute a single test case and return the result."""
    cmd_str = " ".join(cmd_parts)

    try:
        start = time.time()
        proc = subprocess.run(
            cmd_parts,
            capture_output=True,
            text=True,
            cwd=str(workspace),
            timeout=timeout,
        )
        elapsed = time.time() - start
    except subprocess.TimeoutExpired:
        return TestResult(
            test_id=tc.test_id, status="timeout", exit_code=-1,
            elapsed_s=float(timeout),
            notes=f"TIMEOUT after {timeout}s", command=cmd_str,
        )
    except Exception as e:
        return TestResult(
            test_id=tc.test_id, status="error", exit_code=-1,
            notes=f"Exception: {e}", command=cmd_str,
        )

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    return _evaluate_proc(tc, proc, stdout, stderr, elapsed, cmd_str)


# ---------------------------------------------------------------------------
# Result persistence
# ---------------------------------------------------------------------------


def save_result(result: TestResult, output_dir: Path, tc: TestCase,
                stdout: str = "", stderr: str = "") -> None:
    """Write per-test result files for failing or warning tests."""
    if result.status in ("pass",):
        return

    test_dir = output_dir / result.test_id
    test_dir.mkdir(parents=True, exist_ok=True)

    (test_dir / "command.txt").write_text(result.command + "\n", encoding="utf-8")
    (test_dir / "result.json").write_text(
        json.dumps(asdict(result), indent=2), encoding="utf-8"
    )
    if stdout:
        (test_dir / "stdout.txt").write_text(stdout, encoding="utf-8")
    if stderr:
        (test_dir / "stderr.txt").write_text(stderr, encoding="utf-8")
    if result.status == "warn" and result.notes:
        (test_dir / "warnings.txt").write_text(result.notes, encoding="utf-8")


def save_result_with_output(
    tc: TestCase,
    cmd_parts: list[str],
    workspace: Path,
    output_dir: Path,
    timeout: int = 120,
) -> TestResult:
    """Run test, save full output for non-passing tests, return result."""
    cmd_str = " ".join(cmd_parts)

    try:
        start = time.time()
        proc = subprocess.run(
            cmd_parts, capture_output=True, text=True,
            cwd=str(workspace), timeout=timeout,
        )
        elapsed = time.time() - start
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
    except subprocess.TimeoutExpired:
        result = TestResult(
            test_id=tc.test_id, status="timeout", exit_code=-1,
            elapsed_s=float(timeout), notes=f"TIMEOUT after {timeout}s",
            command=cmd_str,
        )
        save_result(result, output_dir, tc)
        return result
    except Exception as e:
        result = TestResult(
            test_id=tc.test_id, status="error", exit_code=-1,
            notes=f"Exception: {e}", command=cmd_str,
        )
        save_result(result, output_dir, tc)
        return result

    result = _evaluate_proc(tc, proc, stdout, stderr, elapsed, cmd_str)
    save_result(result, output_dir, tc, stdout, stderr)
    return result


_STDERR_ISSUE_PATTERNS = (
    "Traceback",
    '{"error"',
    "Exception",
    "CRITICAL:",
    "FAILED",
)


def _stderr_has_real_issues(stderr: str) -> bool:
    """Return True if stderr contains patterns indicating a real problem.

    Benign progress output ([status] ..., {"progress": ...}, plain text
    progress) is expected on stderr per the JSON output convention and
    should not trigger a warning.
    """
    return any(p in stderr for p in _STDERR_ISSUE_PATTERNS)


def _evaluate_proc(
    tc: TestCase, proc: subprocess.CompletedProcess,
    stdout: str, stderr: str, elapsed: float, cmd_str: str,
) -> TestResult:
    """Evaluate a completed process result (shared logic)."""

    if tc.expects_error:
        if proc.returncode != 0:
            for line in stderr.strip().splitlines():
                try:
                    err = json.loads(line.strip())
                    if "error" in err and "code" in err:
                        return TestResult(
                            test_id=tc.test_id, status="pass",
                            exit_code=proc.returncode, elapsed_s=elapsed,
                            stdout_len=len(stdout), stderr_len=len(stderr),
                            command=cmd_str,
                        )
                except Exception:
                    pass
            return TestResult(
                test_id=tc.test_id, status="fail", exit_code=proc.returncode,
                elapsed_s=elapsed,
                notes="Expected structured error JSON on stderr but not found",
                stdout_len=len(stdout), stderr_len=len(stderr), command=cmd_str,
            )
        return TestResult(
            test_id=tc.test_id, status="fail", exit_code=0,
            elapsed_s=elapsed, notes="Expected non-zero exit but got 0",
            stdout_len=len(stdout), stderr_len=len(stderr), command=cmd_str,
        )

    if proc.returncode != 0:
        if tc.expects_no_data_ok:
            for line in stderr.strip().splitlines():
                try:
                    if json.loads(line.strip()).get("code") == "NO_DATA":
                        return TestResult(
                            test_id=tc.test_id, status="pass",
                            exit_code=proc.returncode, elapsed_s=elapsed,
                            notes="NO_DATA (acceptable)",
                            stdout_len=len(stdout), stderr_len=len(stderr),
                            command=cmd_str,
                        )
                except Exception:
                    pass
        return TestResult(
            test_id=tc.test_id, status="fail", exit_code=proc.returncode,
            elapsed_s=elapsed,
            notes=stderr.strip()[:300] if stderr.strip() else "non-zero exit",
            stdout_len=len(stdout), stderr_len=len(stderr), command=cmd_str,
        )

    if tc.expects_json:
        if not stdout.strip():
            return TestResult(
                test_id=tc.test_id, status="fail", exit_code=0,
                elapsed_s=elapsed, notes="stdout is empty (expected JSON)",
                stdout_len=0, stderr_len=len(stderr), command=cmd_str,
            )
        try:
            data = json.loads(stdout.strip())
            if not isinstance(data, dict):
                return TestResult(
                    test_id=tc.test_id, status="fail", exit_code=0,
                    elapsed_s=elapsed,
                    notes=f"JSON is {type(data).__name__}, expected dict",
                    stdout_len=len(stdout), stderr_len=len(stderr), command=cmd_str,
                )
            sv = data.get("status")
            if sv not in ("ok", "error"):
                return TestResult(
                    test_id=tc.test_id, status="fail", exit_code=0,
                    elapsed_s=elapsed,
                    notes=f"JSON status={sv!r}, expected 'ok' or 'error'",
                    stdout_len=len(stdout), stderr_len=len(stderr), command=cmd_str,
                )
        except json.JSONDecodeError as e:
            return TestResult(
                test_id=tc.test_id, status="fail", exit_code=0,
                elapsed_s=elapsed, notes=f"Invalid JSON: {e}",
                stdout_len=len(stdout), stderr_len=len(stderr), command=cmd_str,
            )

    if stderr.strip() and _stderr_has_real_issues(stderr):
        return TestResult(
            test_id=tc.test_id, status="warn", exit_code=0,
            elapsed_s=elapsed, notes=stderr.strip()[:500],
            stdout_len=len(stdout), stderr_len=len(stderr), command=cmd_str,
        )

    return TestResult(
        test_id=tc.test_id, status="pass", exit_code=0, elapsed_s=elapsed,
        stdout_len=len(stdout), stderr_len=len(stderr), command=cmd_str,
    )


def _run_single_test(
    test_id: str,
    cmd_parts: list[str],
    original_command: str,
    expected: str,
    workspace_str: str,
    output_dir_str: str,
    timeout: int,
) -> tuple[str, TestResult, str, str]:
    """Execute one test in a worker process. Returns (test_id, result, stdout, stderr).

    All arguments are pickle-safe primitives / lists so this works with
    ProcessPoolExecutor.
    """
    cmd_str = " ".join(cmd_parts)
    workspace = Path(workspace_str)
    output_dir = Path(output_dir_str)

    tc_stub = TestCase(
        test_id=test_id, title="",
        command=original_command, expected=expected,
    )

    try:
        start = time.time()
        proc = subprocess.run(
            cmd_parts, capture_output=True, text=True,
            cwd=str(workspace), timeout=timeout,
        )
        elapsed = time.time() - start
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        result = _evaluate_proc(tc_stub, proc, stdout, stderr, elapsed, cmd_str)
    except subprocess.TimeoutExpired:
        result = TestResult(
            test_id=test_id, status="timeout", exit_code=-1,
            elapsed_s=float(timeout),
            notes=f"TIMEOUT after {timeout}s", command=cmd_str,
        )
        stdout, stderr = "", ""
    except Exception as e:
        result = TestResult(
            test_id=test_id, status="error", exit_code=-1,
            notes=f"Exception: {e}", command=cmd_str,
        )
        stdout, stderr = "", ""

    save_result(result, output_dir, tc_stub, stdout, stderr)
    return test_id, result, stdout, stderr


# ---------------------------------------------------------------------------
# Summary generation
# ---------------------------------------------------------------------------


def generate_summary(
    results: list[TestResult],
    skipped: list[TestCase],
    output_dir: Path,
) -> dict[str, Any]:
    """Generate and write JSON + markdown summaries."""
    by_status: dict[str, list[TestResult]] = {}
    for r in results:
        by_status.setdefault(r.status, []).append(r)

    summary = {
        "total_executed": len(results),
        "total_skipped": len(skipped),
        "pass": len(by_status.get("pass", [])),
        "warn": len(by_status.get("warn", [])),
        "fail": len(by_status.get("fail", [])),
        "timeout": len(by_status.get("timeout", [])),
        "error": len(by_status.get("error", [])),
        "failures": [
            {"test_id": r.test_id, "exit_code": r.exit_code,
             "elapsed_s": r.elapsed_s, "notes": r.notes[:200]}
            for r in sorted(results, key=lambda x: x.test_id)
            if r.status in ("fail", "timeout", "error")
        ],
        "warnings": [
            {"test_id": r.test_id, "elapsed_s": r.elapsed_s,
             "notes": r.notes[:100]}
            for r in sorted(results, key=lambda x: x.test_id)
            if r.status == "warn"
        ],
    }

    (output_dir / "SUMMARY.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8",
    )

    lines = [
        "# QA Test Run Summary\n",
        f"| Metric | Count |",
        f"|--------|-------|",
        f"| Executed | {summary['total_executed']} |",
        f"| Passed | {summary['pass']} |",
        f"| Warnings | {summary['warn']} |",
        f"| Failed | {summary['fail']} |",
        f"| Timeout | {summary['timeout']} |",
        f"| Error | {summary['error']} |",
        f"| Skipped | {summary['total_skipped']} |",
        "",
    ]

    if summary["failures"]:
        lines.append("## Failures\n")
        lines.append("| Test ID | Exit | Time | Notes |")
        lines.append("|---------|------|------|-------|")
        for f in summary["failures"]:
            notes = f["notes"].replace("|", "\\|").replace("\n", " ")[:80]
            lines.append(
                f"| {f['test_id']} | {f['exit_code']} | {f['elapsed_s']:.1f}s | {notes} |"
            )
        lines.append("")

    if summary["warnings"]:
        lines.append("## Warnings\n")
        lines.append("| Test ID | Time | Notes |")
        lines.append("|---------|------|-------|")
        for w in summary["warnings"]:
            notes = w["notes"].replace("|", "\\|").replace("\n", " ")[:60]
            lines.append(f"| {w['test_id']} | {w['elapsed_s']:.1f}s | {notes} |")
        lines.append("")

    (output_dir / "SUMMARY.md").write_text("\n".join(lines), encoding="utf-8")
    return summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Run QA test cases from the QA test plan.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--plan", default=str(_QA_PLAN_PATH),
        help="Path to testing guide markdown (default: .agent/docs/testing_guide.md)",
    )
    parser.add_argument(
        "--prefix", default=None,
        help="Run only tests whose ID starts with this prefix (e.g. TEST-SKILL)",
    )
    parser.add_argument(
        "--test", default=None,
        help="Run a single test by ID (e.g. TEST-SKILL-039)",
    )
    parser.add_argument(
        "--section", default=None,
        help="Run tests matching a section/category keyword (e.g. 'infrastructure')",
    )
    parser.add_argument(
        "--list", action="store_true", dest="list_only",
        help="List all parsed tests without running them",
    )
    parser.add_argument(
        "--list-runnable", action="store_true",
        help="List only runnable tests",
    )
    parser.add_argument(
        "--output-dir", default=str(_WORKSPACE_ROOT / "work" / "testcase_output"),
        help="Directory for test result output",
    )
    parser.add_argument("--timeout", type=int, default=120, help="Per-test timeout in seconds")
    parser.add_argument("--workers", type=int, default=1,
                        help="Number of parallel worker processes (default: 1 = sequential)")
    parser.add_argument("--json", action="store_true", help="Print JSON summary to stdout")

    from helpers.errors import safe_parse_args
    args = safe_parse_args(parser)

    plan_path = Path(args.plan)
    if not plan_path.exists():
        print(f"QA plan not found: {plan_path}", file=sys.stderr)
        sys.exit(1)

    workspace = _WORKSPACE_ROOT
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Parsing QA plan: {plan_path}", file=sys.stderr)
    all_tests = parse_qa_plan(plan_path)
    print(f"Parsed {len(all_tests)} test cases", file=sys.stderr)

    if args.prefix:
        all_tests = [t for t in all_tests if t.test_id.startswith(args.prefix)]
    if args.test:
        all_tests = [t for t in all_tests if t.test_id == args.test]
    if args.section:
        kw = args.section.lower()
        all_tests = [t for t in all_tests
                     if kw in t.category.lower() or kw in t.title.lower()
                     or kw in t.component.lower()]

    if args.list_only:
        for t in all_tests:
            runnable = "RUNNABLE" if t.is_runnable else "SKIP"
            print(f"{t.test_id:20s} [{runnable:8s}] {t.component:15s} {t.title}")
        print(f"\nTotal: {len(all_tests)} | "
              f"Runnable: {sum(1 for t in all_tests if t.is_runnable)} | "
              f"Skip: {sum(1 for t in all_tests if not t.is_runnable)}")
        return

    if args.list_runnable:
        runnable = [t for t in all_tests if t.is_runnable]
        for t in runnable:
            print(f"{t.test_id:20s} {t.command}")
        print(f"\nRunnable: {len(runnable)}")
        return

    print("Resolving DB path aliases...", file=sys.stderr)
    db_aliases = resolve_db_paths(workspace)
    print(f"Resolved {len(db_aliases)} DB aliases", file=sys.stderr)

    runnable: list[TestCase] = []
    skipped: list[TestCase] = []

    for tc in all_tests:
        if not tc.is_runnable:
            skipped.append(tc)
            continue
        cmd_parts = resolve_command(tc.command, db_aliases, workspace)
        if cmd_parts is None:
            skipped.append(tc)
            continue
        tc._resolved_cmd = cmd_parts  # type: ignore[attr-defined]
        runnable.append(tc)

    print(f"\nRunnable: {len(runnable)} | Skipped: {len(skipped)}", file=sys.stderr)
    print(f"Output: {output_dir}\n", file=sys.stderr)

    icon = {"pass": "PASS", "warn": "WARN", "fail": "FAIL",
            "timeout": "TIME", "error": "ERR!", "skip": "SKIP"}

    results: list[TestResult] = []
    n_workers = max(1, args.workers)

    if n_workers <= 1:
        for i, tc in enumerate(runnable, 1):
            cmd_parts = tc._resolved_cmd  # type: ignore[attr-defined]
            cmd_str = " ".join(cmd_parts)
            tag = f"[{i}/{len(runnable)}]"
            print(f"{tag} {tc.test_id}: {cmd_str[:90]}", file=sys.stderr)

            try:
                start = time.time()
                proc = subprocess.run(
                    cmd_parts, capture_output=True, text=True,
                    cwd=str(workspace), timeout=args.timeout,
                )
                elapsed = time.time() - start
                stdout = proc.stdout or ""
                stderr = proc.stderr or ""
                result = _evaluate_proc(tc, proc, stdout, stderr, elapsed, cmd_str)
            except subprocess.TimeoutExpired:
                result = TestResult(
                    test_id=tc.test_id, status="timeout", exit_code=-1,
                    elapsed_s=float(args.timeout),
                    notes=f"TIMEOUT after {args.timeout}s", command=cmd_str,
                )
                stdout, stderr = "", ""
            except Exception as e:
                result = TestResult(
                    test_id=tc.test_id, status="error", exit_code=-1,
                    notes=f"Exception: {e}", command=cmd_str,
                )
                stdout, stderr = "", ""

            results.append(result)
            save_result(result, output_dir, tc, stdout, stderr)

            print(
                f"  [{icon.get(result.status, '????')}] {result.elapsed_s:.1f}s"
                f"{(' -- ' + result.notes[:60]) if result.notes and result.status != 'warn' else ''}",
                file=sys.stderr,
            )
    else:
        print(f"Running with {n_workers} parallel workers\n", file=sys.stderr)
        futures_map: dict[Any, TestCase] = {}
        with ProcessPoolExecutor(max_workers=n_workers) as pool:
            for tc in runnable:
                cmd_parts = tc._resolved_cmd  # type: ignore[attr-defined]
                fut = pool.submit(
                    _run_single_test,
                    tc.test_id,
                    cmd_parts,
                    tc.command,
                    tc.expected,
                    str(workspace),
                    str(output_dir),
                    args.timeout,
                )
                futures_map[fut] = tc

            done_count = 0
            for fut in as_completed(futures_map):
                done_count += 1
                tc = futures_map[fut]
                try:
                    _, result, _, _ = fut.result()
                except Exception as e:
                    result = TestResult(
                        test_id=tc.test_id, status="error", exit_code=-1,
                        notes=f"Worker exception: {e}",
                        command=" ".join(tc._resolved_cmd),  # type: ignore[attr-defined]
                    )
                results.append(result)
                tag = f"[{done_count}/{len(runnable)}]"
                print(
                    f"{tag} {tc.test_id}: "
                    f"[{icon.get(result.status, '????')}] {result.elapsed_s:.1f}s"
                    f"{(' -- ' + result.notes[:60]) if result.notes and result.status != 'warn' else ''}",
                    file=sys.stderr,
                )

    summary = generate_summary(results, skipped, output_dir)
    total = summary["total_executed"]
    print(
        f"\n{'='*60}\n"
        f"DONE: {total} executed | "
        f"{summary['pass']} pass | {summary['warn']} warn | "
        f"{summary['fail']} fail | {summary['timeout']} timeout | "
        f"{summary['error']} error | {summary['total_skipped']} skipped\n"
        f"Results: {output_dir}\n"
        f"{'='*60}",
        file=sys.stderr,
    )

    if args.json:
        emit_json(summary)


if __name__ == "__main__":
    main()
