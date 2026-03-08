"""Comparison result types and assembly extraction for the verifier.

Contains data structures for representing check results and comparison
outcomes, plus assembly-specific extraction routines for API calls and
memory offsets.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from helpers.asm_patterns import ASM_MEM_OFFSET_RE, CALL_TARGET_RE, IMP_PREFIX_RE


# ---------------------------------------------------------------------------
# Check / Comparison result types
# ---------------------------------------------------------------------------

@dataclass
class CheckResult:
    """Result of a single verification check."""
    name: str
    passed: bool
    expected: Any = None
    actual: Any = None
    details: str = ""
    severity: str = "INFO"  # INFO, WARNING, FAIL, CRITICAL
    discrepancies: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "passed": self.passed,
            "expected": self.expected,
            "actual": self.actual,
            "details": self.details,
            "severity": self.severity,
            "discrepancies": self.discrepancies,
        }


@dataclass
class ComparisonResult:
    """Complete result of comparing lifted code against original."""
    function_name: str
    function_id: int
    checks: list[CheckResult] = field(default_factory=list)
    overall_confidence: float = 0.0  # 0.0 - 1.0
    verdict: str = "UNKNOWN"  # PASS, FAIL, WARN, UNKNOWN

    @property
    def passed_count(self) -> int:
        return sum(1 for c in self.checks if c.passed)

    @property
    def failed_count(self) -> int:
        return sum(1 for c in self.checks if not c.passed)

    @property
    def total_checks(self) -> int:
        return len(self.checks)

    def add_check(self, check: CheckResult) -> None:
        self.checks.append(check)

    def compute_verdict(self) -> None:
        """Compute overall verdict and confidence from check results."""
        if not self.checks:
            self.verdict = "UNKNOWN"
            self.overall_confidence = 0.0
            return

        critical_fails = sum(1 for c in self.checks if not c.passed and c.severity == "CRITICAL")
        fails = sum(1 for c in self.checks if not c.passed and c.severity == "FAIL")
        warnings = sum(1 for c in self.checks if not c.passed and c.severity == "WARNING")
        passes = self.passed_count

        total = self.total_checks
        if total == 0:
            self.verdict = "UNKNOWN"
            self.overall_confidence = 0.0
            return

        if critical_fails > 0:
            self.verdict = "FAIL"
            self.overall_confidence = max(0.0, (passes / total) * 0.5)
        elif fails > 0:
            self.verdict = "FAIL"
            self.overall_confidence = max(0.0, (passes / total) * 0.7)
        elif warnings > 0:
            self.verdict = "WARN"
            self.overall_confidence = max(0.0, passes / total)
        else:
            self.verdict = "PASS"
            self.overall_confidence = 1.0

    def to_dict(self) -> dict:
        return {
            "function_name": self.function_name,
            "function_id": self.function_id,
            "verdict": self.verdict,
            "overall_confidence": round(self.overall_confidence, 3),
            "total_checks": self.total_checks,
            "passed": self.passed_count,
            "failed": self.failed_count,
            "checks": [c.to_dict() for c in self.checks],
        }


# ---------------------------------------------------------------------------
# Assembly-specific extraction for comparison
# ---------------------------------------------------------------------------


def extract_api_calls_from_assembly(assembly_code: str) -> list[str]:
    """Extract all API/function call targets from assembly code.

    Returns a list of unique function names called, with __imp_ prefixes
    stripped (e.g., __imp_CreateFileW -> CreateFileW).
    """
    if not assembly_code:
        return []

    calls: set[str] = set()
    for line in assembly_code.splitlines():
        line = line.strip()
        if not line:
            continue

        m = CALL_TARGET_RE.search(line)
        if m:
            target = m.group(1)
            if target:
                imp_m = IMP_PREFIX_RE.match(target)
                if imp_m:
                    target = imp_m.group(1)
                if not target.isdigit():
                    calls.add(target)

    return sorted(calls)




def extract_memory_offsets_from_assembly(
    assembly_code: str,
    parse_asm_instruction_fn=None,
) -> list[dict]:
    """Extract [base+offset] memory access patterns from assembly.

    Args:
        assembly_code: Raw assembly text.
        parse_asm_instruction_fn: Optional callable to parse an assembly
            instruction line (from verify-decompiled skill) for memory
            access size detection. If None, size defaults to 0.

    Returns:
        List of dicts with: base, offset_hex, offset_decimal, size, line.
    """
    if not assembly_code:
        return []

    accesses: list[dict] = []
    seen: set[str] = set()

    for line in assembly_code.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(";"):
            continue

        for m in ASM_MEM_OFFSET_RE.finditer(stripped):
            base = m.group(1).lower()
            offset_raw = m.group(2)

            off_str = offset_raw.rstrip("h").rstrip("H")
            try:
                offset_dec = int(off_str, 16)
            except ValueError:
                continue

            key = f"{base}+0x{offset_dec:X}"
            if key not in seen:
                seen.add(key)

                size = 0
                if parse_asm_instruction_fn:
                    inst = parse_asm_instruction_fn(stripped)
                    size = inst.memory_access_size if inst else 0

                accesses.append({
                    "base": base,
                    "offset_hex": f"0x{offset_dec:X}",
                    "offset_decimal": offset_dec,
                    "size": size,
                    "line": stripped,
                })

    return accesses
