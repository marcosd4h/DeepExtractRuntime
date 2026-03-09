"""Parameter risk scoring for function signatures.

Scores how dangerous a function's parameters look from an attacker's
perspective by matching type patterns (buffer pointers, handles, COM
interfaces, size parameters) and detecting buffer+size pair combinations.

Extracted from the map-attack-surface skill for reuse across skills.
"""

from __future__ import annotations

import re
from typing import Optional

__all__ = [
    "HIGH_RISK_PARAM_PATTERNS",
    "BUFFER_SIZE_PAIR_PATTERNS",
    "score_parameter_risk",
]

# Type patterns that indicate attacker-controllable input
HIGH_RISK_PARAM_PATTERNS: list[tuple[str, float]] = [
    # Buffer + size pairs (highest risk)
    (r"(?:void|PVOID|LPVOID|char|BYTE|PBYTE|LPBYTE)\s*\*", 1.0),
    (r"(?:wchar_t|WCHAR|LPWSTR|PWSTR|OLECHAR)\s*\*", 0.9),
    (r"(?:LPSTR|LPCSTR|PSTR|PCSTR|char\s+const)\s*\*?", 0.9),
    (r"(?:LPCWSTR|PCWSTR|wchar_t\s+const)\s*\*?", 0.85),
    (r"(?:BSTR|VARIANT|SAFEARRAY)", 0.85),
    # Size/length parameters (amplifiers when paired with buffers)
    (r"(?:DWORD|ULONG|SIZE_T|size_t|unsigned|int)\b", 0.3),
    # Handle parameters (moderate -- can reference attacker objects)
    (r"(?:HANDLE|HKEY|HMODULE|HINSTANCE|SOCKET|HWND)", 0.5),
    # Interface pointers (COM attack surface)
    (r"(?:IUnknown|IDispatch|I[A-Z]\w+)\s*\*", 0.7),
    (r"(?:REFIID|REFCLSID|GUID|IID)", 0.4),
    # Struct pointers
    (r"(?:struct|SECURITY_ATTRIBUTES|OVERLAPPED)\s*\*", 0.5),
    # Flags (low risk alone but can change behavior)
    (r"(?:FLAGS|ULONG|DWORD)\b.*(?:flags|options|mode)", 0.2),
]

BUFFER_SIZE_PAIR_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?:void|char|BYTE|wchar_t|WCHAR)\s*\*.*,\s*(?:DWORD|ULONG|SIZE_T|size_t|unsigned|int)\b", re.I),
    re.compile(r"(?:LPVOID|PVOID|LPBYTE|PBYTE)\s.*,\s*(?:DWORD|ULONG|SIZE_T|size_t|unsigned)\b", re.I),
    re.compile(r"(?:LPWSTR|LPSTR|PWSTR|PSTR)\s.*,\s*(?:DWORD|ULONG|SIZE_T|int|unsigned)\b", re.I),
]


def score_parameter_risk(signature: Optional[str]) -> tuple[float, list[str]]:
    """Score parameter risk from a function signature.

    Returns (risk_score 0.0-1.0, list of risk reasons).
    """
    if not signature:
        return 0.0, []

    risk = 0.0
    reasons: list[str] = []

    # Check for buffer+size pairs (highest risk)
    for pat in BUFFER_SIZE_PAIR_PATTERNS:
        if pat.search(signature):
            risk = max(risk, 0.9)
            reasons.append("buffer+size parameter pair")
            break

    # Score individual parameters
    paren_match = re.search(r"\(([^)]*)\)", signature)
    if not paren_match:
        return risk, reasons

    param_str = paren_match.group(1)
    if not param_str.strip() or param_str.strip().lower() in ("void", ""):
        return 0.1, ["no parameters (limited attack surface)"]

    params = [p.strip() for p in param_str.split(",") if p.strip()]
    param_scores: list[float] = []

    for param in params:
        best_score = 0.0
        for pattern, score in HIGH_RISK_PARAM_PATTERNS:
            if re.search(pattern, param, re.I):
                best_score = max(best_score, score)
        param_scores.append(best_score)

    if param_scores:
        max_param = max(param_scores)
        avg_param = sum(param_scores) / len(param_scores)
        # Weighted: max matters more but count of risky params amplifies
        combined = max_param * 0.6 + avg_param * 0.2 + min(len(params) / 10.0, 0.2)
        risk = max(risk, min(combined, 1.0))

        if max_param >= 0.8:
            reasons.append("high-risk pointer/buffer parameters")
        elif max_param >= 0.5:
            reasons.append("handle/interface pointer parameters")

    return risk, reasons
