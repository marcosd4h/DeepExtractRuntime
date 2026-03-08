"""Semantic classification for RPC procedure names.

Classifies procedure names into semantic categories (read, mutation, destroy,
handle, identity, execute) and assigns a heuristic risk score based on the
category and procedure naming patterns.

Typical usage::

    from helpers.rpc_procedure_classifier import classify_procedure, classify_procedures

    cls = classify_procedure("RpcAddPrinter")
    print(cls)  # ("mutation", 0.7, "Add")

    results = classify_procedures(["RpcEnumPrinters", "RpcDeletePrinter", "RpcOpenPrinter"])
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Pattern table
# ---------------------------------------------------------------------------

_PROCEDURE_PATTERNS: list[tuple[str, re.Pattern, float]] = [
    ("identity",  re.compile(r"(?:WithIdentity|AsUser|Impersonat|LogonUser|Elevat|CredentialProvider)", re.I), 0.9),
    ("execute",   re.compile(r"(?:^|_)(?:Execute|Run|Launch|Start|Invoke|Dispatch|Spawn|Shell)", re.I), 0.8),
    ("mutation",  re.compile(r"(?:^|_)(?:Set|Add|Create|Put|Update|Write|Modify|Register|Install|Configure|Enable|Assign|Store|Push|Insert|Submit|Upload)", re.I), 0.7),
    ("destroy",   re.compile(r"(?:^|_)(?:Delete|Remove|Unregister|Destroy|Clear|Reset|Drop|Disable|Purge|Revoke|Uninstall|Erase|Wipe)", re.I), 0.7),
    ("handle",    re.compile(r"(?:^|_)(?:Open|Close|Bind|Connect|Disconnect|Release|Attach|Detach|Lock|Unlock|Abort|Cancel|Suspend|Resume|Shutdown)", re.I), 0.5),
    ("read",      re.compile(r"(?:^|_)(?:Enum|Get|Query|List|Read|Find|Count|Check|Is|Has|Lookup|Fetch|Retrieve|Load|Search|Peek|Select|Describe|Stat|Verify|Validate|Test|Probe|Ping|Poll|Notify|Wait|Subscribe|Watch|Monitor)", re.I), 0.3),
]

_PREFIX_STRIP_RE = re.compile(
    r"^(?:Rpc|s_|EvtRpc_s_|Elf|Netr?|Sam[r]?|Lsa[r]?|Srv[r]?|Wks[r]?|Svc|Dfs|Drs|Efs|Frs)",
    re.I,
)


@dataclass
class ProcedureClassification:
    """Result of classifying a single procedure name."""
    name: str
    semantic_class: str
    risk_score: float
    matched_keyword: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "semantic_class": self.semantic_class,
            "risk_score": round(self.risk_score, 2),
            "matched_keyword": self.matched_keyword,
        }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def classify_procedure(name: str) -> ProcedureClassification:
    """Classify a single RPC procedure name.

    Returns a ``ProcedureClassification`` with the semantic class,
    risk score (0.0--1.0), and the keyword that triggered the match.
    Falls back to ``"unknown"`` with a score of 0.5 when no pattern
    matches.
    """
    stripped = _PREFIX_STRIP_RE.sub("", name)

    for sem_class, pattern, score in _PROCEDURE_PATTERNS:
        m = pattern.search(stripped)
        if m:
            return ProcedureClassification(
                name=name,
                semantic_class=sem_class,
                risk_score=score,
                matched_keyword=m.group(0),
            )

    return ProcedureClassification(
        name=name,
        semantic_class="unknown",
        risk_score=0.5,
        matched_keyword="",
    )


def classify_procedures(
    names: list[str],
) -> list[ProcedureClassification]:
    """Classify a batch of procedure names."""
    return [classify_procedure(n) for n in names]


def summarize_classifications(
    classifications: list[ProcedureClassification],
) -> dict[str, Any]:
    """Aggregate classification results into a summary dict."""
    by_class: dict[str, int] = {}
    total_risk = 0.0
    high_risk: list[str] = []

    for c in classifications:
        by_class[c.semantic_class] = by_class.get(c.semantic_class, 0) + 1
        total_risk += c.risk_score
        if c.risk_score >= 0.7:
            high_risk.append(c.name)

    avg_risk = total_risk / len(classifications) if classifications else 0.0

    return {
        "total_procedures": len(classifications),
        "by_class": by_class,
        "average_risk": round(avg_risk, 3),
        "high_risk_procedures": high_risk,
        "high_risk_count": len(high_risk),
    }
