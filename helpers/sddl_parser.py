"""SDDL ACE parsing with Deny support and effective permission computation.

Windows evaluates ACEs in order: Deny ACEs are checked before Allow ACEs.
The naive ``_is_permissive_sddl()`` in earlier code only looked for Allow
ACEs matching permissive SIDs, ignoring the possibility that a preceding
Deny ACE revokes that access.  This module corrects that.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

_ACE_RE = re.compile(
    r"\(([AD]);([^;]*);([^;]*);([^;]*);([^;]*);([^)]+)\)",
    re.IGNORECASE,
)

PERMISSIVE_SIDS = frozenset({
    "WD", "AC", "AU", "IU",
    "S-1-1-0", "S-1-15-2-1",
})


@dataclass
class ParsedACE:
    """A single parsed SDDL ACE."""

    ace_type: str   # "A" (Allow) or "D" (Deny)
    flags: str
    rights: str
    object_guid: str
    inherit_object_guid: str
    account_sid: str


def parse_sddl_aces(sddl: str) -> list[ParsedACE]:
    """Parse all ACEs from an SDDL string.

    Returns them in the order they appear, which matches Windows
    evaluation order (Deny before Allow by convention, but we respect
    whatever the SDDL actually contains).
    """
    results: list[ParsedACE] = []
    for m in _ACE_RE.finditer(sddl):
        results.append(ParsedACE(
            ace_type=m.group(1).upper(),
            flags=m.group(2),
            rights=m.group(3),
            object_guid=m.group(4),
            inherit_object_guid=m.group(5),
            account_sid=m.group(6),
        ))
    return results


def effective_permissions_for_sid(
    sddl: str,
    sid: str,
    *,
    permissive_sids: Optional[set[str]] = None,
) -> tuple[bool, str]:
    """Determine whether *sid* has effective access after Deny evaluation.

    Windows processes Deny ACEs before Allow ACEs. This function mirrors
    that logic: if any Deny ACE matches *sid*, access is revoked regardless
    of subsequent Allow ACEs.

    Returns ``(has_access, reason)`` where *reason* explains the decision.
    """
    aces = parse_sddl_aces(sddl)
    if not aces:
        return False, "no ACEs found"

    sid_upper = sid.upper()

    deny_aces = [a for a in aces if a.ace_type == "D"]
    allow_aces = [a for a in aces if a.ace_type == "A"]

    for ace in deny_aces:
        if ace.account_sid.upper() == sid_upper:
            return False, f"Deny ACE for {sid}"

    for ace in allow_aces:
        if ace.account_sid.upper() == sid_upper:
            return True, f"Allow ACE for {sid}"

    return False, f"no ACE matches {sid}"


def is_permissive_sddl(sddl: str) -> bool:
    """Check whether any permissive SID has effective access.

    A Deny ACE for a permissive SID correctly overrides a later Allow ACE
    for the same SID.  This replaces the naive regex-only check.
    """
    if not sddl:
        return False

    aces = parse_sddl_aces(sddl)
    if not aces:
        return False

    denied_sids: set[str] = set()
    for ace in aces:
        if ace.ace_type == "D":
            denied_sids.add(ace.account_sid.upper())

    for ace in aces:
        if ace.ace_type == "A":
            sid_upper = ace.account_sid.upper()
            if sid_upper in denied_sids:
                continue
            if sid_upper in {s.upper() for s in PERMISSIVE_SIDS}:
                return True

    return False
