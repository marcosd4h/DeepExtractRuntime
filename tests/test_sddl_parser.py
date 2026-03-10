"""Tests for helpers/sddl_parser.py -- SDDL ACE parsing with Deny support.

Covers:
  - parse_sddl_aces (extraction of ACE structs from SDDL strings)
  - effective_permissions_for_sid (Deny-before-Allow evaluation)
  - is_permissive_sddl (backward-compatible convenience, Deny-aware)
  - Edge cases (empty SDDL, no ACEs, mixed Deny+Allow, multiple SIDs)
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_AGENT_DIR = Path(__file__).resolve().parent.parent
if str(_AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENT_DIR))

from helpers.sddl_parser import (
    PERMISSIVE_SIDS,
    ParsedACE,
    effective_permissions_for_sid,
    is_permissive_sddl,
    parse_sddl_aces,
)


# ===================================================================
# parse_sddl_aces
# ===================================================================

class TestParseSddlAces:
    """Tests for ACE extraction from SDDL strings."""

    def test_single_allow(self):
        sddl = "O:PSG:BUD:(A;;CCDCLCSWRP;;;WD)"
        aces = parse_sddl_aces(sddl)
        assert len(aces) == 1
        assert aces[0].ace_type == "A"
        assert aces[0].account_sid == "WD"

    def test_single_deny(self):
        sddl = "(D;;GA;;;WD)"
        aces = parse_sddl_aces(sddl)
        assert len(aces) == 1
        assert aces[0].ace_type == "D"
        assert aces[0].account_sid == "WD"

    def test_multiple_aces(self):
        sddl = "O:SYG:SYD:(D;;GA;;;WD)(A;;CCDCLCSWRP;;;AC)(A;;GA;;;SY)"
        aces = parse_sddl_aces(sddl)
        assert len(aces) == 3
        assert aces[0].ace_type == "D"
        assert aces[0].account_sid == "WD"
        assert aces[1].ace_type == "A"
        assert aces[1].account_sid == "AC"
        assert aces[2].ace_type == "A"
        assert aces[2].account_sid == "SY"

    def test_empty_string(self):
        assert parse_sddl_aces("") == []

    def test_no_aces(self):
        assert parse_sddl_aces("O:SYG:SYD:") == []

    def test_rights_preserved(self):
        sddl = "(A;;CCDCLCSWRP;;;WD)"
        aces = parse_sddl_aces(sddl)
        assert aces[0].rights == "CCDCLCSWRP"

    def test_flags_preserved(self):
        sddl = "(A;OICI;GA;;;WD)"
        aces = parse_sddl_aces(sddl)
        assert aces[0].flags == "OICI"

    def test_sid_string(self):
        sddl = "(A;;GA;;;S-1-1-0)"
        aces = parse_sddl_aces(sddl)
        assert len(aces) == 1
        assert aces[0].account_sid == "S-1-1-0"

    def test_case_insensitive(self):
        sddl = "(a;;ga;;;wd)"
        aces = parse_sddl_aces(sddl)
        assert len(aces) == 1
        assert aces[0].ace_type == "A"


# ===================================================================
# effective_permissions_for_sid
# ===================================================================

class TestEffectivePermissions:
    """Tests for Deny-before-Allow SID evaluation."""

    def test_allow_grants_access(self):
        sddl = "(A;;GA;;;WD)"
        has_access, reason = effective_permissions_for_sid(sddl, "WD")
        assert has_access is True
        assert "Allow" in reason

    def test_deny_blocks_access(self):
        sddl = "(D;;GA;;;WD)"
        has_access, reason = effective_permissions_for_sid(sddl, "WD")
        assert has_access is False
        assert "Deny" in reason

    def test_deny_overrides_allow(self):
        sddl = "(D;;GA;;;WD)(A;;GA;;;WD)"
        has_access, reason = effective_permissions_for_sid(sddl, "WD")
        assert has_access is False
        assert "Deny" in reason

    def test_allow_after_deny_for_different_sid(self):
        sddl = "(D;;GA;;;BA)(A;;GA;;;WD)"
        has_access, reason = effective_permissions_for_sid(sddl, "WD")
        assert has_access is True

    def test_no_matching_ace(self):
        sddl = "(A;;GA;;;SY)"
        has_access, reason = effective_permissions_for_sid(sddl, "WD")
        assert has_access is False
        assert "no ACE matches" in reason

    def test_empty_sddl(self):
        has_access, reason = effective_permissions_for_sid("", "WD")
        assert has_access is False
        assert "no ACEs found" in reason

    def test_case_insensitive_sid_match(self):
        sddl = "(A;;GA;;;wd)"
        has_access, _ = effective_permissions_for_sid(sddl, "WD")
        assert has_access is True

    def test_sid_string_match(self):
        sddl = "(A;;GA;;;S-1-1-0)"
        has_access, _ = effective_permissions_for_sid(sddl, "S-1-1-0")
        assert has_access is True

    def test_deny_then_allow_same_sid(self):
        sddl = "O:SYG:SYD:(D;;GA;;;AC)(A;;CCDCLCSWRP;;;AC)"
        has_access, reason = effective_permissions_for_sid(sddl, "AC")
        assert has_access is False
        assert "Deny" in reason


# ===================================================================
# is_permissive_sddl
# ===================================================================

class TestIsPermissiveSddl:
    """Tests for the backward-compatible permissive check."""

    def test_allow_wd_is_permissive(self):
        assert is_permissive_sddl("O:PSG:BUD:(A;;CCDCLCSWRP;;;WD)") is True

    def test_allow_ac_is_permissive(self):
        assert is_permissive_sddl("O:PSG:BUD:(A;;CCDCLCSWRP;;;AC)") is True

    def test_allow_au_is_permissive(self):
        assert is_permissive_sddl("(A;;CCDCLCSWRP;;;AU)") is True

    def test_allow_iu_is_permissive(self):
        assert is_permissive_sddl("(A;;CCDCLCSWRP;;;IU)") is True

    def test_allow_s_1_1_0_is_permissive(self):
        assert is_permissive_sddl("(A;;GA;;;S-1-1-0)") is True

    def test_allow_s_1_15_2_1_is_permissive(self):
        assert is_permissive_sddl("(A;;GA;;;S-1-15-2-1)") is True

    def test_deny_only_not_permissive(self):
        assert is_permissive_sddl("(D;;GA;;;WD)") is False

    def test_deny_overrides_allow_not_permissive(self):
        assert is_permissive_sddl("(D;;GA;;;WD)(A;;GA;;;WD)") is False

    def test_deny_wd_but_allow_ac_is_permissive(self):
        assert is_permissive_sddl("(D;;GA;;;WD)(A;;GA;;;AC)") is True

    def test_deny_all_permissive_sids(self):
        deny_all = "".join(f"(D;;GA;;;{sid})" for sid in PERMISSIVE_SIDS)
        allow_all = "".join(f"(A;;GA;;;{sid})" for sid in PERMISSIVE_SIDS)
        assert is_permissive_sddl(deny_all + allow_all) is False

    def test_restrictive_sddl(self):
        assert is_permissive_sddl("O:SYG:SYD:") is False

    def test_empty_sddl(self):
        assert is_permissive_sddl("") is False

    def test_non_permissive_sid_only(self):
        assert is_permissive_sddl("(A;;GA;;;SY)") is False

    def test_mixed_deny_allow_partial(self):
        sddl = "(D;;GA;;;WD)(D;;GA;;;AC)(A;;GA;;;AU)"
        assert is_permissive_sddl(sddl) is True

    def test_all_denied_except_one(self):
        sddl = "(D;;GA;;;WD)(D;;GA;;;AC)(D;;GA;;;AU)(A;;GA;;;IU)"
        assert is_permissive_sddl(sddl) is True

    def test_real_world_sddl(self):
        sddl = "O:PSG:BUD:P(A;;CCDCLCSWRP;;;WD)(A;;CCDCSW;;;AC)"
        assert is_permissive_sddl(sddl) is True


# ===================================================================
# PERMISSIVE_SIDS constant
# ===================================================================

class TestPermissiveSids:
    """Verify the set of known permissive SIDs."""

    def test_expected_sids_present(self):
        assert "WD" in PERMISSIVE_SIDS
        assert "AC" in PERMISSIVE_SIDS
        assert "AU" in PERMISSIVE_SIDS
        assert "IU" in PERMISSIVE_SIDS
        assert "S-1-1-0" in PERMISSIVE_SIDS
        assert "S-1-15-2-1" in PERMISSIVE_SIDS

    def test_is_frozenset(self):
        assert isinstance(PERMISSIVE_SIDS, frozenset)


# ===================================================================
# ParsedACE dataclass
# ===================================================================

class TestParsedACE:
    """Tests for the ParsedACE dataclass."""

    def test_fields(self):
        ace = ParsedACE(
            ace_type="A",
            flags="OICI",
            rights="GA",
            object_guid="",
            inherit_object_guid="",
            account_sid="WD",
        )
        assert ace.ace_type == "A"
        assert ace.flags == "OICI"
        assert ace.rights == "GA"
        assert ace.account_sid == "WD"
