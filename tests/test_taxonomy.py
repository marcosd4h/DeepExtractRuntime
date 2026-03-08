"""Tests for API and string taxonomy helpers.

Target: helpers/api_taxonomy.py, helpers/string_taxonomy.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# sys.path setup
_AGENT_DIR = Path(__file__).resolve().parent.parent
if str(_AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENT_DIR))

from helpers.api_taxonomy import (
    API_TAXONOMY,
    SECURITY_API_CATEGORIES,
    classify_api,
    classify_api_security,
    get_dangerous_api_prefixes,
)
from helpers.string_taxonomy import (
    CATEGORIES,
    STRING_TAXONOMY,
    categorize_string,
    categorize_string_simple,
)


# ===========================================================================
# API taxonomy tests
# ===========================================================================


class TestAPITaxonomy:
    """Tests for API_TAXONOMY and classify_api()."""

    def test_taxonomy_has_expected_categories(self):
        expected = {"file_io", "registry", "network", "security", "winrt", "wmi", "crypto"}
        for cat in expected:
            assert cat in API_TAXONOMY, f"Missing category: {cat}"

    def test_classify_file_io(self):
        assert classify_api("CreateFileW") == "file_io"
        assert classify_api("NtReadFile") == "file_io"

    def test_classify_strips_import_prefix(self):
        assert classify_api("__imp_CreateFileW") == "file_io"
        assert classify_api("cs:ReadFile") == "file_io"

    def test_classify_winrt(self):
        assert classify_api("RoInitialize") == "winrt"
        assert classify_api("RoGetActivationFactory") == "winrt"
        assert classify_api("RoGetAgileReference") == "winrt"
        assert classify_api("RoParseTypeName") == "winrt"

    def test_classify_wmi(self):
        assert classify_api("WmiQueryAllData") == "wmi"
        assert classify_api("WmiOpenBlock") == "wmi"
        assert classify_api("WmiEnableEvent") == "wmi"

    def test_classify_security(self):
        assert classify_api("CredRead") == "security"
        assert classify_api("CredWrite") == "security"
        assert classify_api("LsaLookupNames2") == "security"
        assert classify_api("SaferCreateLevel") == "security"
        assert classify_api("AuditQuerySystemPolicy") == "security"

    def test_classify_unknown_returns_none(self):
        assert classify_api("SomeUnknownAPI") is None


class TestAPISecurityTaxonomy:
    """Tests for SECURITY_API_CATEGORIES and classify_api_security()."""

    def test_security_classify_privilege(self):
        assert classify_api_security("CredRead") == "privilege"
        assert classify_api_security("CredWrite") == "privilege"
        assert classify_api_security("LsaLookupNames2") == "privilege"

    def test_security_classify_command_execution(self):
        assert classify_api_security("CreateProcessW") == "command_execution"

    def test_security_classify_unknown_returns_none(self):
        assert classify_api_security("GetLastError") is None

    def test_dangerous_prefixes_non_empty(self):
        prefixes = get_dangerous_api_prefixes()
        assert len(prefixes) > 0
        assert "CreateProcess" in prefixes
        assert "CredRead" in prefixes


# ===========================================================================
# String taxonomy tests
# ===========================================================================


class TestStringTaxonomyStructure:
    """Tests for STRING_TAXONOMY structure (avoid brittle exact counts)."""

    def test_taxonomy_minimum_size(self):
        assert len(STRING_TAXONOMY) >= 15

    def test_taxonomy_structure(self):
        for pat, cat, desc in STRING_TAXONOMY:
            assert hasattr(pat, "search"), f"Pattern for {cat} not compiled"
            assert isinstance(cat, str)
            assert isinstance(desc, str)

    def test_categories_include_expected(self):
        expected = {"file_path", "registry_key", "url", "rpc_endpoint", "named_pipe",
                    "alpc_path", "service_account", "certificate", "error_message"}
        for cat in expected:
            assert cat in CATEGORIES, f"Missing category: {cat}"


class TestStringTaxonomyNewPatterns:
    """Tests for newly added high-value string patterns."""

    def test_alpc_path(self):
        result = categorize_string(r"\RPC Control\SomePort")
        assert result is not None
        assert result[0] == "alpc_path"

    def test_base_named_objects(self):
        result = categorize_string(r"\BaseNamedObjects\MyEvent")
        assert result is not None
        assert result[0] == "alpc_path"

    def test_service_account_nt_authority(self):
        result = categorize_string(r"NT AUTHORITY\LOCAL SYSTEM")
        assert result is not None
        assert result[0] == "service_account"

    def test_service_account_network_service(self):
        result = categorize_string(r"NT AUTHORITY\NETWORK SERVICE")
        assert result is not None
        assert result[0] == "service_account"

    def test_service_account_local_system(self):
        result = categorize_string(r"LocalSystem")
        assert result is not None
        assert result[0] == "service_account"

    def test_certificate_extension(self):
        # Use paths without drive letter so certificate matches before file_path
        for ext in (".cer", ".pfx", ".pem", ".crt"):
            result = categorize_string(f"certs\\mycert{ext}")
            assert result is not None, f"Failed for {ext}"
            assert result[0] == "certificate"

    def test_file_url(self):
        result = categorize_string("file:///C:/path/to/file.txt")
        assert result is not None
        assert result[0] == "url"


class TestStringTaxonomyErrorReduction:
    """Tests for error_message false positive reduction."""

    def test_error_phrase_still_matches(self):
        result = categorize_string("Error: access denied")
        assert result is not None
        assert result[0] == "error_message"

    def test_short_identifier_no_match(self):
        # "Invalid" as enum/identifier - should not match (reduced false positive)
        result = categorize_string("Invalid")
        assert result is None or result[0] != "error_message"

    def test_short_error_no_match(self):
        # "Error" alone - should not match
        result = categorize_string("Error")
        assert result is None or result[0] != "error_message"
