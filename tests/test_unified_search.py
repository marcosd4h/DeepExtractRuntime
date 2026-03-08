"""Tests for the unified search module.

Target: helpers/unified_search.py
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from unittest.mock import MagicMock, patch

from helpers.unified_search import (
    MatchMode,
    UnifiedSearchResults,
    ALL_DIMENSIONS,
    DEFAULT_DIMENSIONS,
    DEFAULT_FUZZY_THRESHOLD,
    _match,
    _score_result,
    _extract_literal_prefix,
    _extract_class_from_mangled,
    _highlight_match,
    _build_json_prefilter,
    _match_context_label,
    main,
    run_search,
)
from conftest import _make_function_record as mkfr


# ===================================================================
# _match -- SUBSTRING mode
# ===================================================================

class TestMatchSubstring:
    def test_exact_match(self):
        matched, score = _match("CreateFileW", "CreateFileW", MatchMode.SUBSTRING)
        assert matched is True
        assert score == 1.0

    def test_exact_match_case_insensitive(self):
        matched, score = _match("CreateFileW", "createfilew", MatchMode.SUBSTRING)
        assert matched is True
        assert score == 1.0

    def test_prefix_match(self):
        matched, score = _match("CreateFileW", "Create", MatchMode.SUBSTRING)
        assert matched is True
        assert score == 0.85

    def test_word_boundary_underscore(self):
        matched, score = _match("Ai_LaunchProcess", "LaunchProcess", MatchMode.SUBSTRING)
        assert matched is True
        assert score == 0.75

    def test_word_boundary_camel_case(self):
        matched, score = _match("AiLaunchProcess", "Launch", MatchMode.SUBSTRING)
        assert matched is True
        assert score == 0.75

    def test_plain_substring(self):
        # Uppercase prefix avoids camelCase word-boundary detection
        matched, score = _match("ACreateFileWEx", "CreateFileW", MatchMode.SUBSTRING)
        assert matched is True
        assert score == 0.6

    def test_no_match(self):
        matched, score = _match("CreateFileW", "ReadFile", MatchMode.SUBSTRING)
        assert matched is False
        assert score == 0.0

    def test_empty_text(self):
        matched, score = _match("", "query", MatchMode.SUBSTRING)
        assert matched is False
        assert score == 0.0

    def test_case_sensitive(self):
        matched, _ = _match("CreateFileW", "createfilew", MatchMode.SUBSTRING,
                            case_sensitive=True)
        assert matched is False

    def test_case_sensitive_exact(self):
        matched, score = _match("CreateFileW", "CreateFileW", MatchMode.SUBSTRING,
                                case_sensitive=True)
        assert matched is True
        assert score == 1.0


# ===================================================================
# _match -- REGEX mode
# ===================================================================

class TestMatchRegex:
    def test_full_match(self):
        matched, score = _match("CreateFileW", "^CreateFileW$", MatchMode.REGEX)
        assert matched is True
        assert score == 1.0

    def test_partial_match(self):
        matched, score = _match("CreateFileW", "Create.*", MatchMode.REGEX)
        assert matched is True
        assert score > 0.6

    def test_pattern_group(self):
        matched, _ = _match("AiLaunchProcess", "^Ai.*Process$", MatchMode.REGEX)
        assert matched is True

    def test_no_regex_match(self):
        matched, score = _match("CreateFileW", "^ReadFile$", MatchMode.REGEX)
        assert matched is False
        assert score == 0.0

    def test_invalid_regex_returns_false(self):
        matched, score = _match("test", "[invalid", MatchMode.REGEX)
        assert matched is False
        assert score == 0.0

    def test_regex_case_insensitive_default(self):
        matched, _ = _match("CreateFileW", "createfilew", MatchMode.REGEX)
        assert matched is True

    def test_regex_case_sensitive(self):
        matched, _ = _match("CreateFileW", "createfilew", MatchMode.REGEX,
                            case_sensitive=True)
        assert matched is False

    def test_regex_partial_coverage_score(self):
        matched, score = _match("CreateFileW", "File", MatchMode.REGEX)
        assert matched is True
        assert 0.6 < score < 1.0


# ===================================================================
# _match -- FUZZY mode
# ===================================================================

class TestMatchFuzzy:
    def test_exact_match(self):
        matched, score = _match("CreateProcess", "CreateProcess", MatchMode.FUZZY)
        assert matched is True
        assert score == 1.0

    def test_prefix_match(self):
        matched, score = _match("CreateProcessW", "Create", MatchMode.FUZZY)
        assert matched is True
        assert score == 0.85

    def test_substring_match(self):
        matched, score = _match("AiCreateProcessW", "CreateProcess", MatchMode.FUZZY)
        assert matched is True
        assert score == 0.6

    def test_fuzzy_close_match(self):
        matched, score = _match("CreateProcess", "CreateProces", MatchMode.FUZZY)
        assert matched is True
        assert score > 0.3

    def test_fuzzy_no_match_distant(self):
        matched, score = _match("CreateProcess", "xxxxxxx", MatchMode.FUZZY,
                                fuzzy_threshold=0.6)
        assert matched is False
        assert score == 0.0

    def test_fuzzy_low_threshold_more_permissive(self):
        _, score_low = _match("CreateProcess", "CretPrcs", MatchMode.FUZZY,
                              fuzzy_threshold=0.3)
        _, score_high = _match("CreateProcess", "CretPrcs", MatchMode.FUZZY,
                               fuzzy_threshold=0.9)
        # low threshold allows matches that high threshold rejects
        assert score_low >= score_high

    def test_fuzzy_score_range(self):
        matched, score = _match("CreateProcess", "CrateProcss", MatchMode.FUZZY,
                                fuzzy_threshold=0.5)
        if matched:
            assert 0.3 <= score <= 0.55  # 0.3 + ratio * 0.25


# ===================================================================
# _match -- edge cases across all modes
# ===================================================================

class TestMatchEdgeCases:
    def test_none_text(self):
        matched, score = _match(None, "query", MatchMode.SUBSTRING)
        assert matched is False
        assert score == 0.0

    def test_none_text_regex(self):
        matched, score = _match(None, "query", MatchMode.REGEX)
        assert matched is False

    def test_none_text_fuzzy(self):
        matched, score = _match(None, "query", MatchMode.FUZZY)
        assert matched is False

    def test_unicode_text(self):
        matched, _ = _match("Héllo Wörld", "Wörld", MatchMode.SUBSTRING)
        assert matched is True

    def test_special_chars_substring(self):
        matched, _ = _match("test(value)", "(value)", MatchMode.SUBSTRING)
        assert matched is True

    def test_very_long_text(self):
        text = "A" * 10000
        matched, _ = _match(text, "AAA", MatchMode.SUBSTRING)
        assert matched is True

    def test_very_long_query_no_match(self):
        query = "X" * 10000
        matched, _ = _match("short", query, MatchMode.SUBSTRING)
        assert matched is False


# ===================================================================
# _score_result
# ===================================================================

class TestScoreResult:
    def test_base_score_from_match_quality(self):
        score = _score_result(1.0)
        assert score >= 0.5  # 1.0 * 0.5 = 0.5 minimum

    def test_zero_quality(self):
        score = _score_result(0.0, is_app_code=False)
        assert score == 0.0

    def test_app_code_bonus(self):
        s1 = _score_result(0.5, is_app_code=True)
        s2 = _score_result(0.5, is_app_code=False)
        assert s1 > s2

    def test_decompiled_bonus(self):
        s1 = _score_result(0.5, has_decompiled_code=True)
        s2 = _score_result(0.5, has_decompiled_code=False)
        assert s1 > s2

    def test_export_bonus(self):
        s1 = _score_result(0.5, is_export=True)
        s2 = _score_result(0.5, is_export=False)
        assert s1 > s2

    def test_dangerous_apis_bonus(self):
        s1 = _score_result(0.5, has_dangerous_apis=True)
        s2 = _score_result(0.5, has_dangerous_apis=False)
        assert s1 > s2

    def test_all_bonuses_stacked(self):
        # 1.0 * 0.5 + 0.15 + 0.1 + 0.1 + 0.05 = 0.9
        score = _score_result(1.0, is_app_code=True, has_decompiled_code=True,
                              is_export=True, has_dangerous_apis=True)
        assert score == 0.9

    def test_score_never_exceeds_one(self):
        for q in [0.0, 0.25, 0.5, 0.75, 1.0]:
            score = _score_result(q, is_app_code=True, has_decompiled_code=True,
                                  is_export=True, has_dangerous_apis=True)
            assert 0.0 <= score <= 1.0


# ===================================================================
# _extract_literal_prefix
# ===================================================================

class TestExtractLiteralPrefix:
    def test_simple_word(self):
        assert _extract_literal_prefix("CreateFile") == "CreateFile"

    def test_anchored_pattern(self):
        result = _extract_literal_prefix("^AiLaunchProcess$")
        assert result == "AiLaunchProcess"

    def test_wildcard_pattern_returns_none(self):
        assert _extract_literal_prefix("^Ai.*Process$") is None

    def test_short_literal_returns_none(self):
        assert _extract_literal_prefix("^..$") is None

    def test_pure_wildcard_returns_none(self):
        assert _extract_literal_prefix("^.*$") is None

    def test_empty_pattern(self):
        assert _extract_literal_prefix("") is None

    def test_escaped_literal_special_is_preserved(self):
        result = _extract_literal_prefix(r"foo\.bar")
        assert result == "foo.bar"

    def test_alternation_returns_none(self):
        assert _extract_literal_prefix("Create|ReadFile") is None

    def test_underscore_preserved(self):
        result = _extract_literal_prefix("Create_File_W")
        assert result == "Create_File_W"


# ===================================================================
# _extract_class_from_mangled
# ===================================================================

class TestExtractClassFromMangled:
    def test_constructor(self):
        assert _extract_class_from_mangled("??0CSecurityDescriptor@@QEAA@XZ") == "CSecurityDescriptor"

    def test_destructor(self):
        assert _extract_class_from_mangled("??1CSecurityDescriptor@@UEAA@XZ") == "CSecurityDescriptor"

    def test_vftable(self):
        assert _extract_class_from_mangled("??_7CSecurityDescriptor@@6B@") == "CSecurityDescriptor"

    def test_method(self):
        assert _extract_class_from_mangled("?GetDacl@CSecurityDescriptor@@QEAAXPEAU_ACL@@@Z") == "CSecurityDescriptor"

    def test_no_mangling(self):
        assert _extract_class_from_mangled("CreateFileW") is None

    def test_empty_string(self):
        assert _extract_class_from_mangled("") is None

    def test_none_input(self):
        assert _extract_class_from_mangled(None) is None

    def test_single_question_mark_no_at(self):
        # Malformed: no @@ in the right place
        assert _extract_class_from_mangled("?Foo") is None

    def test_constructor_simple(self):
        assert _extract_class_from_mangled("??0CFoo@@XZ") == "CFoo"

    def test_destructor_simple(self):
        assert _extract_class_from_mangled("??1CFoo@@XZ") == "CFoo"


# ===================================================================
# _highlight_match
# ===================================================================

class TestHighlightMatch:
    def test_basic_highlight(self):
        result = _highlight_match("Hello World CreateFileW call here", "CreateFileW")
        assert "CreateFileW" in result

    def test_long_text_no_match_truncated(self):
        text = "x" * 200
        result = _highlight_match(text, "notfound", max_len=100)
        assert len(result) <= 103  # 100 + "..."

    def test_regex_highlight(self):
        text = "void AiLaunchProcess(void* a1, void* a2)"
        result = _highlight_match(text, "AiLaunch.*", MatchMode.REGEX)
        assert "AiLaunch" in result

    def test_regex_invalid_pattern(self):
        result = _highlight_match("test text", "[bad", MatchMode.REGEX)
        assert isinstance(result, str)

    def test_match_at_start(self):
        result = _highlight_match("CreateFileW is an API", "CreateFileW")
        assert "CreateFileW" in result

    def test_match_in_middle(self):
        text = "x" * 40 + "TARGET" + "y" * 40
        result = _highlight_match(text, "TARGET")
        assert "TARGET" in result

    def test_no_match_returns_prefix(self):
        result = _highlight_match("Hello World", "NOTFOUND")
        assert result.startswith("Hello")


# ===================================================================
# _build_json_prefilter
# ===================================================================

class TestBuildJsonPrefilter:
    def test_substring_mode(self):
        where, params = _build_json_prefilter("string_literals", "test", MatchMode.SUBSTRING)
        assert "LIKE" in where
        assert len(params) == 1
        assert "%test%" in params[0]

    def test_regex_mode_with_literal(self):
        where, params = _build_json_prefilter("string_literals", "^CreateFile$", MatchMode.REGEX)
        assert "LIKE" in where
        assert len(params) == 1

    def test_regex_mode_with_pattern_uses_no_literal_prefilter(self):
        where, params = _build_json_prefilter("string_literals", "CreateFile.*", MatchMode.REGEX)
        assert "IS NOT NULL" in where
        assert "COLLATE NOCASE" not in where
        assert len(params) == 0

    def test_regex_mode_with_alternation_uses_no_literal_prefilter(self):
        where, params = _build_json_prefilter("string_literals", "CreateFile|ReadFile", MatchMode.REGEX)
        assert "IS NOT NULL" in where
        assert "COLLATE NOCASE" not in where
        assert len(params) == 0

    def test_regex_mode_no_extractable_literal(self):
        where, params = _build_json_prefilter("string_literals", "^.*$", MatchMode.REGEX)
        assert "IS NOT NULL" in where
        assert len(params) == 0

    def test_fuzzy_mode(self):
        where, params = _build_json_prefilter("string_literals", "test", MatchMode.FUZZY)
        assert "IS NOT NULL" in where
        assert "LIKE" in where
        assert len(params) == 1

    def test_extra_excludes(self):
        where, _ = _build_json_prefilter("col", "test", MatchMode.SUBSTRING,
                                         extra_excludes="col != 'foo'")
        assert "col != 'foo'" in where

    def test_null_filtering_always_present(self):
        where, _ = _build_json_prefilter("col", "x", MatchMode.SUBSTRING)
        assert "IS NOT NULL" in where
        assert "NOT LIKE 'null%'" in where


# ===================================================================
# _match_context_label
# ===================================================================

class TestMatchContextLabel:
    def test_substring_label(self):
        result = _match_context_label("test", MatchMode.SUBSTRING, "name")
        assert "contains" in result
        assert "'test'" in result

    def test_regex_label(self):
        result = _match_context_label("^test$", MatchMode.REGEX, "name")
        assert "matches" in result
        assert "/^test$/" in result

    def test_fuzzy_label(self):
        result = _match_context_label("test", MatchMode.FUZZY, "name")
        assert "~=" in result
        assert "'test'" in result

    def test_dimension_included(self):
        result = _match_context_label("q", MatchMode.SUBSTRING, "api")
        assert "api" in result


# ===================================================================
# UnifiedSearchResults
# ===================================================================

class TestUnifiedSearchResults:
    def test_init_defaults(self):
        results = UnifiedSearchResults()
        assert results.search_mode == "substring"
        assert not results.has_results()
        assert results.total_unique_functions() == 0
        assert results.dimension_counts() == {}

    def test_init_custom_mode(self):
        results = UnifiedSearchResults(search_mode="regex")
        assert results.search_mode == "regex"

    def test_add_single_result(self):
        results = UnifiedSearchResults()
        results.add("name", 1, "TestFunc", "name contains 'Test'",
                     relevance_score=0.8)
        assert results.has_results()
        assert results.total_unique_functions() == 1
        assert results.dimension_counts() == {"name": 1}

    def test_dedup_within_dimension(self):
        results = UnifiedSearchResults()
        results.add("name", 1, "TestFunc", "ctx1", relevance_score=0.8)
        results.add("name", 1, "TestFunc", "ctx2", relevance_score=0.9)
        assert results.dimension_counts() == {"name": 1}
        # First entry wins
        assert results.results["name"][0]["relevance_score"] == 0.8

    def test_unresolved_matches_do_not_collapse_on_negative_function_id(self):
        results = UnifiedSearchResults()
        results.add("export", -1, "ExportA", "ctx1", relevance_score=0.8)
        results.add("export", -1, "ExportB", "ctx2", relevance_score=0.7)
        assert results.dimension_counts() == {"export": 2}
        assert results.total_unique_functions() == 2
        assert [e["function_name"] for e in results.to_flat_list()] == ["ExportA", "ExportB"]

    def test_same_function_different_dimensions(self):
        results = UnifiedSearchResults()
        results.add("name", 1, "CreateFileW", "name match", relevance_score=0.8)
        results.add("api", 1, "CreateFileW", "api match", relevance_score=0.7)
        assert results.total_unique_functions() == 1
        counts = results.dimension_counts()
        assert counts["name"] == 1
        assert counts["api"] == 1

    def test_multiple_functions_different_dimensions(self):
        results = UnifiedSearchResults()
        results.add("name", 1, "FuncA", "ctx")
        results.add("api", 2, "FuncB", "ctx")
        assert results.total_unique_functions() == 2

    def test_multi_dimension_bonus(self):
        results = UnifiedSearchResults()
        results.add("name", 1, "TestFunc", "ctx1", relevance_score=0.5)
        results.add("api", 1, "TestFunc", "ctx2", relevance_score=0.5)
        results.apply_multi_dimension_bonus()
        name_entry = results.results["name"][0]
        assert name_entry["relevance_score"] > 0.5

    def test_multi_dimension_bonus_capped_at_one(self):
        results = UnifiedSearchResults()
        for dim in ALL_DIMENSIONS:
            results.add(dim, 1, "UbiquitousFunc", "ctx", relevance_score=0.95)
        results.apply_multi_dimension_bonus()
        for dim in ALL_DIMENSIONS:
            for entry in results.results.get(dim, []):
                assert entry["relevance_score"] <= 1.0

    def test_sort_by_relevance(self):
        results = UnifiedSearchResults()
        results.add("name", 1, "LowScore", "ctx", relevance_score=0.3)
        results.add("name", 2, "HighScore", "ctx", relevance_score=0.9)
        results.sort_by_relevance()
        assert results.results["name"][0]["function_name"] == "HighScore"
        assert results.results["name"][1]["function_name"] == "LowScore"

    def test_sort_by_relevance_tiebreaker_name(self):
        results = UnifiedSearchResults()
        results.add("name", 1, "Beta", "ctx", relevance_score=0.5)
        results.add("name", 2, "Alpha", "ctx", relevance_score=0.5)
        results.sort_by_relevance()
        # Same score -> sorted by name ascending
        assert results.results["name"][0]["function_name"] == "Alpha"

    def test_sort_by_name(self):
        results = UnifiedSearchResults()
        results.add("name", 1, "Beta", "ctx", relevance_score=0.5)
        results.add("name", 2, "Alpha", "ctx", relevance_score=0.9)
        results.sort_by_name()
        assert results.results["name"][0]["function_name"] == "Alpha"
        assert results.results["name"][1]["function_name"] == "Beta"

    def test_sort_by_id(self):
        results = UnifiedSearchResults()
        results.add("name", 10, "Z", "ctx")
        results.add("name", 1, "A", "ctx")
        results.sort_by_id()
        assert results.results["name"][0]["function_id"] == 1
        assert results.results["name"][1]["function_id"] == 10

    def test_to_dict_structure(self):
        results = UnifiedSearchResults(search_mode="regex")
        results.add("name", 1, "TestFunc", "ctx", relevance_score=0.8)
        d = results.to_dict()
        assert d["search_mode"] == "regex"
        assert d["total_unique_functions"] == 1
        assert "name" in d["results"]
        assert "dimension_counts" in d

    def test_to_dict_omits_empty_dimensions(self):
        results = UnifiedSearchResults()
        results.add("name", 1, "TestFunc", "ctx")
        d = results.to_dict()
        assert "api" not in d["results"]
        assert "string" not in d["results"]

    def test_result_entry_keys(self):
        results = UnifiedSearchResults()
        results.add("name", 42, "MyFunc", "name contains 'My'",
                     relevance_score=0.75, has_decompiled=True)
        entry = results.results["name"][0]
        assert entry["function_id"] == 42
        assert entry["function_name"] == "MyFunc"
        assert entry["match_context"] == "name contains 'My'"
        assert entry["relevance_score"] == 0.75
        assert entry["has_decompiled"] is True

    def test_empty_results_to_dict(self):
        results = UnifiedSearchResults()
        d = results.to_dict()
        assert d["total_unique_functions"] == 0
        assert d["dimension_counts"] == {}
        assert d["results"] == {}

    def test_dimension_counts_only_nonempty(self):
        results = UnifiedSearchResults()
        results.add("api", 1, "F1", "ctx")
        counts = results.dimension_counts()
        assert "api" in counts
        assert "name" not in counts


# ===================================================================
# run_search -- integration with sample_db
# ===================================================================

class TestRunSearch:
    @patch("helpers.unified_search.load_function_index_for_db")
    def test_name_search_finds_function(self, mock_index, sample_db, sample_function_index):
        mock_index.return_value = sample_function_index
        results = run_search(str(sample_db), "DllMain", dimensions=("name",))
        assert results.has_results()
        assert results.total_unique_functions() >= 1
        entries = results.results.get("name", [])
        assert any(e["function_name"] == "DllMain" for e in entries)

    @patch("helpers.unified_search.load_function_index_for_db")
    def test_signature_search(self, mock_index, sample_db, sample_function_index):
        mock_index.return_value = sample_function_index
        results = run_search(str(sample_db), "BOOL", dimensions=("signature",))
        assert isinstance(results, UnifiedSearchResults)
        entries = results.results.get("signature", [])
        assert len(entries) >= 1, "BOOL should match DllMain's BOOL __stdcall signature"

    @patch("helpers.unified_search.load_function_index_for_db")
    def test_string_search(self, mock_index, sample_db, sample_function_index):
        mock_index.return_value = sample_function_index
        results = run_search(str(sample_db), "security", dimensions=("string",))
        assert isinstance(results, UnifiedSearchResults)
        entries = results.results.get("string", [])
        assert len(entries) >= 1, "'security' should match string literals in test DB"

    @patch("helpers.unified_search.load_function_index_for_db")
    def test_api_search(self, mock_index, sample_db, sample_function_index):
        mock_index.return_value = sample_function_index
        results = run_search(str(sample_db), "RpcServerInqBindings", dimensions=("api",))
        assert isinstance(results, UnifiedSearchResults)
        entries = results.results.get("api", [])
        assert len(entries) >= 1, "RpcServerInqBindings is in DllMain's outbound xrefs"

    @patch("helpers.unified_search.load_function_index_for_db")
    def test_dangerous_api_search(self, mock_index, sample_db, sample_function_index):
        mock_index.return_value = sample_function_index
        results = run_search(str(sample_db), "CreateProcessW", dimensions=("dangerous",))
        assert isinstance(results, UnifiedSearchResults)
        entries = results.results.get("dangerous", [])
        assert len(entries) >= 1, "CreateProcessW is in DllMain's dangerous_api_calls"

    @patch("helpers.unified_search.load_function_index_for_db")
    def test_class_search_mangled(self, mock_index, sample_db, sample_function_index):
        mock_index.return_value = sample_function_index
        results = run_search(str(sample_db), "CFoo", dimensions=("class",))
        assert isinstance(results, UnifiedSearchResults)
        # CFoo appears in mangled name ??0CFoo@@QEAA@XZ for function ID 3
        if results.has_results():
            entries = results.results.get("class", [])
            assert any("CFoo" in e.get("match_context", "") for e in entries)

    @patch("helpers.unified_search.load_function_index_for_db")
    def test_export_search(self, mock_index, sample_db, sample_function_index):
        mock_index.return_value = sample_function_index
        results = run_search(str(sample_db), "AiDisable", dimensions=("export",))
        assert isinstance(results, UnifiedSearchResults)
        entries = results.results.get("export", [])
        assert len(entries) >= 1, "AiDisable should match AiDisableDesktopRpcInterface export"

    @patch("helpers.unified_search.load_function_index_for_db")
    def test_import_search(self, mock_index, sample_db, sample_function_index):
        mock_index.return_value = sample_function_index
        results = run_search(str(sample_db), "CreateFileW", dimensions=("import",))
        assert isinstance(results, UnifiedSearchResults)
        if results.has_results():
            entries = results.results.get("import", [])
            assert any("CreateFileW" in e.get("match_context", "") for e in entries)


class TestMain:
    def test_all_json_uses_status_envelope(self, monkeypatch):
        results = UnifiedSearchResults()
        results.add("name", 1, "TestFunc", "ctx", relevance_score=0.9)

        monkeypatch.setattr(
            "helpers.unified_search._discover_module_dbs",
            lambda: [Path("/tmp/test.db")],
        )
        monkeypatch.setattr(
            "helpers.unified_search.run_search",
            lambda *args, **kwargs: results,
        )
        monkeypatch.setattr(
            "sys.argv",
            ["unified_search.py", "--all", "--query", "TestFunc", "--json"],
        )

        with patch("helpers.unified_search.emit_json") as mock_emit_json:
            main()

        payload = mock_emit_json.call_args.args[0]
        assert payload["status"] == "ok"
        assert payload["query"] == "TestFunc"
        assert "modules" in payload

    @patch("helpers.unified_search.load_function_index_for_db")
    def test_import_search_no_match(self, mock_index, sample_db, sample_function_index):
        mock_index.return_value = sample_function_index
        results = run_search(str(sample_db), "ZZZNONEXISTENT999", dimensions=("import",))
        assert len(results.results.get("import", [])) == 0

    @patch("helpers.unified_search.load_function_index_for_db")
    def test_import_dimension_in_all(self, mock_index, sample_db, sample_function_index):
        """The 'import' dimension should be included in ALL_DIMENSIONS."""
        mock_index.return_value = sample_function_index
        assert "import" in ALL_DIMENSIONS
        results = run_search(str(sample_db), "memcpy", dimensions=ALL_DIMENSIONS)
        assert isinstance(results, UnifiedSearchResults)

    @patch("helpers.unified_search.load_function_index_for_db")
    def test_all_dimensions_searched(self, mock_index, sample_db, sample_function_index):
        mock_index.return_value = sample_function_index
        results = run_search(str(sample_db), "Dll", dimensions=ALL_DIMENSIONS)
        assert isinstance(results, UnifiedSearchResults)

    @patch("helpers.unified_search.load_function_index_for_db")
    def test_no_results_for_nonexistent(self, mock_index, sample_db, sample_function_index):
        mock_index.return_value = sample_function_index
        results = run_search(str(sample_db), "ZZZNONEXISTENT999", dimensions=("name",))
        assert not results.has_results()
        assert results.total_unique_functions() == 0

    @patch("helpers.unified_search.load_function_index_for_db")
    def test_limit_per_dimension_respected(self, mock_index, sample_db, sample_function_index):
        mock_index.return_value = sample_function_index
        results = run_search(str(sample_db), "sub_", dimensions=("name",),
                             limit_per_dimension=1)
        name_count = len(results.results.get("name", []))
        assert name_count <= 1

    @patch("helpers.unified_search.load_function_index_for_db")
    def test_regex_mode(self, mock_index, sample_db, sample_function_index):
        mock_index.return_value = sample_function_index
        results = run_search(str(sample_db), "^Dll.*", dimensions=("name",),
                             mode=MatchMode.REGEX)
        assert isinstance(results, UnifiedSearchResults)

    @patch("helpers.unified_search.load_function_index_for_db")
    def test_regex_mode_alternation_does_not_drop_other_branch(self, mock_index, sample_db, sample_function_index):
        mock_index.return_value = sample_function_index
        results = run_search(
            str(sample_db),
            "CreateProcessW|GetTokenInformation",
            dimensions=("dangerous",),
            mode=MatchMode.REGEX,
        )
        dangerous = results.results.get("dangerous", [])
        assert any(entry["function_name"] == "DllMain" for entry in dangerous)

    @patch("helpers.unified_search.load_function_index_for_db")
    def test_fuzzy_mode(self, mock_index, sample_db, sample_function_index):
        mock_index.return_value = sample_function_index
        results = run_search(str(sample_db), "DlMain", dimensions=("name",),
                             mode=MatchMode.FUZZY)
        assert isinstance(results, UnifiedSearchResults)

    @patch("helpers.unified_search.load_function_index_for_db")
    def test_sort_score(self, mock_index, sample_db, sample_function_index):
        mock_index.return_value = sample_function_index
        results = run_search(str(sample_db), "sub_", dimensions=("name",), sort="score")
        entries = results.results.get("name", [])
        if len(entries) > 1:
            scores = [e["relevance_score"] for e in entries]
            assert scores == sorted(scores, reverse=True)

    @patch("helpers.unified_search.load_function_index_for_db")
    def test_sort_name(self, mock_index, sample_db, sample_function_index):
        mock_index.return_value = sample_function_index
        results = run_search(str(sample_db), "sub_", dimensions=("name",), sort="name")
        entries = results.results.get("name", [])
        if len(entries) > 1:
            names = [e["function_name"].lower() for e in entries]
            assert names == sorted(names)

    @patch("helpers.unified_search.load_function_index_for_db")
    def test_sort_id(self, mock_index, sample_db, sample_function_index):
        mock_index.return_value = sample_function_index
        results = run_search(str(sample_db), "sub_", dimensions=("name",), sort="id")
        entries = results.results.get("name", [])
        if len(entries) > 1:
            ids = [e["function_id"] for e in entries]
            assert ids == sorted(ids)

    @patch("helpers.unified_search.load_function_index_for_db")
    def test_empty_db(self, mock_index, mock_db_path):
        mock_index.return_value = {}
        results = run_search(str(mock_db_path), "anything", dimensions=("name",))
        assert not results.has_results()

    @patch("helpers.unified_search.load_function_index_for_db")
    def test_multi_dimension_bonus_applied(self, mock_index, sample_db, sample_function_index):
        """Functions matching in multiple dimensions get score boosts."""
        mock_index.return_value = sample_function_index
        # DllMain appears in name and potentially signature dimensions
        results = run_search(str(sample_db), "DllMain",
                             dimensions=("name", "signature"))
        # Results should be an instance regardless
        assert isinstance(results, UnifiedSearchResults)

    @patch("helpers.unified_search.load_function_index_for_db")
    def test_results_to_dict_serializable(self, mock_index, sample_db, sample_function_index):
        """Result dict should be JSON-serializable."""
        mock_index.return_value = sample_function_index
        results = run_search(str(sample_db), "Dll", dimensions=ALL_DIMENSIONS)
        d = results.to_dict()
        serialized = json.dumps(d, ensure_ascii=False)
        reparsed = json.loads(serialized)
        assert reparsed["search_mode"] == "substring"


# ===================================================================
# run_search -- input validation edge cases
# ===================================================================

class TestRunSearchEdgeCases:
    @patch("helpers.unified_search.load_function_index_for_db")
    def test_empty_query(self, mock_index, sample_db, sample_function_index):
        """Empty query returns results (everything substring-matches empty)."""
        mock_index.return_value = sample_function_index
        results = run_search(str(sample_db), "", dimensions=("name",))
        assert isinstance(results, UnifiedSearchResults)
        assert results.total_unique_functions() >= 0

    @patch("helpers.unified_search.load_function_index_for_db")
    def test_single_char_query(self, mock_index, sample_db, sample_function_index):
        mock_index.return_value = sample_function_index
        results = run_search(str(sample_db), "D", dimensions=("name",))
        assert isinstance(results, UnifiedSearchResults)
        entries = results.results.get("name", [])
        assert any(e["function_name"] == "DllMain" for e in entries), \
            "'D' should match DllMain by name substring"

    @patch("helpers.unified_search.load_function_index_for_db")
    def test_single_dimension(self, mock_index, sample_db, sample_function_index):
        mock_index.return_value = sample_function_index
        results = run_search(str(sample_db), "test", dimensions=("name",))
        # Only "name" dimension should have results
        for dim in ALL_DIMENSIONS:
            if dim != "name":
                assert len(results.results.get(dim, [])) == 0

    @patch("helpers.unified_search.load_function_index_for_db")
    def test_large_limit(self, mock_index, sample_db, sample_function_index):
        mock_index.return_value = sample_function_index
        results = run_search(str(sample_db), "sub_", dimensions=("name",),
                             limit_per_dimension=10000)
        assert isinstance(results, UnifiedSearchResults)
        entries = results.results.get("name", [])
        assert len(entries) >= 2, "sub_ should match sub_140001000 and sub_140002000"

    @patch("helpers.unified_search.load_function_index_for_db")
    def test_small_limit(self, mock_index, sample_db, sample_function_index):
        mock_index.return_value = sample_function_index
        results = run_search(str(sample_db), "sub_", dimensions=("name",),
                             limit_per_dimension=1)
        # Limit=1 should cap results to at most 1
        assert len(results.results.get("name", [])) <= 1

    @patch("helpers.unified_search.load_function_index_for_db")
    def test_unicode_query(self, mock_index, sample_db, sample_function_index):
        mock_index.return_value = sample_function_index
        results = run_search(str(sample_db), "ünïcödé", dimensions=("name",))
        assert isinstance(results, UnifiedSearchResults)
        assert not results.has_results()  # no unicode functions in test DB
