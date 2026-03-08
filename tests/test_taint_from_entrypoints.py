"""Tests for the --from-entrypoints batch mode in trace_taint_cross_module.

Targets:
  skills/taint-analysis/scripts/trace_taint_cross_module.py

Covers:
  - trace_from_entrypoints invokes run_skill_script with correct args
  - Filtering by top and min_score
  - Graceful skip of entries with null function_id
  - Aggregation of results across multiple entry points
  - _extract_tainted_param_indices parsing
  - Per-entry exception handling (no abort on single failure)
"""

from __future__ import annotations

import importlib.util as _ilu
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

_AGENT_DIR = Path(__file__).resolve().parent.parent
_SCRIPTS_DIR = _AGENT_DIR / "skills" / "taint-analysis" / "scripts"

# Load _common first so bare `from _common import ...` works during module exec.
_common_path = _SCRIPTS_DIR / "_common.py"
_spec_common = _ilu.spec_from_file_location("_common", str(_common_path))
_common_mod = _ilu.module_from_spec(_spec_common)
sys.modules["_common"] = _common_mod
_spec_common.loader.exec_module(_common_mod)

# Add scripts dir so `from trace_taint_forward import ...` resolves.
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

import trace_taint_cross_module as _mod  # noqa: E402

trace_from_entrypoints = _mod.trace_from_entrypoints
_extract_tainted_param_indices = _mod._extract_tainted_param_indices
_build_aggregate = _mod._build_aggregate


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_ranked_entry(
    name: str,
    fid: int | None,
    score: float,
    rank: int,
    etype: str = "EXPORT_DLL",
    tainted_args: list[str] | None = None,
) -> dict:
    return {
        "function_name": name,
        "function_id": fid,
        "attack_score": score,
        "attack_rank": rank,
        "entry_type": etype,
        "tainted_args": tainted_args or [],
    }


def _make_taint_result(
    total: int = 2,
    local: int = 1,
    xmod: int = 1,
    crit: int = 0,
    high: int = 1,
    med: int = 1,
    low: int = 0,
    trust_esc: int = 0,
    modules: list[str] | None = None,
) -> dict:
    return {
        "status": "ok",
        "function": {"function_name": "test_func"},
        "summary": {
            "total_sinks": total,
            "local_sinks": local,
            "cross_module_sinks": xmod,
            "trust_escalations": trust_esc,
            "modules_reached": modules or [],
            "critical": crit,
            "high": high,
            "medium": med,
            "low": low,
        },
    }


SAMPLE_RANKED = [
    _make_ranked_entry("RpcHandler", 10, 0.90, 1, "RPC_HANDLER",
                       ["arg0 (LPWSTR lpName): string pointer - TAINT",
                        "arg2 (DWORD cbSize): size/length - TAINT (controls buffer bounds)"]),
    _make_ranked_entry("ComMethod", 20, 0.75, 2, "COM_METHOD",
                       ["arg1 (IUnknown* pUnk): COM interface - TAINT"]),
    _make_ranked_entry("OrdinalOnly", None, 0.60, 3, "EXPORT_ORDINAL_ONLY"),
    _make_ranked_entry("ExportA", 30, 0.50, 4, "EXPORT_DLL"),
    _make_ranked_entry("ExportB", 40, 0.20, 5, "EXPORT_DLL"),
]


# ---------------------------------------------------------------------------
# _extract_tainted_param_indices
# ---------------------------------------------------------------------------

class TestExtractTaintedParamIndices:
    def test_basic_extraction(self):
        args = [
            "arg0 (LPWSTR lpName): string pointer - TAINT",
            "arg2 (DWORD cbSize): size/length - TAINT (controls buffer bounds)",
        ]
        assert _extract_tainted_param_indices(args) == "1,3"

    def test_single_arg(self):
        assert _extract_tainted_param_indices(["arg1 (IUnknown* p): COM - TAINT"]) == "2"

    def test_empty_list_returns_none(self):
        assert _extract_tainted_param_indices([]) is None

    def test_no_match_returns_none(self):
        assert _extract_tainted_param_indices(["no match here"]) is None

    def test_deduplicates(self):
        args = ["arg0 (LPWSTR a): TAINT", "arg0 (void* b): TAINT"]
        assert _extract_tainted_param_indices(args) == "1"


# ---------------------------------------------------------------------------
# trace_from_entrypoints
# ---------------------------------------------------------------------------

class TestTraceFromEntrypoints:
    """Tests with mocked run_skill_script and trace_cross_module."""

    def _patch_ranking(self, ranked_list):
        return patch.object(
            _mod, "run_skill_script",
            return_value={
                "success": True,
                "json_data": {"status": "ok", "ranked": ranked_list},
                "stdout": "", "stderr": "", "exit_code": 0, "error": None,
            },
        )

    def _patch_taint(self, side_effect=None, return_value=None):
        if side_effect is not None:
            return patch.object(_mod, "trace_cross_module", side_effect=side_effect)
        rv = return_value or _make_taint_result()
        return patch.object(_mod, "trace_cross_module", return_value=rv)

    def test_calls_rank_entrypoints_with_db_path(self):
        with self._patch_ranking(SAMPLE_RANKED) as mock_rank, \
             self._patch_taint():
            trace_from_entrypoints("/fake/db.db", top=1)
            mock_rank.assert_called_once_with(
                "map-attack-surface", "rank_entrypoints.py",
                ["/fake/db.db"], json_output=True, timeout=300,
            )

    def test_top_limits_entries(self):
        with self._patch_ranking(SAMPLE_RANKED), \
             self._patch_taint() as mock_taint:
            result = trace_from_entrypoints("/fake/db.db", top=2)
            assert result["entry_points_analyzed"] == 2
            assert mock_taint.call_count == 2

    def test_skips_null_function_id(self):
        with self._patch_ranking(SAMPLE_RANKED), \
             self._patch_taint() as mock_taint:
            result = trace_from_entrypoints("/fake/db.db", top=5)
            assert result["entry_points_skipped"] == 1
            assert result["entry_points_analyzed"] == 4
            for r in result["results"]:
                assert r["entry_point"]["function_id"] is not None

    def test_min_score_filters(self):
        with self._patch_ranking(SAMPLE_RANKED), \
             self._patch_taint() as mock_taint:
            result = trace_from_entrypoints("/fake/db.db", top=10, min_score=0.7)
            names = [r["entry_point"]["function_name"] for r in result["results"]]
            assert "RpcHandler" in names
            assert "ComMethod" in names
            assert "ExportB" not in names

    def test_ranking_failure_returns_error(self):
        with patch.object(_mod, "run_skill_script", return_value={
            "success": False, "error": "DB not found",
            "json_data": None, "stdout": "", "stderr": "", "exit_code": 1,
        }):
            result = trace_from_entrypoints("/fake/db.db")
            assert result["status"] == "error"
            assert "rank_entrypoints failed" in result["error"]

    def test_empty_ranking_returns_zero_results(self):
        with self._patch_ranking([]):
            result = trace_from_entrypoints("/fake/db.db")
            assert result["status"] == "ok"
            assert result["entry_points_analyzed"] == 0
            assert result["results"] == []

    def test_per_entry_exception_does_not_abort(self):
        call_count = 0

        def side_effect(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("boom")
            return _make_taint_result()

        with self._patch_ranking(SAMPLE_RANKED[:2]), \
             self._patch_taint(side_effect=side_effect):
            result = trace_from_entrypoints("/fake/db.db", top=2)
            assert result["entry_points_analyzed"] == 2
            assert result["results"][0]["taint_result"]["status"] == "error"
            assert result["results"][1]["taint_result"]["status"] == "ok"

    def test_tainted_args_forwarded_as_params(self):
        with self._patch_ranking(SAMPLE_RANKED[:1]), \
             self._patch_taint() as mock_taint:
            trace_from_entrypoints("/fake/db.db", top=1)
            call_kwargs = mock_taint.call_args.kwargs
            assert call_kwargs["params_arg"] == "1,3"

    def test_no_tainted_args_passes_none(self):
        with self._patch_ranking([_make_ranked_entry("Foo", 99, 0.5, 1)]), \
             self._patch_taint() as mock_taint:
            trace_from_entrypoints("/fake/db.db", top=1)
            assert mock_taint.call_args.kwargs["params_arg"] is None

    def test_output_structure(self):
        with self._patch_ranking(SAMPLE_RANKED[:2]), \
             self._patch_taint():
            result = trace_from_entrypoints("/fake/db.db", top=2)
            assert result["status"] == "ok"
            assert result["mode"] == "from_entrypoints"
            assert "aggregate" in result
            assert "results" in result
            for r in result["results"]:
                assert "entry_point" in r
                assert "taint_result" in r
                ep = r["entry_point"]
                for key in ("function_name", "function_id", "attack_score",
                            "attack_rank", "entry_type"):
                    assert key in ep


# ---------------------------------------------------------------------------
# _build_aggregate
# ---------------------------------------------------------------------------

class TestBuildAggregate:
    def test_sums_across_results(self):
        results = [
            {"taint_result": _make_taint_result(total=3, xmod=2, crit=1, high=1, med=1,
                                                trust_esc=1, modules=["ntdll.dll"])},
            {"taint_result": _make_taint_result(total=2, xmod=1, crit=0, high=1, med=0, low=1,
                                                trust_esc=0, modules=["rpcrt4.dll"])},
        ]
        agg = _build_aggregate(results)
        assert agg["total_sinks"] == 5
        assert agg["cross_module_sinks"] == 3
        assert agg["critical"] == 1
        assert agg["high"] == 2
        assert agg["trust_escalations"] == 1
        assert set(agg["modules_reached"]) == {"ntdll.dll", "rpcrt4.dll"}

    def test_empty_results(self):
        agg = _build_aggregate([])
        assert agg["total_sinks"] == 0
        assert agg["modules_reached"] == []

    def test_skips_error_results_gracefully(self):
        results = [
            {"taint_result": {"status": "error", "error": "boom"}},
            {"taint_result": _make_taint_result(total=1, xmod=0, crit=0, high=0, med=1)},
        ]
        agg = _build_aggregate(results)
        assert agg["total_sinks"] == 1
