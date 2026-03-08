"""Integration tests for caching in skill scripts.

Verifies that each newly-cached script correctly stores results, returns
cached data on repeated calls, and bypasses the cache with no_cache=True.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

import helpers.cache as cache_mod
from helpers.cache import get_cached, cache_result, clear_cache

_AGENT_DIR = Path(__file__).resolve().parent.parent
_SKILLS_DIR = _AGENT_DIR / "skills"


# ===================================================================
# Skill-import helper (clean _common resolution per skill)
# ===================================================================

def _import_skill(skill_name: str, module_name: str):
    """Import a skill script with clean _common resolution.

    Each skill has its own _common.py.  We must remove any previously
    cached _common from sys.modules so the correct one is picked up.
    """
    scripts_dir = str(_SKILLS_DIR / skill_name / "scripts")

    # Evict any stale _common from a different skill
    for key in list(sys.modules):
        if key == "_common":
            del sys.modules[key]

    # Ensure this skill's scripts dir is first on sys.path
    if scripts_dir in sys.path:
        sys.path.remove(scripts_dir)
    sys.path.insert(0, scripts_dir)

    module_path = _SKILLS_DIR / skill_name / "scripts" / f"{module_name}.py"
    spec = importlib.util.spec_from_file_location(
        f"skill_{skill_name.replace('-', '_')}_{module_name}", str(module_path),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ===================================================================
# Fixtures
# ===================================================================

@pytest.fixture(autouse=True)
def _isolate_cache(tmp_path, monkeypatch):
    """Redirect all cache writes to a temporary directory."""
    monkeypatch.setattr(cache_mod, "_CACHE_ROOT", tmp_path / "cache")


@pytest.fixture
def rpt_db(tmp_path):
    """Create a minimal analysis DB suitable for skill-script testing."""
    import sqlite3

    db_path = tmp_path / "rpt_module_abc123.db"
    conn = sqlite3.connect(str(db_path))
    conn.executescript("""
        CREATE TABLE schema_version (
            version INTEGER PRIMARY KEY, description TEXT,
            applied_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            migration_notes TEXT);
        INSERT INTO schema_version (version, description) VALUES (1, 'v1');

        CREATE TABLE file_info (
            file_path TEXT PRIMARY KEY, base_dir TEXT, file_name TEXT,
            file_extension TEXT, file_size_bytes BIGINT, md5_hash TEXT,
            sha256_hash TEXT, imports TEXT, exports TEXT, entry_point TEXT,
            file_version TEXT, product_version TEXT, company_name TEXT,
            file_description TEXT, internal_name TEXT, original_filename TEXT,
            legal_copyright TEXT, product_name TEXT, time_date_stamp_str TEXT,
            file_modified_date_str TEXT, sections TEXT, pdb_path TEXT,
            rich_header TEXT, tls_callbacks TEXT, is_net_assembly BOOLEAN,
            clr_metadata TEXT, idb_cache_path TEXT, dll_characteristics TEXT,
            security_features TEXT, exception_info TEXT, load_config TEXT,
            analysis_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP);

        CREATE TABLE functions (
            function_id INTEGER PRIMARY KEY, function_signature TEXT,
            function_signature_extended TEXT, mangled_name TEXT,
            function_name TEXT, assembly_code TEXT, decompiled_code TEXT,
            inbound_xrefs TEXT, outbound_xrefs TEXT,
            simple_inbound_xrefs TEXT, simple_outbound_xrefs TEXT,
            vtable_contexts TEXT, global_var_accesses TEXT,
            dangerous_api_calls TEXT, string_literals TEXT,
            stack_frame TEXT, loop_analysis TEXT, analysis_errors TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
    """)

    imports = json.dumps([{
        "module_name": "kernel32.dll",
        "functions": [
            {"function_name": "CreateFileW", "is_delay_loaded": False},
            {"function_name": "CloseHandle", "is_delay_loaded": False},
        ],
    }])
    exports = json.dumps([
        {"function_name": "DllMain", "ordinal": 1,
         "function_signature_extended":
         "BOOL __stdcall DllMain(HINSTANCE, DWORD, LPVOID)"},
    ])
    entry_point = json.dumps([
        {"function_name": "DllMain", "detection_method": "PE header"},
    ])
    sec_feat = json.dumps({
        "aslr_enabled": True, "dep_enabled": True,
        "cfg_enabled": False, "seh_enabled": True,
    })
    conn.execute(
        """INSERT INTO file_info (file_path, file_name, file_extension,
           file_size_bytes, imports, exports, entry_point,
           company_name, file_description, security_features)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        ("C:\\test.dll", "test.dll", ".dll", 12345, imports, exports,
         entry_point, "TestCorp", "Test Library", sec_feat),
    )

    funcs = [
        (1, "DllMain",
         "BOOL __stdcall DllMain(HINSTANCE a1, DWORD a2, LPVOID a3)",
         "BOOL __stdcall DllMain(HINSTANCE h, DWORD r, LPVOID p)",
         None,
         "BOOL __stdcall DllMain(HINSTANCE a1, DWORD a2, LPVOID a3)"
         "\n{\n  return 1;\n}",
         "mov eax, 1\nret",
         json.dumps([{"function_name": "CreateFileW", "function_id": None,
                       "module_name": "kernel32.dll", "function_type": 0}]),
         None, None,
         json.dumps(["CreateFileW"]),
         json.dumps(["test_string", "C:\\Windows\\System32"]),
         json.dumps({"analysis_available": True, "has_canary": False}),
         json.dumps({"loop_count": 0, "loops": []}),
         None),
        (2, "HelperFunc",
         "void HelperFunc(int a1)", "void HelperFunc(int p)",
         None,
         "void HelperFunc(int a1)\n{\n  return;\n}",
         "xor eax, eax\nret",
         None,
         json.dumps([{"function_name": "DllMain", "function_id": 1,
                       "module_name": "", "function_type": 0}]),
         None, None, None,
         json.dumps({"analysis_available": True, "has_canary": True}),
         json.dumps({"loop_count": 1, "loops": [
             {"cyclomatic_complexity": 2, "nesting_level": 1,
              "is_infinite": False, "instruction_count": 10}]}),
         None),
        (3, "CFoo::DoWork",
         "int __fastcall CFoo::DoWork(CFoo *this, int arg)",
         "int __fastcall CFoo::DoWork(CFoo *this, int arg)",
         "?DoWork@CFoo@@QEAAHH@Z",
         "int __fastcall CFoo::DoWork(CFoo *this, int a2)"
         "\n{\n  *((_DWORD *)this + 4) = a2;\n  return 0;\n}",
         "mov dword ptr [rcx+10h], edx\nxor eax, eax\nret",
         None,
         json.dumps([{"function_name": "DllMain", "function_id": 1,
                       "module_name": "", "function_type": 0}]),
         None, None, None,
         json.dumps({"analysis_available": True, "has_canary": False}),
         None, None),
    ]
    for f in funcs:
        conn.execute(
            """INSERT INTO functions (function_id, function_name,
               function_signature, function_signature_extended,
               mangled_name, decompiled_code, assembly_code,
               simple_outbound_xrefs, simple_inbound_xrefs,
               vtable_contexts, dangerous_api_calls, string_literals,
               stack_frame, loop_analysis, analysis_errors)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", f)

    conn.commit()
    conn.close()
    return db_path


# ===================================================================
# analyze_imports
# ===================================================================

class TestAnalyzeImportsCache:
    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _import_skill("generate-re-report", "analyze_imports")

    def test_first_call_populates_cache(self, rpt_db):
        result = self.mod.analyze_imports(str(rpt_db))
        assert result["total_imports"] == 2
        cached = get_cached(str(rpt_db), "analyze_imports")
        assert cached is not None
        assert cached["total_imports"] == 2

    def test_second_call_returns_cached(self, rpt_db):
        r1 = self.mod.analyze_imports(str(rpt_db))
        r2 = self.mod.analyze_imports(str(rpt_db))
        assert r1 == r2

    def test_no_cache_bypasses(self, rpt_db):
        self.mod.analyze_imports(str(rpt_db))
        cache_result(str(rpt_db), "analyze_imports", {"total_imports": -999})
        result = self.mod.analyze_imports(str(rpt_db), no_cache=True)
        assert result["total_imports"] == 2


# ===================================================================
# analyze_strings
# ===================================================================

class TestAnalyzeStringsCache:
    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _import_skill("generate-re-report", "analyze_strings")

    def test_first_call_populates_cache(self, rpt_db):
        result = self.mod.analyze_strings(str(rpt_db))
        assert "total_unique_strings" in result
        cached = get_cached(str(rpt_db), "analyze_strings")
        assert cached is not None
        assert cached["total_unique_strings"] == result["total_unique_strings"]

    def test_second_call_returns_cached(self, rpt_db):
        r1 = self.mod.analyze_strings(str(rpt_db))
        r2 = self.mod.analyze_strings(str(rpt_db))
        assert r1 == r2

    def test_no_cache_bypasses(self, rpt_db):
        self.mod.analyze_strings(str(rpt_db))
        cache_result(str(rpt_db), "analyze_strings",
                     {"total_unique_strings": -1})
        result = self.mod.analyze_strings(str(rpt_db), no_cache=True)
        assert result["total_unique_strings"] >= 0


# ===================================================================
# analyze_complexity
# ===================================================================

class TestAnalyzeComplexityCache:
    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _import_skill("generate-re-report", "analyze_complexity")

    def test_first_call_populates_cache(self, rpt_db):
        result = self.mod.analyze_complexity(str(rpt_db))
        assert "function_count" in result
        # Default app_only=False, so cache key includes that param
        cached = get_cached(str(rpt_db), "analyze_complexity",
                            params={"app_only": False})
        assert cached is not None
        assert cached["function_count"] == result["function_count"]

    def test_app_only_params_cached_separately(self, rpt_db):
        r1 = self.mod.analyze_complexity(str(rpt_db), app_only=False)
        r2 = self.mod.analyze_complexity(str(rpt_db), app_only=True)
        c1 = get_cached(str(rpt_db), "analyze_complexity",
                         params={"app_only": False})
        c2 = get_cached(str(rpt_db), "analyze_complexity",
                         params={"app_only": True})
        assert c1 is not None
        assert c2 is not None
        assert c1["function_count"] == r1["function_count"]
        assert c2["function_count"] == r2["function_count"]

    def test_no_cache_bypasses(self, rpt_db):
        self.mod.analyze_complexity(str(rpt_db))
        cache_result(str(rpt_db), "analyze_complexity",
                     {"function_count": -1}, params={"app_only": False})
        result = self.mod.analyze_complexity(str(rpt_db), no_cache=True)
        assert result["function_count"] >= 0


# ===================================================================
# scan_com_interfaces
# ===================================================================

class TestScanComInterfacesCache:
    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _import_skill("com-interface-reconstruction",
                                  "scan_com_interfaces")

    def test_first_call_populates_cache(self, rpt_db):
        result = self.mod.scan_module(str(rpt_db))
        assert "com_summary" in result
        cached = get_cached(str(rpt_db), "scan_com_interfaces",
                            params={"vtable_only": False})
        assert cached is not None
        assert "com_summary" in cached

    def test_vtable_only_params_cached_separately(self, rpt_db):
        self.mod.scan_module(str(rpt_db), vtable_only=False)
        self.mod.scan_module(str(rpt_db), vtable_only=True)
        c1 = get_cached(str(rpt_db), "scan_com_interfaces",
                         params={"vtable_only": False})
        c2 = get_cached(str(rpt_db), "scan_com_interfaces",
                         params={"vtable_only": True})
        assert c1 is not None
        assert c2 is not None
        assert "com_summary" in c1
        assert "com_summary" in c2

    def test_no_cache_bypasses(self, rpt_db):
        self.mod.scan_module(str(rpt_db))
        cache_result(str(rpt_db), "scan_com_interfaces",
                     {"com_summary": {"total_functions_scanned": -1}},
                     params={"vtable_only": False})
        result = self.mod.scan_module(str(rpt_db), no_cache=True)
        assert result["com_summary"]["total_functions_scanned"] >= 0


# ===================================================================
# discover_entrypoints  (includes serialization round-trip)
# ===================================================================

class TestDiscoverEntrypointsCache:
    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _import_skill("map-attack-surface",
                                  "discover_entrypoints")

    def test_first_call_populates_cache(self, rpt_db):
        entries = self.mod.discover_all(str(rpt_db))
        assert isinstance(entries, list)
        cached_raw = get_cached(str(rpt_db), "discover_entrypoints")
        assert cached_raw is not None
        assert isinstance(cached_raw, list)

    def test_cached_round_trips_to_entrypoint_objects(self, rpt_db):
        original = self.mod.discover_all(str(rpt_db))
        restored = self.mod.discover_all(str(rpt_db))  # from cache
        assert len(restored) == len(original)
        for orig, rest in zip(original, restored):
            assert orig.function_name == rest.function_name
            assert orig.entry_type == rest.entry_type
            assert orig.type_label == rest.type_label
            assert orig.category == rest.category
            assert abs(orig.param_risk_score - rest.param_risk_score) < 0.01

    def test_no_cache_bypasses(self, rpt_db):
        self.mod.discover_all(str(rpt_db))
        cache_result(str(rpt_db), "discover_entrypoints", [])
        entries = self.mod.discover_all(str(rpt_db), no_cache=True)
        assert len(entries) > 0


# ===================================================================
# scan_struct_fields  (conditional: only --all-classes)
# ===================================================================

class TestScanStructFieldsCache:
    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _import_skill("reconstruct-types", "scan_struct_fields")

    def test_all_classes_populates_cache(self, rpt_db):
        result = self.mod.scan_module(str(rpt_db), all_classes=True)
        assert "functions_scanned" in result
        cached = get_cached(str(rpt_db), "scan_struct_fields",
                            params={"all_classes": True,
                                    "no_asm": False, "app_only": False})
        assert cached is not None
        assert cached["functions_scanned"] == result["functions_scanned"]

    def test_single_function_does_not_cache(self, rpt_db):
        self.mod.scan_module(str(rpt_db), function_filter="DllMain")
        # No scan_struct_fields cache should exist (function mode skips caching)
        cached_bare = get_cached(str(rpt_db), "scan_struct_fields")
        assert cached_bare is None

    def test_no_cache_bypasses(self, rpt_db):
        self.mod.scan_module(str(rpt_db), all_classes=True)
        params = {"all_classes": True, "no_asm": False, "app_only": False}
        cache_result(str(rpt_db), "scan_struct_fields",
                     {"functions_scanned": -1}, params=params)
        result = self.mod.scan_module(str(rpt_db), all_classes=True,
                                       no_cache=True)
        assert result["functions_scanned"] >= 0


# ===================================================================
# build_dossier  (per-function caching, tested via cache API)
# ===================================================================

class TestBuildDossierCache:
    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _import_skill("security-dossier", "build_dossier")

    def test_dossier_caches_per_function(self, rpt_db):
        """Build a dossier and verify cache stores per-function data."""
        with self.mod.open_individual_analysis_db(str(rpt_db)) as db:
            func, err = self.mod.find_function(db, name="DllMain")
            assert err is None
            file_info = db.get_file_info()
            all_functions = db.get_all_functions()

        builder = self.mod.DossierBuilder(
            db_path=str(rpt_db), func=func, file_info=file_info,
            all_functions=all_functions, callee_depth=1,
        )
        dossier = builder.build()
        params = {"function": "DllMain", "callee_depth": 1}
        cache_result(str(rpt_db), "security_dossier", dossier, params=params)

        cached = get_cached(str(rpt_db), "security_dossier", params=params)
        assert cached is not None
        assert cached["identity"]["function_name"] == "DllMain"

    def test_different_functions_have_separate_entries(self, rpt_db):
        d1 = {"identity": {"function_name": "A"}}
        d2 = {"identity": {"function_name": "B"}}
        p1 = {"function": "A", "callee_depth": 1}
        p2 = {"function": "B", "callee_depth": 1}
        cache_result(str(rpt_db), "security_dossier", d1, params=p1)
        cache_result(str(rpt_db), "security_dossier", d2, params=p2)
        assert get_cached(str(rpt_db), "security_dossier", params=p1) == d1
        assert get_cached(str(rpt_db), "security_dossier", params=p2) == d2


# ===================================================================
# Registry consistency
# ===================================================================

class TestRegistryConsistency:
    @pytest.fixture(autouse=True)
    def _load_registry(self):
        reg_path = _SKILLS_DIR / "registry.json"
        with open(reg_path) as f:
            self.registry = json.load(f)["skills"]

    def test_all_cacheable_skills_have_cache_keys(self):
        for name, skill in self.registry.items():
            if skill.get("cacheable"):
                assert "cache_keys" in skill and len(skill["cache_keys"]) > 0, \
                    f"{name}: cacheable=true but no cache_keys"

    def test_all_cached_skills_have_no_cache_flag(self):
        for name, skill in self.registry.items():
            if not skill.get("cacheable"):
                continue
            found = any(
                "--no-cache" in entry.get("accepts", {})
                for entry in skill.get("entry_scripts", [])
            )
            assert found, \
                f"{name}: cacheable=true but no entry script accepts --no-cache"

    def test_expected_skills_are_cacheable(self):
        expected = {
            "callgraph-tracer", "classify-functions", "generate-re-report",
            "import-export-resolver", "map-attack-surface", "reconstruct-types",
            "com-interface-reconstruction", "security-dossier",
            "data-flow-tracer", "taint-analysis", "string-intelligence",
            "deep-research-prompt", "state-machine-extractor", "verify-decompiled",
            "logic-vulnerability-detector", "memory-corruption-detector",
        }
        actual = {
            n for n, s in self.registry.items() if s.get("cacheable")
        }
        assert expected == actual

    def test_expected_cache_keys_per_skill(self):
        expected = {
            "callgraph-tracer": {"call_graph"},
            "classify-functions": {"triage_summary", "classify_module"},
            "generate-re-report": {"analyze_topology", "analyze_imports",
                                   "analyze_strings", "analyze_complexity"},
            "import-export-resolver": {"import_export_index"},
            "map-attack-surface": {"discover_entrypoints"},
            "reconstruct-types": {"scan_struct_fields"},
            "com-interface-reconstruction": {"scan_com_interfaces"},
            "security-dossier": {"security_dossier"},
            "string-intelligence": {"string_analysis"},
            "deep-research-prompt": {"gather_function_context"},
            "state-machine-extractor": {"detect_dispatchers"},
            "verify-decompiled": {"scan_module_verify"},
        }
        for skill_name, keys in expected.items():
            actual = set(self.registry[skill_name].get("cache_keys", []))
            assert actual == keys, \
                f"{skill_name}: expected {sorted(keys)}, got {sorted(actual)}"
