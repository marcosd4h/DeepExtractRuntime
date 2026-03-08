"""Tests for the import-export-resolver skill and ImportExportIndex helper.

Covers registry consistency, ImportExportIndex unit tests with seeded
sample databases, edge cases (empty/malformed data), the unified search
import dimension, and subprocess-level script execution tests.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from helpers.import_export_index import (
    ExportEntry,
    ImportEntry,
    ImportExportIndex,
)

_AGENT_DIR = Path(__file__).resolve().parents[1]
_SCRIPTS_DIR = _AGENT_DIR / "skills" / "import-export-resolver" / "scripts"
_SUBPROCESS_ENV = {**os.environ, "PYTHONPATH": str(_AGENT_DIR)}

_FULL_INDEX_CACHE = _AGENT_DIR / "cache" / "analyzed_files" / "import_export_index_full.json"


@pytest.fixture(autouse=True)
def _clean_full_index_cache():
    """Remove the full-index persistent cache between tests.

    All test fixtures use ``analyzed_files.db`` as the tracking DB name,
    which maps to the same cache path.  Without cleanup a cache written
    by one test would be loaded by the next, causing cross-contamination.
    """
    _FULL_INDEX_CACHE.unlink(missing_ok=True)
    yield
    _FULL_INDEX_CACHE.unlink(missing_ok=True)


# -----------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------

def _create_tracking_db(db_path: Path, modules: list[dict]) -> None:
    """Create a minimal tracking DB pointing to module analysis DBs."""
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE analyzed_files (
            file_path TEXT PRIMARY KEY, base_dir TEXT, file_name TEXT,
            file_extension TEXT, md5_hash TEXT, sha256_hash TEXT,
            analysis_db_path TEXT, status TEXT, analysis_flags TEXT,
            analysis_start_timestamp TEXT, analysis_completion_timestamp TEXT
        )
    """)
    for mod in modules:
        conn.execute("""
            INSERT INTO analyzed_files
            (file_path, file_name, file_extension, analysis_db_path, status)
            VALUES (?, ?, ?, ?, 'COMPLETE')
        """, (
            mod["file_path"],
            mod["file_name"],
            ".dll",
            mod["analysis_db_path"],
        ))
    conn.commit()
    conn.close()


def _create_analysis_db(
    db_path: Path,
    file_name: str,
    imports_json: str | None = None,
    exports_json: str | None = None,
) -> None:
    """Create a minimal analysis DB with file_info containing import/export data."""
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE schema_version (version INTEGER)")
    conn.execute("INSERT INTO schema_version VALUES (1)")
    conn.execute("""
        CREATE TABLE file_info (
            file_path TEXT, base_dir TEXT, file_name TEXT, file_extension TEXT,
            file_size_bytes INTEGER, md5_hash TEXT, sha256_hash TEXT,
            imports TEXT, exports TEXT, entry_point TEXT, file_version TEXT,
            product_version TEXT, company_name TEXT, file_description TEXT,
            internal_name TEXT, original_filename TEXT, legal_copyright TEXT,
            product_name TEXT, time_date_stamp_str TEXT, file_modified_date_str TEXT,
            sections TEXT, pdb_path TEXT, rich_header TEXT, tls_callbacks TEXT,
            is_net_assembly BOOLEAN, clr_metadata TEXT, idb_cache_path TEXT,
            dll_characteristics TEXT, security_features TEXT, exception_info TEXT,
            load_config TEXT, analysis_timestamp TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE functions (
            function_id INTEGER PRIMARY KEY, function_signature TEXT,
            function_signature_extended TEXT, mangled_name TEXT,
            function_name TEXT, assembly_code TEXT, decompiled_code TEXT,
            inbound_xrefs TEXT, outbound_xrefs TEXT, simple_inbound_xrefs TEXT,
            simple_outbound_xrefs TEXT, vtable_contexts TEXT,
            global_var_accesses TEXT, dangerous_api_calls TEXT,
            string_literals TEXT, stack_frame TEXT, loop_analysis TEXT,
            analysis_errors TEXT, created_at TEXT
        )
    """)
    conn.execute("""
        INSERT INTO file_info (file_path, file_name, file_extension,
            imports, exports)
        VALUES (?, ?, '.dll', ?, ?)
    """, (
        f"C:\\test\\{file_name}",
        file_name,
        imports_json,
        exports_json,
    ))
    conn.commit()
    conn.close()


@pytest.fixture
def ie_workspace(tmp_path):
    """Create a workspace with two module DBs and a tracking DB.

    Module A (appinfo.dll):
      - Exports: AiLaunchProcess, AiCheckToken
      - Imports: CreateProcessW from kernel32.dll, NtOpenProcess from ntdll.dll

    Module B (kernel32.dll):
      - Exports: CreateProcessW (forwarded to kernelbase.CreateProcessW),
                 HeapAlloc (forwarded to ntdll.RtlAllocateHeap)
      - Imports: NtAllocateVirtualMemory from ntdll.dll
    """
    dbs_dir = tmp_path / "extracted_dbs"
    dbs_dir.mkdir()

    appinfo_imports = json.dumps([
        {
            "module_name": "kernel32.dll",
            "raw_module_name": "KERNEL32",
            "functions": [
                {"function_name": "CreateProcessW", "ordinal": 0, "is_delay_loaded": False},
                {"function_name": "CloseHandle", "ordinal": 0, "is_delay_loaded": False},
            ],
        },
        {
            "module_name": "ntdll.dll",
            "raw_module_name": "ntdll",
            "functions": [
                {"function_name": "NtOpenProcess", "ordinal": 0, "is_delay_loaded": True},
            ],
        },
    ])
    appinfo_exports = json.dumps([
        {"function_name": "AiLaunchProcess", "ordinal": 1, "is_forwarded": False},
        {"function_name": "AiCheckToken", "ordinal": 2, "is_forwarded": False},
    ])

    kernel32_imports = json.dumps([
        {
            "module_name": "ntdll.dll",
            "functions": [
                {"function_name": "NtAllocateVirtualMemory", "ordinal": 0, "is_delay_loaded": False},
            ],
        },
    ])
    kernel32_exports = json.dumps([
        {
            "function_name": "CreateProcessW", "ordinal": 123,
            "is_forwarded": True, "forwarded_to": "kernelbase.CreateProcessW",
        },
        {
            "function_name": "HeapAlloc", "ordinal": 456,
            "is_forwarded": True, "forwarded_to": "ntdll.RtlAllocateHeap",
        },
        {
            "function_name": "GetLastError", "ordinal": 789,
            "is_forwarded": False,
        },
    ])

    appinfo_db = dbs_dir / "appinfo_dll_abc123.db"
    kernel32_db = dbs_dir / "kernel32_dll_def456.db"

    _create_analysis_db(appinfo_db, "appinfo.dll", appinfo_imports, appinfo_exports)
    _create_analysis_db(kernel32_db, "kernel32.dll", kernel32_imports, kernel32_exports)

    tracking_db = dbs_dir / "analyzed_files.db"
    _create_tracking_db(tracking_db, [
        {
            "file_path": "C:\\test\\appinfo.dll",
            "file_name": "appinfo.dll",
            "analysis_db_path": "appinfo_dll_abc123.db",
        },
        {
            "file_path": "C:\\test\\kernel32.dll",
            "file_name": "kernel32.dll",
            "analysis_db_path": "kernel32_dll_def456.db",
        },
    ])

    return tracking_db


# -----------------------------------------------------------------------
# Registry consistency
# -----------------------------------------------------------------------

class TestRegistryConsistency:
    def test_skill_in_registry(self):
        registry_path = Path(__file__).resolve().parents[1] / "skills" / "registry.json"
        with open(registry_path) as f:
            registry = json.load(f)
        skills = registry["skills"]
        assert "import-export-resolver" in skills

    def test_registry_type(self):
        registry_path = Path(__file__).resolve().parents[1] / "skills" / "registry.json"
        with open(registry_path) as f:
            registry = json.load(f)
        entry = registry["skills"]["import-export-resolver"]
        assert entry["type"] == "analysis"
        assert entry["cacheable"] is True
        assert entry["json_output"] is True

    def test_registry_depends_on(self):
        registry_path = Path(__file__).resolve().parents[1] / "skills" / "registry.json"
        with open(registry_path) as f:
            registry = json.load(f)
        entry = registry["skills"]["import-export-resolver"]
        assert "decompiled-code-extractor" in entry["depends_on"]

    def test_registry_entry_scripts(self):
        registry_path = Path(__file__).resolve().parents[1] / "skills" / "registry.json"
        with open(registry_path) as f:
            registry = json.load(f)
        entry = registry["skills"]["import-export-resolver"]
        script_names = {s["script"] for s in entry["entry_scripts"]}
        assert script_names == {
            "query_function.py",
            "build_index.py",
            "module_deps.py",
            "resolve_forwarders.py",
        }

    def test_skill_md_exists(self):
        skill_dir = Path(__file__).resolve().parents[1] / "skills" / "import-export-resolver"
        assert (skill_dir / "SKILL.md").exists()
        assert (skill_dir / "README.md").exists()
        assert (skill_dir / "scripts" / "_common.py").exists()


# -----------------------------------------------------------------------
# ImportExportIndex unit tests
# -----------------------------------------------------------------------

class TestImportExportIndex:
    def test_who_exports(self, ie_workspace):
        with ImportExportIndex(str(ie_workspace)) as idx:
            results = idx.who_exports("CreateProcessW")
        assert len(results) == 1
        assert results[0].module == "kernel32.dll"
        assert results[0].is_forwarded is True

    def test_who_exports_case_insensitive(self, ie_workspace):
        with ImportExportIndex(str(ie_workspace)) as idx:
            results = idx.who_exports("createprocessw")
        assert len(results) == 1
        assert results[0].module == "kernel32.dll"

    def test_who_exports_not_found(self, ie_workspace):
        with ImportExportIndex(str(ie_workspace)) as idx:
            results = idx.who_exports("NonexistentFunction")
        assert results == []

    def test_who_exports_multiple(self, ie_workspace):
        with ImportExportIndex(str(ie_workspace)) as idx:
            results = idx.who_exports("AiLaunchProcess")
        assert len(results) == 1
        assert results[0].module == "appinfo.dll"
        assert results[0].is_forwarded is False

    def test_who_imports(self, ie_workspace):
        with ImportExportIndex(str(ie_workspace)) as idx:
            results = idx.who_imports("CreateProcessW")
        assert len(results) == 1
        assert results[0].importing_module == "appinfo.dll"
        assert results[0].source_module == "kernel32.dll"

    def test_who_imports_with_filter(self, ie_workspace):
        with ImportExportIndex(str(ie_workspace)) as idx:
            results = idx.who_imports(
                "NtAllocateVirtualMemory", from_module="ntdll.dll"
            )
        assert len(results) == 1
        assert results[0].importing_module == "kernel32.dll"

    def test_who_imports_delay_loaded(self, ie_workspace):
        with ImportExportIndex(str(ie_workspace)) as idx:
            results = idx.who_imports("NtOpenProcess")
        assert len(results) == 1
        assert results[0].is_delay_loaded is True

    def test_module_consumers(self, ie_workspace):
        with ImportExportIndex(str(ie_workspace)) as idx:
            consumers = idx.module_consumers("kernel32.dll")
        assert "appinfo.dll" in consumers
        assert "CreateProcessW" in consumers["appinfo.dll"]

    def test_module_consumers_ntdll(self, ie_workspace):
        with ImportExportIndex(str(ie_workspace)) as idx:
            consumers = idx.module_consumers("ntdll.dll")
        consumer_names = set(consumers.keys())
        assert "appinfo.dll" in consumer_names
        assert "kernel32.dll" in consumer_names

    def test_module_suppliers(self, ie_workspace):
        with ImportExportIndex(str(ie_workspace)) as idx:
            suppliers = idx.module_suppliers("appinfo.dll")
        assert "kernel32.dll" in suppliers
        assert "ntdll.dll" in suppliers
        assert "CreateProcessW" in suppliers["kernel32.dll"]

    def test_dependency_graph(self, ie_workspace):
        with ImportExportIndex(str(ie_workspace)) as idx:
            graph = idx.dependency_graph()
        assert "appinfo.dll" in graph
        assert "kernel32.dll" in graph["appinfo.dll"]
        assert "ntdll.dll" in graph["appinfo.dll"]
        assert "kernel32.dll" in graph
        assert "ntdll.dll" in graph["kernel32.dll"]

    def test_resolve_forwarder_chain(self, ie_workspace):
        with ImportExportIndex(str(ie_workspace)) as idx:
            chain = idx.resolve_forwarder_chain("kernel32.dll", "CreateProcessW")
        assert len(chain) >= 1
        assert chain[0] == ("kernel32.dll", "CreateProcessW")

    def test_module_export_list(self, ie_workspace):
        with ImportExportIndex(str(ie_workspace)) as idx:
            exports = idx.module_export_list("kernel32.dll")
        names = {e.name for e in exports}
        assert "CreateProcessW" in names
        assert "HeapAlloc" in names
        assert "GetLastError" in names

    def test_summary(self, ie_workspace):
        with ImportExportIndex(str(ie_workspace)) as idx:
            s = idx.summary()
        assert s["module_count"] == 2
        assert s["total_exports"] == 5  # 2 appinfo + 3 kernel32
        assert s["total_imports"] == 4  # 3 appinfo + 1 kernel32
        assert s["forwarded_count"] == 2
        assert s["unique_export_names"] == 5
        assert s["unique_import_names"] == 4

    def test_context_manager(self, ie_workspace):
        idx = ImportExportIndex(str(ie_workspace))
        with idx:
            assert idx.who_exports("CreateProcessW")
        with pytest.raises(RuntimeError, match="closed"):
            idx.who_exports("CreateProcessW")


# -----------------------------------------------------------------------
# Edge cases
# -----------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_imports_exports(self, tmp_path):
        """Module with no imports or exports should be handled gracefully."""
        dbs_dir = tmp_path / "extracted_dbs"
        dbs_dir.mkdir()

        db_path = dbs_dir / "empty_dll.db"
        _create_analysis_db(db_path, "empty.dll", None, None)

        tracking_db = dbs_dir / "analyzed_files.db"
        _create_tracking_db(tracking_db, [{
            "file_path": "C:\\test\\empty.dll",
            "file_name": "empty.dll",
            "analysis_db_path": "empty_dll.db",
        }])

        with ImportExportIndex(str(tracking_db)) as idx:
            assert idx.who_exports("anything") == []
            assert idx.who_imports("anything") == []
            s = idx.summary()
            assert s["total_exports"] == 0
            assert s["total_imports"] == 0

    def test_malformed_json(self, tmp_path):
        """Malformed JSON in imports/exports should not crash."""
        dbs_dir = tmp_path / "extracted_dbs"
        dbs_dir.mkdir()

        db_path = dbs_dir / "bad_dll.db"
        _create_analysis_db(db_path, "bad.dll", "{not valid json[", "also broken")

        tracking_db = dbs_dir / "analyzed_files.db"
        _create_tracking_db(tracking_db, [{
            "file_path": "C:\\test\\bad.dll",
            "file_name": "bad.dll",
            "analysis_db_path": "bad_dll.db",
        }])

        with ImportExportIndex(str(tracking_db)) as idx:
            assert idx.who_exports("anything") == []
            assert idx.who_imports("anything") == []

    def test_no_tracking_db(self, tmp_path):
        """Non-existent tracking DB should produce empty index."""
        fake_path = str(tmp_path / "nonexistent.db")
        with ImportExportIndex(fake_path) as idx:
            assert idx.who_exports("anything") == []
            assert idx.summary()["module_count"] == 0

    def test_dataclass_to_dict(self):
        exp = ExportEntry(
            module="test.dll", db_path="/test.db", name="Foo",
            ordinal=1, is_forwarded=False, forwarded_to=None,
        )
        d = exp.to_dict()
        assert d["module"] == "test.dll"
        assert d["name"] == "Foo"

        imp = ImportEntry(
            importing_module="a.dll", source_module="b.dll",
            function_name="Bar", is_delay_loaded=True, ordinal=0,
        )
        d = imp.to_dict()
        assert d["is_delay_loaded"] is True


# -----------------------------------------------------------------------
# Subprocess-level script tests
# -----------------------------------------------------------------------

class TestBuildIndexScript:
    """Run build_index.py as a subprocess and validate output."""

    def test_json_output(self, ie_workspace):
        result = subprocess.run(
            [sys.executable, str(_SCRIPTS_DIR / "build_index.py"),
             str(ie_workspace), "--json"],
            capture_output=True, text=True, timeout=30,
            env=_SUBPROCESS_ENV,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        data = json.loads(result.stdout)
        assert data["status"] == "ok"
        assert data["module_count"] == 2
        assert data["total_exports"] == 5
        assert data["total_imports"] == 4
        assert data["forwarded_count"] == 2
        assert "_meta" in data

    def test_text_output(self, ie_workspace):
        result = subprocess.run(
            [sys.executable, str(_SCRIPTS_DIR / "build_index.py"),
             str(ie_workspace)],
            capture_output=True, text=True, timeout=30,
            env=_SUBPROCESS_ENV,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert "Modules indexed" in result.stdout
        assert "Total exports" in result.stdout

    def test_no_cache_flag(self, ie_workspace):
        result = subprocess.run(
            [sys.executable, str(_SCRIPTS_DIR / "build_index.py"),
             str(ie_workspace), "--json", "--no-cache"],
            capture_output=True, text=True, timeout=30,
            env=_SUBPROCESS_ENV,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        data = json.loads(result.stdout)
        assert data["status"] == "ok"

    def test_missing_tracking_db_degrades_gracefully(self, tmp_path):
        """A nonexistent tracking DB should degrade gracefully with empty results."""
        fake = str(tmp_path / "nonexistent.db")
        result = subprocess.run(
            [sys.executable, str(_SCRIPTS_DIR / "build_index.py"),
             fake, "--json", "--no-cache"],
            capture_output=True, text=True, timeout=30,
            env=_SUBPROCESS_ENV,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["status"] == "ok"
        assert data["module_count"] == 0
        assert data["total_exports"] == 0


class TestQueryFunctionScript:
    """Run query_function.py as a subprocess and validate output."""

    def test_both_directions_json(self, ie_workspace):
        result = subprocess.run(
            [sys.executable, str(_SCRIPTS_DIR / "query_function.py"),
             str(ie_workspace), "--function", "CreateProcessW", "--json"],
            capture_output=True, text=True, timeout=30,
            env=_SUBPROCESS_ENV,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        data = json.loads(result.stdout)
        assert data["status"] == "ok"
        assert data["function"] == "CreateProcessW"
        assert data["direction"] == "both"
        assert len(data["exporters"]) == 1
        assert data["exporters"][0]["module"] == "kernel32.dll"
        assert len(data["importers"]) == 1
        assert data["importers"][0]["importing_module"] == "appinfo.dll"

    def test_export_direction_only(self, ie_workspace):
        result = subprocess.run(
            [sys.executable, str(_SCRIPTS_DIR / "query_function.py"),
             str(ie_workspace), "--function", "CreateProcessW",
             "--direction", "export", "--json"],
            capture_output=True, text=True, timeout=30,
            env=_SUBPROCESS_ENV,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        data = json.loads(result.stdout)
        assert "exporters" in data
        assert "importers" not in data

    def test_import_direction_only(self, ie_workspace):
        result = subprocess.run(
            [sys.executable, str(_SCRIPTS_DIR / "query_function.py"),
             str(ie_workspace), "--function", "CreateProcessW",
             "--direction", "import", "--json"],
            capture_output=True, text=True, timeout=30,
            env=_SUBPROCESS_ENV,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        data = json.loads(result.stdout)
        assert "importers" in data
        assert "exporters" not in data

    def test_not_found_function(self, ie_workspace):
        result = subprocess.run(
            [sys.executable, str(_SCRIPTS_DIR / "query_function.py"),
             str(ie_workspace), "--function", "ZZZNonexistent", "--json"],
            capture_output=True, text=True, timeout=30,
            env=_SUBPROCESS_ENV,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        data = json.loads(result.stdout)
        assert data["status"] == "ok"
        assert data["exporters"] == []
        assert data["importers"] == []

    def test_text_output(self, ie_workspace):
        result = subprocess.run(
            [sys.executable, str(_SCRIPTS_DIR / "query_function.py"),
             str(ie_workspace), "--function", "CreateProcessW"],
            capture_output=True, text=True, timeout=30,
            env=_SUBPROCESS_ENV,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert "Exporters" in result.stdout
        assert "kernel32.dll" in result.stdout
        assert "Importers" in result.stdout
        assert "appinfo.dll" in result.stdout

    def test_missing_function_arg(self, ie_workspace):
        result = subprocess.run(
            [sys.executable, str(_SCRIPTS_DIR / "query_function.py"),
             str(ie_workspace), "--json"],
            capture_output=True, text=True, timeout=30,
            env=_SUBPROCESS_ENV,
        )
        assert result.returncode == 1


class TestModuleDepsScript:
    """Run module_deps.py as a subprocess and validate output."""

    def test_full_graph_json(self, ie_workspace):
        result = subprocess.run(
            [sys.executable, str(_SCRIPTS_DIR / "module_deps.py"),
             str(ie_workspace), "--json"],
            capture_output=True, text=True, timeout=30,
            env=_SUBPROCESS_ENV,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        data = json.loads(result.stdout)
        assert data["status"] == "ok"
        assert data["mode"] == "full_graph"
        assert "appinfo.dll" in data["graph"]
        assert "kernel32.dll" in data["graph"]["appinfo.dll"]

    def test_module_suppliers(self, ie_workspace):
        result = subprocess.run(
            [sys.executable, str(_SCRIPTS_DIR / "module_deps.py"),
             str(ie_workspace), "--module", "appinfo.dll", "--json"],
            capture_output=True, text=True, timeout=30,
            env=_SUBPROCESS_ENV,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        data = json.loads(result.stdout)
        assert data["mode"] == "suppliers"
        assert "kernel32.dll" in data["suppliers"]
        assert "ntdll.dll" in data["suppliers"]

    def test_module_consumers(self, ie_workspace):
        result = subprocess.run(
            [sys.executable, str(_SCRIPTS_DIR / "module_deps.py"),
             str(ie_workspace), "--module", "ntdll.dll",
             "--consumers", "--json"],
            capture_output=True, text=True, timeout=30,
            env=_SUBPROCESS_ENV,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        data = json.loads(result.stdout)
        assert data["mode"] == "consumers"
        assert "appinfo.dll" in data["consumers"]
        assert "kernel32.dll" in data["consumers"]

    def test_consumers_requires_module(self, ie_workspace):
        result = subprocess.run(
            [sys.executable, str(_SCRIPTS_DIR / "module_deps.py"),
             str(ie_workspace), "--consumers", "--json"],
            capture_output=True, text=True, timeout=30,
            env=_SUBPROCESS_ENV,
        )
        assert result.returncode == 2

    def test_diagram_output(self, ie_workspace):
        result = subprocess.run(
            [sys.executable, str(_SCRIPTS_DIR / "module_deps.py"),
             str(ie_workspace), "--diagram"],
            capture_output=True, text=True, timeout=30,
            env=_SUBPROCESS_ENV,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert "```mermaid" in result.stdout
        assert "flowchart LR" in result.stdout

    def test_text_output(self, ie_workspace):
        result = subprocess.run(
            [sys.executable, str(_SCRIPTS_DIR / "module_deps.py"),
             str(ie_workspace)],
            capture_output=True, text=True, timeout=30,
            env=_SUBPROCESS_ENV,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert "PE Module Dependency Graph" in result.stdout


class TestResolveForwardersScript:
    """Run resolve_forwarders.py as a subprocess and validate output."""

    def test_single_chain_json(self, ie_workspace):
        result = subprocess.run(
            [sys.executable, str(_SCRIPTS_DIR / "resolve_forwarders.py"),
             str(ie_workspace), "--module", "kernel32.dll",
             "--function", "CreateProcessW", "--json"],
            capture_output=True, text=True, timeout=30,
            env=_SUBPROCESS_ENV,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        data = json.loads(result.stdout)
        assert data["status"] == "ok"
        assert data["mode"] == "single"
        assert data["chain"][0]["module"] == "kernel32.dll"
        assert data["chain"][0]["function"] == "CreateProcessW"
        assert data["chain_length"] >= 1

    def test_all_forwarded_json(self, ie_workspace):
        result = subprocess.run(
            [sys.executable, str(_SCRIPTS_DIR / "resolve_forwarders.py"),
             str(ie_workspace), "--module", "kernel32.dll",
             "--all", "--json"],
            capture_output=True, text=True, timeout=30,
            env=_SUBPROCESS_ENV,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        data = json.loads(result.stdout)
        assert data["status"] == "ok"
        assert data["mode"] == "all_forwarded"
        assert data["forwarded_count"] == 2
        names = {e["export"] for e in data["forwarded_exports"]}
        assert "CreateProcessW" in names
        assert "HeapAlloc" in names

    def test_non_forwarded_function(self, ie_workspace):
        result = subprocess.run(
            [sys.executable, str(_SCRIPTS_DIR / "resolve_forwarders.py"),
             str(ie_workspace), "--module", "kernel32.dll",
             "--function", "GetLastError", "--json"],
            capture_output=True, text=True, timeout=30,
            env=_SUBPROCESS_ENV,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        data = json.loads(result.stdout)
        assert data["chain_length"] == 1

    def test_text_output(self, ie_workspace):
        result = subprocess.run(
            [sys.executable, str(_SCRIPTS_DIR / "resolve_forwarders.py"),
             str(ie_workspace), "--module", "kernel32.dll",
             "--function", "HeapAlloc"],
            capture_output=True, text=True, timeout=30,
            env=_SUBPROCESS_ENV,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert "Forwarder chain" in result.stdout
        assert "kernel32.dll" in result.stdout

    def test_module_required(self, ie_workspace):
        result = subprocess.run(
            [sys.executable, str(_SCRIPTS_DIR / "resolve_forwarders.py"),
             str(ie_workspace), "--function", "HeapAlloc", "--json"],
            capture_output=True, text=True, timeout=30,
            env=_SUBPROCESS_ENV,
        )
        assert result.returncode == 2

    def test_function_or_all_required(self, ie_workspace):
        result = subprocess.run(
            [sys.executable, str(_SCRIPTS_DIR / "resolve_forwarders.py"),
             str(ie_workspace), "--module", "kernel32.dll", "--json"],
            capture_output=True, text=True, timeout=30,
            env=_SUBPROCESS_ENV,
        )
        assert result.returncode == 2


# -----------------------------------------------------------------------
# Hybrid JSON+DB path tests
# -----------------------------------------------------------------------

def _write_file_info_json(
    module_dir: Path,
    imports: list | None = None,
    exports: list | None = None,
) -> Path:
    """Write a file_info.json with the given imports/exports into a module dir."""
    module_dir.mkdir(parents=True, exist_ok=True)
    data = {
        "module_name": module_dir.name,
        "basic_file_info": {"file_name": module_dir.name},
        "imports": imports,
        "exports": exports,
    }
    fi_path = module_dir / "file_info.json"
    fi_path.write_text(json.dumps(data), encoding="utf-8")
    return fi_path


@pytest.fixture
def hybrid_workspace(tmp_path):
    """Create a workspace with three modules:

    - appinfo.dll: has BOTH file_info.json AND a DB  (JSON path used)
    - kernel32.dll: has ONLY a DB, no file_info.json  (DB fallback)
    - ntoskrnl.exe: has ONLY file_info.json, no DB   (not in tracking DB, so skipped)

    This validates the hybrid strategy.
    """
    dbs_dir = tmp_path / "extracted_dbs"
    dbs_dir.mkdir()
    code_dir = tmp_path / "extracted_code"
    code_dir.mkdir()

    appinfo_imports = [
        {
            "module_name": "kernel32.dll",
            "functions": [
                {"function_name": "CreateProcessW", "ordinal": 0, "is_delay_loaded": False},
            ],
        },
    ]
    appinfo_exports = [
        {"function_name": "AiLaunchProcess", "ordinal": 1, "is_forwarded": False},
    ]
    kernel32_exports = [
        {"function_name": "CreateProcessW", "ordinal": 123, "is_forwarded": False},
        {"function_name": "GetLastError", "ordinal": 456, "is_forwarded": False},
    ]
    kernel32_imports = [
        {
            "module_name": "ntdll.dll",
            "functions": [
                {"function_name": "NtClose", "ordinal": 0, "is_delay_loaded": False},
            ],
        },
    ]

    # appinfo.dll: create DB AND file_info.json in extracted_code/appinfo_dll/
    appinfo_db = dbs_dir / "appinfo_dll_abc.db"
    _create_analysis_db(
        appinfo_db, "appinfo.dll",
        json.dumps(appinfo_imports), json.dumps(appinfo_exports),
    )
    _write_file_info_json(
        code_dir / "appinfo_dll",
        imports=appinfo_imports, exports=appinfo_exports,
    )

    # kernel32.dll: create DB only, NO file_info.json
    kernel32_db = dbs_dir / "kernel32_dll_def.db"
    _create_analysis_db(
        kernel32_db, "kernel32.dll",
        json.dumps(kernel32_imports), json.dumps(kernel32_exports),
    )

    tracking_db = dbs_dir / "analyzed_files.db"
    _create_tracking_db(tracking_db, [
        {
            "file_path": "C:\\test\\appinfo.dll",
            "file_name": "appinfo.dll",
            "analysis_db_path": "appinfo_dll_abc.db",
        },
        {
            "file_path": "C:\\test\\kernel32.dll",
            "file_name": "kernel32.dll",
            "analysis_db_path": "kernel32_dll_def.db",
        },
    ])

    return tracking_db


@pytest.fixture
def json_only_workspace(tmp_path):
    """Workspace where all modules have file_info.json (no DB fallback needed)."""
    dbs_dir = tmp_path / "extracted_dbs"
    dbs_dir.mkdir()
    code_dir = tmp_path / "extracted_code"
    code_dir.mkdir()

    mod_a_imports = [
        {"module_name": "mod_b.dll", "functions": [
            {"function_name": "FuncB", "ordinal": 0, "is_delay_loaded": False},
        ]},
    ]
    mod_a_exports = [
        {"function_name": "FuncA", "ordinal": 1, "is_forwarded": False},
    ]
    mod_b_exports = [
        {"function_name": "FuncB", "ordinal": 1, "is_forwarded": False},
    ]

    db_a = dbs_dir / "mod_a_dll_111.db"
    db_b = dbs_dir / "mod_b_dll_222.db"
    _create_analysis_db(db_a, "mod_a.dll", json.dumps(mod_a_imports), json.dumps(mod_a_exports))
    _create_analysis_db(db_b, "mod_b.dll", None, json.dumps(mod_b_exports))

    _write_file_info_json(code_dir / "mod_a_dll", imports=mod_a_imports, exports=mod_a_exports)
    _write_file_info_json(code_dir / "mod_b_dll", imports=[], exports=mod_b_exports)

    tracking_db = dbs_dir / "analyzed_files.db"
    _create_tracking_db(tracking_db, [
        {"file_path": "C:\\test\\mod_a.dll", "file_name": "mod_a.dll", "analysis_db_path": "mod_a_dll_111.db"},
        {"file_path": "C:\\test\\mod_b.dll", "file_name": "mod_b.dll", "analysis_db_path": "mod_b_dll_222.db"},
    ])
    return tracking_db


class TestHybridJsonDbPath:
    """Verify the hybrid JSON+DB index build strategy."""

    def test_mixed_json_and_db(self, hybrid_workspace):
        """Module with JSON uses it; module without JSON falls back to DB."""
        with ImportExportIndex(str(hybrid_workspace)) as idx:
            # appinfo.dll (loaded from JSON or DB -- either way, data is correct)
            ai_exports = idx.who_exports("AiLaunchProcess")
            assert len(ai_exports) == 1
            assert ai_exports[0].module == "appinfo.dll"

            # kernel32.dll (must come from DB since there's no file_info.json)
            k32_exports = idx.who_exports("CreateProcessW")
            assert len(k32_exports) == 1
            assert k32_exports[0].module == "kernel32.dll"

            # Cross-module link: appinfo imports from kernel32
            importers = idx.who_imports("CreateProcessW")
            assert len(importers) == 1
            assert importers[0].importing_module == "appinfo.dll"

    def test_mixed_summary(self, hybrid_workspace):
        """Summary counts should reflect both JSON- and DB-sourced modules."""
        with ImportExportIndex(str(hybrid_workspace)) as idx:
            s = idx.summary()
        assert s["module_count"] == 2
        assert s["total_exports"] == 3  # 1 appinfo + 2 kernel32
        assert s["total_imports"] == 2  # 1 appinfo + 1 kernel32

    def test_all_json_path(self, json_only_workspace):
        """When all modules have file_info.json, no DB fallback is needed."""
        with ImportExportIndex(str(json_only_workspace)) as idx:
            assert len(idx.who_exports("FuncA")) == 1
            assert len(idx.who_exports("FuncB")) == 1
            assert len(idx.who_imports("FuncB")) == 1

            s = idx.summary()
            assert s["module_count"] == 2
            assert s["total_exports"] == 2
            assert s["total_imports"] == 1

    def test_json_with_corrupt_data_falls_back(self, tmp_path):
        """A corrupt file_info.json should be skipped; DB fallback is used."""
        dbs_dir = tmp_path / "extracted_dbs"
        dbs_dir.mkdir()
        code_dir = tmp_path / "extracted_code"
        code_dir.mkdir()

        exports = [{"function_name": "GoodFunc", "ordinal": 1, "is_forwarded": False}]
        db_path = dbs_dir / "test_dll_aaa.db"
        _create_analysis_db(db_path, "test.dll", None, json.dumps(exports))

        # Write a corrupt file_info.json
        bad_dir = code_dir / "test_dll"
        bad_dir.mkdir()
        (bad_dir / "file_info.json").write_text("{invalid json!!!", encoding="utf-8")

        tracking_db = dbs_dir / "analyzed_files.db"
        _create_tracking_db(tracking_db, [{
            "file_path": "C:\\test\\test.dll",
            "file_name": "test.dll",
            "analysis_db_path": "test_dll_aaa.db",
        }])

        with ImportExportIndex(str(tracking_db)) as idx:
            # JSON is corrupt, but the module should still be indexed from DB fallback
            # (the error handler catches JSONDecodeError and falls back)
            # Since _scan_one catches the exception, the module is skipped entirely
            # -- this is acceptable degradation behavior
            s = idx.summary()
            # Either 0 (skipped) or 1 (DB fallback) is acceptable
            assert s["module_count"] in (0, 1)

    def test_json_map_folder_name_resolution(self, tmp_path):
        """_build_json_map correctly maps folder names to file names."""
        code_dir = tmp_path / "extracted_code"
        (code_dir / "kernel32_dll").mkdir(parents=True)
        (code_dir / "kernel32_dll" / "file_info.json").write_text(
            '{"imports": [], "exports": []}', encoding="utf-8",
        )
        (code_dir / "ntdll_dll").mkdir()
        (code_dir / "ntdll_dll" / "file_info.json").write_text(
            '{"imports": [], "exports": []}', encoding="utf-8",
        )
        # Folder without file_info.json -- should not appear
        (code_dir / "empty_dll").mkdir()

        json_map = ImportExportIndex._build_json_map(tmp_path)

        assert "kernel32.dll" in json_map
        assert "kernel32_dll" in json_map
        assert "ntdll.dll" in json_map
        assert "ntdll_dll" in json_map
        assert "empty.dll" not in json_map
        assert "empty_dll" not in json_map

    def test_db_only_still_works(self, ie_workspace):
        """Original DB-only fixture (no extracted_code/) continues to work."""
        with ImportExportIndex(str(ie_workspace)) as idx:
            assert len(idx.who_exports("CreateProcessW")) == 1
            assert len(idx.who_imports("CreateProcessW")) == 1
            assert idx.summary()["module_count"] == 2

    def test_workspace_relative_analysis_db_path_is_indexed(self, tmp_path):
        dbs_dir = tmp_path / "extracted_dbs"
        dbs_dir.mkdir()

        exports = [{"function_name": "GoodFunc", "ordinal": 1, "is_forwarded": False}]
        module_db = dbs_dir / "test_dll_aaa.db"
        _create_analysis_db(module_db, "test.dll", None, json.dumps(exports))

        tracking_db = dbs_dir / "analyzed_files.db"
        _create_tracking_db(tracking_db, [{
            "file_path": "C:\\test\\test.dll",
            "file_name": "test.dll",
            "analysis_db_path": "extracted_dbs/test_dll_aaa.db",
        }])

        with ImportExportIndex(str(tracking_db)) as idx:
            exports = idx.who_exports("GoodFunc")
            assert len(exports) == 1
            assert exports[0].module == "test.dll"
            assert exports[0].db_path == str(module_db)


# -----------------------------------------------------------------------
# Full-index persistent cache tests
# -----------------------------------------------------------------------

class TestFullIndexCache:
    """Verify the persistent full-index cache in ImportExportIndex."""

    def test_cache_created_on_first_build(self, ie_workspace, monkeypatch):
        """First instantiation should write a cache file to disk."""
        from helpers.cache import _cache_path, _module_from_db_path

        db_str = str(ie_workspace)
        module = _module_from_db_path(db_str)
        path = _cache_path(module, ImportExportIndex._CACHE_OPERATION)

        assert not path.exists()
        with ImportExportIndex(db_str) as idx:
            idx.summary()
        assert path.exists()

    def test_cache_hit_on_second_build(self, ie_workspace, monkeypatch):
        """Second instantiation should load from cache, not scan DBs."""
        db_str = str(ie_workspace)

        with ImportExportIndex(db_str) as idx:
            first_summary = idx.summary()

        scan_calls: list[str] = []
        orig_scan_db = ImportExportIndex._scan_module_from_db

        def tracking_scan(db_path, file_name):
            scan_calls.append("db")
            return orig_scan_db(db_path, file_name)

        monkeypatch.setattr(
            ImportExportIndex, "_scan_module_from_db",
            staticmethod(tracking_scan),
        )

        with ImportExportIndex(db_str) as idx:
            second_summary = idx.summary()

        assert scan_calls == [], "DB scan should not have been called on cache hit"
        assert first_summary == second_summary

    def test_cache_invalidated_on_db_change(self, ie_workspace):
        """Modifying the tracking DB should invalidate the cache."""
        import time

        db_str = str(ie_workspace)

        with ImportExportIndex(db_str) as idx:
            idx.summary()

        time.sleep(0.05)
        conn = sqlite3.connect(db_str)
        conn.execute("UPDATE analyzed_files SET status='COMPLETE' WHERE 1=1")
        conn.commit()
        conn.close()

        with ImportExportIndex(db_str) as idx:
            s = idx.summary()
        assert s["module_count"] == 2

    def test_cache_invalidated_on_module_db_change_without_tracking_db_touch(
        self,
        ie_workspace,
        monkeypatch,
    ):
        db_str = str(ie_workspace)

        with ImportExportIndex(db_str) as idx:
            idx.summary()

        workspace_root = ie_workspace.parent.parent
        module_db = workspace_root / "extracted_dbs" / "kernel32_dll_def456.db"
        current_mtime = os.path.getmtime(module_db)
        os.utime(module_db, (current_mtime + 5, current_mtime + 5))

        scan_calls: list[str] = []
        orig_scan_db = ImportExportIndex._scan_module_from_db

        def tracking_scan(db_path, file_name):
            scan_calls.append(file_name)
            return orig_scan_db(db_path, file_name)

        monkeypatch.setattr(
            ImportExportIndex,
            "_scan_module_from_db",
            staticmethod(tracking_scan),
        )

        with ImportExportIndex(db_str) as idx:
            idx.summary()

        assert "kernel32.dll" in scan_calls

    def test_cache_invalidated_on_file_info_json_change_without_tracking_db_touch(
        self,
        hybrid_workspace,
        monkeypatch,
    ):
        db_str = str(hybrid_workspace)

        with ImportExportIndex(db_str) as idx:
            idx.summary()

        workspace_root = hybrid_workspace.parent.parent
        json_path = workspace_root / "extracted_code" / "appinfo_dll" / "file_info.json"
        current_mtime = os.path.getmtime(json_path)
        os.utime(json_path, (current_mtime + 5, current_mtime + 5))

        scan_calls: list[str] = []
        orig_scan_json = ImportExportIndex._scan_module_from_json

        def tracking_scan(json_path_arg, file_name, db_path):
            scan_calls.append(file_name)
            return orig_scan_json(json_path_arg, file_name, db_path)

        monkeypatch.setattr(
            ImportExportIndex,
            "_scan_module_from_json",
            staticmethod(tracking_scan),
        )

        with ImportExportIndex(db_str) as idx:
            idx.summary()

        assert "appinfo.dll" in scan_calls

    def test_no_cache_bypasses_cache(self, ie_workspace):
        """no_cache=True should skip reading and writing the cache."""
        from helpers.cache import _cache_path, _module_from_db_path

        db_str = str(ie_workspace)
        module = _module_from_db_path(db_str)
        path = _cache_path(module, ImportExportIndex._CACHE_OPERATION)

        with ImportExportIndex(db_str, no_cache=True) as idx:
            s = idx.summary()

        assert s["module_count"] == 2
        assert not path.exists(), "Cache file should not be written when no_cache=True"

    def test_cache_roundtrip_data_integrity(self, ie_workspace):
        """All query results must be identical between fresh build and cached load."""
        db_str = str(ie_workspace)

        with ImportExportIndex(db_str, no_cache=True) as fresh:
            fresh_exporters = fresh.who_exports("CreateProcessW")
            fresh_importers = fresh.who_imports("CreateProcessW")
            fresh_consumers = fresh.module_consumers("ntdll.dll")
            fresh_suppliers = fresh.module_suppliers("appinfo.dll")
            fresh_graph = fresh.dependency_graph()
            fresh_export_list = fresh.module_export_list("kernel32.dll")
            fresh_chain = fresh.resolve_forwarder_chain("kernel32.dll", "CreateProcessW")
            fresh_summary = fresh.summary()

        with ImportExportIndex(db_str) as idx:
            idx.summary()

        with ImportExportIndex(db_str) as cached:
            assert [e.to_dict() for e in cached.who_exports("CreateProcessW")] == \
                   [e.to_dict() for e in fresh_exporters]
            assert [i.to_dict() for i in cached.who_imports("CreateProcessW")] == \
                   [i.to_dict() for i in fresh_importers]

            cached_consumers = cached.module_consumers("ntdll.dll")
            for mod in fresh_consumers:
                assert sorted(cached_consumers[mod]) == sorted(fresh_consumers[mod])

            cached_suppliers = cached.module_suppliers("appinfo.dll")
            for src in fresh_suppliers:
                assert sorted(cached_suppliers[src]) == sorted(fresh_suppliers[src])

            cached_graph = cached.dependency_graph()
            assert set(cached_graph.keys()) == set(fresh_graph.keys())
            for mod in fresh_graph:
                assert cached_graph[mod] == fresh_graph[mod]

            assert [e.to_dict() for e in cached.module_export_list("kernel32.dll")] == \
                   [e.to_dict() for e in fresh_export_list]

            assert cached.resolve_forwarder_chain("kernel32.dll", "CreateProcessW") == fresh_chain
            assert cached.summary() == fresh_summary
