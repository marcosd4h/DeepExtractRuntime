"""Shared test fixtures and helpers for the DeepExtractIDA test suite.

Fixture data is modeled on real extractions from appinfo.dll (Windows
Application Information Service) to ensure tests reflect actual IDA
output structure, field formats, and data patterns.
"""

import pytest
import sqlite3
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from helpers.individual_analysis_db.records import FunctionRecord


# -----------------------------------------------------------------------
# Helper functions (importable by test modules)
# -----------------------------------------------------------------------

def _make_function_record(**kwargs) -> FunctionRecord:
    """Create a FunctionRecord with defaults for all fields."""
    defaults = {
        "function_id": 0, "function_signature": None, "function_signature_extended": None,
        "mangled_name": None, "function_name": None, "assembly_code": None,
        "decompiled_code": None, "inbound_xrefs": None, "outbound_xrefs": None,
        "simple_inbound_xrefs": None, "simple_outbound_xrefs": None,
        "vtable_contexts": None, "global_var_accesses": None, "dangerous_api_calls": None,
        "string_literals": None, "stack_frame": None, "loop_analysis": None,
        "analysis_errors": None, "created_at": None,
    }
    for k, v in kwargs.items():
        if k in defaults:
            defaults[k] = v
    return FunctionRecord(**defaults)


def import_skill_module(skill_name: str, module_name: str = "_common"):
    """Import a skill module via the script_runner helper."""
    from helpers.script_runner import load_skill_module
    return load_skill_module(skill_name, module_name)


def _create_sample_db(db_path: Path):
    """Create a minimal analysis DB with schema but no data."""
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
    conn.commit()
    conn.close()


# -----------------------------------------------------------------------
# Realistic data constants (modeled on appinfo.dll / cmd.exe extractions)
# -----------------------------------------------------------------------

# Modeled on appinfo.dll security_features
_SECURITY_FEATURES = json.dumps({
    "aslr_enabled": True,
    "cfg_enabled": True,
    "cfg_check_function_present": True,
    "dep_enabled": True,
    "seh_enabled": True,
    "code_integrity": False,
    "isolated": True,
})

# Modeled on appinfo.dll imports (msvcrt + kernel32 subset)
_IMPORTS = json.dumps([
    {"module_name": "msvcrt.dll", "raw_module_name": "msvcrt", "is_api_set": True,
     "functions": [
         {"function_name": "memcpy", "address": "0x180049288", "ordinal": 0},
         {"function_name": "memset", "address": "0x180049308", "ordinal": 0},
         {"function_name": "free", "address": "0x180049248", "ordinal": 0},
         {"function_name": "malloc", "address": "0x180049240", "ordinal": 0},
     ]},
    {"module_name": "KERNEL32.dll", "raw_module_name": "KERNEL32",
     "functions": [
         {"function_name": "CreateFileW", "address": "0x180049400", "ordinal": 0},
         {"function_name": "CloseHandle", "address": "0x180049408", "ordinal": 0},
         {"function_name": "GetLastError", "address": "0x180049410", "ordinal": 0},
     ]},
])

# Modeled on appinfo.dll exports
_EXPORTS = json.dumps([
    {"function_name": "AiDisableDesktopRpcInterface", "ordinal": 1, "address": "0x180041680",
     "mangled_name": "AiDisableDesktopRpcInterface", "is_forwarded": False},
    {"function_name": "AiIsElevationRpcReady", "ordinal": 2, "address": "0x180041700",
     "mangled_name": "AiIsElevationRpcReady", "is_forwarded": False},
])

# Sections modeled on real PE
_SECTIONS = json.dumps([
    {"name": ".text", "size": 262144, "virtual_size": 261992},
    {"name": ".rdata", "size": 131072, "virtual_size": 130448},
    {"name": ".data", "size": 8192, "virtual_size": 7680},
    {"name": ".pdata", "size": 16384, "virtual_size": 16200},
])

# Real IDA assembly format for AiDisableDesktopRpcInterface
_ASM_EXPORT = """sub     rsp, 28h
and     [rsp+28h+BindingVector], 0
lea     rcx, [rsp+28h+BindingVector]
call    cs:__imp_RpcServerInqBindings
nop     dword ptr [rax+rax+00h]
test    eax, eax
jnz     short loc_end
mov     rdx, [rsp+28h+BindingVector]
lea     rcx, unk_1800461E0
xor     r8d, r8d
call    cs:__imp_RpcEpUnregister
add     rsp, 28h
ret"""

# Real IDA decompiled output for AiDisableDesktopRpcInterface
_DECOMP_EXPORT = """void __fastcall AiDisableDesktopRpcInterface()
{
  RPC_BINDING_VECTOR *BindingVector; // [rsp+30h] [rbp+8h] BYREF

  BindingVector = nullptr;
  if ( !RpcServerInqBindings(&BindingVector) )
  {
    RpcEpUnregister(&unk_1800461E0, BindingVector, nullptr);
    RpcBindingVectorFree(&BindingVector);
  }
}"""

# Real assembly for a simple WIL function (TraceLogging pattern)
_ASM_WIL = """mov     eax, 1\nret"""

# Real decompiled output for a WIL trace function
_DECOMP_WIL = """void __fastcall wil_details_FeatureReporting_ReportUsageToService(void *a1)
{
  return;
}"""

# Real assembly for AccessCheckIncomingToken
_ASM_SECURITY = """push    rbx
sub     rsp, 60h
mov     rbx, rcx
xor     ecx, ecx
call    cs:__imp_GetTokenInformation
test    eax, eax
jz      short loc_err
call    cs:__imp_GetLastError
cmp     eax, 7Ah
jnz     short loc_ret
pop     rbx
ret"""

# Real decompiled for AccessCheckIncomingToken
_DECOMP_SECURITY = """long __fastcall AccessCheckIncomingToken(void *a1, void *a2)
{
  if ( !GetTokenInformation(a1, TokenElevationType, &v5, 4u, &v7) )
  {
    if ( GetLastError() != 122 )
      return v4;
  }
  return 0;
}"""


def _seed_sample_db(db_path: Path) -> None:
    """Populate an already-created DB with 4 functions matching test expectations.

    Data modeled on real appinfo.dll extraction output.
    """
    conn = sqlite3.connect(db_path)

    # File info modeled on appinfo.dll (but named test.dll for test isolation)
    conn.execute("""
        INSERT INTO file_info (file_path, base_dir, file_name, file_extension,
            file_size_bytes, md5_hash, sha256_hash, imports, exports, entry_point,
            file_version, product_version, company_name, file_description,
            internal_name, original_filename, legal_copyright, product_name,
            time_date_stamp_str, file_modified_date_str, sections, pdb_path,
            rich_header, tls_callbacks, is_net_assembly, clr_metadata,
            idb_cache_path, dll_characteristics, security_features,
            exception_info, load_config, analysis_timestamp)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        "C:\\Windows\\System32\\test.dll", "C:\\Windows\\System32",
        "test.dll", ".dll",
        409600, "f2bbf324a1176c01101bc75d017633bc",
        "60df03e7deba0b62ecafabc123456789abcdef0123456789abcdef0123456789",
        _IMPORTS, _EXPORTS,
        json.dumps({"name": "AiDisableDesktopRpcInterface", "address": "0x180041680"}),
        "10.0.26100.7824", "10.0.26100.7824",
        "Test Corp", "Application Information Service",
        "test.dll", "test.dll",
        "\u00a9 Microsoft Corporation. All rights reserved.",
        "Microsoft\u00ae Windows\u00ae Operating System",
        "2024-01-15", "2024-06-20",
        _SECTIONS, None, None, None, False, None, None, None,
        _SECURITY_FEATURES, None, None, "2024-06-20T12:00:00",
    ))

    # 4 functions modeled on real appinfo.dll patterns
    funcs = [
        # ID=1: Export function (modeled on AiDisableDesktopRpcInterface)
        (1, "BOOL __stdcall DllMain(HINSTANCE, DWORD, LPVOID)", None,
         "?DllMain@@YAHHPAX@Z", "DllMain",
         _ASM_EXPORT, _DECOMP_EXPORT,
         None, None, None,
         json.dumps([
             {"function_name": "RpcServerInqBindings", "function_id": None,
              "module_name": "RPCRT4.dll", "function_type": 3,
              "extraction_type": "script", "xref_type": "Call Near"},
             {"function_name": "sub_140001000", "function_id": 3,
              "module_name": "internal", "function_type": 1,
              "extraction_type": "script", "xref_type": "Call Near"},
         ]),
         None, None,
         json.dumps(["CreateProcessW"]),   # dangerous_api_calls (for search test)
         json.dumps(["onecoreuap\\ds\\security\\services\\lua\\appinfo\\launch.cxx"]),
         None, None, None, None),

        # ID=2: WIL telemetry function (modeled on wil_details_FeatureReporting)
        (2, "void __fastcall wil_details_FeatureReporting_ReportUsageToService(void *)", None,
         "?ReportUsageToService@FeatureReporting@details@wil@@SAXPEAX@Z",
         "WppAutoLogTrace",  # test expects this name
         _ASM_WIL, _DECOMP_WIL,
         None, None, None, None, None, None, None, None, None, None, None, None),

        # ID=3: No decompiled code, has constructor mangled name ??0CFoo
        # (modeled on wil::details::ThreadFailureCallbackHolder ctor)
        (3, "void __fastcall CFoo::CFoo(CFoo *__hidden this)", None,
         "??0CFoo@@QEAA@XZ", "sub_140001000",
         _ASM_SECURITY, None,   # no decompiled code
         None, None,
         json.dumps([{"function_name": "DllMain", "function_id": 1,
                      "module_name": "internal", "function_type": 1,
                      "extraction_type": "script", "xref_type": "Call Near"}]),
         json.dumps([
             {"function_name": "GetTokenInformation", "function_id": None,
              "module_name": "kernelbase.dll", "function_type": 3,
              "extraction_type": "script", "xref_type": "Call Near"},
             {"function_name": "GetLastError", "function_id": None,
              "module_name": "kernelbase.dll", "function_type": 3,
              "extraction_type": "script", "xref_type": "Call Near"},
         ]),
         None, None, None,
         json.dumps(["\\\\?\\C:\\Windows\\System32\\test.dll"]),
         None, None, None, None),

        # ID=4: Normal function with decompiled code + loop_analysis
        (4, "void __fastcall sub_140002000(__int64)", None,
         None, "sub_140002000",
         "push rbp\nmov rbp, rsp\nmov [rbp+8h], rcx\npop rbp\nret",
         "void __fastcall sub_140002000(__int64 a1)\n{\n  *(_DWORD *)(a1 + 8) = 1;\n}",
         None, None, None, None, None, None, None, None, None,
         json.dumps({"loop_count": 0, "loops": []}), None, None),
    ]

    for f in funcs:
        conn.execute("""
            INSERT INTO functions (
                function_id, function_signature, function_signature_extended,
                mangled_name, function_name, assembly_code, decompiled_code,
                inbound_xrefs, outbound_xrefs, simple_inbound_xrefs,
                simple_outbound_xrefs, vtable_contexts, global_var_accesses,
                dangerous_api_calls, string_literals, stack_frame,
                loop_analysis, analysis_errors, created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, f)

    conn.commit()
    conn.close()


# -----------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------

@pytest.fixture
def mock_db_path(tmp_path):
    """Empty DB (schema only, no rows)."""
    db_path = tmp_path / "test_analysis.db"
    _create_sample_db(db_path)
    return db_path


@pytest.fixture
def sample_function_data():
    """Dict of column values suitable for inserting into a functions table."""
    return {
        "function_id": 1,
        "function_name": "TestFunc",
        "mangled_name": "?TestFunc@@YAHXZ",
        "decompiled_code": "int TestFunc() { return 0; }",
        "assembly_code": "mov eax, 0\nret",
        "simple_outbound_xrefs": json.dumps([
            {"function_name": "Callee", "module_name": "other.dll",
             "function_id": None, "function_type": 3,
             "extraction_type": "script", "xref_type": "Call Near"},
        ]),
    }


@pytest.fixture
def sample_db(tmp_path):
    """DB pre-populated with 4 functions and file_info (realistic appinfo.dll data)."""
    db_path = tmp_path / "sample_analysis.db"
    _create_sample_db(db_path)
    _seed_sample_db(db_path)
    return db_path


@pytest.fixture
def sample_db_with_extras(tmp_path):
    """sample_db with additional functions for dangerous API ranking tests."""
    db_path = tmp_path / "extras_analysis.db"
    _create_sample_db(db_path)
    _seed_sample_db(db_path)
    conn = sqlite3.connect(db_path)
    # Modeled on StateRepository functions that call multiple dangerous APIs
    conn.execute("""
        INSERT INTO functions (function_id, function_name, dangerous_api_calls,
                               decompiled_code, assembly_code)
        VALUES (?, ?, ?, ?, ?)
    """, (5, "RiskyFunc",
          json.dumps(["CreateProcessW", "VirtualAlloc", "WriteProcessMemory"]),
          "void RiskyFunc() {}", "sub rsp, 28h\ncall CreateProcessW\nadd rsp, 28h\nret"))
    conn.execute("""
        INSERT INTO functions (function_id, function_name, dangerous_api_calls,
                               decompiled_code, assembly_code)
        VALUES (?, ?, ?, ?, ?)
    """, (6, "MildFunc",
          json.dumps(["memcpy"]),
          "void MildFunc() {}", "mov eax, 1\nret"))
    conn.commit()
    conn.close()
    return db_path


@pytest.fixture
def sample_function_index():
    """Function index dict matching sample_db functions (realistic format)."""
    return {
        "DllMain": {
            "function_id": 1, "file": "test_dll_standalone_group_0.cpp",
            "has_decompiled": True, "has_assembly": True, "library": None,
        },
        "WppAutoLogTrace": {
            "function_id": 2, "file": "test_dll_wil_group_0.cpp",
            "has_decompiled": True, "has_assembly": True, "library": "WIL",
        },
        "sub_140001000": {
            "function_id": 3, "file": "test_dll_standalone_group_0.cpp",
            "has_decompiled": False, "has_assembly": True, "library": None,
        },
        "sub_140002000": {
            "function_id": 4, "file": "test_dll_standalone_group_0.cpp",
            "has_decompiled": True, "has_assembly": True, "library": None,
        },
        "STLHelper": {
            "function_id": 100, "file": "test_dll_stl_group_0.cpp",
            "has_decompiled": False, "has_assembly": False, "library": "STL",
        },
    }


@pytest.fixture
def workspace_root():
    """Return the real workspace root for this project."""
    return Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _invalidate_config_cache():
    """Reset the config cache before and after every test.

    Ensures tests that monkeypatch env vars or ``_DEFAULTS_PATH`` get a
    fresh config load rather than a stale cached copy.
    """
    from helpers.config import invalidate_config_cache
    invalidate_config_cache()
    yield
    invalidate_config_cache()
