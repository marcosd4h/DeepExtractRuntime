#!/usr/bin/env python3
"""Migrate RPC extraction data from flat list + separate procedures to binary-keyed schema.

Reads:
  - exported_system_rpc_objects.json      (list of 222 objects with FullPath + RPC)
  - exported_system_rpc_procedures_by_binary.json  (dict of binary -> procedure names)

Writes:
  - rpc_servers.json  (single binary-keyed file)

Strips PowerShell serialization noise (23 of 26 FullPath fields, 25 of 29
VersionInfo fields, Directory/PSDrive/PSProvider sub-objects), normalizes
type variants (InterfaceVersion dict->str, Endpoints str->list, ComplexTypes
str->list), drops redundant fields (RPC.Server, RPC.Procedures placeholders,
RPC.TransferSyntaxVersion, RPC.FilePath, RPC.Name).

Usage:
    python scripts/migrate_rpc_to_binary_keyed.py [--verify] [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

WORKSPACE_ROOT = Path(__file__).resolve().parents[1]
RPC_DATA_DIR = WORKSPACE_ROOT / "config" / "assets" / "rpc_data"

OBJECTS_FILE = RPC_DATA_DIR / "exported_system_rpc_objects.json"
PROCEDURES_FILE = RPC_DATA_DIR / "exported_system_rpc_procedures_by_binary.json"
OUTPUT_FILE = RPC_DATA_DIR / "rpc_servers.json"


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------

def _normalize_version(ver: Any) -> str:
    if isinstance(ver, str):
        return ver
    if isinstance(ver, dict):
        return f"{ver.get('Major', 0)}.{ver.get('Minor', 0)}"
    return "0.0"


def _normalize_endpoints(raw: Any) -> list[str]:
    if isinstance(raw, list):
        return [e.strip() for e in raw if isinstance(e, str) and e.strip()]
    if isinstance(raw, str) and raw.strip():
        return [raw.strip()]
    return []


def _normalize_complex_types(raw: Any) -> list[str]:
    if isinstance(raw, list):
        return [str(t) for t in raw if t]
    if isinstance(raw, str) and raw.strip():
        return [t.strip() for t in raw.split(" - ") if t.strip() and t.strip() != "-"]
    return []


def _extract_file_info(version_info: Any) -> dict[str, str]:
    if not isinstance(version_info, dict):
        return {
            "file_description": "",
            "file_version": "",
            "company_name": "",
            "product_version": "",
        }
    return {
        "file_description": version_info.get("FileDescription", "") or "",
        "file_version": version_info.get("FileVersion", "") or "",
        "company_name": version_info.get("CompanyName", "") or "",
        "product_version": version_info.get("ProductVersion", "") or "",
    }


# ---------------------------------------------------------------------------
# RPC interface conversion
# ---------------------------------------------------------------------------

RPC_KEPT_FIELDS = {
    "InterfaceId", "InterfaceVersion", "TransferSyntaxId", "ProcedureCount",
    "ComplexTypes", "Offset", "ServiceName", "ServiceDisplayName",
    "IsServiceRunning", "Endpoints", "EndpointCount", "Client",
}

RPC_DROPPED_FIELDS = {
    "TransferSyntaxVersion", "Procedures", "Server", "FilePath", "Name",
}

ALL_RPC_FIELDS = RPC_KEPT_FIELDS | RPC_DROPPED_FIELDS


def _convert_rpc_interface(rpc_obj: dict) -> dict:
    for k in rpc_obj:
        if k not in ALL_RPC_FIELDS:
            raise ValueError(f"Unknown RPC field '{k}'")

    return {
        "interface_id": rpc_obj.get("InterfaceId", ""),
        "interface_version": _normalize_version(rpc_obj.get("InterfaceVersion")),
        "transfer_syntax_id": rpc_obj.get("TransferSyntaxId", ""),
        "procedure_count": int(rpc_obj.get("ProcedureCount", 0)),
        "offset": int(rpc_obj.get("Offset", 0)),
        "is_client": bool(rpc_obj.get("Client", False)),
        "service_name": rpc_obj.get("ServiceName"),
        "service_display_name": rpc_obj.get("ServiceDisplayName"),
        "is_service_running": bool(rpc_obj.get("IsServiceRunning", False)),
        "endpoints": _normalize_endpoints(rpc_obj.get("Endpoints")),
        "endpoint_count": int(rpc_obj.get("EndpointCount", 0)),
        "complex_types": _normalize_complex_types(rpc_obj.get("ComplexTypes")),
    }


# ---------------------------------------------------------------------------
# Main conversion
# ---------------------------------------------------------------------------

def convert(objects_path: Path, procedures_path: Path) -> dict:
    with open(objects_path, "r", encoding="utf-8") as f:
        objects_data = json.load(f)

    procs_data: dict = {}
    if procedures_path.exists():
        with open(procedures_path, "r", encoding="utf-8") as f:
            procs_data = json.load(f)

    if not isinstance(objects_data, list):
        raise ValueError(f"Expected list in {objects_path}, got {type(objects_data).__name__}")

    output: dict[str, dict] = {}

    for entry in objects_data:
        if not isinstance(entry, dict):
            continue

        full_path = entry.get("FullPath") or {}
        if not isinstance(full_path, dict):
            continue

        binary_full = full_path.get("FullName", "")
        version_info = full_path.get("VersionInfo") or {}

        bin_key = binary_full.lower() if binary_full else "<unknown>"

        if bin_key not in output:
            output[bin_key] = {
                "binary_path": binary_full,
                "file_info": _extract_file_info(version_info),
                "interfaces": [],
                "procedures": [],
            }

        rpc_data = entry.get("RPC")
        if rpc_data is None:
            continue

        rpc_list = rpc_data if isinstance(rpc_data, list) else [rpc_data]
        for rpc_obj in rpc_list:
            if not isinstance(rpc_obj, dict):
                continue
            output[bin_key]["interfaces"].append(_convert_rpc_interface(rpc_obj))

    for raw_path, func_names in procs_data.items():
        if not isinstance(func_names, list):
            continue
        proc_key = raw_path.lower()
        if proc_key in output:
            output[proc_key]["procedures"] = func_names
        else:
            output[proc_key] = {
                "binary_path": raw_path,
                "file_info": {
                    "file_description": "",
                    "file_version": "",
                    "company_name": "",
                    "product_version": "",
                },
                "interfaces": [],
                "procedures": func_names,
            }

    return output


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify(
    objects_path: Path, procedures_path: Path, output_path: Path,
) -> list[str]:
    errors: list[str] = []

    with open(objects_path, "r", encoding="utf-8") as f:
        original_objects = json.load(f)
    with open(output_path, "r", encoding="utf-8") as f:
        converted = json.load(f)

    orig_iface_count = 0
    for entry in original_objects:
        rpc = entry.get("RPC")
        if isinstance(rpc, dict):
            orig_iface_count += 1
        elif isinstance(rpc, list):
            orig_iface_count += len(rpc)

    conv_iface_count = sum(len(b["interfaces"]) for b in converted.values())
    if orig_iface_count != conv_iface_count:
        errors.append(f"Interface count mismatch: original={orig_iface_count}, converted={conv_iface_count}")

    orig_uuids = set()
    for entry in original_objects:
        rpc = entry.get("RPC")
        rpc_list = rpc if isinstance(rpc, list) else ([rpc] if isinstance(rpc, dict) else [])
        for r in rpc_list:
            if isinstance(r, dict):
                orig_uuids.add(r.get("InterfaceId", "").lower())

    conv_uuids = set()
    for b in converted.values():
        for iface in b["interfaces"]:
            conv_uuids.add(iface["interface_id"].lower())

    missing_uuids = orig_uuids - conv_uuids
    if missing_uuids:
        errors.append(f"Missing interface UUIDs: {missing_uuids}")

    if procedures_path.exists():
        with open(procedures_path, "r", encoding="utf-8") as f:
            orig_procs = json.load(f)
        orig_proc_count = sum(len(v) for v in orig_procs.values())
        conv_proc_count = sum(len(b["procedures"]) for b in converted.values())
        if orig_proc_count != conv_proc_count:
            errors.append(f"Procedure count mismatch: original={orig_proc_count}, converted={conv_proc_count}")

    return errors


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Migrate RPC data to binary-keyed schema")
    parser.add_argument("--verify", action="store_true", help="Run verification after conversion")
    parser.add_argument("--dry-run", action="store_true", help="Convert but don't write files")
    args = parser.parse_args()

    if not OBJECTS_FILE.exists():
        print(f"Objects file not found: {OBJECTS_FILE}", file=sys.stderr)
        return 1

    print("Converting RPC data...", file=sys.stderr)
    result = convert(OBJECTS_FILE, PROCEDURES_FILE)

    bin_count = len(result)
    iface_count = sum(len(b["interfaces"]) for b in result.values())
    proc_count = sum(len(b["procedures"]) for b in result.values())
    print(f"  {bin_count} binaries, {iface_count} interfaces, {proc_count} procedures", file=sys.stderr)

    if not args.dry_run:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"  Wrote {OUTPUT_FILE}", file=sys.stderr)

    if args.verify and not args.dry_run:
        errors = verify(OBJECTS_FILE, PROCEDURES_FILE, OUTPUT_FILE)
        if errors:
            print("\nVerification FAILED:", file=sys.stderr)
            for e in errors:
                print(f"  {e}", file=sys.stderr)
            return 1
        print("\nVerification PASSED: all counts match.", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
