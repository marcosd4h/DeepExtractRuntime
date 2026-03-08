#!/usr/bin/env python3
"""Migrate COM and WinRT extraction data from CLSID/class-keyed to binary-keyed schema.

Reads:
  - com_servers_details.json + com_procedures_by_binary.json  (4 access contexts)
  - winrt_servers_details.json + winrt_procedures_by_binary.json  (4 access contexts)

Writes:
  - com_servers.json   (4 access contexts)
  - winrt_servers.json (4 access contexts)

Usage:
    python scripts/migrate_to_binary_keyed.py [--verify] [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

WORKSPACE_ROOT = Path(__file__).resolve().parents[1]
COM_DATA_ROOT = WORKSPACE_ROOT / "config" / "assets" / "com_data"
WINRT_DATA_ROOT = WORKSPACE_ROOT / "config" / "assets" / "winrt_data"

ACCESS_CONTEXTS = [
    "extracted_high_il/all_servers",
    "extracted_high_il/privileged_servers",
    "extracted_medium_il/medium_il/all_servers",
    "extracted_medium_il/medium_il/privileged_servers",
]

KEY_UNKNOWN = "<unknown>"
KEY_APPID_HOSTED = "<appid_hosted>"


# ---------------------------------------------------------------------------
# Field mapping tables
# ---------------------------------------------------------------------------

COM_ENTRY_MAP: dict[str, str] = {
    "CLSID": "clsid",
    "Name": "display_name",
    "ServerType": "registration_type",
    "CanElevate": "can_elevate",
    "AutoElevation": "auto_elevate",
    "Elevation": "elevation_policy",
    "HasLaunchPermission": "has_launch_permission",
    "HasRunAs": "has_run_as_identity",
    "AccessPermission": "access_permission_sddl",
    "LaunchPermission": "launch_permission_sddl",
    "RunAs": "run_as_identity",
    "CreateContext": "clsctx_flags",
    "SupportsRemoteActivation": "supports_remote_activation",
    "TrustedMarshaller": "is_trusted_marshaller",
    "TrustedMarshallerCategory": "in_trusted_marshaller_category",
    "TypeLib": "has_typelib",
}

COM_APPID_MAP: dict[str, str] = {
    "AppId": "app_id_guid",
    "Name": "app_id_name",
    "Flags": "app_id_flags",
    "IsService": "is_service",
    "ServiceName": "service_name",
    "ServiceProtectionLevel": "service_protection_level",
    "HasDllSurrogate": "has_dll_surrogate",
    "DllSurrogate": "dll_surrogate_path",
    "HasRunAs": "has_run_as_identity",
    "RunAs": "run_as_identity",
    "LaunchPermission": "launch_permission_sddl",
    "AccessPermission": "access_permission_sddl",
    "HasLaunchPermission": "has_launch_permission",
    "HasAccessPermission": "has_access_permission",
    "HasPermission": "has_any_permission",
    "HasLowILAccess": "allows_low_il_access",
    "HasLowILLaunch": "allows_low_il_launch",
    "Inside_ServiceName": "resolved_service_name",
    "Inside_ServiceType": "resolved_service_type",
    "Inside_ServiceUsername": "resolved_service_username",
    "Inside_ServiceProtectionLevel": "resolved_service_protection_level",
    "LocalService": "local_service",
}

COM_LOCAL_SERVICE_MAP: dict[str, str] = {
    "DisplayName": "display_name",
    "Name": "service_name",
    "ServiceType": "service_type",
    "UserName": "account",
    "ImagePath": "image_path",
    "ServiceDll": "service_dll",
    "ProtectionLevel": "protection_level",
}

COM_ELEVATION_MAP: dict[str, str] = {
    "Enabled": "enabled",
    "AutoApproval": "auto_approval",
    "IconReference": "icon_reference",
    "VirtualServerObjects": "virtual_server_object_clsids",
}

METHOD_MAP: dict[str, str] = {
    "Access": "access_type",
    "Type": "dispatch_type",
    "Name": "method_name",
    "File": "binary_path",
}

WINRT_ENTRY_MAP: dict[str, str] = {
    "Name": "class_name",
    "Server": "hosting_server",
    "DefaultServer": "default_hosting_server",
    "HasServer": "has_hosting_server",
    "ActivationType": "activation_type",
    "TrustLevel": "trust_level",
    "ServerPermissions": "server_launch_permission_sddl",
    "ServerIdentity": "server_run_as_identity",
    "ServerName": "server_display_name",
    "ServerExePath": "server_exe_path",
    "ServerExeName": "server_exe_name",
    "ServerType": "server_registration_type",
    "ServiceName": "service_name",
    "DefaultAccessPermission": "default_access_permission_sddl",
    "DefaultLaunchPermission": "default_launch_permission_sddl",
    "SupportsRemoteActivation": "supports_remote_activation",
    "Source": "registration_source",
    "ActivateInSharedBroker": "activate_in_shared_broker",
    "Identity": "class_identity",
    "IdentityType": "class_identity_type",
    "InstancingType": "instancing_type",
    "Permissions": "class_permission_sddl",
    "PackageId": "package_id",
    "RuntimeServer": "runtime_server",
}

# Fields handled specially (not simple renames)
COM_SPECIAL_FIELDS = {"FullPath", "Interfaces", "PseudoInterfaces", "TypelibInterfaces", "AppID"}
WINRT_SPECIAL_FIELDS = {"Methods", "PseudoInterfaces"}


# ---------------------------------------------------------------------------
# Mapping helpers
# ---------------------------------------------------------------------------

def _map_dict(src: dict, field_map: dict[str, str], context: str) -> dict:
    """Map a source dict through a field mapping, erroring on unknown fields."""
    result = {}
    for src_key, value in src.items():
        if src_key in field_map:
            result[field_map[src_key]] = value
        else:
            raise ValueError(f"Unknown field '{src_key}' in {context}")
    return result


def _map_method(src: dict) -> dict:
    for k in src:
        if k not in METHOD_MAP:
            raise ValueError(f"Unknown method field '{k}'")
    return {METHOD_MAP[k]: v for k, v in src.items()}


def _map_elevation(src: Any) -> Any:
    if src is None:
        return None
    if not isinstance(src, dict):
        return src
    for k in src:
        if k not in COM_ELEVATION_MAP:
            raise ValueError(f"Unknown Elevation field '{k}'")
    return {COM_ELEVATION_MAP[k]: v for k, v in src.items()}


def _map_local_service(src: Any) -> Any:
    if src is None or not isinstance(src, dict):
        return src
    for k in src:
        if k not in COM_LOCAL_SERVICE_MAP:
            raise ValueError(f"Unknown LocalService field '{k}'")
    return {COM_LOCAL_SERVICE_MAP[k]: v for k, v in src.items()}


def _map_appid(src: Any) -> Any:
    if src is None or not isinstance(src, dict):
        return src
    result = {}
    for src_key, value in src.items():
        if src_key not in COM_APPID_MAP:
            raise ValueError(f"Unknown AppID field '{src_key}'")
        target_key = COM_APPID_MAP[src_key]
        if src_key == "LocalService":
            result[target_key] = _map_local_service(value)
        else:
            result[target_key] = value
    return result


def _build_interfaces(
    raw_interfaces: dict | None,
    raw_pseudo: dict | None,
) -> list[dict]:
    """Merge Interfaces/Methods and PseudoInterfaces into a unified interface array."""
    ifaces_dict: dict[str, Any] = raw_interfaces if isinstance(raw_interfaces, dict) else {}
    pseudo_dict: dict[str, Any] = raw_pseudo if isinstance(raw_pseudo, dict) else {}

    result: list[dict] = []
    seen_iface_names: set[str] = set()

    for iface_name, method_list in ifaces_dict.items():
        seen_iface_names.add(iface_name)
        methods = []
        if isinstance(method_list, list):
            for m in method_list:
                if isinstance(m, dict):
                    methods.append(_map_method(m))

        pseudo_lines = _find_pseudo_idl(iface_name, pseudo_dict)

        result.append({
            "iface_name": iface_name,
            "methods": methods,
            "pseudo_idl": pseudo_lines,
        })

    for pseudo_key, lines in pseudo_dict.items():
        base_name = pseudo_key.split("_(")[0]
        if pseudo_key not in seen_iface_names and base_name not in seen_iface_names:
            pseudo_lines = lines if isinstance(lines, list) else []
            result.append({
                "iface_name": pseudo_key,
                "methods": [],
                "pseudo_idl": pseudo_lines,
            })

    return result


def _find_pseudo_idl(iface_name: str, pseudo_dict: dict) -> list[str]:
    """Find pseudo-IDL lines for an interface, handling COM's _(guid) suffix pattern."""
    if iface_name in pseudo_dict:
        v = pseudo_dict[iface_name]
        return v if isinstance(v, list) else []

    for pk, pv in pseudo_dict.items():
        if pk.startswith(iface_name + "_("):
            return pv if isinstance(pv, list) else []

    return []


# ---------------------------------------------------------------------------
# COM conversion
# ---------------------------------------------------------------------------

def _normalize_com_fullpath(full_path: Any) -> str:
    """Normalize a COM FullPath into a binary grouping key."""
    if full_path is None:
        return KEY_UNKNOWN
    fp = str(full_path).strip()
    if not fp:
        return KEY_UNKNOWN
    if fp == "<APPID HOSTED>":
        return KEY_APPID_HOSTED
    fp = fp.strip('"')
    return fp.lower()


def _original_com_path(full_path: Any) -> str:
    """Preserve the original-cased path (with quotes stripped)."""
    if full_path is None:
        return ""
    fp = str(full_path).strip().strip('"')
    return fp


def convert_com_context(ctx_dir: Path) -> dict | None:
    """Convert one COM access context into binary-keyed format."""
    details_path = ctx_dir / "com_servers_details.json"
    procs_path = ctx_dir / "com_procedures_by_binary.json"

    if not details_path.exists():
        return None

    with open(details_path, "r", encoding="utf-8") as f:
        details_data = json.load(f)

    procs_data: dict = {}
    if procs_path.exists():
        with open(procs_path, "r", encoding="utf-8") as f:
            procs_data = json.load(f)

    output: dict[str, dict] = {}

    for clsid, entries in details_data.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue

            full_path = entry.get("FullPath")
            bin_key = _normalize_com_fullpath(full_path)
            orig_path = _original_com_path(full_path)

            if bin_key not in output:
                output[bin_key] = {
                    "binary_path": orig_path,
                    "servers": [],
                    "procedures": [],
                }
            elif not output[bin_key]["binary_path"] and orig_path:
                output[bin_key]["binary_path"] = orig_path

            server = {}
            for src_key, value in entry.items():
                if src_key in COM_SPECIAL_FIELDS:
                    continue
                if src_key not in COM_ENTRY_MAP:
                    raise ValueError(
                        f"Unknown COM entry field '{src_key}' in CLSID {clsid}"
                    )
                target_key = COM_ENTRY_MAP[src_key]
                if src_key == "Elevation":
                    server[target_key] = _map_elevation(value)
                else:
                    server[target_key] = value

            server["app_id"] = _map_appid(entry.get("AppID"))

            server["interfaces"] = _build_interfaces(
                entry.get("Interfaces"),
                entry.get("PseudoInterfaces"),
            )

            raw_typelib = entry.get("TypelibInterfaces")
            server["typelib_interfaces"] = raw_typelib if isinstance(raw_typelib, dict) else {}

            output[bin_key]["servers"].append(server)

    for raw_path, func_names in procs_data.items():
        if not isinstance(func_names, list):
            continue
        proc_key = raw_path.lower()
        if proc_key not in output:
            output[proc_key] = {
                "binary_path": raw_path,
                "servers": [],
                "procedures": [],
            }
        output[proc_key]["procedures"] = func_names

    return output


# ---------------------------------------------------------------------------
# WinRT conversion
# ---------------------------------------------------------------------------

def _resolve_winrt_hosting_binary(entry: dict) -> tuple[str, str]:
    """Resolve the hosting binary for a WinRT server from its method files.

    Returns (normalized_key, original_path).
    """
    methods_dict = entry.get("Methods")
    if isinstance(methods_dict, dict):
        for iface_name, method_list in methods_dict.items():
            if isinstance(method_list, list):
                for m in method_list:
                    if isinstance(m, dict):
                        f = m.get("File", "")
                        if f:
                            return f.lower(), f
    return KEY_UNKNOWN, ""


def convert_winrt_context(ctx_dir: Path) -> dict | None:
    """Convert one WinRT access context into binary-keyed format."""
    details_path = ctx_dir / "winrt_servers_details.json"
    procs_path = ctx_dir / "winrt_procedures_by_binary.json"

    if not details_path.exists():
        return None

    with open(details_path, "r", encoding="utf-8") as f:
        details_data = json.load(f)

    procs_data: dict = {}
    if procs_path.exists():
        with open(procs_path, "r", encoding="utf-8") as f:
            procs_data = json.load(f)

    output: dict[str, dict] = {}

    for class_name, entries in details_data.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue

            bin_key, orig_path = _resolve_winrt_hosting_binary(entry)

            if bin_key not in output:
                output[bin_key] = {
                    "binary_path": orig_path,
                    "servers": [],
                    "procedures": [],
                }
            elif not output[bin_key]["binary_path"] and orig_path:
                output[bin_key]["binary_path"] = orig_path

            server = {}
            for src_key, value in entry.items():
                if src_key in WINRT_SPECIAL_FIELDS:
                    continue
                if src_key not in WINRT_ENTRY_MAP:
                    raise ValueError(
                        f"Unknown WinRT entry field '{src_key}' in class {class_name}"
                    )
                server[WINRT_ENTRY_MAP[src_key]] = value

            server["interfaces"] = _build_interfaces(
                entry.get("Methods"),
                entry.get("PseudoInterfaces"),
            )

            output[bin_key]["servers"].append(server)

    for raw_path, func_names in procs_data.items():
        if not isinstance(func_names, list):
            continue
        proc_key = raw_path.lower()
        if proc_key not in output:
            output[proc_key] = {
                "binary_path": raw_path,
                "servers": [],
                "procedures": [],
            }
        output[proc_key]["procedures"] = func_names

    return output


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_com_context(ctx_dir: Path, output_path: Path) -> list[str]:
    """Verify a converted COM context against source files."""
    errors: list[str] = []
    ctx_name = str(ctx_dir.relative_to(COM_DATA_ROOT))

    details_path = ctx_dir / "com_servers_details.json"
    procs_path = ctx_dir / "com_procedures_by_binary.json"

    if not details_path.exists():
        return errors

    with open(details_path, "r", encoding="utf-8") as f:
        original = json.load(f)
    with open(output_path, "r", encoding="utf-8") as f:
        converted = json.load(f)

    orig_count = sum(len(entries) for entries in original.values())
    conv_count = sum(len(b["servers"]) for b in converted.values())
    if orig_count != conv_count:
        errors.append(f"[{ctx_name}] Server count mismatch: original={orig_count}, converted={conv_count}")

    orig_clsids = set()
    for clsid, entries in original.items():
        for _ in entries:
            orig_clsids.add(clsid)
    conv_clsids = set()
    for b in converted.values():
        for s in b["servers"]:
            conv_clsids.add(s["clsid"])
    missing = orig_clsids - conv_clsids
    if missing:
        errors.append(f"[{ctx_name}] Missing CLSIDs: {missing}")

    if procs_path.exists():
        with open(procs_path, "r", encoding="utf-8") as f:
            orig_procs = json.load(f)
        orig_proc_count = sum(len(v) for v in orig_procs.values())
        conv_proc_count = sum(len(b["procedures"]) for b in converted.values())
        if orig_proc_count != conv_proc_count:
            errors.append(f"[{ctx_name}] Procedure count mismatch: original={orig_proc_count}, converted={conv_proc_count}")

    return errors


def verify_winrt_context(ctx_dir: Path, output_path: Path) -> list[str]:
    """Verify a converted WinRT context against source files."""
    errors: list[str] = []
    ctx_name = str(ctx_dir.relative_to(WINRT_DATA_ROOT))

    details_path = ctx_dir / "winrt_servers_details.json"
    procs_path = ctx_dir / "winrt_procedures_by_binary.json"

    if not details_path.exists():
        return errors

    with open(details_path, "r", encoding="utf-8") as f:
        original = json.load(f)
    with open(output_path, "r", encoding="utf-8") as f:
        converted = json.load(f)

    orig_count = sum(len(entries) for entries in original.values())
    conv_count = sum(len(b["servers"]) for b in converted.values())
    if orig_count != conv_count:
        errors.append(f"[{ctx_name}] Server count mismatch: original={orig_count}, converted={conv_count}")

    orig_classes = set()
    for name, entries in original.items():
        for e in entries:
            orig_classes.add(e.get("Name", name))
    conv_classes = set()
    for b in converted.values():
        for s in b["servers"]:
            conv_classes.add(s["class_name"])
    missing = orig_classes - conv_classes
    if missing:
        errors.append(f"[{ctx_name}] Missing classes: {missing}")

    if procs_path.exists():
        with open(procs_path, "r", encoding="utf-8") as f:
            orig_procs = json.load(f)
        orig_proc_count = sum(len(v) for v in orig_procs.values())
        conv_proc_count = sum(len(b["procedures"]) for b in converted.values())
        if orig_proc_count != conv_proc_count:
            errors.append(f"[{ctx_name}] Procedure count mismatch: original={orig_proc_count}, converted={conv_proc_count}")

    return errors


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Migrate COM/WinRT data to binary-keyed schema")
    parser.add_argument("--verify", action="store_true", help="Run verification after conversion")
    parser.add_argument("--dry-run", action="store_true", help="Convert but don't write files")
    args = parser.parse_args()

    all_errors: list[str] = []

    for ctx in ACCESS_CONTEXTS:
        ctx_dir = COM_DATA_ROOT / ctx
        if not ctx_dir.is_dir():
            print(f"  Skipping COM {ctx} (directory not found)", file=sys.stderr)
            continue

        print(f"  Converting COM {ctx}...", file=sys.stderr)
        result = convert_com_context(ctx_dir)
        if result is None:
            print(f"  Skipping COM {ctx} (no details file)", file=sys.stderr)
            continue

        out_path = ctx_dir / "com_servers.json"
        server_count = sum(len(b["servers"]) for b in result.values())
        proc_count = sum(len(b["procedures"]) for b in result.values())
        print(f"    {len(result)} binaries, {server_count} servers, {proc_count} procedures", file=sys.stderr)

        if not args.dry_run:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            print(f"    Wrote {out_path}", file=sys.stderr)

        if args.verify and not args.dry_run:
            errors = verify_com_context(ctx_dir, out_path)
            all_errors.extend(errors)

    for ctx in ACCESS_CONTEXTS:
        ctx_dir = WINRT_DATA_ROOT / ctx
        if not ctx_dir.is_dir():
            print(f"  Skipping WinRT {ctx} (directory not found)", file=sys.stderr)
            continue

        print(f"  Converting WinRT {ctx}...", file=sys.stderr)
        result = convert_winrt_context(ctx_dir)
        if result is None:
            print(f"  Skipping WinRT {ctx} (no details file)", file=sys.stderr)
            continue

        out_path = ctx_dir / "winrt_servers.json"
        server_count = sum(len(b["servers"]) for b in result.values())
        proc_count = sum(len(b["procedures"]) for b in result.values())
        print(f"    {len(result)} binaries, {server_count} servers, {proc_count} procedures", file=sys.stderr)

        if not args.dry_run:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            print(f"    Wrote {out_path}", file=sys.stderr)

        if args.verify and not args.dry_run:
            errors = verify_winrt_context(ctx_dir, out_path)
            all_errors.extend(errors)

    if all_errors:
        print("\nVerification FAILED:", file=sys.stderr)
        for e in all_errors:
            print(f"  {e}", file=sys.stderr)
        return 1

    if args.verify:
        print("\nVerification PASSED: all counts match.", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
