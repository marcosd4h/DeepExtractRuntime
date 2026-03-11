"""Workspace scanning functions for the session-start hook.

Extracted from inject-module-context.py to improve maintainability.
Low-level directory iteration delegates to ``helpers.module_discovery``;
this module adds hook-specific metadata extraction on top.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from helpers.module_discovery import (
    db_stem_from_filename as _db_stem_from_filename,
    iter_module_dbs as _iter_module_dbs,
    iter_module_dirs as _iter_module_dirs,
)

_LIBRARY_CLASS_PREFIXES = (
    "wil", "std", "wistd", "Microsoft", "__crt", "ATL", "WRL",
    "_tlg", "Windows", "_com_",
)


def scan_modules(extracted_code_dir: Path) -> list[dict]:
    """Read file_info.json from each module directory."""
    modules: list[dict] = []

    for mod in _iter_module_dirs(extracted_code_dir, require_file_info=True):
        file_info_path = mod.path / "file_info.json"
        try:
            with open(file_info_path, "r", encoding="utf-8") as fh:
                info = json.load(fh)
        except (json.JSONDecodeError, OSError):
            continue

        if not isinstance(info, dict):
            continue

        basic = info.get("basic_file_info", {})
        version = info.get("pe_version_info", {})
        func_summary = info.get("function_summary", {})
        entry_points = info.get("entry_points", [])
        exports = info.get("exports", [])
        imports = info.get("imports", [])

        import_func_count = sum(
            len(imp.get("functions", []))
            for imp in imports
        )

        export_count = 0
        export_names: list[str] = []
        if isinstance(exports, list):
            export_count = len(exports)
            for exp in exports:
                if isinstance(exp, dict):
                    export_names.append(
                        exp.get("function_name", exp.get("raw_name", "?"))
                    )
                else:
                    export_names.append(str(exp))
        elif isinstance(exports, dict):
            funcs = exports.get("functions", [])
            export_count = len(funcs)
            for exp in funcs:
                if isinstance(exp, dict):
                    export_names.append(
                        exp.get("function_name", exp.get("raw_name", "?"))
                    )
                else:
                    export_names.append(str(exp))

        class_methods = func_summary.get("class_methods", [])
        class_count = len(class_methods)

        app_classes = [
            cm for cm in class_methods
            if not any(
                cm.get("class_name", "").startswith(p)
                for p in _LIBRARY_CLASS_PREFIXES
            )
        ]
        if not app_classes:
            app_classes = class_methods
        sorted_classes = sorted(
            app_classes,
            key=lambda c: len(c.get("methods", [])),
            reverse=True,
        )[:3]
        top_classes = [
            {
                "name": cm.get("class_name", "?"),
                "method_count": len(cm.get("methods", [])),
            }
            for cm in sorted_classes
            if len(cm.get("methods", [])) > 0
        ]

        modules.append({
            "name": info.get("module_name", mod.name),
            "file_name": basic.get("file_name", ""),
            "file_path": basic.get("file_path", ""),
            "description": version.get("file_description", ""),
            "product": version.get("product_name", ""),
            "company": version.get("company_name", ""),
            "version": version.get("file_version", ""),
            "size_bytes": basic.get("size_bytes", 0),
            "md5": basic.get("md5_hash", "")[:10],
            "total_functions": func_summary.get("total_functions", 0),
            "class_count": class_count,
            "top_classes": top_classes,
            "standalone_count": len(func_summary.get("standalone_functions", [])),
            "entry_point_count": len(entry_points),
            "export_count": export_count,
            "export_names": export_names,
            "import_func_count": import_func_count,
            "import_dll_count": len(imports),
            "dir": mod.name,
        })

    return modules


def derive_module_dir_name(analysis_db_path: str) -> str:
    """``'appinfo_dll_f2bbf324a1.db'`` -> ``'appinfo_dll'``"""
    return _db_stem_from_filename(analysis_db_path)


def scan_modules_from_tracking_db(
    tracking_db_path: Path,
    open_analyzed_files_db: Any,
) -> list[dict]:
    """Lightweight module scan using the tracking DB."""
    try:
        with open_analyzed_files_db(tracking_db_path) as db:
            records = db.get_all()
    except (FileNotFoundError, RuntimeError, OSError):
        return []

    modules: list[dict] = []
    for rec in sorted(records, key=lambda r: r.file_name or ""):
        db_path = rec.analysis_db_path or ""
        dir_name = _db_stem_from_filename(db_path) if db_path else ""
        modules.append({
            "name": dir_name or rec.file_name or "?",
            "file_name": rec.file_name or "",
            "db_path": db_path,
            "status": rec.status or "UNKNOWN",
        })
    return modules


def scan_modules_from_extraction_report(report_path: Path) -> list[dict]:
    """Last-resort fallback: parse extraction_report.json."""
    if not report_path.exists():
        return []
    try:
        with open(report_path, "r", encoding="utf-8") as fh:
            report = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return []

    modules: list[dict] = []
    for entry in report.get("successful_extractions", []):
        file_name = Path(entry.get("FileName", "")).name
        db_full_path = entry.get("DbPath", "")
        db_basename = Path(db_full_path).name if db_full_path else ""
        dir_name = derive_module_dir_name(db_basename) if db_basename else ""
        modules.append({
            "name": dir_name or file_name or "?",
            "file_name": file_name,
            "db_path": db_basename,
            "status": "COMPLETE",
        })
    return sorted(modules, key=lambda m: m["name"])


def count_modules_fast(
    extracted_code_dir: Path,
    tracking_db_path: Path | None,
    open_analyzed_files_db: Any,
) -> int:
    """Count modules without reading file_info.json."""
    if tracking_db_path and tracking_db_path.exists():
        try:
            with open_analyzed_files_db(tracking_db_path) as db:
                return sum(db.count_by_status().values())
        except (FileNotFoundError, RuntimeError, OSError):
            pass

    return len(_iter_module_dirs(extracted_code_dir, require_file_info=True))


def scan_dbs(extracted_dbs_dir: Path) -> tuple[list[dict], bool]:
    """List per-module analysis DBs and check for tracking DB."""
    from helpers.module_discovery import get_tracking_db_path as _get_tracking_db_path

    has_tracking = _get_tracking_db_path(extracted_dbs_dir) is not None
    dbs = [
        {
            "file": db.file_name,
            "path": f"extracted_dbs/{db.file_name}",
            "size_kb": round(db.size_bytes / 1024, 1),
        }
        for db in _iter_module_dbs(extracted_dbs_dir, include_empty=True)
    ]
    return dbs, has_tracking


def scan_skills(skills_dir: Path) -> list[str]:
    """List available skill names from skills/."""
    skills: list[str] = []
    if not skills_dir.is_dir():
        return skills
    for skill_dir in sorted(skills_dir.iterdir()):
        if skill_dir.is_dir() and (skill_dir / "SKILL.md").exists():
            skills.append(skill_dir.name)
    return skills


def scan_workspace_rules(workspace_root: Path) -> list[str]:
    """List .mdc rule files in .cursor/rules/."""
    rules_dir = workspace_root / ".cursor" / "rules"
    if not rules_dir.is_dir():
        return []
    return sorted(
        f.stem for f in rules_dir.iterdir()
        if f.suffix == ".mdc" and f.is_file()
    )


def load_registry(registry_path: Path, key: str) -> dict:
    """Load a registry.json and return the value under *key*."""
    if not registry_path.exists():
        return {}
    try:
        with open(registry_path, "r", encoding="utf-8") as fh:
            return json.load(fh).get(key, {})
    except (json.JSONDecodeError, OSError):
        return {}


def scan_module_profiles(extracted_code_dir: Path) -> dict[str, dict]:
    """Read module_profile.json from each module directory."""
    profiles: dict[str, dict] = {}
    if not extracted_code_dir.is_dir():
        return profiles
    for module_dir in sorted(extracted_code_dir.iterdir()):
        if not module_dir.is_dir():
            continue
        profile_path = module_dir / "module_profile.json"
        if not profile_path.exists():
            continue
        try:
            with open(profile_path, "r", encoding="utf-8") as fh:
                profiles[module_dir.name] = json.load(fh)
        except (json.JSONDecodeError, OSError):
            continue
    return profiles


def scan_cached_results(cache_dir: Path, module_name: str) -> list[dict]:
    """Check what analysis results are already cached for a module."""
    cached: list[dict] = []
    mod_cache = cache_dir / module_name
    if not mod_cache.is_dir():
        return cached
    for cache_file in sorted(mod_cache.iterdir()):
        if not cache_file.name.endswith(".json"):
            continue
        try:
            with open(cache_file, "r", encoding="utf-8") as fh:
                envelope = json.load(fh)
            operation = envelope.get("operation", cache_file.stem)
            cached_at = envelope.get("cached_at", "")
            cached.append({
                "operation": operation,
                "cached_at": cached_at,
                "file": cache_file.name,
            })
        except (json.JSONDecodeError, OSError):
            continue
    return cached


def load_triage_summary(cache_dir: Path, module_name: str) -> dict | None:
    """Load cached triage summary if available for a module."""
    cache_file = cache_dir / module_name / "triage_summary.json"
    if not cache_file.exists():
        return None
    try:
        with open(cache_file, "r", encoding="utf-8") as fh:
            envelope = json.load(fh)
        return envelope.get("result")
    except (json.JSONDecodeError, OSError):
        return None


def load_module_list_sidecar(
    sidecar_path: Path,
    tracking_db_path: Path,
) -> list[dict] | None:
    """Return cached module list if the sidecar is fresh."""
    if not sidecar_path.exists():
        return None
    try:
        with open(sidecar_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        stored_mtime = data.get("tracking_db_mtime")
        if stored_mtime is not None and tracking_db_path.exists():
            current_mtime = tracking_db_path.stat().st_mtime
            if abs(current_mtime - stored_mtime) < 1.0:
                return data.get("modules")
    except (OSError, json.JSONDecodeError, TypeError, KeyError):
        pass
    return None


def save_module_list_sidecar(
    sidecar_path: Path,
    modules: list[dict],
    tracking_db_path: Path,
) -> None:
    """Persist module list to a sidecar cache file."""
    try:
        mtime = tracking_db_path.stat().st_mtime if tracking_db_path.exists() else None
        sidecar_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"tracking_db_mtime": mtime, "modules": modules}
        with open(sidecar_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, separators=(",", ":"))
    except OSError:
        pass


__all__ = [
    "count_modules_fast",
    "derive_module_dir_name",
    "load_module_list_sidecar",
    "load_registry",
    "load_triage_summary",
    "save_module_list_sidecar",
    "scan_cached_results",
    "scan_dbs",
    "scan_module_profiles",
    "scan_modules",
    "scan_modules_from_extraction_report",
    "scan_modules_from_tracking_db",
    "scan_skills",
    "scan_workspace_rules",
]
