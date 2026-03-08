"""Load and query pre-computed module profiles (module_profile.json).

Module profiles are generated unconditionally during extraction and
contain pre-computed fingerprints: library composition, API surface,
complexity metrics, and security posture.  Skills and agents can use
this helper instead of recomputing the same metrics from the DB.

Typical usage::

    from helpers.module_profile import load_module_profile, load_all_profiles

    profile = load_module_profile(Path("extracted_code/appinfo_dll"))
    all_profiles = load_all_profiles(Path("extracted_code"))
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .config import get_config_value
from .errors import log_warning

_DB_HASH_SUFFIX_RE = re.compile(r"_[0-9a-f]{6,}$")

PROFILE_FILENAME = "module_profile.json"


def load_module_profile(module_dir: Path) -> dict[str, Any] | None:
    """Load module_profile.json from a module's extracted_code directory.

    Args:
        module_dir: Path to the module directory (e.g. ``extracted_code/appinfo_dll``).

    Returns:
        Parsed profile dict, or ``None`` if the file is missing or unparseable.
    """
    profile_path = module_dir / PROFILE_FILENAME
    if not profile_path.exists():
        log_warning(
            f"Module profile not found: {profile_path}", "NOT_FOUND",
        )
        return None
    try:
        with open(profile_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        log_warning(
            f"Invalid JSON in module profile {profile_path}: {exc}",
            "PARSE_ERROR",
        )
        return None
    except OSError as exc:
        log_warning(
            f"Cannot read module profile {profile_path}: {exc}",
            "DB_ERROR",
        )
        return None


def load_all_profiles(
    extracted_code_dir: Path,
    *,
    max_modules: int | None = None,
) -> dict[str, dict[str, Any]]:
    """Load module profiles keyed by directory name.

    Args:
        extracted_code_dir: Path to the ``extracted_code/`` directory.
        max_modules: Maximum number of profiles to load.  Defaults to
            ``scale.max_modules_cross_scan`` from config.

    Returns:
        Dict mapping module directory name to its parsed profile.
        Modules without a profile are silently skipped.
    """
    if max_modules is None:
        max_modules = get_config_value("scale.max_modules_cross_scan", 0)
    import sys
    profiles: dict[str, dict[str, Any]] = {}
    if not extracted_code_dir.is_dir():
        return profiles
    dirs = sorted(d for d in extracted_code_dir.iterdir() if d.is_dir())
    total = len(dirs)
    loaded = 0
    for i, module_dir in enumerate(dirs, 1):
        if max_modules and max_modules > 0 and loaded >= max_modules:
            break
        if total >= 500 and i % 500 == 0:
            print(
                f"  load_all_profiles: {i}/{total} modules...",
                file=sys.stderr,
            )
        profile = load_module_profile(module_dir)
        if profile is not None:
            profiles[module_dir.name] = profile
            loaded += 1
    return profiles


def load_profile_for_db(db_path: Path) -> dict[str, Any] | None:
    """Resolve a module profile from an analysis DB path.

    Derives the module directory name from the DB filename by stripping
    the hash suffix (e.g. ``appinfo_dll_f2bbf324a1.db`` -> ``appinfo_dll``),
    then does a direct lookup instead of scanning all directories.

    Args:
        db_path: Path to an analysis ``.db`` file in ``extracted_dbs/``.

    Returns:
        Parsed profile dict, or ``None`` if not found.
    """
    from .db_paths import _auto_workspace_root

    db_path = Path(db_path).resolve()
    workspace_root = _auto_workspace_root()

    db_stem = db_path.stem
    m = _DB_HASH_SUFFIX_RE.search(db_stem)
    derived_name = db_stem[:m.start()] if m else db_stem

    extracted_code_dir = workspace_root / "extracted_code"
    if not extracted_code_dir.is_dir():
        log_warning(
            f"extracted_code directory not found: {extracted_code_dir}",
            "NOT_FOUND",
        )
        return None

    candidate = extracted_code_dir / derived_name
    if candidate.is_dir():
        return load_module_profile(candidate)

    log_warning(
        f"No module directory matching DB stem '{db_stem}' in {extracted_code_dir}",
        "NOT_FOUND",
    )
    return None


def get_noise_ratio(profile: dict[str, Any]) -> float:
    """Return the library noise ratio (0.0 to 1.0) from a profile."""
    return profile.get("library_profile", {}).get("noise_ratio", 0.0)


def get_technology_flags(profile: dict[str, Any]) -> dict[str, bool]:
    """Return technology presence flags from the import surface."""
    surface = (
        profile.get("api_profile", {}).get("import_surface", {})
    )
    return {
        "com": surface.get("com_present", False),
        "rpc": surface.get("rpc_present", False),
        "winrt": surface.get("winrt_present", False),
        "named_pipes": surface.get("named_pipes_present", False),
    }


def get_canary_coverage(profile: dict[str, Any]) -> float | None:
    """Return stack canary coverage percentage, or ``None`` if unavailable."""
    return profile.get("security_posture", {}).get("canary_coverage_pct")
