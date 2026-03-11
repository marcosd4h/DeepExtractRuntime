#!/usr/bin/env python3
"""Hook: sessionStart -- Auto-inject DeepExtractIDA workspace context.

Scans extracted_code/*/file_info.json and extracted_dbs/*.db to build
a structured context summary.  Injected as additional_context so the
agent always starts with awareness of the binary identity, architecture,
and available analysis data.

Also resolves a session ID from the host platform (Cursor or Claude Code)
and propagates it via the ``env`` output field and the injected context.
This enables session-scoped scratchpads for the grind-loop stop hook.

Input  (stdin JSON):  event metadata (session_id, conversation_id, ...)
Output (stdout JSON): { "env": {...}, "additional_context": "..." }
Exit 0 on success; non-zero/non-2 fail-open.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Workspace root resolution
# .agent/hooks/script.py  ->  .agent/  ->  workspace root
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).resolve().parent
_AGENT_DIR = _SCRIPT_DIR.parent
_WORKSPACE_ROOT = _AGENT_DIR.parent
sys.path.insert(0, str(_AGENT_DIR))

from helpers.analyzed_files_db import open_analyzed_files_db  # noqa: E402
from helpers.config import get_config_value  # noqa: E402
from helpers.session_utils import resolve_session_id, scratchpad_path, SCRATCHPADS_DIR, read_hook_input  # noqa: E402
from hooks._scanners import (  # noqa: E402
    scan_modules,
    scan_modules_from_tracking_db,
    scan_modules_from_extraction_report,
    count_modules_fast,
    scan_dbs,
    scan_skills,
    scan_workspace_rules,
    load_registry,
    scan_module_profiles,
    scan_cached_results,
    load_triage_summary,
    load_module_list_sidecar,
    save_module_list_sidecar,
)
from hooks._context_builder import build_context, _is_level_enabled  # noqa: E402
from hooks._context_builder import build_context  # noqa: E402
from hooks._readme_loader import (  # noqa: E402
    load_skills_readme_overview,
    load_commands_readme_overview,
    load_agents_readme_overview,
)

_CONTEXT_LEVELS = {"minimal", "standard", "full"}
_DEFAULT_CONTEXT_LEVEL = "standard"
_DEFAULT_MODULE_THRESHOLD = 25
_HOOK_DEADLINE_SECONDS = float(get_config_value("hooks.session_start_timeout_seconds", 15))

_MODULE_LIST_SIDECAR = _WORKSPACE_ROOT / ".agent" / "cache" / "_module_list.json"

_hook_start_time: float = 0.0


def _deadline_exceeded() -> bool:
    """Return True if the hook has consumed most of its time budget."""
    return (time.monotonic() - _hook_start_time) >= _HOOK_DEADLINE_SECONDS


# Thin wrappers that bind workspace-specific arguments to _scanners functions.

def _count_modules_fast(extracted_code_dir, tracking_db_path):
    return count_modules_fast(extracted_code_dir, tracking_db_path, open_analyzed_files_db)


def _scan_modules_from_tracking_db(tracking_db_path):
    return scan_modules_from_tracking_db(tracking_db_path, open_analyzed_files_db)


def _load_module_list_sidecar(tracking_db_path):
    return load_module_list_sidecar(_MODULE_LIST_SIDECAR, tracking_db_path)


def _save_module_list_sidecar(modules, tracking_db_path):
    save_module_list_sidecar(_MODULE_LIST_SIDECAR, modules, tracking_db_path)


def _normalize_context_level(value: str | None) -> str:
    if value is None:
        return _DEFAULT_CONTEXT_LEVEL
    level = str(value).strip().lower()
    return level if level in _CONTEXT_LEVELS else _DEFAULT_CONTEXT_LEVEL


def _read_hook_input() -> dict:
    """Read JSON from stdin (Cursor hook protocol).  Delegates to shared helper."""
    return read_hook_input()


# ---------------------------------------------------------------------------
# Registry loaders
# ---------------------------------------------------------------------------
def _load_skill_registry(skills_dir: Path) -> dict:
    return load_registry(skills_dir / "registry.json", "skills")


def _load_agent_registry(agents_dir: Path) -> dict:
    return load_registry(agents_dir / "registry.json", "agents")


def _load_command_registry(commands_dir: Path) -> dict:
    return load_registry(commands_dir / "registry.json", "commands")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def _emit_minimal_fallback(session_id: str, module_count: int) -> None:
    """Emit a minimal context when the deadline is exceeded."""
    lines = [
        "## DeepExtractIDA Workspace Context (auto-injected)",
        "",
        f"**{module_count:,} extracted module(s)** (context truncated due to scale)",
        "",
        "**Read `.agent/AGENTS.md`** for runtime architecture, conventions, and getting-started guide.",
        "",
        "Use `/search <term>` to find modules, `/triage <module>` for overview.",
        "Cross-module operations (`--all` flags) may be slow with this many modules.",
    ]
    if session_id:
        lines.extend([
            "", "### Session", "",
            f"Session ID: `{session_id}`",
            f"Scratchpad: `.agent/hooks/scratchpads/{session_id}.md`",
        ])
    output = {
        "env": {"AGENT_SESSION_ID": session_id},
        "additional_context": "\n".join(lines),
    }
    print(json.dumps(output))
    sys.exit(0)


def main() -> None:
    global _hook_start_time
    _hook_start_time = time.monotonic()

    stdin_data = _read_hook_input()
    context_level = _normalize_context_level(
        stdin_data.get("context_level") if isinstance(stdin_data, dict) else None
    )
    if context_level == _DEFAULT_CONTEXT_LEVEL:
        context_level = _normalize_context_level(
            os.environ.get("DEEPEXTRACT_CONTEXT_LEVEL")
        )

    session_id = resolve_session_id(stdin_data)

    scratchpads_dir = _WORKSPACE_ROOT / ".agent" / "hooks" / "scratchpads"
    os.makedirs(str(scratchpads_dir), exist_ok=True)

    # --- Workspace scanning ---
    extracted_code_dir = _WORKSPACE_ROOT / "extracted_code"
    extracted_dbs_dir = _WORKSPACE_ROOT / "extracted_dbs"
    tracking_db_path = extracted_dbs_dir / "analyzed_files.db"
    agent_dir = _WORKSPACE_ROOT / ".agent"
    skills_dir = agent_dir / "skills"
    agents_dir = agent_dir / "agents"
    commands_dir = agent_dir / "commands"

    config_threshold = get_config_value("scale.compact_mode_threshold", _DEFAULT_MODULE_THRESHOLD)
    threshold = int(
        os.environ.get(
            "DEEPEXTRACT_MODULE_THRESHOLD",
            str(config_threshold),
        )
    )
    module_count = _count_modules_fast(extracted_code_dir, tracking_db_path)
    compact_mode = module_count > threshold

    if _deadline_exceeded():
        _emit_minimal_fallback(session_id, module_count)

    if compact_mode:
        modules = _load_module_list_sidecar(tracking_db_path)
        if modules is None:
            modules = _scan_modules_from_tracking_db(tracking_db_path)
            if modules:
                _save_module_list_sidecar(modules, tracking_db_path)
        if not modules:
            modules = scan_modules_from_extraction_report(
                _WORKSPACE_ROOT / "extraction_report.json"
            )
        dbs: list[dict] = []
        has_tracking = tracking_db_path.exists()
        module_profiles: dict[str, dict] = {}
    else:
        modules = scan_modules(extracted_code_dir)
        module_profiles = {}
        if _is_level_enabled(context_level, "full"):
            module_profiles = scan_module_profiles(extracted_code_dir)
        dbs, has_tracking = scan_dbs(extracted_dbs_dir)

    if _deadline_exceeded():
        _emit_minimal_fallback(session_id, len(modules))

    skills = scan_skills(skills_dir)
    workspace_rules = scan_workspace_rules(_WORKSPACE_ROOT)
    skill_registry = _load_skill_registry(skills_dir)
    agent_registry = _load_agent_registry(agents_dir)
    command_registry = _load_command_registry(commands_dir)

    cached_results: dict[str, list[dict]] = {}
    triage_summaries: dict[str, dict] = {}
    skills_readme_overview: str | None = None
    commands_readme_overview: str | None = None
    agents_readme_overview: str | None = None

    if not compact_mode and _is_level_enabled(context_level, "standard"):
        cache_dir = _WORKSPACE_ROOT / ".agent" / "cache"
        for m in modules:
            if _deadline_exceeded():
                break
            mod_name = m["name"]
            cached_results[mod_name] = scan_cached_results(cache_dir, mod_name)

    if _is_level_enabled(context_level, "full"):
        if not compact_mode:
            cache_dir = _WORKSPACE_ROOT / ".agent" / "cache"
            for m in modules:
                if _deadline_exceeded():
                    break
                mod_name = m["name"]
                triage = load_triage_summary(cache_dir, mod_name)
                if triage:
                    triage_summaries[mod_name] = triage

        if not _deadline_exceeded():
            skills_readme_overview = load_skills_readme_overview(skills_dir)
            commands_readme_overview = load_commands_readme_overview(commands_dir)
            agents_readme_overview = load_agents_readme_overview(agents_dir)

    context = build_context(
        modules, dbs, has_tracking, skills, context_level, session_id,
        compact_mode=compact_mode,
        skill_registry=skill_registry,
        agent_registry=agent_registry,
        command_registry=command_registry,
        cached_results=cached_results,
        triage_summaries=triage_summaries,
        module_profiles=module_profiles,
        skills_readme_overview=skills_readme_overview,
        commands_readme_overview=commands_readme_overview,
        agents_readme_overview=agents_readme_overview,
        workspace_rules=workspace_rules,
    )

    output: dict = {
        "env": {"AGENT_SESSION_ID": session_id},
        "additional_context": context,
    }
    print(json.dumps(output))
    sys.exit(0)


if __name__ == "__main__":
    main()
