"""Context message builder for the session-start hook.

Extracted from inject-module-context.py to improve maintainability
and testability.  The ``build_context()`` function assembles the
Markdown context string that gets injected as ``additional_context``.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from hooks._profile_formatter import format_profile_line

_log = logging.getLogger(__name__)

_LEVEL_ORDER = {"minimal": 0, "standard": 1, "full": 2}

_IPC_PATH_ENSURED = False


def _ensure_helpers_path() -> None:
    """Ensure the helpers package is importable (idempotent)."""
    global _IPC_PATH_ENSURED
    if _IPC_PATH_ENSURED:
        return
    _root = Path(__file__).resolve().parents[1]
    _agent = _root / ".agent"
    path_entry = str(_agent) if _agent.is_dir() else str(_root)
    if path_entry not in sys.path:
        sys.path.insert(0, path_entry)
    _IPC_PATH_ENSURED = True


def _is_level_enabled(context_level: str, required_level: str) -> bool:
    return _LEVEL_ORDER.get(context_level, 1) >= _LEVEL_ORDER.get(required_level, 1)


def build_context(
    modules: list[dict],
    dbs: list[dict],
    has_tracking_db: bool,
    skills: list[str],
    context_level: str = "standard",
    session_id: str = "",
    compact_mode: bool = False,
    skill_registry: dict | None = None,
    agent_registry: dict | None = None,
    command_registry: dict | None = None,
    cached_results: dict[str, list[dict]] | None = None,
    triage_summaries: dict[str, dict] | None = None,
    module_profiles: dict[str, dict] | None = None,
    skills_readme_overview: str | None = None,
    commands_readme_overview: str | None = None,
    agents_readme_overview: str | None = None,
    workspace_rules: list[str] | None = None,
) -> str:
    """Assemble the Markdown context message for injection."""
    lines: list[str] = []

    lines.append("## DeepExtractIDA Workspace Context (auto-injected)")
    lines.append("")

    agent_names = sorted(agent_registry.keys()) if agent_registry else []
    command_names = sorted(command_registry.keys()) if command_registry else []

    db_count = len(modules) if compact_mode else len(dbs)
    status_counts: dict[str, int] = {}
    for m in modules:
        s = m.get("status", "UNKNOWN")
        status_counts[s] = status_counts.get(s, 0) + 1
    uniform_status = len(status_counts) <= 1
    if uniform_status:
        module_part = f"**{len(modules)} extracted module(s)**"
    else:
        status_parts = [
            f"{count} {status}"
            for status, count in sorted(status_counts.items(), key=lambda x: -x[1])
        ]
        module_part = f"**{len(modules)} extracted module(s)** ({', '.join(status_parts)})"
    lines.append(
        f"{module_part} | "
        f"**{db_count} analysis DB(s)** | "
        f"**{len(skills)} skill(s)** | "
        f"**{len(agent_names)} agent(s)** | "
        f"**{len(command_names)} command(s)**"
    )
    lines.append(f"**Context level**: `{context_level}`")
    lines.append("")

    lines.append(
        "**Read `.agent/AGENTS.md`** for runtime architecture, "
        "conventions, and getting-started guide."
    )
    if workspace_rules:
        rules_str = ", ".join(f"`{r}`" for r in workspace_rules)
        lines.append(
            f"**Workspace rules** (`.cursor/rules/`): {rules_str} "
            "-- read and follow all rules in this directory."
        )
    lines.append("")

    if _is_level_enabled(context_level, "standard"):
        _build_ipc_summary_line(lines)

    if not _is_level_enabled(context_level, "standard"):
        _build_minimal_component_list(lines, skills, agent_names, command_names)

    _build_module_section(lines, modules, context_level, compact_mode)

    if module_profiles and _is_level_enabled(context_level, "full"):
        _build_profile_section(lines, module_profiles)

    if _is_level_enabled(context_level, "full"):
        _build_rpc_section(lines, modules, context_level)
        _build_com_section(lines, modules, context_level)

    if _is_level_enabled(context_level, "full"):
        _build_db_section(lines, modules, dbs, has_tracking_db, compact_mode)

    if skills and _is_level_enabled(context_level, "standard"):
        _build_skills_section(lines, skills, skill_registry)

    if agent_registry and _is_level_enabled(context_level, "standard"):
        _build_agents_table(lines, agent_registry)

    if command_names and _is_level_enabled(context_level, "standard"):
        if _is_level_enabled(context_level, "full"):
            _build_commands_table(lines, command_registry)
        else:
            _build_commands_summary(lines, command_registry)

    if _is_level_enabled(context_level, "full"):
        _build_readme_sections(
            lines, skills_readme_overview,
            agents_readme_overview, commands_readme_overview,
        )

    if cached_results:
        _build_cached_results_section(lines, cached_results, context_level)

    if triage_summaries and _is_level_enabled(context_level, "full"):
        _build_triage_section(lines, triage_summaries)

    if session_id:
        _build_session_section(lines, session_id)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _build_minimal_component_list(
    lines: list[str],
    skills: list[str],
    agent_names: list[str],
    command_names: list[str],
) -> None:
    if skills:
        lines.append(
            "**Skills**: "
            + ", ".join(f"`{s}`" for s in skills)
        )
    if agent_names:
        lines.append(
            "**Agents**: "
            + ", ".join(f"`{a}`" for a in agent_names)
        )
    if command_names:
        lines.append(
            "**Commands**: "
            + ", ".join(f"`/{c}`" for c in command_names)
        )
    if skills or agent_names or command_names:
        lines.append("")


def _build_ipc_summary_line(lines: list[str]) -> None:
    """Add a one-line IPC server summary for workspace modules."""
    try:
        from helpers.ipc_workspace import discover_workspace_ipc_servers
        result = discover_workspace_ipc_servers()
        summary = result.get("summary", {})
        com_n = summary.get("com_modules", 0)
        rpc_n = summary.get("rpc_modules", 0)
        winrt_n = summary.get("winrt_modules", 0)
        if com_n or rpc_n or winrt_n:
            parts = []
            if rpc_n:
                parts.append(f"**{rpc_n} module(s) with RPC**")
            if com_n:
                parts.append(f"**{com_n} module(s) with COM**")
            if winrt_n:
                parts.append(f"**{winrt_n} module(s) with WinRT**")
            lines.append(" | ".join(parts))
            lines.append("")
    except Exception:
        pass


def _build_module_section(
    lines: list[str],
    modules: list[dict],
    context_level: str,
    compact_mode: bool,
) -> None:
    """Emit per-module listing only at minimal level.

    At standard/full level the module count and status are already in the
    header line, and discovery commands are in the commands list.
    """
    if not modules:
        return

    if not _is_level_enabled(context_level, "standard") and not compact_mode:
        lines.append("### Modules")
        lines.append("")
        for m in modules:
            lines.append(
                f"- `{m['name']}`: {m['total_functions']} functions, "
                f"{m['export_count']} exports"
            )
        lines.append("")


def _build_profile_section(
    lines: list[str], module_profiles: dict[str, dict],
) -> None:
    lines.append("### Module Profiles")
    lines.append("")
    for mod_dir_name, profile in sorted(module_profiles.items()):
        mod_name = profile.get("identity", {}).get(
            "module_name", mod_dir_name
        )
        lines.append(format_profile_line(mod_name, profile))
    lines.append("")


def _build_rpc_section(
    lines: list[str], modules: list[dict], context_level: str,
) -> None:
    """Inject RPC surface summary when the RPC index is available."""
    try:
        _ensure_helpers_path()
        from helpers.rpc_index import get_rpc_index
        idx = get_rpc_index()
        if not idx.loaded:
            return
    except Exception as exc:
        _log.warning("Failed to load RPC index for context injection: %s", exc)
        return

    summary = idx.summary()
    if summary["total_interfaces"] == 0:
        return

    module_names = {m.get("file_name", "").lower() for m in modules if m.get("file_name")}
    rpc_modules = []
    for mod in modules:
        fname = mod.get("file_name", "")
        if not fname:
            continue
        ifaces = idx.get_interfaces_for_module(fname)
        if ifaces:
            procs = idx.get_procedures_for_module(fname)
            tiers = {i.risk_tier for i in ifaces}
            highest = "low"
            for t in ("critical", "high", "medium"):
                if t in tiers:
                    highest = t
                    break
            pipes = sorted({p for i in ifaces for p in i.pipe_names})
            rpc_modules.append({
                "name": fname,
                "interfaces": len(ifaces),
                "procedures": len(procs),
                "risk_tier": highest,
                "pipes": ", ".join(pipes) if pipes else "-",
                "service": next((i.service_name for i in ifaces if i.service_name), ""),
            })

    if not rpc_modules:
        return

    lines.append("### RPC Attack Surface")
    lines.append("")
    lines.append(
        f"**{summary['total_interfaces']} RPC interfaces** across "
        f"**{summary['total_modules']} system modules** | "
        f"**{summary['remote_reachable']} remote-reachable** | "
        f"**{summary['named_pipe']} named-pipe** | "
        f"`/rpc` for analysis"
    )
    lines.append("")

    if _is_level_enabled(context_level, "standard"):
        lines.append(
            "| Module | Interfaces | Procedures | Risk | Pipes | Service |"
        )
        lines.append(
            "|--------|-----------|-----------|------|-------|---------|"
        )
        for rm in sorted(rpc_modules, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x["risk_tier"], 9)):
            lines.append(
                f"| `{rm['name']}` | {rm['interfaces']} | {rm['procedures']} "
                f"| {rm['risk_tier']} | {rm['pipes']} | {rm['service'] or '-'} |"
            )
        lines.append("")


def _build_com_section(
    lines: list[str], modules: list[dict], context_level: str,
) -> None:
    """Inject COM surface summary when the COM index is available."""
    try:
        _ensure_helpers_path()
        from helpers.com_index import get_com_index
        idx = get_com_index()
        if not idx.loaded:
            return
    except Exception as exc:
        _log.warning("Failed to load COM index for context injection: %s", exc)
        return

    summary = idx.summary()
    if summary["total_servers"] == 0:
        return

    com_modules = []
    for mod in modules:
        fname = mod.get("file_name", "")
        if not fname:
            continue
        servers = idx.get_servers_for_module(fname)
        if servers:
            methods = sum(s.method_count for s in servers)
            tiers = {s.best_risk_tier for s in servers}
            highest = "low"
            for t in ("critical", "high", "medium"):
                if t in tiers:
                    highest = t
                    break
            svc = next((s.service_name for s in servers if s.service_name), "")
            com_modules.append({
                "name": fname,
                "servers": len(servers),
                "methods": methods,
                "risk_tier": highest,
                "service": svc,
                "elevatable": sum(1 for s in servers if s.can_elevate or s.auto_elevation),
            })

    if not com_modules:
        return

    lines.append("### COM Attack Surface")
    lines.append("")
    lines.append(
        f"**{summary['total_servers']} COM servers** across "
        f"**{summary['total_modules']} modules** | "
        f"**{summary.get('can_elevate', 0)} elevatable** | "
        f"**{summary.get('runs_as_system', 0)} SYSTEM** | "
        f"`/com` for analysis"
    )
    lines.append("")

    if _is_level_enabled(context_level, "standard"):
        lines.append(
            "| Module | Servers | Methods | Risk | Service | Elevatable |"
        )
        lines.append(
            "|--------|---------|---------|------|---------|------------|"
        )
        tier_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for cm in sorted(com_modules, key=lambda x: tier_order.get(x["risk_tier"], 9)):
            lines.append(
                f"| `{cm['name']}` | {cm['servers']} | {cm['methods']} "
                f"| {cm['risk_tier']} | {cm['service'] or '-'} | {cm['elevatable']} |"
            )
        lines.append("")


def _build_db_section(
    lines: list[str],
    modules: list[dict],
    dbs: list[dict],
    has_tracking_db: bool,
    compact_mode: bool,
) -> None:
    if compact_mode:
        lines.append("### Analysis Databases")
        lines.append("")
        if has_tracking_db:
            lines.append(
                "- **Tracking DB**: `extracted_dbs/analyzed_files.db` "
                "(module index, status, hashes)"
            )
        lines.append(
            f"- **{len(modules):,}** per-module analysis databases "
            "in `extracted_dbs/`"
        )
        lines.append("")
    elif dbs:
        lines.append("### Analysis Databases")
        lines.append("")
        if has_tracking_db:
            lines.append(
                "- **Tracking DB**: `extracted_dbs/analyzed_files.db` "
                "(module index, status, hashes)"
            )
        for db in dbs:
            lines.append(f"- `{db['path']}` ({db['size_kb']} KB)")
        lines.append("")


def _build_skills_section(
    lines: list[str], skills: list[str], skill_registry: dict | None,
) -> None:
    lines.append("### Available Skills")
    lines.append("")
    lines.append("| Skill | Type | Purpose | Cacheable |")
    lines.append("|-------|------|---------|-----------|")
    for name in sorted(skills):
        meta = (skill_registry or {}).get(name, {})
        stype = meta.get("type", "?")
        purpose = meta.get("purpose", "")
        cacheable = "yes" if meta.get("cacheable") else "no"
        lines.append(f"| `{name}` | {stype} | {purpose} | {cacheable} |")
    lines.append("")
    lines.append(
        "*Read a skill's `SKILL.md` before first use. "
        "Cacheable skills accept `--no-cache` to recompute.*"
    )
    lines.append("")


def _build_agents_table(
    lines: list[str], agent_registry: dict,
) -> None:
    lines.append("### Available Agents")
    lines.append("")
    lines.append("| Agent | Type | Purpose | Skills Used |")
    lines.append("|-------|------|---------|-------------|")
    for name, meta in sorted(agent_registry.items()):
        atype = meta.get("type", "?")
        purpose = meta.get("purpose", "")
        agent_skills = meta.get("skills_used", [])
        skills_str = f"{len(agent_skills)} skills" if agent_skills else "--"
        lines.append(
            f"| `{name}` | {atype} | {purpose} | {skills_str} |"
        )
    lines.append("")
    lines.append(
        "*Read an agent's `.md` file (e.g. `.agent/agents/code-lifter.md`) "
        "for entry scripts, parameters, and composed skills.*"
    )
    lines.append("")


def _build_commands_summary(
    lines: list[str], command_registry: dict,
) -> None:
    lines.append("### Available Commands")
    lines.append("")
    lines.append("| Command | Purpose |")
    lines.append("|---------|---------|")
    for name, meta in sorted(command_registry.items()):
        purpose = meta.get("purpose", "")
        lines.append(f"| `/{name}` | {purpose} |")
    lines.append("")
    lines.append(
        "*Read a command's `.md` file before execution for full usage, "
        "parameters, and skills/agents composed.*"
    )
    lines.append("")


def _build_commands_table(
    lines: list[str], command_registry: dict,
) -> None:
    lines.append("### Available Commands")
    lines.append("")
    lines.append("| Command | Purpose | Params | Skills/Agents |")
    lines.append("|---------|---------|--------|---------------|")
    for name, meta in sorted(command_registry.items()):
        purpose = meta.get("purpose", "")
        params = meta.get("parameters", "")
        cmd_skills = meta.get("skills_used", [])
        cmd_agents = meta.get("agents_used", [])
        uses_parts = [f"S:{len(cmd_skills)}"] if cmd_skills else []
        if cmd_agents:
            uses_parts.append(f"A:{','.join(cmd_agents)}")
        uses_str = " ".join(uses_parts) if uses_parts else "--"
        lines.append(
            f"| `/{name}` | {purpose} "
            f"| `{params}` | {uses_str} |"
        )
    lines.append("")


def _build_readme_sections(
    lines: list[str],
    skills_readme_overview: str | None,
    agents_readme_overview: str | None,
    commands_readme_overview: str | None,
) -> None:
    if skills_readme_overview:
        lines.append("### Skills Documentation (from README)")
        lines.append("")
        lines.append(skills_readme_overview)
        lines.append("")
    if agents_readme_overview:
        lines.append("### Agents Documentation (from README)")
        lines.append("")
        lines.append(agents_readme_overview)
        lines.append("")
    if commands_readme_overview:
        lines.append("### Commands Documentation (from README)")
        lines.append("")
        lines.append(commands_readme_overview)
        lines.append("")


def _build_cached_results_section(
    lines: list[str],
    cached_results: dict[str, list[dict]],
    context_level: str,
) -> None:
    any_cached = any(v for v in cached_results.values())
    if not any_cached or not _is_level_enabled(context_level, "standard"):
        return

    if _is_level_enabled(context_level, "full"):
        lines.append("### Cached Analysis Results")
        lines.append("")
        lines.append(
            "*Previously computed results "
            "(use `--no-cache` to recompute):*"
        )
        lines.append("")
        for mod_name, caches in sorted(cached_results.items()):
            if caches:
                ops = ", ".join(
                    f"`{c['operation']}`" for c in caches
                )
                lines.append(f"- **{mod_name}**: {ops}")
        lines.append("")
    else:
        cache_parts: list[str] = []
        for mod_name, caches in sorted(cached_results.items()):
            if caches:
                seen: set[str] = set()
                unique_ops: list[str] = []
                for c in caches:
                    op = c["operation"]
                    if op not in seen:
                        seen.add(op)
                        unique_ops.append(op)
                cache_parts.append(
                    f"**{mod_name}**({', '.join(unique_ops)})"
                )
        if cache_parts:
            lines.append(
                f"**Cached**: {'; '.join(cache_parts)}"
            )
            lines.append("")


def _build_triage_section(
    lines: list[str], triage_summaries: dict[str, dict],
) -> None:
    lines.append("### Pre-Computed Triage Highlights")
    lines.append("")
    for mod_name, triage in sorted(triage_summaries.items()):
        summary = triage.get("summary", {})
        top_interesting = triage.get("top_interesting", [])
        total = summary.get("total_functions", 0)
        app_count = summary.get("application_functions", 0)
        lib_count = summary.get("library_functions", 0)
        lines.append(
            f"- **{mod_name}**: {total} functions "
            f"({app_count} application, {lib_count} library)"
        )
        if top_interesting:
            top3 = top_interesting[:3]
            for item in top3:
                name = item.get("function_name", "?")
                score = item.get("interest_score", "?")
                cat = item.get("primary_category", "?")
                lines.append(
                    f"  - `{name}` (interest: {score}/10, category: {cat})"
                )
    lines.append("")


def _build_session_section(lines: list[str], session_id: str) -> None:
    lines.append("")
    lines.append("### Session")
    lines.append("")
    lines.append(f"Session ID: `{session_id}`")
    lines.append(
        f"Scratchpad: `.agent/hooks/scratchpads/{session_id}.md`"
    )
    lines.append(
        "*When the grind-loop protocol requires a scratchpad, "
        "always use the session-scoped path above.*"
    )


__all__ = ["build_context"]
