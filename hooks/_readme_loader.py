"""README overview loaders for the session-start hook.

Extracted from inject-module-context.py to improve maintainability
and testability.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional


def load_readme_overview(
    readme_path: Path, stop_before: str | None = None,
) -> str | None:
    """Load README content up to a stop heading.  Returns None if missing."""
    if not readme_path.exists():
        return None
    try:
        text = readme_path.read_text(encoding="utf-8")
    except OSError:
        return None

    if stop_before:
        idx = text.find(stop_before)
        if idx > 0:
            text = text[:idx].rstrip()

    return text or None


def extract_readme_section(
    readme_path: Path, section_heading: str,
) -> str | None:
    """Extract a single ## section (heading + body) from a README."""
    if not readme_path.exists():
        return None
    try:
        text = readme_path.read_text(encoding="utf-8")
    except OSError:
        return None

    start = text.find(section_heading)
    if start < 0:
        return None

    after_start = start + len(section_heading)
    next_h2 = text.find("\n## ", after_start)
    if next_h2 > 0:
        section = text[start:next_h2].rstrip()
    else:
        section = text[start:].rstrip()

    return section or None


def load_skills_readme_overview(skills_dir: Path) -> str | None:
    return load_readme_overview(
        skills_dir / "README.md",
        stop_before="\n## Skill Details",
    )


def load_commands_readme_overview(commands_dir: Path) -> str | None:
    readme_path = commands_dir / "README.md"
    overview = load_readme_overview(
        readme_path, stop_before="\n## Command Details",
    )
    integration_map = extract_readme_section(
        readme_path, "## Skill Integration Map",
    )
    parts = [p for p in (overview, integration_map) if p]
    return "\n\n".join(parts) if parts else None


def load_agents_readme_overview(agents_dir: Path) -> str | None:
    readme_path = agents_dir / "README.md"
    overview = load_readme_overview(
        readme_path, stop_before="\n## Subagents",
    )
    decision_table = extract_readme_section(
        readme_path, "## When to Use Which Subagent",
    )
    subagent_vs_skill = extract_readme_section(
        readme_path, "## Subagent vs Skill",
    )
    parts = [p for p in (overview, decision_table, subagent_vs_skill) if p]
    return "\n\n".join(parts) if parts else None


__all__ = [
    "extract_readme_section",
    "load_agents_readme_overview",
    "load_commands_readme_overview",
    "load_readme_overview",
    "load_skills_readme_overview",
]
