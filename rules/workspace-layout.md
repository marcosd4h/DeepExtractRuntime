---
description: Workspace directory layout and data location reference
alwaysApply: true
---

# Workspace Data Layout

| Path | Contents |
|------|----------|
| `extracted_code/{module}/` | Decompiled .cpp files + file_info.json/md + module_profile.json |
| `extracted_code/{module}/reports/` | Saved reports, visualizations, and analysis artifacts (.md, .html, .h) |
| `extracted_dbs/` | SQLite analysis DBs (assembly, xrefs, strings, loops) |
| `.claude/helpers/` | Shared Python library (30+ modules) -- **use for all script development** |
| `.claude/docs/` | Architecture, authoring guides, format references, testing, onboarding, and more |
| `.claude/skills/` | Analysis skills with helper scripts in scripts/ subdirs |
| `.claude/agents/` | Subagent definitions and scripts |
| `.claude/commands/` | Slash command definitions (.md files) |
| `.claude/hooks/` | Lifecycle hooks (sessionStart context injector, stop grind loop) |
| `.claude/cache/` | Cached skill-script results (validated by DB mtime + 24h TTL, use `--no-cache` to bypass) |
| `.claude/workspace/` | Run directories for multi-step workflow handoff |
| `.claude/config/` | defaults.json -- classification weights, thresholds, timeouts |
| `.claude/tests/` | Test files + conftest.py |

Use `file_info.json` (not .md) for programmatic lookups. Use `module_profile.json` for pre-computed module-level metrics. Use analysis DBs for assembly, xrefs, strings, and loop data not available in .cpp files.

## Script Development

When developing new skill scripts, agent scripts, or hooks, always import from `.claude/helpers/` for database access, function resolution, error handling, classification, JSON output, caching, and all other shared operations. Read `.claude/helpers/README.md` for the full categorized developer reference with import patterns and operation-to-helper mappings. Never reimplement what a helper already provides.
