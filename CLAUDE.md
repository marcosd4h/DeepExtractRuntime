# DeepExtractIDA Agent Analysis Runtime

AI-driven binary analysis runtime that turns IDA Pro decompiled code and SQLite
analysis databases into structured, queryable intelligence. Analyzes Windows PE
binaries via slash commands, specialized agents, analysis skills, and shared
helper modules.

---

## Quick Rules

- All extraction databases are **read-only**. Never write to them.
- **Always use helpers** for DB access, function resolution, error handling, and classification -- never reimplement what `helpers/` provides.
- Read a skill's `SKILL.md` before invoking it for the first time.
- Use `--json` when capturing script output programmatically; data to stdout, progress/errors to stderr.
- After resolving a function, use `--id <function_id>` in all subsequent calls.
- Prefer cached results from `cache/`. Never pass `--no-cache` unless the user explicitly asks.
- Degrade gracefully on missing data -- never crash with opaque errors; explain what is missing.
- **Never suppress stderr** when running skill scripts. Do not use `2>/dev/null` or equivalent redirections -- structured errors and diagnostics are emitted on stderr by design. Suppressing them hides the exact information needed to debug failures.
- Before creating or modifying a command, skill, or agent, read the corresponding authoring guide in `docs/` and follow its checklist.

---

## Workflow Principles

- **Plan before building.** Enter plan mode for any non-trivial task (3+ steps or architectural decisions). Write detailed specs upfront to reduce ambiguity. If something goes sideways, stop and re-plan immediately.
- **Use subagents liberally.** Offload research, exploration, and parallel analysis to subagents. One task per subagent for focused execution. For complex problems, throw more compute at it via subagents.
- **Verify before marking done.** Never mark a task complete without proving it works. Diff behavior between main and your changes. Run tests, check logs, demonstrate correctness. Ask yourself: "Would a staff engineer approve this?"
- **Demand elegance.** For non-trivial changes, pause and ask "is there a more elegant way?" If a fix feels hacky, implement the clean solution. Challenge your own work before presenting it.
- **Fix bugs autonomously.** When given a bug report, just fix it. Point at logs, errors, failing tests -- then resolve them. Zero context switching required from the user.
- **Simplicity first, minimal impact.** Make every change as simple as possible. Find root causes, not temporary fixes. Changes should only touch what is necessary.

---

## Getting Started

1. **See available modules**: The sessionStart hook injects a module table automatically. If not visible, scan `extracted_dbs/` for `.db` files or `extracted_code/` for module directories.
2. **Triage a module**: `/triage <module>` -- identity, classification, call graph, attack surface, recommendations.
3. **Drill into a function**: `/explain <module> <function>` for quick understanding, `/audit <module> <function>` for security assessment.

Use lightweight commands (`/explain`, `/verify-decompiler`, `/search`) for quick answers;
heavyweight commands (`/audit`, `/lift-class`, `/full-report`) for deep analysis. Run `/health` to diagnose workspace issues.

For a guided walkthrough, read `docs/ONBOARDING.md`.

---

## Architecture

```
Commands  -->  Agents  -->  Skills  -->  Helpers  -->  Data (DBs + JSON)
```

Full details: `docs/architecture.md`.

---

## Key Directories

| Directory    | Purpose                                           | Index                                  |
| ------------ | ------------------------------------------------- | -------------------------------------- |
| `commands/`  | Slash-triggered workflows (`.md` files)           | `commands/README.md`, `registry.json`  |
| `skills/`    | Reusable analysis pipelines with Python scripts   | `skills/README.md`, `registry.json`    |
| `agents/`    | Specialized subagents for multi-step orchestration| `agents/README.md`, `registry.json`    |
| `helpers/`   | Shared Python modules (30+) -- import, don't reimplement | `helpers/README.md`             |
| `docs/`      | Architecture, authoring guides, format references | See progressive disclosure index below |
| `config/`    | Runtime configuration defaults                    | `config/defaults.json`                 |
| `config/pipelines/` | Example YAML pipeline definitions for batch mode | `docs/pipeline_guide.md` |

---

## When You Need To...

Read the relevant doc **on demand** -- don't front-load this context.

| Task                                    | Read                                          |
| --------------------------------------- | --------------------------------------------- |
| Understand the data model / DB schema   | `docs/data_format_reference.md`               |
| Write a new skill                       | `docs/skill_authoring_guide.md`               |
| Write a new command                     | `docs/command_authoring_guide.md`             |
| Write a new agent                       | `docs/agent_authoring_guide.md`               |
| Use the helper library                  | `helpers/README.md`, `docs/helper_api_reference.md` |
| Understand caching                      | `docs/cache_conventions.md`                   |
| Run headless/batch analysis pipelines   | `docs/pipeline_guide.md`                      |
| Parse `file_info.json`                  | `docs/file_info_format_reference.md`          |
| Parse `function_index.json`             | `docs/function_index_format_reference.md`     |
| Parse `module_profile.json`             | `docs/module_profile_format_reference.md`     |
| Optimize for large modules              | `docs/performance_guide.md`                   |
| Debug workspace issues                  | `docs/troubleshooting.md`                     |
| Understand end-to-end data flow         | `docs/integration_guide.md`                   |
| See concrete usage examples             | `docs/examples.md`                            |
| Get started (guided walkthrough)        | `docs/ONBOARDING.md`                          |

---

## Conventions

These apply to **every** script, skill, and agent.

- **Error handling**: Entry scripts use `emit_error(msg, code)`. Library code raises `ScriptError(msg, code)`. Non-fatal issues use `log_warning()`. Wrap DB ops with `db_error_handler()`. Codes: `NOT_FOUND`, `INVALID_ARGS`, `DB_ERROR`, `PARSE_ERROR`, `NO_DATA`, `AMBIGUOUS`, `UNKNOWN`.
- **JSON output**: `--json` emits one JSON dict to stdout with a `"status"` key. Without it, human-readable output. Progress/errors always go to stderr.
- **Workspace pattern**: When a workflow runs 2+ skills, create a run directory in `workspace/` with `manifest.json`, per-step `results.json` and `summary.json`.
- **Grind loop**: For batch tasks with 3+ items, use the scratchpad checklist in `hooks/scratchpads/`. The stop hook re-invokes for unchecked items (up to 10 iterations).
- **Registry maintenance**: When adding a command, skill, or agent, update both `registry.json` and `README.md` in that directory.
- **Hooks**: sessionStart (`inject-module-context.py`) injects module context and session ID. stop (`grind-until-done.py`) checks scratchpad for remaining work.

---

## Testing

Two testing tiers cover the runtime. See `docs/testing_guide.md` for full details.

**Unit tests** -- validate helpers, parsers, and internal modules in isolation:

```bash
python -m pytest tests/ -v
```

Also executed by `/health --full` (step 8).

**Integration tests** -- exercise full scripts against real analysis databases:

```bash
python helpers/qa_runner.py
```

The runner parses `docs/testing_guide.md`, resolves DB paths, executes each
script-level test case, and validates output against the JSON output convention.
