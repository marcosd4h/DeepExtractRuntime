# Cursor / Claude Code Hooks

Hooks run scripts before or after agent actions. In an installed workspace they
are located under `.agent/hooks/`, while root-level `hooks.json` wires them
into the host. They communicate over stdin/stdout JSON and can inject context,
gate operations, or create iteration loops. Works with both Cursor and Claude
Code.

Configuration: `hooks.json` (workspace root)
Documentation: https://cursor.com/docs/agent/hooks

## Hooks

### sessionStart -- inject-module-context.py

Fires once when a new conversation starts. Scans the workspace and injects a structured context summary so the agent always knows what it's working with. Also resolves a **session ID** from the host platform and propagates it for session-scoped scratchpads.

**What it injects:**

- Module table: name, binary, description, function count, class count, exports, imports
- Per-module detail: company, version, size, entry point count
- Module profiles: pre-computed fingerprints from `module_profile.json` (library noise ratio, dangerous API categories, technology surface flags, complexity metrics)
- Analysis database listing with file sizes
- Quick-reference commands for all skill scripts (find_module_db, list_functions, extract_function_data, triage_summary, scan_module, verify_function)
- Available skills table with type, purpose, dependencies, and cacheability (from `skills/registry.json`)
- Available agents table with type, purpose, and skills used (from `agents/registry.json`)
- Available commands table with purpose, parameters, skills/agents used, grind loop, and workspace flags (from `commands/registry.json`)
- Available rules table with filenames and purposes (from `.agent/rules/*.mdc`)
- README-derived documentation overviews: skills dependency graph, commands usage/integration map, agents architecture/decision table (from `skills/README.md`, `commands/README.md`, `agents/README.md`)
- Workspace layout summary
- **Session ID and scratchpad path** for grind-loop isolation

**Session ID resolution (platform-agnostic):**

1. `AGENT_SESSION_ID` environment variable
2. `conversation_id` from stdin JSON (Cursor -- stable across all hook events)
3. `session_id` from stdin JSON (Claude Code -- present in all hook events)
4. UUID4 fallback (if no platform ID is available)

**Output:**

```json
{
  "env": { "AGENT_SESSION_ID": "<session_id>" },
  "additional_context": "<workspace context with session info>"
}
```

The `env` field (Cursor) sets `AGENT_SESSION_ID` for all subsequent hooks in this session. The `additional_context` includes a `### Session` section with the session ID and scratchpad path.

**How it works:**

1. Reads stdin JSON for session identification
2. Reads `extracted_code/*/file_info.json` for each module (binary identity, PE metadata, function summaries)
3. Reads `extracted_code/*/module_profile.json` for pre-computed module fingerprints (library composition, API surface, complexity)
4. Lists `extracted_dbs/*.db` for analysis databases
5. Lists `.agent/skills/*/SKILL.md` for available skills
6. Scans `.agent/rules/*.mdc` for installed runtime rules
7. Loads `skills/registry.json`, `agents/registry.json`, `commands/registry.json` for machine-readable metadata (type, purpose, dependencies, parameters, skills used)
8. At `full` level: loads condensed overviews from `skills/README.md`, `commands/README.md`, `agents/README.md` (overview tables, dependency graphs, decision matrices -- stops before per-item detailed descriptions)
9. Ensures `.agent/hooks/scratchpads/` directory exists
10. Assembles everything into a Markdown context and outputs JSON with `env` and `additional_context`

**Timeout:** 15s host timeout (`hooks.json`); the hook uses the same value from `hooks.session_start_timeout_seconds` as its internal deadline.

#### Context Levels

The hook supports three context levels via the `DEEPEXTRACT_CONTEXT_LEVEL` environment variable (or the `context_level` field in stdin JSON). This controls how much workspace context is injected at session start, trading off completeness vs. token cost.

Set it before launching the agent:

```bash
# Linux/macOS
export DEEPEXTRACT_CONTEXT_LEVEL=full

# Windows PowerShell
$env:DEEPEXTRACT_CONTEXT_LEVEL = "full"
```

| Level | Description | Injected Content |
|-------|-------------|-----------------|
| **`minimal`** | Lightweight context for constrained token budgets | Module summary (compact one-liner per module), analysis database listing, compact name lists of all skills/agents/commands, session ID + scratchpad path |
| **`standard`** (default) | Balanced context for most workflows | Everything in `minimal` **plus**: full module table, per-module detail block, quick-reference commands, skills table (type, purpose, dependencies, caching), agents table (type, purpose, skills used), commands table (purpose, parameters, skills/agents, grind loop, workspace), workspace layout summary |
| **`full`** | Maximum context for deep analysis sessions | Everything in `standard` **plus**: module profiles (library noise, dangerous APIs, complexity), README-derived documentation (skills dependency graph, commands usage/integration map, agents architecture/decision table), cached analysis results, pre-computed triage highlights |

**What each level excludes:**

- `minimal` omits: module table, module detail blocks, module profiles, quick-reference commands, registry tables (skills/agents/commands), workspace layout, README overviews, cached results, triage highlights
- `standard` omits: module profiles, README overviews, cached results, triage highlights
- `full` includes everything

**When to use each level:**

- `minimal` -- Large workspaces with many modules where token budget is tight, or when the agent only needs to know which modules exist and what skills/commands/agents are available by name
- `standard` -- Default for most reverse engineering sessions; provides enough context to navigate the workspace, understand skill/agent/command capabilities and dependencies, and route tasks intelligently
- `full` -- Deep analysis sessions where pre-computed results, module fingerprints, and rich documentation overviews help the agent skip redundant work and make informed routing decisions

### stop -- grind-until-done.py

Fires when the agent loop ends. Resolves the session ID, checks the session-scoped scratchpad for unchecked items, and re-invokes the agent if work remains. Creates bounded iterative workflows for multi-item tasks like batch lifting or multi-phase reports.

**Session-scoped scratchpads:**

Each agent session gets its own scratchpad at `.agent/hooks/scratchpads/{session_id}.md`. This prevents concurrent sessions from overwriting each other's task lists.

**How it works:**

1. Resolves session ID from `AGENT_SESSION_ID` env var, or `conversation_id`/`session_id` from stdin JSON
2. Looks for `.agent/hooks/scratchpads/{session_id}.md`
3. Parses `- [x]` / `- [ ]` checkboxes and the `## Status` section
4. If unchecked items remain and Status is not `DONE`, outputs `{ "followup_message": "..." }` with remaining items
5. If all items are checked or Status is `DONE`, outputs `{}` (normal stop) and deletes the scratchpad
6. Opportunistically cleans up stale scratchpad files older than 24 hours

**Bounded:** `loop_limit: 10` in hooks.json caps automatic re-invocations.

**Scratchpad format** (created by the agent, skills, or commands):

```markdown
# Task: Lift CSecurityDescriptor methods (appinfo.dll)

## Items

- [x] CSecurityDescriptor::CSecurityDescriptor (constructor)
- [x] CSecurityDescriptor::~CSecurityDescriptor (destructor)
- [ ] CSecurityDescriptor::GetDacl
- [ ] CSecurityDescriptor::SetDacl

## Status

IN_PROGRESS
```

**Who creates the scratchpad:**

- The agent, guided by `.agent/rules/grind-loop-protocol.mdc` (always-on rule)
- Grind-loop commands such as `/lift-class`, `/full-report`, `/verify-decompiler-batch`, `/hunt-execute`, `/batch-audit`, and `/scan`
- Skills `batch-lift` and `verify-decompiled` reference the protocol at their iteration points

**Timeout:** 5s

### sessionEnd -- cleanup-workspace.py

Fires when a conversation ends. Delegates to `helpers.cleanup_workspace.cleanup_workspace()` to remove stale workspace artifacts accumulated during the session.

**What it cleans:**

- **Workspace run directories** in `.agent/workspace/` older than the configured threshold
- **Agent state files** (e.g., code-lifter class state JSONs) older than the threshold
- **Stale cache entries** via `helpers.cache.evict_stale()`

**Configuration:** Age threshold is `hooks.workspace_cleanup_age_hours` in `config/defaults.json` (default: 48 hours). The hook converts this to days for the helper's API.

**Output:** `{}` on success. Cleanup summary written to stderr.

**Timeout:** 10s

## Files

```text
<DeepExtractIDA_output_root>/
  hooks.json                          # Hook configuration installed by the runtime
  .agent/
    hooks/
      README.md                       # This file
      inject-module-context.py        # sessionStart hook
      grind-until-done.py             # stop hook
      cleanup-workspace.py            # sessionEnd hook
      _context_builder.py             # Markdown context assembly helpers
      _profile_formatter.py           # Module-profile formatting helpers
      _readme_loader.py               # README overview extraction helpers
      _scanners.py                    # Workspace scanning helpers
      scratchpads/                    # Runtime-generated session scratchpads
        {session_id}.md               # Ephemeral task state (one per session)
    rules/
      grind-loop-protocol.mdc         # Scratchpad protocol rule
```

`scratchpads/` is created on demand by the session-start hook and may be absent
in a fresh source checkout until hooks have run at least once.

## Platform Compatibility

| Platform    | Session ID source (resolution order)                                       | Env propagation                                   |
| ----------- | -------------------------------------------------------------------------- | ------------------------------------------------- |
| Cursor      | `AGENT_SESSION_ID` env -> `conversation_id` -> `session_id` -> UUID4       | `env` output field sets vars for subsequent hooks |
| Claude Code | `AGENT_SESSION_ID` env -> `conversation_id` -> `session_id` -> UUID4       | stdout goes to context                            |

## Protocol

All hooks follow the Cursor/Claude Code hook protocol:

- **Input:** JSON on stdin (event-specific fields plus common envelope)
- **Output:** JSON on stdout (hook-specific response fields)
- **Exit 0:** Success, use JSON output
- **Exit 2:** Block the action
- **Other exit:** Fail-open (action proceeds)
