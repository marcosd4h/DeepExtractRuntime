# DeepExtractIDA Persistence and Lifecycle

This document describes scratchpad lifecycle, the `/runs` command, persistent storage for findings/hypotheses, and session vs cross-session persistence mechanisms.

---

## 1. Grind Loop Scratchpad Lifecycle

### Overview

The grind loop uses **session-scoped scratchpads** to track multi-item task progress. The stop hook (`grind-until-done.py`) reads the scratchpad and, when unchecked items remain, re-invokes the agent to continue until completion.

### When Created

Scratchpads are **created by the agent** (or skill) when:

- The task involves **3+ discrete items** to process sequentially (e.g., lifting N functions, running N analysis phases)
- The user says "all", "every", "each", "batch" — anything implying iteration
- A slash command workflow (e.g. `/lift-class`, `/full-report`, `/batch-audit`, `/hunt-execute`) has multiple tracked steps

**Do NOT** create a scratchpad for single-item tasks or simple questions.

### Location

```
.agent/hooks/scratchpads/{session_id}.md
```

- `{session_id}` comes from: `AGENT_SESSION_ID` env → `conversation_id` → `session_id` (stdin) → UUID4 fallback
- If session ID is unavailable in context, fall back to `.agent/hooks/scratchpads/default.md`.

### Format

```markdown
# Task: <short description>

## Items
- [ ] Item 1 -- brief description
- [x] Item 2 -- completed

## Status
IN_PROGRESS
```

### When Deleted

The scratchpad is **deleted automatically** when:

1. **Status is `DONE`** — the hook deletes the file and exits without followup
2. **All items are checked** — same behavior
3. **Standalone DONE/COMPLETE** in the `## Status` section — same behavior

### Stale Cleanup

- **Orphaned scratchpads** (session-specific files older than `grind_scratchpad_stale_hours`, default 24 hours) are removed opportunistically when the stop hook runs
- `default.md` is **never** cleaned up — it is an intentional shared fallback

### What They Store

- **Task checklist**: `- [ ]` or `- [x]` items with brief descriptions
- **Status**: `IN_PROGRESS` or `DONE`
- **No** findings, hypotheses, or research state — only task progress

### Loop Limit

- Up to **10** re-invocations per run (`loop_limit` in `hooks.json`)

---

## 2. `/runs` Command

### Purpose

Browse prior workspace runs created by multi-step workflows (`/triage`, `/full-report`, `/scan`, `/batch-audit`, `/audit`, etc.).

### Subcommands

| Subcommand | Description |
|------------|-------------|
| `list [module]` | List the 10 most recent runs (optionally filtered by module) |
| `show <run_id>` | Reopen a specific run by ID |

### What It Inspects

- **Source**: `.agent/workspace/` — run directories
- **Helpers**:
  - `helpers.workspace.list_runs()` — run discovery and sorting
  - `helpers.workspace.read_summary()` — per-step summaries
  - `helpers.workspace_validation.validate_workspace_run()` — validate run structure

### Workspace Outputs

Each run directory:

```
.agent/workspace/<module>_<goal>_<timestamp>/
├── manifest.json
├── <step_name>/
│   ├── results.json   # full payload
│   └── summary.json   # compact summary
```

### Manifest Structure

```json
{
  "run_id": "appinfo_audit_RAiGetTokenForAxIS_20260309",
  "module_name": "appinfo",
  "goal": "audit",
  "created_at": "2026-03-09T04:40:12.118216Z",
  "updated_at": "2026-03-09T04:42:05.317899Z",
  "steps": {
    "dossier": {
      "status": "success",
      "summary_path": "dossier/summary.json",
      "updated_at": "2026-03-09T04:40:12.118216Z"
    },
    "extract": { ... }
  }
}
```

- **Step status**: `success`, `error`, `running`, `in_progress`, `pending`
- **Validation**: `validate_workspace_run()` checks manifest.json presence, step records, summary_path existence, and per-step `results.json` / `summary.json`

---

## 3. Persistent Storage for Findings, Hypotheses, and Research State

### Workspace Run Directories

| Path | Contents |
|------|----------|
| `.agent/workspace/<module>_<goal>_<timestamp>/` | Run outputs: `manifest.json`, step subdirs with `results.json` and `summary.json` |
| `.agent/workspace/<module>_hunt_plan_<timestamp>.json` | Hunt plans (hypotheses, commands, threat model) |

**Hunt plans** (`/hunt-plan`):

- Schema: `module`, `mode`, `hypotheses` (id, statement, priority, commands, validation_criteria), `threat_model`, `created_at`
- Used by `/hunt-execute` across sessions

### Cache

| Path | Contents | TTL |
|------|----------|-----|
| `.agent/cache/{module}/{operation}.json` | Skill script results (triage, classification, call graph, etc.) | 24h (validated by DB mtime) |
| `.agent/cache/_module_list.json` | Module list sidecar for large workspaces | — |

- Cache eviction: `evict_stale()` removes entries older than `cache.max_age_hours` (default 24)
- Size limit: `cache.max_cache_size_mb` (default 500) — evicts oldest when exceeded

### Agent State Files

| Path | Contents |
|------|----------|
| `.agent/agents/<agent>/state/*.json` | Per-agent state (e.g. code-lifter iteration state) |

- Cleaned by sessionEnd hook when older than `workspace_cleanup_age_hours` (default 48)

### No Dedicated Findings Storage

- **Findings** from scans/audits are stored in **workspace run step outputs** (`results.json`, `summary.json`), not in a central findings DB
- **Prioritized findings** (`/prioritize`) are output in chat; no persistent store unless the user saves them
- **Brainstorm** and **replan** read from `.agent/cache/` and `.agent/workspace/` manifests

---

## 4. Session vs Cross-Session Persistence

### Session-Scoped (Single Session)

| Artifact | Location | Lifetime |
|----------|----------|----------|
| Scratchpad | `.agent/hooks/scratchpads/{session_id}.md` | Until DONE or all items checked; orphaned files removed after 24h |
| Session ID | `AGENT_SESSION_ID` env (from sessionStart hook) | Per conversation |

### Cross-Session (Persists Across Sessions)

| Artifact | Location | Lifetime |
|----------|----------|----------|
| Workspace runs | `.agent/workspace/<run_id>/` | Until `workspace_cleanup_age_hours` (default 48h) or manual purge |
| Hunt plans | `.agent/workspace/*_hunt_plan_*.json` | Same as workspace runs |
| Cache | `.agent/cache/{module}/{operation}.json` | 24h TTL, or size eviction |
| Agent state | `.agent/agents/<agent>/state/*.json` | Until 48h stale |

### Session Lifecycle Hooks

| Hook | When | Purpose |
|------|------|----------|
| `sessionStart` | Start of session | Inject context, resolve session ID, set `AGENT_SESSION_ID` |
| `stop` | End of agent turn | Grind loop: if scratchpad has pending items, re-invoke agent |
| `sessionEnd` | End of session | Cleanup: remove workspace runs & agent state older than 48h, evict stale cache |

### Configuration

- `config/defaults.json`:
  - `hooks.grind_scratchpad_stale_hours`: 24
  - `hooks.workspace_cleanup_age_hours`: 48
  - `cache.max_age_hours`: 24
  - `cache.max_cache_size_mb`: 500

---

## Summary Table

| Mechanism | Scope | Lifetime | Primary Use |
|-----------|-------|----------|-------------|
| Scratchpad | Session | Until DONE or 24h orphan | Grind loop task checklist |
| Workspace run | Cross-session | 48h default | Step outputs, manifests |
| Hunt plan | Cross-session | 48h default | Hypotheses for `/hunt-execute` |
| Cache | Cross-session | 24h TTL | Skill script results |
| Agent state | Cross-session | 48h default | Per-agent iteration state |
