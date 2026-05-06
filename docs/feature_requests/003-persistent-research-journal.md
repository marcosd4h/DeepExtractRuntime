# FR-003: Persistent Research Journal

**Status:** Proposed
**Priority:** High
**Category:** Workflow / Persistence
**Author:** Runtime Assessment Review
**Date:** 2026-03-16

---

## Problem Statement

Between sessions, there is no mechanism to accumulate research state,
track verified vs. unverified hypotheses, or maintain a running
investigation log.  An intermediate-to-advanced researcher doing a
multi-day vulnerability research campaign has to manually track what
they have already investigated.

### What Exists Today

| Artifact | Lifetime | What It Stores | Gap |
|----------|----------|----------------|-----|
| Scratchpads | Until DONE or 24h | Task progress checklist | Deleted on completion; no findings |
| Workspace runs | 48h (sessionEnd) | Step outputs (results.json, summary.json) | Cleaned up; scattered across directories |
| Hunt plans | 48h | Hypotheses and commands | Cleaned up with workspace |
| Cache | 24h TTL | Skill script results | Invalidated; not human-readable |
| Findings store | 30 days | Structured `Finding` records from scans | Scan findings only; no hypotheses, notes, or status tracking |
| Reports | Permanent | Markdown analysis reports | Per-module, per-command; no cross-module aggregation |

The `findings_store.py` (`.claude/cache/findings.db`) partially
addresses finding persistence for scan results.  But it does NOT cover:

- **Research hypotheses** -- "I think there is a TOCTOU in appinfo.dll
  between AiCheckSecure and AiLaunchProcess" -- with status tracking
  (ACTIVE / DISPROVED / CONFIRMED)
- **Manual research notes** -- observations, dead ends, context that
  doesn't fit a structured finding format
- **Investigation status** -- which modules have been triaged, which
  functions audited, what remains unexplored
- **Cross-module correlation** -- "Finding F-001 in appinfo.dll is
  related to the COM activation path in consent.exe"
- **Finding status progression** -- UNVERIFIED -> VERIFIED -> REPORTED
  or UNVERIFIED -> FALSE_POSITIVE with reasoning

---

## Proposed Solution

### Storage: Markdown Files with an INDEX.md

Use markdown files, not SQLite.  Agents can Read markdown directly
without helper scripts.  Markdown is human-readable, diffable, and
aligns with the existing report pattern.  At the scale of a research
journal (tens to hundreds of entries), SQLite query capabilities add
complexity for no benefit.

### Directory Layout

```
.claude/research/
  INDEX.md                              # Master index: summary table, links to entries
  findings/
    F-001_appinfo_AiLaunchProcess.md    # One file per finding
    F-002_appinfo_AiCheckSecure.md
  hypotheses/
    H-001_TOCTOU_appinfo_junction.md    # One file per hypothesis
  notes/
    2026-03-09_appinfo_initial_triage.md # Chronological research notes
```

### INDEX.md Format

```markdown
# Research Journal

Last updated: 2026-03-09T14:30:00Z

## Findings (3 total: 1 verified, 1 unverified, 1 false-positive)

| ID    | Module      | Function            | Category        | Status     | Severity | File |
|-------|-------------|---------------------|-----------------|------------|----------|------|
| F-001 | appinfo.dll | AiLaunchProcess     | taint/exec      | VERIFIED   | CRITICAL | [link](findings/F-001_appinfo_AiLaunchProcess.md) |
| F-002 | appinfo.dll | AiCheckSecureAppDir | buffer_overflow | UNVERIFIED | HIGH     | [link](findings/F-002_appinfo_AiCheckSecure.md) |
| F-003 | shell32.dll | ShellExecCmdLine    | taint/exec      | FALSE_POS  | MEDIUM   | [link](findings/F-003_shell32_ShellExecCmdLine.md) |

## Hypotheses (2 total: 1 active, 1 disproved)

| ID    | Module      | Type       | Status    | File |
|-------|-------------|------------|-----------|------|
| H-001 | appinfo.dll | TOCTOU     | ACTIVE    | [link](hypotheses/H-001_TOCTOU_appinfo_junction.md) |
| H-002 | appinfo.dll | AuthBypass | DISPROVED | [link](hypotheses/H-002_auth_bypass.md) |

## Modules Investigated

- appinfo.dll: triage, scan, 2 audits, 1 hunt
- shell32.dll: triage, scan
```

### Per-Finding File Format

```markdown
# F-001: Tainted input reaches CreateProcessW via AiLaunchProcess

- **Module:** appinfo.dll
- **Function:** AiLaunchProcess (ID: 42)
- **Category:** taint / command_execution
- **Severity:** CRITICAL
- **Status:** VERIFIED
- **Source command:** /scan appinfo.dll (2026-03-09)
- **Verified by:** /audit appinfo.dll AiLaunchProcess (2026-03-09)

## Summary
Tainted parameter 1 flows to CreateProcessW lpCommandLine with no sanitization...

## Evidence
- Taint path: AiLaunchProcess.a1 -> ... -> CreateProcessW.arg2
- Guards: none on path
- Assembly verified: yes (offset 0x1234)

## Related
- Hypothesis: H-001 (TOCTOU on same function)
- Cross-module: flows into kernel32.dll (not extracted)
```

---

## Architecture

### New Helper: `helpers/research_journal.py`

Core CRUD operations for the journal:

| Function | Purpose |
|----------|---------|
| `add_finding(module, function, category, severity, summary, evidence)` | Create `F-NNN` file, update INDEX.md |
| `add_hypothesis(module, type, statement)` | Create `H-NNN` file, update INDEX.md |
| `add_note(text)` | Create dated note file |
| `update_status(entry_id, new_status, reasoning)` | Update finding/hypothesis status, rebuild index |
| `rebuild_index()` | Regenerate INDEX.md from all files in findings/ and hypotheses/ |
| `load_index()` | Parse INDEX.md for quick counts and status summary |
| `get_entry(entry_id)` | Return path to a specific finding or hypothesis file |

The helper reads/writes plain markdown.  No database, no schema
migrations.

### New Command: `/journal`

Subcommands:

| Subcommand | Purpose |
|------------|---------|
| `list` | Show all findings and hypotheses with status counts |
| `show <ID>` | Display the full finding or hypothesis file |
| `add-note` | Create a dated research note |
| `update <ID> --status <STATUS>` | Update status (VERIFIED, FALSE_POS, DISPROVED, REPORTED) |
| `summary` | Module-level investigation coverage summary |

### Relationship to findings_store.py

The research journal and `findings_store.py` serve different purposes
and coexist:

| Aspect | findings_store.py | Research Journal |
|--------|-------------------|------------------|
| Storage | SQLite (`findings.db`) | Markdown files |
| Content | Structured `Finding` records | Findings + hypotheses + notes |
| Source | Automated scan output | Automated + manual |
| Status tracking | score monotone-increasing upsert | UNVERIFIED -> VERIFIED -> REPORTED |
| Lifetime | 30 days (configurable) | Permanent (researcher-managed) |
| Consumers | `/prioritize`, `finding_merge` | Human researcher, `/hunt-plan replan` |
| Human-readable | No (SQLite) | Yes (markdown) |

Commands that produce scan findings should write to BOTH:
- `findings_store` for automated ranking (existing behavior)
- Research journal for researcher tracking (new behavior)

---

## Integration Points

### Commands That WRITE to the Journal

| Command | What It Writes | When |
|---------|----------------|------|
| `/scan` | Finding entries from verified scan output | After report synthesis |
| `/audit` | Finding entry for the audited function | After report synthesis |
| `/taint` | Finding entries for confirmed taint paths | After taint report |
| `/hunt-plan` | Hypothesis entries with ACTIVE status | When plan is created |
| `/hunt-execute` | Hypothesis updates with confidence + evidence | After each hypothesis |
| `/batch-audit` | Multiple finding entries | After batch report |
| `/memory-scan` | Finding entries from verified output | After report synthesis |
| `/ai-logical-bug-scan` | Finding entries from verified output | After report synthesis |

Each command calls `helpers.research_journal.add_finding()` or
`add_hypothesis()` as a final step -- one function call added to each
command workflow.

### Commands That READ from the Journal

| Command | What It Reads | How It Uses It |
|---------|---------------|----------------|
| `/prioritize` | INDEX.md + finding files | Include journal findings in ranking |
| `/hunt-plan replan` | INDEX.md | Gap analysis: what is investigated, what is pending |
| `/hunt-execute` | Hypothesis entries | Skip already-disproved hypotheses |
| `/scan` | INDEX.md | Flag "new" vs "known" findings in output |

### Hooks

| Hook | Change |
|------|--------|
| `sessionStart` | If INDEX.md exists, inject summary (finding counts, active hypotheses) into session context |
| `sessionEnd` | No change -- `.claude/research/` is not in cleanup targets |

---

## What NOT to Build

- **No SQLite database for the journal.** Markdown is human-readable,
  diffable, and directly consumable by agents.  The findings_store
  already provides SQLite-backed persistence for automated ranking.
- **No automatic cleanup of research data.** The journal is permanent
  until the researcher explicitly deletes entries.  This is
  intentionally different from workspace runs (48h) and cache (24h).
- **No duplicate of findings_store functionality.** The journal does
  not replace `findings_store.py` for automated scan finding
  persistence and ranking.  They serve different audiences
  (human-readable investigation log vs machine-readable ranking input).

---

## Acceptance Criteria

1. `.claude/research/INDEX.md` is created on first finding and kept
   up to date automatically
2. `/scan`, `/audit`, `/taint`, `/memory-scan`, `/ai-logical-bug-scan`,
   `/hunt-plan`, `/hunt-execute`, `/batch-audit` all write to the
   journal as a final step
3. `/journal list` shows all findings and hypotheses with status
4. `/journal show F-001` displays the full finding file
5. `/journal update F-001 --status VERIFIED` updates the finding and
   rebuilds the index
6. `sessionStart` injects journal summary into context when INDEX.md
   exists
7. `.claude/research/` survives sessionEnd cleanup
8. `research/` is in `.claude/.gitignore`
9. Coexists cleanly with `findings_store.py` -- no conflicts or
   duplicate writes that corrupt either store

---

## References

- [Persistence and Lifecycle](../persistence-and-lifecycle.md) --
  current persistence mechanisms and their lifetimes
- [findings_store.py](../../helpers/findings_store.py) -- existing
  SQLite-backed finding persistence
- [Grind Loop Protocol](../../rules/grind-loop-protocol.mdc) --
  scratchpad lifecycle
- [Workspace Pattern](../../rules/workspace-pattern.mdc) -- run
  directory lifecycle
