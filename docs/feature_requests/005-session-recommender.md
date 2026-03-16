# FR-005: Session-Level "What Should I Look At Next" Recommender

**Status:** Proposed
**Priority:** Medium
**Category:** Workflow / Research Guidance
**Author:** Runtime Assessment Review
**Date:** 2026-03-16
**Depends on:** FR-003 (Persistent Research Journal) -- optional but enhances cross-session awareness

---

## Problem Statement

Commands produce "Recommended Next Steps" in their output, but there is
no session-level recommender that tracks what has already been analyzed,
what remains, and what the highest-value unexplored areas are.

Each command independently generates recommendations based only on its
own output.  No command checks what the researcher has already done.

| Command | How It Recommends | Limitation |
|---------|-------------------|------------|
| `/triage` | Lists top functions by interest score | Unaware of prior audits |
| `/audit` | Suggests related functions by danger category | Unaware of prior scans |
| `/scan` | Lists `/audit` and `/taint` for top findings | Unaware of already-audited findings |
| `/hunt-plan` | Generates hypothesis commands | Unaware of completed investigations |
| `/hunt-execute` | Follow-up suggestions per hypothesis | Unaware of other hypotheses |
| `/prioritize` | Ranks findings cross-module | Report-oriented; no "already done" subtraction |

There is no `/next` command that says "based on everything you have
done so far, here is the single most valuable thing to investigate."

### What Tracks "Already Analyzed" Today

Nothing, at the session level:

- **Cache** (`.agent/cache/`): Tells you what data was computed, not
  what the researcher has reviewed.
- **Workspace runs** (`.agent/workspace/`): Past run directories
  indicate prior commands but there is no aggregated "analyzed set."
- **Findings store** (`.agent/cache/findings.db`): Stores scan findings
  with 30-day retention but does not track investigation status.
- **Session context** (`sessionStart` hook): Injects module counts
  and cached result summaries.  Does not track session activity.

---

## Proposed Solution

### `/next` Command

A lightweight command that answers "what should I do next":

```
/next                    # recommend based on all available data
/next appinfo.dll        # recommend within a specific module
```

### How It Works

1. **Load the "done set"** -- what has already been analyzed:
   - Research journal INDEX.md (if FR-003 is implemented)
   - Fallback: scan workspace run directories for completed steps
   - Fallback: check cache entries for modules with triage/scan results

2. **Load the "candidate set"** -- what could be analyzed next:
   - Ranked entry points from `discover_entrypoints` cache
   - Top interesting functions from `classify_functions` cache
   - Unresolved hypotheses from research journal (if available)
   - Untriaged modules (modules with DBs but no triage cache)

3. **Subtract done from candidates** -- remove functions already audited,
   modules already scanned, hypotheses already resolved

4. **Rank remaining candidates** using existing signals:
   - Entry point attack_score from `rank_entrypoints`
   - Interest score from `classify_functions`
   - Unresolved hypothesis priority from research journal
   - Module size and complexity from `module_profile.json`

5. **Present top 3-5 recommendations** with concrete commands:

```
## What to Do Next

Based on your work so far (3 functions audited, 1 module scanned):

| # | Module      | Target                | Why                                    | Command |
|---|-------------|-----------------------|----------------------------------------|---------|
| 1 | appinfo.dll | RAiGetTokenForService | CRITICAL scan finding, not yet audited | `/audit appinfo.dll RAiGetTokenForService` |
| 2 | appinfo.dll | AiCheckLUA            | HIGH entry point, unexplored           | `/taint appinfo.dll AiCheckLUA` |
| 3 | shell32.dll | (not triaged)         | 2nd largest module, no analysis yet    | `/triage shell32.dll` |
| 4 | appinfo.dll | H-001 TOCTOU          | Active hypothesis, unresolved          | `/hunt-execute appinfo.dll` |
```

### Integration with Existing Commands

After `/triage`, `/scan`, `/audit`, and `/hunt-execute` complete, they
could optionally invoke the recommender logic and append a session-aware
"What to do next" section that subtracts already-completed work.  This
would replace the current per-command fire-and-forget "Recommended Next
Steps" with a unified recommender.

This integration is optional and additive -- existing commands continue
to work unchanged.  The `/next` command is the primary entry point.

---

## Architecture

### Data Sources for Recommendation

| Source | What It Provides | How to Access |
|--------|------------------|---------------|
| Entry point rankings | Ranked attack surface candidates | `cache/<module>/discover_entrypoints.json` |
| Function classification | Interest scores for all functions | `cache/<module>/triage_summary.json` |
| Findings store | Confirmed scan findings with severity | `helpers.findings_store.load_findings()` |
| Research journal (FR-003) | Investigated functions, active hypotheses | `.agent/research/INDEX.md` |
| Module profiles | Module size, noise ratio, technology flags | `extracted_code/<module>/module_profile.json` |
| Workspace runs | Which commands were run for which modules | `.agent/workspace/*/manifest.json` |

### Recommendation Ranking

The recommender does NOT introduce any new scoring.  It uses existing
ordinal sort keys to order candidates:

1. **Findings with high LLM-assigned severity not yet audited** --
   sort by `Finding.score` (ordinal sort key from LLM severity)
2. **Entry points with high attack_score not yet investigated** --
   sort by `attack_score` from `rank_entrypoints`
3. **Untriaged modules** -- sort by function count (larger = more
   to investigate)
4. **Active hypotheses** -- sort by hypothesis priority from research
   journal

The recommender combines these into a unified list, deduplicates by
function, and presents the top N.

---

## Integration Points

| File | Change |
|------|--------|
| `commands/next.md` | New command definition |
| `commands/registry.json` | Add `next` entry |
| `commands/README.md` | Add `/next` to command table |
| `helpers/command_validation.py` | Add `next` to `_COMMAND_REQUIREMENTS` (optional module) |

### Optional Integrations (Later)

| File | Change |
|------|--------|
| `commands/triage.md` | Append `/next` output after triage |
| `commands/scan.md` | Append `/next` output after scan |
| `commands/audit.md` | Append `/next` output after audit |

---

## What NOT to Build

- **No new scoring.** The recommender uses existing ordinal sort keys
  (LLM-assigned severity, attack_score, interest_score).  It subtracts
  already-done work and presents the remainder sorted by these existing
  signals.
- **No session state database.** The "done set" is derived from
  existing artifacts (cache, workspace runs, journal).  No new
  persistence layer.
- **No automatic invocation.** `/next` is explicitly invoked by the
  researcher.  Commands do not auto-append recommendations unless
  the researcher opts in.

---

## Acceptance Criteria

1. `/next` produces a ranked list of 3-5 unexplored high-value targets
2. Already-audited functions are excluded from recommendations
3. Recommendations include concrete commands the researcher can run
4. Works without the research journal (falls back to cache and
   workspace data)
5. Enhanced when research journal exists (cross-session awareness)
6. `/next appinfo.dll` scopes recommendations to a single module
7. `/next` with no prior analysis suggests `/triage` on the largest
   untriaged module

---

## References

- [FR-003: Persistent Research Journal](003-persistent-research-journal.md) --
  provides the "done set" for cross-session awareness
- [Prioritize Command](../../commands/prioritize.md) -- existing
  cross-module finding ranking
- [Command Depth Spectrum](../command_depth_spectrum.md) -- how
  commands relate to each other
