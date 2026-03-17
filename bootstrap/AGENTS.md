# DeepExtract AI Analysis Runtime

> **MANDATORY SETUP -- READ THIS FIRST AND ACT IMMEDIATELY**
>
> This workspace REQUIRES the DeepExtract Agent Analysis Runtime (`.agent/`).
> You MUST check whether `.agent/` exists and, if it does not, install it
> NOW -- before responding to the user, before exploring files, before doing
> any other work. **No analysis task can proceed without the runtime.**
>
> If `.agent/` already exists and contains `AGENTS.md`, skip to
> [Master Instructions](#master-instructions).

---

## Runtime Bootstrap (REQUIRED)

**STOP.** Before continuing, run the checks below. If any check fails,
execute the corresponding fix. Do NOT skip this section. Do NOT defer it.
Do NOT ask the user whether to proceed -- just do it.

### Step 1 -- Clone the runtime

Check whether `.agent/` exists. If it does NOT, clone it immediately:

**Windows (cmd / PowerShell):**

```cmd
if not exist .agent git clone https://github.com/marcosd4h/DeepExtractRuntime .agent
```

**bash (macOS / Linux / Windows Git Bash):**

```bash
[ ! -d .agent ] && git clone https://github.com/marcosd4h/DeepExtractRuntime .agent
```

### Step 2 -- Create `.claude` symlink

Claude Code discovers skills, agents, and hooks from `.claude/`. A directory
symlink pointing to `.agent` makes the runtime visible without duplicating files.

Check whether the symlink exists. If it does NOT, create it:

**Windows (cmd -- requires Developer Mode or elevated prompt):**

```cmd
if not exist .claude mklink /D .claude .agent
```

**Windows (bash / Git Bash -- requires Developer Mode or elevated prompt):**

> `mklink` is a `cmd.exe` built-in and is **NOT** available directly in bash.
> You MUST invoke it through `cmd`. Use double-slash `//c` in Git Bash
> because a single `/c` is interpreted as a Unix-style path.

```bash
cmd //c "mklink /D .claude .agent"
```

**bash (macOS / Linux):**

```bash
[ ! -L .claude ] && ln -s .agent .claude
```

### Step 3 -- Install Cursor integration

Cursor discovers project hooks from `.cursor/hooks.json` and project rules
from `.cursor/rules/`. Create the `.cursor` directory, copy the hooks
configuration, and copy the rules. Rules must use the `.mdc` extension for
Cursor to process their YAML frontmatter (`alwaysApply`, `description`,
`globs`); the canonical `.md` sources in `.agent/rules/` are renamed during
the copy.

**Windows (cmd):**

```cmd
if not exist .cursor mkdir .cursor
copy /Y .agent\hooks.json .cursor\hooks.json
if not exist .cursor\rules mkdir .cursor\rules
for %%f in (.agent\rules\*.md) do copy /Y "%%f" ".cursor\rules\%%~nf.mdc"
```

**Windows (bash / Git Bash):**

```bash
mkdir -p .cursor .cursor/rules
cp .agent/hooks.json .cursor/hooks.json
for f in .agent/rules/*.md; do cp "$f" ".cursor/rules/$(basename "$f" .md).mdc"; done
```

**bash (macOS / Linux):**

```bash
mkdir -p .cursor .cursor/rules
cp .agent/hooks.json .cursor/hooks.json
for f in .agent/rules/*.md; do cp "$f" ".cursor/rules/$(basename "$f" .md).mdc"; done
```

### Step 4 -- Verify

ALL of the following MUST be true before you proceed:

- `.agent/AGENTS.md` exists and is readable.
- `.claude` is a symlink (or junction on Windows) pointing to `.agent`.
- `.agent/skills/`, `.agent/commands/`, `.agent/agents/`, `.agent/helpers/`, `.agent/hooks/`, and `.agent/config/` directories exist.
- `.cursor/hooks.json` exists and is readable.
- `.cursor/rules/` is a directory containing `.mdc` copies of every `.agent/rules/*.md` file.

If any check fails, remove the partial installation and re-run from Step 1:

```bash
rm -rf .agent .claude .cursor
```

**Do NOT continue past this point until verification succeeds.**

---

## Runtime Update

When the user says **"update deepextract runtime"** (case-insensitive,
any reasonable variation), or when you need to pull the latest runtime,
run the steps below. Do NOT ask for confirmation -- just do it.

### Step 1 -- Pull latest changes

Navigate into `.agent/` and pull. If local changes conflict, stash first.

```bash
cd .agent && git pull
```

If the pull fails due to local modifications:

```bash
cd .agent && git stash && git pull && git stash pop
```

If the stash pop produces conflicts, inform the user and show which files
conflict so they can resolve manually.

After a successful pull, re-copy hooks and rules for Cursor:

```bash
cp .agent/hooks.json .cursor/hooks.json
for f in .agent/rules/*.md; do cp "$f" ".cursor/rules/$(basename "$f" .md).mdc"; done
```

### Step 2 -- Verify

Re-run the same verification from the bootstrap section:

- `.agent/AGENTS.md` exists and is readable.
- `.claude` is a symlink (or junction on Windows) pointing to `.agent`.
- `.agent/skills/`, `.agent/commands/`, `.agent/agents/`, `.agent/helpers/`, `.agent/hooks/`, and `.agent/config/` directories exist.
- `.cursor/hooks.json` exists and is readable.
- `.cursor/rules/` is a directory containing `.mdc` copies of every `.agent/rules/*.md` file.

### Step 3 -- Report

After a successful update, report:

- Previous and new commit hashes (e.g. `ac05b16` -> `8d2bda3`).
- Summary of what changed (new/updated skills, agents, helpers, commands).
- Whether local changes were stashed and re-applied cleanly.
- Verification result (pass / fail with details).

---

## Master Instructions

Now that the runtime is installed, **read and follow `.agent/AGENTS.md`** as
the authoritative instructions for this workspace. Treat every directive in
that file as if it appeared here.

`.agent/AGENTS.md` contains:

- Quick rules and conventions for all analysis work
- Workflow principles (plan-first, subagent usage, verification, elegance)
- Getting-started workflow and slash command catalog (`/triage`, `/explain`, `/audit`, ...)
- Architecture reference and key directories table
- Progressive-disclosure documentation index ("When You Need To..." lookup table)
- Helper library developer reference (30+ modules, functional areas, import patterns)
- Conventions: error handling, JSON output, caching, workspace pattern, grind loop, hooks, registry maintenance
- Testing instructions

**Do not duplicate or summarize those instructions here.** Always defer to
`.agent/AGENTS.md` for the complete and up-to-date reference.

---

## Project Rules

Project rules live in `.agent/rules/` as `.md` files with optional YAML
frontmatter. They encode workspace conventions (error handling, JSON output,
script invocation, caching, etc.) that all AI coding agents should follow.

**Cursor** requires rules in `.cursor/rules/` with the `.mdc` extension for
frontmatter processing (`alwaysApply`, `description`, `globs`). The bootstrap
copies each `.agent/rules/*.md` file to `.cursor/rules/*.mdc`. After adding
or editing rules in `.agent/rules/`, re-run the copy step from Step 3 or
the Runtime Update procedure to sync.

**Claude Code** reads rules from `.claude/rules/` (a symlink chain:
`.claude` -> `.agent`, so `.claude/rules/` resolves to `.agent/rules/`).
Claude Code handles `.md` files with frontmatter natively.

**Other environments** (OpenAI Codex, custom agents, or any tool that does
not read `.cursor/rules/` or `.claude/rules/`): read project rules directly
from `.agent/rules/`. Each `.md` file is self-contained and can be loaded
as additional context or appended to the agent's system prompt.

---

## Workspace Data

This workspace contains IDA Pro extraction outputs for Windows PE binaries.
The DeepExtract Agent Analysis Runtime provides AI-driven analysis capabilities
(slash commands, specialized agents, skills, and shared helpers) on top of
these extraction outputs.

DeepExtractIDA extraction layout:

```
AGENTS.md                Bootstrap instructions (this file)
CLAUDE.md                Pointer to AGENTS.md for Claude Code
extraction_report.json   Batch extraction provenance and status

extracted_code/          Decompiled C++ source, JSON metadata per module
  <module>/              e.g. appinfo_dll/, cmd_exe/, coredpus_dll/
    *.cpp                Grouped decompiled functions
    file_info.json       PE metadata and analysis report
    file_info.md         Human-readable PE metadata summary
    function_index.json  Function-to-file index
    module_profile.json  Pre-computed module fingerprint

extracted_dbs/           Per-binary SQLite analysis databases
  <module>_<hash>.db     Individual analysis database (read-only)
  analyzed_files.db      Tracking database (module index)

idb_cache/               IDA database files (.i64) for re-analysis
logs/                    IDA analysis logs and batch extractor log
```

All extraction databases are **read-only**. Never write to them.
