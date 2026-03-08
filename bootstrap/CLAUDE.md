This file is intentionally minimal.

**Authoritative project instructions live in `AGENTS.md`.**

You must:

1. Open and follow `AGENTS.md` before doing any work.
2. Treat `AGENTS.md` as the single source of truth for all operations.
3. Update `AGENTS.md` (not this file) when guidelines/architecture/standards change.

Read now: [AGENTS.md](./AGENTS.md)

---

## Install DeepExtract Runtime

When the user says **"install deepextract runtime"** (case-insensitive,
any reasonable variation), you MUST immediately execute the full bootstrap
procedure described in [AGENTS.md -- Runtime Bootstrap](./AGENTS.md#runtime-bootstrap-required).
Do NOT ask for confirmation -- just run all three steps (clone, symlink,
verify) in sequence, adapting commands to the detected OS and shell.

After successful installation, report:

- Whether `.agent/` was freshly cloned or already existed.
- Whether `.claude` symlink was created or already existed.
- Verification result (pass / fail with details).

---

## Update DeepExtract Runtime

When the user says **"update deepextract runtime"** (case-insensitive,
any reasonable variation), you MUST immediately execute the update
procedure described in [AGENTS.md -- Runtime Update](./AGENTS.md#runtime-update).
Do NOT ask for confirmation -- just run all steps (pull, verify, report)
in sequence, adapting commands to the detected OS and shell.
