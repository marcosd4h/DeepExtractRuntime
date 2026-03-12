# Adversarial Reasoning

Hypothesis-driven vulnerability research methodology for Windows PE binaries.
Encodes the strategic layer that decides *where to look*, *what to test*, and
*how to confirm* vulnerabilities -- then maps each decision to the right
workspace commands and skills.

**This is a documentation-only skill.** It has no scripts. It provides
structured methodology, hypothesis templates, attack pattern playbooks, and
validation strategies that guide the agent (or researcher) through VR workflows.

## When to Use

- Planning a vulnerability research campaign against a module
- Generating attack hypotheses from triage or classification data
- Finding variants of a known bug class (CVE variant analysis)
- Validating a suspected vulnerability (confirmation/refutation checklist)
- Reasoning about trust boundaries and privilege escalation vectors
- Assessing exploit feasibility and PoC planning

## Research Modes

| Mode | Trigger | Output |
|------|---------|--------|
| **Campaign** | "Where should I look?" / module name only | 3-7 ranked hypotheses with investigation commands |
| **Hypothesis** | "Is this vulnerability real?" / specific suspicion | Focused investigation plan (3-5 commands) |
| **Variant** | "Are there more like this?" / known CVE or pattern | Search queries + candidate function list |
| **Validate** | "How do I confirm this finding?" / suspicious code | Confirmation checklist + PoC skeleton |
| **Surface** | "Where can an attacker get in?" / trust boundary mapping | Ranked attack vectors with boundary analysis |

## Quick Start

### Campaign Mode (most common)

1. Ensure triage data exists: run `/triage <module>` if not already cached
2. Activate this skill (the agent reads the SKILL.md)
3. Answer focusing questions (threat model, time budget, vuln class interest)
4. Receive 3-7 ranked hypotheses with per-hypothesis investigation commands

### Hypothesis Mode

1. State your hypothesis: "I suspect TOCTOU in the path handler of AiLaunchProcess"
2. The skill classifies it, identifies confirmation/refutation criteria
3. Receive a focused plan: `/verify-decompiler` the decompiled code, `/taint` the
   file path parameter, `/data-flow forward` to trace the path usage

### Variant Mode

1. Provide the known pattern: CVE number, bug class, affected API, code shape
2. The skill decomposes it into searchable signals
3. Receive search queries (`/search`, `/taint`) and ranked candidate functions

## Key Frameworks

### Hypothesis Generation

Generates testable hypotheses by connecting three signal sources:

- **Entry point types** (RPC handlers, COM methods, named pipes, exports)
  map to hypothesis templates about caller identity, impersonation, and
  parameter trust.

- **Classification signals** (security + process APIs, file I/O without
  security checks, crypto + hardcoded strings) map to vulnerability class
  hypotheses.

- **Data flow patterns** (parameter flows to CreateProcessW, allocation
  sizes, unguarded sinks) map to specific exploitation hypotheses.

See [SKILL.md](SKILL.md) for the full template tables.

### Prioritization Rubric

Rank hypotheses on four dimensions (score 1-5 each, multiply for composite):

| Dimension | 5 (Highest) | 1 (Lowest) |
|-----------|-------------|------------|
| Exploitability | Direct attacker control, no preconditions | Multiple unlikely preconditions |
| Impact | Code execution or full privesc | DoS or minor info leak |
| Novelty | New vulnerability class | Known pattern, already patched |
| Feasibility | Strong static evidence | Weak evidence, complex setup |

Focus on hypotheses scoring >= 45 first. Defer those below 9.

### Validation Strategy Matrix

Maps each vulnerability class to static validation commands and dynamic
testing approaches. Covered classes: auth/access bypass, TOCTOU/race,
symlink/junction, privilege escalation, integer overflow, type confusion,
UAF/lifetime, stack overflow.

See [SKILL.md](SKILL.md) for the full matrix.

## Reference Material

The [reference.md](reference.md) companion document (951 lines) contains:

- **Section A** -- Vulnerability class encyclopedia (memory corruption,
  logic bugs, race conditions, type confusion, crypto weaknesses)
- **Section B** -- Windows-specific attack patterns (IPC security pitfalls,
  file system attacks, privilege escalation vectors)
- **Section C** -- Research playbooks (step-by-step investigation guides
  per vulnerability class)
- **Section D** -- Variant analysis methodology (decomposing known patterns
  into searchable signals)
- **Section E** -- Hypothesis templates (copy-paste templates for common
  vulnerability scenarios)

## Workspace Integration

| Hypothesis Type | Primary Commands | Supporting Skills |
|---|---|---|
| Missing access check | `/audit`, `/taint` | security-dossier, taint-analysis |
| TOCTOU / file race | `/data-flow forward`, `/audit` | data-flow-tracer, security-dossier |
| Symlink/junction | `/search CreateFileW`, `/data-flow forward` | data-flow-tracer, classify-functions |
| Integer overflow | `/verify-decompiler`, `/taint` | verify-decompiled, taint-analysis |
| COM privilege escalation | `/reconstruct-types`, `/audit --diagram` | com-interface-reconstruction, callgraph-tracer |
| Named pipe impersonation | `/search CreateNamedPipe`, `/taint` | taint-analysis, map-attack-surface |
| RPC auth bypass | `/search RpcImpersonate`, `/audit` | security-dossier, taint-analysis |

## Files

```
adversarial-reasoning/
├── SKILL.md       # Agent skill instructions -- methodology, frameworks, matrices
├── reference.md   # Vulnerability class encyclopedia and attack pattern playbooks
└── README.md      # This file
```

## Related Skills

- [brainstorming](../brainstorming/SKILL.md) -- General collaborative design dialogue (broader scope than VR)
- [security-dossier](../security-dossier/SKILL.md) -- Function-level security context gathering
- [taint-analysis](../taint-analysis/SKILL.md) -- Attacker input to dangerous sink tracing
- [map-attack-surface](../map-attack-surface/SKILL.md) -- Entry point discovery and risk ranking
- [data-flow-tracer](../data-flow-tracer/SKILL.md) -- Parameter and data flow tracing
- [verify-decompiled](../verify-decompiled/SKILL.md) -- Decompiler accuracy verification
