---
name: adversarial-reasoning
description: "Guide hypothesis-driven vulnerability research on Windows PE binaries using structured attack methodology, vulnerability class knowledge, and Windows-specific attack pattern playbooks. Use when the user asks to plan a vulnerability research campaign, generate attack hypotheses, find variants of a known bug class, validate a suspected vulnerability, reason about trust boundaries, identify privilege escalation vectors, plan a TOCTOU/race condition investigation, assess exploit feasibility, or asks for VR strategy guidance on an extracted module."
---

# Adversarial Reasoning

## Purpose

Encode the methodology that separates elite vulnerability researchers from routine auditors: hypothesis-driven investigation, attack pattern recognition, variant analysis, and structured validation. This skill replaces manual expert intuition with a repeatable framework for deciding *where to look*, *what to test*, and *how to confirm* vulnerabilities in Windows PE binaries analyzed by DeepExtractIDA.

The skill does not run analysis scripts. It guides the researcher (or the agent acting as researcher) to formulate testable hypotheses and map them to the right workspace commands and skills. Think of it as the strategic layer that sits above the tactical tools.

**Do not run analysis, write code, or execute scripts when this skill is active.** The purpose is to produce an approved research design. All implementation happens after the researcher approves.

## When to Use

- Planning a vulnerability research campaign against a module
- Generating testable hypotheses from triage/classification data
- Finding variants of a known bug class or CVE pattern
- Validating a suspected vulnerability with a structured investigation plan
- Mapping trust boundaries and privilege escalation vectors
- Deciding what to look at next after initial triage

## When NOT to Use

- Running actual taint analysis or data flow tracing -- use **taint-analysis** or **data-flow-tracer**
- Building a security dossier for a specific function -- use **security-dossier**
- Detecting specific memory corruption patterns -- use **memory-corruption-detector**
- Assessing exploitability of already-identified findings -- use **exploitability-assessment**
- Explaining what a function does (no VR needed) -- use **re-analyst** or `/explain`

## Rationalizations to Reject

| Rationalization | Why It's Wrong |
|-----------------|----------------|
| "The module looks well-written, probably not vulnerable" | Code quality is orthogonal to vulnerability. Well-written code can have logic errors in security checks, TOCTOU in file operations, and integer overflows in size calculations. |
| "Only 3 entry points, small attack surface" | A single unguarded RPC handler or COM method is enough for privilege escalation. Entry point count doesn't measure risk; entry point quality does. |
| "Mitigations are enabled, exploitation is unlikely" | Mitigations raise cost, they don't prevent vulnerabilities. CFG bypasses, ASLR info leaks, and ROP chains exist. Find the bug first, assess exploitability second. |
| "This API is commonly used, it's probably safe here" | Common APIs in uncommon contexts are the #1 source of vulnerabilities. `CreateFileW` is safe in isolation; `CreateFileW` on a user-writable path in a SYSTEM service is a symlink/junction target. |
| "No taint findings, so the function is safe" | Taint analysis has false negatives. Missing cross-module resolution, unmodeled indirect calls, and incomplete parameter tracking all cause gaps. Absence of taint findings is not evidence of safety. |

## Research Modes

Determine the mode from the user's request. Default to `campaign` when only a module name is provided.

### Mode 1: Campaign -- "Where should I look?"

Full research campaign planning against a module. The researcher has a binary but no specific hypothesis yet.

**Workflow:**

1. Check what data exists: triage output, attack surface map, classification in `.agent/cache/` or `.agent/workspace/`
2. If no triage exists, recommend `/triage <module>` first -- campaign planning requires reconnaissance
3. Ask focused questions (AskQuestion tool):
   - Threat model: local attacker? remote? network service? what privilege level?
   - Time budget: deep single-target audit or broad pattern scan?
   - Vulnerability class interest: logic bugs, memory corruption, or both?
   - Prior knowledge: known CVEs in this component? similar components with known bugs?
4. Review the module profile: entry point types, IPC surface (RPC/COM/pipes), security features, dangerous API categories
5. Apply the hypothesis generation framework (below) to produce 3-7 ranked hypotheses
6. Present the campaign plan with per-hypothesis investigation commands

### Mode 2: Hypothesis -- "Is this vulnerability real?"

The researcher has a specific hypothesis to test (e.g., "TOCTOU in the file path handler").

**Workflow:**

1. Capture the hypothesis statement and supporting evidence
2. Classify the hypothesis into a vulnerability class (see reference.md Section A)
3. Identify what would confirm vs refute the hypothesis
4. Map to the validation strategy matrix (below)
5. Produce a focused investigation plan: 3-5 commands to run, in priority order

### Mode 3: Variant -- "Are there more like this?"

The researcher knows a bug pattern and wants to find variants.

**Workflow:**

1. Capture the known pattern: CVE number, bug class, affected API, code structure
2. Decompose the pattern into searchable signals (see reference.md Section D):
   - Entry point type, data flow shape, missing check type, sink API
3. Design search queries using `/search`, `/taint`, and classification data
4. Identify candidate functions and rank by pattern match strength
5. For each candidate, produce a focused hypothesis to test

### Mode 4: Validate -- "How do I confirm this finding?"

The researcher found something suspicious and needs to confirm/refute it and plan PoC development.

**Workflow:**

1. Capture: which function, what pattern was observed, what makes it suspicious
2. Check decompiler accuracy first -- `/verify` the function to ensure the code is trustworthy
3. Apply the validation strategy matrix for the suspected vulnerability class
4. Determine: static confirmation possible? dynamic testing needed? what would a PoC look like?
5. Produce: confirmation checklist, PoC skeleton, and severity assessment guidance

### Mode 5: Surface -- "Where can an attacker get in?"

Map trust boundaries and identify the most promising attack vectors in a module.

**Workflow:**

1. Check for existing attack surface data (`/triage` or `/full-report` output)
2. Ask: attacker profile (local user, network client, sandboxed process), privilege level, known entry vectors
3. Enumerate trust boundaries: process boundaries, integrity levels, impersonation contexts, session isolation
4. For each boundary crossing, identify what security checks exist and what could go wrong
5. Rank attack vectors by the prioritization rubric and suggest investigation commands

## Hypothesis Generation Framework

Generate testable hypotheses by connecting observations to vulnerability classes. Use this framework in campaign mode and whenever the researcher needs help formulating what to look for.

### From Entry Point Types

| Entry Point Type | Hypothesis Template |
|---|---|
| RPC_HANDLER / ALPC | "Caller identity may not be verified. Check for missing `RpcImpersonateClient` or insufficient impersonation level checks." |
| COM_METHOD | "COM activation context may allow cross-privilege invocation. Check for elevation moniker susceptibility or missing `CoImpersonateClient`." |
| NAMED_PIPE_HANDLER | "Pipe server may impersonate client at too high a level. Check impersonation level and whether the pipe name is predictable/squattable." |
| SERVICE_MAIN / SERVICE_CTRL | "Service runs as SYSTEM. Any path from service entry to file/registry write with user-controlled input is a privesc candidate." |
| EXPORT_DLL (in a privileged process) | "Exported function called by a higher-privilege consumer may trust arguments without validation." |
| CALLBACK_REGISTRATION | "Callback may execute in a different security context than expected. Check what triggers it and whether the trigger is attacker-controllable." |
| WINDOW_PROC | "Window message handler may process messages from lower-integrity processes. Check for missing message filtering (`ChangeWindowMessageFilter`)." |

### From Classification Signals

| Signal | Hypothesis Template |
|---|---|
| `security` category + `process_thread` APIs | "Process creation with attacker-influenced parameters -> command injection or argument injection." |
| `file_io` category + no `security` APIs | "File operations without access checks -> symlink/junction attack or TOCTOU." |
| `registry` category + writable keys | "Registry operations on attacker-writable keys -> registry symlink or value injection." |
| `crypto` category + hardcoded strings | "Cryptographic operations with hardcoded keys/IVs -> weak crypto or key recovery." |
| `network` category + `command_execution` APIs | "Network input reaching command execution -> remote code execution." |
| `memory_alloc` + large `instruction_count` | "Complex allocation logic -> integer overflow in size calculation." |
| High cyclomatic complexity + `security` APIs | "Complex security decision logic -> logic error in access check bypass." |

### From Data Flow Patterns

| Pattern | Hypothesis Template |
|---|---|
| Parameter flows to `CreateProcessW` / `ShellExecuteW` | "Attacker-controlled argument reaches process creation -> command/argument injection." |
| Parameter flows to `CreateFileW` without path validation | "Attacker-controlled path reaches file open -> junction/symlink redirection." |
| Parameter flows to allocation size (`HeapAlloc`, `malloc`) | "Attacker-controlled size -> integer overflow -> heap corruption." |
| Parameter flows to buffer copy (`memcpy`, `RtlCopyMemory`) | "Attacker-controlled length -> buffer overflow." |
| No guards between export entry and dangerous sink | "Missing access check between attacker entry and sensitive operation -> direct exploitation." |
| Global variable written in one function, read in security check | "Shared state between functions -> TOCTOU on the global -> check bypass." |

### From Code Patterns

| Code Pattern | What to Check |
|---|---|
| `RpcImpersonateClient` without `RpcRevertToSelf` on all paths | Impersonation token leak -- SYSTEM operations execute under impersonated token |
| `CreateFileW` followed by separate read/write | TOCTOU -- file may be replaced between open and use; check for oplock opportunity |
| `if (flag & MASK)` with no validation of `flag` source | Bitmask bypass -- attacker may set unexpected flag combinations |
| Allocation `size * count` without overflow check | Integer overflow -> undersized allocation -> heap overflow |
| `goto cleanup` paths that skip security checks | Error path bypass -- alternate paths may not apply the same gates |
| Cast from `void*` to specific type without validation | Type confusion -- wrong object type may be passed through the pointer |
| `switch` on user-controlled value without `default` | Missing case handling -> uninitialized state or fall-through to wrong handler |

## Windows Security Mental Models

### Trust Boundaries

```
Kernel  ─────────────────────────────────────────────
  │
System services (SYSTEM/LOCAL SERVICE/NETWORK SERVICE)
  │
  ├── Protected processes (PPL)
  │
High-integrity processes (elevated admin)
  │
Medium-integrity processes (standard user)  ← most attacker entry
  │
Low-integrity processes (sandboxed, IE/Edge)
  │
AppContainer (UWP, sandboxed apps)
```

Every crossing is a potential vulnerability. Key questions:
- Does this function execute at a higher privilege than its caller?
- Does it validate the caller's identity before performing privileged operations?
- Can the caller influence the operation's target (file path, registry key, COM object)?

### Privilege Escalation Vectors

| Vector | Mechanism | Detection Signal |
|---|---|---|
| Service abuse | Service runs as SYSTEM, processes user input | `SERVICE_MAIN` entry + `CreateFileW`/`CreateProcessW` in call chain |
| COM elevation | Elevation moniker activates out-of-proc server | COM class factory export + `CoCreateInstance` with CLSCTX_LOCAL_SERVER |
| Token manipulation | Impersonation of privileged token | `ImpersonateLoggedOnUser` / `SetThreadToken` in call chain |
| Named pipe impersonation | Pipe server impersonates connecting client | `CreateNamedPipeW` + `ImpersonateNamedPipeClient` |
| Junction/symlink pivot | Redirect privileged file op to arbitrary target | `CreateFileW` on user-writable directory without `OPEN_EXISTING` exclusive |
| DLL hijacking | Privileged process loads from writable path | `LoadLibraryW` with relative or incomplete path |
| Registry symlink | Redirect privileged reg op to arbitrary key | `RegOpenKeyExW` on volatile subkey of writable parent |

### IPC Security Pitfalls

**RPC/ALPC:**
- Missing `RpcImpersonateClient` -- server operates with its own token, not caller's
- Impersonation at `SecurityIdentification` level when `SecurityImpersonation` is needed
- Insufficient parameter validation -- trusting client-provided lengths/offsets
- Port ACL allows connection from untrusted callers

**Named Pipes:**
- Server creates pipe before client connects -- name squattable by attacker
- `PIPE_ACCESS_DUPLEX` with `PIPE_TYPE_MESSAGE` -- full duplex may leak data
- Impersonation level too high -- server gains ability to act as client across network

**COM:**
- Missing `CoImpersonateClient` in server methods -- operates as server identity
- `CLSCTX_LOCAL_SERVER` allows cross-session activation -- session 0 isolation bypass
- Custom marshaling (IMarshal) -- attacker controls deserialization
- Elevation moniker (`Elevation:Administrator!new:`) -- auto-elevation without consent

### File System Attack Surface

| Attack | Precondition | Signal in Code |
|---|---|---|
| Directory junction | Privileged process writes to user-writable dir | `CreateFileW` on `C:\ProgramData\*` or `%TEMP%` paths |
| Mount point | Volume mount point redirects to different volume | `SetVolumeMountPointW` or `DeviceIoControl` with `IOCTL_MOUNTMGR_*` |
| Symlink | NTFS symlink redirects file open | Paths through user-writable directories |
| Oplock race | Oplock pauses privileged op for attacker swap | `CreateFileW` + separate write; no exclusive lock between them |
| Share mode race | Permissive share flags allow concurrent access | `FILE_SHARE_WRITE` or `FILE_SHARE_DELETE` on security-sensitive files |

### Memory Safety Checklist

| Risk | What to Check |
|---|---|
| Integer overflow in size | Multiplication or addition used for `HeapAlloc`/`malloc` size without overflow guard (`ULongMult`, `SizeTMult`, or manual check) |
| Stack buffer overflow | Fixed-size `WCHAR[MAX_PATH]` or `char[N]` with `wcscpy`/`strcpy` or unbounded loop copy |
| Heap UAF | Object freed in one path, pointer retained and used in another; check destructor vs caller lifetime |
| Type confusion | `void*` cast to concrete type without tag check; COM `QueryInterface` with wrong IID |
| Uninitialized read | Stack variable used in `if` before assignment on all paths; struct field gap (padding) copied to output |
| Double free | Error handler frees buffer; normal path also frees on cleanup |

## Research Prioritization Rubric

Rank hypotheses using these four dimensions. Score each 1-5 and multiply for a composite.

| Dimension | 5 (Highest) | 3 (Medium) | 1 (Lowest) |
|---|---|---|---|
| **Exploitability** | Direct attacker control, no preconditions | One precondition (race win, config state) | Multiple preconditions, unlikely alignment |
| **Impact** | Code execution or full privesc | Auth bypass or targeted info leak | DoS or minor info leak |
| **Novelty** | New vulnerability class or technique | New variant of known class | Known pattern, already patched elsewhere |
| **Feasibility** | Strong static evidence, easy to test | Moderate evidence, testable with effort | Weak evidence, requires complex setup |

**Priority = Exploitability x Impact x Novelty x Feasibility**

Focus on hypotheses scoring >= 45 first (e.g., 5x3x3x1 = 45). Hypotheses scoring < 9 can be deferred.

## Validation Strategy Matrix

| Vulnerability Class | Static Validation (commands) | Dynamic Validation Approach | PoC Skeleton |
|---|---|---|---|
| Auth/access bypass | `/audit` (dossier + verify), `/taint` (param to sink) | Call the entry point from a lower-privilege context; check if operation succeeds | Craft RPC/COM call with unprivileged token |
| TOCTOU / race | `/data-flow` (file path tracking), `/verify` (decompiler accuracy) | Create junction/oplock, trigger operation, observe race | Oplock callback + junction swap tool |
| Symlink/junction | `/search` (path strings), `/data-flow forward` (path param flow) | Create junction in target directory, trigger privileged write | `CreateMountPoint` + trigger mechanism |
| Privilege escalation | `/audit` (full dossier), `/audit --diagram` (entry to sink) | Trigger from medium-IL process, observe elevated operation | Service trigger + token check |
| Integer overflow | `/verify` (assembly size check), `/taint` (size param flow) | Provide large size values, observe allocation behavior | Craft input with boundary size values |
| Type confusion | `/reconstruct-types` (struct layout), `/verify` (cast correctness) | Pass wrong-typed object through the confused interface | COM proxy with alternate vtable |
| UAF / lifetime | `/data-flow` (object lifetime tracking), `/audit --diagram` (free path) | Trigger free, then trigger use from a different entry | Race the free/use paths |
| Stack overflow | `/verify` (buffer size vs copy), `/taint` (length param) | Provide oversized input to the vulnerable parameter | Input with length > buffer size |

## Workspace Integration

Map each hypothesis type to the exact workspace commands for investigation.

| Hypothesis Type | Primary Commands | Supporting Skills |
|---|---|---|
| Missing access check | `/audit <module> <func>`, `/taint <module> <func>` | security-dossier, taint-analysis |
| TOCTOU / file race | `/data-flow forward <module> <func>`, `/audit <module> <func>` | data-flow-tracer, security-dossier |
| Symlink/junction attack | `/search <module> CreateFileW`, `/data-flow forward <module> <func>` | data-flow-tracer, classify-functions |
| Integer overflow | `/verify <module> <func>`, `/taint <module> <func>` | verify-decompiled, taint-analysis |
| COM privilege escalation | `/reconstruct-types <module> <class>`, `/audit <module> <export> --diagram` | com-interface-reconstruction, callgraph-tracer |
| Type confusion | `/verify <module> <func>`, `/reconstruct-types <module> <class>` | verify-decompiled, reconstruct-types |
| UAF / lifetime error | `/data-flow forward <module> <func>`, `/audit <module> <export> --diagram` | data-flow-tracer, callgraph-tracer |
| Variant of known CVE | `/search <module> <api_pattern>`, `/triage <module>` | classify-functions, map-attack-surface |
| Named pipe impersonation | `/search <module> CreateNamedPipe`, `/taint <module> <handler>` | taint-analysis, map-attack-surface |
| RPC auth bypass | `/search <module> RpcImpersonate`, `/audit <module> <handler>` | security-dossier, taint-analysis |

## Integration with Other Skills

| Task | Skill |
|---|---|
| Gather function security context before hypothesis testing | security-dossier |
| Trace attacker input to dangerous sinks | taint-analysis |
| Track data flow for TOCTOU/race analysis | data-flow-tracer |
| Map entry points and rank attack value | map-attack-surface |
| Classify functions to find hypothesis targets | classify-functions |
| Trace call chains from entry points | callgraph-tracer |
| Verify decompiler accuracy before trusting code | verify-decompiled |
| Reconstruct types for type confusion analysis | reconstruct-types |
| Reconstruct COM interfaces for COM attack analysis | com-interface-reconstruction |
| Lift code for detailed manual review | code-lifting / batch-lift |

## Additional Resources

- [reference.md](reference.md) -- Vulnerability class encyclopedia, Windows attack patterns, research playbooks, variant analysis methodology, and hypothesis templates
- [security-dossier](../security-dossier/SKILL.md) -- Function-level security context gathering
- [taint-analysis](../taint-analysis/SKILL.md) -- Attacker input to dangerous sink tracing
- [map-attack-surface](../map-attack-surface/SKILL.md) -- Entry point discovery and ranking
- [data_format_reference.md](../../docs/data_format_reference.md) -- DB schema for direct queries
