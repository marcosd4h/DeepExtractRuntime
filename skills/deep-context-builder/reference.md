# Deep Context Builder Reference

## Contents

- Per-function microstructure checklist
- IDA/Hex-Rays artifact recognition
- Completeness checklist
- Worked example outline
- Output requirements template

---

## Per-Function Microstructure Checklist

For every non-trivial function, complete each section before moving to
the next function.

### 1. Purpose (2-3 sentences minimum)

Why the function exists and its role in the system. State what it does,
not what you think it might do.

### 2. Inputs and Assumptions

- **Parameters**: Each parameter with its type, purpose, and constraints
- **Implicit inputs**: `this` pointer, global state, TLS, environment
- **Preconditions**: What must be true before calling this function
- **Trust assumptions**: Which inputs are trusted vs attacker-controlled

### 3. Outputs and Effects

- **Return value**: Type, meaning, error codes (HRESULT, NTSTATUS, BOOL)
- **State writes**: Globals modified, heap allocations, registry writes
- **External interactions**: API calls, IPC, file I/O, network
- **Events/callbacks**: Anything triggered as a side effect
- **Postconditions**: What is guaranteed to be true after return

### 4. Block-by-Block Analysis

For each logical block in the decompiled code:

| Question | Answer |
|----------|--------|
| What does this block do? | (concrete description) |
| Why does it appear here? | (ordering logic, dependency on prior blocks) |
| What assumptions does it rely on? | (input constraints, state expectations) |
| What invariants does it establish? | (guarantees for subsequent blocks) |
| What later logic depends on it? | (which blocks or callees need its output) |

Apply at least one of:
- **First Principles**: Strip away the decompiler artifacts. What is the fundamental operation?
- **5 Whys**: Why does this block exist? Why this approach? Why this ordering?
- **5 Hows**: How does data reach this point? How is the result consumed?

---

## IDA/Hex-Rays Artifact Recognition

### IDA Naming Conventions

| Pattern | Meaning |
|---------|---------|
| `sub_XXXXX` | Unnamed function at address XXXXX |
| `loc_XXXXX` | Code label (branch target) |
| `dword_XXXXX` | 4-byte global variable |
| `off_XXXXX` | Pointer/offset global |
| `unk_XXXXX` | Unknown-type global |
| `a1`, `a2`, ... | Function parameters (positional) |
| `v1`, `v2`, ... | Local variables (arbitrary naming) |

### Hex-Rays Output Patterns

| Pattern | Interpretation |
|---------|---------------|
| `HIDWORD(x)` / `LODWORD(x)` | High/low 32 bits of a 64-bit value |
| `BYTE1(x)` / `BYTE2(x)` | Specific byte extraction from a multi-byte value |
| `(unsigned __int64)` casts | Often sign extension -- check assembly |
| `__fastcall` with `this` as first param | Recovered C++ member function |
| `(**(void (__fastcall **)(...))(*(QWORD*)obj + offset))(...)` | Virtual function call through vtable |
| `_DWORD` / `_QWORD` / `_BYTE` casts | IDA's type-recovery placeholders |

### Windows-Specific Patterns

| Pattern | Context |
|---------|---------|
| `NTSTATUS` return + `if (result < 0)` | NT status error checking |
| `HRESULT` return + `if (FAILED(hr))` | COM/Win32 error checking |
| `RpcImpersonateClient` ... `RpcRevertToSelf` | RPC impersonation bracket |
| `CoImpersonateClient` ... `CoRevertToSelf` | COM impersonation bracket |
| `EnterCriticalSection` ... `LeaveCriticalSection` | Lock pair (check all exit paths) |
| `AcquireSRWLock*` ... `ReleaseSRWLock*` | Slim reader/writer lock pair |

### COM/WRL Template Patterns

| Pattern | Meaning |
|---------|---------|
| `AddRef` / `Release` | Reference counting (check for leaks on error paths) |
| `QueryInterface` with IID comparison chain | COM interface resolution |
| `Microsoft::WRL::ComPtr` | Smart pointer (implicit Release in destructor) |
| `Microsoft::WRL::RuntimeClassImpl` | WRL class template expansion |
| `weak_ref` / `resolve_weak_ref` | Weak reference pattern |

---

## Completeness Checklist

Before concluding analysis of a function, verify:

### Structural Completeness

- [ ] Purpose section present (2-3 sentences minimum)
- [ ] All parameters documented with types and constraints
- [ ] All implicit inputs identified (globals, TLS, environment)
- [ ] Return value and error codes documented
- [ ] All state modifications listed
- [ ] Every logical block analyzed (no blocks skipped without justification)

### Content Depth

- [ ] At least 3 invariants identified
- [ ] At least 5 assumptions documented
- [ ] At least 3 risk considerations noted
- [ ] At least 1 First Principles application
- [ ] At least 3 combined 5 Whys / 5 Hows applications
- [ ] IDA artifacts recognized and interpreted (not taken at face value)

### Continuity and Integration

- [ ] Cross-function dependencies documented (callee assumptions propagated)
- [ ] External call outcomes modeled (success, failure, adversarial)
- [ ] Invariants from prior functions referenced where relevant
- [ ] New insights connected to the global model

### Anti-Hallucination

- [ ] No vague statements ("it probably...", "this might...")
- [ ] Uncertainty expressed as "unclear; need to inspect X"
- [ ] Evidence-based claims only (line references, assembly excerpts)
- [ ] Earlier assumptions corrected when contradicted by new evidence

---

## Output Requirements Template

When performing deep context analysis, structure output as follows.
This is a flexible template -- adapt sections based on what the
analysis reveals, but maintain the core structure.

```
## Function: {name} (ID: {id})

### Purpose
{2-3 sentences describing what the function does and why it exists}

### Inputs and Assumptions
- Parameter 1 ({type}): {purpose} -- Assumption: {constraint}
- Parameter 2 ({type}): {purpose} -- Assumption: {constraint}
- Implicit: {globals, this, TLS}
- Trust boundary: {which inputs are attacker-controlled}

### Outputs and Effects
- Returns: {type} -- {meaning, error codes}
- Modifies: {globals, heap, registry, files}
- Calls: {significant API calls with security relevance}

### Block-by-Block Analysis

#### Block 1: {description} (lines {start}-{end})
- What: {concrete description}
- Why here: {ordering logic}
- Assumes: {assumptions}
- Establishes: {invariants}
- First Principles: {fundamental operation}

#### Block 2: {description} (lines {start}-{end})
...

### Cross-Function Dependencies
- Calls {callee}: passes {param} as arg {N}; callee assumes {constraint}
- Called by {caller}: receives {param} which originates from {source}

### Invariants
1. {invariant 1}
2. {invariant 2}
3. {invariant 3}

### Assumptions
1. {assumption 1}
2. {assumption 2}
...

### Risk Considerations
1. {risk 1}: if {assumption} is violated, {consequence}
2. {risk 2}: if {assumption} is violated, {consequence}
3. {risk 3}: if {assumption} is violated, {consequence}

### Unresolved Questions
- {question 1}: need to inspect {what}
- {question 2}: need to check {what}
```
