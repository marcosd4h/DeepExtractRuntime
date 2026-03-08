# Finding Verification Reference

## Contents

- Gate reviews for PE binary analysis
- False positive patterns in decompiled binaries
- Bug-class verification requirements
- Evidence templates

---

## Gate Reviews

Every finding must pass through these gates. A failure at any gate
downgrades the finding toward FALSE POSITIVE unless subsequent gates
provide overriding evidence.

### Gate 1: Assembly Ground Truth

**Question**: Does the vulnerability exist in the actual instructions?

**Tools**: `verify-decompiled` (`verify_function.py --id <id> --json`)

**What to check**:
- Compare the Hex-Rays output at the finding location against assembly
- Look for decompiler artifacts that create phantom bugs:
  - Sign extension handling: Hex-Rays may show signed comparison where
    assembly uses unsigned (`JB` vs `JL`)
  - Implicit casts: Decompiler inserts casts that don't exist in assembly
  - Loop unrolling artifacts: Decompiler reconstructs a loop that was
    unrolled; the "missing check" exists in each unrolled iteration
  - Tail call optimization: Function appears to fall through when
    assembly actually jumps to another function
  - Optimized-away checks: Compiler proved a check was unnecessary and
    removed it; decompiler shows the "missing" check

**Verdict impact**: If the assembly contradicts the decompiled code at
the finding location, the finding is likely a FALSE POSITIVE from
decompiler inaccuracy.

### Gate 2: Data Flow

**Question**: Does data actually flow from attacker-controlled source
to the dangerous sink?

**Tools**: `data-flow-tracer` (`forward_trace.py`, `backward_trace.py`)

**What to check**:
- Trace forward from the alleged source parameter to the sink
- Verify every hop in the chain exists (not just the endpoints)
- Check for guards and validation functions along the path
- Look for type conversions that sanitize the data
- Verify the trace depth is sufficient to cover the full path

**Verdict impact**: If no data flow path exists between source and sink,
the finding is a FALSE POSITIVE from incomplete taint modeling.

### Gate 3: Attacker Control

**Question**: Can the attacker actually control the relevant parameter?

**Tools**: `callgraph-tracer` (`chain_analysis.py`),
`import-export-resolver` (`query_function.py`)

**What to check**:
- Trace from the vulnerable function back to module entry points
- Verify the function is reachable from an attacker-accessible entry
  (export, RPC handler, COM method, named pipe handler)
- Check how many hops separate the entry from the vulnerable function
- At each hop, verify the relevant parameter is passed through
  (not replaced with a constant or sanitized value)

**Verdict impact**: If the function is unreachable from attacker-controlled
entry points, the finding is a FALSE POSITIVE (internal-only function).

### Gate 4: Cross-Module Boundary

**Question**: Does the vulnerability survive across DLL boundaries?

**Tools**: `import-export-resolver` (`query_function.py`, `module_deps.py`),
`callgraph-tracer` (`cross_module_resolve.py`)

**What to check**:
- For cross-module findings, verify parameter mapping across the boundary
- Check if marshaling or serialization sanitizes the data
- Verify trust boundary assumptions (does the callee trust the caller?)
- Check if the exporting module validates inputs independently

**Verdict impact**: If the vulnerability requires crossing a trust
boundary that validates inputs, the finding may be a FALSE POSITIVE
or reduced severity.

### Gate 5: Devil's Advocate

**Question**: What would prevent exploitation?

**Approach**: Argue against the finding systematically.

**What to check**:
- List all compensating controls identified in the taint analysis guards
- For each guard, assess bypass difficulty (is it attacker-controllable?)
- Check module security features: ASLR, DEP, CFG, CET, stack canaries
- Consider the execution context: privilege level, sandbox, integrity level
- Ask: "If I were defending this code, what would I point to?"

**Verdict impact**: Strong compensating controls don't eliminate the
finding but affect severity. Document them in the evidence.

---

## False Positive Patterns in Decompiled PE Binaries

These patterns frequently trigger scanners but are not real vulnerabilities.
Check for each before accepting a finding.

### 1. Hex-Rays Type Recovery Errors

Hex-Rays sometimes misidentifies signed vs unsigned types, creating
phantom integer overflows. The assembly uses `JB` (unsigned below) but
the decompiler shows a signed comparison with `<`, making it appear
that negative values bypass a check.

**Detection**: Compare the branch instruction in assembly against the
decompiled comparison operator.

### 2. Library Boilerplate Triggers

WIL error handling (`wil::details::*`), CRT initialization
(`__scrt_*`, `_initterm`), STL container operations
(`std::vector::_Emplace_reallocate`), and ETW tracing all use patterns
that look dangerous (memcpy, allocation, error suppression) but are
well-tested library code.

**Detection**: Check if the function has a library tag (WIL, CRT, STL,
WRL, ETW) via `function-index`. Library-tagged functions are almost
never the source of application vulnerabilities.

### 3. Optimized-Away Code Paths

The compiler may prove that a code path is unreachable and optimize it
away. Hex-Rays reconstructs the "missing" path from debug info or
patterns, making it appear that a check is absent when the compiler
simply proved it was unnecessary.

**Detection**: Look for the code path in assembly. If the corresponding
basic block doesn't exist, the path was optimized away.

### 4. Cross-Reference Resolution Gaps

IDA may not resolve all indirect calls (virtual dispatch, function
pointers). This creates gaps in the call graph that taint analysis
interprets as "unguarded paths" when in reality the call goes through
a validation function.

**Detection**: Check if the path contains unresolved indirect calls
(`call [rax]`, `call qword ptr [rcx+offset]`). If so, the gap may
hide a guard function.

### 5. COM/WRL Template Expansions

WRL template instantiations (`RuntimeClassImpl`, `ComPtr`) generate
large amounts of boilerplate code that contains apparent reference
counting bugs, null dereferences, and type confusion. These are
template artifacts, not application bugs.

**Detection**: Check if the function name contains `Microsoft::WRL::`
or `ComPtr` or `RuntimeClass`. Template-generated code follows strict
patterns that are correct by construction.

---

## Bug-Class Verification Requirements

Each bug class has specific evidence requirements beyond the general gates.

### Memory Corruption (Buffer Overflow, Integer Overflow)

- Verify allocation size math in assembly (not just decompiled code)
- Check if the size parameter is actually attacker-controlled (Gate 3)
- Verify no safe integer arithmetic wrappers (`ULongMult`, `SizeTMult`)
- For stack overflows: verify buffer size vs copy length in assembly

### Logic Bugs (Auth Bypass, Missing Check)

- Verify branch conditions against actual register values in assembly
- Check all paths through the function (not just the flagged path)
- Verify the "missing" check isn't present in a caller or callee
- For TOCTOU: verify the timing window exists in instruction sequence

### Race Conditions (TOCTOU, Double Fetch)

- Verify the two accesses (check and use) are separate instructions
- Check if a lock is held between the accesses
- Verify the shared resource is actually accessible to another thread
- Check if the operation is atomic or uses interlocked primitives

---

## Evidence Templates

### Data Flow Evidence

```
Source: Parameter {N} of {function_name} (ID: {func_id})
Path: {source} -> {hop1} -> {hop2} -> ... -> {sink}
Sink: {dangerous_api} at {location}
Guards: {guard1} (bypassable: {yes/no}), {guard2} (bypassable: {yes/no})
Assembly verified: {yes/no} -- {assembly excerpt if relevant}
```

### Assembly Ground Truth Evidence

```
Finding location: {function_name}+{offset}
Decompiled: {decompiled code snippet}
Assembly:   {assembly instructions}
Discrepancy: {description of difference, if any}
Impact: {how this affects the finding}
```

### Attacker Control Chain

```
Entry point: {export/RPC/COM method} (type: {entry_type})
Hop 1: {caller} -> {callee} (param {N} passed as arg {M})
Hop 2: {caller} -> {callee} (param {N} passed as arg {M})
...
Target: {vulnerable_function} (param {N} is attacker-controlled)
Control quality: {full/partial/indirect}
```

### Verdict Format

```
## Verdict: {TRUE POSITIVE | FALSE POSITIVE}

**Finding**: {one-line description}
**Function**: {name} (ID: {id}, Module: {module})
**Evidence**:
- Assembly gate: {PASS/FAIL} -- {brief reason}
- Data flow gate: {PASS/FAIL} -- {brief reason}
- Attacker control gate: {PASS/FAIL} -- {brief reason}
- Cross-module gate: {PASS/FAIL/N/A} -- {brief reason}
- Devil's advocate: {compensating controls found}

**Confidence**: {HIGH/MEDIUM/LOW}
**Severity** (if TRUE POSITIVE): {CRITICAL/HIGH/MEDIUM/LOW}
```
