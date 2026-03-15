# IDA Hex-Rays Decompiler Pitfalls

When analyzing IDA Pro decompiled C/C++ output for memory corruption
vulnerabilities, be aware of these common misreadings. The decompiled code
is a **reconstruction**, not the original source. **Assembly is ground truth.**

When any finding depends on a specific code behavior, verify it against the
assembly before reporting.

---

## 1. Sign/Zero Extension Mismatches

Hex-Rays may show an unsigned cast `(unsigned int)v5` when the assembly
actually performs sign extension (`movsxd rax, ecx`). This matters for size
comparisons: a signed-extended negative value becomes a very large unsigned
value, which changes whether an overflow is exploitable.

**What to check:** Look for `movsxd` (sign-extend 32-to-64) vs `mov eax, ecx`
(implicit zero-extend) in the assembly. If the decompiled code shows unsigned
but assembly does sign extension, the attacker may be able to pass negative
values that become large sizes.

---

## 2. Stack Variable Aliasing

Two "different" local variables in the decompiled output may actually occupy
the same stack slot. Hex-Rays creates separate variable names when it detects
non-overlapping live ranges, but this is a heuristic. If both variables
are live simultaneously (e.g. across a function call), the decompiler may show
incorrect behavior.

**What to check:** If a vulnerability depends on two variables being
independent (e.g. one is the allocation size and another is the copy size),
verify in the assembly that they use different stack offsets
(`[rsp+XX]` vs `[rsp+YY]`).

---

## 3. Parameter Count and Calling Convention Errors

IDA may misidentify the number of parameters or the calling convention,
especially for:

- Functions called only via indirect calls (vtable dispatches)
- Variadic functions (`printf`-family)
- Functions with unusual register usage

This can cause the decompiler to assign the wrong expressions to parameter
positions, making it look like a tainted value reaches a dangerous argument
when it actually goes to a different parameter.

**What to check:** Count the `mov rcx/rdx/r8/r9` or stack push instructions
before the `call`. Compare with what Hex-Rays shows as the argument list.

---

## 4. Pointer Aliasing Invisibility

Two pointer variables that point to the same heap object appear completely
independent in decompiled code. Hex-Rays does not perform alias analysis.
This means:

- A free through one alias followed by use through another alias will NOT
  look like a use-after-free in the decompiled output.
- A write through one alias followed by a read through another will NOT show
  the data dependency.

**What to check:** If you suspect aliasing (e.g. two variables assigned from
the same function call, or one assigned from a struct field that another
also references), trace the pointer values through the assembly to confirm
whether they hold the same address.

---

## 5. Indirect Calls and Vtable Dispatches

Expressions like `(*(void (__fastcall **)(__int64, __int64))(*(_QWORD *)v5 + 0x18))(v5, v8)`
are vtable calls. The pattern is:

1. `*(_QWORD *)v5` -- read the vtable pointer from offset 0 of the object
2. `+ 0x18` -- index into the vtable (0x18 / 8 = slot 3)
3. Outer dereference + call -- invoke the method

The decompiler does NOT resolve which concrete function this calls. The
actual target depends on the runtime type of the object. Check the
`vtable_contexts` field in the function's extracted data for IDA's resolved
vtable assignments.

---

## 6. Switch Statement Misrendering

Complex switch statements, especially those compiled into jump tables, may
be misrendered by Hex-Rays. Common issues:

- Missing cases (the decompiler merges cases or drops fall-through paths)
- Incorrect case values (when the compiler uses arithmetic on the switch
  variable before the table lookup)
- Default case handling (may not match actual assembly behavior)

**What to check:** Look for `jmp [reg*8 + table_addr]` patterns in the
assembly. The jump table entries show the real case targets.

---

## 7. LOBYTE/HIBYTE/LOWORD/HIWORD Macros

These are IDA artifacts representing partial register or variable access:

- `LOBYTE(v5)` = low 8 bits of v5 (assembly: `al` or `[rsp+X]`)
- `HIBYTE(v5)` = bits 8-15 of v5 (assembly: `ah` or `[rsp+X+1]`)
- `LOWORD(v5)` = low 16 bits (assembly: `ax` or `[rsp+X]`)
- `HIWORD(v5)` = bits 16-31 (assembly: `[rsp+X+2]`)
- `LODWORD(v5)` = low 32 bits of a 64-bit variable
- `HIDWORD(v5)` = high 32 bits

These are NOT function calls. They represent sub-register access. A write to
`LOBYTE(v5)` only modifies the lowest byte; the upper bytes are preserved.
This matters for size calculations where only part of a variable is
attacker-controlled.

---

## 8. Compound Assignment Artifacts

Hex-Rays sometimes generates `v5 = v5` or `LODWORD(v5) = v5` as artifacts
of register reuse. These are no-ops in the assembly but can confuse data
flow analysis.

**What to check:** If a variable appears to be assigned to itself, verify in
the assembly whether any actual `mov` instruction exists or if this is a
decompiler artifact.

---

## 9. Missing Volatile Reads

When a value is read from shared memory or a memory-mapped register, the
compiler may load it once into a register and reuse the register value.
Hex-Rays shows a single variable read, not the multiple memory accesses that
a `volatile` qualifier would force. This hides double-fetch vulnerabilities.

**What to check:** If analyzing a potential double-fetch (Pattern 6 in
vulnerability_patterns.md), count the actual `mov` instructions that read
from the shared address in the assembly.

---

## 10. Error Path Elision

Hex-Rays aggressively simplifies error paths. An early return on error may
be shown as a simple `if (v5) return -1;` but in the assembly the error
path may include cleanup (freeing buffers, releasing locks, decrementing
reference counts). If the cleanup is incomplete, this is where UAF and
double-free bugs hide.

**What to check:** For any error-handling branch that returns early, read the
assembly to see if there are `call` instructions to free/release functions
that the decompiler elided or folded into the normal path representation.

---

## Summary Rule

**When in doubt, check the assembly.** The decompiled code is helpful for
understanding high-level logic, but any finding that depends on specific
data sizes, pointer identity, calling convention, or control flow edge cases
must be verified against the x64 assembly. The assembly is the binary's
actual behavior; the decompiled code is one possible interpretation.
